"""Tactic-sequence injection from real-recording signatures (spec §2.2).

Operates on tactic tokens only. Raw telemetry is never read, moved, or modified
here: inputs are the signature library (built by scripts/build_signatures.py from
real public recordings via the frozen mappers) and benign tactic streams.

Typical use:
    from ctit.inject import splice
    idx = splice.SignatureIndex.load()
    res = splice.resolve_actor("APT29", mapper="extended", seed=0, index=idx)
    seqs = splice.scenario_sequences(res)          # list[list[str]] per scenario
    print(splice.coverage_summary(res))
    vis = splice.visibility_sources(res)           # adds `source`, `match` columns
"""
from __future__ import annotations

import zlib
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd

from ctit.eval import plans
from ctit.eval.visibility import draft_rows

SIGNATURES = Path("data/eval/tactic_signatures.parquet")
FALLBACK_COL = {"extended": "drift_tactic", "brims": "brims_tactic"}
NO_TACTIC = "—"


def parent(technique: str) -> str:
    return technique.split(".")[0] if technique else ""


def _h(s: str) -> int:
    return zlib.crc32(s.encode("utf-8"))


@dataclass(frozen=True)
class StepResolution:
    actor: str
    ability_id: str
    step_id: str
    scenario: int
    technique: str
    mapper: str
    source: str        # splunk_attack_data | otrf_atomic | process_only
    match: str         # exact | parent | none
    recording: str     # "<file>#<host>" or "" for process_only
    tactics: tuple[str, ...]
    rel_s: tuple[float, ...]


class SignatureIndex:
    """Lookup of real-recording tactic subsequences by (mapper, technique)."""

    def __init__(self, df: pd.DataFrame, collapsed: bool = True):
        tcol, rcol = ("tactics_collapsed", "rel_s_collapsed") if collapsed else ("tactics", "rel_s")
        self.collapsed = collapsed
        self._by: dict[tuple[str, str, str], list[tuple]] = {}
        df = df.sort_values(["mapper", "technique", "source", "recording", "host"], kind="stable")
        for row in df.itertuples(index=False):
            tac = tuple(str(t) for t in getattr(row, tcol))
            if not tac:
                continue
            rel = tuple(float(x) for x in getattr(row, rcol))
            entry = (row.source, f"{row.recording}#{row.host}", tac, rel)
            self._by.setdefault((row.mapper, "exact", row.technique), []).append(entry)
            self._by.setdefault((row.mapper, "parent", parent(row.technique)), []).append(entry)

    @classmethod
    def load(cls, path: Path = SIGNATURES, collapsed: bool = True) -> "SignatureIndex":
        return cls(pd.read_parquet(path), collapsed=collapsed)

    def candidates(self, mapper: str, technique: str, allow_parent: bool = True) -> tuple[str, list[tuple]]:
        c = self._by.get((mapper, "exact", technique))
        if c:
            return "exact", c
        if allow_parent:
            c = self._by.get((mapper, "parent", parent(technique)))
            if c:
                return "parent", c
        return "none", []


def resolve_actor(
    actor: str,
    mapper: str,
    seed: int,
    index: SignatureIndex,
    allow_parent: bool = True,
    max_tokens: int | None = None,
) -> list[StepResolution]:
    """Choose, per plan step, the tactic subsequence to inject.

    Exact technique match first, then parent technique (if allowed), else the
    process-creation draft from ctit.eval.visibility (source=process_only).
    Choice among recordings is seeded and independent of other actors/mappers.
    """
    if mapper not in FALLBACK_COL:
        raise ValueError(f"mapper must be one of {sorted(FALLBACK_COL)}")
    steps = plans.load_plan(actor)
    draft = draft_rows(steps)
    fallback = dict(zip(draft["ability_id"].astype(str), draft[FALLBACK_COL[mapper]].astype(str)))
    rng = np.random.default_rng([seed, _h(actor), _h(mapper)])

    out: list[StepResolution] = []
    for s in steps:
        match, cands = index.candidates(mapper, s.technique, allow_parent)
        if cands:
            source, recording, tac, rel = cands[int(rng.integers(len(cands)))]
            if max_tokens is not None:
                tac, rel = tac[:max_tokens], rel[:max_tokens]
        else:
            t = fallback.get(str(s.ability_id), NO_TACTIC)
            source, recording, match = "process_only", "", "none"
            tac, rel = ((t,), (0.0,)) if t and t != NO_TACTIC else ((), ())
        out.append(StepResolution(
            actor=actor, ability_id=str(s.ability_id), step_id=str(s.step_id),
            scenario=int(s.scenario), technique=s.technique, mapper=mapper,
            source=source, match=match, recording=recording,
            tactics=tuple(tac), rel_s=tuple(rel),
        ))
    return out


def scenario_sequences(resolutions: list[StepResolution]) -> list[list[str]]:
    """One concatenated tactic list per scenario, in plan order (skips empty steps)."""
    by: dict[int, list[str]] = {}
    for r in resolutions:
        by.setdefault(r.scenario, []).extend(r.tactics)
    return [by[k] for k in sorted(by) if by[k]]


def coverage_summary(resolutions: list[StepResolution]) -> dict:
    n = len(resolutions) or 1
    src = pd.Series([r.source for r in resolutions]).value_counts().to_dict()
    mat = pd.Series([r.match for r in resolutions]).value_counts().to_dict()
    real = sum(v for k, v in src.items() if k != "process_only")
    return {
        "steps": len(resolutions),
        "pct_real_recording": round(100 * real / n, 1),
        "pct_exact": round(100 * mat.get("exact", 0) / n, 1),
        "pct_parent": round(100 * mat.get("parent", 0) / n, 1),
        "pct_process_only": round(100 * src.get("process_only", 0) / n, 1),
        "pct_no_tactic": round(100 * sum(1 for r in resolutions if not r.tactics) / n, 1),
        "by_source": src,
    }


def visibility_sources(resolutions: list[StepResolution]) -> pd.DataFrame:
    """Per-step frame to merge into the visibility CSV on ability_id."""
    return pd.DataFrame([{
        "ability_id": r.ability_id,
        "step_id": r.step_id,
        "technique": r.technique,
        "mapper": r.mapper,
        "source": r.source,
        "match": r.match,
        "recording": r.recording,
        "sig_tactics": " > ".join(r.tactics) if r.tactics else NO_TACTIC,
        "n_tokens": len(r.tactics),
    } for r in resolutions])


def splice_stream(
    benign: pd.DataFrame,
    resolutions: list[StepResolution],
    start: pd.Timestamp | str,
    rng: np.random.Generator,
    gap_lognorm: tuple[float, float] = (float(np.log(60.0)), 1.0),
    max_step_span_s: float | None = 3600.0,
) -> pd.DataFrame:
    """Insert injected tactic tokens into one benign host's tactic stream.

    benign: columns `ts` (datetime64[ns, UTC]) and `tactic` (str; "" allowed).
    Steps are placed sequentially from `start`: each step's tokens at
    step_start + rel_s (clipped to max_step_span_s), and the next step starts after
    a lognormal gap (mu, sigma in log-seconds; fit these to range inter-event times
    per spec §2.2). Benign rows are never altered or removed.

    Returns columns ts, tactic, is_injected, ability_id, sorted by ts (stable).
    """
    cursor = pd.Timestamp(start)
    if cursor.tzinfo is None:
        cursor = cursor.tz_localize("UTC")
    rows = []
    for r in resolutions:
        if not r.tactics:
            continue
        for tac, rel in zip(r.tactics, r.rel_s):
            if max_step_span_s is not None:
                rel = min(rel, max_step_span_s)
            rows.append((cursor + pd.to_timedelta(rel, unit="s"), tac, True, r.ability_id))
        cursor = rows[-1][0] + pd.to_timedelta(float(rng.lognormal(*gap_lognorm)), unit="s")

    inj = pd.DataFrame(rows, columns=["ts", "tactic", "is_injected", "ability_id"])
    ben = benign[["ts", "tactic"]].assign(is_injected=False, ability_id="")
    out = pd.concat([ben, inj], ignore_index=True)
    out["ts"] = pd.to_datetime(out["ts"], utc=True)
    return out.sort_values("ts", kind="stable").reset_index(drop=True)
