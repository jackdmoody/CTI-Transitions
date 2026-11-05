"""Scoring engine for the AICS-27 revision (internal review), ADOPTED SETTINGS (Jack, 2026-11-05). No model calls.

Adopted settings, used for the main text and for every sensitivity analysis:
- Chance is exact. A random k-edge set has TP ~ Hypergeometric(182, |E_g|, k), so F1 / chance = TP / E[TP]
  = precision / (|E_g| / 182), and the percentile is 100 (P(TP < tp) + P(TP = tp) / 2). No Monte Carlo is
  on the main path. tests/test_revision_engine.py checks that a tie-fixed Monte Carlo agrees with it.
- Every bootstrap draws 10,000 resamples (seed 20261105):
  * own-plan IG (Table 3): an i.i.d. bootstrap over plan transitions; bold and dagger come from it;
  * a moving-block bootstrap over plan transitions: blocks of b in {2, 3, 5} stay inside one segment of
    ctit.eval.reference and never wrap around; a cell gets * if its status (above / spans / below zero) at
    any b differs from the i.i.d. status;
  * paired R - B IG over plan transitions: the same resampled indices for R and B (i.i.d. and block);
  * R - B report-level bootstrap (reports, and samples where there are several) plus the
    leave-one-report-out jackknife (Table 5); 'clear' = both exclude zero on the same side.

scorecard(cfg, variant, filt): 'adopted' reference or sensitivity variant 'A' / 'B'; evidence filter None,
'fragments' or 'strict' (R kernels rebuilt without transitions whose quote fails that check; B has no evidence
check and is never filtered). The draft's Monte Carlo / 1,000- and 2,000-resample numbers are kept as a record in
results/revision/sensitivity/base.json (written at c701c77), not recomputed here.
"""
from __future__ import annotations

import math
import zlib
from dataclasses import dataclass

import numpy as np
from scipy.stats import hypergeom
from scipy.stats import t as student_t

from ctit.cti import prior
from ctit.cti.manifest import load_actors
from ctit.eval import recovery
from ctit.eval import reference as ref
from ctit.experiments import v2_common as v2
from ctit.experiments.prior_likelihood import bits, conditional

ALPHA = 0.5
K = 14
N_OFF = recovery.N_OFF  # 182
ACTORS = ["APT29", "OilRig", "Sandworm", "menuPass"]  # paper order
R_LABELS = ["F", "G", "Q", "Q5", "M", "M5", "M3"]
B_LABELS = ["F", "G", "Q", "M"]
FAMILIES = [f"R-{x}" for x in R_LABELS] + [f"B-{x}" for x in B_LABELS] + ["ATTK"]
PAIRS = ["F", "G", "Q", "Q5", "M", "M5", "M3"]
NAMES = {"F": "Claude Opus", "G": "GPT-6 Astra", "Q": "Qwen 14B", "Q5": "Qwen 14B sampled", "M": "Ministral 14B",
         "M5": "Ministral 14B sampled", "M3": "Ministral 3B", "M35": "Ministral 3B sampled"}
SEED = 20261105
N_BOOT = 10000
BLOCKS = (2, 3, 5)
FILTER_FLAG = {"fragments": "evidence_ok_fragments", "strict": "evidence_ok"}
SETTINGS = {"chance": "exact hypergeometric", "n_boot": N_BOOT, "seed": SEED, "block_lengths": list(BLOCKS),
            "block_rule": "moving blocks inside segments, no wrap-around; * if status at any b differs from i.i.d.",
            "clear_rule": "report bootstrap and leave-one-report-out jackknife both exclude zero, same side",
            "alpha": ALPHA}


# ----------------------------------------------------------------------------- references

@dataclass
class Ref:
    actor: str
    variant: str
    segments: list
    G: np.ndarray       # 14 x 14 transition counts (no pair across a segment boundary)
    pairs: np.ndarray   # (L, 2)
    seg: np.ndarray     # (L,) segment index of each transition

    @property
    def L(self) -> int:
        return len(self.pairs)

    @property
    def g(self) -> int:
        return int(((self.G > 0) & recovery.OFF_DIAG).sum())


def reference(actor: str, variant: str = "adopted") -> Ref:
    segs = ref.variant_segments(actor, variant)
    return Ref(actor, variant, segs, ref.counts(segs), ref.pairs_array(segs), ref.segment_ids(segs))


# ----------------------------------------------------------------------------- exact chance

def exact_chance(k: int, g: int, tp: int) -> dict:
    """Edge-F1 of a random k-edge set against g truth edges: TP ~ Hypergeometric(182, g, k).
    Mean F1 = 2 E[TP] / (k + g) with E[TP] = k g / 182; percentile = 100 (P(TP < tp) + P(TP = tp) / 2)."""
    if k == 0 or g == 0:
        return {"mean_f1": 0.0, "expected_tp": 0.0, "percentile": 50.0 if tp == 0 else 100.0, "ratio": None}
    h = hypergeom(N_OFF, g, k)
    etp = k * g / N_OFF
    mean_f1 = 2 * etp / (k + g)
    return {"mean_f1": mean_f1, "expected_tp": etp, "percentile": float(100 * (h.cdf(tp - 1) + 0.5 * h.pmf(tp))),
            "ratio": tp / etp}


class ExactChance:
    """Exact chance for one truth: ratio (= TP / E[TP]) and percentile from (C, truth)."""

    def __init__(self, G: np.ndarray):
        self.G = G
        self.g = int(((G > 0) & recovery.OFF_DIAG).sum())

    def score(self, C: np.ndarray) -> dict:
        r = recovery.edge_prf(C, self.G)
        e = exact_chance(r["edges_extracted"], self.g, r["tp"])
        return {**r, "ratio": e["ratio"], "percentile": e["percentile"], "chance_mean_f1": e["mean_f1"]}


# ----------------------------------------------------------------------------- kernels

def r_tensor(cfg: dict, label: str, actor: str, filt: str | None = None) -> np.ndarray:
    """(samples, reports, 14, 14) binary: the edges each report supports, after the evidence filter."""
    reports = v2.prior_reports(actor)
    pos = {r: i for i, r in enumerate(reports)}
    ds = v2.load(cfg["priors"][label], "R", actor)
    E = np.zeros((len(ds), len(reports), K, K))
    for s, d in enumerate(ds):
        for t in d["transitions"]:
            if filt is not None and t.get(FILTER_FLAG[filt]) is False:
                continue
            E[s, pos[t["doc_id"]], prior.INDEX[t["from_tactic"]], prior.INDEX[t["to_tactic"]]] = 1
        if filt is None and not np.array_equal(E[s].sum(axis=0), np.array(d["counts"])):
            raise RuntimeError(f"per-report edges do not rebuild the saved counts ({label} {actor})")
    return E


def b_counts(cfg: dict, label: str, actor: str) -> list[np.ndarray]:
    return v2.counts(cfg["priors"][label], "B", actor)


def attk_counts(actor: str) -> list[np.ndarray]:
    return [prior.attk_counts(load_actors()[actor]["attack_group"])[0]]


def family_counts(cfg: dict, name: str, actor: str, filt: str | None = None) -> list[np.ndarray]:
    if name == "ATTK":
        return attk_counts(actor)
    cond, label = name.split("-", 1)
    if cond == "R":
        return list(r_tensor(cfg, label, actor, filt).sum(axis=1))
    return b_counts(cfg, label, actor)


# ----------------------------------------------------------------------------- resampling

def block_list(seg: np.ndarray, b: int) -> list[np.ndarray]:
    """Every admissible block: b consecutive transitions inside one segment, or a whole segment shorter than b."""
    blocks = []
    for s in np.unique(seg):
        pos = np.flatnonzero(seg == s)
        blocks += [pos] if len(pos) <= b else [pos[i:i + b] for i in range(len(pos) - b + 1)]
    return blocks


def admissible_blocks(seg: np.ndarray, b: int) -> int:
    return len(block_list(seg, b))


def segment_blocks(seg: np.ndarray, b: int, n: int, rng: np.random.Generator) -> np.ndarray:
    """(n, L) moving-block bootstrap indices that respect segments: blocks drawn uniformly from block_list(),
    concatenated until L is reached, truncated to L. No block crosses a boundary; none wraps around."""
    L = len(seg)
    blocks = block_list(seg, b)
    lens = np.array([len(x) for x in blocks])
    if (lens == lens[0]).all():
        B = np.stack(blocks)
        k = -(-L // lens[0])
        return B[rng.integers(0, len(B), (n, k))].reshape(n, -1)[:, :L]
    out = np.empty((n, L), dtype=int)
    for r in range(n):
        got: list[int] = []
        while len(got) < L:
            got.extend(blocks[rng.integers(0, len(blocks))].tolist())
        out[r] = got[:L]
    return out


def transition_indices(R: Ref) -> dict:
    """{'iid': (N, L), 2: ..., 3: ..., 5: ...}: resampled transition indices, seeded per actor and scheme, shared by
    every family (and by R and B in the paired difference)."""
    a = zlib.crc32(R.actor.encode())
    out = {"iid": np.random.default_rng([SEED, 0, a]).integers(0, R.L, (N_BOOT, R.L))}
    for b in BLOCKS:
        out[b] = segment_blocks(R.seg, b, N_BOOT, np.random.default_rng([SEED, b, a]))
    return out


def ci(m: np.ndarray, idx: np.ndarray) -> list[float]:
    return [float(x) for x in np.percentile(m[idx].mean(axis=1), [2.5, 97.5])]


def status(lo: float, hi: float) -> str:
    return v2.status(lo, hi)


def intervals(m: np.ndarray, idx: dict) -> dict:
    """Point, i.i.d. and block intervals of a per-transition statistic; mark = block status differs at any b."""
    c = ci(m, idx["iid"])
    out = {"point": float(m.mean()), "iid": {"ci95": c, "status": status(*c)}}
    for b in BLOCKS:
        cb = ci(m, idx[b])
        out[f"block_{b}"] = {"ci95": cb, "status": status(*cb)}
    out["mark"] = any(out[f"block_{b}"]["status"] != out["iid"]["status"] for b in BLOCKS)
    return out


# ----------------------------------------------------------------------------- statistics

def per_transition(Cs: list[np.ndarray], pr: np.ndarray, alpha: float = ALPHA) -> np.ndarray:
    """(L,) log2(13 P) per plan transition, mean over samples."""
    return np.mean([bits(conditional(C, alpha), pr) for C in Cs], axis=0)


def t2_cell(Cs: list[np.ndarray], ch: ExactChance) -> dict:
    rs = [ch.score(C) for C in Cs]
    ok = [r["ratio"] for r in rs if r["ratio"] is not None]
    m = lambda k: float(np.mean([r[k] for r in rs]))
    return {"samples": len(Cs), "truth_edges": ch.g, "edges_mean": m("edges_extracted"), "edge_f1": m("f1"),
            "precision": m("precision"), "recall": m("recall"),
            "f1_over_chance": float(np.mean(ok)) if ok else None, "percentile": m("percentile")}


def _nanmean(x) -> float:
    x = np.asarray(x, dtype=float)
    return float(np.nanmean(x)) if (~np.isnan(x)).any() else np.nan


def jackknife(point, reps: np.ndarray) -> dict:
    n = len(reps)
    if point is None or np.isnan(reps).any():
        return {"replicates": [None if np.isnan(x) else float(x) for x in reps], "min": None, "max": None,
                "se": None, "ci95": None}
    se = float(np.sqrt((n - 1) / n * ((reps - reps.mean()) ** 2).sum()))
    q = float(student_t.ppf(0.975, n - 1))
    return {"replicates": [float(x) for x in reps], "min": float(reps.min()), "max": float(reps.max()),
            "se": se, "t_quantile": q, "ci95": [point - q * se, point + q * se]}


def _ci(x: np.ndarray) -> dict:
    ok = x[~np.isnan(x)]
    if not len(ok):
        return {"ci95": None, "undefined_resamples": int(len(x))}
    return {"ci95": [float(np.percentile(ok, 2.5)), float(np.percentile(ok, 97.5))], "median": float(np.median(ok)),
            "undefined_resamples": int(np.isnan(x).sum())}


def clear(entry: dict) -> str:
    """'above' / 'below' if the bootstrap and the jackknife interval both exclude zero on the same side."""
    b, j = entry.get("ci95"), (entry.get("jackknife") or {}).get("ci95")
    if b is None or j is None:
        return "undefined"
    sb, sj = status(*b), status(*j)
    return sb if sb == sj and sb != "spans" else "not clear"


def rb_one(E: np.ndarray, B: list[np.ndarray], R: Ref, ch: ExactChance, n_boot: int, rng: np.random.Generator,
           alpha: float = ALPHA) -> dict:
    """R - B at the report level: reports drawn with replacement (the same draw for every R sample), R samples drawn
    with replacement where there are several, B samples likewise (a single temperature-0 B is held fixed); plus the
    leave-one-report-out jackknife (every R sample kept, B at its point estimate). Statistics: exact F1 / chance,
    raw edge-F1, own-plan IG (plan transitions held fixed)."""
    pr = R.pairs

    def stat(Cs):
        sc = [ch.score(C) for C in Cs]
        return (_nanmean([np.nan if s["ratio"] is None else s["ratio"] for s in sc]),
                float(np.mean([bits(conditional(C, alpha), pr).mean() for C in Cs])),
                float(np.mean([s["f1"] for s in sc])))

    r_pt, b_pt = stat(E.sum(axis=1)), stat(B)
    Bs = np.array([stat([C]) for C in B])  # per B sample: ratio, ig, f1
    nS, nR, nB = E.shape[0], E.shape[1], len(B)
    boot = np.full((n_boot, 6), np.nan)  # R ratio, B ratio, R ig, B ig, R f1, B f1
    for b in range(n_boot):
        idx_r = rng.integers(0, nR, nR)
        idx_s = rng.integers(0, nS, nS) if nS > 1 else np.zeros(1, dtype=int)
        idx_b = rng.integers(0, nB, nB) if nB > 1 else np.zeros(1, dtype=int)
        rs = stat(E[idx_s][:, idx_r].sum(axis=1))
        boot[b, 0], boot[b, 2], boot[b, 4] = rs
        boot[b, 1] = _nanmean(Bs[idx_b, 0])
        boot[b, 3] = Bs[idx_b, 1].mean()
        boot[b, 5] = Bs[idx_b, 2].mean()
    jk = np.array([stat(E[:, np.arange(nR) != i].sum(axis=1)) for i in range(nR)])
    pt = lambda x: None if x is None or np.isnan(x) else float(x)
    gap = lambda j: (pt(r_pt[j] - b_pt[j]) if not (np.isnan(r_pt[j]) or np.isnan(b_pt[j])) else None)
    out = {"reports": nR, "r_samples": nS, "b_samples": nB}
    for key, i, j in (("f1_over_chance", 0, 0), ("ig_bits", 2, 1), ("edge_f1", 4, 2)):
        g = {"point": gap(j), **_ci(boot[:, i] - boot[:, i + 1]), "jackknife": jackknife(gap(j), jk[:, j] - b_pt[j])}
        g["clear"] = clear(g)
        out[key] = {"R": pt(r_pt[j]), "B": pt(b_pt[j]), "R_minus_B": g}
    return out


# ----------------------------------------------------------------------------- scorecard

def scorecard(cfg: dict, variant: str = "adopted", filt: str | None = None, with_rb: bool = True) -> dict:
    refs = {a: reference(a, variant) for a in ACTORS}
    ch = {a: ExactChance(refs[a].G) for a in ACTORS}
    idx = {a: transition_indices(refs[a]) for a in ACTORS}
    counts = {name: {a: family_counts(cfg, name, a, filt) for a in ACTORS} for name in FAMILIES}
    out: dict = {"variant": variant, "filter": filt, "settings": SETTINGS,
                 "reference": {a: {"edges": refs[a].g, "L": refs[a].L, "segments": len(refs[a].segments),
                                   "admissible_blocks": {b: admissible_blocks(refs[a].seg, b) for b in BLOCKS}}
                               for a in ACTORS},
                 "t2": {}, "t3": {}, "attr": {}, "paired_ig": {}, "rb": {}, "h3": {}}
    for name, by_a in counts.items():
        out["t2"][name] = {a: t2_cell(Cs, ch[a]) for a, Cs in by_a.items()}
        out["t3"][name] = {a: intervals(per_transition(Cs, refs[a].pairs), idx[a]) for a, Cs in by_a.items()}
        sc = {ra: {ca: float(per_transition(by_a[ra], refs[ca].pairs).mean()) for ca in ACTORS} for ra in ACTORS}
        best = {ca: max(ACTORS, key=lambda ra: sc[ra][ca]) for ca in ACTORS}
        out["attr"][name] = {"n": sum(best[a] == a for a in ACTORS), "plan_to": best, "matrix": sc}
    for lab in PAIRS:
        for a in ACTORS:
            d = per_transition(counts[f"R-{lab}"][a], refs[a].pairs) - per_transition(b_counts(cfg, lab, a), refs[a].pairs)
            out["paired_ig"].setdefault(lab, {})[a] = intervals(d, idx[a])
    f_f1 = {a: out["t2"]["R-F"][a]["edge_f1"] for a in ACTORS}
    for lab in ("Q", "Q5", "M", "M5", "M3", "G"):
        sh = {a: out["t2"][f"R-{lab}"][a]["edge_f1"] / f_f1[a] for a in ACTORS}
        out["h3"][lab] = {"share": sh, "meets_80": sum(v >= 0.8 for v in sh.values())}
    if with_rb:
        for a in ACTORS:
            for lab in PAIRS:
                rng = np.random.default_rng([SEED, zlib.crc32(lab.encode()), zlib.crc32(a.encode())])
                out["rb"].setdefault(lab, {})[a] = rb_one(r_tensor(cfg, lab, a, filt), b_counts(cfg, lab, a), refs[a],
                                                          ch[a], N_BOOT, rng)
    return out


# ----------------------------------------------------------------------------- smoothing

def smoothing(Cs: list[np.ndarray], n_docs: int | None, alpha: float = ALPHA) -> dict:
    """Effective smoothing of Eq. 1 kernels. n_docs: reports (R) or 1 (one B generation); None = ATTK."""
    off = [np.where(np.eye(K, dtype=bool), 0, C) for C in Cs]
    rows = np.concatenate([C.sum(axis=1) for C in off])
    fitted = [conditional(C, alpha).max() for C in Cs]
    out = {"samples": len(Cs), "row_total_max": float(rows.max()), "row_total_sum_mean": float(np.mean([C.sum() for C in off])),
           "nonempty_rows_mean": float(np.mean([(C.sum(axis=1) > 0).sum() for C in off])),
           "fitted_max_row_prob": float(max(fitted)), "fitted_max_row_prob_mean": float(np.mean(fitted)),
           "fitted_bits": float(math.log2((K - 1) * max(fitted)))}
    if n_docs is not None:
        cap = (n_docs + alpha) / (n_docs + (K - 1) * alpha)
        out.update({"n_docs": n_docs, "cap": cap, "cap_bits": math.log2((K - 1) * cap)})
    else:  # ATTK, C = n n^T: row i of Eq. 1 tends to n_j / sum_{k != i} n_k as counts grow; no report cap
        n = np.sqrt(np.diag(Cs[0]))
        lim = max((n[j] / (n.sum() - n[i])) for i in range(K) for j in range(K) if j != i and n.sum() - n[i] > 0)
        out.update({"n_docs": None, "cap": float(lim), "cap_bits": math.log2((K - 1) * lim),
                    "cap_note": "no report cap: limit of max_j n_j / sum_{k != i} n_k as counts grow"})
    return out
