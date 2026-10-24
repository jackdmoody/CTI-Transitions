"""WP4b report for the frozen extended mapper vs. the BRiMS mapper (spec §2.5).

Writes tagged events under data/<dataset>/tagged_{extended,brims}/ and returns metrics:
K per dataset/source, benign tag rates (ATLASv2 benign split), recall on OTRF APT29 plan
steps, recall on Splunk Attack Data samples, and event-level recall on ATLASv2 Security
ground truth (EventRecordIDs).
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pandas as pd

from ctit.ingest import splunk
from ctit.map import attack, validate
from ctit.map.attack import TACTICS
from ctit.map.sigma_rules import SIGMA_COMMIT, load_compiled

REPO_ROOT = Path(__file__).resolve().parents[2]
OTRF = REPO_ROOT / "data" / "otrf" / "apt29"
ATLAS = REPO_ROOT / "data" / "atlasv2"
MAPPERS = ("extended", "brims")
ORDER = {t: i for i, t in enumerate(TACTICS)}


def _sorted_tactics(ts) -> list[str]:
    return sorted(ts, key=ORDER.get)


def _save(tagged: dict[str, pd.DataFrame], root: Path, name: str) -> None:
    for m, df in tagged.items():
        out = root / f"tagged_{m}"
        out.mkdir(parents=True, exist_ok=True)
        df.to_parquet(out / f"{name}.parquet", index=False)


def _atlas_part(args) -> dict:
    """Aggregates for one ATLASv2 canonical part (runs in a worker process)."""
    path, gt_ids = args
    rules = load_compiled()
    df = pd.read_parquet(path)
    split = path.parent.name.split("-")[0]
    tagged = validate.tag_both(df, rules)
    _save(tagged, ATLAS, f"{path.parent.name}__{path.stem}")
    out = {"split": split, "scenario": path.parent.name, "mappers": {}}
    for m, t in tagged.items():
        hit = t["tactic"] != ""
        stats = {
            "events_by_source": Counter(t["source"]),
            "tagged_by_source_tactic": Counter(zip(t.loc[hit, "source"], t.loc[hit, "tactic"])),
        }
        if gt_ids is not None and "EventRecordID" in df.columns:
            is_gt = (df["source"] == "security") & pd.to_numeric(df["EventRecordID"], errors="coerce").isin(gt_ids)
            sec = df["source"] == "security"
            stats["gt"] = {
                "gt_events": int(is_gt.sum()), "gt_tagged": int((is_gt & hit.values).sum()),
                "other_security_events": int((sec & ~is_gt).sum()),
                "other_security_tagged": int((sec & ~is_gt & hit.values).sum()),
            }
        out["mappers"][m] = stats
    return out


def run(config: dict, calls=None) -> dict:
    rules = load_compiled()
    rules_by_id = {r["id"]: r for r in rules}
    metrics: dict = {"sigma_commit": SIGMA_COMMIT, "n_rules": len(rules),
                     "rules_by_tactic": dict(Counter(r["tactics"][0] for r in rules))}

    # --- OTRF APT29 -------------------------------------------------------------
    pooled = {m: {} for m in MAPPERS}
    otrf_k = {m: defaultdict(set) for m in MAPPERS}
    otrf_rates = {}
    for day in ("day1", "day2"):
        tagged = validate.tag_both(pd.read_parquet(OTRF / "canonical" / f"{day}.parquet"), rules)
        _save(tagged, OTRF, day)
        for m, t in tagged.items():
            pooled[m][day] = validate.pooled(validate.annotate(t, m, rules_by_id))
            hit = t[t["tactic"] != ""]
            for source, g in hit.groupby("source"):
                otrf_k[m][source].update(g["tactic"])
            otrf_rates.setdefault(m, {})[day] = validate.tactic_rates(t)
    steps, unresolved = validate.otrf_plan_steps(OTRF / "plan" / "apt29.xlsx")
    metrics["otrf"] = {
        "K": {m: {s: _sorted_tactics(v) for s, v in otrf_k[m].items()} for m in MAPPERS},
        "tag_rates": otrf_rates,
        "plan_unresolved_names": unresolved,
        "recall": {m: validate.step_recall(steps, pooled[m]) for m in MAPPERS},
    }

    # --- Splunk Attack Data -----------------------------------------------------
    rows, skipped = [], []
    for path in sorted(splunk.SAMPLES.iterdir()):
        try:
            sample = splunk.read_sample(path)
        except Exception as e:  # noqa: BLE001 - malformed export; record it
            skipped.append(f"{path.name}: {type(e).__name__}")
            continue
        if sample is None:
            skipped.append(f"{path.name}: not XML")
            continue
        technique, df = sample
        tid = validate.parent(technique)
        truth_tactics = set(attack.technique_tactics(technique))
        row = {"file": path.name, "technique": technique, "events": len(df)}
        for m, t in validate.tag_both(df, rules).items():
            techs, tacs = set(), set()
            for th, ta in validate.pooled(validate.annotate(t, m, rules_by_id)).values():
                techs |= th
                tacs |= ta
            row[f"{m}_technique_hit"] = tid in techs
            row[f"{m}_tactic_hit"] = bool(truth_tactics & tacs)
        rows.append(row)
    sp = pd.DataFrame(rows)
    metrics["splunk"] = {
        "samples": len(sp), "skipped": skipped,
        "recall": {m: {"technique": float(sp[f"{m}_technique_hit"].mean()),
                       "tactic": float(sp[f"{m}_tactic_hit"].mean())} for m in MAPPERS},
        "per_sample": rows,
    }

    # --- ATLASv2 ----------------------------------------------------------------
    gt = json.loads((ATLAS / "groundtruth_record_ids.json").read_text())
    jobs = []
    for part in sorted((ATLAS / "canonical").rglob("*.parquet")):
        scen = part.parent.name  # attack-h1-s1 -> groundtruth key h1_s1
        key = "_".join(scen.split("-")[1:3]) if scen.startswith("attack-") else None
        jobs.append((part, set(gt[key]) if key in gt else None))
    with ProcessPoolExecutor(max_workers=config.get("workers", 4)) as pool:
        parts = list(pool.map(_atlas_part, jobs))
    atlas: dict = {}
    for m in MAPPERS:
        ev = {"benign": Counter(), "attack": Counter()}
        tg = {"benign": Counter(), "attack": Counter()}
        gt_tot = Counter()
        for p in parts:
            ev[p["split"]].update(p["mappers"][m]["events_by_source"])
            tg[p["split"]].update(p["mappers"][m]["tagged_by_source_tactic"])
            gt_tot.update(p["mappers"][m].get("gt", {}))
        benign_total = sum(ev["benign"].values())
        by_tactic = Counter()
        for (_, tac), n in tg["benign"].items():
            by_tactic[tac] += n
        atlas[m] = {
            "K": {split: {src: _sorted_tactics({t for (s, t) in tg[split] if s == src})
                          for src in ev[split]} for split in ev},
            "benign_events_by_source": dict(ev["benign"]),
            "benign_tag_rate_by_source": {
                src: sum(n for (s, _), n in tg["benign"].items() if s == src) / ev["benign"][src]
                for src in ev["benign"]},
            "benign_tag_rate_by_tactic": {t: n / benign_total for t, n in sorted(by_tactic.items(), key=lambda kv: ORDER[kv[0]])},
            "security_groundtruth": {
                **dict(gt_tot),
                "recall": gt_tot["gt_tagged"] / gt_tot["gt_events"] if gt_tot["gt_events"] else None,
                "other_tag_rate": (gt_tot["other_security_tagged"] / gt_tot["other_security_events"]
                                   if gt_tot["other_security_events"] else None),
            },
        }
    metrics["atlasv2"] = atlas
    return metrics
