"""WP5: APT29 visibility draft + the H4-viability gate numbers (spec §2.2, §2.5).

Writes data/eval/visibility_apt29.csv (DRAFT, for Jack's sign-off) and
data/eval/plans/<actor>_cited_sources.txt (for the manifest's cited_by_emulation_plan).
Metrics: K under both mappers (from a mapper_report run), each actor's ground-truth
sequence projected onto K, and pairwise actor JSD under both mappers.
"""
from __future__ import annotations

import json
from pathlib import Path

from ctit.eval import actor_jsd, plans, visibility
from ctit.map import v3
from ctit.map.attack import TACTICS

REPO_ROOT = Path(__file__).resolve().parents[2]
EVAL = REPO_ROOT / "data" / "eval"
ORDER = {t: i for i, t in enumerate(TACTICS)}


def k_from_report(report: dict, mapper: str) -> dict[str, list[str]]:
    """K = primary tactics the mapper emitted, per dataset and over all public data."""
    otrf = {t for ts in report["otrf"]["K"][mapper].values() for t in ts}
    atlas = {t for split in report["atlasv2"][mapper]["K"].values() for ts in split.values() for t in ts}
    otrf_sysmon = set(report["otrf"]["K"][mapper].get("sysmon", []))
    srt = lambda s: sorted(s, key=ORDER.get)  # noqa: E731
    return {"otrf_sysmon": srt(otrf_sysmon), "otrf_all": srt(otrf), "atlasv2_all": srt(atlas),
            "public_all": srt(otrf | atlas)}


def k_from_v3(v3_report: dict) -> dict[str, list[str]]:
    """K under mapper v3 = primary tactics v3 emitted on the OpTC benign sample or the
    technique recordings (the paper's two sides: background and injected signatures)."""
    st = v3_report["steps"]["c3_no_remote_thread"]
    srt = lambda s: sorted(s, key=ORDER.get)  # noqa: E731
    k = srt(set(st["optc"]["K"]) | set(st["recordings"]["K"]))
    return {"optc_benign": srt(st["optc"]["K"]), "recordings": srt(st["recordings"]["K"]), "public_all": k}


def run(config: dict, calls=None) -> dict:
    report = json.loads((REPO_ROOT / config["mapper_report"]).read_text())
    actors = config["actors"]
    steps = {a: plans.load_plan(a) for a in actors}
    # mapper_version 3: the extended mapper is the frozen v3 subset, and its K comes from a
    # mapper_v3 run; the BRiMS reference is unchanged.
    rules = {3: v3.load_v3, "3h": v3.load_v3h}.get(config.get("mapper_version"), lambda: None)()

    for a in actors:
        (EVAL / "plans" / f"{a}_cited_sources.txt").write_text("\n".join(plans.cited_sources(a)) + "\n")
    drafts = {a: visibility.draft_rows(steps[a], rules) for a in actors}
    drafts["APT29"].to_csv(EVAL / config.get("visibility_out", "visibility_apt29.csv"), index=False)

    K = {m: k_from_report(report, m) for m in ("extended", "brims")}
    if rules is not None:
        K["extended"] = k_from_v3(json.loads((REPO_ROOT / config["mapper_v3_report"]).read_text()))
    k_choice = config.get("k_scope", "public_all")
    plan_seqs = {a: plans.sequences(steps[a]) for a in actors}
    out: dict = {
        "mapper_report": config["mapper_report"], "k_scope": k_choice, "K": K,
        "steps": {a: len(steps[a]) for a in actors},
        "visibility_draft": {a: drafts[a]["visible_sysmon"].value_counts().to_dict() for a in actors},
        "cited_sources": {a: len(plans.cited_sources(a)) for a in actors},
        "plan_tactic_counts": {a: {t: sum(s.tactic == t for s in steps[a]) for t in TACTICS
                                   if any(s.tactic == t for s in steps[a])} for a in actors},
        "jsd": {},
    }
    for alpha in config.get("alphas", [0.5, 0.0]):
        key = f"alpha={alpha}"
        out["jsd"][key] = {"plan_14": actor_jsd.pairwise(plan_seqs, TACTICS, alpha)}
        for m in ("extended", "brims"):
            keep = K[m][k_choice]
            out["jsd"][key][f"plan_on_K_{m}"] = actor_jsd.pairwise(
                {a: actor_jsd.project_sequences(s, keep) for a, s in plan_seqs.items()}, keep, alpha)
            # What each mapper would actually see: the drafted per-step tactic (process-creation
            # artifacts only), steps with no tactic dropped. Draft for every actor, but only the
            # APT29 CSV is written and gated.
            col = "drift_tactic" if m == "extended" else "brims_tactic"
            vis = {}
            for a in actors:
                tac = dict(zip(drafts[a]["ability_id"], drafts[a][col]))
                vis[a] = plans.sequences(steps[a], tactic_of=lambda s, tac=tac: (tac[s.ability_id] if tac[s.ability_id] != "—" else None))
            out["jsd"][key][f"visible_{m}"] = actor_jsd.pairwise(vis, TACTICS, alpha)
    return out
