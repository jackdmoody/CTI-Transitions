"""Phase 1 ground-truth audit (AICS-27 revision, internal review). No model calls; nothing outside
results/revision/ is written.

    python scripts/revision/gt_audit.py

Writes results/revision/gt_audit/{config.yaml, metrics.json}, results/revision/gt_audit.md and
results/revision/tables/sigma_crosswalk.{csv,tex}.
- Old ground truth: ctit.eval.recovery.ground_truth_counts (edges) and ctit.experiments.v2_common.plan_pairs
  (transitions with multiplicity), as every paper table used them.
- New ground truth: ctit.eval.reference.build_reference (segments; no pair across a boundary).
- Sensitivity variants (reported, not adopted): platform-split (every maximal same-platform run is its own
  segment, cutting the plans' sequential Linux <-> Windows handoffs) and, for menuPass, the plan's two
  Optional steps (doc Steps 8 and 9) as separate segments.
- Multi-tactic rule: which branch each step took (ctit.eval.reference.tactic_rule).
- Sigma crosswalk: every 'attack.' tactic-like tag in the pinned SigmaHQ rules/windows, its frozen tactic
  (ctit.map.frozen_tactics.to_frozen_tactic) and rule counts in the release, the compiled mapper (v2) and
  the frozen v3 subset, plus the rules whose first tactic tag decides an event's tactic.
"""
from __future__ import annotations

import csv
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

import numpy as np
import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from ctit.eval import plans, recovery  # noqa: E402
from ctit.eval import reference as ref  # noqa: E402
from ctit.experiments import v2_common as v2  # noqa: E402
from ctit.map import sigma_rules, v3  # noqa: E402
from ctit.map.attack import TACTICS  # noqa: E402
from ctit.map.frozen_tactics import drop_reason, to_frozen_tactic  # noqa: E402

ACTORS = ["APT29", "OilRig", "Sandworm", "menuPass"]
OLD_L = {"APT29": 45, "OilRig": 17, "Sandworm": 25, "menuPass": 6}  # the paper's stated L
MENUPASS_OPTIONAL = ref.MENUPASS_OPTIONAL
OUT = REPO / "results" / "revision"
SHORT = {"Reconnaissance": "Recon", "Resource Development": "ResDev", "Initial Access": "InitAcc",
         "Execution": "Exec", "Persistence": "Persist", "Privilege Escalation": "PrivEsc",
         "Defense Evasion": "DefEva", "Credential Access": "CredAcc", "Discovery": "Disc",
         "Lateral Movement": "LatMov", "Collection": "Collect", "Command and Control": "C2",
         "Exfiltration": "Exfil", "Impact": "Impact"}


def edges(C: np.ndarray) -> set[tuple[str, str]]:
    return {(TACTICS[i], TACTICS[j]) for i, j in zip(*np.nonzero((C > 0) & recovery.OFF_DIAG))}


def e(p) -> str:
    return f"{SHORT[p[0]]}→{SHORT[p[1]]}"


def seams(segs_full, segs_split) -> list[dict]:
    """Transitions of the reference that a platform split would cut: the handoff between two consecutive
    steps on different platforms, when it is also a tactic change."""
    out = []
    for g in segs_full:
        st = g.steps
        for k in range(1, len(st)):
            if st[k].platforms != st[k - 1].platforms and st[k].tactic != st[k - 1].tactic:
                out.append({"from_step": st[k - 1].step_id, "from_platform": "+".join(st[k - 1].platforms),
                            "to_step": st[k].step_id, "to_platform": "+".join(st[k].platforms),
                            "edge": (st[k - 1].tactic, st[k].tactic)})
    return out


def menupass_optional_segments():
    return ref.variant_segments("menuPass", "B")


def variant_summary(old_C, old_L, segs) -> dict:
    C = ref.counts(segs)
    old_e, new_e = edges(old_C), edges(C)
    return {"segments": len(segs), "edges": len(new_e), "L": int(len(ref.pairs_array(segs))),
            "edges_removed": sorted(old_e - new_e), "edges_added": sorted(new_e - old_e),
            "L_change": int(len(ref.pairs_array(segs)) - old_L)}


def sigma_crosswalk() -> dict:
    root = sigma_rules.SIGMA_ROOT
    sigma_rules._sigma_commit()
    release: dict[str, list[str]] = {}
    for p in sorted(sigma_rules.RULES_DIR.rglob("*.yml")):
        for doc in yaml.safe_load_all(p.read_text()):
            if isinstance(doc, dict) and "id" in doc:
                release[str(doc["id"])] = [str(t) for t in doc.get("tags") or []]
    compiled = {r["id"]: r for r in sigma_rules.load_compiled()}
    frozen = {r["id"] for r in v3.load_v3()}
    rows, dropped = {}, Counter()
    for rid, tags in release.items():
        for tag in dict.fromkeys(tags):
            if not tag.startswith("attack."):
                dropped[("non-ATT&CK tag (" + tag.split(".")[0] + ".*)", drop_reason(tag, "sigma"))] += 1
                continue
            t = to_frozen_tactic(tag, "sigma")
            if t is None:
                reason = drop_reason(tag, "sigma")
                key = tag if reason == "attack tag is not a tactic" else {"technique tag": "attack.tNNNN[.NNN]",
                                                                         "group/software tag": "attack.gNNNN / attack.sNNNN"}[reason]
                dropped[(key, reason)] += 1
                continue
            r = rows.setdefault(tag, {"tag": tag, "tactic": t, "release": 0, "compiled_v2": 0, "frozen_v3": 0,
                                      "first_tactic_v2": 0, "first_tactic_v3": 0})
            r["release"] += 1
            r["compiled_v2"] += rid in compiled
            r["frozen_v3"] += rid in frozen
    # the tag that decides an event's tactic: the first tactic tag of the rule (MAPPER_POLICY)
    first_tag = {}
    for rid in compiled:
        tt = [t for t in release[rid] if to_frozen_tactic(t, "sigma")]
        first_tag[rid] = tt[0]
        rows[tt[0]]["first_tactic_v2"] += 1
        rows[tt[0]]["first_tactic_v3"] += rid in frozen
    multi = {k: sum(len(set(compiled[r]["tactics"])) > 1 for r in ids)
             for k, ids in (("compiled_v2", compiled), ("frozen_v3", frozen))}
    folded_both = sum({"attack.stealth", "attack.defense-impairment"} <= set(release[r]) for r in compiled)
    # consistency: the compiled mapper's tactic lists are what to_frozen_tactic gives today
    mismatch = [r for r, x in compiled.items()
                if x["tactics"] != list(dict.fromkeys(t for t in (to_frozen_tactic(g, "sigma") for g in release[r]) if t))]
    order = {t: i for i, t in enumerate(TACTICS)}
    return {"rules_release": len(release), "rules_compiled_v2": len(compiled), "rules_frozen_v3": len(frozen),
            "rows": sorted(rows.values(), key=lambda r: (order[r["tactic"]], r["tag"])),
            "dropped": [{"tag": k, "reason": why, "rule_tag_instances": n} for (k, why), n in sorted(dropped.items())],
            "multi_tactic_rules": multi, "rules_tagged_stealth_and_defense_impairment_v2": folded_both,
            "compiled_tactics_mismatch": mismatch}


def write_crosswalk(cw: dict) -> None:
    tdir = OUT / "tables"
    tdir.mkdir(parents=True, exist_ok=True)
    cols = ["tag", "tactic", "release", "compiled_v2", "frozen_v3", "first_tactic_v2", "first_tactic_v3"]
    with (tdir / "sigma_crosswalk.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols + ["note"])
        for r in cw["rows"]:
            note = "ATT&CK v19 split; folded to Defense Evasion" if r["tag"] in ("attack.stealth", "attack.defense-impairment") else ""
            w.writerow([r[c] for c in cols] + [note])
        for d in cw["dropped"]:
            w.writerow([d["tag"], "(dropped: " + d["reason"] + ")", d["rule_tag_instances"], "", "", "", "", ""])
    lines = [r"\begin{tabular}{@{}llrrrr@{}}", r"\toprule",
             r"Sigma tag & Frozen tactic & Release & Mapper & Frozen v3 & Decides (v3) \\", r"\midrule"]
    for r in cw["rows"]:
        tag = r["tag"].replace("_", r"\_")
        mark = r"$^\ast$" if r["tag"] in ("attack.stealth", "attack.defense-impairment") else ""
        lines.append(rf"\texttt{{{tag}}}{mark} & {r['tactic'].replace('&', r'\&')} & {r['release']} & {r['compiled_v2']} & "
                     rf"{r['frozen_v3']} & {r['first_tactic_v3']} \\")
    lines += [r"\midrule"]
    for d in cw["dropped"]:
        tag = d["tag"].replace("_", r"\_").replace("&", r"\&")
        lines.append(rf"\texttt{{{tag}}} & dropped ({d['reason']}) & {d['rule_tag_instances']} & & & \\")
    lines += [r"\bottomrule", r"\end{tabular}"]
    (tdir / "sigma_crosswalk.tex").write_text("\n".join(lines) + "\n")


def main() -> int:
    res: dict = {"plans": {}, "multi_tactic": {}}
    for a in ACTORS:
        steps = plans.load_plan(a, platforms=None)
        old_C, old_pairs = recovery.ground_truth_counts(a), v2.plan_pairs(a)
        segs = ref.build_reference(a, steps)
        split = ref.build_reference(a, steps, split_platforms=True)
        new_C, new_pairs = ref.counts(segs), ref.pairs_array(segs)
        sm = seams(segs, split)
        within = Counter(p for g in segs for p in g.pairs)
        for s in sm:
            s["edge_count_in_reference"] = within[s["edge"]]
            s["duplicates_another_occurrence"] = within[s["edge"]] > 1
        res["plans"][a] = {
            "steps": len(steps), "platforms": dict(Counter("+".join(s.platforms) for s in steps)),
            "segments": [{"scenario": g.scenario, "path": g.path, "steps": len(g.steps),
                          "first_step": g.steps[0].step_id, "last_step": g.steps[-1].step_id,
                          "tactics": g.tactics, "transitions": len(g.pairs)} for g in segs],
            "old": {"edges": len(edges(old_C)), "L": int(len(old_pairs)), "L_paper": OLD_L[a]},
            "new": {"edges": len(edges(new_C)), "L": int(len(new_pairs))},
            "edges_added": sorted(edges(new_C) - edges(old_C)), "edges_removed": sorted(edges(old_C) - edges(new_C)),
            "pairs_identical": bool(np.array_equal(old_pairs, new_pairs)),
            "counts_identical": bool(np.array_equal(old_C, new_C)),
            "reference_edges": sorted(edges(new_C)),
            "platform_handoffs": sm,
            "sensitivity": {"platform_split": variant_summary(old_C, len(old_pairs), split)},
        }
        if a == "menuPass":
            res["plans"][a]["sensitivity"]["optional_steps_separate"] = variant_summary(old_C, len(old_pairs),
                                                                                        menupass_optional_segments())
        res["multi_tactic"][a] = [ref.tactic_rule(s) for s in steps]
    res["sigma"] = sigma_crosswalk()
    write_crosswalk(res["sigma"])
    sha = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "-C", str(REPO), "status", "--porcelain", "--untracked-files=no"],
                                capture_output=True, text=True).stdout.strip())
    d = OUT / "gt_audit"
    d.mkdir(parents=True, exist_ok=True)
    (d / "config.yaml").write_text(yaml.safe_dump({
        "script": "scripts/revision/gt_audit.py", "git_sha": sha, "git_dirty": dirty, "seeds": [],
        "plans": "data/eval/plans/<actor>.yaml (SOURCES.txt: ael 5594518d..., ctid 4467a6ee...)",
        "sigma": {"tag": sigma_rules.SIGMA_TAG, "commit": sigma_rules.SIGMA_COMMIT},
        "old_L_paper": OLD_L, "menupass_optional": MENUPASS_OPTIONAL}, sort_keys=False))
    (d / "metrics.json").write_text(json.dumps(res, indent=1, default=list))
    print(json.dumps({a: {k: v for k, v in p.items() if k in ("old", "new", "pairs_identical", "sensitivity")}
                      for a, p in res["plans"].items()}, indent=1, default=list))
    print("sigma:", {k: v for k, v in res["sigma"].items() if k not in ("rows", "dropped")})
    return 0


if __name__ == "__main__":
    sys.exit(main())
