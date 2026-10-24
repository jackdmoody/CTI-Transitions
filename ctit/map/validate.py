"""WP4b mapper report: K, benign tag rates, recall (spec §2.5). Public data only.

Ground truth used here is for validating the mapper and never feeds it:
  - OTRF APT29: the evals plan workbook (data/otrf/apt29/plan/apt29.xlsx). It has no
    per-event labels, so recall is per plan step on the step's victim host and day.
    Techniques are named with 2020 ATT&CK names, resolved with ATT&CK v6.3 and then
    revoked-by -> v18.1 IDs.
  - Splunk Attack Data atomic_red_team samples: each file is one technique.
Matching is at parent-technique level (T1003.001 counts for T1003) and, separately, at
tactic level. For the extended mapper an event carries every matching rule's techniques
and tactics; for the BRiMS mapper, its one technique and tactic.
"""
from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import pandas as pd

from ctit.map import attack
from ctit.map.coverage import brims_tag
from ctit.map.extended import tag as extended_tag
from ctit.map.sigma_rules import load_compiled

REPO_ROOT = Path(__file__).resolve().parents[2]
VICTIMS = {"scranton", "nashua", "utica", "newyork"}


def parent(tid: str) -> str:
    return tid.upper().split(".")[0]


def annotate(tagged: pd.DataFrame, mapper: str, rules_by_id: dict | None = None) -> pd.DataFrame:
    """Per event: sets of parent techniques and tactics the mapper assigns."""
    if mapper == "extended":
        techs, tacs = [], []
        for ids in tagged["rule_ids"]:
            t, a = set(), set()
            for rid in filter(None, ids.split(",")):
                t.update(parent(x) for x in rules_by_id[rid]["techniques"])
                a.update(rules_by_id[rid]["tactics"])
            techs.append(t)
            tacs.append(a)
    else:
        techs = [{parent(t)} if t else set() for t in tagged["technique"]]
        tacs = [{t} if t else set() for t in tagged["tactic"]]
    return pd.DataFrame({"host": tagged["host"].values, "techniques": techs, "tactics": tacs})


def pooled(ann: pd.DataFrame) -> dict[str, tuple[set, set]]:
    out: dict[str, tuple[set, set]] = defaultdict(lambda: (set(), set()))
    for host, t, a in zip(ann["host"], ann["techniques"], ann["tactics"]):
        out[host][0].update(t)
        out[host][1].update(a)
    return out


# --- OTRF APT29 plan -------------------------------------------------------------

def otrf_plan_steps(path: Path) -> tuple[list[dict], list[str]]:
    names = attack.technique_names("6.3")
    steps, unresolved = [], []
    for day, tcol, src, dst in (("day1", "Technique", "Source", "Target"),
                                ("day2", "Techniques", "Source Endpoint", "Target Endpoint")):
        sheet = pd.read_excel(path, sheet_name=day)
        for _, r in sheet.iterrows():
            if pd.isna(r[tcol]) or str(r["Step"]).strip() in ("0", "nan"):
                continue
            hosts = [h for col in (dst, src) for h in str(r[col]).lower().split() if h in VICTIMS]
            if not hosts:
                continue  # attacker-side or cloud step: no endpoint telemetry
            techniques = []
            for name in str(r[tcol]).replace("\n", ",").replace(";", ",").split(","):
                name = name.strip().lower()
                if not name:
                    continue
                tid = names.get(name)
                if tid is None:
                    unresolved.append(f"{day} {r['Step']}: {name}")
                    continue
                techniques.append(attack.current_id(tid))
            if techniques:
                tactics = sorted({t for tid in techniques for t in attack.technique_tactics(tid)})
                steps.append({"day": day, "step": str(r["Step"]).strip(), "host": hosts[0],
                              "techniques": sorted({parent(t) for t in techniques}), "tactics": tactics})
    return steps, unresolved


def step_recall(steps: list[dict], pooled_by_day: dict[str, dict]) -> dict:
    rows = []
    for s in steps:
        techs, tacs = pooled_by_day[s["day"]].get(s["host"], (set(), set()))
        rows.append({
            **s,
            "technique_hit": [t for t in s["techniques"] if t in techs],
            "tactic_hit": [t for t in s["tactics"] if t in tacs],
        })
    n_tech = sum(len(r["techniques"]) for r in rows)
    n_tac = sum(len(r["tactics"]) for r in rows)
    return {
        "steps": len(rows),
        "technique_recall": sum(len(r["technique_hit"]) for r in rows) / n_tech if n_tech else None,
        "tactic_recall": sum(len(r["tactic_hit"]) for r in rows) / n_tac if n_tac else None,
        "steps_with_any_technique_hit": sum(bool(r["technique_hit"]) for r in rows),
        "per_step": rows,
    }


# --- Report --------------------------------------------------------------------

def tag_both(df: pd.DataFrame, rules: list[dict]) -> dict[str, pd.DataFrame]:
    return {"extended": extended_tag(df, rules), "brims": brims_tag(df)}


def tactic_rates(tagged: pd.DataFrame) -> dict:
    """Primary-tactic tag rate per tactic, as a fraction of all events and per source."""
    out = {"events": int(len(tagged)), "by_source": {}, "by_tactic": {}}
    for source, g in tagged.groupby("source"):
        out["by_source"][source] = {"events": int(len(g)), "tag_rate": float((g["tactic"] != "").mean())}
    counts = tagged.loc[tagged["tactic"] != "", "tactic"].value_counts()
    out["by_tactic"] = {t: {"events": int(n), "rate": float(n / len(tagged))} for t, n in counts.items()}
    return out
