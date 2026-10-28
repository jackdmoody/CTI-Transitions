"""Case study A (spec §2.3b, T7; SPEC_ISSUES 2026-10-27): what mapper v3 recovers from the real
OTRF APT29 recording, against the APT29 plan, and how well each prior matches it.

- Executed sequence: OTRF APT29 day 1 and day 2, Sysmon only (§2.3b step 1), tagged with the
  frozen v3 rules; per host and day, tagged events in time order, consecutive repeated tactics
  collapsed (as the plan ground truth, ctit.eval.recovery), transitions counted and summed. The
  recording has no benign split, so background activity on the four hosts is included.
- Executed vs. plan: edge P/R/F1 against the APT29 plan ground truth (all steps), and against the
  plan projected onto K (the tactics v3 can emit; projected, then collapsed).
- Each prior vs. the executed edges: edge P/R/F1 with the edge-count chance control (post hoc
  control, ctit.eval.recovery.chance_control). Priors: APT29 R and B (F, S, S-sampled), ATTK, Uni,
  and the other actors' R priors as off-target rows. Multi-sample priors: mean over samples.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

from ctit.cti import prior
from ctit.eval import actor_jsd, plans, recovery
from ctit.experiments.redteam_scoring import PRIORS, reachable, run_dir
from ctit.map import v3
from ctit.map.attack import TACTICS
from ctit.map.extended import tag

REPO_ROOT = Path(__file__).resolve().parents[2]
OTRF = REPO_ROOT / "data" / "otrf" / "apt29" / "canonical"


def executed_sequences(rules: list[dict]) -> dict[str, list[str]]:
    """'<day>/<host>' -> collapsed tactic sequence."""
    out = {}
    for day in ("day1", "day2"):
        df = pd.read_parquet(OTRF / f"{day}.parquet")
        t = tag(df[df["source"] == "sysmon"], rules)
        t = t[t["tactic"] != ""].sort_values(["host", "ts"], kind="stable")
        for h, g in t.groupby("host"):
            out[f"{day}/{h}"] = recovery.collapse(g["tactic"].tolist())
    return out


def _summ(rows: list[dict]) -> dict:
    keys = ("f1", "precision", "recall", "edges_extracted", "chance_mean", "f1_over_chance", "percentile")
    return {k: (float(np.mean([r[k] for r in rows if r[k] is not None])) if any(r[k] is not None for r in rows) else None)
            for k in keys} | {"samples": len(rows)}


def run(config: dict, calls=None) -> dict:
    rules = v3.load_v3()
    K = reachable(rules)
    seqs = executed_sequences(rules)
    E = actor_jsd.counts(list(seqs.values()), list(TACTICS))
    plan = [recovery.collapse(s) for s in plans.sequences(plans.load_plan("APT29", platforms=None))]
    G = actor_jsd.counts(plan, list(TACTICS))
    GK = actor_jsd.counts([recovery.collapse(s) for s in actor_jsd.project_sequences(plan, K)], list(TACTICS))
    rng = np.random.default_rng(config["seed"])
    draws = config["draws"]
    vs_plan = {"plan_all": recovery.chance_control(E, G, draws, rng), "plan_on_K": recovery.chance_control(E, GK, draws, rng)}

    priors: dict[str, list[np.ndarray]] = {"ATTK/APT29": [prior.attk_counts("G0016")[0]],
                                           "Uni": [np.ones((len(TACTICS),) * 2)]}
    for mode, spec in config["runs"].items():
        run_id, sub = run_dir(spec)
        for cond in ("R", "B"):
            for a in config["actors"]:
                if cond == "B" and a != "APT29":
                    continue
                files = sorted((PRIORS / run_id / (sub or mode)).glob(f"{cond}_{a}_*.json"))
                if files:
                    priors[f"{cond}-{mode}/{a}"] = [np.array(json.loads(f.read_text())["counts"]) for f in files]
    vs_exec = {name: _summ([recovery.chance_control(C, E, draws, rng) for C in Cs]) for name, Cs in priors.items()}
    vs_plan_prior = {name: _summ([recovery.chance_control(C, G, draws, rng) for C in Cs])
                     for name, Cs in priors.items() if name.endswith("APT29") or name == "Uni"}
    edges = lambda M: sorted(f"{TACTICS[i]} -> {TACTICS[j]}" for i, j in zip(*np.nonzero(M * recovery.OFF_DIAG)))
    return {
        "K": K, "host_days": {k: len(v) for k, v in seqs.items()},
        "tactics_observed": sorted({t for s in seqs.values() for t in s}, key=TACTICS.index),
        "executed_transitions": int(E.sum()), "executed_edges": edges(E),
        "plan_edges": len(edges(G)), "plan_edges_on_K": len(edges(GK)),
        "executed_vs_plan": vs_plan, "executed_edges_in_plan": sorted(set(edges(E)) & set(edges(G))),
        "priors_vs_executed": vs_exec, "priors_vs_plan": vs_plan_prior,
        "draws": draws, "seed": config["seed"],
    }
