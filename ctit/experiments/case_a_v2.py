"""Case study A against the executed OTRF APT29 sequence, every Table 5 prior (POST HOC, 2026-10-31;
Jack's final coding pass, item 4). No model calls.

Executed sequence: ctit.experiments.otrf_case.executed_sequences (frozen v3, Sysmon only, per host and
day, repeats collapsed): 37 transitions. For every prior family in `families` and every actor's
prior of that family (the APT29 prior is the matched one; the others are off-target):
- information gain in bits per executed transition at alpha, with the 95% i.i.d. interval drawn
  exactly as ctit.experiments.prior_likelihood draws its case A resamples (so the existing case A
  numbers reproduce), and its status (above / below / spanning zero);
- edge-F1 against the executed edge set, F1 / chance and the chance percentile, chance from the
  shared draw of paper table a (keyed by edge-set size). Multi-sample priors: mean over samples.
"""
from __future__ import annotations

import numpy as np

from ctit.eval import actor_jsd
from ctit.experiments import otrf_case, v2_common as v2
from ctit.experiments.ig_dependence import per_transition
from ctit.experiments.prior_likelihood import pairs
from ctit.map import v3
from ctit.map.attack import TACTICS


def run(config: dict, calls=None) -> dict:
    alpha, actors = config["alpha"], config["actors"]
    seqs = list(otrf_case.executed_sequences(v3.load_v3()).values())
    executed, E = pairs(seqs), actor_jsd.counts(seqs, list(TACTICS))
    rng = np.random.default_rng(config["iid"]["seed"])  # prior_likelihood's draw order: plans, then case A
    for a in actors:
        rng.integers(0, len(v2.plan_pairs(a)), (config["iid"]["n_boot"], len(v2.plan_pairs(a))))
    boot = rng.integers(0, len(executed), (config["iid"]["n_boot"], len(executed)))
    ch = v2.ChanceTable(E, v2.shared_chance(config))
    out: dict = {"note": "POST HOC (2026-10-31): every Table 5 prior against the executed OTRF APT29 sequence",
                 "executed_transitions": int(len(executed)), "executed_edges": ch.g, "alpha": alpha, "cells": {}}
    for name in config["families"]:
        for a in actors:
            Cs = v2.family_counts(config, name, a)
            if not Cs:
                continue
            m = per_transition(Cs, executed, alpha)
            ci = [float(x) for x in np.percentile(m[boot].mean(axis=1), [2.5, 97.5])]
            f1k = [v2.f1_k(C, E) for C in Cs]
            ratios = [ch.ratio(f, k) for f, k in f1k]
            out["cells"].setdefault(name, {})[a] = {
                "bits": float(m.mean()), "ci95": ci, "status": v2.status(*ci), "samples": len(Cs),
                "edge_f1": float(np.mean([f for f, _ in f1k])), "edges": float(np.mean([k for _, k in f1k])),
                "f1_over_chance": (float(np.mean([r for r in ratios if r is not None]))
                                   if any(r is not None for r in ratios) else None),
                "percentile": float(np.mean([ch.percentile(f, k) for f, k in f1k]))}
    return out
