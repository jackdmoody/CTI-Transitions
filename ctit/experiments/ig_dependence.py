"""Dependence-aware intervals for own-plan information gain (POST HOC, 2026-10-31; Jack's final
coding pass, item 2). No model calls.

Table 5's intervals (ctit.experiments.prior_likelihood) resample a plan's transitions i.i.d. Here,
for every prior family in `families` at `alpha`, the same statistic (bits over uniform per own-plan
transition; multi-sample priors: the per-transition mean over samples, as in prior_likelihood) is
also bootstrapped with a circular block bootstrap over the plan's transition sequence:
- the sequence is the plan's collapsed transitions in plan order, scenario after scenario
  (ctit.experiments.v2_common.plan_pairs), treated as one circular sequence of length L, so a block
  may run across a scenario boundary or wrap from the end to the start;
- each resample concatenates ceil(L / b) blocks of b consecutive transitions with uniformly drawn
  starts and truncates to L; block lengths `block_lengths`.
The i.i.d. intervals are recomputed exactly as prior_likelihood draws them (same seed, same draw
order), so they reproduce Table 5. Every cell whose status (interval above zero, below zero, or
spanning zero) differs between the i.i.d. interval and any block interval is flagged.
"""
from __future__ import annotations

import zlib

import numpy as np

from ctit.experiments import v2_common as v2
from ctit.experiments.prior_likelihood import bits, conditional


def circular_blocks(L: int, b: int, n: int, rng: np.random.Generator) -> np.ndarray:
    """(n, L) indices of circular block-bootstrap resamples of a length-L sequence."""
    k = -(-L // b)
    starts = rng.integers(0, L, (n, k))
    return ((starts[:, :, None] + np.arange(b)) % L).reshape(n, k * b)[:, :L]


def per_transition(Cs: list[np.ndarray], pr: np.ndarray, alpha: float) -> np.ndarray:
    return np.mean([bits(conditional(C, alpha), pr) for C in Cs], axis=0)


def run(config: dict, calls=None) -> dict:
    alpha, actors = config["alpha"], config["actors"]
    plan = {a: v2.plan_pairs(a) for a in actors}
    # i.i.d. resamples exactly as prior_likelihood.run draws them
    rng = np.random.default_rng(config["iid"]["seed"])
    iid = {a: rng.integers(0, len(p), (config["iid"]["n_boot"], len(p))) for a, p in plan.items()}
    block = {(a, b): circular_blocks(len(p), b, config["block"]["n_boot"],
                                     np.random.default_rng([config["block"]["seed"], b, zlib.crc32(a.encode())]))
             for a, p in plan.items() for b in config["block"]["lengths"]}
    out: dict = {"note": "POST HOC (2026-10-31): circular block bootstrap of own-plan IG next to the i.i.d. intervals",
                 "alpha": alpha, "transitions": {a: len(p) for a, p in plan.items()},
                 "iid": config["iid"], "block": config["block"], "cells": {}, "flagged": []}
    for name in config["families"]:
        for a in actors:
            Cs = v2.family_counts(config, name, a)
            if not Cs:
                continue
            m = per_transition(Cs, plan[a], alpha)
            ci = lambda idx: [float(x) for x in np.percentile(m[idx].mean(axis=1), [2.5, 97.5])]
            cell = {"bits": float(m.mean()), "samples": len(Cs), "iid": {"ci95": ci(iid[a])}}
            cell["iid"]["status"] = v2.status(*cell["iid"]["ci95"])
            for b in config["block"]["lengths"]:
                c = ci(block[(a, b)])
                cell[f"block_{b}"] = {"ci95": c, "status": v2.status(*c)}
            changed = [b for b in config["block"]["lengths"] if cell[f"block_{b}"]["status"] != cell["iid"]["status"]]
            cell["status_changes_at_block"] = changed
            out["cells"].setdefault(name, {})[a] = cell
            if changed:
                out["flagged"].append({"prior": name, "actor": a, "iid": cell["iid"]["status"],
                                       **{f"block_{b}": cell[f"block_{b}"]["status"] for b in config["block"]["lengths"]}})
    return out
