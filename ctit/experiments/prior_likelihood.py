"""Priors scored as probabilistic models (POST HOC, 2026-10-27, SPEC_ISSUES). No model calls.

Score: mean over a plan's ground-truth transitions of log2(13 * P(next | current)), i.e. bits
gained per transition over the uniform chain. Transitions: each plan scenario's tactic sequence
over all plan steps, consecutive repeats collapsed (ctit.eval.recovery), with multiplicity.
P: the prior's counts + alpha over the 14 tactics, self-transition cell dropped, renormalized over
the other 13 (so Uni scores exactly 0). ATTK counts are n n^T (prior.attk_counts).
95% CI: bootstrap of transitions within each plan; multi-sample priors use the mean over samples,
with the same resampled transitions for every sample. Also: the 4x4 R-prior actor x plan matrix
per model (which actor's chain gives each plan the highest likelihood), alpha sensitivity, and
case study A (the executed OTRF APT29 sequence, ctit.experiments.otrf_case).
"""
from __future__ import annotations

import json

import numpy as np

from ctit.cti import prior
from ctit.cti.manifest import load_actors
from ctit.eval import plans, recovery
from ctit.experiments import otrf_case
from ctit.experiments.redteam_scoring import PRIORS, run_dir
from ctit.map import v3
from ctit.map.attack import TACTICS

IDX = {t: i for i, t in enumerate(TACTICS)}


def conditional(C: np.ndarray, alpha: float) -> np.ndarray:
    """(C + alpha) with the diagonal dropped, each row renormalized over the 13 other tactics."""
    A = np.asarray(C, dtype=float) + alpha
    np.fill_diagonal(A, 0.0)
    return A / A.sum(axis=1, keepdims=True)


def pairs(seqs: list[list[str]]) -> np.ndarray:
    """(n, 2) tactic-index pairs of consecutive steps, sequences already collapsed."""
    return np.array([(IDX[a], IDX[b]) for s in seqs for a, b in zip(s, s[1:])], dtype=int).reshape(-1, 2)


def bits(P: np.ndarray, pr: np.ndarray) -> np.ndarray:
    return np.log2((len(TACTICS) - 1) * P[pr[:, 0], pr[:, 1]])


def score(Cs: list[np.ndarray], pr: np.ndarray, alpha: float, boot: np.ndarray) -> dict:
    """Cs: one count matrix per sample; boot: (n_boot, n) resampled transition indices."""
    per = np.array([bits(conditional(C, alpha), pr) for C in Cs])  # samples x transitions
    m = per.mean(axis=0)
    out = {"bits": float(m.mean()), "ci95": [float(x) for x in np.percentile(m[boot].mean(axis=1), [2.5, 97.5])],
           "samples": len(Cs)}
    if len(Cs) > 1:
        s = per.mean(axis=1)
        out["mean_sd_over_samples"] = [float(s.mean()), float(s.std(ddof=1))]
    return out


def load_priors(config: dict) -> dict[str, dict[str, list[np.ndarray]]]:
    """'<cond>-<label>' -> actor -> count matrices (one per sample); plus ATTK and Uni."""
    groups = {a: v["attack_group"] for a, v in load_actors().items()}
    out: dict = {"ATTK": {a: [prior.attk_counts(groups[a])[0]] for a in config["actors"]},
                 "Uni": {a: [np.zeros((len(TACTICS),) * 2)] for a in config["actors"]}}
    for label, spec in config["runs"].items():
        run, sub = run_dir(spec)
        for cond in ("R", "B"):
            for a in config["actors"]:
                files = sorted((PRIORS / run / (sub or label)).glob(f"{cond}_{a}_*.json"))
                if files:
                    out.setdefault(f"{cond}-{label}", {})[a] = [np.array(json.loads(f.read_text())["counts"]) for f in files]
    return out


def run(config: dict, calls=None) -> dict:
    rng = np.random.default_rng(config["seed"])
    actors = config["actors"]
    plan_pairs = {a: pairs([recovery.collapse(s) for s in plans.sequences(plans.load_plan(a, platforms=None))])
                  for a in actors}
    executed = pairs(list(otrf_case.executed_sequences(v3.load_v3()).values()))
    boot = {a: rng.integers(0, len(p), (config["n_boot"], len(p))) for a, p in plan_pairs.items()}
    boot_exec = rng.integers(0, len(executed), (config["n_boot"], len(executed)))
    pri = load_priors(config)
    out: dict = {"note": "POST HOC (2026-10-27): bits over uniform per transition, log2(13 P)",
                 "transitions": {a: len(p) for a, p in plan_pairs.items()}, "executed_transitions": len(executed),
                 "alphas": config["alphas"], "own_plan": {}, "matrix": {}, "column_best": {}, "case_a": {}}
    for al in config["alphas"]:
        key = str(al)
        out["own_plan"][key] = {name: {a: score(Cs, plan_pairs[a], al, boot[a]) for a, Cs in by_a.items()}
                                for name, by_a in pri.items()}
        out["matrix"][key] = {name: {ra: {ca: score(Cs, plan_pairs[ca], al, boot[ca])["bits"] for ca in actors}
                                     for ra, Cs in by_a.items()}
                              for name, by_a in pri.items() if name.startswith("R-") and len(by_a) == len(actors)}
        out["column_best"][key] = {name: {ca: max(m, key=lambda ra: m[ra][ca]) for ca in actors}
                                   for name, m in out["matrix"][key].items()}
        out["case_a"][key] = {f"{name}/{a}": score(Cs, executed, al, boot_exec)
                              for name, by_a in pri.items() for a, Cs in by_a.items()}
    return out
