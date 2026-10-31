"""Report-level bootstrap for reading vs. remembering, R - B (POST HOC, 2026-10-31; Jack's final
coding pass, item 1). No model calls.

For each label in `pairs` (R and B priors of one model) and each actor, `n_boot` resamples:
- the actor's R reports (all its manifest prior documents, a report with no transitions included)
  are drawn with replacement, the same draw for every R sample; each sample's counts are rebuilt
  by Eq. 1 (each edge once per report, so a report drawn twice counts twice) and the prior is
  (C + alpha) as in the paper;
- a label with several R samples (F, Q5, M5) also has its samples drawn with replacement; a label
  with several B samples (B-F, B-Q5, B-M5) has its no-report samples drawn with replacement;
  a single-call B prior (B-Q, B-M, B-M3: temperature 0, one call) is held fixed;
- statistics, each the mean over the (resampled) samples:
  * edge-F1 / chance, chance from the shared draw of paper table a, keyed by edge-set size;
  * own-plan information gain in bits per transition at alpha (ctit.experiments.prior_likelihood),
    the plan's transitions held fixed (this interval is report-level only).
Also (POST HOC, 2026-10-31, after the bootstrap was seen to shift intervals down): a leave-one-report-out
jackknife of R - B (every R sample kept, B at its point estimate): min and max over replicates, the jackknife
SE and the 95% interval point +/- t(0.975, n - 1) SE; and the bootstrap median.
Reported: point estimates (no resampling; these are paper tables a/b and Table 3), and 95%
percentile intervals for R, B and R - B. A ratio is undefined when an edge set is empty (chance 0);
a sample with an undefined ratio is left out of its mean (as paper table a); resamples where every
sample is undefined are counted and left out of that interval. Each (label, actor) has its own
generator, seeded from (seed, label, actor), so adding a model to the config changes no other number.
"""
from __future__ import annotations

import zlib

import numpy as np

from ctit.experiments import v2_common as v2
from ctit.experiments.prior_likelihood import bits, conditional
from ctit.eval import recovery


def _ratio(C: np.ndarray, G: np.ndarray, ch: v2.ChanceTable) -> float:
    f1, k = v2.f1_k(C, G)
    r = ch.ratio(f1, k)
    return np.nan if r is None else r


def _nanmean(x) -> float:
    """Mean over samples, an undefined (empty-edge-set) sample left out, as paper table a."""
    x = np.asarray(x, dtype=float)
    return float(np.nanmean(x)) if (~np.isnan(x)).any() else np.nan


def _ig(C: np.ndarray, pr: np.ndarray, alpha: float) -> float:
    return float(bits(conditional(C, alpha), pr).mean())


def _ci(x: np.ndarray) -> dict:
    ok = x[~np.isnan(x)]
    if not len(ok):
        return {"ci95": None, "undefined_resamples": int(len(x))}
    return {"ci95": [float(np.percentile(ok, 2.5)), float(np.percentile(ok, 97.5))], "median": float(np.median(ok)),
            "undefined_resamples": int(np.isnan(x).sum())}


def jackknife(point: float, reps: np.ndarray) -> dict:
    """Leave-one-report-out: min and max of the replicates, SE = sqrt((n-1)/n * sum (theta_i - mean)^2), and the
    95% interval point +/- t(0.975, n-1) * SE."""
    from scipy.stats import t
    n = len(reps)
    if point is None or np.isnan(reps).any():
        return {"replicates": [None if np.isnan(x) else float(x) for x in reps], "min": None, "max": None,
                "se": None, "ci95": None}
    se = float(np.sqrt((n - 1) / n * ((reps - reps.mean()) ** 2).sum()))
    q = float(t.ppf(0.975, n - 1))
    return {"replicates": [float(x) for x in reps], "min": float(reps.min()), "max": float(reps.max()),
            "se": se, "t_quantile": q, "ci95": [point - q * se, point + q * se]}


def one(spec, actor: str, G: np.ndarray, pr: np.ndarray, ch: v2.ChanceTable, alpha: float,
        n_boot: int, rng: np.random.Generator) -> dict:
    """One label and actor; `rng` is seeded per (label, actor), so adding a label changes no other."""
    reports = v2.prior_reports(actor)
    R = v2.load(spec, "R", actor)
    E = np.stack([v2.report_edges(d, reports) for d in R])           # samples x reports x 14 x 14
    B = [np.array(d["counts"], dtype=float) for d in v2.load(spec, "B", actor)]
    stat = lambda Cs: (_nanmean([_ratio(C, G, ch) for C in Cs]), float(np.mean([_ig(C, pr, alpha) for C in Cs])))
    r_pt, b_pt = stat(E.sum(axis=1)), stat(B)
    B_ratio = np.array([_ratio(C, G, ch) for C in B])
    B_ig = np.array([_ig(C, pr, alpha) for C in B])
    nR, nS, nB = len(reports), len(R), len(B)
    boot = np.full((n_boot, 4), np.nan)  # R ratio, B ratio, R ig, B ig
    for b in range(n_boot):
        idx_r = rng.integers(0, nR, nR)
        idx_s = rng.integers(0, nS, nS) if nS > 1 else np.zeros(1, dtype=int)
        idx_b = rng.integers(0, nB, nB) if nB > 1 else np.zeros(1, dtype=int)
        Cs = E[idx_s][:, idx_r].sum(axis=1)
        boot[b, 0] = _nanmean([_ratio(C, G, ch) for C in Cs])
        boot[b, 1] = _nanmean(B_ratio[idx_b])
        boot[b, 2] = np.mean([_ig(C, pr, alpha) for C in Cs])
        boot[b, 3] = B_ig[idx_b].mean()
    # leave-one-report-out jackknife (POST HOC, 2026-10-31): every R sample kept, B at its point estimate;
    # computed after the bootstrap and from no generator, so the bootstrap numbers are unchanged
    jk = np.array([stat(E[:, np.arange(nR) != i].sum(axis=1)) for i in range(nR)])  # reports x (ratio, ig)
    pt = lambda x: None if x is None or np.isnan(x) else float(x)
    return {
        "reports": reports, "r_samples": nS, "b_samples": nB,
        "b_held_fixed": nB == 1, "r_samples_resampled": nS > 1,
        "f1_over_chance": {
            "R": {"point": pt(r_pt[0]), **_ci(boot[:, 0])}, "B": {"point": pt(b_pt[0]), **_ci(boot[:, 1])},
            "R_minus_B": {"point": (pt(r_pt[0] - b_pt[0]) if not (np.isnan(r_pt[0]) or np.isnan(b_pt[0])) else None),
                          **_ci(boot[:, 0] - boot[:, 1]),
                          "jackknife": jackknife(pt(r_pt[0] - b_pt[0]) if not (np.isnan(r_pt[0]) or np.isnan(b_pt[0])) else None,
                                                 jk[:, 0] - b_pt[0])}},
        "ig_bits": {
            "R": {"point": float(r_pt[1]), **_ci(boot[:, 2])}, "B": {"point": float(b_pt[1]), **_ci(boot[:, 3])},
            "R_minus_B": {"point": float(r_pt[1] - b_pt[1]), **_ci(boot[:, 2] - boot[:, 3]),
                          "jackknife": jackknife(float(r_pt[1] - b_pt[1]), jk[:, 1] - b_pt[1])}},
    }


def run(config: dict, calls=None) -> dict:
    order = v2.shared_chance(config)
    alpha = config["alpha"]
    out = {"note": "POST HOC (2026-10-31): report-level bootstrap of R - B; plan transitions held fixed",
           "n_boot": config["n_boot"], "seed": config["seed"], "alpha": alpha, "chance": config["chance"],
           "results": {}}
    for a in config["actors"]:
        G = recovery.ground_truth_counts(a, all_platforms=True)
        ch, pr = v2.ChanceTable(G, order), v2.plan_pairs(a)
        for label in config["pairs"]:
            rng = np.random.default_rng([config["seed"], zlib.crc32(label.encode()), zlib.crc32(a.encode())])
            out["results"].setdefault(label, {})[a] = one(config["priors"][label], a, G, pr, ch, alpha,
                                                          config["n_boot"], rng)
    return out
