"""Transition recovery (spec §6, T2, T4/H4): extracted priors vs. emulation-plan ground truth.

Ground truth (2026-10-27): each plan scenario's tactic sequence over ALL plan steps, every
platform (ctit.eval.plans, full 14-tactic space, no visibility filter; the Windows-only
variant is the appendix one) with consecutive repeated tactics collapsed
(Discovery, Discovery, Execution -> Discovery, Execution), then consecutive pairs counted.
Collapsing removes the self-transitions the extraction prompts forbid, so both sides live on
the 14 x 14 off-diagonal cells.

- Edge P/R/F1: binary edges, extracted count > 0 vs. ground-truth count > 0.
- JSD: between the two joint edge distributions over the off-diagonal cells, each
  (counts + alpha) normalized to sum 1 (natural log, in [0, ln 2]), as in ctit.eval.actor_jsd.
- Hallucinated-evidence rate is reported for report-conditioned priors only (ctit.cti.extract).
"""
from __future__ import annotations

import numpy as np

from ctit.adapters.drift import observational
from ctit.eval import actor_jsd, plans
from ctit.map.attack import TACTICS

OFF_DIAG = ~np.eye(len(TACTICS), dtype=bool)


def collapse(seq: list[str]) -> list[str]:
    return [t for i, t in enumerate(seq) if i == 0 or t != seq[i - 1]]


def ground_truth_counts(actor: str, all_platforms: bool = True) -> np.ndarray:
    steps = plans.load_plan(actor, platforms=None if all_platforms else ("windows",))
    seqs = [collapse(s) for s in plans.sequences(steps)]
    return actor_jsd.counts(seqs, list(TACTICS))


def edge_prf(extracted: np.ndarray, truth: np.ndarray) -> dict:
    e, g = (extracted > 0) & OFF_DIAG, (truth > 0) & OFF_DIAG
    tp = int((e & g).sum())
    p = tp / e.sum() if e.sum() else 0.0
    r = tp / g.sum() if g.sum() else 0.0
    return {"precision": p, "recall": r, "f1": 2 * p * r / (p + r) if p + r else 0.0,
            "edges_extracted": int(e.sum()), "edges_truth": int(g.sum()), "tp": tp}


def jsd(extracted: np.ndarray, truth: np.ndarray, alpha: float) -> float:
    a, b = extracted[OFF_DIAG] + alpha, truth[OFF_DIAG] + alpha
    return float(observational.jsd(a / a.sum(), b / b.sum()))


def matrix(priors: dict[str, np.ndarray], truths: dict[str, np.ndarray], alpha: float) -> dict:
    """H4 at the prior level: rows = prior actor, cols = plan actor; edge-F1 and JSD per cell,
    and per row the diagonal minus the best off-diagonal."""
    out = {"f1": {}, "jsd": {}, "diag_margin": {}}
    for ra, C in priors.items():
        out["f1"][ra] = {ca: edge_prf(C, G)["f1"] for ca, G in truths.items()}
        out["jsd"][ra] = {ca: jsd(C, G, alpha) for ca, G in truths.items()}
        if ra in truths and len(truths) > 1:
            others = [c for c in truths if c != ra]
            out["diag_margin"][ra] = {
                "f1": out["f1"][ra][ra] - max(out["f1"][ra][c] for c in others),
                "jsd": min(out["jsd"][ra][c] for c in others) - out["jsd"][ra][ra],  # > 0: diagonal closer
            }
    return out
