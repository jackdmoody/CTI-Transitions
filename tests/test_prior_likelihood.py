"""Prior log-likelihood (post hoc): bits over uniform per plan transition."""
import numpy as np
import pytest

from ctit.eval import plans, recovery
from ctit.experiments import prior_likelihood as pl
from ctit.map.attack import TACTICS


def test_uniform_scores_exactly_zero_and_rows_exclude_self():
    P = pl.conditional(np.zeros((14, 14)), 0.5)
    assert np.allclose(np.diag(P), 0) and np.allclose(P.sum(axis=1), 1)
    pr = np.array([[0, 1], [3, 2]])
    assert pl.bits(P, pr) == pytest.approx([0.0, 0.0])


def test_a_prior_on_the_truth_gains_bits():
    pr = np.array([[0, 1], [1, 2], [0, 1]])
    C = np.zeros((14, 14))
    C[0, 1], C[1, 2] = 10, 10
    rng = np.random.default_rng(0)
    out = pl.score([C, C], pr, 0.5, rng.integers(0, 3, (50, 3)))
    assert out["bits"] > 2 and out["mean_sd_over_samples"][1] == 0
    assert out["ci95"][0] <= out["bits"] <= out["ci95"][1]


def test_plan_transition_counts_match_ground_truth():
    for actor, n in {"APT29": 45, "OilRig": 17, "Sandworm": 25, "menuPass": 6}.items():
        seqs = [recovery.collapse(s) for s in plans.sequences(plans.load_plan(actor, platforms=None))]
        assert len(pl.pairs(seqs)) == n
        assert len(TACTICS) - 1 == 13
