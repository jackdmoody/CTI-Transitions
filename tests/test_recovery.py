"""Transition recovery vs. plan ground truth (spec §6)."""
import numpy as np
import pytest

from ctit.eval import recovery
from ctit.map.attack import TACTICS

I = {t: i for i, t in enumerate(TACTICS)}


def _m(*edges):
    C = np.zeros((len(TACTICS), len(TACTICS)))
    for a, b in edges:
        C[I[a], I[b]] += 1
    return C


def test_collapse_consecutive_repeats():
    assert recovery.collapse(["Discovery", "Discovery", "Execution", "Discovery", "Discovery"]) == \
        ["Discovery", "Execution", "Discovery"]


def test_edge_prf_and_jsd():
    truth = _m(("Initial Access", "Execution"), ("Execution", "Persistence"))
    ext = _m(("Initial Access", "Execution"), ("Execution", "Discovery"))
    r = recovery.edge_prf(ext, truth)
    assert (r["tp"], r["precision"], r["recall"], r["f1"]) == (1, 0.5, 0.5, 0.5)
    assert recovery.jsd(truth, truth, 0.5) == pytest.approx(0.0, abs=1e-12)
    assert 0 < recovery.jsd(ext, truth, 0.5) < np.log(2)


def test_h4_matrix_diagonal_margin():
    tA, tB = _m(("Initial Access", "Execution")), _m(("Discovery", "Collection"))
    m = recovery.matrix({"A": tA, "B": tB}, {"A": tA, "B": tB}, 0.5)
    assert m["f1"]["A"] == {"A": 1.0, "B": 0.0} and m["diag_margin"]["A"]["f1"] == 1.0
    assert m["diag_margin"]["B"]["jsd"] > 0


def test_ground_truth_has_no_self_transitions():
    for actor in ("menuPass", "OilRig", "Sandworm"):
        G = recovery.ground_truth_counts(actor)
        assert G.trace() == 0 and G.sum() > 0


def test_ground_truth_all_platforms_default_with_windows_variant():
    for actor in ("OilRig", "Sandworm"):
        assert recovery.ground_truth_counts(actor).sum() > recovery.ground_truth_counts(actor, all_platforms=False).sum()


def test_chance_control_matches_hypergeometric_mean():
    rng = np.random.default_rng(0)
    # E[F1] = 2 E[tp] / (k + g), E[tp] = k g / 182
    k, g = 30, 20
    c = recovery.chance_f1(k, g, 20000, rng)
    assert c.mean() == pytest.approx(2 * (k * g / 182) / (k + g), rel=0.02)
    truth = _m(("Initial Access", "Execution"), ("Execution", "Persistence"))
    r = recovery.chance_control(truth, truth, 1000, rng)
    assert r["f1"] == 1.0 and r["percentile"] > 99 and r["f1_over_chance"] > 10
    assert recovery.chance_control(np.zeros_like(truth), truth, 10, rng)["f1_over_chance"] is None
