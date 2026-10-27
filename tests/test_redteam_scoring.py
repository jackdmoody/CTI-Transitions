"""Case study B scorer on synthetic windows (no OpTC data)."""
import numpy as np
import pytest

from ctit.experiments import redteam_scoring as rs


def test_reachable_is_primary_tactics_in_tactic_order():
    rules = [{"tactics": ["Execution", "Persistence"]}, {"tactics": ["Initial Access"]}]
    assert rs.reachable(rules) == ["Initial Access", "Execution"]


def test_lr_prefers_adversary_transitions():
    P_ben = np.array([[0.9, 0.1], [0.1, 0.9]])
    P_adv = np.array([[0.1, 0.9], [0.9, 0.1]])
    seqs = np.array([[0, 0, 0, 0], [0, 1, 0, 1]])
    s = rs.lr_scores(seqs, P_adv, P_ben)
    assert s[1] > 0 > s[0]
    assert s[1] == pytest.approx(np.log(9))


def test_u_is_zero_for_the_baseline_itself_and_positive_otherwise():
    base = np.full(4, 0.25)
    s = rs.u_scores(np.array([[0, 1, 1, 0], [0, 0, 0, 0]]), base, alpha=1e6)
    assert s[0] == pytest.approx(0, abs=1e-6)
    assert rs.u_scores(np.array([[0, 0, 0, 0]]), base, alpha=0.5)[0] > 0.1


def test_metrics_threshold_and_ttd():
    y = np.array([False] * 200 + [True, True, True, True])
    host = np.array(["a"] * 200 + ["b", "b", "c", "c"])
    score = np.concatenate([np.linspace(0, 1, 200), [0.5, 2.0, 0.1, 0.2]])
    m = rs.metrics(score, y, host)
    assert m["det_1fpr"] == 0.25 and m["fpr_actual"] <= 0.01
    assert m["ttd"] == pytest.approx((0.5 + 1.0) / 2)  # b detected at its 2nd of 2, c never


def test_matrix_from_edge_counts():
    M = rs.matrix({"Execution|Discovery": 3, "Discovery|Discovery": 1}, ["Execution", "Discovery"])
    assert M.tolist() == [[0, 3], [0, 1]]
