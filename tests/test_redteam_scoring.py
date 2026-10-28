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


def test_collapsed_pairs_drop_repeats():
    ki = {"Execution": 0, "Defense Evasion": 1, "Discovery": 2}
    w, a, b = rs.collapsed_pairs([["Defense Evasion"] * 8, ["Execution", "Execution", "Defense Evasion",
                                                             "Defense Evasion", "Discovery", "Discovery", "Execution", "Execution"]], ki)
    assert w.tolist() == [1, 1, 1] and list(zip(a, b)) == [(0, 1), (1, 2), (2, 0)]


def test_collapsed_scores_tie_windows_without_offdiag_transitions():
    pairs = (np.array([1]), np.array([0]), np.array([1]))
    P = rs.offdiag(np.full((2, 2), 0.5))
    s = rs.lr_scores_collapsed(2, pairs, P, P)
    assert s.tolist() == [0.0, 0.0]


def test_collapsed_prior_has_no_self_cell_and_uni_is_uniform():
    from ctit.map.attack import TACTICS
    K = [t for t in TACTICS if t != "Reconnaissance"]
    P = rs.collapsed_prior(np.zeros((14, 14)), 0.5, K)
    assert np.allclose(np.diag(P), 0) and np.allclose(P.sum(axis=1), 1)
    assert np.allclose(P[~np.eye(len(K), dtype=bool)], 1 / (len(K) - 1))
    C = np.zeros((14, 14)); C[TACTICS.index("Execution"), TACTICS.index("Persistence")] = 50
    Q = rs.collapsed_prior(C, 0.5, K)
    assert np.allclose(np.diag(Q), 0) and Q[K.index("Execution"), K.index("Persistence")] > 0.5


def test_tie_report_flags_threshold_inside_zero_block():
    y = np.array([False] * 1000 + [True] * 4)
    score = np.concatenate([np.zeros(995), np.ones(5), [0.0, 0.0, 2.0, -1.0]])
    r = rs.tie_report(score, y)
    assert r["zero_share_negative"] == 0.995 and r["zero_share_positive"] == 0.5
    b = r["threshold_inside_tie_block"]
    assert b["is_zero_block"] and b["below_side"]["fpr"] == 0.005 and b["above_side"]["fpr"] == 1.0
    assert b["below_side"]["det"] == 0.25 and b["above_side"]["det"] == 0.75
    assert "threshold_inside_tie_block" not in rs.tie_report(np.linspace(0, 1, 1004), y)
