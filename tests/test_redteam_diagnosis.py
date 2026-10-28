"""Case study B diagnosis helpers on synthetic data (no OpTC data)."""
import numpy as np
import pandas as pd
import pytest

from ctit.experiments import redteam_diagnosis as rd

K = ["Execution", "Defense Evasion"]


def test_entropy_bits():
    assert rd.entropy_bits(np.full((2, 2), 0.5)) == pytest.approx(1.0)
    assert rd.entropy_bits(np.eye(2)) == pytest.approx(0.0)


def test_scripted_hosts():
    assert rd.scripted("sysclient0051") and rd.scripted("sysclient0201") and not rd.scripted("sysclient0052")


def test_decompose_sums_to_score_difference():
    seqs = np.array([[0, 1, 1], [1, 1, 1]])
    y = np.array([True, False])
    d = np.array([[0.0, 2.0], [0.0, -1.0]])
    out = rd.decompose(seqs, y, d, K)
    assert out["positive"]["total"] == pytest.approx((2.0 - 1.0) / 2)  # 0->1 then 1->1, / 2 transitions
    assert out["negative"]["top"][0]["transition"] == "Defense Evasion -> Defense Evasion"
    assert out["negative"]["total"] == pytest.approx(-1.0)


def test_u_contrib_terms_sum_to_jsd():
    from ctit.experiments import redteam_scoring as rs
    seqs = np.array([[0, 1, 1, 0], [1, 1, 1, 1]])
    y = np.array([True, False])
    base = np.array([0.1, 0.2, 0.3, 0.4])
    out = rd.u_contrib(seqs, y, base, 0.5, K)
    u = rs.u_scores(seqs, base, 0.5)
    assert out["mean_u"]["positive"] == pytest.approx(u[0]) and out["mean_u"]["negative"] == pytest.approx(u[1])


def test_windows_keep_rules_and_cut_like_optc_redteam():
    from ctit.eval import optc_redteam
    t = pd.DataFrame({"Hostname": ["h"] * 17, "_timestamp": pd.date_range("2019-09-23", periods=17, freq="s", tz="UTC"),
                      "tactic": ["Execution"] * 17, "rule_id": [f"r{i}" for i in range(17)],
                      "malicious": [False] * 9 + [True] + [False] * 7})
    w = rd.windows(t)
    ref = optc_redteam.windows(t)
    assert len(w) == len(ref) == 2 and w["rules"][1][0] == "r8"
    assert w["positive"].tolist() == ref["positive"].tolist() == [False, True]


def test_decompose_splits_self_and_offdiagonal_parts():
    seqs = np.array([[0, 1, 1]])
    out = rd.decompose(seqs, np.array([True]), np.array([[0.0, 2.0], [0.0, -1.0]]), K)["positive"]
    assert out["offdiag_part"] == pytest.approx(1.0) and out["self_part"] == pytest.approx(-0.5)
    assert out["self_part"] + out["offdiag_part"] == pytest.approx(out["total"])
