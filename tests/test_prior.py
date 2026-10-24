import numpy as np
import pytest

from ctit.cti import prior
from ctit.map import attack

HAVE_STIX = (attack.STIX_DIR / "enterprise-attack-18.1.json").exists()


def test_from_counts_and_uniform_rows_sum_to_one():
    P = prior.from_counts(np.zeros((14, 14)))
    np.testing.assert_allclose(P, prior.uniform())
    P = prior.from_counts(np.diag(np.arange(14)))
    np.testing.assert_allclose(P.sum(axis=1), 1.0)


def test_project_identity_when_all_observable():
    rng = np.random.default_rng(0)
    P = prior.from_counts(rng.integers(0, 5, (14, 14)))
    np.testing.assert_allclose(prior.project(P, prior.TACTICS), P)


def test_project_hand_example():
    # A -> B always, B -> C always, C -> A always; B unobservable => A -> C, C -> A.
    P = np.array([[0, 1, 0], [0, 0, 1], [1, 0, 0]], dtype=float)
    out = prior.project(P, ["A", "C"], tactics=["A", "B", "C"])
    np.testing.assert_allclose(out, [[0, 1], [1, 0]])
    # B loops on itself with 0.5 before leaving to C: still A -> C with probability 1.
    P2 = np.array([[0, 1, 0], [0, 0.5, 0.5], [1, 0, 0]], dtype=float)
    np.testing.assert_allclose(prior.project(P2, ["A", "C"], tactics=["A", "B", "C"]), [[0, 1], [1, 0]])


def test_project_rows_sum_to_one_on_smoothed_prior():
    rng = np.random.default_rng(1)
    P = prior.from_counts(rng.integers(0, 9, (14, 14)))
    keep = ["Execution", "Persistence", "Defense Evasion", "Credential Access", "Command and Control"]
    out = prior.project(P, keep)
    assert out.shape == (5, 5)
    np.testing.assert_allclose(out.sum(axis=1), 1.0)
    assert (out > 0).all()


@pytest.mark.skipif(not HAVE_STIX, reason="ATT&CK STIX not in data/attack_stix")
def test_attk_counts_apt29():
    C, meta = prior.attk_counts("G0016")
    assert meta["group_name"] == "APT29" and meta["n_techniques"] > 20
    n = np.array([meta["tactic_counts"][t] for t in prior.TACTICS])
    np.testing.assert_allclose(C, np.outer(n, n))
    P = prior.from_counts(C)
    np.testing.assert_allclose(P.sum(axis=1), 1.0)


def test_save_load_round_trip(tmp_path):
    P = prior.uniform()
    prior.save(tmp_path / "p.json", P, {"condition": "Uni"})
    Q, tactics, meta = prior.load(tmp_path / "p.json")
    np.testing.assert_allclose(P, Q)
    assert tactics == prior.TACTICS and meta == {"condition": "Uni"}
