"""Revision engine: segment-respecting block resampling, the enrichment identity, exact chance, and
reproduction of the draft's numbers from the cached priors."""
from __future__ import annotations

import numpy as np
import pytest
import yaml

from ctit.eval import recovery
from ctit.experiments import revision_engine as R
from ctit.experiments import v2_common as v2


# ----------------------------------------------------------------------------- block resampling

def _blocks_of(row: np.ndarray, b: int) -> list[np.ndarray]:
    return [row[i:i + b] for i in range(0, len(row), b)]


@pytest.mark.parametrize("b", [2, 3, 5])
def test_blocks_never_cross_a_segment_and_never_wrap(b):
    seg = np.array([0] * 33 + [1] * 12)  # APT29's two scenarios
    idx = R.segment_blocks(seg, b, 2000, np.random.default_rng(0))
    assert idx.shape == (2000, len(seg))
    for row in idx[:500]:
        for blk in _blocks_of(row, b):
            assert len(set(seg[blk])) == 1                      # one segment
            assert np.all(np.diff(blk) == 1)                    # consecutive, so no wrap-around
    # every admissible start is used; none outside
    starts = set(idx[:, ::b].ravel().tolist())
    admissible = {i for i in range(len(seg)) if i + b <= len(seg) and seg[i] == seg[i + b - 1]}
    assert starts == admissible
    assert R.admissible_blocks(seg, b) == len(admissible)


def test_short_segment_is_one_block():
    seg = np.array([0, 0, 1, 1, 1, 1, 1, 2])  # segments of length 2, 5, 1
    blocks = [b.tolist() for b in R.block_list(seg, 3)]
    assert blocks == [[0, 1], [2, 3, 4], [3, 4, 5], [4, 5, 6], [7]]
    idx = R.segment_blocks(seg, 3, 300, np.random.default_rng(1))
    assert idx.shape == (300, 8) and set(np.unique(idx)) == set(range(8))


def test_single_segment_menupass_degenerate():
    seg = np.zeros(6, dtype=int)
    assert R.admissible_blocks(seg, 5) == 2
    idx = R.segment_blocks(seg, 5, 100, np.random.default_rng(2))
    assert {tuple(r[:5]) for r in idx} <= {(0, 1, 2, 3, 4), (1, 2, 3, 4, 5)}


# ----------------------------------------------------------------------------- exact chance vs tie-fixed Monte Carlo

def _tie_fixed_mc(truth: np.ndarray, k: int, tp: int, draws: int, seed: int) -> tuple[float, float]:
    """The draft's shared-ordering Monte Carlo with ties compared on TP (integers), not on float F1."""
    order = np.argsort(np.random.default_rng(seed).random((draws, recovery.N_OFF)), axis=1)
    t = ((truth > 0) & recovery.OFF_DIAG)[recovery.OFF_DIAG]
    hits = t[order][:, :k].sum(axis=1)
    g = int(t.sum())
    return float((2 * hits / (k + g)).mean()), float(100 * ((hits < tp).mean() + 0.5 * (hits == tp).mean()))


@pytest.mark.parametrize("g,k,tp", [(6, 13, 4), (15, 24, 4), (28, 44, 10), (21, 182, 21), (15, 13, 1)])
def test_exact_chance_agrees_with_tie_fixed_mc(g, k, tp):
    truth = np.zeros((14, 14))
    off = np.argwhere(recovery.OFF_DIAG)[:g]
    truth[off[:, 0], off[:, 1]] = 1
    e = R.exact_chance(k, g, tp)
    mean_mc, pct_mc = _tie_fixed_mc(truth, k, tp, 40000, 7)
    assert mean_mc == pytest.approx(e["mean_f1"], rel=0.02)
    assert pct_mc == pytest.approx(e["percentile"], abs=1.0)


def test_identity_ratio_precision_tp():
    rng = np.random.default_rng(3)
    cells = np.argwhere(recovery.OFF_DIAG)
    for g, k in [(6, 13), (15, 40), (28, 60), (21, 182)]:
        truth = np.zeros((14, 14))
        truth[cells[:g, 0], cells[:g, 1]] = 1
        C = np.zeros((14, 14))
        pick = cells[rng.choice(len(cells), k, replace=False)]
        C[pick[:, 0], pick[:, 1]] = 1
        s = R.ExactChance(truth).score(C)
        assert s["ratio"] == pytest.approx(s["f1"] / s["chance_mean_f1"])
        assert s["ratio"] == pytest.approx(s["precision"] / (g / 182))
        assert s["ratio"] == pytest.approx(s["tp"] / (k * g / 182))


def test_full_edge_set_is_a_tie():
    assert R.exact_chance(182, 21, 21)["percentile"] == pytest.approx(50.0)
    assert R.exact_chance(182, 21, 21)["ratio"] == pytest.approx(1.0)


# ----------------------------------------------------------------------------- reproduction

@pytest.fixture(scope="module")
def cfg():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    c = yaml.safe_load((root / "configs" / "v2_priors.yaml").read_text())
    if not v2.prior_dir(c["priors"]["F"]).exists():
        pytest.skip("cached priors not present")
    return c


def test_reproduces_chance_independent_draft_numbers(cfg):
    sc = R.scorecard(cfg, with_rb=False)
    assert [round(sc["t2"]["R-F"][a]["edge_f1"], 3) for a in R.ACTORS] == [0.371, 0.396, 0.372, 0.300]
    assert [round(sc["t3"]["R-F"][a]["point"], 2) for a in R.ACTORS] == [0.11, 0.62, 0.31, 0.91]
    assert sc["attr"]["R-F"]["n"] == 3 and sc["attr"]["R-G"]["n"] == 3 and sc["attr"]["R-M"]["n"] == 3
    # exact ratios (Opus): TP / E[TP]
    assert [round(sc["t2"]["R-F"][a]["f1_over_chance"], 2) for a in R.ACTORS] == [1.99, 3.23, 2.65, 5.78]


def test_rb_ig_jackknife_reproduces_draft(cfg):
    ref = R.reference("OilRig")
    e = R.rb_one(R.r_tensor(cfg, "F", "OilRig"), R.b_counts(cfg, "F", "OilRig"), ref, R.ExactChance(ref.G), 50,
                 np.random.default_rng(0))
    g = e["ig_bits"]["R_minus_B"]
    assert round(g["point"], 2) == 0.61 and [round(x, 2) for x in g["jackknife"]["ci95"]] == [0.28, 0.94]


def test_evidence_filter_only_removes(cfg):
    for lab in ("F", "M"):
        E0 = R.r_tensor(cfg, lab, "OilRig")
        for filt in ("fragments", "strict"):
            assert np.all(R.r_tensor(cfg, lab, "OilRig", filt) <= E0)
    assert np.array_equal(R.r_tensor(cfg, "G", "APT29", "strict"), R.r_tensor(cfg, "G", "APT29"))
