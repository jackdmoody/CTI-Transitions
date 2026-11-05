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


# ----------------------------------------------------------------------------- enrichment identity

def test_exact_identity_and_mc_agreement():
    rng = np.random.default_rng(3)
    order = np.argsort(rng.random((20000, recovery.N_OFF)), axis=1)
    off = recovery.OFF_DIAG
    for g, k in [(6, 13), (15, 40), (28, 60), (21, 182)]:
        truth = np.zeros((14, 14))
        truth[np.nonzero(off)[0][:g], np.nonzero(off)[1][:g]] = 1
        ch = v2.ChanceTable(truth, order)
        cells = np.argwhere(off)
        C = np.zeros((14, 14))
        pick = cells[rng.choice(len(cells), k, replace=False)]
        C[pick[:, 0], pick[:, 1]] = 1
        r = recovery.edge_prf(C, truth)
        e = R.exact_chance(k, g, r["tp"])
        # identity: F1 / exact chance = precision / (g / 182) = TP / E[TP]
        assert e["ratio"] == pytest.approx(r["f1"] / e["mean_f1"])
        assert e["ratio"] == pytest.approx(r["precision"] / (g / 182))
        assert e["ratio"] == pytest.approx(r["tp"] / (k * g / 182))
        # Monte Carlo chance converges to the exact hypergeometric mean
        assert ch.mean[k] == pytest.approx(e["mean_f1"], rel=0.02)


def test_exact_percentile_full_edge_set_is_a_tie():
    # k = 182: every random set equals the prior's, so the percentile is 50 (all ties)
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


def test_reproduces_draft_opus(cfg):
    sc = R.scorecard(cfg, with_rb=False)
    f1 = [round(sc["t2"]["R-F"][a]["edge_f1"], 3) for a in R.ACTORS]
    ratio = [round(sc["t2"]["R-F"][a]["f1_over_chance"], 2) for a in R.ACTORS]
    ig = [round(sc["t3"]["R-F"][a]["bits"], 2) for a in R.ACTORS]
    assert f1 == [0.371, 0.396, 0.372, 0.300]
    assert ratio == [1.99, 3.23, 2.66, 5.79]
    assert ig == [0.11, 0.62, 0.31, 0.91]
    assert sc["attr"]["R-F"]["n"] == 3 and sc["attr"]["R-G"]["n"] == 3 and sc["attr"]["R-M"]["n"] == 3


def test_rb_reproduces_reading_bootstrap(cfg):
    import zlib
    ref = R.reference("OilRig")
    from ctit.experiments.paper_tables import chance_orderings
    ch = v2.ChanceTable(ref.G, chance_orderings(10000, 20261027))
    rng = np.random.default_rng([R.RB["seed"], zlib.crc32(b"F"), zlib.crc32(b"OilRig")])
    e = R.rb_one(R.r_tensor(cfg, "F", "OilRig"), R.b_counts(cfg, "F", "OilRig"), ref, ch, 0.5, R.RB["n_boot"], rng)
    g = e["ig_bits"]["R_minus_B"]
    assert round(g["point"], 2) == 0.61 and [round(x, 2) for x in g["ci95"]] == [0.07, 0.69]
    assert round(e["f1_over_chance"]["R_minus_B"]["point"], 2) == 1.87


def test_evidence_filter_only_removes(cfg):
    for lab in ("F", "M"):
        E0 = R.r_tensor(cfg, lab, "OilRig")
        for filt in ("fragments", "strict"):
            E1 = R.r_tensor(cfg, lab, "OilRig", filt)
            assert np.all(E1 <= E0)
    # GPT-6 Astra has no failing quote: filtering changes nothing
    assert np.array_equal(R.r_tensor(cfg, "G", "APT29", "strict"), R.r_tensor(cfg, "G", "APT29"))
