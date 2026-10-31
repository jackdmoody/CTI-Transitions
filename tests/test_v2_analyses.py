"""v2 analyses (POST HOC, 2026-10-31): unit checks on synthetic inputs, no data needed."""
import numpy as np

from ctit.eval import recovery
from ctit.experiments import evidence_audit, ig_dependence, paper_tables, v2_common as v2
from ctit.map.attack import TACTICS


def test_chance_table_matches_paper_table_a():
    rng = np.random.default_rng(0)
    G = np.zeros((14, 14))
    for i, j in [(0, 1), (1, 2), (2, 3), (3, 5), (5, 0), (7, 8)]:
        G[i, j] = 1
    order = paper_tables.chance_orderings(500, 3)
    ch = v2.ChanceTable(G, order)
    for k in (1, 6, 40, 182):
        C = np.zeros((14, 14))
        cells = np.argwhere(recovery.OFF_DIAG)[rng.choice(182, k, replace=False)]
        C[cells[:, 0], cells[:, 1]] = 1
        ref = paper_tables.chance_row(C, G, order)
        f1, kk = v2.f1_k(C, G)
        assert kk == k
        assert np.isclose(ch.mean[k], ref["chance_mean"])
        assert np.isclose(ch.percentile(f1, k), ref["percentile"])
    assert ch.ratio(0.0, 0) is None


def test_report_edges_rebuild_counts():
    reports = ["A-P01", "A-P02"]
    tr = [{"doc_id": "A-P01", "from_tactic": TACTICS[0], "to_tactic": TACTICS[1]},
          {"doc_id": "A-P01", "from_tactic": TACTICS[0], "to_tactic": TACTICS[1]},  # same edge twice: once
          {"doc_id": "A-P02", "from_tactic": TACTICS[0], "to_tactic": TACTICS[1]},
          {"doc_id": "A-P02", "from_tactic": TACTICS[2], "to_tactic": TACTICS[3]}]
    C = np.zeros((14, 14))
    C[0, 1], C[2, 3] = 2, 1
    E = v2.report_edges({"transitions": tr, "counts": C.tolist(), "meta": {"mode": "x", "actor": "A"}}, reports)
    assert E.shape == (2, 14, 14) and np.array_equal(E.sum(axis=0), C)
    assert np.array_equal(E[[1, 1]].sum(axis=0)[0, 1], 2)  # a report drawn twice counts twice


def test_circular_blocks():
    idx = ig_dependence.circular_blocks(7, 3, 50, np.random.default_rng(1))
    assert idx.shape == (50, 7) and idx.min() >= 0 and idx.max() < 7
    for row in idx:  # within each block of 3, consecutive indices mod 7
        for s in range(0, 6, 3):
            blk = row[s:s + 3]
            assert all((blk[i + 1] - blk[i]) % 7 == 1 for i in range(len(blk) - 1))


def test_status():
    assert v2.status(0.1, 0.5) == "above" and v2.status(-0.5, -0.1) == "below" and v2.status(-0.1, 0.1) == "spans"


def test_draw_spreads_quota():
    rows = [{"actor": "a"}] * 2 + [{"actor": "b"}] * 30 + [{"actor": "c"}] * 30
    out = evidence_audit.draw(rows, ["a", "b", "c"], 10, np.random.default_rng(0))
    got = {x: sum(r["actor"] == x for r in out) for x in "abc"}
    assert got == {"a": 2, "b": 4, "c": 4}
    assert len(evidence_audit.draw(rows, ["a", "b", "c"], "all", np.random.default_rng(0))) == 62


def test_closest_finds_paraphrased_passage():
    src = "Intro text. The actor then used PowerShell to download a second-stage loader from its server. End."
    passage, score = evidence_audit.closest("the actor used PowerShell to download a second stage loader", src)
    assert "PowerShell to download" in passage and score > 0.85
