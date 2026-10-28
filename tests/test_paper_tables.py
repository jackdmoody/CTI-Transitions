"""paper_tables: one shared chance draw (same k -> same chance), and its mean matches the hypergeometric."""
import numpy as np

from ctit.eval import recovery
from ctit.experiments import paper_tables as pt


def _edges(cells):
    C = np.zeros(recovery.OFF_DIAG.shape)
    for i, j in cells:
        C[i, j] = 1
    return C


def test_shared_draw_and_expectation():
    order = pt.chance_orderings(20000, 1)
    G = _edges([(0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6)])
    A, B = _edges([(0, 1), (2, 1), (3, 2)]), _edges([(6, 5), (7, 8), (9, 10)])  # same k = 3
    a, b = pt.chance_row(A, G, order), pt.chance_row(B, G, order)
    assert a["chance_mean"] == b["chance_mean"]
    k, g, n = 3, 6, recovery.N_OFF
    assert abs(a["chance_mean"] - 2 * (k * g / n) / (k + g)) < 0.003
    assert a["f1"] > b["f1"] == 0.0 and a["percentile"] > b["percentile"]


def test_no_edges():
    order = pt.chance_orderings(100, 1)
    r = pt.chance_row(np.zeros(recovery.OFF_DIAG.shape), _edges([(0, 1)]), order)
    assert (r["edges"], r["chance_mean"], r["f1_over_chance"]) == (0, 0.0, None)


def test_ollama_params(tmp_path):
    import json
    man = tmp_path / "models" / "manifests" / "registry.ollama.ai" / "library"
    (man / "m").mkdir(parents=True)
    (man / "m" / "t").write_text(json.dumps({"layers": [{"mediaType": "application/vnd.ollama.image.params",
                                                          "digest": "sha256:ab"}]}))
    (tmp_path / "models" / "blobs").mkdir()
    (tmp_path / "models" / "blobs" / "sha256-ab").write_text('{"temperature": 0.6}')
    assert pt.ollama_params("m:t", man) == ("sha256:ab", {"temperature": 0.6})
    assert pt.ollama_params("x:y", man) == (None, None)
