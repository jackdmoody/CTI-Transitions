"""scripts/revision/make_supplement.py: column-spec parsing, longtable conversion, and the label -> S<n> order."""
from __future__ import annotations

import pytest

from scripts.revision import make_supplement as MS

TAB = "\\begin{tabular}{@{}llrrr@{}}\n\\toprule\nA & B & C & D & E \\\\\n\\midrule\n1 & 2 & 3 & 4 & 5 \\\\\n\\bottomrule\n\\end{tabular}"


def test_ncols_ignores_at_braces():
    assert MS.ncols(TAB) == 5


def test_longtable_keeps_spec_header_and_rows():
    out = MS.longtable(TAB, "tab:x", "cap")
    assert "\\begin{longtable}{@{}llrrr@{}}" in out
    assert out.count("A & B & C & D & E") == 2          # first head and repeated head
    assert "\\endfirsthead" in out and "\\endhead" in out
    assert "1 & 2 & 3 & 4 & 5" in out and "\\multicolumn{5}{l}" in out


def test_numbering_matches_paper_references():
    order = [label for _, _, tables in MS.SECTIONS for _, label, _ in tables]
    s = {label: f"S{i}" for i, label in enumerate(order, 1)}
    # the main paper cites these numbers (paper/w2_aics_draft_REVISED_v2.tex)
    assert [s["tab:s-evf-t2"], s["tab:s-evs-t5"]] == ["S2", "S7"]
    assert s["tab:s-h3-ev"] == "S8" and s["tab:s-varB-t2"] == "S9"
    assert s["tab:s-sigma"] == "S15" and s["tab:s-t5-all"] == "S18"
    assert len(order) == len(set(order)) == 22


def test_bodies_are_ascii_and_uncommented():
    if not (MS.SUPP / "s_case_b.tex").exists():
        pytest.skip("results/revision/final/supplement not present (gitignored)")
    for _, _, tables in MS.SECTIONS:
        for name, _, _ in tables:
            b = MS.body(name)
            assert b.startswith("\\begin{tabular}") and not any(l.lstrip().startswith("%") for l in b.splitlines())
