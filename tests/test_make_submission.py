"""scripts/revision/make_submission.py: kit preamble verbatim, no hyperref/\\draftnote, one bib style (the kit's)."""
from __future__ import annotations

from scripts.revision import make_submission as MS

KIT = (
    "\\documentclass[letterpaper]{article} % DO NOT CHANGE THIS\n"
    "\\usepackage{aaai2027}  % DO NOT CHANGE THIS\n"
    "\\usepackage{natbib}  % DO NOT CHANGE THIS AND DO NOT ADD ANY OPTIONS TO IT\n"
    "\\setcounter{secnumdepth}{0} %May be changed\n"
    "\\title{Kit example}\n\\begin{document}\n\\end{document}\n"
)


def test_submission_uses_kit_preamble_and_drops_forbidden(tmp_path):
    (tmp_path / MS.KIT_TEMPLATE).write_text(KIT)
    out = MS.build(tmp_path)
    pre, body = out.split("\\title{", 1)
    assert KIT.split("\\title{")[0] in pre                       # kit preamble verbatim
    assert "Kit example" not in out                               # but not the kit's example body
    assert "\\title{Beyond CTI Reporting" in out
    for bad in ("hyperref", "\\draftnote", "aaai27-preview", "\\bibliographystyle"):
        assert bad not in out
    assert "\\bibliography{references}" in body and body.rstrip().endswith("\\end{document}")
    assert out.count("\\documentclass") == 1 and out.count("\\begin{document}") == 1
