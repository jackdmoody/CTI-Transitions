"""Assemble paper/w2_aics_supplement.tex from results/revision/final/supplement/*.tex (no computation).

    python scripts/revision/make_supplement.py

Each generated table body is inlined verbatim (its leading `%` comment dropped), so the supplement is one
self-contained file. Tables are numbered S1, S2, ... in the order of SECTIONS below; that order is what the
main paper's "Supplement Table S<n>" references point to. Prints the label -> number map.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
SUPP = REPO / "results" / "revision" / "final" / "supplement"
OUT = REPO / "paper" / "w2_aics_supplement.tex"

KEY = ("Kernel codes: R = report-conditioned, B = no report (actor name and aliases only), ATTK = ATT\\&CK-derived "
       "kernel. F = Claude Opus 5.5, G = GPT-6 Astra (API models; means of five runs), Q = Qwen3 14B, M = Ministral 3 14B "
       "(temperature 0), Q5 and M5 = the same models over five runs at default sampling, M3 = Ministral 3 3B.")

SECTIONS = [
    ("Evidence filtering",
     "The main analysis counts every schema-valid edge, whether or not its evidence quote matches the source. "
     "Here the report-conditioned kernels are rebuilt without edges whose quotes fail the fragment-aware check "
     "(the check described in the paper) or a strict whole-span check. B and ATTK kernels are unaffected. "
     "Each table shows the adopted value beside the filtered one.",
     [("s_evidence_shares", "tab:s-ev-shares",
       "Share of report-conditioned edges, and of count units (edge $\\times$ report support, summed over samples), "
       "that rest only on evidence quotes failing the fragment-aware or the strict check."),
      ("s_ev_fragments_t2", "tab:s-evf-t2",
       "Fragment-aware evidence filter: support recovery (cf.\\ main Table~2). Edge-F1, F1 $\\div$ chance (exact), "
       "and percentile against chance, adopted vs.\\ filtered."),
      ("s_ev_fragments_t3", "tab:s-evf-t3",
       "Fragment-aware evidence filter: information gain over uniform (cf.\\ main Table~3), with i.i.d.\\ 95\\% "
       "intervals (10,000 resamples of plan transitions), status, and segment-block marks (*), adopted vs.\\ filtered."),
      ("s_ev_fragments_t5", "tab:s-evf-t5",
       "Fragment-aware evidence filter: R$-$B gaps for every model (cf.\\ main Table~5 and Table~\\ref{tab:s-t5-all}), "
       "with report-bootstrap (10,000) and leave-one-report-out jackknife intervals for $\\Delta$F1 and "
       "$\\Delta$enrichment, and the paired transition-level i.i.d.\\ interval for $\\Delta$IG."),
      ("s_ev_strict_t2", "tab:s-evs-t2", "Strict whole-span evidence filter: support recovery (cf.\\ main Table~2)."),
      ("s_ev_strict_t3", "tab:s-evs-t3", "Strict whole-span evidence filter: information gain (cf.\\ main Table~3)."),
      ("s_ev_strict_t5", "tab:s-evs-t5", "Strict whole-span evidence filter: R$-$B gaps for every model (cf.\\ main Table~5)."),
      ("s_h3_evidence", "tab:s-h3-ev",
       "Each local model's edge-F1 as a share of Claude Opus's (the 80\\% criterion of the small-model comparison): "
       "as run, and under each evidence filter against Claude Opus filtered the same way or as run.")]),
    ("Ground-truth variants",
     "Two alternative readings of the plans, each scored with the same kernels. Variant B treats menuPass's two "
     "steps marked Optional (8.A and 7.1) as separate segments, which leaves the plan four edges. Variant A splits "
     "OilRig and Sandworm at every Linux/Windows handoff (OilRig 15 $\\to$ 12 edges, Sandworm 21 $\\to$ 19). "
     "Neither is adopted.",
     [("s_var_B_t2", "tab:s-varB-t2",
       "Variant B (menuPass optional steps as separate segments; four edges): support recovery, adopted vs.\\ variant."),
      ("s_var_B_t3", "tab:s-varB-t3", "Variant B: information gain over uniform, adopted vs.\\ variant."),
      ("s_var_B_t5", "tab:s-varB-t5", "Variant B: R$-$B gaps for every model, adopted vs.\\ variant."),
      ("s_var_A_t2", "tab:s-varA-t2",
       "Variant A (split at every Linux/Windows handoff): support recovery, adopted vs.\\ variant."),
      ("s_var_A_t3", "tab:s-varA-t3", "Variant A: information gain over uniform, adopted vs.\\ variant."),
      ("s_var_A_t5", "tab:s-varA-t5", "Variant A: R$-$B gaps for every model, adopted vs.\\ variant.")]),
    ("Tactic mapping",
     "",
     [("sigma_crosswalk", "tab:s-sigma",
       "SigmaHQ r2026-07-01 (\\texttt{rules/windows}) tags and the frozen tactic each maps to. Release: rules in the "
       "release carrying the tag; Mapper: rules in the compiled mapper (2,017 rules); Frozen v3: rules in the frozen "
       "subset evaluable on both eCAR and Sysmon (707); Decides (v3): v3 rules in which the tag is the first tactic tag, "
       "which sets an event's tactic. $^\\ast$: the release has no Defense Evasion tag, so these two tags map to it.")]),
    ("Resampling and chance",
     "",
     [("s3a_enrichment_exact", "tab:s-enrich",
       "F1 $\\div$ chance computed exactly (hypergeometric over the 182 edges) and checked against the identity "
       "F1 $\\div$ chance $=$ precision $\\div$ ($|E_g|/182$) for every kernel."),
      ("s3f_effective_smoothing", "tab:s-smooth",
       "Effective smoothing of Eq.~1 at $\\alpha=0.5$ per kernel: number of reports $n$, samples, largest row total, "
       "maximum attainable and fitted row concentration, in probability and in bits above uniform. The ATTK kernel "
       "has no report-count cap."),
      ("s_table5_all_models", "tab:s-t5-all",
       "R$-$B gaps for every model (exact chance; 10,000 resamples). For each of $\\Delta$F1, $\\Delta$enrichment "
       "(F1 $\\div$ chance) and $\\Delta$IG: the report-bootstrap and leave-one-report-out jackknife 95\\% intervals and "
       "whether the gap is clear (both exclude zero on the same side). For $\\Delta$IG, the paired interval from "
       "resampling plan transitions (i.i.d.\\ and blocks of 2/3/5 within scenarios) is also shown. B samples: number "
       "of no-report generations averaged."),
      ("s_table3_intervals_and_old_marks", "tab:s-t3-marks",
       "Information gain over uniform (main Table~3) with i.i.d.\\ 95\\% intervals (10,000 resamples), status under "
       "segment-respecting blocks of 2, 3 and 5, and the draft's earlier block marks (circular, crossing scenario "
       "boundaries), kept for comparison.")]),
    ("Case studies",
     "",
     [("s_case_a", "tab:s-case-a",
       "Case study A (OTRF recording of the APT29 emulation; 37 transitions, 22 edges): information gain over uniform "
       "with i.i.d.\\ 95\\% intervals (10,000 resamples) and block status, and support recovery against the executed "
       "sequence (exact chance). The executed sequence matches the plan at 2.07$\\times$ chance."),
      ("s_case_b", "tab:s-case-b",
       "Case study B (OpTC red team): AUPRC per run and condition with host-cluster bootstrap 95\\% intervals, "
       "draft (1,000 resamples) vs.\\ adopted (10,000). Point AUPRCs are identical in both."),
      ("s3g_case_b_changes", "tab:s-case-b-changes",
       "Case study B: number of tactic changes per test window, positive and negative windows.")]),
]

LONG = {"s_case_b"}

PREAMBLE = r"""%% Supplement to: Beyond CTI Reporting: Evaluating LLM-Compiled Threat Intelligence as Adversary Behavior Models
%% GENERATED by scripts/revision/make_supplement.py from results/revision/final/supplement/*.tex. Do not edit by hand.
\documentclass[letterpaper,10pt]{article}
\usepackage[margin=0.9in]{geometry}
\usepackage[T1]{fontenc}
\usepackage{times}
\usepackage{booktabs}
\usepackage{longtable}
\usepackage{pdflscape}
\usepackage{adjustbox}
\usepackage{amsmath,amssymb}
\usepackage[hidelinks]{hyperref}
\renewcommand{\thetable}{S\arabic{table}}
\newcommand{\supptable}[3]{%
  \begin{table}[!htbp]\centering\scriptsize
  \caption{#2}\label{#1}
  \begin{adjustbox}{max width=\linewidth, max totalheight=0.88\textheight}#3\end{adjustbox}
  \end{table}}

\title{Supplement to ``Beyond CTI Reporting: Evaluating LLM-Compiled Threat Intelligence as Adversary Behavior Models''}
\author{Jack Moody \and Iain Cruickshank}
\date{}

\begin{document}
\maketitle

All numbers use the paper's adopted settings: exact hypergeometric chance, 10,000 resamples for every bootstrap
(seed 20261105), and block resampling with blocks of 2, 3 or 5 consecutive transitions kept within one plan scenario.
No model calls were made for any table here; every table is recomputed from the cached extractions.
""" + KEY + "\n"


def body(name: str) -> str:
    lines = (SUPP / f"{name}.tex").read_text().splitlines()
    lines = [l for l in lines if not l.lstrip().startswith("%")]
    s = "\n".join(lines).replace("—", "--")
    if re.search(r"[^\x00-\x7F]", s):
        raise ValueError(f"non-ASCII left in {name}")
    return s


def ncols(tab: str) -> int:
    spec = re.search(r"\\begin\{tabular\}\{(.*)\}\s*$", tab, re.M).group(1)
    return len(re.sub(r"@\{\}|[^lcrp]", "", spec))


def longtable(tab: str, label: str, cap: str) -> str:
    spec = re.search(r"\\begin\{tabular\}\{(.*)\}\s*$", tab, re.M).group(1)
    inner = tab.split("\n", 1)[1].rsplit("\\end{tabular}", 1)[0].strip().splitlines()
    head_end = inner.index("\\midrule")
    head = "\n".join(inner[: head_end + 1])
    rest = "\n".join(inner[head_end + 1:])
    return (f"{{\\scriptsize\n\\begin{{longtable}}{{{spec}}}\n\\caption{{{cap}}}\\label{{{label}}}\\\\\n{head}\n\\endfirsthead\n"
            f"\\multicolumn{{{ncols(tab)}}}{{l}}{{Table~\\thetable\\ (continued)}}\\\\\n{head}\n\\endhead\n{rest}\n"
            f"\\end{{longtable}}}}\n")


def main() -> int:
    out, n, mapping = [PREAMBLE], 0, []
    for title, intro, tables in SECTIONS:
        out.append(f"\n\\clearpage\n\\section{{{title}}}\n{intro}\n")
        for name, label, cap in tables:
            n += 1
            mapping.append((f"S{n}", name, label))
            tab = body(name)
            if name in LONG:
                out.append("\\clearpage\n" + longtable(tab, label, cap))
            elif ncols(tab) > 9:
                out.append(f"\\begin{{landscape}}\n\\supptable{{{label}}}{{{cap}}}{{%\n{tab}}}\n\\end{{landscape}}\n")
            else:
                out.append(f"\\supptable{{{label}}}{{{cap}}}{{%\n{tab}}}\n")
    out.append("\n\\end{document}\n")
    OUT.write_text("".join(out))
    for m in mapping:
        print(*m)
    return 0


if __name__ == "__main__":
    sys.exit(main())
