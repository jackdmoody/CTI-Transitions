"""Claims check: every number and clear / not-clear statement in the revised paper against its source. Read-only.

    python scripts/revision/claims_check.py

Checks, in order:
  1. Tables 2, 3, 5 (paper/tables/) are byte-identical to results/revision/final/main/, and the supplement
     (paper/w2_aics_supplement.tex) is byte-identical to a fresh build from results/revision/final/supplement/.
  2. The two inline tables (Table 1 actors, Table 4 specificity matrix).
  3. Every claim in the prose (anchor = exact substring of the .tex): numbers rounded half-up to the printed
     precision, and statuses (clear / not clear, above / below / spans) recomputed from the source.
  4. Coverage: every number in the prose that no claim anchor covers is listed, so nothing is skipped silently.

Revision results come from results/revision/final/ (claims.json, scenarios/*.json, case_a/, case_b/) and
docs/revision/facts.md. Numbers the revision did not recompute (corpus, mapper, go/no-go, OpTC counts, timing,
refusals, quote-failure rates) come from the runs listed in configs/paper_tables_v2.yaml and earlier runs, named
per row. Writes results/revision/final/claims_check.csv and prints the mismatches. No model calls.
"""
from __future__ import annotations

import csv
import io
import json
import math
import re
import sys
from collections import Counter
from contextlib import redirect_stdout
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path

import pandas as pd

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
TEX = REPO / "paper" / "w2_aics_draft_REVISED_v2.tex"
SUPTEX = REPO / "paper" / "w2_aics_supplement.tex"
FIN = REPO / "results" / "revision" / "final"
OUT = FIN / "claims_check.csv"
A = ["APT29", "OilRig", "Sandworm", "menuPass"]

SRC = TEX.read_text()
BODY = SRC[SRC.index("\\begin{abstract}"):SRC.index("\\bibliographystyle")]


def J(p):
    return json.loads((REPO / p).read_text())


CL = J("results/revision/final/claims.json")
C, CF, CS, CA_, CBv = CL["adopted"], CL["ev_fragments"], CL["ev_strict"], CL["var_A"], CL["var_B"]
SC = J("results/revision/final/scenarios/adopted.json")
SCF = J("results/revision/final/scenarios/ev_fragments.json")
SCB = J("results/revision/final/scenarios/var_B.json")
CASEA = J("results/revision/final/case_a/metrics.json")
CB_AS = J("results/revision/final/case_b/as_run/metrics.json")
CB_COL = J("results/revision/final/case_b/collapsed/metrics.json")
CB_SCR = J("results/revision/final/case_b/scripted/metrics.json")
EXT = "results/20261031T172438Z-extraction_report-16049f4/metrics.json"
E = J(EXT)
PT2 = "results/paper_tables_v2"
FAB = pd.read_csv(REPO / PT2 / "t_fabricated_evidence.csv")
H4T = pd.read_csv(REPO / PT2 / "t4_h4_tests.csv")
PH0 = J("results/revision/phase0/metrics.json")
GT = J("results/revision/gt_audit/metrics.json")
MAPPER_REPORT = "results/20261024T145254Z-mapper_report-714f999/metrics.json"
MAPPER_V3 = "results/20261027T021514Z-mapper_v3-ca50242/metrics.json"
WP5 = "results/20261027T023611Z-wp5_gate-a44d741/metrics.json"
BENIGN = "results/20261027T021709Z-benign_windows-e3e96e8/metrics.json"
RT_DIAG = "results/20261027T124122Z-redteam_diag-59998a9/metrics.json"
CB_DIAG = "results/20261028T044917Z-redteam_diagnosis-ce77e76/metrics.json"
OLD_AUDIT = REPO / "paper" / "number_audit.csv"
FACTS = (REPO / "docs" / "revision" / "facts.md").read_text()
ROWS: list[dict] = []
COVERED: list[tuple[int, int]] = []


# ----------------------------------------------------------------------------- helpers
def clean(s: str) -> str:
    s = s.replace("$-$", "-").replace("$+$", "+").replace("−", "-").replace("\\%", "").replace("%", "")
    s = re.sub(r"\\times|\$|\\,|×|,|\{|\}|\\", "", s)
    return s.strip().lstrip("+")


def rnd(x: float, nd: int) -> Decimal:
    return Decimal(repr(float(x))).quantize(Decimal(1).scaleb(-nd), rounding=ROUND_HALF_UP)


def same(paper: str, src: float, scale=1.0) -> bool:
    c = clean(paper)
    nd = len(c.split(".")[1]) if "." in c else 0
    r, p = rnd(src * scale, nd), Decimal(c)
    return r == p or (r == 0 and p == 0)


def anchor(a: str):
    i = BODY.find(a)
    if i >= 0:
        COVERED.append((i, i + len(a)))
    return i >= 0


def row(sec, claim, paper, src, path, match, note=""):
    if not claim.startswith("[") and not anchor(claim):
        note = (note + "; " if note else "") + "ANCHOR NOT FOUND in .tex"
        match = "no" if match == "yes" else match
    ROWS.append(dict(section=sec, claim=claim, paper=str(paper), source=str(src), source_path=path, match=match, note=note))


def num(sec, claim, paper, src, path, scale=1.0, note=""):
    row(sec, claim, paper, f"{src * scale:.6g}" if isinstance(src, float) else src, path,
        "yes" if src is not None and same(paper, src, scale) else "no", note)


def rng(sec, claim, paper, lo, hi, path, scale=1.0, note=""):
    a, b = re.split(r"--|–", paper.replace("$", ""))[:2]
    row(sec, claim, paper, f"{lo * scale:.6g}–{hi * scale:.6g}", path,
        "yes" if same(a, lo, scale) and same(b, hi, scale) else "no", note)


def ok(sec, claim, paper, cond: bool, src, path, note=""):
    row(sec, claim, paper, src, path, "yes" if cond else "no", note)


def ivl(sec, claim, paper_lo, paper_hi, lo, hi, path, note=""):
    row(sec, claim, f"[{paper_lo}, {paper_hi}]", f"[{lo:.4f}, {hi:.4f}]", path,
        "yes" if same(paper_lo, lo) and same(paper_hi, hi) else "no", note)


T5 = lambda lab, met: C[f"T5 {lab} {met}"]          # {actor: [point, boot, jack, clear]}
T5F = lambda lab, met: CF[f"T5 {lab} {met}"]
clear_above = lambda d: [a for a in A if d[a][3] == "above"]
clear_below = lambda d: [a for a in A if d[a][3] == "below"]
spans0 = lambda iv: iv[0] <= 0 <= iv[1]
CJ = "results/revision/final/claims.json"
SJ = "results/revision/final/scenarios/adopted.json"

# =============================================================================== 1. generated tables
for t in ("table2", "table3", "table5"):
    p, s = REPO / "paper" / "tables" / f"{t}.tex", FIN / "main" / f"{t}.tex"
    d = REPO / "docs" / "revision" / "tables" / f"{t}.tex"
    ok("Tables", f"[table] paper/tables/{t}.tex", "file", p.read_bytes() == s.read_bytes() == d.read_bytes(),
       "identical to final/main and docs/revision/tables", str(s.relative_to(REPO)))
import scripts.revision.make_supplement as MS  # noqa: E402

_tmp = REPO / "results" / "revision" / "final" / "_supplement_rebuild.tex"
MS.OUT = _tmp
with redirect_stdout(io.StringIO()):
    MS.main()
ok("Supplement", "[supplement] paper/w2_aics_supplement.tex", "file", _tmp.read_text() == SUPTEX.read_text(),
   "identical to a fresh build from final/supplement", "scripts/revision/make_supplement.py")
_tmp.unlink()
# supplement captions and intro: the few numbers that are not table bodies
supnums = {"20261105": "seed", "10,000": "N_BOOT", "2,017": "mapper rules", "707": "v3 rules", "37 transitions": "case A",
           "22 edges": "case A", "2.07": "case A", "1,000 resamples": "draft case B", "15 $\\to$ 12": "var A OilRig",
           "21 $\\to$ 19": "var A Sandworm", "four edges": "var B"}
sup = SUPTEX.read_text()
ok("Supplement", "[supplement] caption numbers", ", ".join(supnums), all(k in sup for k in supnums)
   and CASEA["executed_transitions"] == 37 and CASEA["executed_edges"] == 22 and same("2.07", CASEA["executed_vs_plan"]["ratio"])
   and SCB["reference"]["menuPass"]["edges"] == 4 and CA_["GT edges"]["OilRig"] == 12 and CA_["GT edges"]["Sandworm"] == 19
   and J(MAPPER_REPORT)["n_rules"] == 2017 and J(MAPPER_V3)["steps"]["c3_no_remote_thread"]["queries"] == 707,
   "case A 37/22/2.07; var B menuPass 4; var A 12/19; mapper 2017/707", "final/case_a, claims.json, mapper runs")

# =============================================================================== 2. inline tables
steps = {"APT29": 79, "OilRig": 44, "Sandworm": 40, "menuPass": 15}
t1 = SRC[SRC.index("\\begin{tabular}{@{}lllrr@{}}"):SRC.index("\\label{tab:actors}")]
for a in A:
    m = re.search(rf"^{a} & .*? & .*? & (\d+) & (\d+) \\\\", t1, re.M)
    ok("Table 1", f"[table] Table 1 {a} steps / GT edges", f"{m.group(1)} / {m.group(2)}",
       int(m.group(1)) == GT["plans"][a]["steps"] if "plans" in GT and "steps" in GT["plans"].get(a, {}) else int(m.group(1)) == steps[a],
       f"{steps[a]} / {C['GT edges'][a]}", "facts.md §5 (steps); claims.json GT edges")
    ok("Table 1", f"[table] Table 1 {a} GT edges", m.group(2), int(m.group(2)) == C["GT edges"][a], C["GT edges"][a], CJ)
t4 = SRC[SRC.index("\\begin{tabular}{@{}lcccc@{}}"):SRC.index("\\label{tab:h4}")]
for line in t4.splitlines():
    m = re.match(r"^(APT29|OilRig|Sandworm|menuPass) & (.*)\\\\", line)
    if m:
        for ca, v in zip(A, [clean(x.replace("\\textbf", "")) for x in m.group(2).split("&")]):
            num("Table 4", f"[table] Table 4 kernel {m.group(1)} x plan {ca}", "." + v.split(".")[1], E["h4"]["F"]["f1"][m.group(1)][ca], EXT)

# =============================================================================== 3. prose
S = "Abstract"
nrep = pd.read_csv(REPO / "data/cti/manifest.csv")
nrep = nrep[nrep.used_for == "prior"]
ok(S, "From 23 reports on four actors", "23", len(nrep) == 23 and nrep.actor.nunique() == 4, f"{len(nrep)} reports, {nrep.actor.nunique()} actors", "data/cti/manifest.csv")
ok(S, "approximately two to six times the edge precision", "2-6", 1.95 <= min(C["R-F ratio range"][0], C["R-G ratio range"][0])
   and max(C["R-F ratio range"][1], C["R-G ratio range"][1]) < 6.5, f"R-F {C['R-F ratio range']}, R-G {C['R-G ratio range']}", CJ,
   "F1/chance = precision enrichment (exact identity, s3a)")
ok(S, "Their mean information gain over uniform is positive on all four plans", "4/4 (F, G)",
   len(C["T3 R-F bits>0"]) == 4 and len(C["T3 R-G bits>0"]) == 4, f"F {C['T3 R-F bits>0']}; G {C['T3 R-G bits>0']}", CJ)
ok(S, "although several uncertainty intervals include zero", "several",
   sum(C["T3 R-F"][a][1] == "spans" for a in A) + sum(C["T3 R-G"][a][1] == "spans" for a in A) >= 2,
   f"spanning: F {[a for a in A if C['T3 R-F'][a][1] == 'spans']}, G {[a for a in A if C['T3 R-G'][a][1] == 'spans']}", CJ)
for lab in ("F", "G"):
    r, b = C[f"T2 R-{lab}"]["menuPass"], C[f"T2 B-{lab}"]["menuPass"]
    ok(S, "for menuPass, no-report outputs have higher edge-F1 and precision enrichment without an established likelihood advantage",
       f"{lab}: B>R on F1 and enrichment; IG not clear", b[0] > r[0] and b[1] > r[1] and T5(lab, "ig_bits")["menuPass"][3] == "not clear",
       f"R {r[:2]} B {b[:2]}; dIG {T5(lab, 'ig_bits')['menuPass']}", CJ)
q3, m3 = C["H3 Q"], C["H3 M"]
ok(S, "reaches at least 80\\% of Claude Opus's edge-F1 on three of four actors (not the same three)", "3, 3, differ",
   q3[1] == 3 and m3[1] == 3 and {a for a in A if q3[0][a] >= 80} != {a for a in A if m3[0][a] >= 80}, f"Q {q3}, M {m3}", CJ)
fq, fm, ff, fg = (FAB[FAB.model == k].fragment_aware for k in ("Q", "M", "F", "G"))
rng(S, "but 7--30\\% of their evidence quotations fail source matching", "7--30", min(fq.min(), fm.min()), max(fq.max(), fm.max()),
    f"{PT2}/t_fabricated_evidence.csv", scale=100, note="fragment_aware, Q and M at temperature 0")
num(S, "compared with at most 0.5\\% for the frontier models", "0.5", float(max(ff.max(), fg.max())), f"{PT2}/t_fabricated_evidence.csv", scale=100)

S = "Introduction"
ok(S, "predict edges at two to six times the precision of size-matched random edge sets", "2-6",
   1.95 <= C["R-F ratio range"][0] and C["R-F ratio range"][1] < 6.5 and 1.95 <= C["R-G ratio range"][0], "see abstract", CJ)
ok(S, "have positive mean information gain over the uniform chain on all four plans", "4/4", len(C["T3 R-F bits>0"]) == len(C["T3 R-G bits>0"]) == 4, "", CJ)
ok(S, "they outperform the tested ATT\\&CK frequency baseline", "F, G > ATTK on F1/chance and IG, every actor",
   all(C["T2 R-F"][a][1] > C["T2 ATTK"][a][1] and C["T2 R-G"][a][1] > C["T2 ATTK"][a][1]
       and C["T3 R-F"][a][0] > C["T3 ATTK"][a][0] and C["T3 R-G"][a][0] > C["T3 ATTK"][a][0] for a in A), "", CJ)
enr = {lab: clear_above(T5(lab, "f1_over_chance")) for lab in ("F", "G", "Q", "M")}
ok(S, "In precision enrichment, the reports clearly help for one of four actors under Claude Opus and each 14B model, and for none under GPT-6 Astra",
   "F 1, Q 1, M 1, G 0", [len(enr[k]) for k in ("F", "Q", "M", "G")] == [1, 1, 1, 0], enr, CJ)
igc = {lab: clear_above(T5(lab, "ig_bits")) for lab in ("F", "G", "Q", "Q5", "M", "M5", "M3")}
ok(S, "In likelihood, the reports' advantage is clear only for OilRig, under Claude Opus, GPT-6 Astra, and Ministral 14B",
   "OilRig: F, G, M only", igc == {"F": ["OilRig"], "G": ["OilRig"], "Q": [], "Q5": [], "M": ["OilRig"], "M5": [], "M3": []}, igc, CJ,
   "M3 APT29 is clearly negative (a disadvantage), not counted")
pair = {lab: C[f"paired IG {lab}"]["OilRig"][3] for lab in ("F", "G", "M")}
filt = {lab: T5F(lab, "ig_bits")["OilRig"][3] for lab in ("F", "G", "M")}
ok(S, "only Claude Opus's also survives resampling the plan's transitions and removing edges whose quotes fail", "F only",
   pair["F"] == "above" and filt["F"] == "above" and not (pair["G"] == "above" and filt["G"] == "above")
   and not (pair["M"] == "above" and filt["M"] == "above"), f"paired transition-level status {pair}; fragment-filtered clear {filt}", CJ)
ok(S, "including when edges with failed quotes are removed", "Q 3, M 3 (fragment and strict)",
   all(CL[k]["H3 Q"][1] == 3 and CL[k]["H3 M"][1] == 3 for k in ("ev_fragments", "ev_strict")),
   {k: (CL[k]["H3 Q"][1], CL[k]["H3 M"][1]) for k in ("ev_fragments", "ev_strict")}, CJ, "H3 vs Opus as run")
rng(S, "but 7--30\\% of their evidence quotes fail source matching", "7--30", min(fq.min(), fm.min()), max(fq.max(), fm.max()), f"{PT2}/t_fabricated_evidence.csv", scale=100)
num(S, "against at most 0.5\\% for the frontier models. We also", "0.5", float(max(ff.max(), fg.max())), f"{PT2}/t_fabricated_evidence.csv", scale=100)

S = "Model"
K, al = 14, 0.5
ok(S, "Let $\\mathcal{T}$ be the $K=14$ tactics", "14", len(E["tactics"]) == 14, len(E["tactics"]), EXT)
ok(S, "the other $K-1=13$ tactics", "13", True, 13, "(K-1)")
ok(S, "There are $K(K-1)=182$ possible transitions", "182", True, 182, "(K(K-1))")
ok(S, "with the pre-registered $\\alpha = 0.5$", "0.5", SC["settings"].get("alpha", 0.5) == 0.5, 0.5, SJ)
cap = lambda n: (n + al) / (n + (K - 1) * al)
num(S, "about 0.52 for $n_a=6$", "0.52", cap(6), "(formula)")
num(S, "or 2.8 bits for $n_a=6$", "2.8", math.log2((K - 1) * cap(6)), "(formula)")

S = "Method"
num(S, "$(1+\\alpha)/(1+(K-1)\\alpha)=0.20$", "0.20", cap(1), "(formula)")
num(S, "(1.38 bits above uniform)", "1.38", math.log2(13 * cap(1)), "(formula)")
npa = nrep.groupby("actor").size().to_dict()
rng(S, "against 0.48--0.56 for report kernels built from five to seven reports", "0.48--0.56", cap(min(npa.values())), cap(max(npa.values())),
    f"(formula; reports per actor {npa})")
ok(S, "built from five to seven reports", "5-7", (min(npa.values()), max(npa.values())) == (5, 7), npa, "data/cti/manifest.csv")
rng(S, "(2.64--2.85 bits)", "2.64--2.85", math.log2(13 * cap(5)), math.log2(13 * cap(7)), "(formula)")
ok(S, "we draw five generations per API model and one at temperature 0 per local model", "5 / 1",
   all(SC["t2"][f"B-{k}"][a]["samples"] == 5 for k in ("F", "G") for a in A) and all(SC["t2"][f"B-{k}"][a]["samples"] == 1 for k in ("Q", "M") for a in A),
   "t2 B-* samples", SJ)
ok(S, "Validate, then aggregate.} Output must parse", "40/222 M, 8/222 Q, 13/216 M3, 0 API", all(s in FACTS for s in (
    "Ministral 14B: 40 of 222 first attempts fail", "| Qwen 14B t0 (Q) | 37 | 1 | 1 |", "| Qwen 14B sampled (Q5, ×5) | 185 | 7 | 7 |",
    "| Ministral 3B t0 (M3) | 36 | 2 | 2 |", "| Ministral 3B sampled (M35, ×5) | 180 | 12 | 11 |", "| GPT-6 Astra (G, ×5) | 185 | 0 | 0 |",
    "| Claude Opus (F, ×5) | 185 | 1 | 0 |")), "facts.md §2: lost after retry Q 1+7=8/222, M 8+32=40/222, M3 2+11=13/216, F 0, G 0",
   "docs/revision/facts.md §2")
anchor("After the retry, 40 of 222 chunks still failed for Ministral 14B, 8 of 222 for Qwen 14B, 13 of 216 for Ministral 3B")

ok(S, "Each report is split into chunks of about 6,000 tokens with 300 tokens of overlap", "6000 / 300",
   "chunk: {tokens: 6000, overlap: 300}" in (REPO / "configs/extraction_report.yaml").read_text(), "chunk: {tokens: 6000, overlap: 300}", "configs/extraction_report.yaml")
ok(S, "requires every fragment of at least 8 characters", "8", "MIN_FRAGMENT = 8" in (REPO / "ctit/cti/extract.py").read_text(), "MIN_FRAGMENT = 8", "ctit/cti/extract.py")
r225 = [r for r in csv.DictReader(OLD_AUDIT.open()) if r["claim_text"] == "(counts up to 225)"]
ok(S, "under tactic $i$ (up to 225)", "225", bool(r225) and r225[0]["match"] == "yes", r225[0]["value_in_source"] if r225 else None,
   "paper/number_audit.csv @ a0bb280 (ctit/cti/prior.py attk_counts)", "not recomputed by the revision")
anchor("We expected a 14B open model to reach at least 80\\% of Claude Opus's edge-F1")
anchor("two 14B open-weight models each reach at least 80\\% of Claude Opus's edge-F1")
row(S, "[definition] 80% criterion (H3 threshold)", "80", "spec H3", "docs/W2_EXPERIMENT_SPEC.md", "yes", "threshold, not a result")

S = "Experimental design"
ok(S, "including the 26 steps whose technique maps to more than one tactic", "26 / 1 / no edge",
   "**26 steps**" in (REPO / "docs/revision/gt_audit.md").read_text() and "**1 step** has a non-tactic label" in (REPO / "docs/revision/gt_audit.md").read_text(),
   "gt_audit.md: 26 multi-tactic-technique steps, 1 non-tactic label; rule changes none", "docs/revision/gt_audit.md")
ok(S, "excluding them leaves four edges", "4", SCB["reference"]["menuPass"]["edges"] == 4, SCB["reference"]["menuPass"]["edges"], "scenarios/var_B.json")
ok(S, "We assembled 23 reports (2018--2025)", "23; 2018-2025", len(nrep) == 23, len(nrep), "data/cti/manifest.csv",
   "years not re-derived here (manifest publication dates; release/cti_manifest.csv)")
ok(S, "APT29 had seven reports, menuPass five, OilRig five, and Sandworm six", "7/5/5/6", npa == {"APT29": 7, "menuPass": 5, "OilRig": 5, "Sandworm": 6}, npa, "data/cti/manifest.csv")
cited = sum(sum(1 for l in (REPO / f"data/eval/plans/{a}_cited_sources.txt").read_text().splitlines() if l.strip() and not l.strip().startswith("#")) for a in A)
ok(S, "(204 links across the four plans)", "204", cited == 204, cited, "data/eval/plans/*_cited_sources.txt")
words = len((REPO / "data/cti/reports/Sandworm-P05.txt").read_text().split())
ok(S, "a 492-word landing page", "492", words == 492, words, "data/cti/reports/Sandworm-P05.txt")
r19b = [r for r in csv.DictReader(OLD_AUDIT.open()) if r["claim_text"].startswith("All but one (a 2019 APT29 report)")]
ok(S, "All but one report (a 2019 APT29 report) postdate the plan", "1 (2019, APT29)", bool(r19b) and r19b[0]["match"] == "yes",
   r19b[0]["note"][:80] if r19b else None, "paper/number_audit.csv @ a0bb280 (results/paper_tables/g_report_dates.csv)")
ok(S, "each extraction runs five times", "5", all(SC["t2"][f"R-{k}"][a]["samples"] == 5 for k in ("F", "G") for a in A), "t2 R-F/R-G samples", SJ)
ok(S, "(APT29 45, OilRig 17, Sandworm 25, menuPass 6)", "45/17/25/6", C["L"] == {"APT29": 45, "OilRig": 17, "Sandworm": 25, "menuPass": 6}, C["L"], CJ)
ok(S, "with 95\\% intervals from 10{,}000 resamples of transitions", "10,000", SC["settings"]["n_boot"] == 10000, SC["settings"]["n_boot"], SJ)
ok(S, "a block bootstrap that keeps blocks of 2, 3, or 5 transitions", "2, 3, 5", SC["settings"]["block_lengths"] == [2, 3, 5], SC["settings"]["block_lengths"], SJ)
ok(S, "Gap intervals come from 10{,}000 resamples of reports", "10,000", SC["settings"]["n_boot"] == 10000, SC["settings"]["n_boot"], SJ)
num(S, "distinct reports (3.4 of 5)", "3.4", 5 * (1 - (1 - 1 / 5) ** 5), "(formula)")
ok(S, "Claude Opus's OilRig IG was 0.30, 0.42, 0.53, and 0.62 bits with two to five distinct reports", "0.30/0.42/0.53/0.62",
   "| Claude Opus | 0.30 | 0.42 | 0.53 | 0.62 |" in FACTS, "facts.md §7.1 table", "docs/revision/facts.md §7.1")

S = "Results: match"
ok(S, "Claude Opus's report kernels reach 2.0--5.8 times chance", "2.0--5.8", same("2.0", C["R-F ratio range"][0]) and same("5.8", C["R-F ratio range"][1]), C["R-F ratio range"], CJ)
ok(S, "at or above the 99.7th percentile for every actor", "99.7", C["R-F min percentile"] >= 99.7, C["R-F min percentile"], CJ)
ok(S, "GPT-6 Astra's reach 2.2--3.3 times", "2.2--3.3", same("2.2", C["R-G ratio range"][0]) and same("3.3", C["R-G ratio range"][1]), C["R-G ratio range"], CJ)
ok(S, "at or above the 97th", "97", C["R-G min percentile"] >= 97, C["R-G min percentile"], CJ)
ok(S, "Both 14B models exceed chance for every actor", "ratio>1", not C["R-Q ratio<1"] and not C["R-M ratio<1"], "", CJ)
num(S, "Qwen 14B on OilRig (93rd percentile)", "93", C["R-Q below 95th"]["OilRig"], CJ)
num(S, "Ministral 14B on Sandworm (84th)", "84", C["R-M below 95th"]["Sandworm"], CJ)
ok(S, "fall short of the 95th", "only these two", list(C["R-Q below 95th"]) == ["OilRig"] and list(C["R-M below 95th"]) == ["Sandworm"], "", CJ)
ok(S, "Ministral 3B falls below chance on APT29", "APT29", C["R-M3 ratio<1"] == ["APT29"], C["R-M3 ratio<1"], CJ)
ok(S, "Claude Opus's and GPT-6 Astra's chains beat the uniform chain on all four plans", "4/4", len(C["T3 R-F bits>0"]) == len(C["T3 R-G bits>0"]) == 4, "", CJ)
ok(S, "clearly on two for Claude Opus (OilRig and menuPass)", "OilRig, menuPass", C["T3 R-F clear above"] == ["OilRig", "menuPass"], C["T3 R-F clear above"], CJ)
ok(S, "and on one for GPT-6 Astra (APT29;", "APT29", C["T3 R-G clear above"] == ["APT29"], C["T3 R-G clear above"], CJ)
g = SC["t3"]["R-G"]["OilRig"]["iid"]["ci95"]
ivl(S, "its OilRig interval, $[-0.01, 1.08]$, includes zero", "-0.01", "1.08", g[0], g[1], SJ)
ok(S, "Ministral 14B's beat it on three", "3", len(C["T3 R-M bits>0"]) == 3, C["T3 R-M bits>0"], CJ)
ok(S, "Qwen 14B's clearly only on menuPass", "menuPass", C["T3 R-Q clear above"] == ["menuPass"], C["T3 R-Q clear above"], CJ)
ok(S, "Ministral 3B's clearly only on menuPass while falling clearly below uniform on APT29", "menuPass / APT29",
   C["T3 R-M3 clear above"] == ["menuPass"] and C["T3 R-M3 clear below"] == ["APT29"], "", CJ)
ok(S, "sits at chance on edges (0.94--1.38 times", "0.94--1.38", same("0.94", C["ATTK ratio range"][0]) and same("1.38", C["ATTK ratio range"][1]), C["ATTK ratio range"], CJ)
ok(S, "for Sandworm its edge set is all 182 edges", "182", SC["t2"]["ATTK"]["Sandworm"]["edges_mean"] == 182, SC["t2"]["ATTK"]["Sandworm"]["edges_mean"], SJ)
ok(S, "and below uniform on every plan, clearly so for Sandworm and, under i.i.d.\\ resampling, APT29", "all <0; clear APT29, Sandworm; APT29 *",
   not C["T3 ATTK bits>0"] and C["T3 ATTK clear below"] == ["APT29", "Sandworm"] and C["T3 ATTK"]["APT29"][2] and not C["T3 ATTK"]["Sandworm"][2], "", CJ)

S = "Results: specificity"
att = {k: C[f"Attr {k}"][0] for k in ("R-F", "R-G", "R-M", "R-Q", "R-M3", "B-F", "B-G", "B-Q", "B-M")}
ok(S, "Claude Opus, GPT-6 Astra, and Ministral 14B attribute 3 of 4 plans correctly, Qwen 14B 1, and Ministral 3B none", "3,3,3,1,0",
   [att[k] for k in ("R-F", "R-G", "R-M", "R-Q", "R-M3")] == [3, 3, 3, 1, 0], att, CJ)
ok(S, "no-report kernels manage at most 2", "2", max(att[k] for k in ("B-F", "B-G", "B-Q", "B-M")) == 2, att, CJ)
ok(S, "both frontier models confuse APT29 and menuPass", "F APT29->menuPass, G menuPass->APT29",
   C["Attr R-F"][1] == {"APT29": "menuPass"} and C["Attr R-G"][1] == {"menuPass": "APT29"}, (C["Attr R-F"][1], C["Attr R-G"][1]), CJ)
col = dict(zip(H4T.prior, H4T.colwise_pass))
ok(S, "Edge overlap with each plan held fixed agrees (Claude Opus 3 of 4, GPT-6 Astra 4, Qwen 14B and Ministral 14B 3 each, Ministral 3B none)",
   "3,4,3,3,0", [col[k] for k in ("R-F", "R-G", "R-Q", "R-M", "R-M3")] == [3, 4, 3, 3, 0], col, f"{PT2}/t4_h4_tests.csv")

S = "Results: with vs without"
ef = {lab: T5(lab, "edge_f1") for lab in ("F", "G", "Q", "M")}
ok(S, "On raw edge-F1, the report-conditioned kernel scores higher for every actor except menuPass under Claude Opus and GPT-6 Astra, and for every actor under both 14B models",
   "F,G: + + + -; Q,M: all +", all(ef[l][a][0] > 0 for l in ("F", "G") for a in A[:3]) and all(ef[l]["menuPass"][0] < 0 for l in ("F", "G"))
   and all(ef[l][a][0] > 0 for l in ("Q", "M") for a in A), {l: [ef[l][a][0] for a in A] for l in ef}, CJ)
rng(S, "(1.2--3.3 times as many;", "1.2--3.3", *C["R/B edges (F,Q,M)"], CJ)
rng(S, "3.6--5.4 times for GPT-6 Astra)", "3.6--5.4", *C["R/B edges (G)"], CJ)
ok(S, "the reports clearly help only for OilRig under Claude Opus, for no actor under GPT-6 Astra, and for Sandworm under Qwen 14B and OilRig under Ministral 14B",
   "F OilRig; G none; Q Sandworm; M OilRig", enr == {"F": ["OilRig"], "G": [], "Q": ["Sandworm"], "M": ["OilRig"]}, enr, CJ)
apt = {l: T5(l, "f1_over_chance")["APT29"][1] for l in ("F", "G", "Q", "Q5", "M", "M5")}
ok(S, "every APT29 interval spans zero", "all span", all(spans0(v) for v in apt.values()), apt, CJ, "report-bootstrap intervals; M3 undefined (B empty)")
mp = {l: T5(l, "f1_over_chance")["menuPass"] for l in ("F", "G")}
ok(S, "On menuPass, the comparison reverses for both frontier models", "F, G < 0", mp["F"][0] < 0 and mp["G"][0] < 0, {l: v[0] for l, v in mp.items()}, CJ)
ok(S, "GPT-6 Astra's gap is clear (jackknife", "clear", mp["G"][3] == "below", mp["G"][3], CJ)
ivl(S, "(jackknife $[-6.87, -4.26]$)", "-6.87", "-4.26", *mp["G"][2], CJ)
lo, hi = C["T5 F menuPass LOO range"]
ok(S, "Claude Opus's is negative whichever report is left out ($-7.21$ to $-3.47$)", "-7.21 to -3.47", same("-7.21", lo) and same("-3.47", hi) and hi < 0, [lo, hi], CJ)
ok(S, "although its jackknife interval reaches zero", "jackknife spans 0", spans0(mp["F"][2]) and mp["F"][3] == "not clear", mp["F"][2], CJ)
num(S, "Claude Opus recalls on average 80\\% of the plan's six edges", "80", C["B-F menuPass recall, edges"][0], CJ)
num(S, "with about 13 predicted edges", "13", C["B-F menuPass recall, edges"][1], CJ)
q14 = {l: T5(l, "f1_over_chance")["menuPass"] for l in ("Q", "M")}
ok(S, "Neither 14B model shows a clear reversal.", "not clear", all(v[3] != "below" for v in q14.values()), {l: (v[0], v[3]) for l, v in q14.items()}, CJ)
for lab, p in (("F", "-0.4"), ("G", "-1.0"), ("Q", "+0.4"), ("M", "-0.8")):
    num(S, {"F": "are $-0.4$ for Claude Opus", "G": "$-1.0$ for GPT-6 Astra", "Q": "$+0.4$ for Qwen 14B", "M": "and $-0.8$ for Ministral 14B"}[lab],
        p, C[f"H2b rho {lab}"], CJ)
ok(S, "whose OilRig and Sandworm gaps are nearly equal", "~equal", abs(T5("Q", "f1_over_chance")["OilRig"][0] - T5("Q", "f1_over_chance")["Sandworm"][0]) < 0.05,
   (T5("Q", "f1_over_chance")["OilRig"][0], T5("Q", "f1_over_chance")["Sandworm"][0]), CJ)
for lab, an, p, l_, h_ in (("F", "Claude Opus ($+0.61$ bits per transition [0.07, 0.69])", "+0.61", "0.07", "0.69"),
                           ("G", "GPT-6 Astra ($+0.50$ [0.02, 0.66])", "+0.50", "0.02", "0.66"),
                           ("M", "Ministral 14B ($+0.56$ [0.16, 0.64])", "+0.56", "0.16", "0.64")):
    d = T5(lab, "ig_bits")["OilRig"]
    ok(S, an, f"{p} [{l_}, {h_}] clear", same(p, d[0]) and same(l_, d[1][0]) and same(h_, d[1][1]) and d[3] == "above", d, CJ)
pg = C["paired IG G"]["OilRig"]
ok(S, "does not exclude zero when the plan's transitions are resampled instead ($[-0.02, 1.00]$", "[-0.02, 1.00] spans",
   same("-0.02", pg[1][0]) and same("1.00", pg[1][1]) and pg[3] == "spans", pg[:2] + [pg[3]], CJ)
ok(S, "and Ministral 14B's does not survive removing edges whose quotes fail", "not clear", T5F("M", "ig_bits")["OilRig"][3] == "not clear",
   T5F("M", "ig_bits")["OilRig"], "claims.json ev_fragments")
ok(S, "Only Claude Opus's survives both.", "F", pair["F"] == "above" and filt["F"] == "above", (pair, filt), CJ)
mi = {l: T5(l, "ig_bits")["menuPass"] for l in ("F", "G")}
ok(S, "neither frontier model's likelihood difference excludes zero ($-0.09$ and $-0.01$)", "-0.09, -0.01, not clear",
   same("-0.09", mi["F"][0]) and same("-0.01", mi["G"][0]) and all(v[3] == "not clear" for v in mi.values()), mi, CJ)
r19 = [r for r in csv.DictReader(OLD_AUDIT.open()) if r["claim_text"] == "the 3B model returned an empty list in 19 of 24 calls"]
ok(S, "it returned an empty list in 19 of 24 calls", "19 of 24", bool(r19) and r19[0]["match"] == "yes" and r19[0]["value_in_source"] == "19",
   "19 (and 24 files)", "paper/number_audit.csv @ a0bb280 (data/priors/...-d032eae B_*.json)", "not recomputed by the revision")

S = "Results: small models"
for lab, an, vals in (("Q", "Qwen 14B reaches 96\\%, 52\\%, 91\\%, and 90\\% of it", ("96", "52", "91", "90")),
                      ("M", "Ministral 14B 90\\%, 95\\%, 45\\%, and 89\\%", ("90", "95", "45", "89"))):
    ok(S, an, "/".join(vals), [str(C[f"H3 {lab}"][0][a]) for a in A] == list(vals), C[f"H3 {lab}"][0], CJ)
ok(S, "so each meets the criterion for three of four actors, but not the same three", "3, 3", q3[1] == m3[1] == 3, "", CJ)
m3v = list(C["H3 M3"][0].values())
ok(S, "Ministral 3B meets it for none (36--76\\%)", "0; 36-76", C["H3 M3"][1] == 0 and (min(m3v), max(m3v)) == (36, 76), C["H3 M3"], CJ)
fs = lambda lab: [SC["t2"][lab][a]["edge_f1"] / SC["t2"]["R-F"][a]["edge_f1"] for a in A]
ok(S, "Sampled runs are weaker for Qwen 14B", "Q5 <= Q on 3+ actors", sum(x < y for x, y in zip(fs("R-Q5"), fs("R-Q"))) >= 3,
   [round(100 * x) for x in fs("R-Q5")], SJ, "qualitative; Q5 shares vs Q 96/52/91/90")
ok(S, "and mixed for Ministral 14B", "mixed", 0 < sum(x < y for x, y in zip(fs("R-M5"), fs("R-M"))) < 4, [round(100 * x) for x in fs("R-M5")], SJ, "qualitative")
r115 = [r for r in csv.DictReader(OLD_AUDIT.open()) if r["claim_text"] == "(up to 115 transitions from one chunk)"]
ok(S, "(up to 115 transitions from one chunk)", "115", bool(r115) and r115[0]["match"] == "yes", "115", "paper/number_audit.csv @ a0bb280", "not recomputed by the revision")
num(S, "The quote-match failure rate is at most .005 for Claude Opus", ".005", float(ff.max()), f"{PT2}/t_fabricated_evidence.csv")
ok(S, "and zero for GPT-6 Astra", "0", float(fg.max()) == 0, float(fg.max()), f"{PT2}/t_fabricated_evidence.csv")
rng(S, "but .07--.29 by actor for Qwen 14B", ".07--.29", float(fq.min()), float(fq.max()), f"{PT2}/t_fabricated_evidence.csv")
rng(S, ".20--.30 for Ministral 14B", ".20--.30", float(fm.min()), float(fm.max()), f"{PT2}/t_fabricated_evidence.csv")
f3 = FAB[FAB.model == "M3"].fragment_aware
rng(S, "and .50--.68 for Ministral 3B", ".50--.68", float(f3.min()), float(f3.max()), f"{PT2}/t_fabricated_evidence.csv")
ok(S, "failed the output schema on 40 of 222 chunks, none of which the retry recovered", "40/222, 0 recovered",
   "All 40 fail again on retry, so 40 chunks are lost" in FACTS, "facts.md §2", "docs/revision/facts.md §2")
ok(S, "leaves the frontier kernels essentially unchanged", "no status change for F, G",
   all(T5F(l, m)[a][3] == T5(l, m)[a][3] for l in ("F", "G") for m in ("edge_f1", "f1_over_chance", "ig_bits") for a in A)
   and all(CF[f"T3 R-{l}"][a][1] == C[f"T3 R-{l}"][a][1] for l in ("F", "G") for a in A), "", "claims.json ev_fragments")
ok(S, "the 14B models' structure result intact (same three actors", "same 3",
   {a for a in A if CF["H3 Q"][0][a] >= 80} == {a for a in A if q3[0][a] >= 80} and {a for a in A if CF["H3 M"][0][a] >= 80} == {a for a in A if m3[0][a] >= 80},
   (CF["H3 Q"], CF["H3 M"]), "claims.json ev_fragments")
ok(S, "but Qwen 14B's Sandworm gap and Ministral 14B's OilRig likelihood advantage no longer exclude zero", "both not clear",
   T5F("Q", "f1_over_chance")["Sandworm"][3] == "not clear" and T5F("M", "ig_bits")["OilRig"][3] == "not clear",
   (T5F("Q", "f1_over_chance")["Sandworm"], T5F("M", "ig_bits")["OilRig"]), "claims.json ev_fragments",
   "the bootstrap interval still excludes zero for Qwen Sandworm; the jackknife does not")
ok(S, "and attribution improves for Qwen 14B and Ministral 3B", "Q 1->2, M3 0->1", CF["Attr R-Q"][0] > C["Attr R-Q"][0] and CF["Attr R-M3"][0] > C["Attr R-M3"][0],
   (C["Attr R-Q"][0], CF["Attr R-Q"][0], C["Attr R-M3"][0], CF["Attr R-M3"][0]), "claims.json ev_fragments")
T = E["timing"]
t14 = [T["20261027T121707Z-extraction-a53c21c"][k]["sec_per_call"] for k in ("qwen3:14b", "qwen3:14b (sampled)")] + \
      [T["20261028T005130Z-extraction-5528fd6"][k]["sec_per_call"] for k in ("ministral-3-nosys:14b-instruct-2512-q4_K_M", "ministral-3-nosys:14b-instruct-2512-q4_K_M (sampled)")]
rng(S, "ran at 41--57\\,s per call for the 14B models", "41--57", min(t14), max(t14), EXT)
ok(S, "The local models refused nothing", "0", set(E["refusals"]) == {"F"}, list(E["refusals"]), EXT)
ok(S, "Claude Opus refused 11 of 185 calls", "11 of 185", "| Claude Opus (F, ×5) | 185 | 1 | 0 | 11 |" in FACTS, "facts.md §2", "docs/revision/facts.md §2")
ok(S, "including every sample of the OpTC red-team ground-truth document", "5/5", E["refusals"]["F"]["oracle#0"] == "5/5", E["refusals"]["F"]["oracle#0"], EXT)

S = "Case studies"
V3 = J(MAPPER_V3)
c3 = V3["steps"]["c3_no_remote_thread"]
ok(S, "(release r2026-07-01; 2,017 rules)", "2017", J(MAPPER_REPORT)["n_rules"] == 2017, J(MAPPER_REPORT)["n_rules"], MAPPER_REPORT)
ex = re.search(r"excludes \*\*(\d+) rules\*\*", (REPO / "docs/MAPPER_POLICY.md").read_text())
ok(S, "excluded 56 actor- or malware-specific rules", "56", ex and int(ex.group(1)) == 56, ex.group(1) if ex else None, "docs/MAPPER_POLICY.md")
ok(S, "(707 of 3,174 queries)", "707 / 3174", c3["queries"] == 707 and V3["steps"]["v2"]["queries"] == 3174, (c3["queries"], V3["steps"]["v2"]["queries"]), MAPPER_V3)
oc = c3["optc"]
rate = (oc["sysmon"]["tagged"] + oc["security"]["tagged"]) / (oc["sysmon"]["events"] + oc["security"]["events"])
ok(S, "tags $3\\times10^{-6}$ of benign events, in one tactic", "3e-6; 1", f"{rate:.0e}" == "3e-06" and len(oc["K"]) == 1, f"{rate:.3g}; {oc['K']}", MAPPER_V3)
vis = J(WP5)["jsd"]["alpha=0.0"]["visible_extended"]["n_transitions"]
ok(S, "leaves the injected chains 27, 3, 1, and 3 visible transitions per actor", "27,3,1,3 (APT29, OilRig, Sandworm, menuPass)",
   [vis[a] for a in A] == [27, 3, 1, 3], [vis[a] for a in A], WP5)
SPEC = (REPO / "docs/W2_EXPERIMENT_SPEC.md").read_text()
gng = "benign K = 2 (needed ≥ 4) and benign tag rate 2.4e-5 (needed ≥ 1e-4), and visible transitions were APT29 27, OilRig 3, menuPass 3, Sandworm 1 (needed ≥ 10 for every actor)"
ok(S, "raises the benign tag rate only to $2.4\\times10^{-5}$", "2.4e-5", gng in SPEC, "spec go/no-go record (candidate mapper v3h)", "docs/W2_EXPERIMENT_SPEC.md:28")
ok(S, "against thresholds of at least four benign tactics, a benign tag rate of at least $10^{-4}$, and at least ten visible transitions per actor",
   "4 / 1e-4 / 10", gng in SPEC, "needed ≥ 4, ≥ 1e-4, ≥ 10", "docs/W2_EXPERIMENT_SPEC.md:28")
ok(S, "the frozen mapper recovers 8 tactics and 37 transitions", "8 / 37", CASEA["executed_transitions"] == 37, CASEA["executed_transitions"], "final/case_a",
   "8 tactics and the four missing tactics: verified in paper/number_audit.csv @ a0bb280")
num(S, "matches the plan at 2.07$\\times$ chance", "2.07", CASEA["executed_vs_plan"]["ratio"], "final/case_a")
ce = CASEA["cells"]
num(S, "Claude Opus's APT29 kernel reaches 1.45$\\times$ chance", "1.45", ce["R-F"]["APT29"]["f1_over_chance"], "final/case_a")
ok(S, "no better than its OilRig kernel", "APT29 ~ OilRig", abs(ce["R-F"]["APT29"]["f1_over_chance"] - ce["R-F"]["OilRig"]["f1_over_chance"]) < 0.02,
   (ce["R-F"]["APT29"]["f1_over_chance"], ce["R-F"]["OilRig"]["f1_over_chance"]), "final/case_a")
num(S, "although GPT-6 Astra's (1.79$\\times$)", "1.79", ce["R-G"]["APT29"]["f1_over_chance"], "final/case_a")
oth = [ce["R-G"][a]["f1_over_chance"] for a in A[1:]]
rng(S, "beats its other actors' kernels (1.08--1.63$\\times$)", "1.08--1.63", min(oth), max(oth), "final/case_a")
at = ce["ATTK"]["APT29"]
ok(S, "($+0.76$ bits per transition, 95\\% interval $[0.50, 0.98]$)", "+0.76 [0.50, 0.98]", same("0.76", at["point"]) and same("0.50", at["iid"]["ci95"][0])
   and same("0.98", at["iid"]["ci95"][1]), (at["point"], at["iid"]["ci95"]), "final/case_a")
aboveA = [k for k in ce if ce[k]["APT29"]["iid"]["status"] == "above"]
ok(S, "the ATT\\&CK kernel is the only one clearly above uniform", "ATTK only (APT29 kernels)", aboveA == ["ATTK"], aboveA, "final/case_a",
   "among APT29 kernels; the ATTK OilRig and menuPass kernels are also clearly above: "
   + ", ".join(f"{k}/{a}" for k in ce for a in A[1:] if ce[k][a]["iid"]["status"] == "above"))
ok(S, "while the extracted chains sit at or below zero", "APT29 R/B points <= ~0", all(ce[k]["APT29"]["point"] < 0.02 for k in ce if k != "ATTK"),
   {k: round(ce[k]["APT29"]["point"], 3) for k in ce if k != "ATTK"}, "final/case_a",
   "max over other actors' extracted kernels: " + f"{max(ce[k][a]['point'] for k in ce if k != 'ATTK' for a in A):+.2f}")
for lab, an, p, l_, h_ in (("R-F", "Claude Opus $-0.12$ $[-0.34, 0.10]$", "-0.12", "-0.34", "0.10"),
                           ("R-G", "GPT-6 Astra $-0.04$ $[-0.28, 0.19]$", "-0.04", "-0.28", "0.19")):
    x = ce[lab]["APT29"]
    ok(S, an, f"{p} [{l_}, {h_}]", same(p, x["point"]) and same(l_, x["iid"]["ci95"][0]) and same(h_, x["iid"]["ci95"][1]), (x["point"], x["iid"]["ci95"]), "final/case_a")
ok(S, "The basis, 37 transitions from one recording", "37", CASEA["executed_transitions"] == 37, 37, "final/case_a")
RD = J(RT_DIAG)
ok(S, "235,698 events on the 29 red-team hosts are malicious", "235698 / 29", RD["totals"]["malicious_events"] == 235698 and CB_COL["hosts"] == 29,
   (RD["totals"]["malicious_events"], CB_COL["hosts"]), RT_DIAG)
num(S, "the mapper tags 160 of them (0.07\\%)", "0.07", RD["totals"]["tagged_malicious"] / RD["totals"]["malicious_events"], RT_DIAG, scale=100,
    note=f"tagged = {RD['totals']['tagged_malicious']}")
ok(S, "the mapper tags 160 of them", "160", RD["totals"]["tagged_malicious"] == 160, RD["totals"]["tagged_malicious"], RT_DIAG)
ok(S, "the test set has 4,428 windows of eight tagged events, 46 positive", "4428 / 8 / 46", CB_COL["windows"] == 4428 and CB_COL["positive"] == 46
   and J(BENIGN)["window"] == 8, (CB_COL["windows"], J(BENIGN)["window"], CB_COL["positive"]), "final/case_b/collapsed")
au = lambda m, k: m["conditions"][k]["point"]["auprc"]
rng(S, "which lets the ATT\\&CK kernel lead (AUPRC .19--.37)", ".19--.37", min(au(CB_AS, f"ATTK/{a}") for a in A), max(au(CB_AS, f"ATTK/{a}") for a in A), "final/case_b/as_run")
num(S, "a kernel built from all ATT\\&CK groups matches (.306)", ".306", au(CB_AS, "ATTK-all"), "final/case_b/as_run")
rng(S, "report kernels reach .28--.43 (Claude Opus)", ".28--.43", min(au(CB_COL, f"R-F/{a}") for a in A), max(au(CB_COL, f"R-F/{a}") for a in A), "final/case_b/collapsed")
rng(S, "and .18--.47 (GPT-6 Astra)", ".18--.47", min(au(CB_COL, f"R-G/{a}") for a in A), max(au(CB_COL, f"R-G/{a}") for a in A), "final/case_b/collapsed")
num(S, "against .18 for uniform", ".18", au(CB_COL, "Uni"), "final/case_b/collapsed")
orc = {k: au(CB_COL, k) for k in CB_COL["conditions"] if k.startswith("oracle")}
ok(S, "oracle kernels compiled from the red team's own ground truth by GPT-6 Astra and the local models stay at uniform", "~ .18",
   all(abs(v - au(CB_COL, "Uni")) < 0.03 for v in orc.values()), {k: round(v, 3) for k, v in orc.items()}, "final/case_b/collapsed",
   "'at uniform' read as within 0.03 AUPRC of Uni")
i1, i2 = CB_SCR["i_drop_xx01_xx51_hosts"], CB_SCR["ii_drop_scripted_rule_tags"]
au2 = lambda d, k: d["conditions"][k]["point"]["auprc"]
ok(S, "survives dropping the five hosts that run one scripted benign job", "5", len(i1["hosts_dropped"]) == 5, len(i1["hosts_dropped"]), "final/case_b/scripted")
DS = J(CB_DIAG)["d_scripted_removed"]["collapsed"]
share = 1 - (DS["i_drop_xx01_xx51_hosts"]["windows"] - DS["i_drop_xx01_xx51_hosts"]["positive"]) / (DS["primary"]["windows"] - DS["primary"]["positive"])
num(S, "91\\% of negative windows (.38--.68", "91", share, CB_DIAG, scale=100)
rng(S, "(.38--.68 against .19;", ".38--.68", min(au2(i1, f"R-F/{a}") for a in A), max(au2(i1, f"R-F/{a}") for a in A), "final/case_b/scripted")
num(S, ".38--.68 against .19; 29", ".19", au2(i1, "Uni"), "final/case_b/scripted")
ok(S, "29 positive windows remain", "29", i1["positive"] == 29, i1["positive"], "final/case_b/scripted")
ok(S, "vanishes when only that job's two rules are removed", "2", len(i2["rules"]) == 2, len(i2["rules"]), "final/case_b/scripted")
rng(S, "(.15--.19 against .15;", ".15--.19", min(au2(i2, f"R-F/{a}") for a in A), max(au2(i2, f"R-F/{a}") for a in A), "final/case_b/scripted")
num(S, ".15--.19 against .15; 45", ".15", au2(i2, "Uni"), "final/case_b/scripted")
ok(S, "45 remain", "45", i2["positive"] == 45, i2["positive"], "final/case_b/scripted")
s3g = pd.read_csv(FIN / "supplement" / "s3g_case_b_changes.csv")
pos = s3g[s3g.Windows == "positive"].set_index("Tactic changes")["count"]
ok(S, "11 of the 46 positive windows contain no tactic change", "11 of 46", int(pos[0]) == 11 and CB_COL["positive"] == 46, (int(pos[0]), CB_COL["positive"]), "supplement/s3g_case_b_changes")
ok(S, "and 7 contain one", "7", int(pos[1]) == 7, int(pos[1]), "supplement/s3g_case_b_changes")

S = "Discussion"
ok(S, "and this holds when the plan's two optional steps are removed", "var B: B > R on F1 and enrichment (F, G); IG not clear",
   all(CBv[f"T2 B-{l}"]["menuPass"][0] > CBv[f"T2 R-{l}"]["menuPass"][0] and CBv[f"T2 B-{l}"]["menuPass"][1] > CBv[f"T2 R-{l}"]["menuPass"][1]
       and CBv[f"T5 {l} ig_bits"]["menuPass"][3] == "not clear" for l in ("F", "G")), "", "claims.json var_B")
ok(S, "That neither 14B model shows the reversal", "no clear reversal", all(v[3] != "below" for v in q14.values()), "", CJ)
rng(S, "report the failure rate per model (7--30\\% for the 14B models)", "7--30", min(fq.min(), fm.min()), max(fq.max(), fm.max()), f"{PT2}/t_fabricated_evidence.csv", scale=100)
num(S, "one scripted job supplied 91\\% of the negative windows", "91", share, CB_DIAG, scale=100)
ok(S, "a quarter of OpTC's attack windows contain no tactic change at all", "1/4", abs(11 / 46 - 0.25) < 0.02, f"{11 / 46:.3f}", "supplement/s3g_case_b_changes")

S = "Limitations"
ok(S, "Ground truth is small (menuPass's plan yields six edges)", "6", C["GT edges"]["menuPass"] == 6, C["GT edges"]["menuPass"], CJ)
ok(S, "changes the status of nine cells", "9", len(C["T3 marks"]) == 9, len(C["T3 marks"]), CJ)
ok(S, "which leaves its plan four edges and lowers both 14B models to two of four actors on the 80\\% criterion while leaving the menuPass reversal intact",
   "4; Q 2, M 2; reversal", SCB["reference"]["menuPass"]["edges"] == 4 and CBv["H3 Q"][1] == 2 and CBv["H3 M"][1] == 2
   and all(CBv[f"T5 {l} f1_over_chance"]["menuPass"][0] < 0 for l in ("F", "G")), (CBv["H3 Q"][1], CBv["H3 M"][1]), "claims.json var_B")
ok(S, "cutting cross-platform handoffs (mainly OilRig)", "OilRig", CA_["GT edges"]["OilRig"] < C["GT edges"]["OilRig"], CA_["GT edges"], "claims.json var_A",
   "also Sandworm 21->19; the status changes are mainly OilRig")

# =============================================================================== 4. coverage
NUMRE = re.compile(r"(?<![A-Za-z0-9\\{_^.-])[-+]?\$?[-+]?\.?\d[\d,.]*")
IGNORE = re.compile(r"^(1|2|3|4|5|0|14|13|182)$")
MASK = BODY
for pat in (r"%[^\n]*", r"\\(?:cite[pt]?|label|ref|eqref|input|includegraphics|citep)\{[^}]*\}", r"APT29|GPT-6|Opus 5\.5|r2026-07-01|ATT\\&CK v18(?:\.1)?|\d+B\b|Qwen3|Ministral 3 ",
            r"\\begin\{tabular\}\{@\{\}lllrr@\{\}\}.*?\\end\{tabular\}", r"\\begin\{tabular\}\{@\{\}lcccc@\{\}\}.*?\\end\{tabular\}",
            r"\$[^$]*\\(?:frac|log_2|sum|bigl|mathcal|hat)[^$]*\$", r"\\begin\{equation\}.*?\\end\{equation\}"):
    MASK = re.sub(pat, lambda m: " " * len(m.group(0)), MASK, flags=re.S)
unc = []
for m in NUMRE.finditer(MASK):
    if any(a <= m.start() < b for a, b in COVERED):
        continue
    tok = clean(m.group(0)).strip(".")
    pre = MASK[max(0, m.start() - 40):m.start()]
    if not tok or IGNORE.match(tok) or re.search(r"(Eq\.~|Table~|Tables~|Figure~|Supplement Tables?~S|K=|n_a=|\$n_a=)\W*$", pre):
        continue
    ctx = BODY[max(0, m.start() - 60):m.end() + 30].replace("\n", " ")
    unc.append(dict(section="(coverage)", claim=ctx, paper=m.group(0), source="", source_path="", match="unchecked", note="number not under any claim anchor"))
ROWS.extend(unc)

with OUT.open("w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=["section", "claim", "paper", "source", "source_path", "match", "note"])
    w.writeheader()
    w.writerows(ROWS)
cnt = Counter(r["match"] for r in ROWS)
print(f"{len(ROWS)} rows: {dict(cnt)} -> {OUT.relative_to(REPO)}")
for r in ROWS:
    if r["match"] != "yes":
        print(f"[{r['match']}] {r['section']}: {r['claim'][:110]} | paper {r['paper']} | source {str(r['source'])[:120]} | {r['note'][:160]}")
