"""Audit every number in paper/w2_aics_draft.tex against the result files it was transcribed from.

Writes paper/number_audit.csv with columns
    section, claim_text, value_in_paper, value_in_source, source_path, source_field, match, note

- value_in_paper is the string as printed. Table cells are parsed from the .tex; for text claims the
  claim_text is an exact substring of the .tex and is checked to be present (a missing anchor is noted).
- value_in_source is always read (or recomputed) from the file by this script.
- match: "yes" if the source value rounded (half-up) to the paper's displayed precision equals the paper
  value; "rounding" if the paper value is a difference of rounded numbers that is one unit in the last
  place off the rounded exact difference; "no" otherwise; "no source" if nothing could be found.

Read-only: makes no model calls and edits no existing file. Run inside the w2 env:
    python scripts/number_audit.py
"""
from __future__ import annotations

import csv
import glob
import json
import math
import re
from collections import Counter
from decimal import ROUND_HALF_UP, Decimal
from pathlib import Path

import pandas as pd
import yaml

ROOT = Path(__file__).resolve().parents[1]
TEX = ROOT / "paper" / "w2_aics_draft.tex"
OUT = ROOT / "paper" / "number_audit.csv"
PT = "results/paper_tables"
EXT = "results/20261028T123410Z-extraction_report-ecf227b/metrics.json"
LIK = "results/20261028T123417Z-prior_likelihood-ecf227b/metrics.json"
CASEA = "results/20261028T044412Z-otrf_case-ce77e76/metrics.json"
CB_AS = "results/20261028T123535Z-redteam_scoring-ecf227b/metrics.json"
CB_COL = "results/20261028T123734Z-redteam_scoring-ecf227b/metrics.json"
CB_DIAG = "results/20261028T044917Z-redteam_diagnosis-ce77e76/metrics.json"
RT_DIAG = "results/20261027T124122Z-redteam_diag-59998a9/metrics.json"
SCHEMA = "results/20261028T122317Z-schema_failures-6b29976/metrics.json"
OPUS_CALLS = "results/20261027T121723Z-extraction-a53c21c/calls.jsonl"
MAPPER_REPORT = "results/20261024T145254Z-mapper_report-714f999/metrics.json"
MAPPER_V3 = "results/20261027T021514Z-mapper_v3-ca50242/metrics.json"
WP5 = "results/20261027T023611Z-wp5_gate-a44d741/metrics.json"
BENIGN = "results/20261027T021709Z-benign_windows-e3e96e8/metrics.json"
M3_PRIORS = "data/priors/20261028T040137Z-extraction-d032eae"
QWEN_PRIORS = "data/priors/20261027T223928Z-extraction-a686409"

ACTORS = ["APT29", "OilRig", "Sandworm", "menuPass"]
TEXT = TEX.read_text()
ROWS: list[dict] = []


# ----------------------------------------------------------------------------- helpers
def J(path):
    return json.loads((ROOT / path).read_text())


def csvf(name):
    return pd.read_csv(ROOT / PT / name)


def dline(path, pattern):
    """First line of a doc matching pattern -> (match object, 'path:line')."""
    for i, line in enumerate((ROOT / path).read_text().splitlines(), 1):
        m = re.search(pattern, line)
        if m:
            return m, f"{path}:{i}"
    return None, f"{path}: pattern not found"


def clean(s: str) -> str:
    s = s.replace("$-$", "-").replace("$+$", "+").replace("−", "-").replace("\u2212", "-")
    s = re.sub(r"\\textbf\{|\}|\\vf|\$|\\,|s$|%|\\%|×|\\times|,", "", s)
    return s.strip().lstrip("+")


def dec(s: str) -> tuple[Decimal, int]:
    c = clean(s)
    nd = len(c.split(".")[1]) if "." in c else 0
    return Decimal(c), nd


def rnd(x: float, nd: int) -> Decimal:
    return Decimal(repr(float(x))).quantize(Decimal(1).scaleb(-nd), rounding=ROUND_HALF_UP)


def same(paper: str, src: float, scale: float = 1.0) -> bool:
    p, nd = dec(paper)
    r = rnd(src * scale, nd)
    return r == p or (r == 0 and p == 0)


def fmt(x) -> str:
    if isinstance(x, (int,)) or (isinstance(x, float) and x.is_integer() and abs(x) > 1):
        return str(int(x))
    if isinstance(x, float):
        return f"{x:.6g}"
    return str(x)


def add(section, claim, paper, src, path, field, match, note=""):
    if claim not in TEXT and not claim.startswith(("[table]", "[supplement]", "[recomputed]")):
        note = (note + "; " if note else "") + "anchor text not found verbatim in .tex"
    ROWS.append(dict(section=section, claim_text=claim, value_in_paper=paper, value_in_source=src,
                     source_path=path, source_field=field, match=match, note=note))


def num(section, claim, paper, src, path, field, scale=1.0, note=""):
    if src is None:
        add(section, claim, paper, "", path, field, "no source", note)
        return
    add(section, claim, paper, fmt(src * scale if scale != 1 else src), path, field,
        "yes" if same(paper, src, scale) else "no", note)


def cnt(section, claim, paper, src, path, field, note=""):
    p = int(clean(str(paper)).split("/")[0]) if not isinstance(paper, int) else paper
    add(section, claim, str(paper), str(src), path, field, "yes" if int(src) == p else "no", note)


def rng(section, claim, paper, lo, hi, path, field, scale=1.0, note=""):
    a, b = re.split(r"--|–|-(?=\d|\.)", clean_range(paper))[:2]
    ok = same(a, lo, scale) and same(b, hi, scale)
    add(section, claim, paper, f"{fmt(lo * scale)}–{fmt(hi * scale)}", path, field, "yes" if ok else "no", note)


def clean_range(s):
    return s.replace("$", "").replace("\\times", "").replace("×", "").replace("\\%", "").replace("%", "")


def label_block(label):
    i = TEXT.index("\\label{" + label + "}")
    start = TEXT.rfind("\\begin{table", 0, i)
    return TEXT[start:i]


# ----------------------------------------------------------------------------- sources
A = csvf("a_support_recovery.csv")
IG = csvf("b_information_gain_own_plan.csv")
IGSRC = LIK  # own_plan[alpha][prior][actor]; same values as paper_tables b_information_gain_own_plan.csv, unrounded
ATTR = csvf("b_attribution_counts.csv")
FAB = csvf("c_fabricated_evidence.csv")
REF = csvf("d_refusals.csv")
DATES = csvf("g_report_dates.csv")
OPEN = csvf("f_open_models.csv")
E = J(EXT)
L = J(LIK)
MOD = yaml.safe_load((ROOT / "configs/models.yaml").read_text())
N14 = sum(1 for v in MOD["open_weight"].values() if str(v.get("parameters", "")).startswith(("13.", "14."))
          and v["tag"] in yaml.safe_load((ROOT / "configs/extraction_report.yaml").read_text())["ollama_labels"])
N3 = sum(1 for v in MOD["open_weight"].values() if str(v.get("parameters", "")).startswith("3.")
         and v["tag"] in yaml.safe_load((ROOT / "configs/extraction_report.yaml").read_text())["ollama_labels"])
N14F = ("configs/models.yaml", "count(open_weight models with parameters 13.x/14.x B that are in extraction_report ollama_labels)")
CASES = [CASEA, CB_COL]
THIN = len(re.findall(r"P0\d", dline("docs/W2_EXPERIMENT_SPEC.md", r"Sandworm-P04 and P05")[0].string.split(":")[0]))
THINF = dline("docs/W2_EXPERIMENT_SPEC.md", r"Sandworm-P04 and P05")[1]


def a_val(prior, actor, col):
    r = A[(A.prior == prior) & (A.actor == actor)]
    return float(r[col].iloc[0])


def ig_row(prior, actor, alpha=0.5):
    """Unrounded own-plan information gain (the paper_tables CSV is rounded to 4 dp)."""
    r = L["own_plan"][str(alpha)][prior][actor]
    return float(r["bits"]), float(r["ci95"][0]), float(r["ci95"][1])


CHANCE_KEY = {"R-F": "F/R", "R-Q": "S-Q/R", "R-Q5": "S-Q-sampled/R", "R-M": "S-M/R", "R-M5": "S-M-sampled/R", "R-M3": "S-M3/R",
              "B-F": "F/B", "B-Q": "S-Q/B", "B-M": "S-M/B", "ATTK": "baseline/ATTK"}


def f1_exact(prior, actor):
    """Unrounded edge-F1 from the extraction report (post_hoc.chance[...].f1.mean)."""
    return float(E["post_hoc"]["chance"][f"{CHANCE_KEY[prior]}/{actor}"]["f1"]["mean"])


def attr(prior, alpha=0.5):
    return int(ATTR[(ATTR.prior == prior) & (ATTR.alpha == alpha)].plans_own_actor_best.iloc[0])


def ratio_diff(model):
    return {a: a_val(f"R-{model}", a, "f1_over_chance") - a_val(f"B-{model}", a, "f1_over_chance") for a in ACTORS}


def first_calls(models):
    return int(REF[REF.model.isin(models)].first_attempt_calls.sum())


SCH = J(SCHEMA)


def schema_fail(modes):
    return sum(sum(SCH["counts"][m]["attempt1"].values()) for m in modes)


identical_mv = sum(1 for m in ("S-M", "S-M-sampled") for f in SCH["failures"][m]
                   if f["attempt"] == 1 and f["class"] == "multiple_values" and "(identical)" in f["detail"])
h3 = E["h3"]
q_pass = [a for a in ACTORS if h3["S-Q"][a]["s_over_f"] >= 0.8]
m_pass = [a for a in ACTORS if h3["S-M"][a]["s_over_f"] >= 0.8]
m3_max = max(h3[m][a]["s_over_f"] for m in ("S-M3", "S-M3-sampled") for a in ACTORS)
fab_t0 = FAB[FAB.model.isin(["Q", "M"])].fragment_aware
d3 = {m: ratio_diff(m) for m in ("F", "Q", "M")}
f_memory_ge = [a for a in ACTORS if d3["F"][a] <= 0.05]
r_f_lo_pos = sum(ig_row("R-F", a)[1] > 0 for a in ACTORS)
attk_ratio = [a_val("ATTK", a, "f1_over_chance") for a in ACTORS]
rf_ratio = [a_val("R-F", a, "f1_over_chance") for a in ACTORS]
rf_pct = min(a_val("R-F", a, "percentile") for a in ACTORS)

# =============================================================================== Abstract
S = "Abstract"
cnt(S, "using 23 reports that the plans do not cite", 23, int((pd.read_csv(ROOT / "data/cti/manifest.csv").used_for == "prior").sum()),
    "data/cti/manifest.csv", "count(used_for == prior)")
cnt(S, "ground truth for four actors", 4, A.actor.nunique(), f"{PT}/a_support_recovery.csv", "nunique(actor)")
rng(S, "recover plan transitions at 2.0--5.8$\\times$ an edge-count-matched chance level", "2.0--5.8",
    min(rf_ratio), max(rf_ratio), f"{PT}/a_support_recovery.csv", "f1_over_chance, prior R-F, min/max over actors")
cnt(S, "(95\\% intervals above zero for two of four)", 2, r_f_lo_pos, IGSRC,
    "count(ci95_lo > 0), prior R-F, alpha 0.5")
cnt(S, "for two of four actors, Opus's memory alone matches the plan about as well as the reports do", 2, len(f_memory_ge),
    f"{PT}/a_support_recovery.csv", "count(actors with R-F minus B-F f1_over_chance <= +0.05)",
    note="criterion 'about as well or better' operationalised as R-B <= 0.05; actors: " + ", ".join(f_memory_ge))
cnt(S, "Two 14B open-weight models", 2, N14, *N14F)
num(S, "each reach at least 80\\% of Opus's edge-F1", "80", 0.8, "docs/W2_EXPERIMENT_SPEC.md", "H3 threshold (definitional)",
    scale=100, note="threshold, not a result")
cnt(S, "for three of four actors (not the same three)", 3, min(len(q_pass), len(m_pass)), EXT,
    "h3.S-Q / h3.S-M .<actor>.s_over_f >= 0.8",
    note=f"Qwen passes {q_pass}, Ministral {m_pass}; sets differ: {set(q_pass) != set(m_pass)}")
rng(S, "fabricate 7--30\\% of their evidence quotes", "7--30", float(fab_t0.min()), float(fab_t0.max()),
    f"{PT}/c_fabricated_evidence.csv", "fragment_aware, models Q and M (temperature 0), min/max", scale=100)
num(S, "against at most 0.5\\% for Opus", "0.5", float(FAB[FAB.model == "F"].fragment_aware.max()),
    f"{PT}/c_fabricated_evidence.csv", "max fragment_aware, model F", scale=100)
add(S, "a 3B model never reaches 80\\%", "never reaches 80%", fmt(m3_max), EXT, "max h3.S-M3*/<actor>.s_over_f",
    "yes" if m3_max < 0.8 else "no")
num(S, "tags 0.07\\% of one intrusion's malicious events", "0.07",
    J(RT_DIAG)["totals"]["tagged_malicious"] / J(RT_DIAG)["totals"]["malicious_events"], RT_DIAG,
    "totals.tagged_malicious / totals.malicious_events", scale=100)
cnt(S, "In two case studies on public telemetry", 2, len(CASES), " ; ".join(CASES), "number of case-study runs (A, B)",
    note="structural count")

# =============================================================================== Introduction
S = "1 Introduction"
add(S, "for APT29 and menuPass, a strong model's memory already matches the ground truth at least as well as the reports do",
    "APT29, menuPass", ", ".join(f_memory_ge), f"{PT}/a_support_recovery.csv",
    "actors with R-F minus B-F f1_over_chance <= +0.05", "yes" if set(f_memory_ge) == {"APT29", "menuPass"} else "no",
    note=f"R-B: APT29 {d3['F']['APT29']:+.4f}, menuPass {d3['F']['menuPass']:+.4f}")
cnt(S, "Two 14B open models running locally each reach at least 80\\% of the frontier model's edge-F1 for three of four actors",
    3, min(len(q_pass), len(m_pass)), EXT, "h3.S-Q / h3.S-M s_over_f >= 0.8")
cnt(S, "\\item A leakage-controlled benchmark\\flag{F4}: four actors", 4, A.actor.nunique(), f"{PT}/a_support_recovery.csv", "nunique(actor)")
cnt(S, "a comparison of a frontier model against two 14B open-weight models and a 3B model", 2, N14, *N14F)
cnt(S, "a comparison of a frontier model against two 14B open-weight models and a 3B model", 1, N3, N14F[0], "count(open_weight 3.x B models in extraction_report)")

# =============================================================================== 3 Problem setup
S = "3 Problem Setup"
cnt(S, "We use the 14 Enterprise ATT\\&CK tactics", 14, len(E["tactics"]), EXT, "len(tactics)")
cnt(S, "there are 182 possible transitions", 182, len(E["tactics"]) * (len(E["tactics"]) - 1), EXT, "len(tactics)*(len(tactics)-1)")
cited = {a: sum(1 for l in (ROOT / f"data/eval/plans/{a}_cited_sources.txt").read_text().splitlines()
                if l.strip() and not l.strip().startswith("#")) for a in ACTORS}
wp5_cited = J(WP5)["cited_sources"]
cnt(S, "(204 links across the four plans\\vf)", 204, sum(cited.values()), "data/eval/plans/*_cited_sources.txt",
    "non-empty, non-comment lines, summed over actors",
    note=f"dagger; per actor {cited}; also {WP5} cited_sources sum = {sum(wp5_cited.values())}")

# =============================================================================== 4 Model
S = "4 Adversary Behavior Model"
K, n6, al = 14, 6, float(yaml.safe_load((ROOT / "configs/extraction_report.yaml").read_text())["alpha"])
cnt(S, "Let $\\mathcal{T}$ be the $K=14$ tactics", 14, len(E["tactics"]), EXT, "len(tactics)")
cnt(S, "the other $K-1=13$ tactics", 13, len(E["tactics"]) - 1, EXT, "len(tactics) - 1")
num(S, "$\\alpha=0.5$ is the Jeffreys prior", "0.5", al, "configs/extraction_report.yaml", "alpha")
cap = (n6 + al) / (n6 + (K - 1) * al)
num(S, "about 0.52 for $n_a=6$ and $\\alpha=0.5$", "0.52", cap, "(formula)", "(n+alpha)/(n+(K-1)alpha), n=6, alpha=0.5 (config), K=14",
    note="recomputed from the formula")
num(S, "or 2.8 bits for $n_a=6$", "2.8", math.log2((K - 1) * cap), "(formula)", "log2((K-1)(n+alpha)/(n+(K-1)alpha)), n=6, alpha=0.5, K=14",
    note="recomputed from the formula, in bits")

# =============================================================================== 5 Method
S = "5 Method"
ER = yaml.safe_load((ROOT / "configs/extraction_report.yaml").read_text())
num(S, "chunks of about 6,000 tokens", "6000", ER["chunk"]["tokens"], "configs/extraction_report.yaml", "chunk.tokens")
num(S, "with 300 tokens of overlap", "300", ER["chunk"]["overlap"], "configs/extraction_report.yaml", "chunk.overlap")
cnt(S, "restricted to the 14 tactic names", 14, len(E["tactics"]), EXT, "len(tactics)")
cnt(S, "use only the 14 tactic names", 14, len(E["tactics"]), EXT, "len(tactics)")
mf = re.search(r"^MIN_FRAGMENT\s*=\s*(\d+)", (ROOT / "ctit/cti/extract.py").read_text(), re.M)
cnt(S, "every fragment of at least 8 characters", 8, int(mf.group(1)), "ctit/cti/extract.py", "MIN_FRAGMENT")
num(S, "we use the pre-registered $\\alpha=0.5$", "0.5", al, "configs/extraction_report.yaml", "alpha")
cnt(S, "so each extraction runs five times", 5, MOD["frontier"]["F"]["samples"], "configs/models.yaml", "frontier.F.samples")
add(S, "Effort is pinned at \\emph{high}", "high", MOD["frontier"]["F"]["options"]["effort"], "configs/models.yaml",
    "frontier.F.options.effort", "yes" if MOD["frontier"]["F"]["options"]["effort"] == "high" else "no")
gb, gbf = dline("CLAUDE.md", r"(\d+)\s*GB")
num(S, "24\\,GB of unified memory", "24", int(gb.group(1)) if gb else None, "CLAUDE.md", gbf, note="hardware; from project doc")
nc = MOD["open_weight"]["S"]["options"]["num_ctx"]
add(S, "with 16k context", "16k", str(nc), "configs/models.yaml", "open_weight.{S,S_3B,S_qwen3_14b}.options.num_ctx",
    "yes" if all(MOD["open_weight"][k]["options"]["num_ctx"] == 16384 for k in ("S", "S_3B", "S_qwen3_14b")) else "no",
    note="16384 tokens = 16k")
t0 = [MOD["open_weight"][k]["options"]["temperature"] for k in ("S", "S_3B", "S_qwen3_14b")]
add(S, "Q, M, and M3 run at temperature 0", "0", str(t0), "configs/models.yaml", "open_weight.{S_qwen3_14b,S,S_3B}.options.temperature",
    "yes" if all(t == 0 for t in t0) else "no")
cnt(S, "\\emph{Q5}, \\emph{M5}, and the sampled 3B runs are five samples", 5,
    min(len(MOD["open_weight"][k]["sampled"]["seeds"]) for k in ("S", "S_3B", "S_qwen3_14b")), "configs/models.yaml",
    "open_weight.*.sampled.seeds (length)")
qd = json.loads(OPEN[(OPEN.model == "Q") & (OPEN.setting == "sampled")].model_default_params.iloc[0])
num(S, "(Qwen: temperature 0.6", "0.6", float(qd["temperature"]), f"{PT}/f_open_models.csv", "Q sampled model_default_params.temperature")
num(S, "top-$k$ 20", "20", float(qd["top_k"]), f"{PT}/f_open_models.csv", "Q sampled model_default_params.top_k")
num(S, "top-$p$ 0.95", "0.95", float(qd["top_p"]), f"{PT}/f_open_models.csv", "Q sampled model_default_params.top_p")
mt = [MOD["open_weight"][k]["sampled"]["options"]["temperature"] for k in ("S", "S_3B")]
num(S, "Ministral: temperature 0.15", "0.15", mt[0], "configs/models.yaml", "open_weight.S.sampled.options.temperature",
    note=f"S_3B also {mt[1]}" + ("" if mt[0] == mt[1] else " (differs!)"))
alias_v = str(yaml.safe_load((ROOT / "configs/actor_aliases.yaml").read_text())["attack_version"])
num(S, "its ATT\\&CK v18.1 aliases", "18.1", float(alias_v), "configs/actor_aliases.yaml", "attack_version")
try:
    from ctit.cti import prior as _prior  # noqa: E402
    acts = yaml.safe_load((ROOT / "configs/actors.yaml").read_text())["actors"]
    attk_max = {a: float(_prior.attk_counts(acts[a]["attack_group"])[0].max()) for a in ACTORS}
    attk_src, attk_field = "ctit/cti/prior.py + configs/actors.yaml", "max over actors of attk_counts(attack_group)[0].max()"
except Exception as exc:  # pragma: no cover - fallback if the ATT&CK bundle is unavailable
    attk_max = {a: J(CB_DIAG)["a_attk_build"][a]["count_max"] for a in ACTORS}
    attk_src, attk_field = CB_DIAG, f"max a_attk_build.<actor>.count_max (attk_counts failed: {exc})"
cnt(S, "(counts up to 225)", 225, int(max(attk_max.values())), attk_src, attk_field, note=f"per actor {attk_max}")

# =============================================================================== 6 Design + Table 1
S = "6 Experimental Design"
from ctit.eval import plans, recovery  # noqa: E402

t1 = label_block("tab:actors")
for a in ACTORS:
    m = re.search(rf"^{a} & .* & (\d+) & (\d+) \\\\", t1, re.M)
    steps = len(plans.load_plan(a, platforms=None))
    G = recovery.ground_truth_counts(a)
    cnt("Table 1", f"[table] Table 1 {a} Steps", int(m.group(1)), steps, f"data/eval/plans/{a}.yaml",
        "len(plans.load_plan(actor, platforms=None))")
    cnt("Table 1", f"[table] Table 1 {a} GT edges", int(m.group(2)), int((G > 0).sum()), f"data/eval/plans/{a}.yaml",
        "(recovery.ground_truth_counts(actor) > 0).sum()",
        note=f"extraction_report ground_truth.all.{a}.edges = {E['ground_truth']['all'][a]['edges']}")
man = pd.read_csv(ROOT / "data/cti/manifest.csv")
cnt(S, "We assembled 24 candidate reports", 24, len(man), "data/cti/manifest.csv", "row count")
yrs = pd.to_datetime(man.pub_date).dt.year
add(S, "candidate reports (2018--2025)", "2018--2025", f"{yrs.min()}–{yrs.max()}", "data/cti/manifest.csv", "min/max year(pub_date)",
    "yes" if (yrs.min(), yrs.max()) == (2018, 2025) else "no")
cnt(S, "One was excluded because it does not name the actor", 1, int((man.used_for == "excluded").sum()), "data/cti/manifest.csv",
    "count(used_for == excluded)", note="excluded: " + ", ".join(man[man.used_for == "excluded"].doc_id))
cnt(S, "leaving 23", 23, int((man.used_for == "prior").sum()), "data/cti/manifest.csv", "count(used_for == prior)")
per = man[man.used_for == "prior"].groupby("actor").size().to_dict()
for a, n in (("APT29", 7), ("menuPass", 5), ("OilRig", 5), ("Sandworm", 6)):
    cnt(S, f"{a} {n}", n, per[a], "data/cti/manifest.csv", f"count(used_for == prior, actor == {a})")
g = DATES[DATES.used_for == "prior"]
notafter = g[~g.published_after_plan]
cnt(S, "All but one (a 2019 APT29 report) postdate the plan", 1, len(notafter), f"{PT}/g_report_dates.csv",
    "count(used_for == prior and published_after_plan == False)",
    note="that report: " + ", ".join(f"{r.doc_id} {r.pub_date}" for r in notafter.itertuples()))
dayafter = g[(g.actor == "Sandworm") & (g.days_before_plan == -1)]
cnt(S, "one Sandworm report appeared the day after its plan", 1, len(dayafter), f"{PT}/g_report_dates.csv",
    "count(actor == Sandworm and days_before_plan == -1)", note=", ".join(dayafter.doc_id))
add(S, "one report covers core APT10 and four cover the MirrorFace/Earth Kasha subgroup", "1 + 4", "", "data/cti/manifest.csv",
    "(no subgroup field)", "no source",
    note="searched manifest.csv (no subgroup column), g_report_dates.csv; total menuPass prior docs = %d" % per["menuPass"])
cnt(S, "Two Sandworm documents are thin", 2, THIN, "docs/W2_EXPERIMENT_SPEC.md", THINF, note="doc ids named in the spec bullet")
wc = len((ROOT / "data/cti/reports/Sandworm-P05.txt").read_text().split())
cnt(S, "a 492-word landing page", 492, wc, "data/cti/reports/Sandworm-P05.txt", "whitespace word count")
cnt(S, "10,000 random edge sets of the same size", 10000, E["post_hoc"]["draws"], EXT, "post_hoc.draws")
cnt(S, "drawn from the 182 edges", 182, len(E["tactics"]) * (len(E["tactics"]) - 1), EXT, "len(tactics)*(len(tactics)-1)")
for a, n in (("APT29", 45), ("OilRig", 17), ("Sandworm", 25), ("menuPass", 6)):
    cnt(S, f"{a} {n}", n, L["transitions"][a], LIK, f"transitions.{a}",
        note=f"also ground_truth.all.{a}.transitions = {E['ground_truth']['all'][a]['transitions']}")
cnt(S, "Specificity (H4) is a $4\\times4$ matrix", 4, len(E["h4"]["F"]["f1"]), EXT, "len(h4.F.f1)")
cnt(S, "(descriptive, $n=4$", 4, A.actor.nunique(), f"{PT}/a_support_recovery.csv", "nunique(actor)")
num(S, "a 14B open model recovers $\\geq$80\\% of F's edge-F1", "80", 0.8, "docs/W2_EXPERIMENT_SPEC.md", "H3 threshold (definitional)",
    scale=100, note="threshold, not a result")

# =============================================================================== Table 2
t2 = label_block("tab:recovery")
cell = r"(\.\d+)\\x\{([\d.]+)\}"
seen: Counter = Counter()
for line in t2.splitlines():
    m = re.match(r"^(APT29|OilRig|Sandworm|menuPass) \((\d+)\)\s*&(.*)\\\\", line)
    if not m:
        continue
    a, gt, rest = m.group(1), int(m.group(2)), m.group(3)
    block = seen[a]
    seen[a] += 1
    cells = re.findall(cell, rest)
    priors = ["R-F", "R-Q", "R-Q5", "R-M", "R-M5", "R-M3"] if block == 0 else ["B-F", "B-Q", "B-M", "ATTK"]
    cnt("Table 2", f"[table] Table 2 {a} row label GT edges (block {block + 1})", gt, int(a_val("R-F", a, "truth_edges")),
        f"{PT}/a_support_recovery.csv", "truth_edges")
    for p, (f1, ratio) in zip(priors, cells):
        ex = f1_exact(p, a)
        num("Table 2", f"[table] Table 2 {p} {a} edge-F1", f1, ex, EXT,
            f"post_hoc.chance['{CHANCE_KEY[p]}/{a}'].f1.mean",
            note=f"paper_tables a_support_recovery edge_f1 = {a_val(p, a, 'edge_f1')}"
            + ("; exact half-way value (rounds up half-up and half-even); paper shows it rounded down" if same(f1, ex - 1e-9) and not same(f1, ex) else ""))
        num("Table 2", f"[table] Table 2 {p} {a} F1/chance", ratio, a_val(p, a, "f1_over_chance"), f"{PT}/a_support_recovery.csv",
            f"f1_over_chance [{p},{a}]")
cnt("Table 2", "[table] Table 2 caption: 10,000 random edge sets", 10000, E["post_hoc"]["draws"], EXT, "post_hoc.draws")
cnt("Table 2", "[table] Table 2 caption: F, Q5, and M5 are means over five samples", 5,
    int(A[A.prior.isin(["R-F", "R-Q5", "R-M5"])].samples.min()), f"{PT}/a_support_recovery.csv", "samples (R-F, R-Q5, R-M5)")

# =============================================================================== 7 Results text
S = "7 Results"
num(S, "lies at or above the 99.7th percentile of its chance distribution", "99.7", rf_pct, f"{PT}/a_support_recovery.csv",
    "min percentile, prior R-F", note="claim is a lower bound: source min must be >= 99.7")
ROWS[-1]["match"] = "yes" if rf_pct >= 99.7 else "no"
rng(S, "of its chance distribution (2.0--5.8$\\times$)", "2.0--5.8", min(rf_ratio), max(rf_ratio), f"{PT}/a_support_recovery.csv",
    "f1_over_chance, prior R-F, min/max")
q_m_min = min(a_val(p, a, "f1_over_chance") for p in ("R-Q", "R-Q5", "R-M", "R-M5") for a in ACTORS)
add(S, "both 14B models' report priors exceed the chance mean for every actor", "> 1 (all)", fmt(q_m_min),
    f"{PT}/a_support_recovery.csv", "min f1_over_chance over R-Q, R-Q5, R-M, R-M5", "yes" if q_m_min > 1 else "no")
rng(S, "performs at chance (0.94--1.38$\\times$)", "0.94--1.38", min(attk_ratio), max(attk_ratio), f"{PT}/a_support_recovery.csv",
    "f1_over_chance, prior ATTK, min/max")
num(S, "its edge set comprises all 182 edges", "182", a_val("ATTK", "Sandworm", "edges_mean"), f"{PT}/a_support_recovery.csv",
    "edges_mean [ATTK,Sandworm]")
er = [a_val(f"R-{m}", a, "edges_mean") / a_val(f"B-{m}", a, "edges_mean") for m in ("F", "Q", "M") for a in ACTORS]
rng(S, "R priors list 1.2 to 3.3 times as many edges as B priors", "1.2--3.3", min(er), max(er), f"{PT}/a_support_recovery.csv",
    "edges_mean R-x / B-x for x in F,Q,M, min/max over actor",
    note="cross-check modes[*].summary.edges in " + EXT)
num(S, "whereas Ministral gains from reading ($+0.95$)", "+0.95", d3["M"]["APT29"], f"{PT}/a_support_recovery.csv",
    "f1_over_chance R-M minus B-M, APT29")
num(S, "recalling on average 80\\% of the plan's six edges", "80", E["modes"]["F"]["B/menuPass"]["summary"]["recall_all"]["mean"],
    EXT, "modes.F['B/menuPass'].summary.recall_all.mean", scale=100)
cnt(S, "of the plan's six edges", 6, E["ground_truth"]["all"]["menuPass"]["edges"], EXT, "ground_truth.all.menuPass.edges")
num(S, "with about 13 predicted edges", "13", float(pd.Series(E["modes"]["F"]["B/menuPass"]["summary"]["edges"]).mean()), EXT,
    "mean modes.F['B/menuPass'].summary.edges", note="mean 13.4")
h2_full = [a for a in ACTORS if all(d3[m][a] > 0 for m in ("F", "Q", "M"))]
cnt(S, "H2 therefore holds fully for two of four actors", 2, len(h2_full), f"{PT}/a_support_recovery.csv",
    "count(actors with R-B f1_over_chance > 0 for F, Q, M)", note="actors: " + ", ".join(h2_full))
rmb = E["post_hoc"]["r_minus_b"]
for paper, mode, who in (("-0.4", "F", "Opus"), ("+0.4", "S-Q", "Qwen"), ("-0.8", "S-M", "Ministral")):
    v = rmb[mode]["_spearman_ratio_gap_vs_fewer_references"]
    anchor = {"F": "rank correlations of $-0.4$ for Opus", "S-Q": "$+0.4$ for Qwen", "S-M": "$-0.8$ for Ministral"}[mode]
    num(S, anchor, paper, v, EXT, f"post_hoc.r_minus_b['{mode}']._spearman_ratio_gap_vs_fewer_references",
        note="key is Spearman vs FEWER references (sign = against coverage shrinkage, see flag F12); key uses per-sample chance "
             "(post_hoc.r_minus_b ratio_gap), where Qwen's OilRig/Sandworm gaps order differently from Table 3; see [recomputed] row")
# H2b recomputed from Table-2 ratios for consistency
try:
    from scipy.stats import spearmanr
    refs = [rmb["F"][a]["attack_references"] for a in ACTORS]
    for paper, m, who in (("-0.4", "F", "Opus"), ("+0.4", "Q", "Qwen"), ("-0.8", "M", "Ministral")):
        rho = spearmanr([-r for r in refs], [d3[m][a] for a in ACTORS]).statistic
        num(S, f"[recomputed] H2b Spearman for {who} from Table 3 gaps vs fewer references", paper, float(rho),
            f"{PT}/a_support_recovery.csv + {EXT}", "spearman(-attack_references, R-B f1_over_chance)",
            note="cross-check of the metrics key using the paper's Table-2 ratios")
except Exception:
    pass
for paper, a in (("0.61", "OilRig"), ("0.33", "Sandworm"), ("0.06", "APT29"), ("-0.09", "menuPass")):
    d = ig_row("R-F", a)[0] - ig_row("B-F", a)[0]
    anchor = {"OilRig": "by 0.61 bits per transition on OilRig", "Sandworm": "0.33 on Sandworm",
              "APT29": "by only 0.06 on APT29", "menuPass": "trail them by 0.09 on menuPass"}[a]
    num(S, anchor, paper, d, IGSRC, f"bits_per_transition R-F minus B-F, {a}, alpha 0.5",
        note="'trail by 0.09' = -0.09" if a == "menuPass" else "")
b3 = sorted(glob.glob(str(ROOT / M3_PRIORS / "S_3B" / "B_*.json")) + glob.glob(str(ROOT / M3_PRIORS / "S_3B-sampled" / "B_*.json")))
empty = 0
for f in b3:
    d = json.loads(Path(f).read_text())
    mt_ = d["meta"]
    empty += int(mt_["chunk_status"]["ok"] == 1 and len(d["transitions"]) == 0 and mt_["rejected_items"] == 0)
cnt(S, "the 3B model returned an empty list in 19 of 24 calls", 19, empty, M3_PRIORS + "/S_3B{,-sampled}/B_*.json",
    "count(chunk ok, 0 transitions, 0 rejected items)",
    note=f"of {len(b3)} no-report calls; 22 priors have 0 valid transitions (1 schema skip, 2 all-rejected)")
cnt(S, "returned an empty list in 19 of 24 calls", 24, len(b3), M3_PRIORS + "/S_3B{,-sampled}/B_*.json", "number of B prior files (t0 + 5 samples x 4 actors)")

# H3 paragraph
for model, mode, vals in (("Qwen", "S-Q", ("96", "52", "91", "90")), ("Ministral", "S-M", ("90", "95", "45", "89"))):
    anchor = ("Qwen reaches 96\\%, 52\\%, 91\\%, and 90\\%" if model == "Qwen" else "Ministral 90\\%, 95\\%, 45\\%, and 89\\%")
    for a, p in zip(ACTORS, vals):
        num(S, anchor, p, h3[mode][a]["s_over_f"], EXT, f"h3['{mode}'].{a}.s_over_f", scale=100, note=a)
cnt(S, "each meets H3's 80\\% criterion for three of four actors", 3, min(len(q_pass), len(m_pass)), EXT, "h3 s_over_f >= 0.8 (S-Q, S-M)",
    note=f"Qwen {len(q_pass)}, Ministral {len(m_pass)}")
m3t0 = [h3["S-M3"][a]["s_over_f"] for a in ACTORS]
cnt(S, "The 3B model meets it for none", 0, sum(v >= 0.8 for v in m3t0), EXT, "count(h3['S-M3'].*.s_over_f >= 0.8)")
rng(S, "meets it for none (36--76\\%)", "36--76", min(m3t0), max(m3t0), EXT, "h3['S-M3'].*.s_over_f min/max", scale=100)
loops, loopsrc = 0, ""
for f in glob.glob(str(ROOT / QWEN_PRIORS / "S-sampled" / "R_*.json")) + glob.glob(str(ROOT / QWEN_PRIORS / "S" / "R_*.json")):
    d = json.loads(Path(f).read_text())
    c = Counter((t.get("doc_id"), t.get("chunk")) for t in d["transitions"] + d.get("rejected", []))
    if c and max(c.values()) > loops:
        loops, loopsrc = max(c.values()), f"{Path(f).parent.name}/{Path(f).name} {c.most_common(1)[0][0]}"
docm, docf = dline("docs/SPEC_ISSUES.md", r"up to (\d+) transitions from one chunk")
cnt(S, "(up to 123 transitions from one chunk)", 123, loops, QWEN_PRIORS + "/S{,-sampled}/R_*.json",
    "max transitions (valid + rejected) per (doc, chunk)",
    note=f"max at {loopsrc}; {docf} states {docm.group(1) if docm else '?'} (pre-fix run 121707Z gives the same 115)")
sens = E["h3_sensitivity"]
q_t0_diff = max(abs(sens["S-Q"]["R"][a]["f1"]["mean"] - E["modes"]["S-Q"][f"R/{a}"]["summary"]["f1_all"]["mean"]) for a in ACTORS)
add(S, "leaves Qwen's temperature-0 priors unchanged", "unchanged", fmt(q_t0_diff), EXT,
    "max |h3_sensitivity['S-Q'].R.<a>.f1.mean - modes['S-Q']['R/<a>'].summary.f1_all.mean|", "yes" if q_t0_diff < 1e-12 else "no")
q5_diff = max(abs(sens["S-Q-sampled"]["R"][a]["f1"]["mean"] - E["modes"]["S-Q-sampled"][f"R/{a}"]["summary"]["f1_all"]["mean"]) for a in ACTORS)
add(S, "moves its sampled F1 by at most 0.007", "0.007", fmt(q5_diff), EXT,
    "max |h3_sensitivity['S-Q-sampled'].R.<a>.f1.mean - modes['S-Q-sampled']['R/<a>'].summary.f1_all.mean|",
    "yes" if float(rnd(q5_diff, 3)) <= 0.007 else "no", note="upper bound")
fq = FAB[FAB.model == "Q"].fragment_aware
fm = FAB[FAB.model == "M"].fragment_aware
f3 = FAB[FAB.model == "M3"].fragment_aware
rng(S, "the fabricated-evidence rate is .07--.30 by actor for Qwen", ".07--.30", float(fq.min()), float(fq.max()),
    f"{PT}/c_fabricated_evidence.csv", "fragment_aware, model Q (t0), min/max",
    note="Qwen max is APT29 %.4f (modes['S-Q']['R/APT29'].summary.hallucinated_fragments = %.4f) -> .29, not .30; Q5 range is %.2f-%.2f"
    % (float(fq.max()), E["modes"]["S-Q"]["R/APT29"]["summary"]["hallucinated_fragments"]["mean"],
       FAB[FAB.model == "Q5"].fragment_aware.min(), FAB[FAB.model == "Q5"].fragment_aware.max()))
rng(S, ".20--.30 for Ministral", ".20--.30", float(fm.min()), float(fm.max()), f"{PT}/c_fabricated_evidence.csv",
    "fragment_aware, model M (t0), min/max")
rng(S, ".50--.68 for the 3B", ".50--.68", float(f3.min()), float(f3.max()), f"{PT}/c_fabricated_evidence.csv",
    "fragment_aware, model M3 (t0), min/max")
num(S, "against at most .005 for Opus", ".005", float(FAB[FAB.model == "F"].fragment_aware.max()), f"{PT}/c_fabricated_evidence.csv",
    "max fragment_aware, model F")
fr = REF[REF.model == "F"]
cnt(S, "Opus refused 11 of 185 calls", 11, int(fr.refused_calls.sum()), f"{PT}/d_refusals.csv", "sum refused_calls, model F")
cnt(S, "Opus refused 11 of 185 calls", 185, int(fr.first_attempt_calls.sum()), f"{PT}/d_refusals.csv", "sum first_attempt_calls, model F")
rf = E["refusals"]["F"]
cnt(S, "all five samples of the OpTC red-team ground-truth document", 5, int(rf["oracle#0"].split("/")[0]), EXT, "refusals.F['oracle#0']")
cnt(S, "and of one OilRig chunk", 5, int(rf["OilRig-P02#1"].split("/")[0]), EXT, "refusals.F['OilRig-P02#1'] (all five samples)",
    note="'one OilRig chunk' = 1 chunk: " + str(sum(1 for k in rf if k.startswith("OilRig"))))
cnt(S, "one sample of an APT29 chunk", 1, int(rf["APT29-P03#0"].split("/")[0]), EXT, "refusals.F['APT29-P03#0']")
cnt(S, "no open model refused anything", 0, int(REF[REF.model != "F"].refused_calls.sum()), f"{PT}/d_refusals.csv",
    "sum refused_calls, models != F")
for paper_n, paper_d, modes, models, anchor in (
        (1, 185, ("F",), ("F",), "First-attempt schema failures were 1 of 185 for Opus"),
        (8, 222, ("S-Q", "S-Q-sampled"), ("Q", "Q5"), "8 of 222 for Qwen"),
        (40, 222, ("S-M", "S-M-sampled"), ("M", "M5"), "40 of 222 for Ministral 14B"),
        (14, 216, ("S-M3", "S-M3-sampled"), ("M3", "M35"), "14 of 216 for the 3B")):
    cnt(S, anchor, paper_n, schema_fail(modes), SCHEMA, f"sum counts[{','.join(modes)}].attempt1")
    cnt(S, anchor, paper_d, first_calls(models), f"{PT}/d_refusals.csv", f"sum first_attempt_calls, models {','.join(models)}")
cnt(S, "(18 if replies repeating one identical JSON value count as parsed)", 18, schema_fail(("S-M", "S-M-sampled")) - identical_mv,
    SCHEMA, "40 minus attempt-1 failures with class multiple_values and '(identical)' in detail",
    note=f"identical multiple-value failures = {identical_mv}")
T = E["timing"]
num(S, "Mean time per call was 17\\,s for Opus via the API", "17",
    T["20261027T121723Z-extraction-a53c21c"]["claude-opus-5-5"]["sec_per_call"], EXT,
    "timing['20261027T121723Z-extraction-a53c21c']['claude-opus-5-5'].sec_per_call")
t14 = [T["20261027T121707Z-extraction-a53c21c"][k]["sec_per_call"] for k in ("qwen3:14b", "qwen3:14b (sampled)")] + \
      [T["20261028T005130Z-extraction-5528fd6"][k]["sec_per_call"] for k in
       ("ministral-3-nosys:14b-instruct-2512-q4_K_M", "ministral-3-nosys:14b-instruct-2512-q4_K_M (sampled)")]
rng(S, "41--57\\,s for the 14B models", "41--57", min(t14), max(t14), EXT,
    "timing[121707Z qwen3:14b{, (sampled)}; 005130Z ministral 14b{, (sampled)}].sec_per_call min/max",
    note="first-call runs only; the retry-only run 223928Z (1 and 7 calls) has 78 s and 124 s")
t3 = [v["sec_per_call"] for v in T["20261028T040137Z-extraction-d032eae"].values()]
add(S, "and 9\\,s for the 3B on the laptop", "9", f"{min(t3):.2f}–{max(t3):.2f}", EXT,
    "timing['20261028T040137Z-extraction-d032eae'].*.sec_per_call (t0, sampled)",
    "yes" if all(same("9", v) for v in t3) else "no")
cost, ncalls = 0.0, 0
for line in (ROOT / OPUS_CALLS).read_text().splitlines():
    if line.strip():
        ncalls += 1
        cost += json.loads(line).get("cost_usd") or 0.0
num(S, "Opus cost \\$11.92 for its first 185 calls", "11.92", cost, OPUS_CALLS, "sum cost_usd")
cnt(S, "Opus cost \\$11.92 for its first 185 calls", 185, ncalls, OPUS_CALLS, "number of calls")

# =============================================================================== Table 4
t4 = label_block("tab:h4")
h4f = E["h4"]["F"]["f1"]
for line in t4.splitlines():
    m = re.match(r"^(APT29|OilRig|Sandworm|menuPass) & (.*)\\\\", line)
    if not m:
        continue
    ra = m.group(1)
    vals = [clean(x) for x in m.group(2).split("&")]
    for ca, v in zip(ACTORS, vals):
        num("Table 4", f"[table] Table 4 prior {ra} x plan {ca}", v, h4f[ra][ca], EXT, f"h4.F.f1.{ra}.{ca}")
cap4 = t4[t4.index("\\caption"):]
rowmodes = {"F": "F", "Q": "S-Q", "Q5": "S-Q-sampled", "M": "S-M", "M5": "S-M-sampled", "M3": "S-M3"}
rw = re.search(r"row-wise test: (.*?)\.", cap4).group(1)
for lab, n in re.findall(r"(\w+) (\d)/4", rw):
    src = sum(v["f1"] > 0 for v in E["h4"][rowmodes[lab]]["diag_margin"].values())
    cnt("Table 4", f"[table] Table 4 caption row-wise {lab}", f"{n}/4", src, EXT, f"count(h4['{rowmodes[lab]}'].diag_margin.*.f1 > 0)")
cw = re.search(r"column-wise test \(plan held fixed\): (.*?)\.", cap4).group(1)
for lab, n in re.findall(r"(\w+) (\d)/4", cw):
    src = sum(v > 0 for v in E["post_hoc"]["h4_colwise"][rowmodes[lab]]["f1"].values())
    cnt("Table 4", f"[table] Table 4 caption column-wise {lab}", f"{n}/4", src, EXT,
        f"count(post_hoc.h4_colwise['{rowmodes[lab]}'].f1.* > 0)")

S = "7 Results"
dm = E["h4"]["F"]["diag_margin"]
for paper, a in ((".085", "APT29"), (".047", "OilRig"), (".076", "Sandworm")):
    num(S, "by margins of .085, .047, and .076", paper, dm[a]["f1"], EXT, f"h4.F.diag_margin.{a}.f1")
mp = h4f["menuPass"]
add(S, "it scores higher against the APT29 and OilRig plans than against its own six-edge plan", "APT29, OilRig",
    ", ".join(c for c in ACTORS if c != "menuPass" and mp[c] > mp["menuPass"]), EXT, "h4.F.f1.menuPass.* > h4.F.f1.menuPass.menuPass",
    "yes" if {c for c in ACTORS if c != "menuPass" and mp[c] > mp["menuPass"]} == {"APT29", "OilRig"} else "no")
for lab, mode, n in (("Qwen", "S-Q", 2), ("Ministral", "S-M", 2), ("3B", "S-M3", 0)):
    cnt(S, "Qwen and Ministral pass two rows each and the 3B none", n,
        sum(v["f1"] > 0 for v in E["h4"][mode]["diag_margin"].values()), EXT, f"count(h4['{mode}'].diag_margin.*.f1 > 0)", note=lab)
ph4 = E["post_hoc"]["h4"]["F"]
j01 = sum(v > 0 for v in ph4["jsd_alpha_0.01_margin"].values())
j1 = sum(v > 0 for v in ph4["jsd_alpha_0.1_margin"].values())
add(S, "at $\\alpha\\in\\{0.01, 0.1\\}$ (post hoc), F passes two or three rows", "2 or 3", f"{j01} (alpha 0.01), {j1} (alpha 0.1)",
    EXT, "count(post_hoc.h4.F.jsd_alpha_{0.01,0.1}_margin.* > 0)", "yes" if sorted([j01, j1]) == [2, 3] else "no",
    note="margin > 0 = diagonal closer (ctit/eval/recovery.py:65)")
num(S, "JSD at the pre-registered $\\alpha=0.5$ is uninformative", "0.5", E["alpha"], EXT, "alpha")
for lab, mode in (("F", "F"), ("Qwen", "S-Q"), ("Ministral", "S-M")):
    cnt(S, "gives F, Qwen, and Ministral 3/4 each", "3/4", sum(v > 0 for v in E["post_hoc"]["h4_colwise"][mode]["f1"].values()), EXT,
        f"count(post_hoc.h4_colwise['{mode}'].f1.* > 0)", note=lab)

# =============================================================================== Table 5
t5 = label_block("tab:ig")
for line in t5.splitlines():
    m = re.match(r"^(R-F|R-Q5|R-Q|R-M5|R-M3|R-M|B-F|B-Q|B-M|ATTK) & (.*)\\\\", line)
    if not m:
        continue
    p = m.group(1)
    cells = [c.strip() for c in m.group(2).split("&")]
    for a, c in zip(ACTORS, cells[:4]):
        bits, lo, hi = ig_row(p, a)
        bold, dag = "\\textbf" in c, "\\vf" in c
        val_ok = same(clean(c), bits)
        fmt_ok = (bold == (lo > 0)) and (dag == (hi < 0))
        add("Table 5", f"[table] Table 5 {p} {a}", c.replace("$", ""),
            f"{bits:.4f} [ci {lo:.4f}, {hi:.4f}]", IGSRC,
            f"bits_per_transition, ci95_lo/hi [{p},{a},alpha 0.5]",
            "yes" if val_ok and fmt_ok else "no",
            note=("" if val_ok else f"value mismatch: unrounded {bits:.6f} rounds to {rnd(bits, dec(clean(c))[1])}"
                  + (f" (4-dp CSV value {float(IG[(IG.prior == p) & (IG.actor == a) & (IG.alpha == 0.5)].bits_per_transition.iloc[0])} double-rounded gives the paper value)" if same(clean(c), float(rnd(float(IG[(IG.prior == p) & (IG.actor == a) & (IG.alpha == 0.5)].bits_per_transition.iloc[0]), 3))) else "") + "; ") + ("" if fmt_ok else f"marker mismatch (bold={bold}, lo>0={lo > 0}, dag={dag}, hi<0={hi < 0}); ")
            + ("\\dag here = interval below zero (caption), not a corpus-check dagger" if dag else ""))
    cnt("Table 5", f"[table] Table 5 {p} Attr.", cells[4], attr(p), f"{PT}/b_attribution_counts.csv",
        f"plans_own_actor_best [{p}, alpha 0.5]")
cnt("Table 5", "[table] Table 5 caption: means over five samples", 5,
    int(IG[IG.prior.isin(["R-F", "R-Q5", "R-M5"])].samples.min()), f"{PT}/b_information_gain_own_plan.csv", "samples (R-F, R-Q5, R-M5)")

S = "7 Results"
cnt(S, "with intervals above zero for OilRig and menuPass", 2, sum(ig_row("R-F", a)[1] > 0 for a in ACTORS),
    IGSRC, "count(ci95_lo > 0), R-F",
    note="actors: " + ", ".join(a for a in ACTORS if ig_row("R-F", a)[1] > 0))
cnt(S, "Opus's chains predict their own plan's next tactic better than the uniform chain for all four actors", 4,
    sum(ig_row("R-F", a)[0] > 0 for a in ACTORS), IGSRC, "count(bits > 0), R-F")
cnt(S, "Ministral's do so for three", 3, sum(ig_row("R-M", a)[0] > 0 for a in ACTORS), IGSRC,
    "count(bits > 0), R-M")
cnt(S, "Qwen's only clearly for menuPass", 1, sum(ig_row("R-Q", a)[1] > 0 for a in ACTORS), IGSRC,
    "count(ci95_lo > 0), R-Q", note="actor: " + ", ".join(a for a in ACTORS if ig_row("R-Q", a)[1] > 0))
for paper, p, anchor in ((3, "R-F", "recovers the right actor for 3 of 4 plans with Opus and with Ministral"),
                         (3, "R-M", "recovers the right actor for 3 of 4 plans with Opus and with Ministral"),
                         (2, "R-M5", "2 with sampled Ministral"), (1, "R-Q", "1 with Qwen"), (0, "R-M3", "and none with the 3B")):
    cnt(S, anchor, paper, attr(p), f"{PT}/b_attribution_counts.csv", f"plans_own_actor_best [{p}, alpha 0.5]", note=p)
cnt(S, "memory chains manage at most 2", 2, max(attr(p) for p in ("B-F", "B-Q", "B-M", "B-M5")), f"{PT}/b_attribution_counts.csv",
    "max plans_own_actor_best over B-F, B-Q, B-M, B-M5 (alpha 0.5)")
apt_best = ATTR[(ATTR.prior == "R-F") & (ATTR.alpha == 0.5)].plan_APT29_best_prior.iloc[0]
add(S, "With Opus, the APT29 plan goes to the menuPass chain", "menuPass", apt_best, f"{PT}/b_attribution_counts.csv",
    "plan_APT29_best_prior [R-F, alpha 0.5]", "yes" if apt_best == "menuPass" else "no")
neg01 = IG[(IG.alpha == 0.01) & (~IG.prior.isin(["Uni", "ATTK"]))]
add(S, "At $\\alpha=0.01$, most chains fall below uniform", "most", f"{int((neg01.bits_per_transition < 0).sum())} of {len(neg01)}",
    IGSRC, "count(bits < 0) at alpha 0.01, extracted priors",
    "yes" if (neg01.bits_per_transition < 0).mean() > 0.5 else "no")

# =============================================================================== 8 Hunting
S = "8 Hunting on Public Telemetry"
pol, polf = dline("docs/MAPPER_POLICY.md", r"r2026-07-01")
add(S, "release r2026-07-01", "r2026-07-01", "r2026-07-01" if pol else "", "docs/MAPPER_POLICY.md", polf,
    "yes" if pol else "no source", note=f"{MAPPER_REPORT} records sigma_commit {J(MAPPER_REPORT)['sigma_commit'][:7]} only")
cnt(S, "2,017 rules\\vf", 2017, J(MAPPER_REPORT)["n_rules"], MAPPER_REPORT, "n_rules", note="dagger")
ex, exf = dline("docs/MAPPER_POLICY.md", r"excludes \*\*(\d+) rules\*\*")
rq, rqf = dline("docs/REVIEW_QUEUE.md", r"(\d+) actor/software-tagged rules excluded")
cnt(S, "excluded 56 actor- or malware-specific rules", 56, int(ex.group(1)), "docs/MAPPER_POLICY.md", exf,
    note=f"dagger-era doc value (no metrics field); {rqf} also says {rq.group(1) if rq else '?'}")
V3 = J(MAPPER_V3)
c3 = V3["steps"]["c3_no_remote_thread"]
cnt(S, "(707 of 3,174 queries\\vf)", 707, c3["queries"], MAPPER_V3, "steps.c3_no_remote_thread.queries", note="dagger")
cnt(S, "(707 of 3,174 queries\\vf)", 3174, V3["steps"]["v2"]["queries"], MAPPER_V3, "steps.v2.queries",
    note=f"dagger; also ctit/map/compiled_rules.jsonl has {sum(1 for _ in open(ROOT / 'ctit/map/compiled_rules.jsonl'))} lines")
oc = c3["optc"]
rate = (oc["sysmon"]["tagged"] + oc["security"]["tagged"]) / (oc["sysmon"]["events"] + oc["security"]["events"])
add(S, "tags $3\\times10^{-6}$ of benign events", "3e-6", f"{rate:.4g}", MAPPER_V3,
    "steps.c3_no_remote_thread.optc (sysmon+security tagged / events)", "yes" if f"{rate:.0e}" == "3e-06" else "no",
    note="dagger; sysmon tag_rate %.4g" % oc["sysmon"]["tag_rate"])
cnt(S, "of benign events, in one tactic", 1, len(oc["K"]), MAPPER_V3, "len(steps.c3_no_remote_thread.optc.K)", note="dagger; K = " + str(oc["K"]))
vis = J(WP5)["jsd"]["alpha=0.0"]["visible_extended"]["n_transitions"]
vis_order = [vis[a] for a in ACTORS]
add(S, "leaves the injected chains 27, 3, 3, and 1 visible transitions per actor\\vf", "27, 3, 3, 1",
    ", ".join(str(v) for v in vis_order), WP5, "jsd['alpha=0.0'].visible_extended.n_transitions (APT29, OilRig, Sandworm, menuPass)",
    "yes" if vis_order == [27, 3, 3, 1] else "no",
    note="dagger; same multiset but in the paper's actor order the source is 27/3/1/3 (Sandworm 1, menuPass 3); order unstated in text"
    if sorted(vis_order) == sorted([27, 3, 3, 1]) and vis_order != [27, 3, 3, 1] else "dagger")
brims = J(WP5)["jsd"]["alpha=0.0"]["visible_brims"]["jsd"]
num(S, "(pairwise JSD $\\leq 0.009$\\vf)", "0.009", max(brims.values()), WP5, "max jsd['alpha=0.0'].visible_brims.jsd",
    note="dagger; upper bound")
cnt(S, "ATLASv2 \\citep{riddle2024atlasv2} has five scorable benign windows", 5, J(BENIGN)["atlasv2"]["windows_sysmon"], BENIGN,
    "atlasv2.windows_sysmon", note=f"windows_sysmon_security = {J(BENIGN)['atlasv2']['windows_sysmon_security']}")
cnt(S, "we turn to two real intrusions", 2, len(CASES), " ; ".join(CASES), "number of case-study runs", note="structural count")

CA = J(CASEA)
cnt(S, "the frozen mapper recovers 8 tactics", 8, len(CA["tactics_observed"]), CASEA, "len(tactics_observed)")
cnt(S, "8 tactics and 37 transitions", 37, CA["executed_transitions"], CASEA, "executed_transitions")
missing = [t for t in E["tactics"] if t not in CA["tactics_observed"]]
named = ["Discovery", "Command and Control", "Exfiltration", "Initial Access"]
add(S, "with no Discovery, Command and Control, Exfiltration, or Initial Access", "; ".join(named), "; ".join(missing), CASEA,
    "tactics not in tactics_observed", "yes" if set(named) <= set(missing) else "no",
    note="also unobserved: " + ", ".join(t for t in missing if t not in named))
num(S, "matches the plan at 2.07$\\times$ chance", "2.07", CA["executed_vs_plan"]["plan_all"]["f1_over_chance"], CASEA,
    "executed_vs_plan.plan_all.f1_over_chance")
pa = CA["priors_vs_executed"]["R-F/APT29"]["f1_over_chance"]
po = CA["priors_vs_executed"]["R-F/OilRig"]["f1_over_chance"]
num(S, "Opus's APT29 prior reaches 1.45$\\times$ chance", "1.45", pa, CASEA, "priors_vs_executed['R-F/APT29'].f1_over_chance")
add(S, "no better than its OilRig prior", "no better", f"APT29 {pa:.4f} vs OilRig {po:.4f}", CASEA,
    "priors_vs_executed['R-F/OilRig'].f1_over_chance", "yes" if pa - po < 0.01 else "no",
    note="qualitative; APT29 exceeds OilRig by %.4f" % (pa - po))
ca = L["case_a"]["0.5"]
num(S, "($+0.76$ bits per transition", "+0.76", ca["ATTK/APT29"]["bits"], LIK, "case_a['0.5']['ATTK/APT29'].bits")
num(S, "95\\% interval $[0.50, 0.98]$)", "0.50", ca["ATTK/APT29"]["ci95"][0], LIK, "case_a['0.5']['ATTK/APT29'].ci95[0]")
num(S, "95\\% interval $[0.50, 0.98]$)", "0.98", ca["ATTK/APT29"]["ci95"][1], LIK, "case_a['0.5']['ATTK/APT29'].ci95[1]")
pos = sorted({k.split("/")[0] for k, v in ca.items() if v["ci95"][0] > 0})
add(S, "ATTK is the only prior clearly above uniform", "ATTK", ", ".join(pos), LIK, "case_a['0.5'] families with ci95[0] > 0",
    "yes" if pos == ["ATTK"] else "no", note="ATTK/APT29, /OilRig, /menuPass all have lo > 0")
cnt(S, "The basis, 37 transitions from one recording", 37, CA["executed_transitions"], CASEA, "executed_transitions")

RD = J(RT_DIAG)
cnt(S, "235,698 events on the 29 red-team hosts are malicious", 235698, RD["totals"]["malicious_events"], RT_DIAG, "totals.malicious_events")
hosts = len({r["host"] for r in RD["per_host_day"]})
cnt(S, "235,698 events on the 29 red-team hosts are malicious", 29, hosts, RT_DIAG, "distinct per_host_day[].host",
    note=f"{CB_COL} hosts = {J(CB_COL)['hosts']}")
cnt(S, "the mapper tags 160 of them", 160, RD["totals"]["tagged_malicious"], RT_DIAG, "totals.tagged_malicious")
num(S, "the mapper tags 160 of them (0.07\\%)", "0.07", RD["totals"]["tagged_malicious"] / RD["totals"]["malicious_events"], RT_DIAG,
    "totals.tagged_malicious / totals.malicious_events", scale=100)
COL, AS = J(CB_COL), J(CB_AS)
cnt(S, "the test set has 4,428 windows of eight tagged events", 4428, COL["windows"], CB_COL, "windows")
cnt(S, "windows of eight tagged events", 8, J(BENIGN)["window"], BENIGN, "window")
cnt(S, "4,428 windows of eight tagged events, 46 positive", 46, COL["positive"], CB_COL, "positive")
attk_as = [AS["conditions"][f"ATTK/{a}"]["point"]["auprc"] for a in ACTORS]
rng(S, "which lets ATTK lead (AUPRC .19--.37)", ".19--.37", min(attk_as), max(attk_as), CB_AS, "conditions['ATTK/<actor>'].point.auprc min/max")
num(S, "a prior built from all ATT\\&CK groups matches (.306)", ".306", AS["conditions"]["ATTK-all"]["point"]["auprc"], CB_AS,
    "conditions['ATTK-all'].point.auprc")
rf_col = [COL["conditions"][f"R-F/{a}"]["point"]["auprc"] for a in ACTORS]
rng(S, "Opus's four report priors reach .28--.43", ".28--.43", min(rf_col), max(rf_col), CB_COL, "conditions['R-F/<actor>'].point.auprc min/max")
num(S, "against .18 for uniform", ".18", COL["conditions"]["Uni"]["point"]["auprc"], CB_COL, "conditions['Uni'].point.auprc")
DS = J(CB_DIAG)["d_scripted_removed"]["collapsed"]
cnt(S, "survives dropping the five hosts that run one scripted benign job", 5, len(DS["i_drop_xx01_xx51_hosts"]["hosts_dropped"]), CB_DIAG,
    "d_scripted_removed.collapsed.i_drop_xx01_xx51_hosts.hosts_dropped")
neg_all = DS["primary"]["windows"] - DS["primary"]["positive"]
neg_left = DS["i_drop_xx01_xx51_hosts"]["windows"] - DS["i_drop_xx01_xx51_hosts"]["positive"]
share = (neg_all - neg_left) / neg_all
for sec, anchor in ((S, "(91\\% of negative windows)"), ("9 Discussion", "one scripted job supplied 91\\% of the negative windows")):
    num(sec, anchor, "91", share, CB_DIAG, "1 - (i_drop.windows - i_drop.positive)/(primary.windows - primary.positive), collapsed",
        scale=100, note=f"{neg_all - neg_left} of {neg_all} negative windows")
cnt(S, "vanishes when only that job's two rules are removed", 2, len(DS["ii_drop_scripted_rule_tags"]["rules"]), CB_DIAG,
    "d_scripted_removed.collapsed.ii_drop_scripted_rule_tags.rules")
cnt(S, "11 of the 46 positive windows contain no tactic change", 11, COL["positive_windows_without_offdiag"], CB_COL,
    "positive_windows_without_offdiag", note=f"offdiag_transitions_per_window.positive['0'] = {COL['offdiag_transitions_per_window']['positive']['0']}")
cnt(S, "11 of the 46 positive windows contain no tactic change", 46, COL["positive"], CB_COL, "positive")
cnt(S, "and 7 contain one", 7, COL["offdiag_transitions_per_window"]["positive"]["1"], CB_COL, "offdiag_transitions_per_window.positive['1']")

# =============================================================================== 9 Discussion, 11 Limitations, 12 Conclusion
S = "9 Discussion"
num(S, "(R$-$B $+0.16$ and $-0.08$)", "+0.16", d3["Q"]["menuPass"], f"{PT}/a_support_recovery.csv", "f1_over_chance R-Q minus B-Q, menuPass")
num(S, "(R$-$B $+0.16$ and $-0.08$)", "-0.08", d3["M"]["menuPass"], f"{PT}/a_support_recovery.csv", "f1_over_chance R-M minus B-M, menuPass")
cnt(S, "Two 14B models on a laptop each recovered most of the ordering for three of four actors", 3, min(len(q_pass), len(m_pass)), EXT,
    "h3 s_over_f >= 0.8 (S-Q, S-M)")
cnt(S, "(the 3B model met H3 for no actor)", 0, sum(v >= 0.8 for v in m3t0), EXT, "count(h3['S-M3'].*.s_over_f >= 0.8)")
qshare = COL["positive_windows_without_offdiag"] / COL["positive"]
add(S, "a quarter of OpTC's attack windows contain no tactic change at all", "a quarter", f"{qshare:.3f}", CB_COL,
    "positive_windows_without_offdiag / positive", "yes" if abs(qshare - 0.25) < 0.02 else "no", note="11/46")
S = "11 Limitations"
cnt(S, "menuPass's plan yields six edges", 6, E["ground_truth"]["all"]["menuPass"]["edges"], EXT, "ground_truth.all.menuPass.edges")
cnt(S, "with four actors, cross-actor patterns are descriptive", 4, A.actor.nunique(), f"{PT}/a_support_recovery.csv", "nunique(actor)")
cnt(S, "two Sandworm documents are thin", 2, THIN, "docs/W2_EXPERIMENT_SPEC.md", THINF)
cnt(S, "Ministral 14B failed the output schema on 40 of 222 first attempts", 40, schema_fail(("S-M", "S-M-sampled")), SCHEMA,
    "sum counts[S-M,S-M-sampled].attempt1")
cnt(S, "Ministral 14B failed the output schema on 40 of 222 first attempts", 222, first_calls(("M", "M5")), f"{PT}/d_refusals.csv",
    "sum first_attempt_calls, models M, M5")
cnt(S, "Hunting evidence rests on two case studies", 2, len(CASES), " ; ".join(CASES), "number of case-study runs", note="structural count")
S = "12 Conclusion"
cnt(S, "Two 14B local models recover much of the structure", 2, N14, *N14F)

# =============================================================================== supplement
add("Supplement (S3)", "[supplement] all numbers in the supplement (S3), incl. case study B detail", "", "", "", "",
    "n/a (supplement not in repo)", note="the supplement is not in this repository; not audited")

# ----------------------------------------------------------------------------- Table 3 (after helpers; placed in order below)
t3b = label_block("tab:h2")
t3rows = []
for line in t3b.splitlines():
    if line.startswith("ATT\\&CK refs."):
        for a, v in zip(ACTORS, [x.strip() for x in line.split("&")[2:]]):
            v = v.replace("\\\\", "").strip()
            t3rows.append(dict(section="Table 3", claim_text=f"[table] Table 3 ATT&CK refs. {a}", value_in_paper=v,
                               value_in_source=str(E["post_hoc"]["r_minus_b"]["F"][a]["attack_references"]), source_path=EXT,
                               source_field=f"post_hoc.r_minus_b.F.{a}.attack_references",
                               match="yes" if int(v) == E["post_hoc"]["r_minus_b"]["F"][a]["attack_references"] else "no", note=""))
    m = re.match(r"^(F|Q|M): R\$-\$B & (.*)\\\\", line)
    if m:
        mod = m.group(1)
        for a, v in zip(ACTORS, [x.strip() for x in m.group(2).split("&")]):
            p, nd = dec(v)
            Rv, Bv = a_val(f"R-{mod}", a, "f1_over_chance"), a_val(f"B-{mod}", a, "f1_over_chance")
            exact = rnd(Rv - Bv, nd)
            of_rounded = rnd(Rv, nd) - rnd(Bv, nd)
            if exact == p:
                mt_, nt = "yes", ""
            elif of_rounded == p and abs(exact - p) == Decimal(1).scaleb(-nd):
                mt_, nt = "rounding", f"paper = {rnd(Rv, nd)} - {rnd(Bv, nd)} (difference of rounded Table-2 ratios); exact difference rounds to {exact}"
            else:
                mt_, nt = "no", f"exact rounds to {exact}; difference of rounded = {of_rounded}"
            t3rows.append(dict(section="Table 3", claim_text=f"[table] Table 3 {mod}: R-B {a}", value_in_paper=v.replace("$", ""),
                               value_in_source=f"{Rv - Bv:.4f}", source_path=f"{PT}/a_support_recovery.csv",
                               source_field=f"f1_over_chance R-{mod} minus B-{mod} [{a}]", match=mt_, note=nt))
# insert Table 3 rows right after Table 2
idx = max(i for i, r in enumerate(ROWS) if r["section"] == "Table 2") + 1
ROWS[idx:idx] = t3rows

# ----------------------------------------------------------------------------- write
with OUT.open("w", newline="") as fh:
    w = csv.DictWriter(fh, fieldnames=["section", "claim_text", "value_in_paper", "value_in_source", "source_path",
                                       "source_field", "match", "note"])
    w.writeheader()
    w.writerows(ROWS)
c = Counter(r["match"] for r in ROWS)
print(f"{len(ROWS)} rows -> {OUT.relative_to(ROOT)}: " + ", ".join(f"{k} {v}" for k, v in sorted(c.items())))
