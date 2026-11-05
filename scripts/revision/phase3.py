"""Phase 3 of the AICS-27 revision: resampling and new comparisons on the adopted reference. No model calls.

    python scripts/revision/phase3.py

a  enrichment identity: F1 / chance (shared Monte Carlo draw) vs precision / (|E_g| / 182) = TP / E[TP], every
   kernel (every sample) x plan; exact hypergeometric chance and percentile.
b  every Table 3 cell: point, i.i.d. 95% (the draft's 1,000 and a new 10,000), segment-respecting moving-block
   95% (no wrap-around, b = 2, 3, 5, 10,000), the old circular boundary-crossing marks next to the new ones.
   New mark '*': the status (interval above / below / spanning zero) at any b differs from the i.i.d. (10,000).
c  paired R - B IG over plan transitions, the same resampled indices for R and B: i.i.d. and block.
d  report-level R - B enrichment for Qwen and Ministral 14B (t0, sampled): bootstrap over reports + jackknife.
e  three-metric gap table: raw delta edge-F1, delta enrichment (report bootstrap + jackknife), delta IG (paired).
f  effective smoothing per kernel type.
g  case study B: positive windows with 0 and 1 tactic changes.
Writes results/revision/phase3/{config.yaml, metrics.json} and results/revision/tables/t3{a..g}.{csv,tex}.
"""
from __future__ import annotations

import csv
import json
import subprocess
import sys
import zlib
from pathlib import Path

import numpy as np
import pandas as pd
import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from ctit.eval import recovery  # noqa: E402
from ctit.experiments import revision_engine as R  # noqa: E402
from ctit.experiments import v2_common as v2  # noqa: E402
from ctit.experiments.paper_tables import chance_orderings  # noqa: E402
from scripts.revision.sensitivity import write  # noqa: E402

OUT = REPO / "results" / "revision" / "phase3"
SEED = 20261105
N = 10000
BS = [2, 3, 5]
OLD_BLOCK_RUN = REPO / "results" / "20261031T172545Z-ig_dependence-a0bb280" / "metrics.json"
WINDOWS = REPO / "data" / "eval" / "optc_redteam_windows.parquet"


def iv(c, d=2):
    return "—" if not c else f"[{c[0]:+.{d}f}, {c[1]:+.{d}f}]"


def st(c):
    return R.status(*c)


def main() -> int:
    cfg = yaml.safe_load((REPO / "configs" / "v2_priors.yaml").read_text())
    base = json.loads((REPO / "results" / "revision" / "sensitivity" / "base.json").read_text())
    refs = {a: R.reference(a) for a in R.ACTORS}
    counts = {name: {a: R.family_counts(cfg, name, a) for a in R.ACTORS} for name in R.FAMILIES}
    out: dict = {}

    # ---------------------------------------------------------------- a. enrichment identity
    # ChanceTable.percentile (the draft's) tests ties with float ==, but edge_prf's F1 (2pr/(p+r)) and the chance
    # draw's F1 (2TP/(k+g)) can differ by one ulp, so tied draws are mis-assigned. pct_tiefix compares on TP.
    order = chance_orderings(R.CHANCE["draws"], R.CHANCE["seed"])
    ch = {a: v2.ChanceTable(refs[a].G, order) for a in R.ACTORS}

    def tiefix(ca, k, tp):
        c = ch[ca].f1[:, k - 1] * (k + refs[ca].g) / 2  # TP of each chance draw
        c = np.rint(c)
        return float(100 * ((c < tp).mean() + 0.5 * (c == tp).mean()))

    rows_a, cells_a = [], []
    worst = {"ratio_abs": 0.0, "ratio_rel": 0.0, "pct_tiefix_vs_exact": 0.0, "pct_draft_vs_exact": 0.0,
             "table2_ratio_abs": 0.0, "table2_ratio_rel": 0.0}
    for name, by_a in counts.items():
        for ra, Cs in by_a.items():
            for ca in R.ACTORS:
                G, g = refs[ca].G, refs[ca].g
                acc = {k: [] for k in ("mc", "ex", "ident", "tp_etp", "pd", "pt", "pe", "f1")}
                for C in Cs:
                    r = recovery.edge_prf(C, G)
                    k, tp = r["edges_extracted"], r["tp"]
                    m = ch[ca].ratio(r["f1"], k)
                    e = R.exact_chance(k, g, tp)
                    if m is None or e["ratio"] is None:
                        continue
                    ident = r["precision"] / (g / R.N_OFF)
                    assert abs(ident - e["ratio"]) < 1e-9 and abs(tp / e["expected_tp"] - e["ratio"]) < 1e-9
                    for key, v in (("mc", m), ("ex", e["ratio"]), ("ident", ident), ("tp_etp", tp / e["expected_tp"]),
                                   ("pd", ch[ca].percentile(r["f1"], k)), ("pt", tiefix(ca, k, tp)),
                                   ("pe", e["percentile"]), ("f1", r["f1"])):
                        acc[key].append(v)
                    worst["ratio_abs"] = max(worst["ratio_abs"], abs(m - e["ratio"]))
                    if e["ratio"] > 0:
                        worst["ratio_rel"] = max(worst["ratio_rel"], abs(m / e["ratio"] - 1))
                    worst["pct_tiefix_vs_exact"] = max(worst["pct_tiefix_vs_exact"], abs(acc["pt"][-1] - acc["pe"][-1]))
                    worst["pct_draft_vs_exact"] = max(worst["pct_draft_vs_exact"], abs(acc["pd"][-1] - acc["pe"][-1]))
                if not acc["mc"]:
                    continue
                mean = {k: float(np.mean(v)) for k, v in acc.items()}
                cells_a.append({"prior": name, "prior_actor": ra, "plan": ca, "samples": len(acc["mc"]), **mean})
                if ra == ca:
                    worst["table2_ratio_abs"] = max(worst["table2_ratio_abs"], abs(mean["mc"] - mean["ex"]))
                    worst["table2_ratio_rel"] = max(worst["table2_ratio_rel"], abs(mean["mc"] / mean["ex"] - 1) if mean["ex"] else 0)
                    flag = ("ratio" if f"{mean['mc']:.2f}" != f"{mean['ex']:.2f}" else "") + \
                           (" pct" if abs(mean["pd"] - mean["pe"]) >= 1 else "")
                    rows_a.append([name, ca, f"{mean['f1']:.3f}", f"{mean['mc']:.2f}", f"{mean['ident']:.3f}",
                                   f"{mean['ex']:.3f}", f"{mean['pd']:.1f}", f"{mean['pt']:.1f}", f"{mean['pe']:.1f}",
                                   flag.strip()])
    gaps_exact = {}
    for lab in ("F", "G", "Q", "M"):
        for a in R.ACTORS:
            ce = {c["prior"]: c for c in cells_a if c["prior_actor"] == a and c["plan"] == a}
            if f"B-{lab}" in ce and f"R-{lab}" in ce:
                gaps_exact.setdefault(lab, {})[a] = {"mc": ce[f"R-{lab}"]["mc"] - ce[f"B-{lab}"]["mc"],
                                                     "exact": ce[f"R-{lab}"]["ex"] - ce[f"B-{lab}"]["ex"]}
    out["a_enrichment_identity"] = {"largest_discrepancy": worst, "cells": cells_a, "r_minus_b_exact": gaps_exact,
                                    "note": "identity is exact: precision/(g/182) = TP/E[TP] = F1/exact chance; the MC "
                                            "ratio differs by Monte Carlo error. The draft's MC percentile has a float "
                                            "tie bug; pct_tiefix (ties on TP) agrees with the exact percentile."}
    write("t3a_enrichment_identity", ["Prior", "Plan", "edge-F1", "F1/chance (MC, draft)", "precision/(|Eg|/182)",
                                      "TP/E[TP] exact", "pct (MC, draft)", "pct (MC, tie fixed)", "pct (exact)", "differs"],
          rows_a,
          f"Phase 3a: enrichment identity on Table 2 cells (multi-sample: mean over samples). Largest |MC - exact| "
          f"ratio over every kernel x plan {worst['ratio_abs']:.3f} ({100 * worst['ratio_rel']:.1f}% relative); over Table 2 "
          f"cells {worst['table2_ratio_abs']:.3f} ({100 * worst['table2_ratio_rel']:.1f}%). Percentile: draft vs exact up to "
          f"{worst['pct_draft_vs_exact']:.0f} points (tie bug); tie-fixed MC vs exact up to {worst['pct_tiefix_vs_exact']:.2f}.")

    # ---------------------------------------------------------------- b. block intervals for Table 3
    iid = {a: np.random.default_rng([SEED, 0, zlib.crc32(a.encode())]).integers(0, refs[a].L, (N, refs[a].L))
           for a in R.ACTORS}
    blk = {(a, b): R.segment_blocks(refs[a].seg, b, N, np.random.default_rng([SEED, b, zlib.crc32(a.encode())]))
           for a in R.ACTORS for b in BS}
    old = json.loads(OLD_BLOCK_RUN.read_text())["cells"]
    m_cache = {(name, a): R.per_transition(Cs, refs[a].pairs) for name, by_a in counts.items() for a, Cs in by_a.items()}
    cells_b, rows_b = [], []
    for name in R.FAMILIES:
        for a in R.ACTORS:
            m = m_cache[(name, a)]
            draft = base["t3"][name][a]
            c10 = R.ci(m, iid[a])
            cell = {"prior": name, "actor": a, "L": refs[a].L, "bits": float(m.mean()),
                    "iid_draft_1000": {"ci95": draft["ci95"], "status": draft["status"]},
                    "iid_10000": {"ci95": c10, "status": st(c10)}}
            for b in BS:
                c = R.ci(m, blk[(a, b)])
                cell[f"block_{b}"] = {"ci95": c, "status": st(c), "admissible_blocks": R.admissible_blocks(refs[a].seg, b)}
            oc = old[name][a]
            cell["old_circular"] = {f"b{b}": oc[f"block_{b}"]["status"] for b in BS}
            cell["old_mark"] = bool(oc["status_changes_at_block"])
            cell["new_mark"] = any(cell[f"block_{b}"]["status"] != cell["iid_10000"]["status"] for b in BS)
            cell["iid_1000_vs_10000_status_change"] = draft["status"] != cell["iid_10000"]["status"]
            cell["changes_vs_draft"] = (cell["new_mark"] != cell["old_mark"]) or cell["iid_1000_vs_10000_status_change"]
            cells_b.append(cell)
            rows_b.append([name, a, f"{cell['bits']:+.2f}", iv(draft["ci95"]), iv(c10)] +
                          [iv(cell[f"block_{b}"]["ci95"]) for b in BS] +
                          ["*" if cell["old_mark"] else "", "*" if cell["new_mark"] else "",
                           cell["iid_10000"]["status"] + " -> " + "/".join(cell[f"block_{b}"]["status"] for b in BS)])
    out["b_block"] = {"n": N, "seed": SEED, "block_lengths": BS, "cells": cells_b,
                      "admissible_blocks": {a: {b: R.admissible_blocks(refs[a].seg, b) for b in BS} for a in R.ACTORS},
                      "note": "menuPass has 6 transitions (2 admissible blocks at b = 5, 4 at b = 3): its block intervals "
                              "are near-degenerate and carry little information."}
    write("t3b_block_intervals", ["Prior", "Plan", "IG", "i.i.d. 95% (draft, 1,000)", "i.i.d. 95% (10,000)",
                                  "block b=2", "block b=3", "block b=5", "old * (circular)", "new * (segments)",
                                  "status i.i.d. -> b=2/3/5"], rows_b,
          "Phase 3b: own-plan IG, i.i.d. vs segment-respecting moving-block bootstrap (10,000, no wrap-around)")

    # ---------------------------------------------------------------- c. paired R - B IG
    rows_c, cells_c = [], []
    for lab in R.PAIRS:
        for a in R.ACTORS:
            mR = R.per_transition(list(R.r_tensor(cfg, lab, a).sum(axis=1)), refs[a].pairs)
            mB = R.per_transition(R.b_counts(cfg, lab, a), refs[a].pairs)
            d = mR - mB
            cell = {"model": lab, "actor": a, "point": float(d.mean()), "iid_10000": {"ci95": R.ci(d, iid[a])}}
            cell["iid_10000"]["status"] = st(cell["iid_10000"]["ci95"])
            for b in BS:
                c = R.ci(d, blk[(a, b)])
                cell[f"block_{b}"] = {"ci95": c, "status": st(c)}
            rep = base["rb"][lab][a]["ig_bits"]["R_minus_B"]
            cell["report_bootstrap"] = {"ci95": rep["ci95"], "jackknife": rep["jackknife"]["ci95"], "clear": rep["clear"]}
            cells_c.append(cell)
            rows_c.append([R.NAMES[lab], a, f"{cell['point']:+.2f}", iv(cell["iid_10000"]["ci95"])] +
                          [iv(cell[f"block_{b}"]["ci95"]) for b in BS] +
                          [cell["iid_10000"]["status"] + " / " + "/".join(cell[f"block_{b}"]["status"] for b in BS),
                           iv(rep["ci95"]), rep["clear"]])
    out["c_paired_ig"] = {"cells": cells_c, "focus": [c for c in cells_c if c["actor"] == "OilRig" and c["model"] in ("F", "G", "M")]}
    write("t3c_paired_ig_gap", ["Model", "Plan", "R−B IG", "i.i.d. 95%", "block b=2", "block b=3", "block b=5",
                                "status i.i.d. / b=2/3/5", "report bootstrap 95% (draft)", "report-level clear"], rows_c,
          "Phase 3c: paired R - B information gain over plan transitions (same resampled indices for R and B)")

    # ---------------------------------------------------------------- d. report-level intervals, local models
    rows_d = []
    for lab in ("Q", "Q5", "M", "M5"):
        for a in R.ACTORS:
            e = base["rb"][lab][a]
            g = e["f1_over_chance"]["R_minus_B"]
            rows_d.append([R.NAMES[lab], a, e["b_samples"], "held fixed" if e["b_samples"] == 1 else "resampled",
                           f"{g['point']:+.2f}", iv(g["ci95"]), iv(g["jackknife"]["ci95"]),
                           f"{g['jackknife']['min']:+.2f} … {g['jackknife']['max']:+.2f}", g["clear"]])
    out["d_local_report_level"] = {lab: {a: base["rb"][lab][a]["f1_over_chance"]["R_minus_B"] for a in R.ACTORS}
                                   for lab in ("Q", "Q5", "M", "M5")}
    write("t3d_local_report_intervals", ["Model", "Actor", "B samples", "B", "R−B F1/chance", "report bootstrap 95%",
                                         "jackknife 95%", "LOO min … max", "clear"], rows_d,
          "Phase 3d: report-level R - B enrichment for the 14B models (bootstrap 2,000 over reports; leave-one-report-out)")

    # ---------------------------------------------------------------- e. three-metric gap table
    rows_e = []
    cmap = {(c["model"], c["actor"]): c for c in cells_c}
    for lab in R.PAIRS:
        for a in R.ACTORS:
            e = base["rb"][lab][a]
            f1, en = e["edge_f1"]["R_minus_B"], e["f1_over_chance"]["R_minus_B"]
            c = cmap[(lab, a)]
            rows_e.append([R.NAMES[lab], a,
                           f"{f1['point']:+.3f}", iv(f1["ci95"], 3), iv(f1["jackknife"]["ci95"], 3), f1["clear"],
                           "—" if en["point"] is None else f"{en['point']:+.2f}", iv(en["ci95"]), iv(en["jackknife"]["ci95"]), en["clear"],
                           f"{c['point']:+.2f}", iv(c["iid_10000"]["ci95"]), iv(c["block_2"]["ci95"]), iv(c["block_3"]["ci95"]),
                           iv(c["block_5"]["ci95"])])
    write("t3e_three_metric_gaps", ["Model", "Actor", "ΔF1", "boot 95%", "jackknife 95%", "clear",
                                    "Δenrichment", "boot 95%", "jackknife 95%", "clear",
                                    "ΔIG", "i.i.d. 95%", "block b=2", "block b=3", "block b=5"], rows_e,
          "Phase 3e: R - B in raw edge-F1, F1/chance and IG")
    out["e_three_metric"] = {"rows": rows_e}

    # ---------------------------------------------------------------- f. effective smoothing
    rows_f, cells_f = [], []
    for a in R.ACTORS:
        nrep = len(v2.prior_reports(a))
        for lab in R.R_LABELS:
            s = R.smoothing(counts[f"R-{lab}"][a], nrep)
            cells_f.append({"kernel": f"R-{lab}", "actor": a, **s})
        for lab in R.B_LABELS:
            s = R.smoothing(counts[f"B-{lab}"][a], 1)
            cells_f.append({"kernel": f"B-{lab}", "actor": a, **s})
        cells_f.append({"kernel": "ATTK", "actor": a, **R.smoothing(counts["ATTK"][a], None)})
    for c in cells_f:
        rows_f.append([c["kernel"], c["actor"], "—" if c["n_docs"] is None else c["n_docs"], c["samples"],
                       f"{c['row_total_max']:.0f}", f"{c['row_total_sum_mean']:.1f}", f"{c['nonempty_rows_mean']:.1f}",
                       f"{c['cap']:.3f}", f"{c['cap_bits']:.2f}", f"{c['fitted_max_row_prob']:.3f}",
                       f"{c['fitted_max_row_prob_mean']:.3f}", f"{c['fitted_bits']:.2f}"])
    out["f_smoothing"] = cells_f
    write("t3f_effective_smoothing", ["Kernel", "Actor", "n (reports / generations)", "samples", "max row total",
                                      "total count (mean)", "non-empty rows (mean)", "max attainable P", "cap bits (log2 13P)",
                                      "fitted max P (max)", "fitted max P (mean)", "fitted bits"], rows_f,
          "Phase 3f: effective smoothing of Eq. 1 (alpha = 0.5); ATTK has no report cap (limit as counts grow shown)")

    # ---------------------------------------------------------------- g. case study B
    win = pd.read_parquet(WINDOWS)
    y = win["positive"].to_numpy(bool)
    changes = np.array([sum(1 for j in range(1, len(t)) if t[j] != t[j - 1]) for t in win["tactics"]])
    dist = lambda sel: {int(k): int(v) for k, v in zip(*np.unique(changes[sel], return_counts=True))}
    out["g_case_b"] = {"windows": int(len(win)), "positive": int(y.sum()), "positive_by_changes": dist(y),
                       "negative_by_changes": dist(~y), "positive_0": int((changes[y] == 0).sum()),
                       "positive_1": int((changes[y] == 1).sum()),
                       "source": str(WINDOWS.relative_to(REPO)),
                       "note": "tactic changes = off-diagonal transitions after collapsing the window (as "
                               "ctit.experiments.redteam_scoring.collapsed_pairs); the crosswalk changed no telemetry "
                               "label, so the cached windows stand"}
    write("t3g_case_b_changes", ["Windows", "Tactic changes", "count"],
          [["positive", k, v] for k, v in out["g_case_b"]["positive_by_changes"].items()] +
          [["negative", k, v] for k, v in out["g_case_b"]["negative_by_changes"].items()],
          "Phase 3g: case study B, tactic changes per window (8 tagged events per window)")

    sha = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "-C", str(REPO), "status", "--porcelain", "--untracked-files=no"],
                                capture_output=True, text=True).stdout.strip())
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "config.yaml").write_text(yaml.safe_dump({
        "script": "scripts/revision/phase3.py", "git_sha": sha, "git_dirty": dirty, "reference": "adopted",
        "priors": cfg["priors"], "seeds": {"phase3": SEED, "chance": R.CHANCE["seed"], "iid_draft": R.IID_DRAFT["seed"],
                                           "report_bootstrap": R.RB["seed"]},
        "n_resamples": N, "block_lengths": BS, "old_block_run": str(OLD_BLOCK_RUN.relative_to(REPO)),
        "base_scorecard": "results/revision/sensitivity/base.json"}, sort_keys=False))
    (OUT / "metrics.json").write_text(json.dumps(out, indent=1, default=float))
    print("a worst:", worst)
    print("a R-B exact:", {l: {a: (round(v["mc"], 2), round(v["exact"], 2)) for a, v in d.items()} for l, d in gaps_exact.items()})
    for c in cells_b:
        if c["old_mark"] or c["new_mark"] or c["iid_1000_vs_10000_status_change"]:
            print("b", c["prior"], c["actor"], "draft", c["iid_draft_1000"]["status"], "iid10k", c["iid_10000"]["status"],
                  "blocks", [c[f"block_{b}"]["status"] for b in BS], "old*", c["old_mark"], "new*", c["new_mark"])
    for c in out["c_paired_ig"]["focus"]:
        print("c", c["model"], c["actor"], round(c["point"], 3), c["iid_10000"], {b: c[f"block_{b}"] for b in BS})
    print("g", out["g_case_b"]["positive"], out["g_case_b"]["positive_0"], out["g_case_b"]["positive_1"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
