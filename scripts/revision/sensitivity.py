"""Sensitivity analyses for the AICS-27 revision (Jack, 2026-11-05). Scored only, never adopted. No model calls.

    python scripts/revision/sensitivity.py

Scenarios (ctit.experiments.revision_engine.scorecard):
  base          adopted reference, as-run kernels (reproduces the draft)
  ev_fragments  R kernels rebuilt without transitions whose quote fails the fragment-aware check
  ev_strict     the same with the strict whole-span check
  var_A         reference variant A (split at every Linux <-> Windows handoff)
  var_B         reference variant B (menuPass's Optional steps as separate segments)
Writes results/revision/sensitivity/{config.yaml, <scenario>.json, diff_<scenario>.csv, evidence_shares.csv}
and supplement tables results/revision/tables/s_<scenario>_{t2,t3,t5}.{csv,tex} and
s_evidence_shares.{csv,tex}, s_h3_evidence.{csv,tex}.
"""
from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from ctit.experiments import revision_engine as R  # noqa: E402

OUT = REPO / "results" / "revision" / "sensitivity"
TAB = REPO / "results" / "revision" / "tables"
SCENARIOS = {"base": ("adopted", None), "ev_fragments": ("adopted", "fragments"), "ev_strict": ("adopted", "strict"),
             "var_A": ("A", None), "var_B": ("B", None)}


def provenance() -> dict:
    sha = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "-C", str(REPO), "status", "--porcelain", "--untracked-files=no"],
                                capture_output=True, text=True).stdout.strip())
    return {"git_sha": sha, "git_dirty": dirty}


def f(x, d):
    return "—" if x is None else f"{x:+.{d}f}" if d < 0 else f"{x:.{d}f}"


def sgn(x, d=2):
    return "—" if x is None else f"{x:+.{d}f}"


def iv(c, d=2):
    return "—" if not c else f"[{c[0]:+.{d}f}, {c[1]:+.{d}f}]"


# ----------------------------------------------------------------------------- diffs

def cells(sc: dict) -> dict:
    """Flatten a scorecard to {(table, row, col, field): (value, printed)} at the draft's printed precision."""
    out = {}
    for a, r in sc["reference"].items():
        out[("T1", a, "GT", "edges")] = (r["edges"], str(r["edges"]))
        out[("T1", a, "GT", "L")] = (r["L"], str(r["L"]))
    for fam, by in sc["t2"].items():
        for a, c in by.items():
            out[("T2", fam, a, "edge_f1")] = (c["edge_f1"], f"{c['edge_f1']:.3f}")
            out[("T2", fam, a, "f1_over_chance")] = (c["f1_over_chance"], f(c["f1_over_chance"], 2))
            out[("T2", fam, a, "percentile")] = (c["percentile"], f"{c['percentile']:.1f}")
    for fam, by in sc["t3"].items():
        for a, c in by.items():
            out[("T3", fam, a, "bits")] = (c["bits"], sgn(c["bits"]))
            out[("T3", fam, a, "iid_status")] = (c["status"], c["status"])
    for fam, at in sc["attr"].items():
        out[("T3", fam, "Attr.", "n")] = (at["n"], f"{at['n']}/4")
    for lab, by in sc.get("rb", {}).items():
        for a, e in by.items():
            for key, d in (("f1_over_chance", 2), ("ig_bits", 2), ("edge_f1", 3)):
                g = e[key]["R_minus_B"]
                out[("T5", lab, a, f"{key}_gap")] = (g["point"], sgn(g["point"], d))
                out[("T5", lab, a, f"{key}_boot")] = (g["ci95"], iv(g["ci95"], d))
                out[("T5", lab, a, f"{key}_jack")] = (g["jackknife"]["ci95"], iv(g["jackknife"]["ci95"], d))
                out[("T5", lab, a, f"{key}_clear")] = (g["clear"], g["clear"])
    for lab, h in sc["h3"].items():
        for a, v in h["share"].items():
            out[("H3", lab, a, "share")] = (v, f"{100 * v:.0f}%")
        out[("H3", lab, "all", "meets_80")] = (h["meets_80"], f"{h['meets_80']}/4")
    return out


def diff(base: dict, new: dict) -> list[dict]:
    b, n = cells(base), cells(new)
    rows = []
    for k in b:
        if b[k][1] != n[k][1]:
            rows.append({"table": k[0], "row": k[1], "col": k[2], "field": k[3], "old": b[k][1], "new": n[k][1],
                         "status_field": k[3].endswith(("status", "clear", "meets_80")) or k[3] == "n"})
    return rows


# ----------------------------------------------------------------------------- tables

def write(name: str, header: list[str], rows: list[list], caption: str) -> None:
    TAB.mkdir(parents=True, exist_ok=True)
    with (TAB / f"{name}.csv").open("w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(header)
        w.writerows(rows)
    esc = lambda s: str(s).replace("&", r"\&").replace("%", r"\%").replace("_", r"\_").replace("→", r"$\to$") \
        .replace("−", "$-$").replace("÷", r"$\div$").replace("≥", r"$\geq$")
    lines = [f"% {caption}", r"\begin{tabular}{@{}" + "l" * 2 + "r" * (len(header) - 2) + "@{}}", r"\toprule",
             " & ".join(esc(h) for h in header) + r" \\", r"\midrule"]
    lines += [" & ".join(esc(c) for c in r) + r" \\" for r in rows]
    lines += [r"\bottomrule", r"\end{tabular}"]
    (TAB / f"{name}.tex").write_text("\n".join(lines) + "\n")


def scenario_tables(key: str, base: dict, sc: dict) -> None:
    fams = R.FAMILIES if sc["filter"] is None else [x for x in R.FAMILIES if x.startswith("R-")]
    rows = []
    for fam in fams:
        for a in R.ACTORS:
            o, n = base["t2"][fam][a], sc["t2"][fam][a]
            rows.append([fam, a, n["truth_edges"], f"{o['edge_f1']:.3f}", f"{n['edge_f1']:.3f}", f(o["f1_over_chance"], 2),
                         f(n["f1_over_chance"], 2), f"{o['percentile']:.1f}", f"{n['percentile']:.1f}",
                         f"{o['edges_mean']:.1f}", f"{n['edges_mean']:.1f}"])
    write(f"s_{key}_t2", ["Prior", "Actor", "GT edges", "F1 old", "F1 new", "F1/chance old", "F1/chance new",
                          "pct old", "pct new", "edges old", "edges new"], rows, f"{key}: Table 2 old vs new")
    rows = []
    for fam in fams:
        for a in R.ACTORS:
            o, n = base["t3"][fam][a], sc["t3"][fam][a]
            rows.append([fam, a, sgn(o["bits"]), sgn(n["bits"]), iv(o["ci95"]), iv(n["ci95"]), o["status"], n["status"]])
        rows.append([fam, "Attr.", f"{base['attr'][fam]['n']}/4", f"{sc['attr'][fam]['n']}/4", "", "", "", ""])
    write(f"s_{key}_t3", ["Prior", "Actor", "IG old", "IG new", "95% i.i.d. old", "95% i.i.d. new", "status old",
                          "status new"], rows, f"{key}: Table 3 old vs new (i.i.d. 1,000 resamples, seed 20261027)")
    rows = []
    for lab in R.PAIRS:
        for a in R.ACTORS:
            o, n = base["rb"][lab][a]["f1_over_chance"]["R_minus_B"], sc["rb"][lab][a]["f1_over_chance"]["R_minus_B"]
            oi, ni = base["rb"][lab][a]["ig_bits"]["R_minus_B"], sc["rb"][lab][a]["ig_bits"]["R_minus_B"]
            rows.append([R.NAMES[lab], a, sgn(o["point"]), sgn(n["point"]), iv(n["ci95"]), iv(n["jackknife"]["ci95"]),
                         o["clear"], n["clear"], sgn(oi["point"]), sgn(ni["point"]), iv(ni["ci95"]), oi["clear"], ni["clear"]])
    write(f"s_{key}_t5", ["Model", "Actor", "R−B ratio old", "new", "boot 95% new", "jackknife 95% new", "clear old",
                          "clear new", "R−B IG old", "new", "boot 95% new", "clear old", "clear new"], rows,
          f"{key}: R - B (Table 5) old vs new; report bootstrap 2,000 + leave-one-report-out jackknife")


def evidence_shares() -> list[list]:
    ph0 = json.loads((REPO / "results" / "revision" / "phase0" / "metrics.json").read_text())
    rows = []
    for lab in ["F", "G", "Q", "Q5", "M", "M5", "M3", "M35"]:
        for a in R.ACTORS:
            ev = ph0["evidence"][lab][a]
            e = sum(x["edges"] for x in ev)
            c = sum(x["count_total"] for x in ev)
            pc = lambda k, tot: f"{100 * sum(x[k] for x in ev) / tot:.1f}%" if tot else "—"
            rows.append([R.NAMES[lab], a, len(ev), e, pc("edges_lost_if_filtered_fragments", e),
                         pc("edges_lost_if_filtered_strict", e), c, pc("count_units_only_failing_fragments", c),
                         pc("count_units_only_failing_strict", c)])
    return rows


def main() -> int:
    cfg = yaml.safe_load((REPO / "configs" / "v2_priors.yaml").read_text())
    OUT.mkdir(parents=True, exist_ok=True)
    res = {}
    for key, (variant, filt) in SCENARIOS.items():
        res[key] = R.scorecard(cfg, variant, filt)
        (OUT / f"{key}.json").write_text(json.dumps(res[key], indent=1, default=float))
    for key in SCENARIOS:
        if key == "base":
            continue
        rows = diff(res["base"], res[key])
        with (OUT / f"diff_{key}.csv").open("w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=["table", "row", "col", "field", "old", "new", "status_field"])
            w.writeheader()
            w.writerows(rows)
        scenario_tables(key, res["base"], res[key])
        print(key, "changed printed cells:", len(rows), "status changes:", sum(r["status_field"] for r in rows))
    write("s_evidence_shares", ["Model", "Actor", "samples", "edges", "edges only failing (fragment)",
                                "edges only failing (strict)", "count units", "units only failing (fragment)",
                                "units only failing (strict)"], evidence_shares(),
          "Share of R edges and count units resting only on failing quotes (summed over samples)")
    rows = []
    for lab in ("Q", "Q5", "M", "M5", "M3", "G"):
        for a in R.ACTORS:
            fu = res["base"]["t2"]["R-F"][a]["edge_f1"]
            for key in ("base", "ev_fragments", "ev_strict"):
                pass
            rows.append([R.NAMES[lab], a,
                         f"{100 * res['base']['h3'][lab]['share'][a]:.0f}%",
                         f"{100 * res['ev_fragments']['h3'][lab]['share'][a]:.0f}%",
                         f"{100 * res['ev_fragments']['t2'][f'R-{lab}'][a]['edge_f1'] / fu:.0f}%",
                         f"{100 * res['ev_strict']['h3'][lab]['share'][a]:.0f}%",
                         f"{100 * res['ev_strict']['t2'][f'R-{lab}'][a]['edge_f1'] / fu:.0f}%"])
        rows.append([R.NAMES[lab], "meets 80%",
                     f"{res['base']['h3'][lab]['meets_80']}/4", f"{res['ev_fragments']['h3'][lab]['meets_80']}/4",
                     f"{sum(res['ev_fragments']['t2'][f'R-{lab}'][a]['edge_f1'] / res['base']['t2']['R-F'][a]['edge_f1'] >= .8 for a in R.ACTORS)}/4",
                     f"{res['ev_strict']['h3'][lab]['meets_80']}/4",
                     f"{sum(res['ev_strict']['t2'][f'R-{lab}'][a]['edge_f1'] / res['base']['t2']['R-F'][a]['edge_f1'] >= .8 for a in R.ACTORS)}/4"])
    write("s_h3_evidence", ["Model", "Actor", "as run", "fragment: vs Opus filtered", "fragment: vs Opus as run",
                            "strict: vs Opus filtered", "strict: vs Opus as run"], rows,
          "Share of Claude Opus's edge-F1 (H3), as run and with failed-quote edges removed")
    (OUT / "config.yaml").write_text(yaml.safe_dump({
        "script": "scripts/revision/sensitivity.py", **provenance(), "priors": cfg["priors"],
        "scenarios": {k: {"variant": v, "filter": fl} for k, (v, fl) in SCENARIOS.items()},
        "chance": R.CHANCE, "iid": R.IID_DRAFT, "report_bootstrap": R.RB, "alpha": R.ALPHA,
        "seeds": [R.CHANCE["seed"], R.IID_DRAFT["seed"], R.RB["seed"]]}, sort_keys=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
