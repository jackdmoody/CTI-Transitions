"""Every derived number or status the 04 Nov draft states, recomputed from a scorecard
(ctit.experiments.revision_engine.scorecard), so scenarios can be compared claim by claim.

    python scripts/revision/claims.py      # prints the claims table for every saved sensitivity scenario
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np
from scipy.stats import spearmanr

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from ctit.experiments import revision_engine as R  # noqa: E402

REFS = {"APT29": 44, "OilRig": 28, "Sandworm": 26, "menuPass": 20}  # ATT&CK group-page references (Table 5)
A = R.ACTORS


def rng_(xs, d=2):
    xs = [x for x in xs if x is not None]
    return f"{min(xs):.{d}f}–{max(xs):.{d}f}"


def sset(d: dict, want: str) -> str:
    s = [a for a in A if d[a] == want]
    return "{" + ", ".join(s) + "}"


def claims(sc: dict) -> dict[str, str]:
    t2, t3, rb, at = sc["t2"], sc["t3"], sc["rb"], sc["attr"]
    c: dict[str, str] = {}
    c["T1 GT edges"] = ", ".join(f"{a} {sc['reference'][a]['edges']}" for a in A)
    c["T1/Metrics L"] = ", ".join(f"{a} {sc['reference'][a]['L']}" for a in A)
    for lab in ("F", "G"):
        c[f"R-{lab} F1/chance range"] = rng_([t2[f"R-{lab}"][a]["f1_over_chance"] for a in A])
        c[f"R-{lab} min percentile"] = f"{min(t2[f'R-{lab}'][a]['percentile'] for a in A):.1f}"
    for lab in ("Q", "M", "M3"):
        c[f"R-{lab} actors above chance (ratio>1)"] = sset({a: "y" if (t2[f"R-{lab}"][a]["f1_over_chance"] or 0) > 1 else "n"
                                                           for a in A}, "y")
        c[f"R-{lab} actors below 95th pct"] = ", ".join(f"{a} {t2[f'R-{lab}'][a]['percentile']:.0f}" for a in A
                                                        if t2[f"R-{lab}"][a]["percentile"] < 95) or "none"
    c["ATTK F1/chance range"] = rng_([t2["ATTK"][a]["f1_over_chance"] for a in A])
    c["ATTK Sandworm edges"] = f"{t2['ATTK']['Sandworm']['edges_mean']:.0f}"
    for fam in ("R-F", "R-G", "R-Q", "R-Q5", "R-M", "R-M5", "R-M3", "B-F", "B-G", "B-Q", "B-M", "ATTK"):
        st = {a: t3[fam][a]["status"] for a in A}
        c[f"T3 {fam} bits>0"] = sset({a: "y" if t3[fam][a]["bits"] > 0 else "n" for a in A}, "y")
        c[f"T3 {fam} clear above"] = sset(st, "above")
        c[f"T3 {fam} clear below"] = sset(st, "below")
        c[f"T3 {fam} Attr."] = f"{at[fam]['n']}/4 ({', '.join(f'{p}->{q}' for p, q in at[fam]['plan_to'].items() if p != q) or 'all own'})"
    c["Attr. memory chains max"] = str(max(at[f]["n"] for f in ("B-F", "B-G", "B-Q", "B-M")))
    for lab in ("F", "G", "Q", "M"):
        c[f"raw edge-F1 R>B ({lab})"] = sset({a: "y" if t2[f"R-{lab}"][a]["edge_f1"] > t2[f"B-{lab}"][a]["edge_f1"] else "n"
                                              for a in A}, "y")
    er = lambda labs: rng_([t2[f"R-{x}"][a]["edges_mean"] / t2[f"B-{x}"][a]["edges_mean"] for x in labs for a in A], 1)
    c["R/B edge-count ratio (F,Q,M)"] = er(["F", "Q", "M"])
    c["R/B edge-count ratio (G)"] = er(["G"])
    for lab in ("F", "G", "Q", "M", "Q5", "M5"):
        g = {a: rb[lab][a]["f1_over_chance"]["R_minus_B"] for a in A}
        c[f"T5 {lab} R-B ratio"] = ", ".join(f"{a} {g[a]['point']:+.2f}" if g[a]["point"] is not None else f"{a} —" for a in A)
        c[f"T5 {lab} clear (ratio)"] = ", ".join(f"{a}:{g[a]['clear']}" for a in A if g[a]["clear"] in ("above", "below")) or "none"
        c[f"T5 {lab} APT29 boot/jack"] = f"{g['APT29']['ci95']} / {g['APT29']['jackknife']['ci95']}"
        if lab in ("F", "G"):
            for a in A:
                c[f"T5 {lab} {a} boot / jackknife"] = (f"[{g[a]['ci95'][0]:+.2f}, {g[a]['ci95'][1]:+.2f}] / "
                                                      f"[{g[a]['jackknife']['ci95'][0]:+.2f}, {g[a]['jackknife']['ci95'][1]:+.2f}]")
            j = g["menuPass"]["jackknife"]
            c[f"T5 {lab} menuPass LOO min..max"] = f"{j['min']:+.2f} … {j['max']:+.2f}"
        pts = [g[a]["point"] for a in A]
        if all(p is not None for p in pts):
            rho = spearmanr(pts, [-REFS[a] for a in A]).statistic
            c[f"H2b rho ({lab})"] = f"{rho:+.1f}"
        ig = {a: rb[lab][a]["ig_bits"]["R_minus_B"] for a in A}
        c[f"T5 IG {lab} clear"] = ", ".join(f"{a}:{ig[a]['clear']} {ig[a]['point']:+.2f} [{ig[a]['ci95'][0]:.2f}, {ig[a]['ci95'][1]:.2f}]"
                                            for a in A if ig[a]["clear"] in ("above", "below")) or "none"
        c[f"T5 IG {lab} menuPass"] = f"{ig['menuPass']['point']:+.2f} [{ig['menuPass']['ci95'][0]:+.2f}, {ig['menuPass']['ci95'][1]:+.2f}] ({ig['menuPass']['clear']})"
    c["B-F menuPass recall / edges"] = f"{100 * t2['B-F']['menuPass']['recall']:.0f}% / {t2['B-F']['menuPass']['edges_mean']:.1f}"
    for lab in ("Q", "M", "M3"):
        sh = sc["h3"][lab]["share"]
        c[f"H3 {lab} share"] = ", ".join(f"{a} {100 * sh[a]:.0f}%" for a in A) + f" ({sc['h3'][lab]['meets_80']}/4 >= 80%)"
    c["menuPass R vs B edge-F1 (F,G,Q,M)"] = ", ".join(
        f"{lab} {t2[f'R-{lab}']['menuPass']['edge_f1']:.3f} vs {t2[f'B-{lab}']['menuPass']['edge_f1']:.3f}" for lab in ("F", "G", "Q", "M"))
    c["menuPass R vs B F1/chance (F,G,Q,M)"] = ", ".join(
        f"{lab} {t2[f'R-{lab}']['menuPass']['f1_over_chance'] or 0:.2f} vs {t2[f'B-{lab}']['menuPass']['f1_over_chance'] or 0:.2f}"
        for lab in ("F", "G", "Q", "M"))
    return c


def main() -> int:
    d = REPO / "results" / "revision" / "sensitivity"
    scs = {k: json.loads((d / f"{k}.json").read_text()) for k in ("base", "ev_fragments", "ev_strict", "var_A", "var_B")}
    cl = {k: claims(v) for k, v in scs.items()}
    out = {"claims": cl, "changed": {k: {c: [cl["base"][c], v] for c, v in cl[k].items() if v != cl["base"][c]}
                                     for k in cl if k != "base"}}
    (d / "claims.json").write_text(json.dumps(out, indent=1))
    for k, ch in out["changed"].items():
        print(f"\n=== {k}: {len(ch)} claims change")
        for c, (o, n) in ch.items():
            print(f"  {c}: {o}  ->  {n}")
    print("\n=== base")
    for c, v in cl["base"].items():
        print(f"  {c}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
