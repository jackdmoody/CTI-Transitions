"""Case study A under the adopted settings (exact chance; 10,000 resamples). No model calls.

    python scripts/revision/case_a_final.py

Executed sequence: ctit.experiments.otrf_case.executed_sequences (frozen v3; per host and day, repeats collapsed).
For every prior family and actor: IG per executed transition with an i.i.d. 95% interval (10,000, seed
[20261105, 0, crc32('caseA')]) and moving-block intervals inside each host-day sequence (b = 2, 3, 5); edge-F1
against the executed edges with exact F1 / chance and percentile. Also the executed edge set against the APT29 plan.
Writes results/revision/final/case_a/{config.yaml, metrics.json} and supplement/s_case_a.{csv,tex}.
"""
from __future__ import annotations

import json
import sys
import zlib
from pathlib import Path

import numpy as np
import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from ctit.eval import actor_jsd  # noqa: E402
from ctit.experiments import otrf_case  # noqa: E402
from ctit.experiments import revision_engine as R  # noqa: E402
from ctit.experiments.prior_likelihood import pairs  # noqa: E402
from ctit.map import v3  # noqa: E402
from ctit.map.attack import TACTICS  # noqa: E402
from scripts.revision.final import SUPP, iv, provenance, sg, write  # noqa: E402

OUT = REPO / "results" / "revision" / "final" / "case_a"


def main() -> int:
    cfg = yaml.safe_load((REPO / "configs" / "v2_priors.yaml").read_text())
    seqs = list(otrf_case.executed_sequences(v3.load_v3()).values())
    executed, E = pairs(seqs), actor_jsd.counts(seqs, list(TACTICS))
    seg = np.array([i for i, s in enumerate(seqs) for _ in range(max(len(s) - 1, 0))])
    ref = R.Ref("caseA", "executed", [], E, executed, seg)
    a = zlib.crc32(b"caseA")
    idx = {"iid": np.random.default_rng([R.SEED, 0, a]).integers(0, ref.L, (R.N_BOOT, ref.L))}
    for b in R.BLOCKS:
        idx[b] = R.segment_blocks(seg, b, R.N_BOOT, np.random.default_rng([R.SEED, b, a]))
    ch = R.ExactChance(E)
    plan = R.reference("APT29")
    vs_plan = R.ExactChance(plan.G).score(E)
    out = {"executed_transitions": ref.L, "executed_edges": ch.g, "sequences": len(seqs),
           "executed_vs_plan": {k: vs_plan[k] for k in ("f1", "ratio", "percentile", "edges_extracted", "tp")}, "cells": {}}
    rows = []
    for fam in R.FAMILIES:
        for actor in R.ACTORS:
            Cs = R.family_counts(cfg, fam, actor)
            c = R.intervals(R.per_transition(Cs, executed), idx)
            t2 = R.t2_cell(Cs, ch)
            out["cells"].setdefault(fam, {})[actor] = {**c, **{k: t2[k] for k in ("edge_f1", "f1_over_chance", "percentile", "edges_mean")}}
            rows.append([fam, actor, sg(c["point"]), iv(c["iid"]["ci95"]), c["iid"]["status"],
                         "/".join(c[f"block_{b}"]["status"] for b in R.BLOCKS), f"{t2['edge_f1']:.3f}",
                         "—" if t2["f1_over_chance"] is None else f"{t2['f1_over_chance']:.2f}", f"{t2['percentile']:.1f}"])
    write(SUPP, "s_case_a", ["Prior", "Prior actor", "IG", "i.i.d. 95%", "status", "block b=2/3/5", "edge-F1",
                             "F1/chance (exact)", "pct (exact)"], rows,
          f"Case A (executed OTRF APT29, {ref.L} transitions, {ch.g} edges): exact chance, 10,000 resamples. "
          f"Executed vs plan: F1/chance {vs_plan['ratio']:.2f}")
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "metrics.json").write_text(json.dumps(out, indent=1, default=float))
    (OUT / "config.yaml").write_text(yaml.safe_dump({"script": "scripts/revision/case_a_final.py", **provenance(),
                                                     "settings": R.SETTINGS, "seed": [R.SEED, 0, "crc32(caseA)"]},
                                                    sort_keys=False))
    print("executed vs plan", out["executed_vs_plan"], "L", ref.L, "edges", ch.g, "seqs", len(seqs))
    for fam in ("R-F", "R-G", "ATTK", "B-G"):
        print(fam, {k: (round(v["point"], 2), [round(x, 2) for x in v["iid"]["ci95"]], v["iid"]["status"],
                        round(v["f1_over_chance"] or 0, 2)) for k, v in out["cells"][fam].items()})
    return 0


if __name__ == "__main__":
    sys.exit(main())
