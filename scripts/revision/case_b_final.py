"""Case study B at 10,000 host-cluster bootstrap resamples (adopted settings; Jack, 2026-11-05). No model calls.

    python scripts/revision/case_b_final.py

Reruns the three case-B runs behind the draft, each from its own saved config with only the bootstrap
changed to {n: 10000, seed: 20261105}:
  as_run     results/20261031T172917Z-redteam_scoring-a0bb280
  collapsed  results/20261031T173148Z-redteam_scoring-a0bb280
  scripted   results/20261031T172645Z-case_b_scripted-a0bb280
Writes results/revision/final/case_b/<name>/{config.yaml, metrics.json} and supplement/s_case_b.{csv,tex}.
Point AUPRCs do not depend on the bootstrap; the script checks that they equal the draft runs'.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from ctit.experiments import case_b_scripted, redteam_scoring  # noqa: E402
from ctit.experiments import revision_engine as R  # noqa: E402
from scripts.revision.final import SUPP, provenance, write  # noqa: E402

OUT = REPO / "results" / "revision" / "final" / "case_b"
RUNS = {"as_run": ("20261031T172917Z-redteam_scoring-a0bb280", redteam_scoring.run),
        "collapsed": ("20261031T173148Z-redteam_scoring-a0bb280", redteam_scoring.run),
        "scripted": ("20261031T172645Z-case_b_scripted-a0bb280", case_b_scripted.run)}


def auprc_cells(m: dict, name: str) -> dict:
    """{label: (auprc, lo, hi)} from either experiment's metrics."""
    out = {}
    if name == "scripted":
        for variant, v in m.items():
            if isinstance(v, dict) and "conditions" in v:
                for c, x in v["conditions"].items():
                    out[f"{variant}/{c}"] = (x["point"]["auprc"], *x["ci95"]["auprc"])
        return out
    for c, x in m["conditions"].items():
        out[c] = (x["point"]["auprc"], *x["ci95"]["auprc"])
    return out


def main() -> int:
    rows = []
    for name, (run, fn) in RUNS.items():
        cfg = yaml.safe_load((REPO / "results" / run / "config.yaml").read_text())
        cfg.pop("_provenance", None)
        old = json.loads((REPO / "results" / run / "metrics.json").read_text())
        cfg["bootstrap"] = {"n": R.N_BOOT, "seed": R.SEED}
        m = fn(cfg)
        d = OUT / name
        d.mkdir(parents=True, exist_ok=True)
        (d / "metrics.json").write_text(json.dumps(m, indent=1, default=float))
        (d / "config.yaml").write_text(yaml.safe_dump({**cfg, "_provenance": {"script": "scripts/revision/case_b_final.py",
                                                                             "from_run": run, **provenance()}}, sort_keys=False))
        new_c, old_c = auprc_cells(m, name), auprc_cells(old, name)
        for k, (a, lo, hi) in sorted(new_c.items()):
            oa, olo, ohi = old_c[k]
            assert abs(a - oa) < 1e-12, (name, k, a, oa)
            rows.append([name, k, f"{a:.3f}", f"[{olo:.2f}, {ohi:.2f}]", f"[{lo:.2f}, {hi:.2f}]"])
        print("done", name, flush=True)
    write(SUPP, "s_case_b", ["Run", "Condition", "AUPRC", "95% host-cluster (draft, 1,000)", "95% host-cluster (10,000)"],
          rows, "Case study B: AUPRC with host-cluster bootstrap intervals, draft (1,000) vs adopted (10,000)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
