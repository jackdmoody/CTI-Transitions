"""Phase 0 tallies for the AICS-27 revision (internal review). Read-only: cached priors only, no model calls.

Writes results/revision/phase0/{config.yaml, metrics.json}.
- evidence: per label x actor, R priors: edges in C_a, edges whose every supporting transition (in that
  report) fails the strict / fragment-aware evidence check, and C_a if such transitions were dropped.
- schema: per label x condition x actor: calls (chunks), first-attempt schema failures, chunks lost after
  the retry, refusals.
- B: edge-set size per sample and whether counts are binary.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import yaml

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from ctit.cti import extract  # noqa: E402
from ctit.experiments import v2_common as v2  # noqa: E402

OUT = REPO / "results" / "revision" / "phase0"
LABELS = ["F", "G", "Q", "Q5", "M", "M5", "M3", "M35"]
ACTORS = ["APT29", "menuPass", "OilRig", "Sandworm"]


def main() -> int:
    cfg = yaml.safe_load((REPO / "configs" / "v2_priors.yaml").read_text())
    OUT.mkdir(parents=True, exist_ok=True)
    out = {"evidence": {}, "schema": {}, "B": {}}
    for label in LABELS:
        spec = cfg["priors"][label]
        d = v2.prior_dir(spec)
        # schema/refusal tallies over every saved prior file (R, B, oracle)
        for f in sorted(d.glob("*.json")):
            p = json.loads(f.read_text())
            cond, actor = p["meta"]["cond"], p["meta"]["actor"]
            s = out["schema"].setdefault(label, {}).setdefault(cond, {}).setdefault(
                actor, {"calls": 0, "first_attempt_schema_fail": 0, "lost_after_retry": 0, "refused": 0, "samples": 0})
            s["samples"] += 1
            for c in p["chunks"]:
                s["calls"] += 1
                s["first_attempt_schema_fail"] += int(c["attempts"] > 1 or c["status"] == "skipped_schema")
                s["lost_after_retry"] += int(c["status"] == "skipped_schema")
                s["refused"] += int(c["status"] == "refused")
        for a in ACTORS:
            R = v2.load(spec, "R", a)
            ev = []
            for p in R:
                C = np.array(p["counts"])
                tr = p["transitions"]
                C_strict = extract.counts([t for t in tr if t.get("evidence_ok") is not False])
                C_frag = extract.counts([t for t in tr if t.get("evidence_ok_fragments") is not False])
                assert np.array_equal(extract.counts(tr), C), "saved counts are not the unfiltered per-document counts"
                ev.append({
                    "sample": p["meta"]["sample"], "edges": int((C > 0).sum()), "count_total": int(C.sum()),
                    "transitions": len(tr),
                    "transitions_fail_strict": sum(t.get("evidence_ok") is False for t in tr),
                    "transitions_fail_fragments": sum(t.get("evidence_ok_fragments") is False for t in tr),
                    "count_units_only_failing_strict": int((C - C_strict).sum()),
                    "count_units_only_failing_fragments": int((C - C_frag).sum()),
                    "edges_lost_if_filtered_strict": int(((C > 0) & (C_strict == 0)).sum()),
                    "edges_lost_if_filtered_fragments": int(((C > 0) & (C_frag == 0)).sum()),
                })
            out["evidence"].setdefault(label, {})[a] = ev
            B = v2.load(spec, "B", a)
            out["B"].setdefault(label, {})[a] = [
                {"sample": p["meta"]["sample"], "edges": int((np.array(p["counts"]) > 0).sum()),
                 "max_count": int(np.max(p["counts"])), "chunk_status": [c["status"] for c in p["chunks"]],
                 "attempts": [c["attempts"] for c in p["chunks"]]} for p in B]
    sha = subprocess.run(["git", "-C", str(REPO), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    dirty = bool(subprocess.run(["git", "-C", str(REPO), "status", "--porcelain", "--untracked-files=no"],
                                capture_output=True, text=True).stdout.strip())
    (OUT / "config.yaml").write_text(yaml.safe_dump({"script": "scripts/revision/phase0_tally.py", "git_sha": sha,
                                                     "git_dirty": dirty, "labels": LABELS, "priors": cfg["priors"],
                                                     "seeds": []}, sort_keys=False))
    (OUT / "metrics.json").write_text(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
