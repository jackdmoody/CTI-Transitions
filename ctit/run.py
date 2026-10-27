"""Run contract (spec §8): python -m ctit.run --config <yaml>

Writes results/<run_id>/{config.yaml, metrics.json, calls.jsonl}. config.yaml is the input
config plus a _provenance block (git SHA, DRIFT commit, seeds, model versions), and can be
passed back to --config to re-run.
"""
from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

from ctit.calls import CallLogger
from ctit.experiments import baseline_priors, benign_breakdown, benign_windows, drift_parity, mapper_report, mapper_v3, redteam_day, redteam_diag, redteam_testset, wp5_gate

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_ROOT = REPO_ROOT / "results"

# experiment name -> fn(config: dict, calls: CallLogger) -> metrics dict
EXPERIMENTS = {
    "drift_parity": drift_parity.run,
    "mapper_report": mapper_report.run,
    "baseline_priors": baseline_priors.run,
    "wp5_gate": wp5_gate.run,
    "mapper_v3": mapper_v3.run,
    "benign_windows": benign_windows.run,
    "benign_breakdown": benign_breakdown.run,
    "redteam_day": redteam_day.run,
    "redteam_testset": redteam_testset.run,
    "redteam_diag": redteam_diag.run,
}


def git_state() -> tuple[str, bool]:
    sha = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    dirty = bool(subprocess.run(
        ["git", "-C", str(REPO_ROOT), "status", "--porcelain", "--untracked-files=no"],
        capture_output=True, text=True, check=True,
    ).stdout.strip())
    return sha, dirty


def load_config(path: Path) -> dict:
    config = yaml.safe_load(Path(path).read_text())
    config.pop("_provenance", None)
    return config


def run(config_path: Path, *, allow_dirty: bool = False, results_root: Path = RESULTS_ROOT) -> Path:
    from ctit.adapters.drift import DRIFT_COMMIT

    config = load_config(config_path)
    experiment = config["experiment"]
    if experiment not in EXPERIMENTS:
        raise ValueError(f"unknown experiment {experiment!r}; known: {sorted(EXPERIMENTS)}")

    sha, dirty = git_state()
    if dirty and not allow_dirty:
        raise RuntimeError(
            "working tree has uncommitted changes to tracked files; commit first "
            "(or pass --allow-dirty for a non-reportable run)"
        )

    started = datetime.now(timezone.utc)
    run_id = f"{started:%Y%m%dT%H%M%SZ}-{experiment}-{sha[:7]}{'-dirty' if dirty else ''}"
    out = results_root / run_id
    out.mkdir(parents=True)

    provenance = {
        "run_id": run_id,
        "started_utc": started.isoformat(),
        "git_sha": sha,
        "git_dirty": dirty,
        "drift_commit": DRIFT_COMMIT,
        "python": platform.python_version(),
        "seeds": config.get("seeds", []),
        "model_versions": config.get("models", {}),
    }
    (out / "config.yaml").write_text(
        yaml.safe_dump({**config, "_provenance": provenance}, sort_keys=False)
    )
    calls = CallLogger(out / "calls.jsonl")

    metrics = EXPERIMENTS[experiment](config, calls)
    (out / "metrics.json").write_text(json.dumps(metrics, indent=2, sort_keys=True))
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", required=True, type=Path)
    p.add_argument("--allow-dirty", action="store_true")
    args = p.parse_args(argv)
    out = run(args.config, allow_dirty=args.allow_dirty)
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
