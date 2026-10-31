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
from ctit.experiments import baseline_priors, benign_breakdown, benign_windows, case_a_v2, case_b_scripted, drift_parity, evidence_audit, extraction, extraction_report, ig_dependence, mapper_report, mapper_v3, otrf_case, paper_tables, paper_tables_v2, prior_likelihood, reading_bootstrap, redteam_day, redteam_diag, redteam_diagnosis, redteam_scoring, redteam_testset, schema_failures, wp5_gate

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
    "extraction": extraction.run,
    "extraction_report": extraction_report.run,
    "redteam_scoring": redteam_scoring.run,
    "otrf_case": otrf_case.run,
    "redteam_diagnosis": redteam_diagnosis.run,
    "prior_likelihood": prior_likelihood.run,
    "schema_failures": schema_failures.run,
    "paper_tables": paper_tables.run,
    # v2 analyses (POST HOC, 2026-10-31)
    "reading_bootstrap": reading_bootstrap.run,
    "ig_dependence": ig_dependence.run,
    "evidence_audit": evidence_audit.run,
    "case_a_v2": case_a_v2.run,
    "case_b_scripted": case_b_scripted.run,
    "paper_tables_v2": paper_tables_v2.run,
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
    if "priors_from" in config and "priors" not in config:  # shared model list (v2 analyses); resolved here
        config["priors"] = yaml.safe_load((REPO_ROOT / config["priors_from"]).read_text())["priors"]
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
