import subprocess
from pathlib import Path

import pandas as pd
import pytest

from ctit.adapters import drift


def test_submodule_at_pinned_commit():
    head = subprocess.run(
        ["git", "-C", str(drift.DRIFT_ROOT), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True,
    ).stdout.strip()
    assert head == drift.DRIFT_COMMIT == "3517424e71a5ffb6f1d9be074f6a82b9e45e3f45"


def test_wrong_commit_raises(monkeypatch):
    monkeypatch.setattr(drift, "DRIFT_COMMIT", "0" * 40)
    with pytest.raises(drift.DriftPinError, match="expected 0000"):
        drift.verify_pin()


def test_missing_submodule_raises(monkeypatch, tmp_path):
    monkeypatch.setattr(drift, "DRIFT_ROOT", tmp_path / "DRIFT")
    with pytest.raises(drift.DriftPinError, match="submodule update --init"):
        drift.verify_pin()


def test_packages_load_from_pinned_paths():
    assert Path(drift.sysmon_pipeline.__file__).is_relative_to(drift.PIPELINE_DRIVERS)
    assert Path(drift.observational.__file__).is_relative_to(drift.OBSERVATIONAL_DIR)
    from observational import build_vectors_union_vocab, compute_peer_baseline_jsd  # noqa: F401


def test_tactic_mapper_chain():
    # Same smoke check DRIFT's setup_env.py runs: raw Sysmon row -> mitre_tactic.
    df = pd.DataFrame({
        "ts": pd.to_datetime(["2024-01-01 10:00:00"]),
        "host": ["h1"], "EventID": [1],
        "Image": ["C:/cmd.exe"], "ParentImage": [""],
        "CommandLine": ["whoami"], "User": ["u"], "IntegrityLevel": ["High"],
    })
    tagged = drift.build_tokens(drift.normalize_schema(df, drift.StrataConfig()))
    assert "mitre_tactic" in tagged.columns
