"""Single entry point to DRIFT. No other ctit module imports DRIFT code directly.

DRIFT is a git submodule at third_party/DRIFT, pinned to tag brims-2026. It ships
no package metadata, so this module puts its two packages on sys.path:

  - sysmon_pipeline: scripts/pipeline_drivers/sysmon_pipeline (used in place)
  - observational:   scripts/pipeline_drivers/observational.tar.gz, extracted to
                     .cache/drift/<sha>/ so the submodule working tree stays clean

On import it checks that the submodule HEAD is the pinned commit and that the
working tree is unmodified, and raises DriftPinError otherwise.
"""
from __future__ import annotations

import subprocess
import sys
import tarfile
from pathlib import Path

DRIFT_TAG = "brims-2026"
DRIFT_COMMIT = "3517424e71a5ffb6f1d9be074f6a82b9e45e3f45"

REPO_ROOT = Path(__file__).resolve().parents[2]
DRIFT_ROOT = REPO_ROOT / "third_party" / "DRIFT"
PIPELINE_DRIVERS = DRIFT_ROOT / "scripts" / "pipeline_drivers"
OBSERVATIONAL_TARBALL = PIPELINE_DRIVERS / "observational.tar.gz"
OBSERVATIONAL_DIR = REPO_ROOT / ".cache" / "drift" / DRIFT_COMMIT[:12]


class DriftPinError(RuntimeError):
    """The DRIFT submodule is missing, at the wrong commit, or modified."""


def _git(*args: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(DRIFT_ROOT), *args],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise DriftPinError(
            f"git {' '.join(args)} failed in {DRIFT_ROOT}: {result.stderr.strip()}. "
            "Run `git submodule update --init third_party/DRIFT`."
        )
    return result.stdout.strip()


def verify_pin() -> None:
    if not (DRIFT_ROOT / ".git").exists():
        raise DriftPinError(
            f"DRIFT submodule not found at {DRIFT_ROOT}. "
            "Run `git submodule update --init third_party/DRIFT`."
        )
    head = _git("rev-parse", "HEAD")
    if head != DRIFT_COMMIT:
        raise DriftPinError(
            f"DRIFT submodule HEAD is {head}, expected {DRIFT_COMMIT} ({DRIFT_TAG}). "
            f"Run `git -C {DRIFT_ROOT} checkout {DRIFT_TAG}`."
        )
    dirty = _git("status", "--porcelain")
    if dirty:
        raise DriftPinError(
            f"DRIFT submodule at {DRIFT_ROOT} has local changes; DRIFT must not be "
            f"modified. Changes:\n{dirty}"
        )


def _extract_observational() -> None:
    if (OBSERVATIONAL_DIR / "observational" / "__init__.py").exists():
        return
    OBSERVATIONAL_DIR.mkdir(parents=True, exist_ok=True)
    with tarfile.open(OBSERVATIONAL_TARBALL, "r:gz") as tar:
        tar.extractall(OBSERVATIONAL_DIR, filter="data")


def _check_origin(module, expected_root: Path) -> None:
    origin = Path(module.__file__).resolve()
    if not origin.is_relative_to(expected_root.resolve()):
        raise DriftPinError(
            f"{module.__name__} was imported from {origin}, not the pinned copy under "
            f"{expected_root}. Uninstall the other copy (e.g. one setup_env.py put "
            "in site-packages)."
        )


def _load():
    verify_pin()
    _extract_observational()
    for path in (str(OBSERVATIONAL_DIR), str(PIPELINE_DRIVERS)):
        if path not in sys.path:
            sys.path.insert(0, path)

    import observational
    import sysmon_pipeline

    _check_origin(sysmon_pipeline, PIPELINE_DRIVERS)
    _check_origin(observational, OBSERVATIONAL_DIR)
    return sysmon_pipeline, observational


sysmon_pipeline, observational = _load()

from sysmon_pipeline.config import StrataConfig  # noqa: E402
from sysmon_pipeline.mapping import build_tokens  # noqa: E402
from sysmon_pipeline.schema import normalize_schema  # noqa: E402
from sysmon_pipeline.sequence import fit_gap_threshold  # noqa: E402

__all__ = [
    "DRIFT_COMMIT", "DRIFT_TAG", "DriftPinError", "verify_pin",
    "sysmon_pipeline", "observational",
    "StrataConfig", "build_tokens", "normalize_schema", "fit_gap_threshold",
]
