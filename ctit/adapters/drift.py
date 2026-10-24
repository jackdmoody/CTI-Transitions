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

import json  # noqa: E402
from dataclasses import dataclass  # noqa: E402

import numpy as np  # noqa: E402
import run_strata as _run_strata  # noqa: E402  (DRIFT driver script, on sys.path via PIPELINE_DRIVERS)
from observational import (  # noqa: E402
    DEFAULT_LAPLACE_ALPHA,
    IngestResult,
    Session,
    build_vectors_union_vocab,
    compute_peer_baseline_jsd,
    from_raw_sysmon_parquet,
    from_tagged_parquet,
    infer_role_from_hostname,
    sessionize_host,
)
from sysmon_pipeline.config import StrataConfig  # noqa: E402
from sysmon_pipeline.mapping import build_tokens  # noqa: E402
from sysmon_pipeline.schema import normalize_schema  # noqa: E402
from sysmon_pipeline.sequence import fit_gap_threshold  # noqa: E402

_check_origin(_run_strata, PIPELINE_DRIVERS)

BRIMS_ROLES_FILE = DRIFT_ROOT / "config" / "example_roles.json"
BRIMS_MIN_TRANSITIONS = 30  # run_strata.py --min-transitions default


def ingest_raw_sysmon(path, *, limit_groups=None, progress=False) -> IngestResult:
    """Raw Sysmon parquet -> normalize_schema -> build_tokens (BRiMS mapper) -> IngestResult."""
    return from_raw_sysmon_parquet(path, limit_groups=limit_groups, progress=progress)


def ingest_tagged(path, *, tactic_col="tactic", host_col="host", ts_col="ts") -> IngestResult:
    return from_tagged_parquet(path, host_col=host_col, ts_col=ts_col, tactic_col=tactic_col)


def save_tagged(path, ingest: IngestResult) -> None:
    """Write (host, ts, tactic) parquet with DRIFT's own writer; read back with ingest_tagged."""
    _run_strata._write_tagged_parquet(Path(path), ingest)


def apply_role_overrides(ingest: IngestResult, roles_file) -> int:
    """Same semantics as run_strata.py --roles-file: only hosts already in the ingest are
    overridden; the rest keep infer_role_from_hostname. Returns the number applied."""
    overrides = json.loads(Path(roles_file).read_text())
    applied = 0
    for host, role in overrides.items():
        if host in ingest.roles:
            ingest.roles[host] = str(role)
            applied += 1
    return applied


@dataclass
class TransitionRun:
    host_ids: list[str]
    vectors: np.ndarray  # (N, D), rows sum to 1
    edges: list[tuple[str, str]]  # length D
    roles: dict[str, str]
    peer_jsd: dict[str, dict]  # host -> {role, jsd, n_peers}
    excluded: list[tuple[str, int]]  # (host, n_transitions) below threshold


def run_brims_transition(
    ingest: IngestResult,
    *,
    min_transitions: int = BRIMS_MIN_TRANSITIONS,
    alpha: float = DEFAULT_LAPLACE_ALPHA,
) -> TransitionRun:
    """run_strata.py steps 2-4 (transition encoding): threshold filter, union-vocab vectors,
    leave-one-out peer-baseline JSD. Clustering and sibling steps are not needed by W2."""
    kept = ingest.hosts_meeting_threshold(min_transitions)
    kept_set = set(kept)
    excluded = [
        (h, sum(ingest.per_host_counts[h].values()))
        for h in ingest.per_host_tactics
        if h not in kept_set
    ]
    host_ids, vectors, edges = build_vectors_union_vocab(
        {h: ingest.per_host_counts[h] for h in kept}, alpha=alpha
    )
    roles = {h: ingest.roles[h] for h in kept}
    peer_jsd = compute_peer_baseline_jsd(host_ids, vectors, roles)
    return TransitionRun(host_ids, vectors, edges, roles, peer_jsd, excluded)


__all__ = [
    "DRIFT_COMMIT", "DRIFT_TAG", "DriftPinError", "verify_pin",
    "sysmon_pipeline", "observational",
    "StrataConfig", "build_tokens", "normalize_schema", "fit_gap_threshold",
    "IngestResult", "Session", "DEFAULT_LAPLACE_ALPHA",
    "build_vectors_union_vocab", "compute_peer_baseline_jsd",
    "infer_role_from_hostname", "sessionize_host",
    "BRIMS_ROLES_FILE", "BRIMS_MIN_TRANSITIONS",
    "ingest_raw_sysmon", "ingest_tagged", "save_tagged", "apply_role_overrides",
    "TransitionRun", "run_brims_transition",
]
