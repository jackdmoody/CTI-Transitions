"""DRIFT parity (WP1): reproduce the BRiMS transition-encoding peer-JSD run through the adapter.

Local only: the BRiMS parquet is range data and never leaves this machine.
"""
from __future__ import annotations

import os
from pathlib import Path

from ctit.adapters import drift

REPO_ROOT = Path(__file__).resolve().parents[2]
PARQUET_ENV = "CTIT_BRIMS_PARQUET"


def resolve(config: dict, key: str) -> Path:
    path = Path(config[key])
    return path if path.is_absolute() else REPO_ROOT / path


def brims_parquet(config: dict) -> Path:
    override = os.environ.get(PARQUET_ENV)
    return Path(override) if override else resolve(config, "brims_parquet")


def load_ingest(config: dict) -> drift.IngestResult:
    """Tagged cache if present (skips the slow row-wise tokenizer), else raw + write the cache."""
    cache = resolve(config, "tagged_cache")
    if cache.exists():
        return drift.ingest_tagged(cache)
    parquet = brims_parquet(config)
    if not parquet.exists():
        raise FileNotFoundError(
            f"BRiMS parquet not found at {parquet}; set brims_parquet in the config or {PARQUET_ENV}"
        )
    ingest = drift.ingest_raw_sysmon(parquet, progress=True)
    drift.save_tagged(cache, ingest)
    return ingest


def run(config: dict, calls=None) -> dict:
    ingest = load_ingest(config)
    drift.apply_role_overrides(ingest, resolve(config, "roles_file"))
    result = drift.run_brims_transition(
        ingest, min_transitions=config["min_transitions"], alpha=config["alpha"]
    )
    ranked = sorted(
        ((h, v["jsd"]) for h, v in result.peer_jsd.items() if v["jsd"] == v["jsd"]),
        key=lambda kv: -kv[1],
    )
    return {
        "n_events_total": ingest.n_events_total,
        "n_events_tagged": ingest.n_events_tagged,
        "n_hosts_kept": len(result.host_ids),
        "n_hosts_excluded": len(result.excluded),
        "edge_vocabulary_size": len(result.edges),
        "top10_peer_jsd": [[h, j] for h, j in ranked[:10]],
        "peer_jsd": {h: v["jsd"] for h, v in result.peer_jsd.items()},
    }
