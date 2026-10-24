"""WP1: the adapter reproduces BRiMS.

test_brims_* need the BRiMS range parquet (local only) and skip without it.
test_adapter_matches_run_strata needs no data: it checks the adapter against DRIFT's own
run_strata.py driver on a synthetic tagged parquet.
"""
import csv
import math

import numpy as np
import pandas as pd
import pytest
import yaml

from ctit.adapters import drift
from ctit.experiments import drift_parity

CONFIG = yaml.safe_load((drift_parity.REPO_ROOT / "configs" / "drift_parity.yaml").read_text())

# BRiMS reference_outputs/tables, transition encoding.
TABLE1 = {
    "n_events_total": 6_773_063,
    "n_events_tagged": 2_141_479,
    "n_hosts_kept": 27,
    "n_hosts_excluded": 1,
    "edge_vocabulary_size": 41,
}
TABLE5_TOP10 = [
    ("l1-eng-067", 0.6153), ("l2-eng-win10-4", 0.4806), ("l4-distrib-1", 0.4278),
    ("l5-dc", 0.4250), ("l5-mail", 0.3907), ("l5-dns", 0.3758),
    ("l3-eng-win7-2", 0.3220), ("l5-smtp", 0.2923), ("l3-eng-win7-1", 0.2765),
    ("l4-maint-2", 0.1152),
]


def _have_brims_data():
    return (drift_parity.resolve(CONFIG, "tagged_cache").exists()
            or drift_parity.brims_parquet(CONFIG).exists())


@pytest.fixture(scope="module")
def brims_metrics():
    if not _have_brims_data():
        pytest.skip(f"BRiMS parquet not available (set {drift_parity.PARQUET_ENV})")
    return drift_parity.run(CONFIG)


@pytest.mark.slow
def test_brims_headline_number(brims_metrics):
    # The parity number: BRiMS Table 5 rank 1, d(l1-eng-067) = 0.6153 (4 dp).
    assert abs(brims_metrics["peer_jsd"]["l1-eng-067"] - 0.6153) < 5e-5


@pytest.mark.slow
def test_brims_table1(brims_metrics):
    assert {k: brims_metrics[k] for k in TABLE1} == TABLE1


@pytest.mark.slow
def test_brims_table5_top10(brims_metrics):
    got = brims_metrics["top10_peer_jsd"]
    assert [h for h, _ in got] == [h for h, _ in TABLE5_TOP10]
    for (_, j), (_, ref) in zip(got, TABLE5_TOP10):
        assert abs(j - ref) < 5e-5


def _synthetic_tagged(path, seed=0):
    """Three roles with distinct tactic Markov chains, 4 hosts each, plus one sparse host."""
    rng = np.random.default_rng(seed)
    tactics = ["Execution", "Defense Evasion", "Persistence", "Credential Access", "Command and Control"]
    rows = []
    for r, role in enumerate(["ws", "srv", "ics"]):
        T = rng.dirichlet(np.ones(len(tactics)) * (0.3 + r), size=len(tactics))
        for i in range(4):
            host = f"l5-{role}-{i + 1}"
            state, t0 = 0, pd.Timestamp("2024-01-01", tz="UTC")
            for k in range(400):
                tac = tactics[state] if rng.random() > 0.3 else ""  # some unmapped events
                rows.append((host, t0 + pd.Timedelta(seconds=int(k * 7 + rng.integers(0, 5))), tac))
                state = rng.choice(len(tactics), p=T[state])
    rows += [("l5-sparse-1", pd.Timestamp("2024-01-01", tz="UTC") + pd.Timedelta(seconds=k), "Execution")
             for k in range(5)]
    pd.DataFrame(rows, columns=["host", "ts", "tactic"]).to_parquet(path, index=False)


def test_adapter_matches_run_strata(tmp_path, capsys):
    data = tmp_path / "tagged.parquet"
    _synthetic_tagged(data)
    roles_file = tmp_path / "roles.json"
    roles_file.write_text('{"l5-ws-1": "workstation", "l5-ws-2": "workstation"}')

    out = tmp_path / "driver_out"
    assert drift._run_strata.main([
        "--input", str(data), "--input-mode", "tagged", "--tactic-col", "tactic",
        "--roles", str(roles_file), "--out-dir", str(out), "--encoding", "transition",
    ]) == 0
    capsys.readouterr()

    ingest = drift.ingest_tagged(data)
    drift.apply_role_overrides(ingest, roles_file)
    result = drift.run_brims_transition(ingest)

    with (out / "peer_baseline_jsd.csv").open() as f:
        driver = {row["host_id"]: row for row in csv.DictReader(f)}
    assert set(driver) == set(result.host_ids)
    assert [h for h, _ in result.excluded] == ["l5-sparse-1"]
    for h, info in result.peer_jsd.items():
        assert driver[h]["role"] == info["role"]
        if math.isnan(info["jsd"]):
            assert driver[h]["jsd_vs_peer_baseline"] == ""
        else:
            assert abs(float(driver[h]["jsd_vs_peer_baseline"]) - info["jsd"]) < 1e-6
    np.testing.assert_allclose(np.load(out / "vectors.npy"), result.vectors)


def test_tagged_cache_round_trip(tmp_path):
    data = tmp_path / "tagged.parquet"
    _synthetic_tagged(data)
    first = drift.ingest_tagged(data)
    cache = tmp_path / "cache.parquet"
    drift.save_tagged(cache, first)
    second = drift.ingest_tagged(cache)
    assert second.per_host_counts == first.per_host_counts
    assert second.n_events_total == first.n_events_total
    assert second.n_events_tagged == first.n_events_tagged
