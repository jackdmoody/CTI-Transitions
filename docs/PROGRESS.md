# Progress

## 2026-10-24: environment setup
- Done: DRIFT pinned as the submodule `third_party/DRIFT` @ `brims-2026` (`3517424`). `ctit/adapters/drift.py` loads it and checks the pin. Conda env `w2` (Python 3.12.15) has DRIFT's `requirements.txt` installed. `ANTHROPIC_API_KEY` is loaded from `.env` (`ctit/env.py`); the API smoke test succeeded.

## 2026-10-24: planning + WP1 (in progress)
- Plan approved: `docs/WORKPLAN.md`. Spec §2.5/§3/§4/§5/§7 updated: mean log-LR per transition, extended Sigma mapper, `qwen3:14b`. SPEC_ISSUES has 4 entries.
- WP1 code done: run contract (`ctit/run.py`, `ctit/calls.py`), adapter API (`ingest_raw_sysmon`, `ingest_tagged`, `save_tagged`, `apply_role_overrides`, `run_brims_transition`), `configs/drift_parity.yaml`, `tests/test_drift_parity.py`.
- Passed: 13 tests, including adapter ≡ DRIFT's `run_strata.py` on a synthetic parquet (peer JSD to 1e-6, identical vectors).
- **Not yet passed (WP1 acceptance):** the 3 BRiMS parity tests skip, because the BRiMS raw Sysmon parquet isn't on this machine. Needed: its path, set as `brims_parquet` in `configs/drift_parity.yaml` or via `CTIT_BRIMS_PARQUET`. Then run `pytest tests/test_drift_parity.py`; the first run tokenizes 6.8M rows and caches to `data/cache/`.
- Open: DPRK plan check and OTRF availability check (Jack, by hand; record results here). Choice of size-curve model pending (proposed `qwen3:4b`). Ollama not installed yet.
- Next: finish WP1 once the parquet is available.

## 2026-10-24: WP3, WP4 (public track)
- WP3 done: `ctit/cti/manifest.py` + `scripts/check_leakage.py`; synthetic fixture manifests (1 good, 4 bad) and tests. `data/cti/manifest.csv` is header-only and fails as expected (0 priors per core actor) until Jack supplies reports.
- WP4 done.
  - **OTRF APT29 is still hosted:** day1 zip 13.9 MB, day2 43.0 MB; SHA-256 in `data/otrf/apt29/raw/`. Ingested 642k events (Sysmon + Security + System) for 4 hosts. Counts match the OTRF README per channel. Roles: newyork = dc (it logs Kerberos 4768/4769), the other 3 are workstations.
  - **ATLASv2** is a single 12.2 GB tarball on Box (not Bitbucket). Ingested 32.1M events: 31.8M Security, 329k Sysmon. **ATLASv2 Sysmon has only event IDs 1 and 5.** Ground truth: Security EventRecordIDs for 16 scenarios. Roles: both hosts are workstations.
  - **BRiMS mapper K:** OTRF Sysmon = {Execution, Persistence, Defense Evasion, Credential Access, C2}; with Security/System it adds {Privilege Escalation, Discovery}. ATLASv2 Sysmon = {Execution, Defense Evasion}. OTRF Sysmon tag rate is 88% (every registry event becomes Persistence, every process access becomes Credential Access). ATLASv2 Sysmon tag rate is 0.3%.
- Ollama 0.40.10 (brew) with qwen3:14b, qwen3:4b and qwen3:4b-instruct; digests in `configs/models.yaml`. No extraction runs.
