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

## 2026-10-24: WP4b (frozen, awaiting review)
- Extended mapper frozen at `714f999`: 2017 SigmaHQ `r2026-07-01` rules, pySigma SQLite engine, deterministic primary tactic; policy in `docs/MAPPER_POLICY.md`. Report run: `results/20261024T145254Z-mapper_report-714f999`.
- Headline numbers: K on OTRF Sysmon 11 (BRiMS 5). Benign Sysmon tag rate 0.028% (BRiMS 0.26%). Technique recall: OTRF plan steps 0.38 (BRiMS 0.21), Splunk samples 0.76 (BRiMS 0.26).
- **Stopped at review point:** `docs/REVIEW_QUEUE.md` (approve freeze; v19 tactic collapse; 4688 mapping; data-component gap-fill; early H4 signal). Two SPEC_ISSUES entries are pending.
- Tests: 32 passed, 3 skipped (BRiMS parity, waiting on range data).
- Note: commit `f46875d` (WP4) accidentally recorded the Sigma submodule at master tip `05d1031`; `714f999` moves it to the pinned release `552f3fe`.

## 2026-10-24: WP4b v2, WP7a, WP5 (stopped at WP5 gates)
- Mapper v2 frozen at `7d36465`: process_creation rules also on Security 4688, approved Defense Evasion fold, gap-fill dropped. Report `results/20261024T153421Z-mapper_report-7d36465`; v1 and v2 numbers side by side in REVIEW_QUEUE. Spec §2.4/§2.5/§7 and CLAUDE.md updated (OTRF primary; ATLASv2 a limited robustness check). Models: F = claude-opus-5-5 (temp 0), S_4B = qwen3:4b-instruct.
- WP7a done (`9e7339c`): `ctit/cti/prior.py` (ATTK from ATT&CK v18.1 group techniques; Uni; absorbing-chain projection onto K). Priors in `data/priors/<actor>/` (run `20261024T153535Z-baseline_priors-9e7339c`).
- WP5 (`b7db2a4`): plans for APT29 (ael), menuPass and OilRig (CTID) pinned in `data/eval/plans/SOURCES.txt`. Draft `data/eval/visibility_apt29.csv` (14 y / 65 partial). Cited-source lists written. Gate run `20261024T154022Z-wp5_gate-b7db2a4`.
- **Stopped at two gates in REVIEW_QUEUE:** APT29 visibility CSV sign-off; H4 viability at K. Also open: DPRK path (the ER6 DPRK plan looks macOS-targeted). Waiting on Jack's CTI manifest for WP6.
- Tests: 42 passed, 3 skipped (BRiMS parity, waiting on range data).
