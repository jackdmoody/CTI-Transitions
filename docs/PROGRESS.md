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

## 2026-10-24: WP5 rerun
- Sandworm promoted to core; DPRK is a stretch actor (report-split). OilRig's plan docs cite ~25 reports, so the citation rule applies and no temporal fallback is needed. `check_leakage.py` now cross-checks `cited_by_emulation_plan` against `data/eval/plans/<actor>_cited_sources.txt`. Gate rerun: `results/20261024T163912Z-wp5_gate-2b1e283`.
- **Result for the paper:** under the BRiMS mapper, the four actors' visible tactic sequences collapse to Execution: pairwise JSD 0.000–0.009 at α = 0. The BRiMS mapper cannot express actor specificity on emulation-plan procedures. This is a reported result, not a failure, and it motivates the extended mapper.
- **Not done:** extending visibility synthesis beyond process creation (Jack's option (a)) was not completed this session. Alternatives are listed in REVIEW_QUEUE. Visible transitions (extended v2, process creation only): APT29 68, OilRig 14, menuPass 7, Sandworm 5.
- WP7b (no manifest needed): `ctit/cti/schema.py` (extraction output validation shared by F and S; only the 14 tactics accepted) and `ctit/llm/ollama.py` (pinned options, thinking off, `num_ctx` 8192, weights-digest check, call logging). Local `qwen3:14b` and `qwen3:4b-instruct` match their pins. No extraction run. Remaining WP7 (S extraction and B-S runs) waits for the WP6 prompts and the manifest.

## 2026-10-25: API surface + OTRF atomic ingest
- `docs/API_SURFACE.md`: import paths, signatures and shapes for the frozen v2 mapper, the BRiMS mapper (via the adapter), the canonical loaders (Splunk XML, OTRF, OTRF atomic, ATLASv2), plan step access, the visibility CSV, and `wp5_gate` inputs.
- OTRF atomic Windows host datasets: 112 archive links from 100 metadata files at the pinned commit (`data/otrf/atomic/SOURCES.txt`). 110 were downloaded; 1 link 404s at that commit (`SDWIN-230718150800` cmd_copy_ntds_from_volume_shadow_copy). All 110 were ingested to `data/otrf/atomic/canonical/` with all raw fields kept; formats handled: Mordor JSON, 2019 Winlogbeat, tar.gz, and stray macOS resource forks.
- Coverage (`data/otrf/atomic/coverage.csv`): 56 techniques in OTRF atomic, 59 in the full-XML Splunk samples, 24 in both. Plan steps whose exact technique has a recording: APT29 46%, menuPass 53%, OilRig 72%, Sandworm 47%. At parent-technique level: 71% / 60% / 79% / 73%.

## 2026-10-26: corpus check (BOTS v1/v2/v3, OpTC, ATLASv2)
- Done: `docs/CORPUS_CHECK.md`.
  - New `ctit/ingest/bots.py`: BOTSv1 JSON, plus a Splunk journal decoder verified against `Hosts.data` on every bucket (v3 17/17, v2 57/57, v2 attack-only 17/17), so no Splunk is needed.
  - New `ctit/ingest/optc.py`: STRATA-E OpTC parquet → canonical, with per-host drive-letter and registry-hive normalization.
  - Tests for both.
- **Results:**
  - **BOTSv1:** 3 real Sysmon hosts.
  - **BOTSv2:** 8 Sysmon hosts; the benign background is one day replayed ~16×; every Windows host is in the attack-only subset.
  - **BOTSv3:** 8 hosts, 6.5 h.
  - **OpTC:** 446 clean hosts × 4 benign days, but eCAR artifacts (bare image names, remote threads) drive ~99% of benign tags even after the shared 719-rule subset and normalization.
  - **ATLASv2:** real users, 15 scorable windows.
- **Under the spec's window (DRIFT session, ≥2 tagged):** no corpus reaches 5,000 scorable benign windows; only OpTC reaches 500 (2,883 day-long sessions).
- **Recommendation (Jack decides):** OpTC primary with three fixes; ATLASv2 for realism; no BOTS. A proposed SPEC_ISSUES entry on the window definition is in CORPUS_CHECK (not filed).
- Data written only under `data/bots/`, `data/optc_check/`. External OpTC data untouched.

## 2026-10-26: reframing, OpTC corpus, mapper v3, Track 2 go/no-go, extraction build
- **Reframing (docs, `3b81f46`):** the paper evaluates LLM-compiled CTI as hunting priors. The baseline is pooled. Open data only.
- **OpTC corpus:**
  - 446 clean hosts; host split 223 / 67 / 156 (`configs/optc_split.yaml`).
  - Red-team targets: `configs/optc_redteam.yaml`.
  - Converter restores bare images where it can; process creates can't be restored.
- **Mapper v3:** frozen (`e3e96e8`). The OpTC fit-sample background collapses to K = {DE} at 3.0e-6. Signatures and gate were rerun under v3.
- **B5 counts:**
  - OpTC test: 3,912 windows, so Det@0.1%FPR is dropped.
  - ATLASv2: 5 windows, so ATLASv2 is dropped.
- **Track 2 (C):**
  - Candidate v3h (threat-hunting rules) gives K = {Exec, DE} at 2.4e-5.
  - Visible transitions are unchanged: 27 / 3 / 3 / 1.
  - Pre-registered C5 failed, so the spec says "hunting = case study". Extraction leads.
- **Extraction (WP6 build, `93736d0`):**
  - Built `ctit/cti/extract.py`, covering both F and S, with replay tests.
  - Prompt drafts are in `prompts/` and the REVIEW_QUEUE gate. They are uncommitted, and no extraction has been run.
- **A2:** `data/optc_check/groundtruth/OpTCRedTeamGroundTruth.pdf` and its text are in place, for the oracle prior.
- **Open:**
  - The CTI manifest file wasn't found locally, so Part B (fetch) hasn't run.
  - F can't take temperature 0 (SPEC_ISSUES).
  - B6 raw eCAR download is on hold.
  - The rules behind the test-host PrivEsc/Discovery tags aren't broken down yet.

## 2026-10-27: Part B, B6, prompts v1, WP6 extraction
- Part B: 24 docs fetched (`scripts/fetch_cti.py`). menuPass-P01 is excluded (doesn't name APT10). Leakage passes with priors APT29 7, menuPass 5, OilRig 5, Sandworm 6.
- B6: raw eCAR for the 29 targets (87 host-days) fetched and converted with pid. Test set: 4,428 windows, 46 positive. Diagnostic: C4's "mapper sees the intrusion" does not hold (the two C4 rules are a scripted xx01/xx51 job). Spec: H4 at the prior level, H1 as case studies.
- Prompts v1 frozen (`bb526e5`). Extraction ran F ($11.92) and S/S-sampled (local). Report: `results/20261027T154811Z-extraction_report-2261148`. F refused 3 chunks, including the oracle (5/5); S refused none.
- **Open:** schema retry is replayed from the response cache (SPEC_ISSUES, needs Jack). The private Ollama server on port 11435 has been stopped.
- Tests: 106 passed, 3 skipped.
- Next: Jack's call on the retry fix; then T2/T4 tables (WP6/WP7).

## 2026-10-27 (later): Jack's decisions on the WP6 report
- Retry fix (`a686409`): the cache is keyed on attempt. The failed calls were re-run. F B/Sandworm s4 recovered; the 8 S retries reproduced their output, so those chunks stay skipped. Post-fix runs: F `20261027T223842Z`, S `20261027T223928Z`.
- Post-hoc chance control, ATTK/Uni baselines, R−B and H2b on F1÷chance, H4 α-sensitivity and chance-normalized matrix. Results: `results/20261027T225638Z-extraction_report-5715a18` (post-fix, primary) and `…225644Z…` (pre-fix).
- Case study A (OTRF APT29): `results/20261027T225650Z-otrf_case-5715a18`. Case study B (OpTC red team): `results/20261027T235002Z-redteam_scoring-5715a18`. Fit-host transitions cached at `data/eval/optc_fit_transitions_v3.json` (~60 min to build).
- Tests: 115 passed, 3 skipped.
- **Open:** why ATTK beats every extracted prior in case study B; whether to adopt the column-wise H4 reading (post hoc, Jack).

## 2026-10-27/28: diagnosis, collapsed case B, likelihood, Ministral, schema failures (all post hoc analyses in SPEC_ISSUES)
- Case B diagnosis (F, then S parts for Q, Q5, M, M5). Collapsed case B scoring with tie reporting. Prior log-likelihood. All are labelled POST HOC.
- Ministral 3 runs with no-system-prompt Modelfiles:
  - 14B `20261028T005130Z`, 3B `20261028T040137Z`.
  - The earlier run with the injected system prompt (`20261028T001101Z`, 61 calls) is kept on disk, labelled DISCARDED.
  - Ollama digests (`configs/models.yaml`): qwen3:14b `bdbd181c33f2` (weights a8cc1361…); ministral-3-nosys:14b `9c53f01aa0e0` (weights bfb40fc6…, template 397d0224…); ministral-3-nosys:3b `5f49d84e5598` (weights 910e4bf4…, same template).
- Schema-failure classifier and wrapping-only fix (`ctit/experiments/schema_failures.py`). The fix changes one prior (F B/Sandworm s4).
- All S analyses rerun with S-Q and S-M side by side. F and Qwen numbers reproduce. Private Ollama server stopped.
- Tests: 150 passed, 3 skipped.
- **Open (Jack):** the multiple_values class (2 substantive chunks); whether the wrapping-fix numbers replace as-run anywhere.
