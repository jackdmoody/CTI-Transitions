## 2026-10-24: DRIFT dependency mechanism (§8), resolved by Jack

**Issue.** §8 said to depend on DRIFT as `drift @ git+...@brims-2026` in `pyproject.toml`. DRIFT has no package metadata (no `pyproject.toml`/`setup.py`). Its code is `scripts/pipeline_drivers/sysmon_pipeline/` plus an `observational` package shipped as `observational.tar.gz`, so it can't be pip-installed from the tag.

**Decision (Jack).** Pin DRIFT as the git submodule `third_party/DRIFT` at `brims-2026` (`3517424`). `ctit/adapters/drift.py` adds DRIFT's packages to `sys.path`, extracting the tarball to the gitignored `.cache/drift/`, and verifies the submodule HEAD and a clean tree. The allowance to add a `pyproject.toml` to DRIFT is removed, and DRIFT is never modified. §8 and CLAUDE.md are updated to match.

## 2026-10-24: §5 likelihood-ratio scoring vs. DRIFT's scorer (approved by Jack, with a change)

**Issue.** §5 defined score(s) = log P_adv(s) − log P_role(s), with P_role as "DRIFT's role-indexed benign transition model", scored per sliding window of "DRIFT default" length. DRIFT at `brims-2026` has neither. Its role baseline is the leave-one-out mean of same-role hosts' *joint* edge distributions (`build_vectors_union_vocab`, α = 0.5, edge list built from the data). Its score is the JSD between a host and that mean (`compute_peer_baseline_jsd`). It computes one score per whole host, with no conditional P(b|a), no windows and no fit/test time split.

**Decision.**
1. *P_role:* for each role r, sum the fit-window tactic-transition counts (DRIFT ingest semantics, unmapped events skipped) over role-r hosts. Add α = 0.5 over a fixed K×K list of edges (K = the mapper's reachable tactics) and normalize each row. Without row-normalization this equals DRIFT's role-mean vector in DRIFT's counts and smoothing, and a test asserts it.
2. *Window:* a DRIFT session (`sessionize_host`, τ from `fit_gap_threshold` per host, fitted on the fit window only). Windows with fewer than 2 tagged events are skipped and counted. The appendix sweeps fixed windows of 8, 16 and 32 tagged events.
3. *P_adv:* the 14-tactic CTI prior projected onto K, with unreachable tactics skipped like DRIFT's unmapped events, via absorbing-chain marginalization: T_obs = T_KK + T_KU (I − T_UU)⁻¹ T_UK. Mixed with P_role at λ ∈ {0.1, 0.3, 0.5}, chosen on validation only.
4. *Window score = mean log-LR per transition:* (1/(n−1)) Σ_t [log P_adv(s_t | s_{t−1}) − log P_role(s_t | s_{t−1})]. The summed version is reported in the appendix only. (Jack's change from the draft, which used the sum.)
5. *U* stays DRIFT's scorer: the JSD between a window's smoothed edge distribution and the role-r fit-window mean, over the same fixed edge list. For whole hosts this reduces to the BRiMS score.
6. *Separating scorer from prior:* Uni (likelihood ratio with a uniform P_adv) is the like-for-like comparison for R. R − Uni is reported as the CTI effect and Uni − U as the scorer effect.
7. The §5 alternative becomes a per-edge JSD contribution weighted by the projected P_adv, kept as an appendix ablation.

§5 is updated to match.

## 2026-10-24: §2.2 / §4: injected tactics the DRIFT mapper can't produce (approved by Jack)

**Issue.** `build_tokens` assigns tactics only through `_map_mitre_technique`.
- Over Sysmon alone it produces Execution, Defense Evasion, Credential Access, Persistence and Command and Control.
- Discovery (4798), Privilege Escalation (4672) and Kerberos (4768) need Security-log event IDs. BRiMS's D = 41 > 25 implies those were present.
- Lateral Movement and Collection are in `MITRE_TECHNIQUE_DB`, but no rule produces them.
- Initial Access, Reconnaissance, Resource Development, Exfiltration and Impact are absent.
- `T1105` (bitsadmin) maps to a technique missing from the DB, so its tactic is `""`.

Injecting steps as tactics the mapper can't produce creates events benign data can never contain. That overstates every condition's detection and breaks agreement with real OTRF events (T7).

**Decision.**
- `visibility_<actor>.csv` gains a `drift_tactic` column: the tactic the **extended mapper** (next entry) produces from the step's concrete artifact, or `—`.
- `drift_tactic` is what gets injected. Steps with `—` count toward recovery metrics only, like `visible = n`.
- Priors are projected onto K (previous entry).
- T1 reports K and mapper coverage.

## 2026-10-24: extended tactic mapper, W2-side (approved by Jack)

**Issue.** Given the reachability gap above, a K of roughly 5–7 tactics may be too small to tell actors apart (H4).

**Decision.**
- Add a W2-side mapper in `ctit/map/`, built from SigmaHQ Windows rules (Sysmon and Security) pinned to one commit, with tactic taken from each rule's ATT&CK tags.
- Gaps are filled only from ATT&CK data-component mappings. There are no hand-written rules derived from emulation plans or eval data.
- A deterministic primary-tactic policy for multi-tactic techniques is documented in `docs/MAPPER_POLICY.md`.
- The mapper is frozen (committed) before any injection or scoring.
- All W2 conditions, U included, use the extended mapper.
- DRIFT's mapper is untouched and used only for the parity test and as the "BRiMS mapper" reference.
- T4 is reported under both mappers.
- WP5 adds a gate: K under the extended mapper, actor ground truth projected onto K, and pairwise JSD between actor transition matrices under both mappers. Jack decides whether H4 is viable at that K before other actors are ported.

Spec §2, §4, §7 and §8 and CLAUDE.md are updated.

## 2026-10-24: open-weight model slots (§3, approved)

- S primary: `qwen3:14b` under Ollama, thinking off, `num_ctx` ≥ 8192, digest pinned.
- The second slot changes from "robustness" to a size curve (approved). Model: `qwen3:4b-instruct` (Qwen3-4B-Instruct-2507, non-thinking). `qwen3:4b` was rejected because it can't switch thinking off. F = `claude-opus-5-5`, temperature 0.

## 2026-10-24: ATT&CK v19 tactic split (§2.5, §4), approved by Jack

**Issue.** ATT&CK v19.0 (2026-04-28) replaced Defense Evasion with Stealth and Defense Impairment, giving 15 tactics. SigmaHQ `r2026-07-01` uses the new tags (800 Stealth, 302 Defense Impairment). The spec (§4, "14 Enterprise ATT&CK tactics"), DRIFT and the 2020 emulation plans use 14.

**Proposed fix.** The extended mapper collapses both to Defense Evasion (`ctit/map/attack.py`, `docs/MAPPER_POLICY.md`). Technique→tactic lookups use ATT&CK v18.1, the last 14-tactic release. Extraction prompts keep 14 tactics. This is reversible: one lookup table.

## 2026-10-24: Sigma process_creation rules vs. Security 4688 (§2.5), approved by Jack (mapper v2)

**Issue.** The frozen mapper applies process_creation rules to Sysmon EID 1 only. Security 4688 events (ATLASv2, and any range host without full Sysmon) get no process-based tactics.

**Proposed fix.** Before final sign-off, also evaluate process_creation rules on 4688 via a field mapping (NewProcessName→Image, ParentProcessName→ParentImage, CommandLine). Re-freeze and re-run the report.

## 2026-10-24: data-component gap-fill dropped; ATLASv2 demoted (§2.4, §2.5, §7), decided by Jack
- The extended mapper's "gap-fill from ATT&CK data-component mappings" is removed from the spec and CLAUDE.md. No kept rule lacks a tactic, and ATT&CK v18+ replaced data components.
- ATLASv2 becomes a limited robustness check (T6, limits stated). OTRF APT29 is the primary public real-execution benchmark.

## 2026-10-24: actor set and OilRig citations (§0 H4, §1, §2.3, §9), decided by Jack
- Sandworm is promoted to core (CTID plan, Windows steps 16–19 only). DPRK becomes a stretch actor via the report-split fallback: the ER6 DPRK plan is macOS-targeted. H4's 4×4 is now APT29/menuPass/OilRig/Sandworm, and the cut order is updated.
- OilRig: the plan YAML has no `cti_source`, but the plan's markdown docs cite ~25 reports. So the temporal fallback (priors must post-date the plan) is not needed. Cited sources for every actor are now YAML `cti_source` plus report URLs in the plan docs, and `check_leakage.py` cross-checks `cited_by_emulation_plan` against them.

## 2026-10-25: emulation-plan choice per actor (§2.3), decided by Jack
- **APT29:** ATT&CK Evals plan (79 Windows steps; the CTID copy is the same file).
- **OilRig:** CTID plan (29 Windows steps). The ATT&CK Evals ManagedServices 2022 YAML is byte-identical.
- **menuPass:** keep the CTID plan (15 Windows steps). The ATT&CK Evals 2024 plan has 96 technique rows over 9 steps, but it is markdown only: no plan tactic labels and no per-row commands. Using it would need a table parser, tactics from ATT&CK technique lookups, and visibility drafts with no commands.
- **Sandworm:** keep the CTID plan (15 Windows steps, steps 16–19).
- **Turla (ATT&CK Evals 2023): not used.** Its YAML is operator-side (every ability runs from the attacker's Linux host, with `x` placeholders for tactic and technique), and its scenario markdown has no per-step technique IDs. Ground truth would need hand conversion (a §1 human gate).

## 2026-10-26: reframing — evaluation of CTI priors, open data only (§0, §2.1, §3, §5, §8, §9b, §10; CLAUDE.md), decided by Jack
- **A1.** The paper is an evaluation of LLM-compiled CTI as priors for sequence-based hunting, not a DRIFT extension. Thesis and H1–H4 are unchanged in substance. U is "an unconditioned transition-based anomaly detector (DRIFT-style, from prior work)" (§0, §3).
- **A2.** A pooled benign baseline (P_ben, all baseline-fit hosts) is the default; role-indexed baselines are optional (§2.1, §5). BRiMS parity (WP1) is optional, run only if range data is ever used. "U is provably the published method" is removed from §8, and CLAUDE.md no longer requires parity.
- **A3.** Range data is out of scope; open data only (§2.1, §9b). The critical-infrastructure framing is removed: IT/OT segment labels, the CI framing check, ICS Zeek logs and rules, and the benign ICS baseline (§2.1, §2.2, §2.3, §9 cut order, §10). Zeek/T8 stays optional, for corpora that ship Zeek logs (OpTC does).
- WORKPLAN: WP1 parity and WP12 (range ingest) are optional.

## 2026-10-26: Track 2 go/no-go for OpTC hunting (pre-registered before any v3h number was read), decided by Jack
- **Candidate mapper v3h** = the v3 filters (a: no informational; b: shared field subset; c: path-unevaluable and `create_remote_thread` excluded, c2 decided on fit hosts) applied to v2 plus SigmaHQ `rules-threat-hunting/windows` from the same pinned release `r2026-07-01` (105 rules, 162 queries; 6 actor/software-tagged rules excluded by the leakage policy). `rules-emerging-threats` stays excluded. Compiled: `ctit/map/compiled_rules_hunting.jsonl`; config `configs/mapper_v3h.yaml`.
- **Rule (C5):** proceed with the full OpTC hunting evaluation under v3h only if, on the 50-host OpTC fit sample, benign K ≥ 4 **and** benign tag rate ≥ 1e-4, **and** every core actor has ≥ 10 visible transitions in the WP5 gate under v3h. Otherwise the spec says "hunting = case study": the paper leads with extraction (T2, T5, H2, H2b, H3), and hunting is shown on the OTRF APT29 recording and the OpTC red team.
- Analysis only for this decision: no scoring and no detection metrics are computed.

## 2026-10-26: corpus decision and pre-scoring changes (§2.1, §2.5, §5, §6, §7, §9, §10), decided by Jack (Part B of 26 Oct)
- **B1, corpus:** DARPA OpTC is primary; BOTS is out. Host count resolved: OpTC ships 475 hosts on 19–25 Sep; the STRATA-E conversion has 473 (SysClient0213 and 0222 have zero-event files on 21 Sep). 27 of the 29 SysClient red-team targets are among the 473, so clean = 446. The other 2 (0005, 0010) are in the 0001–0025 block that OpTC ships only on 23–25 Sep (no benign days at all). DC1 is also a labelled target with no SysClient file. Red-team days in the local conversion: 23 Sep has all 29 targets; 24 Sep 17 of 29 (the STRATA-E fetch died on 24 Sep at host 0503, whose file holds 0501 records); 25 Sep none.
- **B2, split:** by host, seed 20261026, drawn once (`configs/optc_split.yaml`, `scripts/draw_optc_split.py` refuses to redraw): fit 223, validation 67, test 156.
- **B3, mapper v3** (frozen `e3e96e8`; run `20261027T021514Z-mapper_v3-ca50242`; OpTC numbers on 50 fit hosts, 22 Sep, 143.7M Sysmon-mapped events):

  | step | queries dropped | queries left | OpTC Sysmon tag rate | OpTC K |
  |---|---|---|---|---|
  | v2 | — | 3,174 | 1.05e-3 (Security 9.1%, all "User Logoff Event") | 5: ResDev, Exec, PrivEsc, DE, Impact |
  | a) no informational (8 rules incl. "User Logoff Event") | 9 | 3,165 | 1.05e-3 (Security 0) | 4: ResDev, Exec, PrivEsc, DE |
  | b) shared subset (719 shared; 2 of them informational) | 2,448 | 717 | 1.04e-3 | 3: ResDev, PrivEsc, DE |
  | c1) restore images (data only; 15,230 events restored, no tag changed) | 0 | 717 | 1.04e-3 | 3 |
  | c2) path-unevaluable (Execution Of Non-Existing File; Rare Remote Thread Creation By Uncommon Source Image; 3 rules with 1–3 hits) | 5 | 712 | 3.0e-6 | 1: DE |
  | c3) create_remote_thread category | 5 | 707 | 3.0e-6 | 1: DE |

  Bare process-create images can't be restored: on raw eCAR samples the new process's GUID and pid never carry a path (0/2,020 and 2/1,799), and STRATA-E's `image_resolved` on EID 1 is the parent's image (not used). Recordings: K 13 → 11 (Collection, Exfiltration lost). Signatures rebuilt under v3: 77 techniques with an extended signature (v2: 89), 167 recordings; the v2 library is kept as `tactic_signatures_v2.parquet`. Gate under v3 (`20261027T021709Z-wp5_gate-e3e96e8`): visible transitions APT29 27, OilRig 3, menuPass 3, Sandworm 1 (v2: 68/14/7/5); pairwise JSD at α=0.5 0.036–0.046 for APT29 pairs, 0.003–0.005 among the others.
- **B4, window:** primary = 8 consecutive tagged events per host; sessions to the appendix (§5).
- **B5, pre-registered counts** (run `20261027T021709Z-benign_windows-e3e96e8`, v3): OpTC test hosts 3,912 windows (3,636 if windows can't span days) → **< 5,000, so Det@0.1%FPR is dropped**; hunting metrics are Det@1%FPR, AUPRC, P@k. ATLASv2 5 windows → **< 500, so ATLASv2 is dropped.** Over all 4 days the 156 test hosts carry 31,741 tagged events in K = 5 (PrivEsc 17,694, Discovery 8,126, DE 5,893, Impact 19, Exec 9), more than the 22 Sep fit sample showed; the rules behind them are not yet broken down (the run's `top_rules` field had a summing bug, fixed in `93736d0`).
- **B6, real-attack set (T9):** red-team hosts never in a baseline; test set = their benign days + 23–25 Sep, window labels from the Inria corrected-release labels (`_updated` = `_new`; "Infinity" end = still running). Oracle prior from `OpTCRedTeamGroundTruth.pdf` (downloaded, sha256 5986d23b…, FiveDirections/OpTC-data commit b2673729), reported in its own row, never used for tuning. **Blocked:** event labels need each event's pid, which the STRATA-E conversion dropped; 24/25 Sep are incomplete. Needs raw eCAR for the 29 targets on 23–25 Sep (≈17.5 GB); held by Jack pending C5. Code: `ctit/eval/optc_redteam.py`.
- **B7:** limitations added (scripted OpTC benign activity; Sysmon-recorded signatures vs eCAR background).
- **B8:** cut order: truncated/noisy variants → ATLASv2 → T9 (last of these three).

## 2026-10-26: F cannot run at temperature 0 (§3) — resolved 2026-10-27, see below
**Issue.** §3 says "Temperature 0 where supported; else 5 samples and report mean ± sd." `configs/models.yaml` pins F = `claude-opus-5-5` with `temperature: 0`, but Claude Opus 5.5 rejects sampling parameters (400) and can't disable thinking. So temperature 0 is not supported for F, and the spec's fallback (5 samples, mean ± sd) applies: 5× the F extraction cost.
**Proposed fix.** Drop `temperature` from the F pin, pin `effort` explicitly (proposed `high`), and run 5 samples for F. `ctit/cti/extract.py` already sends no sampling parameters. No server-side refusal fallback is used: a fallback model answering would contaminate F; refusals are logged and skipped.

## 2026-10-26: CTI manifest file not found (Part B of 27 Oct request) — resolved 2026-10-27
No `manifest_candidates*.csv` existed locally. On 27 Oct Jack wrote `data/cti/manifest.csv` (header + 24 rows) directly; Part B ran on that file.

## 2026-10-26: Track 2 results (C2–C5), analysis only; C5 = no-go → "hunting = case study" written into §0
- **C2** (50 fit hosts, 22 Sep; runs `20261027T021514Z-mapper_v3-ca50242`, `20261027T023109Z-mapper_v3-33c4d7a`):
  - **v3:** 707 queries; K = {DE}; tag rate 3.0e-6; DE 433 events.
  - **v3h:** 736 queries (29 threat-hunting queries survive the a/b/c filters; c2 also drops "Remote Thread Created In Shell Application"); K = {Exec, DE}; tag rate 2.4e-5; Exec 2,960 events ("Suspicious New Instance Of An Office COM Object"), DE 436.
- **C3:** v3h signatures (`data/eval/tactic_signatures_v3h.parquet`) have 77 techniques and 488 rows (v3: 77, 473). Gate under v3h (`20261027T023611Z-wp5_gate-a44d741`): visible transitions APT29 27, OilRig 3, menuPass 3, Sandworm 1, the same as v3. The gate's visible sequences come from process-creation drafts, and no threat-hunting rule changed them.
- **C4** (23 Sep, 27 red-team targets vs 27 clean hosts drawn with seed 0; run `20261027T023611Z-redteam_day-a44d741`):

  | mapper | group | tag rate | K | tagged events |
  |---|---|---|---|---|
  | v3 | red team | 6.6e-5 | Exec, PrivEsc, DE, Discovery | 4,896 |
  | v3 | control | 4.1e-6 | DE | 304 |
  | v3h | red team | 7.9e-5 | + Credential Access | 5,836 |
  | v3h | control | 1.7e-5 | Exec, DE | 1,284 |

  - **The mapper does see the intrusion:** about 16× the control rate and 4 tactics against 1.
  - **Driven by two rules:** "Process Creation Using Sysnative Folder" (PrivEsc, 3,108) and "Recon Command Output Piped To Findstr" (Discovery, 1,405).
  - **Inside labelled processes' time intervals:** 201 tagged events (v3), 230 (v3h). This is time overlap only (no pid), so it is an upper bound.
  - **Caveat:** the same two rule ids lead the B5 test-host benign counts (PrivEsc 17,694 and Discovery 8,126 over 19–22 Sep). Whether those are scripted benign activity on clean hosts is not yet determined.
- **C5:** fails on every criterion (K 2 < 4; 2.4e-5 < 1e-4; three actors < 10 visible transitions). Applied as pre-registered: spec §0 now says "hunting = case study".

## 2026-10-27: CTI fetch (Part B, B1–B6), no extraction or API calls
- **Fetch:** `scripts/fetch_cti.py` (requests + trafilatura 2.0.0 for readable HTML text; pdftotext for PDFs). All 24 URLs returned 200 and readable text; texts are in `data/cti/reports/<doc_id>.txt` (manifest `TEXT_DIR` moved there from `data/cti/text/`), raw responses in `data/cti/raw/`, and the sha256 column is filled. Fetch log: `data/cti/fetch_report.json`.
- **Redirects:** three final URLs differ from the manifest: menuPass-P01 (CISA TA18-276B → the `news-events/alerts/2018/10/03/…` archive page), OilRig-P05 (Trend Micro `…earth-simnavaz-cyberattacks-uae-gulf-regions.html` → `…earth-simnavaz-cyberattacks.html`), Sandworm-P05 (labs.withsecure.com → withsecure.com `resources-hub/w-labs/kapeka/`). Manifest URLs are left as given.
- **Dates (B2):** three corrected, all month-only before: menuPass-P05 2024-11 → 2024-11-19, menuPass-P06 2025-03 → 2025-03-18, OilRig-P05 2024-10 → 2024-10-11. The other 21 dates match the page's own `datePublished` (the cloud.google.com Mandiant pages carry a 2024-03-25 `article:published_time` from the site migration; their `datePublished` matches the manifest).
- **Citations (B3):** final URLs, redirect targets and manifest URLs, normalized, against all four `*_cited_sources.txt` (194 URLs): no match, and no loose slug match. No `cited_by_emulation_plan` changes.
- **menuPass-P01 (B4): does not name APT10 or menuPass.** TA18-276B says only "APT actors" (and no China attribution) in its saved text and raw HTML. **Decided by Jack (27 Oct):** `used_for=excluded`, with the reason in a new optional `note` column (`ctit/cti/manifest.py`: `excluded` rows need a note and never count as priors). `check_leakage.py` exit 0 afterwards; menuPass has 5 priors (P02–P06). Spec §2.3 now notes that menuPass priors cover the APT10 umbrella (P02 core; P03–P06 MirrorFace / Earth Kasha).
- **Thin texts:** Sandworm-P05 (WithSecure Kapeka) is a 492-word landing page; the full report is a PDF linked from it (`withsecure.com/wp-content/uploads/2026/05/WithSecure-Research-Kapeka.pdf`). Sandworm-P04 (APT44) is the 1,253-word blog summary of a PDF report (`services.google.com/fh/files/misc/apt44-unearthing-sandworm.pdf`). Not substituted: needs Jack.
- **Embedded ATT&CK tables:** several texts end in ATT&CK technique tables (e.g. APT29-P01, APT29-P04, OilRig-P01, OilRig-P03, menuPass-P06). These are the vendors' own mappings, not ATT&CK group pages, so the leakage rule allows them, but extraction may read tactic labels off them rather than infer order from prose. Noted for the T2 discussion.
- **Leakage (B5):** `scripts/check_leakage.py` exit 0, "OK: 24 docs, leakage rules pass". Prior docs: APT29 7, menuPass 6 (5 after excluding P01), Sandworm 6, OilRig 5.

## 2026-10-27: H4 at the prior level, H1 through case studies (§0, §3, §6, §7), decided by Jack
**Change.** Follows from C5 (hunting = case study).
- **H4** is now tested at the prior level: a 4×4 matrix, extracted report-conditioned prior per actor (rows, separately for F and S) × each actor's emulation-plan ground-truth transition matrix (columns), cells = edge-F1 and JSD on the 14-tactic space. Supported if the diagonal beats the off-diagonal in every row. Telemetry-level H4 is dropped, so T4 no longer depends on a mapper.
- **H1** is evidenced through the case studies only: OTRF APT29 (T7) and the OpTC red team with off-target priors and the oracle (T9).
- **§7:** T3 dropped; T4 redefined as above; T5's hunting column is the case-study lift; T7 marked as an H1 case study.
- **Consequence flagged for Jack:** F4 (H2b) plotted the report-minus-no-report *AUPRC* gap, which needed the dropped T3 grid. It now plots the *edge-F1* gap. H2's and H3's "and hunting" clauses stay, read as case-study evidence.

## 2026-10-27: F and S sampling (§3), decided by Jack; resolves the 2026-10-26 F issue
- **F** (claude-opus-5-5) takes no temperature, so F = 5 samples per extraction, reported as mean ± sd. `configs/models.yaml` pins `effort: high` and `max_tokens: 16000` explicitly, and the price used for the cost column ($4 / $20 per MTok in/out).
- **S** runs twice: temperature 0 (primary, unchanged) and 5 samples at the model's default sampling, seeds 0–4, like-for-like with F. Default sampling = the digest's Modelfile params (temperature 0.6, top_k 20, top_p 0.95, repeat_penalty 1), so no temperature is sent. `ctit.llm.ollama.OllamaModel(..., sample=i)`.
- **Asymmetry stated in the spec:** F's reasoning can't be disabled, while S runs with thinking off in both modes.

## 2026-10-27: prompts v1 approved; extraction changes (§4, §6), decided by Jack
- **Prompts:** `prompts/extract_v1.txt` and `prompts/memory_v1.txt` committed verbatim from Jack's review (bb526e5) and frozen; later changes go through REVIEW_QUEUE. Changes from the drafts: from ≠ to stated in both; the excerpt is fenced in `<excerpt>` tags and marked as data; the memory prompt adds `<<ALIASES>>`.
- **Aliases:** `configs/actor_aliases.yaml` from mitreattack-python 6.3.1 over the pinned ATT&CK 18.1 bundle (same as ATTK priors; `scripts/actor_aliases.py`). The actor's own name is left out of its list (Sandworm's list starts with ATT&CK's name "Sandworm Team").
- **Schema:** self-transitions rejected; rejections counted per model and reason.
- **Aggregation:** one count per (report, edge) for R and per (sample, edge) for B; per-mention counts kept as the appendix variant (`counts_mentions`). One prior per model sample.
- **Chunking:** ~6,000 tokens, 300 overlap, for F and S; chunk count per report recorded. S `num_ctx` 16384.
- **Ground truth:** consecutive repeated tactics collapsed in plan sequences before edge P/R/F1 and JSD (`ctit/eval/recovery.py`). After collapsing, the plans give few transitions: menuPass 6, OilRig 7, Sandworm 10 (9 distinct edges). Edge recall per actor therefore moves in steps of 1/6–1/9.
- **JSD as implemented** (spec §6 said "between the prior and the empirical ground-truth transition matrix" without fixing the form): JSD of the two joint edge distributions over the 182 off-diagonal cells, each (counts + α) normalized to sum 1, as `ctit.eval.actor_jsd` does for the WP5 gate. Flagged so Jack can object before T2 is written.
- **Hallucination rate:** R and oracle only (§6).
- **S server:** qwen3:14b at `num_ctx` 16384 does not fit on the GPU under the desktop Ollama server (`OLLAMA_NUM_PARALLEL=4`: 20 GB, 15% CPU / 85% GPU). On a private server with one slot (port 11435, flash attention on, as the desktop server) it is 11 GB, 100% GPU. S runs there; the desktop server's config is untouched. Pinned in `configs/models.yaml` (`ollama_server`).
