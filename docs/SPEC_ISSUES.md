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

## 2026-10-27: refusals, evidence check, extraction ground truth (§4, §6, §10), decided by Jack
Items 2 and 3 were committed before any recovery metric or R-vs-B comparison was computed under them.
**Disclosure:** before these decisions arrived I printed per-sample edge-F1 for the F run against the then-current ground truth (Windows-only steps, repeats collapsed), as part of the run summary. No choice below was made by me; items 2 and 3 are Jack's specifications, implemented as given.
1. **Refusals:** log-and-skip stays. No rewording, retry, or routing to another model. Refusal counts per report and chunk are a result for F and S. The oracle is reported from S only; the F oracle is "refused (5/5)". For H3, S is also reported with F-refused chunks excluded. Pre-registered here: a chunk counts as F-refused if F refused it in any of its 5 samples.
2. **Evidence check (pre-registered):** split each evidence_span on "..." and "…"; normalize whitespace, curly quotes (‘’‚‛′ → ', “”„‟″ → ") and dashes (‐‑‒–—―− → -) on both sides; every fragment of ≥ 8 characters must appear verbatim in the source chunk, in order. Pre-registered here: a span with no fragment of ≥ 8 characters fails. Strict and fragment-aware rates are both reported (`ctit.cti.extract.evidence_ok_fragments`). No further changes after results are seen.
3. **Ground truth = all plan steps, all platforms**, repeats collapsed (`ctit.eval.recovery.ground_truth_counts`, `ctit.eval.plans.load_plan(platforms=None)`); Windows-only is the appendix variant. Transitions / distinct edges, all platforms vs Windows-only: APT29 45/28 vs 45/28 (Windows-only plan); menuPass 6/6 vs 6/6 (Windows-only plan, 15 steps); OilRig 17/15 vs 7/7; Sandworm 25/21 vs 10/9. Sandworm's 40 steps are treated as one scenario, as before. menuPass's short plan is now a stated limitation (§10).


## 2026-10-27: C4 follow-up — benign PrivEsc/Discovery tags are one scripted job on xx01/xx51 hosts (analysis only)
Run `20261027T114209Z-benign_breakdown-fbfd66f` (156 test hosts, 19–22 Sep, v3 and v3h, bare images restored).
- **Per day, v3 (events / tagged / tag rate / K):** 19 Sep 483.3M / 8,343 / 1.7e-5 / {PrivEsc, DE, Discovery, Impact}; 20 Sep 338.8M / 3,548 / 1.0e-5 / {Exec, PrivEsc, DE, Discovery, Impact}; 21 Sep 448.9M / 10,901 / 2.4e-5 / same 5; 22 Sep 444.7M / 8,949 / 2.0e-5 / same 5. v3h adds Execution ("Suspicious New Instance Of An Office COM Object"): tag rate 1.6e-5 to 4.2e-5.
- **By rule:** Privilege Escalation is 100% "Process Creation Using Sysnative Folder" (17,694) and Discovery is 99.9% "Recon Command Output Piped To Findstr.EXE" (8,118 of 8,126): the same two rules that drive the 23 Sep red-team tags (C4). Each fires on only 4 of the 156 test hosts.
- **What they match:** a Python-launched session check, `cmd /c "C:\Windows\SysNative\qwinsta.exe <user> /server 142.20.61.19x"` and `cmd /c "netstat -n | findstr 142.20.61.19x"`, every few minutes. On 21 Sep it runs on exactly the hosts numbered xx01/xx51: fit 0101, 0151, 0301, 0651, 0751, 0801, 0951; validation 0251, 0451, 0701; test 0401, 0551, 0601, 0901. That is OpTC's scripted range activity, not attack behaviour.
- **C4 reinterpreted:** five red-team targets are xx01/xx51 hosts (0051, 0201, 0351, 0501, 0851), against ~3% of clean hosts, so the 27-vs-27 comparison mostly measured that job. The B6 diagnostic (below) tests this against the labels.
- **22 Sep under-represented the benign background.** The 50-host fit sample on 22 Sep (C2) gave tag rate 3.0e-6 and K = {DE}; the 156 test hosts on 22 Sep give 2.0e-5 and K = 5 tactics, and the difference is the xx01/xx51 job, which the 50-host sample happened to miss.
- **C5 under the test-host numbers:** K ≥ 4 would pass on 3 of 4 days, but only because of the one scripted job on ~3% of hosts. Tag rate (≤ 2.4e-5 v3, ≤ 4.2e-5 v3h) still fails the 1e-4 bar, and visibility (APT29 27, OilRig 3, menuPass 3, Sandworm 1) still fails. So C5 fails on two criteria, not on the visibility criterion alone; the go/no-go outcome is unchanged.

## 2026-10-27: B6 built; diagnostic says C4's "mapper sees the intrusion" does not hold (analysis only)
- **Raw eCAR:** 87 host-days (29 targets × 23–25 Sep, 16 GB) range-fetched from the Inria corrected release (doi:10.57745/UXCWOC), length- and gzip-CRC-verified (`scripts/fetch_optc_redteam.py`). Re-converted with pid/ppid kept (`ctit/ingest/ecar.py`, `scripts/convert_optc_redteam.py`). Per-event-id counts match STRATA-E on every host-day it has (23 Sep; 17 hosts on 24 Sep). On 0201/23 Sep every column matches row for row except `target_image` on 2,221 of 2.85M EID 8/10 rows: STRATA-E carried its process table over from 22 Sep, and this conversion starts empty on 23 Sep.
- **Test set** (`20261027T115506Z-redteam_testset-833a565`, `data/eval/optc_redteam_windows.parquet`): 29 hosts, 195 host-days (benign 19–22 Sep: 27 hosts; attack: 29), v3, windows of 8 tagged events. 4,428 windows; 46 positive (contain a labelled-malicious event; 28 on 23 Sep, 14 on 24, 4 on 25); 117 with a malicious event in their time span. 638 label rows on the targets (2 on DC1, no file).
- **Diagnostic** (`20261027T124122Z-redteam_diag-59998a9`, attack days only): 200.5M events, 235,698 labelled-malicious, 9,736 tagged, **160 tagged ∩ malicious (1.6% of tags; 0.07% of malicious events)**, on 24 of 87 host-days. Typical sc1 host-day: ~3,300 malicious events, ~14 tags, 5 of them malicious.
  - Malicious tags: "PSScriptPolicyTest Creation By Uncommon Process" (DE) 108, "HackTool - Empire PowerShell Launch Parameters" (Exec) 24, "Uncommon File Created by Notepad++ Updater Gup.EXE" (Collection) 8, then ≤ 3 each (User Added to Local Administrators, PowerShell Base64, UAC Bypass Using EventVwr, Office Macro File Creation, …).
  - Non-malicious tags: "Process Creation Using Sysnative Folder" 4,708, "Recon Command Output Piped To Findstr" 2,119, "PSScriptPolicyTest Creation" 1,836 (also on benign activity), "System File Execution Location Anomaly" 536, …
  - Possible label gaps among the 9,576 non-malicious tags: 434 on a labelled pid outside its interval, 1 on a descendant of a labelled process, 823 inside some label interval (open-ended rows capped at 4 h), 8,318 elsewhere. The first and third classes are dominated by the two C4 rules (241 and 368), whose command lines are the scripted session check. They overlap the attack by pid reuse and by time, so these are not label gaps.
  - **The two C4 rules fire on 0 labelled-malicious events.** They fire only on the five xx01/xx51 targets (0051, 0201, 0351, 0501, 0851), on 23 and 24 Sep.
- **Verdict:** C4's "the mapper sees the intrusion" does **not** hold. The 16× red-vs-control rate came from the scripted xx01/xx51 session-check job, which is over-represented among the targets. The mapper does see a thin slice of the real attack (PowerShell/Empire staging, PSScriptPolicyTest artefacts, a few privilege-escalation steps): 160 events over 3 days.

## 2026-10-27: WP6 extraction results; schema retry replayed from the cache (open, needs Jack)
Runs: F `20261027T121723Z-extraction-a53c21c` (185 calls, 1.14M in / 0.37M out tokens, $11.92); S and S-sampled `20261027T121707Z-extraction-a53c21c` (222 calls on local qwen3:14b, 0.91M in / 0.21M out, $0); report `20261027T154811Z-extraction_report-2261148` (no calls). The `recovery` fields in the two extraction runs' metrics.json use the superseded Windows-only ground truth; the report run is authoritative.
- **Refusals:** F refused 3 chunks: oracle#0 5/5, OilRig-P02#1 5/5, APT29-P03#0 1/5. S refused none. The H3 sensitivity variant drops those three chunks from S.
- **Bug: the schema retry is not a real retry.** Spec §4.3 says "Retry once on failure, then log and skip". `extract.ask` retries the same prompt, but `Cached.chat` saved the failing response on the first attempt and replays it on the second, so the retry can't change the outcome. Affected: F B/Sandworm s4, a response that opens a ```json fence and never closes it, so it was skipped with 0 edges (that is why B/Sandworm has sd 7.4). S/S-sampled: APT29-P03#0 (t0 and 4 of 5 samples) and OilRig-P02#0 (3 of 5 samples). Every S failure is invalid JSON from an unescaped Windows path (`%TEMP%\d…`) in an evidence span. For S, a real retry gives the same output (temperature 0, or a fixed seed), so the fix changes nothing there unless the retry varies the seed. **Proposed fix (Jack to decide; not applied, because the results have been seen):** key the cache on the attempt number so the retry is a fresh call, then rerun only the failed calls (1 F call, about $0.05). Any lenient JSON parsing (stray backslashes, unclosed fence) would change the parser after results were seen, so it is not proposed.
- **Degenerate S-sampled outputs:** some sampled responses loop. menuPass-P06 gives up to 123 transitions from one chunk; Sandworm-P02 s4 gives 72 transitions, 64 of them failing the evidence check. Per-report dedupe bounds the effect on the prior, but the hallucination rate is per transition, so it is inflated: S-sampled R/menuPass strict rate 0.49 ± 0.36.
- **JSD and short plans:** with α = 0.5 over 182 cells, menuPass's 6-transition ground truth is close to uniform. Diffuse priors therefore score low JSD against it in every row of the H4 matrix. Edge-F1 doesn't have this problem. Reported as is; no change.

## 2026-10-27: Jack's decisions on the WP6 report (retry fix, post-hoc controls, case studies)
1. **Retry bug: fixed (approved).** The response cache is keyed on the attempt number, so a schema retry is a fresh call (`a686409`); attempt 1 keeps its cache file. Only the failed calls were re-run: F `20261027T223842Z-extraction-a686409` (1 call, $0.065) and S/S-sampled `20261027T223928Z-extraction-a686409` (8 calls, local). F's B/Sandworm s4 recovered (19 edges). All 8 S retries reproduced the first output byte for byte (same invalid `\` escape at the same character), as expected at temperature 0 or a fixed seed. So APT29-P03#0 (S t0 and S-sampled s0, s2–s4) and OilRig-P02#0 (S-sampled s0–s2) stay skipped. **Post-fix numbers are primary** (`configs/extraction_report.yaml`); pre-fix numbers are in `configs/extraction_report_prefix.yaml`. The only prior that differs is F B/Sandworm (pre-fix 12.8 ± 7.4 edges, F1 .161; post-fix 15.8 ± 1.9, F1 .183).
2. **Edge-count chance control: post hoc** (spec §6). For every prior: edge-F1 of a random set with the same number of distinct off-diagonal edges (10,000 draws, seed 20261027; true positives are hypergeometric), reporting observed F1, chance mean, F1 ÷ chance, percentile (ties count half), precision and recall. R − B and H2b are recomputed on F1 ÷ chance. `metrics.json` puts all of this under `post_hoc` with a note.
   - The H2b coverage proxy as computed is the ATT&CK 18.1 group-page reference count: APT29 44, OilRig 28, Sandworm 26, menuPass 20. The independent-report count from §2.3 was never collected.
   - F1 ÷ chance is not comparable across actors: chance depends on the size of the plan's edge set (menuPass, 6 edges: chance ≈ 0.05).
3. **Baselines:** ATTK and Uni are scored with the same edge-set definition (count > 0 on an off-diagonal cell) and the chance control. ATTK has no order, so its edge set is every pair of tactics the group uses (Sandworm: all 14 tactics, the same as Uni). Uni equals chance by construction.
4. **H4:** the pre-registered result is reported as is (F 3/4 rows on edge-F1; JSD degenerate at α = 0.5 with sparse ground truth). Post hoc: JSD at α ∈ {0.01, 0.1}, and the 4×4 matrix of chance-normalized edge-F1. The chance-normalized matrix is confounded by column: menuPass's small chance level inflates its whole column. I suggested a column-wise reading of the pre-registered matrix to Jack, but it is not adopted.
5. **Case study B** (`ctit/experiments/redteam_scoring.py`), as run:
   - **Scorer as run (precise wording added 2026-10-27 22:04 EDT):** each prior is (counts + α) row-normalized over all 14 tactics, **self cell kept** (`prior.from_counts`; ATTK's self cell is n_i²), then projected onto K (the 13 tactics v3 can emit, all but Reconnaissance) by the absorbing-chain formula. The self cell survives the projection, and Uni becomes 1/13 on every cell, self included. P_ben is pooled over K × K **including self-transitions**. Windows are **not collapsed**: all 7 transitions are scored, self-transitions included. Self-transitions are 77% of positive-window transitions (322) and 44% of negative-window transitions (30,674). Extracted priors give the self cell only smoothing mass. U is DRIFT's JSD over K × K edges, self edges included.
   - K is the tactics v3 can emit (each rule's primary tactic).
   - P_ben is pooled over the 223 fit hosts, 19–22 Sep; each host's tagged events are kept in time order across its days. Cached in `data/eval/optc_fit_transitions_v3.json`.
   - λ = 0. **Deviation from §5:** λ was to be tuned on validation, but the validation hosts have no attack windows, and test is never used for tuning.
   - The Det@1%FPR threshold comes from the test set's negative windows.
   - TTD as operationalized here: the position of the first detected positive window among a host's positive windows (1 if none is detected), averaged over attacked hosts.
   - CIs: host-cluster bootstrap (29 hosts, 1,000 resamples).
   - F and S-sampled metrics are means over their 5 sample priors. Oracle is S only; F refused 5/5.
   - **Result** (`results/20261027T235002Z-redteam_scoring-5715a18`): 4,428 windows, 46 positive (base rate 1.0%), 23 attacked hosts.
     - U: AUPRC .021, AUROC .18 (ranks the attack below benign).
     - Uni: AUPRC .147 [.111, .352], AUROC .72.
     - R (every actor, F, S and S-sampled): AUPRC .116–.159, AUROC .70–.75.
     - Oracle S: .147.
     - ATTK: OilRig/Sandworm/menuPass .34–.37 (AUROC .97, Det@1%FPR .59–.65); ATTK/APT29 .19.
     - The scorer effect (Uni − U) is large. The CTI effect (R − Uni) is ≈ 0 for every prior, the oracle included, consistent with the mapper seeing 160 of 235,698 malicious events.
     - Why ATTK wins is not yet diagnosed.
6. **Case study A** (`ctit/experiments/otrf_case.py`, `results/20261027T225650Z-otrf_case-5715a18`): built now, because T7 had not been built. v3 tags OTRF APT29 Sysmon only; per host-day, repeats are collapsed. Recovered: 37 transitions, 22 edges, 8 tactics. Against the plan: F1 .28 (2.07× chance, 98th percentile). Priors against the executed edges: only R-S-sampled APT29 is above the 95th percentile, and R-F APT29 ≈ R-F OilRig. The recording has no benign split, so background activity is included.
7. **Sandworm-P04/P05:** kept as fetched (primary) and listed as a limitation (spec §2.3, §10).

## 2026-10-27 20:06 EDT: small open model changes from Qwen3-14B to Ministral 3 14B Instruct (decided by Jack)
- **Change:** the S model changes from Qwen3-14B (`qwen3:14b`) to **Ministral 3 14B Instruct** (Mistral AI, Apache 2.0), for provenance reasons: no PRC-origin models. The size point changes from Qwen3-4B-Instruct to **Ministral 3 3B Instruct**.
- **This was decided after the Qwen results were seen.** Ministral becomes the primary S model whatever its results are. The Qwen3-14B run is kept on disk and in the logs, and is disclosed as "qwen3-14b (superseded)": runs `20261027T121707Z-extraction-a53c21c` (pre-fix) and `20261027T223928Z-extraction-a686409` (post-fix). Nothing from it is deleted. No qwen3:4b-instruct run was ever started.
- **Settings are identical to the Qwen S run except the model:**
  - `num_ctx` 16384, 6k/300 chunks, frozen v1 prompts, the same schema validation and true single retry, the fragment-aware evidence check, per-report dedupe;
  - the same private single-slot Ollama server, stopped when done;
  - one temperature-0 run plus 5 sampled runs. "Sampled" keeps its pre-registered meaning, the model's default (Modelfile) sampling. Every sampling parameter is sent explicitly and recorded;
  - conditions R and B for all four actors, plus the oracle for the 14B only.
- 14B first, then 3B. Every analysis that used S priors is rerun with Ministral as S.

## 2026-10-27: H4 column-wise approved as a POST HOC secondary analysis (Jack)
- For each plan actor (column) of the pre-registered 4×4 matrix: the matched prior's edge-F1 minus the best other actor's prior. For JSD, the best other prior's JSD minus the matched prior's, so a positive value means the matched prior is closer.
- Columns hold the plan, and so the chance level, fixed. That avoids the column confound of the chance-normalized row-wise matrix.
- Always reported next to the pre-registered row-wise result, never in place of it (`ctit.experiments.extraction_report.h4_colwise`).

## 2026-10-27: case study B diagnosis (ATTK lead, U inversion): POST HOC, diagnostics only (Jack)
- Run every analysis, report every one, select nothing from them.
- ATTK's case study B numbers go in the paper regardless; the diagnosis only explains them.
- Contents (`ctit/experiments/redteam_diagnosis.py`):
  - (a) ATTK's construction, and the mean row entropy of every prior as scored;
  - (b) per-transition decomposition of ATTK − Uni and R − Uni over positive and negative windows, with tactic and rule composition;
  - (c) controls: ATTK's edge set with uniform weights; destination-tactic frequency only; actor-agnostic ATTK from all groups; R at α 0.01 and 0.1;
  - (d) scripted job removed: (i) xx01/xx51 hosts dropped; (ii) the two scripted-job rules' tags dropped from test and fit;
  - (e) per host, and leave-one-host-out AUPRC;
  - (f) the same for U.
- **Design choices made here, before any result was seen:**
  - control (1) gives every ATTK edge the mean nonzero ATTK count, keeping ATTK's count scale;
  - control (2) is outer(mean n, n), so every row is the group's tactic profile at ATTK's scale;
  - for (d)(ii) the fit baseline is rebuilt without the two rules (`data/eval/optc_fit_transitions_v3_noscript.json`), so test and baseline are tagged alike.
- F parts first (`configs/redteam_diagnosis_F.yaml`); S parts once the Ministral 14B priors exist.

## 2026-10-27 20:50 EDT: Ministral run stopped; the Ollama template's default system prompt is removed (decided by Jack)
- **What happened:** the official Ollama template for `ministral-3:14b-instruct-2512-q4_K_M` and `ministral-3:3b-instruct-2512-q4_K_M` injects a default system prompt whenever the request carries no system message (ours never does). The template block, quoted verbatim from `ollama show --modelfile` (Ollama 0.40.10, 14B; the 3B is identical except "Ministral-3-3B-Instruct-2512"). `{{ currentDate }}` and `{{ yesterdayDate }}` are filled with the server's date at request time:

````
{{- if not $hasSystemPrompt }}[SYSTEM_PROMPT]You are Ministral-3-14B-Instruct-2512, a Large Language Model (LLM) created by Mistral AI, a French startup headquartered in Paris.
You power an AI assistant called Le Chat.
Your knowledge base was last updated on 2023-10-01.
The current date is {{ currentDate }}.

When you're not sure about some information or when the user's request requires up-to-date or specific data, you must use the available tools to fetch the information. Do not hesitate to use tools whenever they can provide a more accurate or complete response. If no relevant tools are available, then clearly state that you don't have the information and avoid making up anything.
If the user's question is not clear, ambiguous, or does not provide enough context for you to accurately answer the question, you do not try to answer it right away and you rather ask the user to clarify their request (e.g. "What are some good restaurants around me?" => "Where are you?" or "When is the next flight to Tokyo" => "Where do you travel from?").
You are always very attentive to dates, in particular you try to resolve dates (e.g. "yesterday" is {{ yesterdayDate }}) and when asked about information at specific dates, you discard information that is at another date.
You follow these instructions in all languages, and always respond to the user in the language they use or request.
Next sections describe the capabilities that you have.

# WEB BROWSING INSTRUCTIONS

You cannot perform any web search or access internet to open URLs, links etc. If it seems like the user is expecting you to do so, you clarify the situation and ask the user to copy paste the text directly in the chat.

# MULTI-MODAL INSTRUCTIONS

You have the ability to read images, but you cannot generate images. You also cannot transcribe audio files or videos.
You cannot read nor transcribe audio files or videos.

# TOOL CALLING INSTRUCTIONS

You may have access to tools that you can use to fetch information or perform actions. You must use these tools in the following situations:

1. When the request requires up-to-date information.
2. When the request requires specific data that you do not have in your knowledge base.
3. When the request involves actions that you cannot perform without tools.

Always prioritize using tools to provide the most accurate and helpful response. If tools are not available, inform the user that you cannot perform the requested action at the moment.[/SYSTEM_PROMPT]
{{- end }}
````

- **Why it's a problem** (Jack):
  - Opus and Qwen got only the frozen v1 user prompt, so this was a prompt difference between models.
  - The prompt contains the date, so the rendered prompt changes from day to day, and a rerun on another day is not the same experiment.
  - It tells the model to "clearly state that you don't have the information and avoid making up anything", which bears directly on the no-report (B) condition that H2 measures.
- **Stopped** at 20:45 EDT. 61 calls had been made by the 14B in run `20261028T001101Z-extraction-3e5207d`:
  - temperature 0: 44 (37 first attempts + 7 schema retries);
  - sampled seed 0: 17 (14 + 3);
  - no refusals. The 3B never started.
- **Discarded, kept on disk:** all 61 responses (cache dirs 2aa8a7208001cbf8 and 092ba0be9db1448c, plus four empty seed dirs) and the temperature-0 priors written before the stop (`data/priors/20261028T001101Z-extraction-3e5207d/S`). Each carries a DISCARDED.txt, and none is used anywhere.
- **F and Qwen had no system prompt (checked):**
  - Every logged call's prompt hash equals the hash of the frozen v1 user prompt alone: F 185/185 and 1/1, Qwen 222/222 and 8/8. Our code hashes system + user, so nothing was sent as a system message.
  - F is the Anthropic Messages API with no `system` parameter.
  - Qwen's Ollama template renders a system block only when a system message or tools are passed, and its Modelfile has no SYSTEM line.
- **Fix:**
  - Pinned Modelfiles derived from the official ones with only that block removed: `configs/modelfiles/ministral-3-nosys-{14b,3b}-instruct-2512-q4_K_M.Modelfile`, sha256 ae31aeb7…d310b (14B) and 79e8ef9c…12ad1 (3B). Built as `ministral-3-nosys:{14b,3b}-instruct-2512-q4_K_M` (ollama_id 9c53f01aa0e0 / 5f49d84e5598).
  - The model, params (temperature 0.15) and license layers are byte-identical to the official ones (same weights digests bfb40fc6… / 910e4bf4…). The parser stays `ministral`, with no renderer. Only the template layer changes: 397d0224…, the same for both sizes.
  - Verified with one call per model on the debug-logging private server: the prompt "Reply with the single word OK." rendered to 44 characters and 11 tokens (`[INST]…[/INST]`), with no system block and no date.
- **Cache:** the response-cache key now includes the template digest, as well as the tag, weights and options, so none of the 61 calls can be replayed. They also live under a different tag.
- **Relaunch:** 14B, then 3B, with everything else as in the 20:06 entry.

## 2026-10-27 21:14 EDT: parser gaps vs. malformed output (decided by Jack before any new Ministral failure was seen; POST HOC relative to the F and Qwen results)
1. **Definition:**
   - A *parser gap* is output that is valid JSON once the wrapping is removed: an unclosed or mismatched code fence, or prose before or after the JSON.
   - Anything wrong inside the JSON is *malformed output* and stays a failure. That includes bad escapes, trailing commas, unbalanced quotes or brackets, and truncation.
   - JSON content is never repaired.
2. **The runs are not stopped over this.** The Ministral 14B and 3B runs finish with the current parser (`ctit.cti.schema.parse`), and the parser and validation are not changed during them.
3. **After the runs, a wrapping-only fix is applied uniformly** to every model's cached first attempts (F, Ministral 14B and 3B, Qwen superseded), with no new calls.
   - Every affected table is reported both ways: as run, and with the wrapping fix. **Primary numbers stay as run** unless Jack decides otherwise after seeing both.
   - Operational rule (mine, fixed now, before any new failure is seen): in the fix variant, a chunk whose first attempt parses once the wrapping is stripped uses that first attempt. Otherwise it keeps its as-run outcome (retry result or skip). Validation (tactic names, self-transitions) and the evidence checks are unchanged.
   - **Clarification (2026-10-27 21:15 EDT, Jack):** a first attempt is used only if, once the wrapping is stripped, it passes everything that would have triggered a retry at run time. Otherwise the as-run outcome stands.
     - In the code as run (`ctit.cti.extract.ask`), the only retry trigger is `schema.parse`: JSON decoding, and "a JSON list of objects".
     - Item-level validation (`schema.validate`: unknown tactic, self-transition, missing fields) drops single items and never triggered a retry. In the fix variant it is applied to the first attempt exactly as at run time.
     - A first attempt that decodes but isn't a list of objects keeps its as-run outcome.
4. **The schema-failure table** gives, per model and mode, every failure with its parser message and its class under rule 1 (wrapping gap or malformed output), for first attempts and retries.
- Known so far:
  - F has 1 failure, B/Sandworm s4, first attempt: an unclosed ```json fence with complete JSON inside, i.e. a wrapping gap.
  - Qwen has 8 failures, all invalid `\` escapes from unescaped Windows paths: malformed output.

## 2026-10-27 21:38 EDT: AMENDMENT to the 20:06 EDT model-change entry: both 14B open models are reported side by side (decided by Jack before any Ministral result was computed)
1. **Neither 14B model is superseded.**
   - **S-Q** = Qwen3-14B (`qwen3:14b`), the pre-registered S.
   - **S-M** = Ministral 3 14B Instruct (`ministral-3-nosys:14b-instruct-2512-q4_K_M`), added after the first results for provenance, as a non-PRC option.
   - Sampled variants: **S-Q5** and **S-M5**. The size point **S-M3** = Ministral 3 3B Instruct.
   - **No Qwen 4B run.** This replaces "Ministral becomes the primary S" and "Qwen superseded" in the 20:06 entry.
2. **Same tables for both.** Wherever the plan said to move Qwen to a "superseded" block, S-Q and S-M share the same tables:
   - the extraction table with the chance control, R−B, hallucination rates, refusals, schema failures and sec/call;
   - H3 per model, H4 row-wise and column-wise per model;
   - case studies A and B;
   - the S parts of the ATTK diagnosis, run for both models.
3. **Sampling parameters actually sent** (from `calls.jsonl`):
   - **S-Q5** (runs a53c21c and a686409, 185 + 7 sampled calls): options `{num_ctx: 16384}` + seed, with `think: false` sent at the top level of the request. No temperature or other sampling parameter was sent, so the qwen3:14b Modelfile defaults applied: temperature 0.6, top_k 20, top_p 0.95, repeat_penalty 1.
   - **S-M5** (run 5528fd6): options `{temperature: 0.15, num_ctx: 16384}` + seed, no think field. 0.15 is the Ministral Modelfile's only parameter; everything else takes Ollama's built-in defaults.
   - Temperature-0 runs: both models get `{temperature: 0, num_ctx: 16384}`, and Qwen also gets `think: false`.
   - So "default sampling" means temperature 0.6 with top-k/top-p truncation for S-Q5, and temperature 0.15 for S-M5. S5 comparisons between the models are not like-for-like in sampling.
4. **The running Ministral jobs are not stopped or changed.** Nothing else changes.
- Config slot names stay as they are (`S` = Ministral 14B, `S_3B`, `S_qwen3_14b`), so the running jobs aren't touched. Reports label them S-M, S-M3 and S-Q.

## 2026-10-27 21:52 EDT: priors scored as probabilistic models (log-likelihood of plan transitions): POST HOC (Jack; logged before anything is computed)
- CPU only, no model calls. It runs after the diagnosis interim report and does not delay the Ministral runs.
- **Score:** for each prior against each plan, the mean log-likelihood per ground-truth transition, reported as bits gained over uniform: mean over transitions of log2(13 × P̂(next | current)).
  - Transitions: the plan's collapsed sequence with multiplicity (all platforms, as `ctit.eval.recovery`): APT29 45, OilRig 17, Sandworm 25, menuPass 6.
  - α = 0.5 (pre-registered).
- **P̂ as defined here** (my reading, fixed before computing): the prior's counts + α over the 14 tactics, with the self-transition cell dropped (collapsed plans have none), renormalized over the 13 other tactics. So Uni is exactly 0 bits.
  - For ATTK the counts are n nᵀ, its diagonal dropped the same way.
  - No projection onto K: this is the 14-tactic plan space, as in T2/T4.
- **Priors:** R-F, R-Q, R-Q5, B-F, B-Q, ATTK, Uni, and the Ministral priors (R-M, R-M5, B-M, R-M3, …) once they exist. Every saved prior is scored; the listed ones are reported.
- **Uncertainty:**
  - 95% CI by bootstrapping transitions within each plan (1,000 resamples, seed 20261027).
  - For multi-sample priors (F, Q5, M5) the point estimate is the mean over samples. The CI comes from bootstrapping that mean, with the same resampled transitions for every sample. Mean ± sd over samples is also reported.
- **4×4:** R prior actor × plan, per model. For each plan (column), which actor's chain gives the highest likelihood.
- **Sensitivity:** α = 0.01 and 0.1.
- **Case study A:** the same score for each prior against the executed OTRF APT29 sequence (37 transitions, `ctit.experiments.otrf_case`).

## 2026-10-27 22:04 EDT: case study B, collapsed (consistent) scoring added beside the as-run scoring: POST HOC (Jack; logged before any re-scoring)
- **Why:** the as-run case B scoring is inconsistent with how the priors are built. Extraction forbids self-transitions and the ground truth collapses repeats, but case B scored uncollapsed windows. There, self-transitions are 77% of positive-window transitions, and the report priors give them only smoothing mass.
- **As-run results stay exactly as they are.** The collapsed version is added alongside. Neither replaces the other; both go in the report.
1. **"Case B, collapsed":**
   - Consecutive repeated tactics are collapsed within each window, and only the off-diagonal transitions are scored: the mean log-LR over them. A window with none scores 0 under every LR prior, i.e. tied.
   - Every prior: (counts + α) with the self cell dropped, each row renormalized over the 13 other tactics (as in the likelihood analysis), then projected onto K for Reconnaissance. The self cell that projection creates is dropped and each row renormalized again.
   - The benign baseline: pooled K × K fit counts with the self cell dropped, + α, renormalized.
   - Same 4,428/46 test set, host bootstrap (1,000, seed 20261027) and λ = 0.
2. **Conditions scored:** U (unchanged: DRIFT as published, on the uncollapsed window), Uni, ATTK ×4, R-F, R-Q, R-Q5, the oracle (Q, Q5), and the Ministral priors once they exist. Same columns as the case B table.
3. **Also reported:** the number of off-diagonal transitions per window after collapsing, as a distribution for positive and negative windows separately, and the number of positive windows with none (tied under every prior).
4. **Diagnosis:** item 2b splits every as-run score difference into its self-transition part and its off-diagonal part. Items 2c and 2d run on both versions.
5. The case B method note above now says exactly what the as-run scorer did.
- Run after the diagnosis prep finishes. The Ministral runs are not touched.
- **Ties (2026-10-27 22:17 EDT, Jack):** no random tie-breaking. Each condition reports:
  - the share of positive and of negative windows scoring exactly 0;
  - the realized FPR at the Det@1% threshold;
  - the tie convention:
    - AUPRC: sklearn's step over distinct scores, so tied windows enter together.
    - AUROC: a tied positive-negative pair counts 1/2.
    - Det and TTD: detected only if strictly above the threshold.
  - If the 1% point falls inside a tie block (some value v with P(neg > v) < 1% < P(neg ≥ v)), that is flagged, with whether it is the zero block, and detection is reported at the achievable FPR on each side (score > v and score ≥ v).

## 2026-10-27 23:17 EDT: case B diagnosis (F parts) and collapsed case B: results (POST HOC; nothing selected)
Runs: diagnosis `results/20261028T031006Z-redteam_diagnosis-1c54232`; collapsed case B `results/20261028T031454Z-redteam_scoring-1c54232`.
- **The negative set is mostly the scripted job.** Of the 4,382 negative windows, 4,009 sit on the five xx01/xx51 targets. Dropping those hosts leaves 402 windows (29 positive); dropping the two scripted-job rules' tags leaves 499 (45 positive). Negative-window tactics: Privilege Escalation 62%, Discovery 28%, Defense Evasion 10%. Sysnative (21,662) and Findstr (9,757) are the top rules in negative windows. Positive windows are 77% Defense Evasion tokens (PSScriptPolicyTest, System File Execution Location Anomaly) and 77% Defense Evasion → Defense Evasion transitions.
- **ATTK's as-run lead is its weight on staying in Defense Evasion, not actor knowledge or edges:**
  - ATTK's projected P(DE → DE) is 0.11–0.22, against Uni 0.077 and R-F about 0.04.
  - Most of the ATTK − Uni gap (positive minus negative, per window) comes from the self part (+0.25 to +0.62).
  - Controls: destination-tactic frequency only reproduces ATTK (AUPRC .19–.35); actor-agnostic all-groups ATTK gives .306; ATTK's edge set with uniform weights equals Uni (.14–.15).
  - R-F's self part is negative (−0.28 to −0.35) and its off-diagonal part positive (+0.20 to +0.33), so as run it nets to about Uni.
- **Collapsed scoring:**
  - R-F: AUPRC .28–.43 (OilRig .420 [.323, .606], Sandworm .432 [.343, .603]), Det@1% .39–.63.
  - Uni .178, ATTK .19–.29, R-Q and R-Q5 .14–.18, oracle-Q .178.
  - Ties: 11 of 46 positive and 439 of 4,382 negative windows have no off-diagonal transition (score 0). The 1% point falls inside a tie block for every LR condition: the realized FPR is about 0.25–0.3%, and the next achievable FPR is about 1.2% (non-zero blocks) or about 10.3% (zero block).
- **What contradicts a clean story:**
  - Much of R-F's collapsed advantage comes from scoring the scripted PrivEsc ↔ Discovery cycle as unlikely (Discovery → PrivEsc log ratio −0.68 against Uni), not only from the attack's transitions.
  - All four off-target R-F priors help.
  - With the scripted rules' tags dropped (collapsed), R-F (.15–.19) is about Uni (.146) and below ATTK (.21–.28).
  - The scripted job also drives most as-run ATTK and U differences; once it is removed, every condition is .59–.72 (as run).
- **U's inversion is the scripted job:**
  - The fit baseline's mean edge distribution is dominated by DE → DE (0.33), and positive windows are mostly DE → DE, so they sit close to the baseline.
  - Negative windows are mostly the PrivEsc/Discovery cycle (the baseline has 2.5% each), so they sit far from it.
  - With the xx01/xx51 hosts dropped, U's AUROC is .84; with the rules' tags dropped, .85. Neither is inverted.
- **Per host:** sysclient0501 (an xx01 host) has 10 of the 46 positive windows. Leave-one-host-out AUPRC ranges are narrow (e.g. ATTK/OilRig as run .34–.46; U .015–.037).

## 2026-10-27 23:18 EDT: prior log-likelihood results, F and Q (POST HOC; `results/20261028T031747Z-prior_likelihood-31bc352`)
Units are bits over uniform per plan transition at α = 0.5, with [95% CI]; Uni = 0. Ministral is added once its runs finish.
- **Own plan:**
  - R-F: APT29 .11 [−.14, .37], OilRig .62 [.17, 1.04], Sandworm .31 [−.04, .69], menuPass .91 [.32, 1.49].
  - R-Q: .12, −.17, .17, 1.00. R-Q5: .10, −.21, −.02, .86.
  - B-F: .06, .01, −.02, 1.01. B-Q: .10, −.11, −.07, .32.
  - ATTK: −.61, −.05, −.30, −.92 (worse than uniform for every plan).
- **4×4, best actor's chain per plan (column):** R-F 3/4 (OilRig, Sandworm, menuPass; the APT29 plan is best explained by the menuPass prior), R-Q 1/4 (Sandworm), R-Q5 1/4 (menuPass). The R-F column-best pattern is the same at α 0.01 and 0.1.
- **α sensitivity:** at α 0.01 most priors drop well below uniform (sparse chains give near-zero probability to plan transitions they lack). Exceptions: R-F OilRig .24, R-F/R-Q/B-F on menuPass. At α 0.1 the pattern is in between.
- **Case A (executed OTRF APT29, 37 transitions):** ATTK .76 [.50, .98]; R-F −.12, R-Q −.06, R-Q5 −.05, B-F −.05, B-Q .01. ATTK's tactic-frequency profile fits the mapper-visible executed sequence better than any extracted chain.

## 2026-10-28 01:06 EDT: Ministral 14B and 3B runs complete; schema failures; wrapping-only fix (POST HOC); S-Q and S-M side by side
- **Runs:**
  - Ministral 3 14B, no-system-prompt Modelfile: `results/20261028T005130Z-extraction-5528fd6` (262 calls, modes S and S-sampled).
  - Ministral 3 3B: `results/20261028T040137Z-extraction-d032eae` (230 calls, modes S_3B and S_3B-sampled; R and B only).
  - Both exited 0 and made no refusals. Private Ollama server stopped.
- **Schema failures:** `results/20261028T044346Z-schema_failures-ce77e76`; classifier in `ctit.experiments.schema_failures`. Counts are first attempts / retries:
  - F: 1/0, a wrapping gap (fence, then prose).
  - S-Q: 8/8, all malformed (bad `\` escapes).
  - S-M: 40/40. 12 wrapping (`[]` + prose), 23 multiple_values, 5 malformed.
  - S-M3: 14/13. 0 wrapping, 3 multiple_values, 11 malformed.
- **Retries:** retried with the same seed and options, so they mostly repeat the first attempt. Identical retries: S-Q 8/8, S-M 37/40, S-M3 11/14. One S-M3 sampled retry succeeded.
- **New class, not covered by the 21:14 rule, needs Jack:** *multiple_values*, i.e. the first JSON value decodes and another JSON value follows (typically `[]` then a fenced list).
  - Choosing one of the two values is a content decision, so it is classed as neither a wrapping gap nor fixed. As run, these chunks are skipped.
  - 21 of the 23 S-M cases and 2 of the 3 S-M3 cases are `[]` twice, so either choice gives the same counts.
  - Two cases are substantive:
    - S-M t0, R/OilRig-P01 chunk 0: a list of 25, then a list of 9.
    - S-M3 s1, B/menuPass: `[]`, then a list of 8.
- **Wrapping-only fix, POST HOC:** the cache replay through the run-time path reproduces every as-run prior exactly before the fix is applied.
  - The fix changes one prior: F B/Sandworm s4, 15 → 16 edges. The 12 S-M wrapping cases are `[]` + prose, so their counts are unchanged.
  - Affected tables, as run → fixed:
    - F B/Sandworm edge-F1 .183 → .204, F1/chance 1.84 → 2.05.
    - R−B (F, ratio) Sandworm 0.81 → 0.60; H2b Spearman unchanged (−0.4).
    - Likelihood B-F Sandworm, α 0.5: −.02 → .00.
  - Case A uses APT29 B only, and case B uses R and oracle only, so neither is affected.
  - Results: `…T050423Z-extraction_report-f3d6dc4` and `…T044500Z-prior_likelihood-ce77e76`. As-run stays primary.
- **Reproduction:** the reruns with S-Q and S-M side by side reproduce every earlier F and Qwen number exactly, except:
  - the Monte-Carlo chance-control draws for Qwen and the baselines (shared RNG stream, new mode order);
  - the diagnosis's "best other condition" lines, which now pick from more conditions.
- **3B in condition B:** returns an empty list for 19 of 24 actor/sample calls (4 at temperature 0, 20 sampled), and one more is `[]` followed by a list (the multiple_values case above). Where it lists transitions, technique IDs often fail validation. Its B priors have about 0 edges, so its R−B ratio is undefined.
- **oracle-M5:** its five samples score identically in case B (both versions). They differ in edges (22–26) but agree on every prior cell the test windows use (checked), so this is real, not a loading error.
- **Results:**
  - extraction report `results/20261028T050417Z-extraction_report-f3d6dc4` (timing includes the original F and Qwen runs);
  - case A `…T044412Z-otrf_case-ce77e76`;
  - case B as run `…T044524Z-redteam_scoring-ce77e76` and collapsed `…T044720Z-redteam_scoring-ce77e76`;
  - likelihood `…T044436Z-prior_likelihood-ce77e76`;
  - diagnosis with S parts (Q, Q5, M, M5) `…T044917Z-redteam_diagnosis-ce77e76`.

## 2026-10-28 08:21 EDT: multiple-JSON-value replies, Jack's rule (POST HOC; logged before computing anything)
Applies to replies of class *multiple_values* (01:06 entry): two or more JSON values in one reply.
- **Identical values** (every JSON value in the reply equal, including `[]` twice): the reply counts as parsed, using that value. Nothing changes numerically (all such cases are `[]`).
- **Values differ:** the reply stays a failure in the primary (as-run) numbers. A sensitivity is reported for the two content-bearing cases (S-M t0 R/OilRig-P01 chunk 0; S-M3 s1 B/menuPass), taking (a) the first value and (b) the last value, for every affected table: extraction, H3, R−B, H4, likelihood, and case A/B if affected.
- As with the wrapping fix, the value taken goes through the run-time parser and validation unchanged; no content is repaired. The wrapping-only fix (21:14 rule) is applied in the same replays, so the variants are as-run + wrapping fix + this rule.

## 2026-10-28 08:42 EDT: multiple-JSON-value results (POST HOC; rule logged 08:21) and paper tables
- **Replay:** `results/20261028T122317Z-schema_failures-6b29976`. Variants: `__mv` (identical values parsed), `__mvfirst`, `__mvlast`. All three include the wrapping-only fix. As run stays primary.
- **Identical values** (21 S-M t0/sampled replies, both attempts where retried; 2 S-M3 sampled): counted as parsed, and no prior's counts change, confirmed.
  - One S-M3 case (s1 R/Sandworm-P01) was a first attempt with identical `[]` whose retry had succeeded as run. Under the rule the first attempt stands and no retry is made. The retry had yielded no valid transitions, so counts and rejections are unchanged.
  - Chunk statuses change (skipped_schema → ok), so the schema-failure counts under the rule are S-M 40 → 18 first attempts (12 wrapping, 1 multiple values that differ, 5 malformed) and S-M3 14 → 12.
- **Values differ, S-M t0 R/OilRig-P01 chunk 0** (a list of 25, then a list of 9):
  - First and last both add the same new edge (Persistence → Command and Control, not in the plan, i.e. a false positive) and differ in 2 count cells.
  - Extraction: edge-F1 .375 → .367; F1/chance 3.31 → 3.20.
  - H3 S-M/OilRig: .946 → .927 (dropping F-refused chunks: 1.009 → .988).
  - R−B (S-M, ratio) OilRig: 3.31 → 3.20; H2b Spearman unchanged (−0.8).
  - H4 S-M: row margin OilRig −.106 → −.105; column-wise OilRig .067 → .060, Sandworm −.315 → −.306. Positive counts unchanged (row 2/4, column 3/4).
  - Likelihood R-M/OilRig own plan, α 0.5: .373 [.05, .70] → .342 [−.00, .70]; α 0.01: .16 → .08; α 0.1: .42 → .36. Column-best unchanged (R-M 3/4 at every α).
  - Case B R-M/OilRig: as run AUPRC .147 → .153 (AUROC .796 → .790, Det@1% unchanged .174); collapsed .179 → .168 (Det@1% .239 → .217). No other condition changes.
  - Case A: unaffected (APT29 only).
- **Values differ, S-M3 s1 B/menuPass** (`[]`, then a list of 8):
  - First value = `[]`: nothing changes.
  - Last value: that sample gets 8 edges. S-M35 B/menuPass mean edge-F1 0 → .029 (ratio defined for s1 only: 3.89). R−B S-M35 menuPass becomes defined (.17, from one sample).
  - The 3B is in the extraction table and H3 only, so nothing else changes.
- **Results:**
  - extraction `…T122436Z/…T122443Z-extraction_report-3d74201` (first/last);
  - likelihood `…T122451Z/…T122516Z-prior_likelihood-3d74201`;
  - case B `…T122544Z/…T122740Z` (as run) and `…T122938Z/…T123134Z` (collapsed) `-redteam_scoring-3d74201`.
  - Likelihood with M3 under first/last: `…T123443Z/…T123509Z-prior_likelihood-ecf227b`.
- **Paper tables** (`ctit.experiments.paper_tables`, `results/paper_tables/`, run `…-paper_tables-5a5ee02`):
  - Sources rerun at `ecf227b`; they reproduce every earlier number exactly.
  - Additions, purely additive, existing numbers unchanged:
    - case B gains ATTK-all, the all-groups ATT&CK prior, as a condition (matches the diagnosis c3 control, .306 / .285);
    - likelihood gains M3 and 4×4 matrices for every prior family.
  - Table (a) recomputes F1/chance with one shared chance draw (common random numbers: 10,000 orderings of the 182 off-diagonal cells, seed 20261027), so its ratios differ from the report's in the second decimal.
  - Table (f): Qwen's request also carried `think: false` outside `options` (from the cache keys; not in calls.jsonl).
  - Table (g): plan release dates are in `configs/plan_release_dates.yaml` (changelogs; GitHub commit dates for OilRig and Sandworm, which have no changelog).

## 2026-10-28 18:43 EDT: parsing decision — as run is primary everywhere (decided by Jack; CLOSED)
- **As-run numbers are primary in every table and hypothesis test.** This closes the open item from the 01:06 and 08:42 entries (whether the wrapping fix or the identical-values reading becomes primary anywhere).
- The wrapping-only fix (21:14 rule) and the multiple-JSON-value variants (08:21 rule: identical values parsed, and the first/last-value sensitivity) are reported **only as sensitivity analyses in Appendix B**. This supersedes "the reply counts as parsed" in the 08:21 entry for the primary numbers: as run, those replies stay schema failures (S-M 40 and S-M3 14 first attempts in the primary schema-failure table; 18 and 12 under the rule, in Appendix B).
- Nothing is rerun. The paper tables (`results/paper_tables/`, run `…-paper_tables-5a5ee02`) already use the as-run priors only.

## 2026-10-31: final coding pass, Phase 1 (POST HOC; Jack's request; nothing tunes anything)
Everything in this entry is **post hoc**. No prompt, extraction or prior changed; no model was called. Model lists come from `configs/v2_priors.yaml` (`priors_from`), so a model is added by config. Runs at `84bbb70`; tables `results/paper_tables_v2/` (run `20261031T153949Z-paper_tables_v2-ef93a26`).
1. **Report-level bootstrap of R − B** (`reading_bootstrap`, run `20261031T153631Z`): 2,000 resamples, seed 20261031 (one generator per model and actor). Reports drawn with replacement and Eq. 1 rebuilt (each edge once per report; a report drawn twice counts twice); multi-sample R priors (F, Q5, M5) and multi-sample B priors (B-F, B-Q5, B-M5) also have their samples drawn with replacement; single-call B priors (B-Q, B-M, B-M3) are held fixed. F1/chance uses the shared chance draw of paper table a, keyed by edge-set size; IG holds the plan's transitions fixed. Point estimates reproduce Table 3 and F's IG gaps (+0.61, +0.33, +0.06, −0.09). Design note: resampling reports with replacement leaves fewer distinct reports, so the bootstrap distribution of R sits below its point estimate (e.g. F OilRig IG +0.61 [+0.07, +0.69]).
2. **Dependence-aware IG intervals** (`ig_dependence`, run `20261031T153635Z`): circular block bootstrap (b = 2, 3, 5; 2,000 resamples, seed 20261031) over each plan's transition sequence, scenarios concatenated in plan order and wrapped. The i.i.d. intervals are recomputed with prior_likelihood's draw and reproduce Table 5 exactly. Status changes: ATTK/APT29 below → spans at b = 2, 3, 5 (i.i.d. upper bound −0.005); R-Q5/OilRig spans → below at b = 2, 5; B-Q/menuPass spans → above at b = 3, 5; B-M/menuPass spans → above at b = 5. menuPass has 6 transitions, so its b ≥ 3 intervals rest on 6 distinct block starts and are near-degenerate (B-Q b = 3 collapses to a point).
3. **Evidence audit sample** (`evidence_audit`, run `20261031T153702Z`): all 2 failing F spans, 40 each for Q, M, M3 (seed 20261031 per label; equal actor quotas, spares passed on). Closest passage by difflib ratio over span-length windows. Written to `audit/evidence_sample.csv` (holds report text: `audit/` added to .gitignore), `label` column empty for Jack.
4. **Case A, every Table 5 prior** (`case_a_v2`, run `20261031T153636Z`): IG with prior_likelihood's i.i.d. draw (reproduces the existing case A numbers), plus F1/chance and percentile against the executed edges from the shared chance draw (the earlier 1.45× for R-F APT29 used independent hypergeometric draws; the shared draw also gives 1.45).
5. **Case B, scripted job removed** (`case_b_scripted`, run `20261031T153736Z`): the diagnosis's item d, collapsed, for every listed prior; reproduces `20261028T044917Z-redteam_diagnosis-ce77e76` exactly for the conditions it had, and adds R-M3. Oracles: F 5/5 refused (no row), M3 has no oracle run.
6. **Tables v2** (`paper_tables_v2`): CSV + LaTeX; Table 2 adds precision and recall and a Windows-only variant; H4 JSD at α ∈ {0.01, 0.1, 0.5}; chance-normalized H4 matrix now from the shared draw (the extraction report's used independent hypergeometric draws); full IG matrices.
7. **Release** (no push): `README.md` (reproduction from a clean checkout, URL blank), `scripts/release_manifest.py` → `release/cti_manifest.csv` (URL, date, SHA-256 of extracted text, roles; every hash verified; no text). Gaps for a public release are in `docs/PROGRESS.md`.

## 2026-10-31: second frontier model G = OpenAI GPT-6 Astra (POST HOC; logged before any call; Jack)
- **Why:** G is a post hoc addition, chosen to test whether F's no-report (B) results, especially menuPass, are specific to one vendor. G's outputs feed only G's priors; they never fill gaps in F's. Nothing is tuned on it.
- **Model:** requested `gpt-6-astra` (OpenAI Responses API, SDK `openai==3.42.0`); the exact model string the API returns is logged per call (`model_returned` in calls.jsonl) and recorded below after the smoke test. Date: 2026-10-31.
- **Request, every parameter sent:** `model="gpt-6-astra"`, `input=[{"role": "user", "content": <frozen prompt>}]`, `reasoning={"effort": "high"}` (F ran at effort high), `max_output_tokens=32000`. Not sent: `instructions`, any system/developer message, `temperature`, `top_p`, `text`/structured outputs/JSON mode, tools, `store` (left at the API default). The server-echoed temperature and top_p are logged.
- **Protocol = F's:** the same frozen prompts (`extract_v1.txt`, `memory_v1.txt`), the same 6,000/300 chunks, the same B aliases, the as-run parser and validation (`ctit.cti.schema`), and F's retry rule (one fresh retry on a schema failure, then skip). A response with status `incomplete` is logged and counted as a schema failure (so it gets the same single retry). Refusals (a `refusal` content item) are logged and never reworded or retried elsewhere. 5 samples per call.
- **Conditions:** R on every chunk of the 23 reports (32 chunks), B for the 4 actors, and the OpTC red-team ground-truth document as G's own case B oracle: 37 jobs × 5 = 185 first-attempt calls (`configs/extraction_G.yaml`).
- **Budget cap:** $150 at OpenAI's standard rates, $10 / 1M input and $50 / 1M output tokens, reasoning tokens billed as output (cached-input discounts ignored). Before each call its worst case (prompt chars / 2 as input tokens, plus all 32,000 output tokens) is reserved; a call that could take spend past the cap is not made and the run stops cleanly (no priors written; cached responses kept). The smoke run's spend counts toward the cap.
- **Smoke test first:** 2 R chunks, sample s0 (`configs/extraction_G_smoke.yaml`), through the same cache, so the full run reuses them.
- **Logged per call:** tokens (input, cached input, output, reasoning), cost, latency, status, incomplete reason, refusal, schema status (from the saved chunk outcomes), response ID, model returned.
- **Smoke test** (run `20261031T155204Z-extraction-17e8f85`): APT29-P01#0 and APT29-P02#0, s0. Model returned: `gpt-6-astra` (no dated suffix). Server-echoed temperature 1.0, top_p 0.98 (defaults; not sent). Tokens in/out (reasoning): 2,950 / 1,858 (1,552) and 5,550 / 10,265 (8,286); latency 40 s and 174 s; both parsed (4 and 18 transitions, 0 rejected), status completed, no refusal. Spend $0.69. Projected full run $63.10 (input from F's logged tokens × 0.62 G/F tokenizer ratio; every call assumed to emit the smoke mean of 6,062 output tokens), under the $150 cap: continue.
