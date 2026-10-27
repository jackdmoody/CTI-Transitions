# W2 Experiment Spec — CTI-Conditioned ATT&CK Transition Hunting

**Paper:** W2, "CTI Transitions" (working title: *Reading the Adversary: LLM-Compiled Threat Intelligence as Transition Priors for Endpoint Hunting*)
**Venue:** AICS @ AAAI-27 — deadline 20 Nov 2026 AoE, full paper, ~7 pp + refs, AAAI-27 Author Kit, not anonymized
**Repo:** new standalone repo `CTI-Transitions` (package `ctit`; rename freely). This is **not** developed inside DRIFT.
**Framing (2026-10-26, Jack):** the paper is an **evaluation of LLM-compiled CTI as priors for sequence-based hunting**, not a DRIFT extension. The unconditioned baseline U is a DRIFT-style transition-based anomaly detector taken from prior work. The paper uses open data only (§2.1).
**Dependency:** github.com/jackdmoody/DRIFT (SBP-BRiMS 2026 transition-deviation pipeline), consumed as a pinned, read-only dependency for the U scorer, sessionization and the BRiMS reference mapper. See §8.
**Audience:** coding agents. Each section is a work package with inputs, outputs, and acceptance checks. Agents do not change hypotheses, conditions, or metrics without sign-off.

---

## 0. Thesis and hypotheses

**Thesis.** Threat-intelligence prose describing an adversary can be compiled by a language model into an ATT&CK tactic-transition prior. Conditioning transition-based endpoint hunting on that prior makes detection more sensitive to the described adversary than unconditioned behavioral-deviation hunting. A small open-weight model is enough to do this, so the benefit is available to defenders without frontier models.

**U** throughout is *an unconditioned transition-based anomaly detector (DRIFT-style, from prior work)*. The paper evaluates CTI priors against it; it does not claim U is a new method or that W2 extends DRIFT.

| ID | Hypothesis | Test | Supported if |
|---|---|---|---|
| H1 | CTI conditioning improves hunting | **Case studies only (2026-10-27):** conditioned vs. unconditioned (U) transition-based hunting on the OTRF APT29 recording (T7) and the OpTC red team with off-target priors and the oracle (T9). No injected-sequence hunting grid | Higher AUPRC / detection@FPR and earlier detection than U on the case studies; reported as case-study evidence with its scope stated, not as a general result |
| H2 | The report content matters, not just model memory | Report-conditioned prior vs. no-report (parametric-memory) prior | Report > no-report on transition recovery and hunting |
| H3 | Small open-weight models are sufficient (special theme) | Open-weight vs. frontier extraction | Open-weight recovers ≥80% of frontier edge-F1 and ≥80% of its hunting lift |
| H4 | The extracted prior is adversary-specific | **Prior level (2026-10-27):** 4×4 matrix over the core actors APT29 (Russia), menuPass (China), OilRig (Iran), Sandworm (Russia): rows = extracted report-conditioned prior per actor, separately for F and S; columns = each actor's emulation-plan ground-truth transition matrix; cells = edge-F1 and JSD on the 14-tactic space. DPRK added as a 5th row/column if the stretch lands. Telemetry-level H4 is dropped | Diagonal beats off-diagonal in every row: higher edge-F1 and lower JSD for the same actor's plan than for any other actor's plan |
| H2b | The report matters most where memory is thinnest | Report-minus-no-report gap vs. actor public-coverage rank | Gap increases as coverage decreases (APT29 smallest gap; OilRig/DPRK largest). Secondary, reported descriptively with n=4 |

Report negative results honestly. If H2 fails, that is a finding about memorization and still goes in the paper.

**Hunting = case study (2026-10-26, pre-registered rule C5 applied; SPEC_ISSUES).** The OpTC go/no-go failed under the candidate mapper v3h: on the 50-host fit sample benign K = 2 (needed ≥ 4) and benign tag rate 2.4e-5 (needed ≥ 1e-4), and visible transitions were APT29 27, OilRig 3, menuPass 3, Sandworm 1 (needed ≥ 10 for every actor). So the paper **leads with the extraction results**: T2 (transition recovery), T5 (small-model sufficiency and cost), H2, H2b and H3. **Hunting (H1) is a case study**, shown on the OTRF APT29 recording (T7) and the OpTC red team (T9). The full injected-sequence OpTC hunting grid (T3, T8) is not run as a headline result; any hunting numbers are reported as case-study evidence with this scope stated. **H4 is tested at the prior level (2026-10-27, SPEC_ISSUES):** extracted priors against emulation-plan transition matrices (T4), not on telemetry.

---

## 1. Leakage rule (non-negotiable)

The CTI used to **build priors** and the material used to **build injected evaluation sequences** must come from disjoint sources. This rule applies identically to every actor.

- **Evaluation sequences (ground truth):** MITRE emulation plans (CTID Adversary Emulation Library or the ATT&CK Evaluations library, github.com/attackevals/ael) where a Windows-applicable plan exists. Ordered steps with ATT&CK technique IDs → tactic sequences. Parse the machine-readable YAML where available.
- **Report-split fallback (DPRK, and any actor without a usable Windows plan):** partition that actor's reports into an *eval set* (2–3 reports, e.g., CISA advisories, hand-converted into an ordered technique sequence and reviewed by Jack) and a *prior set* (all remaining reports). Never build eval sequences from ATT&CK group mappings, since those are the ATTK baseline.
- **Prior sources (extraction inputs):** vendor and government reports on the actor that are **not** the emulation plan, **not** cited by the emulation plan, and **not** in the eval set. Target 5–8 per actor; accept a minimum of 2 for thinly covered actors and report the count per actor in T1. Record URL, date, SHA-256 of the saved text.
- Maintain `data/cti/manifest.csv` with columns: `doc_id, actor, nation, source_org, url, pub_date, sha256, used_for {prior|eval}, cited_by_emulation_plan {y|n}`.
- **Cited reports:** a plan's citations are every step's `cti_source` plus every report URL in the plan's markdown docs (README, Intelligence Summary, Operations Flow, scenario READMEs). They are extracted to `data/eval/plans/<actor>_cited_sources.txt` (WP5). The OilRig plan YAML has no `cti_source` fields, but its Intelligence Summary and Operations Flow cite ~25 vendor reports, so OilRig uses the same citation rule as the other actors (no temporal fallback needed).
- **Acceptance check:** script `scripts/check_leakage.py` fails the build if any doc is `used_for=prior` and `cited_by_emulation_plan=y`, appears in both roles, is cited by its actor's plan but marked `cited_by_emulation_plan=n`, or if any core actor has fewer than 2 prior docs.

Note for the paper: because frontier models were trained on public APT29 material, the no-report baseline (§3, condition B) is what bounds memorization. Leakage control on the report side doesn't remove that, so state it as a limitation.

---

## 2. Data

### 2.1 Benign corpus (open data only)
- **Range data is out of scope for this paper (2026-10-26, Jack).** Every benign background, injection target and real-attack check comes from open datasets. No critical-infrastructure claim is made.
- **Primary corpus: DARPA OpTC** (decided 2026-10-26, Jack; SPEC_ISSUES). eCAR endpoint telemetry converted to Sysmon fields (`ctit/ingest/optc.py`, read-only over the STRATA-E conversion). Benign days 19–22 Sep 2019. Population: the 473 hosts converted on all four benign days (OpTC ships 475; SysClient0213 and 0222 have empty files on 21 Sep). Clean hosts: 446 = 473 minus the 27 red-team targets in that population. The other 2 SysClient targets (0005, 0010) have no benign days in OpTC at all, and DC1 has no SysClient eCAR file. Red-team targets (`configs/optc_redteam.yaml`) never enter any baseline. BOTS is out.
- **Baseline:** a pooled benign baseline over all baseline-fit hosts is the default (§5). Role-indexed baselines are optional, used only where the corpus documents host roles (OpTC hostnames carry no role).
- **Split (B2): by host, not by day.** Drawn once with a fixed seed before any scoring and never redrawn: `configs/optc_split.yaml` (seed 20261026): fit 223 hosts (baseline), validation 67 (α, λ tuning only), test 156; all four benign days for each host.
- **ATLASv2** is kept as a robustness check only if it gives ≥500 benign windows (§5) under mapper v3; otherwise it is dropped (decided by the pre-registered count, SPEC_ISSUES 2026-10-26).
- **Telemetry:** Sysmon (or an equivalent endpoint stream converted to Sysmon fields) is the primary source. Windows Security events, where the corpus has them, go through the same extended mapper (§2.5). Report which sources were present in T1. Do not collect new data.
- **Zeek (network vantage, optional; T8).** Used only if the chosen corpus ships Zeek logs for the same hosts and time (OpTC does). Do not build full host-network fusion for this paper.
  - **Pre-flight checks (block Zeek work until both pass):** (a) Zeek sensors and endpoint hosts time-synced: estimate clock offset from matched events (Sysmon event 3 vs. conn.log on the same 5-tuple) and require median |offset| ≤ 2 s, else correct per host or drop Zeek; (b) Zeek capture windows cover the fit and test data. Report both in T1.
  - **Logs and fields to ingest** (`ctit/ingest/zeek.py`):
    - conn: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p, proto, service, duration, orig_bytes, resp_bytes, conn_state, history, orig_pkts, resp_pkts
    - dns: query, qtype_name, rcode_name, answers, TTLs
    - http: host, uri, method, user_agent, status_code, request_body_len, response_body_len
    - ssl / x509: server_name, version, cipher, ja3/ja3s (if present); certificate subject, issuer, not_valid_before/after
    - kerberos: request_type, client, service, success, error_msg, cipher
    - ntlm: username, domainname, success; smb_mapping: path, share_type; smb_files: action, path, name
    - dce_rpc: endpoint, operation
    - rdp / ssh: cookie; auth_success, auth_attempts
    - files: mime_type, sha1/sha256, source, total_bytes
    - dhcp (or the corpus's asset inventory with validity intervals): required for the IP→host join
  - **Host attribution:** attribute each network event to the originating host via the IP→host map at event time. Unattributable events are dropped and counted.
  - **Zeek → tactic mapping** (`ctit/map/zeek_rules.yaml`, versioned, reviewed by Jack). Starting rules, not exhaustive:
    - kerberos TGS with RC4 cipher for service accounts → Credential Access (Kerberoasting)
    - dce_rpc `drsuapi` + `DRSGetNCChanges` from a non-DC → Credential Access (DCSync)
    - dce_rpc `svcctl` CreateService* / `atsvc`/`ITaskSchedulerService` to remote host → Lateral Movement / Execution
    - smb_mapping to ADMIN$/C$ from workstation → Lateral Movement
    - rdp/ssh successful auth between internal workstations → Lateral Movement
    - long-lived low-volume external sessions → Command and Control
    - large outbound orig_bytes to external host after staging → Exfiltration
  - Report mapper coverage for Zeek separately from Sysmon.

### 2.2 Injected adversary sequences
- Convert each emulation-plan step to (technique → tactic) and an ordered tactic sequence. Keep technique-level too.
- **Visibility filter (required before injection).** For each step, record in `data/eval/visibility_<actor>.csv`: `step_id, technique, expected_sysmon_events (e.g., 1|10|13), visible_sysmon {y|partial|n}, expected_zeek_logs (e.g., kerberos|dce_rpc), visible_zeek {y|partial|n}, drift_tactic, rationale`. `drift_tactic` is the tactic the extended mapper (§2.5) produces from the step's concrete artifact, or `—` if it produces none. The injected tactic is `drift_tactic`, not the plan's tactic. Steps with `—` count toward recovery metrics only, like `visible=n`. A step's visibility under a configuration is the best of its sources in that configuration (Sysmon-only uses `visible_sysmon`; Sysmon+Zeek uses the max of the two). Zeek-visible steps are injected as network-derived tactic events on the attributed host. Base this on the step's procedure (what process, file, registry, network, or LSASS access it causes), not on the technique name alone. Rules:
  - `visible=y` → injected as a tactic event with the mapped tactic.
  - `visible=partial` → injected, but carries only the tactic the visible artifact supports (e.g., a PowerShell step visible only as event 1 maps to Execution, not to whatever the script did).
  - `visible=n` → not injected (e.g., Kerberos ticket forgery with no Sysmon artifact). The step still counts in the ground-truth transition set for §6 recovery metrics, but not in the hunting ground truth.
  - Jack reviews the visibility CSV for APT29 before other actors are ported. Agents must not mark a step visible just to keep chains long.
  - Report per actor: steps in plan, visible, partial, dropped (T1).
- Injection: splice the visibility-filtered sequence into a test host's timeline. Match the host role to the step (workstation steps on workstation-role hosts) only where the corpus documents roles. Inter-step gaps sampled from the plan's timing or a log-normal fit to the corpus's inter-event times. Interleave with real benign events, without replacing them.
- **Injection level (decided 2026-10-25, replaces the recorded-event wording).** Injection happens at the tactic-sequence level, which is the scorer's input. Each plan step contributes the tactic subsequence that the frozen mapper (v2, and the BRiMS mapper for the reference runs) produced from a real public recording of the step's technique, chosen with a fixed seed and re-timed with that recording's relative timing. It is spliced into the benign host's tactic-token stream. Steps whose technique has no recording fall back to the process-creation draft (`source=process_only`). The visibility CSV records the step's `source` (`otrf_apt29 | splunk_attack_data | otrf_atomic | process_only`). Raw telemetry is never moved, copied or modified. Splunk Attack Data is also the mapper's recall set (§2.5); the mapper is frozen and not tuned on it.
- Variants per actor: full (visibility-filtered) chain; truncated (first 50% of visible steps, measures early detection); noisy (beyond the visibility filter, drop a further 10–20% of `visible=y` steps at random and drop `partial` steps first, simulating sensor gaps and log loss).
- Seeds: ≥10 injection placements per variant.

### 2.3 Actor set (four nations)

| Nation | Core actor | Eval-sequence source | Status |
|---|---|---|---|
| Russia | APT29 | ATT&CK Evals Round 2 plan (scenarios 1–2) | Ready |
| China | menuPass (APT10) | CTID Adversary Emulation Library plan | Ready |
| Iran | OilRig (APT34) | CTID Adversary Emulation Library plan | Ready |
| Russia | Sandworm | CTID plan (Windows steps 16–19 only) | **Core since 24 Oct** (Jack): within-nation comparison with APT29 |
| DPRK (stretch) | Lazarus-family actor | Report-split fallback (§1). The ATT&CK Evals ER6 DPRK plan is macOS-targeted | **Stretch since 24 Oct** (Jack); decision after the WP5 rerun |

- Every actor gets the same pipeline: same injection procedure, same variants, same seeds, same extraction prompts.
- DPRK check: open the 2024 DPRK plan in github.com/attackevals/ael. If its steps are macOS/Linux-only, use the report-split fallback and say so in the paper. Don't map macOS steps onto Windows hosts.
- **menuPass priors cover the APT10 umbrella (2026-10-27, SPEC_ISSUES).** menuPass-P02 (Kaspersky, A41APT/Ecipekac) is the core APT10 report; P03–P06 describe LODEINFO / MirrorFace / Earth Kasha, which the vendors place under or alongside APT10. State this in T1 and the H4 discussion: the menuPass prior describes the umbrella, while the eval sequence is the CTID menuPass plan. menuPass-P01 (CISA TA18-276B) is kept in the manifest as `excluded` because it never names the actor.
- Wherever this spec says "APT29," it now means "each core actor." APT29 is built first as the reference pipeline.
- Optional extra source: the NUS APT29/APT17/APT32/APT41 emulation datasets. These are built from CTI reports, so check their source lists against the prior manifest before using them.
- Record a public-coverage proxy per actor (count of ATT&CK group-page references and count of independent reports found) for H2b.

### 2.3b Real-execution validation (APT29, OTRF Security-Datasets)
- Purpose: show that synthetic injection gives scores comparable to a real emulated attack. This answers the "your attacks are synthetic" reviewer objection.
- Source: OTRF Security-Datasets recordings of the ATT&CK Evaluations APT29 emulation (day 1 and day 2), with Sysmon, Security, and PowerShell logs. **First task: confirm the dataset is still hosted and downloadable, by 23 Oct.** If it's gone, drop this section and add the limitation.
- Procedure:
  1. Run the extended tactic mapper (§2.5) on the OTRF Sysmon logs only, to match the primary corpus's endpoint stream. Extract the attack hosts' tactic sequences using the dataset's attack timestamps.
  2. Compare against the synthetic visibility-filtered APT29 chain: tactic-sequence edit distance, and the fraction of plan steps that actually appear in the real Sysmon logs vs. the fraction your visibility CSV predicted (this checks the visibility filter itself).
  3. Score the real sequences with U, R-F, R-S (baseline fit on the OTRF benign hosts if enough benign data exists; otherwise on the primary corpus's pooled baseline, stated as cross-environment).
  4. Score the synthetic chain identically. Report the score distributions side by side.
- Output: **T7** synthetic vs. real APT29: visibility agreement (predicted vs. observed visible steps), sequence edit distance, AUPRC/TTD under U, R-F, R-S. Fits in the main paper as a small table if space allows, otherwise in the appendix with one sentence in the main text.
- Leakage note: OTRF data is an eval artifact only. It must not feed priors.

### 2.4 ATLASv2 (limited robustness check)
- **OTRF APT29 (§2.3b) is the primary public real-execution benchmark.** ATLASv2 is a limited robustness check only, reported in T6 with its limits stated: its Sysmon has only event IDs 1 and 5 (process create and terminate), and its ground truth labels Security events in a provenance style (97% are 4663 object access), so it is not tactic ground truth.
- bitbucket.org/sts-lab/atlasv2 (data on Box: one 12.2 GB tarball). Windows hosts, Sysmon + Carbon Black Cloud, ~4 days of benign activity from real users, 10 attack scenarios (s1–s4 single-host, m1–m6 multi-host), ground-truth labels under `data/attack/h*/msft-security/groundtruth/`.
- Caveat: ATLASv2 scenarios are exploit-driven and share a common set of attack steps. They are **not** actor-attributed, so ATLASv2 can't test H4. Use it for H1 and H3 only, generating priors from the scenario descriptions in the ATLAS paper treated as "CTI-like" text. Label this clearly.
- Map Sysmon events → ATT&CK tactics with the extended mapper (§2.5), and report mapper coverage.

### 2.5 Tactic mappers
- **BRiMS mapper:** DRIFT's `sysmon_pipeline.mapping.build_tokens`, untouched. Used as the reference mapper in T1 and T4, and for the optional BRiMS parity test (§8).
- **Extended mapper** (`ctit/map/`, W2-side): SigmaHQ Windows rules (Sysmon and Security) pinned to one commit, with tactic taken from each rule's ATT&CK tags. No other gap-filling. No hand-written rules derived from emulation plans or eval data. Rules tagged with an ATT&CK group or software ID are excluded (leakage). Process-creation rules run on Sysmon EID 1 and Security 4688. Stealth and Defense Impairment (ATT&CK v19) fold into Defense Evasion. A deterministic primary-tactic policy for multi-tactic techniques is documented in `docs/MAPPER_POLICY.md`.
- The extended mapper is frozen (committed) before any injection or scoring. Its report gives: the reachable tactic set K; the per-tactic benign tag rate on public data; and recall against OTRF APT29 ground truth.
- All W2 conditions, U included, use the extended mapper.
- **Mapper v3 (2026-10-26, pre-scoring; SPEC_ISSUES, B3).** The frozen v2 rules minus: (a) `level: informational` (general policy); (b) rules outside the shared subset, i.e. not field-evaluable on both the OpTC conversion and the Sysmon technique recordings; (c) after restoring bare OpTC image paths where the data allows, rules whose path conditions still can't be evaluated on OpTC (they matched a fit-host event through a path field holding a bare image name), and the `create_remote_thread` category. The same rule set applies to benign and injected events. Frozen in `ctit/map/rules_v3.json`; `data/eval/tactic_signatures.parquet` is rebuilt under v3. v3 is the extended mapper for every W2 condition from here on.
- **K:** the set of tactics a mapper can emit from the available sources (Sysmon, Security if present, Zeek once ingested). Priors and ground-truth sequences are projected onto K (§5).

---

## 3. Experimental conditions

**Extraction models**
- F = frontier model (one; pin version string and date)
- S = open-weight small model, run locally under Ollama. Primary: `qwen3:14b` (thinking off, `num_ctx` ≥ 8192). A second, ~4B model in the same family gives a size curve. Pin the weights digest.
- Temperature 0 where supported; else 5 samples and report mean ± sd.
- **Sampling as run (2026-10-27, SPEC_ISSUES).** F (Claude Opus 5.5) accepts no temperature or other sampling parameter, so every F extraction is 5 samples, reported as mean ± sd, with `effort` pinned explicitly in `configs/models.yaml`. S runs twice: temperature 0 (primary) and 5 samples at the model's default sampling (seeded; like-for-like with F). F's reasoning can't be disabled, while S runs with thinking off in both modes; state this asymmetry in the paper wherever F and S are compared (H3, T5).

**Prior conditions**

| Code | Prior | Purpose |
|---|---|---|
| U | None — an unconditioned transition-based anomaly detector (DRIFT-style, from prior work) | Baseline |
| Uni | Uniform transition prior over tactics | Sanity floor |
| ATTK | Structured ATT&CK group mapping → technique set → tactic co-occurrence prior (no order) | Strong non-LLM baseline: "do you need an LLM at all?" |
| B-F / B-S | No-report prior: model asked for the actor's tactic transitions from memory | Memorization bound (H2) |
| R-F / R-S | Report-conditioned prior, same actor | Main method (H1, H3) |
| X-F / X-S | Report-conditioned prior from each of the **other three** actors | Specificity (H4 prior-level matrix off-diagonal, T4; off-target rows in T9) |

Full grid: {U, Uni, ATTK, B-F, B-S, R-F, R-S} × {4 core actors} × {full, truncated, noisy} × seeds, plus the 4×4 prior-actor × eval-actor matrix for R-F and R-S (full chain). ATLASv2 runs {U, Uni, R-F, R-S}.

Compute note: priors are extracted once per actor per model condition, with F and S-sampled ×5 samples (2026-10-27); the H4 matrix reuses them and costs no extra extraction.

---

## 4. Extraction pipeline

`ctit/cti/extract.py`
1. Chunk the report (~6k tokens, overlap 300, identical for F and S; 2026-10-27, was ~2k/200). Token counts are approximated as characters / 4. Record the chunk count per report. S runs with `num_ctx` 16384.
2. Prompt (fixed, versioned in `prompts/extract_v1.txt`): return JSON list of `{from_tactic, to_tactic, technique_from?, technique_to?, evidence_span, confidence}`. Tactics restricted to the 14 Enterprise ATT&CK tactics; reject other labels, and reject self-transitions (from_tactic == to_tactic), counting rejections per model.
3. Validate the JSON schema. Retry once on failure, then log and skip.
4. Aggregate across chunks and reports → count matrix C[i,j] over the 14 tactics, **one count per (report, edge)** for R (an edge in several chunks or places of one report counts once) and one count per (sample, edge) for B (2026-10-27), so each report weighs the same regardless of length. The raw per-mention counts are kept as an appendix variant. One prior per model sample (F and S-sampled: mean ± sd over 5). Prior P = row-normalized (C + α), α = 0.5 (sweep {0.1, 0.5, 1} in the appendix). For scoring, P is projected onto the mapper-reachable set K (§2.5, §5). Transition-recovery metrics (§6) are reported both on the 14 tactics and on K.
5. Evidence check: `evidence_span` must be a substring of the source text. Report the hallucinated-span rate per model. Cheap, and it gives you a citable faithfulness metric.
6. No-report condition uses `prompts/memory_v1.txt` with the same output schema; `<<ALIASES>>` is the actor's ATT&CK group alias list from the same ATT&CK version as the ATTK priors (`configs/actor_aliases.yaml`).

Log all calls (model, prompt hash, tokens, latency, cost). Cost and latency tables support the special theme.

---

## 5. Conditioning mechanism

Default: **likelihood-ratio scoring.** For a host window with tactic sequence s = (s_1, …, s_n) over K:

score(s) = (1/(n−1)) Σ_{t=2..n} [ log P_adv(s_t | s_{t−1}) − log P_ben(s_t | s_{t−1}) ]

that is, the mean log-LR per transition. The summed (unnormalized) version is reported in the appendix only.

- **P_ben** (benign baseline) is **pooled by default**: sum the baseline-fit tactic-transition counts over all baseline-fit hosts (DRIFT ingest semantics, unmapped events skipped). Add α = 0.5 over a fixed K×K list of edges and normalize each row. **Role-indexed baselines are optional** (P_role: the same sum over role-r hosts only), used only where the corpus documents host roles; without row-normalization a role baseline equals DRIFT's role-mean edge vector.
- **P_adv** is a first-order Markov model whose transition matrix is the CTI prior projected onto K. Unreachable tactics are skipped as DRIFT skips unmapped events: T_obs = T_KK + T_KU (I − T_UU)⁻¹ T_UK. It is optionally mixed with P_ben, λ ∈ {0.1, 0.3, 0.5}, chosen on a validation split, never test.
- **Window (primary, 2026-10-26)** = 8 consecutive tagged events on one host (non-overlapping; a trailing partial window is dropped). The appendix reports DRIFT sessions (`sessionize_host`, τ fitted per host on fit hosts only; windows with fewer than 2 tagged events skipped and counted) and fixed windows of 16 and 32 tagged events.
- **U** is DRIFT's scorer (prior work): the JSD between a window's smoothed edge distribution and the pooled baseline-fit mean (or the role-r mean when role baselines are used), over the same fixed edge list.
- **Uni** (likelihood ratio with a uniform P_adv) separates the scorer from the prior: R − Uni is reported as the CTI effect, Uni − U as the scorer effect.

Alternative (ablation): DRIFT's per-edge JSD contribution reweighted by the projected P_adv on transitions with deviation above threshold. Keep whichever wins on validation. Report the other in the appendix.

---

## 6. Metrics

**Transition recovery (extraction quality), vs. emulation-plan ground-truth transitions**
- **Ground truth (2026-10-27):** each plan scenario's tactic sequence with consecutive repeated tactics collapsed (D, D, E → D, E) before counting transitions, so neither side has self-transitions; metrics use the 14 × 14 off-diagonal cells (`ctit/eval/recovery.py`)
- Edge precision / recall / F1 (binary edges)
- Weighted: Jensen–Shannon divergence between the prior and the empirical ground-truth transition matrix (as implemented: JSD between the two joint edge distributions over the off-diagonal cells, each (counts + α) normalized to sum 1, natural log)
- Hallucinated-evidence rate (§4.5), **for report-conditioned priors (R, oracle) only**: B's evidence_span is recalled from memory, not quoted, so it can't be checked
- H3 quantity: S-to-F ratio of edge-F1
- H4 quantity (2026-10-27): the 4×4 prior-actor × plan-actor matrix of edge-F1 and JSD; per row, diagonal minus best off-diagonal

**Hunting**
- AUPRC (primary — heavy class imbalance) and AUROC
- Detection rate at fixed FPR per host-window (window as in §5). **Pre-registered (2026-10-26):** Det@0.1%FPR is reported only if the OpTC test hosts give ≥5,000 benign windows; otherwise the hunting metrics are Det@1%FPR, AUPRC and P@k only. The count is recorded by `configs/benign_windows.yaml`.
- Precision@k for k = 10, 50 (analyst-queue framing)
- Time-to-detect: index of the first injected step at which the score crosses the threshold (fixed at 1% FPR), as a fraction of chain length. Truncated variants test this directly.
- Uncertainty: mean ± 95% bootstrap CI over seeds. Paired Wilcoxon for R vs. U, R vs. B, S vs. F.

**Cost**
- Extraction $/report, latency, GPU memory for S

---

## 7. Paper tables and figures (the agents produce exactly these)

- **T1** Data summary: corpus hosts (and roles where documented), events, telemetry sources present, injected chains per actor, eval-sequence source per actor (plan vs. report-split), steps visible/partial/dropped per actor, prior-doc count per actor, ATLASv2 splits, mapper coverage and reachable tactic set K under both the BRiMS and the extended mapper
- **T7** Synthetic vs. real APT29 (OTRF) validation, see §2.3b. OTRF is the primary public real-execution benchmark and one of the two H1 case studies
- **T8** Vantage ablation (Sysmon-only vs. Sysmon+Zeek), per actor: plan steps visible (count and %), AUPRC and TTD under U and R-S, with paired test. Headline sentence: "network vantage recovers X% of steps endpoint telemetry misses and changes CTI-conditioned AUPRC by Y."
- **T2** Transition recovery: rows {B-F, B-S, R-F, R-S, ATTK}, cols {edge P, R, F1, JSD, hallucination rate}, one block per actor
- **T3** ~~Hunting (main) on injected sequences~~ **Dropped (2026-10-27):** H1 is evidenced through the case studies only (T7, T9)
- **T4** Specificity (H4, prior level, 2026-10-27): 4×4 heatmap, extracted prior actor (rows; R-S main, R-F alongside or in the appendix) × emulation-plan actor (cols), cells = edge-F1 and JSD on the 14-tactic space, F mean ± sd over its 5 samples. Diagonal vs. off-diagonal per row. No telemetry, so no mapper dependence
- **F4** H2b: report-minus-no-report edge-F1 gap (2026-10-27; was AUPRC, which needed the dropped T3 grid) vs. actor public-coverage proxy (4 points, labeled; descriptive only)
- **T5** Small-model sufficiency + cost: F vs. S (temperature 0, and sampled ×5) on edge-F1, case-study hunting lift over U (T7/T9), $/report, latency; caption states F reasons and S doesn't
- **T9** Real intrusion (OpTC red team, B6): rows U / Uni / ATTK / R per actor (F, S) / oracle (F, S); columns AUPRC, Det@1%FPR, TTD. The OpTC red team is not a named APT, so no matched prior exists: the R rows are an off-target check (does mismatched intel help, do nothing, or hurt?). The **oracle** rows use a prior extracted from `OpTCRedTeamGroundTruth.pdf` with the same prompts and pipeline (F and S), labelled "oracle (answer key) — upper bound, not a method result". The oracle never influences α, λ or any other tuning (validation hosts only). Test set: the 29 red-team hosts' benign days plus attack days (23–25 Sep), window labels from the Inria corrected-release labels (a window is positive if it contains a labelled malicious event). Red-team hosts are never in a baseline.
- **T6** ATLASv2 robustness check (only if ATLASv2 passes the ≥500-window rule, §2.1): {U, Uni, R-F, R-S}, with its limits stated in the caption (Sysmon EIDs 1/5 only; provenance-style ground truth; not actor-attributed)
- **F1** Method diagram (separate deliverable)
- **F2** Score timeline on one injected host: U vs. R-S, injected steps marked
- **F3** Extracted vs. ground-truth transition heatmaps (APT29, R-S)
- **Appendix** α, λ, window sweeps; noisy-variant results; conditioning-mechanism ablation; prompts verbatim

---

## 8. Repo layout and run contract

**Relationship to DRIFT**
- W2 lives in its own repo. No W2 code is committed to DRIFT.
- The exact DRIFT commit used for BRiMS is tagged `brims-2026` (`3517424e71a5ffb6f1d9be074f6a82b9e45e3f45`). W2 pins it as the git submodule `third_party/DRIFT`, not as a pip dependency. DRIFT has no package metadata and is never modified, not even to add packaging. `ctit/adapters/drift.py` puts DRIFT's packages on `sys.path` and refuses to load unless the submodule HEAD is that commit and its working tree is clean. DRIFT's `requirements.txt` defines the shared dependency pins.
- Import from DRIFT only what W2 needs: preprocessing, the Sysmon tactic mapper, and baseline fitting/scoring. Wrap these in `ctit/adapters/drift.py` so the rest of W2 never imports DRIFT directly. If the DRIFT pin changes later, only the submodule pointer and the adapter's pinned hash move.
- Do not modify DRIFT internals from W2. If a DRIFT function needs different behavior, subclass or wrap it in the adapter, and log the reason in `docs/SPEC_ISSUES.md`.
- Regression check (**optional since 2026-10-26**): `tests/test_drift_parity.py` reproduces one BRiMS baseline number through the adapter. It needs the BRiMS range parquet and is run only if range data is ever used; otherwise it skips. U is described as a DRIFT-style detector from prior work, not as the published BRiMS method.

```
third_party/DRIFT/        (git submodule @ brims-2026, read-only)
ctit/adapters/drift.py   tests/test_drift_parity.py
ctit/map/                (extended Sigma-based tactic mapper)  docs/MAPPER_POLICY.md
ctit/cti/extract.py      ctit/cti/prior.py       ctit/score/lr.py
ctit/inject/emulation.py ctit/inject/splice.py   ctit/eval/metrics.py
prompts/extract_v1.txt    prompts/memory_v1.txt
data/cti/manifest.csv
configs/w2_grid.yaml      scripts/check_leakage.py scripts/make_tables.py
results/<run_id>/{config.yaml, metrics.json, calls.jsonl}
```

- One command: `python -m ctit.run --config configs/w2_grid.yaml` regenerates all results. `scripts/make_tables.py` emits LaTeX for T1–T6.
- Every run writes its resolved config, git SHA, model versions, and seeds.
- Validation split for any tuning. The test split is touched once per final run.
- All work on personal machine and accounts.

---

## 9. Schedule

| Dates | Work package | Done when |
|---|---|---|
| 20–24 Oct | §1 manifest + leakage check; APT29 visibility CSV (Jack reviews); §2.2 APT29 reference injection pipeline; S model running locally; DPRK plan check (22 Oct); OTRF availability check (23 Oct) | `check_leakage` passes; APT29 visibility CSV signed off; one injected host renders in F2 style; DPRK path decided |
| 25–29 Oct | Visibility CSVs (Sysmon + Zeek columns) + injection for menuPass, OilRig, DPRK (~1 day each); Zeek pre-flight checks, ingest, IP→host join, zeek_rules.yaml (Jack reviews); report collection for all 4 actors; §4 extraction F and S; T2 | All 4 actors injected in both vantage configs; Zeek pre-flight passed or Zeek dropped; T2 populated |
| 30 Oct–3 Nov | §5 scoring, full grid; T3–T5; T8 vantage ablation | Main results frozen |
| 4–6 Nov | ATLASv2 (T6); OTRF validation (T7); appendix sweeps | All tables generated by script |
| 7–15 Nov | Writing | Full draft |
| 16–18 Nov | Revision, AAAI-27 formatting, page check (target ~7 pp + refs) | Compiles clean |
| 19 Nov | Submit | — |

**Cut order if behind (drop first → last):** DPRK stretch → appendix sweeps → secondary Security/PowerShell telemetry run → Zeek vantage ablation T8 (main results stay Sysmon-only) → truncated and noisy variants → ~4B size-curve model → ATLASv2 → OpTC real-intrusion check T9 (B6; the only real-attack evidence on the main corpus, so cut last of these three, 2026-10-26) → OTRF validation → Sandworm (fall back to a 3×3 matrix and say so). Never cut: leakage control, visibility filter, no-report baseline, open-weight run, ATTK baseline, the Russia/China/Iran matrix.

---

## 9b. Reproducibility package (release with the paper)

Goal: everything is public and runnable; the paper uses open data only.
- **Public track:** the full pipeline runs end-to-end on public data only (ATLASv2 + OTRF APT29 + CTID/attackevals emulation plans) via `configs/w2_public.yaml`. This is the only track.
- **Released artifacts:** code; prompts; CTI manifest (URLs + hashes, not report text); extracted priors from F and S per actor; no-report priors; visibility CSVs; emulation-derived tactic sequences; `zeek_rules.yaml`; all `results/` configs and metrics; LLM call logs.
- Every table reproduces from public data.

## 10. Framing notes for the write-up

- Fit: AICS "AI in cyber security" (threat detection, tools and metrics). No critical-infrastructure claim.
- Special theme: offensive knowledge (attacker-behavior descriptions) repurposed as defensive priors, and small-model sufficiency (T5).
- Related work: Khanna, Raff, Krasser et al., "Cybersecurity Detection Classification with Reasoning-enabled Language Models" (arXiv 2607.28460); the BRiMS DRIFT paper; CTI-to-ATT&CK extraction (TRAM-style mappers, LLM CTI extraction); ATLAS/ATLASv2; provenance/HIDS hunting.
- Limitations to state: frontier-model memorization of public APT29 material (bounded by B); first-order Markov assumption; tactic-mapper coverage; ATLASv2 not actor-attributed; synthetic injection vs. live intrusions; **OpTC's benign activity is partly scripted** (range-management jobs); **injected signatures come from Sysmon recordings while the background is eCAR** (mitigated by mapper v3's shared rule subset, applied identically to both sides, and the eCAR-quirk exclusions, §2.5).
