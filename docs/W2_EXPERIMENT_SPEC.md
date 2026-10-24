# W2 Experiment Spec — CTI-Conditioned ATT&CK Transition Hunting

**Paper:** W2, "CTI Transitions" (working title: *Reading the Adversary: LLM-Compiled Threat Intelligence as Transition Priors for Endpoint Hunting*)
**Venue:** AICS @ AAAI-27 — deadline 20 Nov 2026 AoE, full paper, ~7 pp + refs, AAAI-27 Author Kit, not anonymized
**Repo:** new standalone repo `CTI-Transitions` (package `ctit`; rename freely). This is **not** developed inside DRIFT.
**Dependency:** github.com/jackdmoody/DRIFT (SBP-BRiMS 2026 transition-deviation pipeline), consumed as a pinned, read-only dependency. See §8.
**Audience:** coding agents. Each section is a work package with inputs, outputs, and acceptance checks. Agents do not change hypotheses, conditions, or metrics without sign-off.

---

## 0. Thesis and hypotheses

**Thesis.** Threat-intelligence prose describing an adversary can be compiled by a language model into an ATT&CK tactic-transition prior. Conditioning transition-based endpoint hunting on that prior makes detection more sensitive to the described adversary than unconditioned behavioral-deviation hunting. A small open-weight model is enough to do this, so the benefit is available to defenders without frontier models.

| ID | Hypothesis | Test | Supported if |
|---|---|---|---|
| H1 | CTI conditioning improves hunting | Conditioned vs. unconditioned DRIFT on injected sequences | Higher AUPRC / detection@FPR and earlier detection, CIs over seeds non-overlapping or paired test p<0.05 |
| H2 | The report content matters, not just model memory | Report-conditioned prior vs. no-report (parametric-memory) prior | Report > no-report on transition recovery and hunting |
| H3 | Small open-weight models are sufficient (special theme) | Open-weight vs. frontier extraction | Open-weight recovers ≥80% of frontier edge-F1 and ≥80% of its hunting lift |
| H4 | The benefit is adversary-specific | 4×4 prior-actor × eval-actor matrix across Russia, China, Iran, DPRK | Diagonal (same-actor) > off-diagonal in every row; off-diagonal ≥ unconditioned is acceptable (generic attack structure) |
| H2b | The report matters most where memory is thinnest | Report-minus-no-report gap vs. actor public-coverage rank | Gap increases as coverage decreases (APT29 smallest gap; OilRig/DPRK largest). Secondary, reported descriptively with n=4 |

Report negative results honestly. If H2 fails, that is a finding about memorization and still goes in the paper.

---

## 1. Leakage rule (non-negotiable)

The CTI used to **build priors** and the material used to **build injected evaluation sequences** must come from disjoint sources. This rule applies identically to every actor.

- **Evaluation sequences (ground truth):** MITRE emulation plans (CTID Adversary Emulation Library or the ATT&CK Evaluations library, github.com/attackevals/ael) where a Windows-applicable plan exists. Ordered steps with ATT&CK technique IDs → tactic sequences. Parse the machine-readable YAML where available.
- **Report-split fallback (DPRK, and any actor without a usable Windows plan):** partition that actor's reports into an *eval set* (2–3 reports, e.g., CISA advisories, hand-converted into an ordered technique sequence and reviewed by Jack) and a *prior set* (all remaining reports). Never build eval sequences from ATT&CK group mappings, since those are the ATTK baseline.
- **Prior sources (extraction inputs):** vendor and government reports on the actor that are **not** the emulation plan, **not** cited by the emulation plan, and **not** in the eval set. Target 5–8 per actor; accept a minimum of 2 for thinly covered actors and report the count per actor in T1. Record URL, date, SHA-256 of the saved text.
- Maintain `data/cti/manifest.csv` with columns: `doc_id, actor, nation, source_org, url, pub_date, sha256, used_for {prior|eval}, cited_by_emulation_plan {y|n}`.
- **Acceptance check:** script `scripts/check_leakage.py` fails the build if any doc is `used_for=prior` and `cited_by_emulation_plan=y`, appears in both roles, or if any actor has fewer than 2 prior docs.

Note for the paper: because frontier models were trained on public APT29 material, the no-report baseline (§3, condition B) is what bounds memorization. Leakage control on the report side doesn't remove that, so state it as a limitation.

---

## 2. Data

### 2.1 Exercise-range corpus (benign background + injection target)
- Source: Jack's exercise-range endpoint telemetry, already used in BRiMS. Release cleared.
- Reuse the DRIFT preprocessing → per-host tactic sequences with host-role labels.
- Record which hosts/segments are IT vs. OT/ICS-adjacent (`data/range/host_roles.csv`, column `segment {it|boundary|ot}`).
- Split: benign baseline fit window / held-out test window, by time. No test-window data in baseline fitting.
- **Telemetry:** Sysmon is the primary source (matches BRiMS and ATLASv2). If the range also collected Windows Security logs (4624/4625 logons, 4688, 4769 Kerberos) or PowerShell script-block logging (4104), ingest them through the same tactic mapper as a secondary run. Report which sources were present in T1. Do not collect new data. If those sources are absent, it's a stated limitation.
- **Zeek (network vantage, secondary source).** Jack is pulling the exercise-network Zeek logs. Use them as a second vantage point for visibility and tactic events. Do not build full host-network fusion for this paper.
  - **Pre-flight checks (block Zeek work until both pass):** (a) Zeek sensors and Sysmon hosts time-synced: estimate clock offset from matched events (Sysmon event 3 vs. conn.log on the same 5-tuple) and require median |offset| ≤ 2 s, else correct per host or drop Zeek; (b) Zeek capture windows cover the Sysmon fit and test windows. Report both in T1.
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
    - ICS: modbus (func, exception); dnp3 (fc_request, fc_reply, iin); ICSNPP logs if present (s7comm, enip/cip, bacnet)
    - dhcp (or static asset inventory `data/range/ip_host_map.csv` with validity intervals): required for the IP→host join
  - **Host attribution:** attribute each network event to the originating host via the IP→host map at event time. Unattributable events are dropped and counted.
  - **Zeek → tactic mapping** (`ctit/map/zeek_rules.yaml`, versioned, reviewed by Jack). Starting rules, not exhaustive:
    - kerberos TGS with RC4 cipher for service accounts → Credential Access (Kerberoasting)
    - dce_rpc `drsuapi` + `DRSGetNCChanges` from a non-DC → Credential Access (DCSync)
    - dce_rpc `svcctl` CreateService* / `atsvc`/`ITaskSchedulerService` to remote host → Lateral Movement / Execution
    - smb_mapping to ADMIN$/C$ from workstation → Lateral Movement
    - rdp/ssh successful auth between internal workstations → Lateral Movement
    - dns/conn patterns flagged by existing CADENCE logic, or long-lived low-volume external sessions → Command and Control
    - large outbound orig_bytes to external host after staging → Exfiltration
    - ICS write/control function codes (modbus write funcs, dnp3 operate/direct-operate) from a non-engineering host → Impact / ICS-tactic flag
  - Report mapper coverage for Zeek separately from Sysmon.

### 2.2 Injected adversary sequences
- Convert each emulation-plan step to (technique → tactic) and an ordered tactic sequence. Keep technique-level too.
- **Visibility filter (required before injection).** For each step, record in `data/eval/visibility_<actor>.csv`: `step_id, technique, expected_sysmon_events (e.g., 1|10|13), visible_sysmon {y|partial|n}, expected_zeek_logs (e.g., kerberos|dce_rpc), visible_zeek {y|partial|n}, rationale`. A step's visibility under a configuration is the best of its sources in that configuration (Sysmon-only uses `visible_sysmon`; Sysmon+Zeek uses the max of the two). Zeek-visible steps are injected as network-derived tactic events on the attributed host. Base this on the step's procedure (what process, file, registry, network, or LSASS access it causes), not on the technique name alone. Rules:
  - `visible=y` → injected as a tactic event with the mapped tactic.
  - `visible=partial` → injected, but carries only the tactic the visible artifact supports (e.g., a PowerShell step visible only as event 1 maps to Execution, not to whatever the script did).
  - `visible=n` → not injected (e.g., Kerberos ticket forgery with no Sysmon artifact). The step still counts in the ground-truth transition set for §6 recovery metrics, but not in the hunting ground truth.
  - Jack reviews the visibility CSV for APT29 before other actors are ported. Agents must not mark a step visible just to keep chains long.
  - Report per actor: steps in plan, visible, partial, dropped (T1).
- Injection: splice the visibility-filtered sequence into a test-window host timeline. Match the host role to the step (workstation steps on workstation-role hosts). Inter-step gaps sampled from the plan's timing or a log-normal fit to range inter-event times. Interleave with real benign events, without replacing them.
- Variants per actor: full (visibility-filtered) chain; truncated (first 50% of visible steps, measures early detection); noisy (beyond the visibility filter, drop a further 10–20% of `visible=y` steps at random and drop `partial` steps first, simulating sensor gaps and log loss).
- Seeds: ≥10 injection placements per variant.
- **CI framing check:** report how many injected steps land on `boundary` or `ot` hosts, and whether Zeek ICS logs (modbus, dnp3, ICSNPP) exist for those segments. The critical-infrastructure claim is earned only if both hold: (a) some injected steps land on boundary/OT hosts, and (b) ICS-protocol telemetry exists there and is mapped. Otherwise the paper says "an exercise range that includes ICS assets" and doesn't claim a CI result. The Sandworm stretch actor is the natural vehicle for OT-adjacent steps. Separately, report the benign ICS-protocol baseline (function-code mix by host role) in the appendix. It's cheap and shows the range is a real ICS environment.

### 2.3 Actor set (four nations)

| Nation | Core actor | Eval-sequence source | Status |
|---|---|---|---|
| Russia | APT29 | ATT&CK Evals Round 2 plan (scenarios 1–2) | Ready |
| China | menuPass (APT10) | CTID Adversary Emulation Library plan | Ready |
| Iran | OilRig (APT34) | CTID Adversary Emulation Library plan | Ready |
| DPRK | Lazarus-family actor | ATT&CK Evals 2024 DPRK plan **if Windows-applicable**; else report-split fallback (§1) | **Verify by 22 Oct** |
| Russia (stretch) | Sandworm | CTID plan | Stretch: within-nation comparison + ICS relevance |

- Every actor gets the same pipeline: same injection procedure, same variants, same seeds, same extraction prompts.
- DPRK check: open the 2024 DPRK plan in github.com/attackevals/ael. If its steps are macOS/Linux-only, use the report-split fallback and say so in the paper. Don't map macOS steps onto Windows hosts.
- Wherever this spec says "APT29," it now means "each core actor." APT29 is built first as the reference pipeline.
- Optional extra source: the NUS APT29/APT17/APT32/APT41 emulation datasets. These are built from CTI reports, so check their source lists against the prior manifest before using them.
- Record a public-coverage proxy per actor (count of ATT&CK group-page references and count of independent reports found) for H2b.

### 2.3b Real-execution validation (APT29, OTRF Security-Datasets)
- Purpose: show that synthetic injection gives scores comparable to a real emulated attack. This answers the "your attacks are synthetic" reviewer objection.
- Source: OTRF Security-Datasets recordings of the ATT&CK Evaluations APT29 emulation (day 1 and day 2), with Sysmon, Security, and PowerShell logs. **First task: confirm the dataset is still hosted and downloadable, by 23 Oct.** If it's gone, drop this section and add the limitation.
- Procedure:
  1. Run the DRIFT tactic mapper on the OTRF Sysmon logs only, to match the range corpus. Extract the attack hosts' tactic sequences using the dataset's attack timestamps.
  2. Compare against the synthetic visibility-filtered APT29 chain: tactic-sequence edit distance, and the fraction of plan steps that actually appear in the real Sysmon logs vs. the fraction your visibility CSV predicted (this checks the visibility filter itself).
  3. Score the real sequences with U, R-F, R-S (role baseline fit on the OTRF benign hosts if enough benign data exists; otherwise on the range baseline, stated as cross-environment).
  4. Score the synthetic chain identically. Report the score distributions side by side.
- Output: **T7** synthetic vs. real APT29: visibility agreement (predicted vs. observed visible steps), sequence edit distance, AUPRC/TTD under U, R-F, R-S. Fits in the main paper as a small table if space allows, otherwise in the appendix with one sentence in the main text.
- Leakage note: OTRF data is an eval artifact only. It must not feed priors.

### 2.4 ATLASv2 (external benchmark)
- bitbucket.org/sts-lab/atlasv2. Windows hosts, Sysmon + Carbon Black Cloud, ~4 days of benign activity from real users, 10 attack scenarios (s1–s4 single-host, m1–m6 multi-host), ground-truth labels under `data/attack/h*/msft-security/groundtruth/`.
- Caveat: ATLASv2 scenarios are exploit-driven and share a common set of attack steps. They are **not** actor-attributed, so ATLASv2 can't test H4. Use it for H1 and H3 only, generating priors from the scenario descriptions in the ATLAS paper treated as "CTI-like" text. Label this clearly.
- Map Sysmon/CB events → ATT&CK tactics with the same mapper DRIFT uses, and report mapper coverage.

---

## 3. Experimental conditions

**Extraction models**
- F = frontier model (one; pin version string and date)
- S = open-weight small model (one primary, ≤8–14B, run locally; optionally a second for robustness). Pin weights hash.
- Temperature 0 where supported; else 5 samples and report mean ± sd.

**Prior conditions**

| Code | Prior | Purpose |
|---|---|---|
| U | None — unconditioned DRIFT (BRiMS method) | Baseline |
| Uni | Uniform transition prior over tactics | Sanity floor |
| ATTK | Structured ATT&CK group mapping → technique set → tactic co-occurrence prior (no order) | Strong non-LLM baseline: "do you need an LLM at all?" |
| B-F / B-S | No-report prior: model asked for the actor's tactic transitions from memory | Memorization bound (H2) |
| R-F / R-S | Report-conditioned prior, same actor | Main method (H1, H3) |
| X-F / X-S | Report-conditioned prior from each of the **other three** actors | Specificity (H4 matrix off-diagonal) |

Full grid: {U, Uni, ATTK, B-F, B-S, R-F, R-S} × {4 core actors} × {full, truncated, noisy} × seeds, plus the 4×4 prior-actor × eval-actor matrix for R-F and R-S (full chain). ATLASv2 runs {U, Uni, R-F, R-S}.

Compute note: priors are extracted once per actor per model (8 extractions + 8 no-report runs); the matrix reuses them, so the 4×4 grid costs only scoring time.

---

## 4. Extraction pipeline

`ctit/cti/extract.py`
1. Chunk the report (~2k tokens, overlap 200).
2. Prompt (fixed, versioned in `prompts/extract_v1.txt`): return JSON list of `{from_tactic, to_tactic, technique_from?, technique_to?, evidence_span, confidence}`. Tactics restricted to the 14 Enterprise ATT&CK tactics; reject other labels.
3. Validate the JSON schema. Retry once on failure, then log and skip.
4. Aggregate across chunks and reports → count matrix C[i,j]. Prior P = row-normalized (C + α), α = 0.5 (sweep {0.1, 0.5, 1} in the appendix).
5. Evidence check: `evidence_span` must be a substring of the source text. Report the hallucinated-span rate per model. Cheap, and it gives you a citable faithfulness metric.
6. No-report condition uses `prompts/memory_v1.txt` with the same output schema.

Log all calls (model, prompt hash, tokens, latency, cost). Cost and latency tables support the special theme.

---

## 5. Conditioning mechanism

Default: **likelihood-ratio scoring.** For a host window with tactic sequence s:

score(s) = log P_adv(s) − log P_role(s)

where P_role is DRIFT's role-indexed benign transition model and P_adv is a first-order Markov model with the CTI prior as transition matrix (with smoothing; optionally a mixture with P_role, λ∈{0.1,0.3,0.5}, chosen on a validation split, never test).

Alternative (ablation): DRIFT deviation score reweighted by P_adv on transitions with deviation above threshold. Keep whichever wins on validation. Report the other in the appendix.

Scoring is per sliding window (window length = DRIFT default; sweep in the appendix).

---

## 6. Metrics

**Transition recovery (extraction quality), vs. emulation-plan ground-truth transitions**
- Edge precision / recall / F1 (binary edges)
- Weighted: Jensen–Shannon divergence between the prior and the empirical ground-truth transition matrix
- Hallucinated-evidence rate (§4.5)
- H3 quantity: S-to-F ratio of edge-F1

**Hunting**
- AUPRC (primary — heavy class imbalance) and AUROC
- Detection rate at fixed FPR (0.1%, 1%) per host-window
- Precision@k for k = 10, 50 (analyst-queue framing)
- Time-to-detect: index of the first injected step at which the score crosses the threshold (fixed at 1% FPR), as a fraction of chain length. Truncated variants test this directly.
- Uncertainty: mean ± 95% bootstrap CI over seeds. Paired Wilcoxon for R vs. U, R vs. B, S vs. F.

**Cost**
- Extraction $/report, latency, GPU memory for S

---

## 7. Paper tables and figures (the agents produce exactly these)

- **T1** Data summary: corpus hosts/roles/segments, events, telemetry sources present, injected chains per actor, eval-sequence source per actor (plan vs. report-split), steps visible/partial/dropped per actor, prior-doc count per actor, ATLASv2 splits, mapper coverage
- **T7** Synthetic vs. real APT29 (OTRF) validation, see §2.3b
- **T8** Vantage ablation (Sysmon-only vs. Sysmon+Zeek), per actor: plan steps visible (count and %), AUPRC and TTD under U and R-S, with paired test. Headline sentence: "network vantage recovers X% of steps endpoint telemetry misses and changes CTI-conditioned AUPRC by Y."
- **T2** Transition recovery: rows {B-F, B-S, R-F, R-S, ATTK}, cols {edge P, R, F1, JSD, hallucination rate}, one block per actor
- **T3** Hunting (main): rows {U, Uni, ATTK, B-F, B-S, R-F, R-S}, cols {AUPRC, AUROC, Det@1%FPR, P@10, TTD}, full chain, macro-averaged over the 4 actors with per-actor values in the appendix
- **T4** Specificity (H4): 4×4 heatmap, prior actor (rows) × eval actor (cols), cell = AUPRC lift over U, R-S (R-F in appendix). This is the paper's headline figure-table
- **F4** H2b: report-minus-no-report AUPRC gap vs. actor public-coverage proxy (4 points, labeled; descriptive only)
- **T5** Small-model sufficiency + cost: F vs. S on edge-F1, hunting lift over U, $/report, latency
- **T6** ATLASv2: {U, Uni, R-F, R-S}
- **F1** Method diagram (separate deliverable)
- **F2** Score timeline on one injected host: U vs. R-S, injected steps marked
- **F3** Extracted vs. ground-truth transition heatmaps (APT29, R-S)
- **Appendix** α, λ, window sweeps; noisy-variant results; conditioning-mechanism ablation; prompts verbatim

---

## 8. Repo layout and run contract

**Relationship to DRIFT**
- W2 lives in its own repo. No W2 code is committed to DRIFT.
- The exact DRIFT commit used for BRiMS is tagged `brims-2026` (`3517424e71a5ffb6f1d9be074f6a82b9e45e3f45`). W2 pins it as the git submodule `third_party/DRIFT`, not as a pip dependency. DRIFT has no package metadata and is never modified, not even to add packaging. `ctit/adapters/drift.py` puts DRIFT's packages on `sys.path` and refuses to load unless the submodule HEAD is that commit and its working tree is clean. DRIFT's `requirements.txt` defines the shared dependency pins.
- Import from DRIFT only what W2 needs: preprocessing, the Sysmon tactic mapper, and role-baseline fitting/scoring. Wrap these in `ctit/adapters/drift.py` so the rest of W2 never imports DRIFT directly. If the DRIFT pin changes later, only the submodule pointer and the adapter's pinned hash move.
- Do not modify DRIFT internals from W2. If a DRIFT function needs different behavior, subclass or wrap it in the adapter, and log the reason in `docs/SPEC_ISSUES.md`.
- Regression check: `tests/test_drift_parity.py` reproduces one BRiMS baseline number through the adapter, so the U condition is provably the published method.

```
third_party/DRIFT/        (git submodule @ brims-2026, read-only)
ctit/adapters/drift.py   tests/test_drift_parity.py
ctit/cti/extract.py      ctit/cti/prior.py       ctit/score/lr.py
ctit/inject/emulation.py ctit/inject/splice.py   ctit/eval/metrics.py
prompts/extract_v1.txt    prompts/memory_v1.txt
data/cti/manifest.csv     data/range/host_roles.csv
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

**Cut order if behind (drop first → last):** Sandworm stretch → appendix sweeps → secondary Security/PowerShell telemetry run → benign ICS-protocol baseline → Zeek vantage ablation T8 (main results stay Sysmon-only) → noisy variant → second open-weight model → ATLASv2 → OTRF validation → DPRK (fall back to a 3×3 matrix and say so). Never cut: leakage control, visibility filter, no-report baseline, open-weight run, ATTK baseline, the Russia/China/Iran matrix.

---

## 9b. Reproducibility package (release with the paper)

Goal: everything except raw range telemetry is public and runnable.
- **Public track:** the full pipeline runs end-to-end on public data only (ATLASv2 + OTRF APT29 + CTID/attackevals emulation plans) via `configs/w2_public.yaml`. Build and test against this config first, then switch the data root to the range for final runs.
- **Released artifacts:** code; prompts; CTI manifest (URLs + hashes, not report text); extracted priors from F and S per actor; no-report priors; visibility CSVs; emulation-derived tactic sequences; `zeek_rules.yaml`; all `results/` configs and metrics; LLM call logs.
- **Range data:** raw telemetry is not released. If release-approved, publish aggregated role-level tactic transition counts (no host identifiers or timestamps) so the role baselines can be reproduced.
- Paper states plainly which tables reproduce fully from public data (T2, T5 extraction, T6, T7) and which depend on the range corpus.

## 10. Framing notes for the write-up

- Fit: AICS "AI in cyber security" (threat detection, tools and metrics, critical infrastructure only if §2.2 supports it).
- Special theme: offensive knowledge (attacker-behavior descriptions) repurposed as defensive priors, and small-model sufficiency (T5).
- Related work: Khanna, Raff, Krasser et al., "Cybersecurity Detection Classification with Reasoning-enabled Language Models" (arXiv 2607.28460); the BRiMS DRIFT paper; CTI-to-ATT&CK extraction (TRAM-style mappers, LLM CTI extraction); ATLAS/ATLASv2; provenance/HIDS hunting.
- Limitations to state: frontier-model memorization of public APT29 material (bounded by B); first-order Markov assumption; tactic-mapper coverage; ATLASv2 not actor-attributed; synthetic injection vs. live intrusions.
