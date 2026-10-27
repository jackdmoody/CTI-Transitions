
## 2026-10-24: WP4b extended mapper review (blocking WP5)

**What:** the frozen extended mapper (`714f999`, `ctit/map/`, policy in `docs/MAPPER_POLICY.md`), validated on public data. Run: `results/20261024T145254Z-mapper_report-714f999/metrics.json`.

**Rule set:** 2017 SigmaHQ `r2026-07-01` Windows rules (Sysmon, Security and System); 56 actor/software-tagged rules excluded. Rule count by primary tactic: Defense Evasion 528, Execution 337, Privilege Escalation 287, Persistence 264, Credential Access 158, C2 128, Discovery 98, Lateral Movement 52, Impact 43, Collection 41, Initial Access 31, Exfiltration 29, Resource Development 16, Reconnaissance 5.

**Reachable tactic set K (primary tactic actually emitted):**

| Data | BRiMS mapper | Extended mapper |
|---|---|---|
| OTRF APT29 Sysmon | 5: Exec, Pers, DE, CA, C2 | 11: ResDev, Exec, Pers, PrivEsc, DE, CA, Disc, LM, Coll, Exfil, Impact |
| OTRF APT29, all sources | 7 (+PrivEsc, Disc) | 11 (Security adds nothing new) |
| ATLASv2 Sysmon (EIDs 1/5 only) | 2: Exec, DE | 5: Exec, PrivEsc, DE, CA, Disc |
| ATLASv2, all sources | 3 (+PrivEsc) | 6 (+Impact) |

**Benign tag rate (ATLASv2 benign split, 4–5 days × 2 hosts, 28.0M events):**

| | BRiMS | Extended |
|---|---|---|
| Sysmon | 0.26% | 0.028% |
| Security | 2.4% (an artifact: `ProcessName` on handle events read as Image) | ~0% |
| Highest per-tactic rate | DE 2.4e-2 | CA 1.6e-6; DE, Exec, PrivEsc ~6e-7 |

On OTRF (attack days, no benign split) the BRiMS mapper tags 84–90% of Sysmon events: every registry event becomes Persistence and every process access becomes Credential Access. The extended mapper tags 0.06–0.6%.

**Recall:**

| Test | BRiMS | Extended |
|---|---|---|
| OTRF APT29 plan steps (48 steps on victim hosts), parent-technique | 0.21 | **0.38** |
| OTRF APT29 plan steps, tactic | 0.83 | 0.84 |
| Splunk Attack Data atomic samples (62), technique | 0.26 | **0.76** |
| Splunk Attack Data atomic samples, tactic | 0.63 | **0.87** |
| ATLASv2 Security ground truth (4081 events), event-level | 0.015 | 0.000 |

Caveats:
- **OTRF tactic recall is pooled per host and day, so it means little.** The BRiMS mapper's 88% tag rate fills almost every tactic. Technique recall is the informative OTRF number.
  - Extended per-tactic recall on OTRF: DE 20/20, Exec 11/11, Disc 17/17, CA 6/6, LM 4/4, PrivEsc 13/14, Pers 10/12, Exfil 3/4, **C2 3/8, Collection 1/7, Initial Access 0/2**.
  - Most-missed techniques: T1057, T1083, T1005, T1070, T1074, T1560, T1105.
- **Splunk recall is optimistic.** Sigma rules are routinely tested against Atomic Red Team data. 43 Security samples were skipped (classic-text format, not XML) and 1 Sysmon file is malformed.
- **ATLASv2 ground truth is not tactic ground truth.** 97% of labelled events are 4663 object-access (provenance labels); 69 are 4688. Neither mapper is meant to tag those.
- OTRF recall uses the evals plan only to validate. It does not feed the mapper.

**Decisions needed from Jack:**
1. **Approve the freeze**, or ask for changes before WP5. Changing the mapper later is a spec issue.
2. **Stealth / Defense Impairment → Defense Evasion collapse** (ATT&CK v19 split). Proposed so the mapper stays on the spec's 14 tactics. The alternative is to move everything to 15 tactics (spec §4, prompts, DRIFT comparison).
3. **Security 4688 process creation.** Sigma `process_creation` rules are applied to Sysmon EID 1 only. Applying them to Security 4688 as well (field mapping NewProcessName→Image, ParentProcessName→ParentImage) would add Execution and other tactics on ATLASv2 Security and on any range host without Sysmon EID 1. Recommendation: add it before the freeze is final. It changes the rule engine, not the rule set.
4. **"Gap-fill from ATT&CK data-component mappings"** is not implemented: no kept rule lacks a tactic. ATT&CK v18+ replaced data components with detection strategies. Is there a specific gap-fill you meant (for example, tactic for events that no rule matches)? Otherwise I propose dropping it from the spec.
5. **H4 risk, early signal:** C2, Collection and Initial Access are rarely recovered on OTRF, and ATLASv2 Sysmon is process-only. K on the range will depend on its Sysmon config. This feeds the WP5 H4 gate.

### 2026-10-24 update: mapper v2 (Jack's decisions applied; frozen at `7d36465`)
v2 also runs Sigma process_creation rules on Security 4688 (pySigma `windows_audit_pipeline`). The Defense Evasion fold is approved, the data-component gap-fill is dropped, and the 56-rule actor/software exclusion is kept. Run: `results/20261024T153421Z-mapper_report-7d36465/metrics.json`. BRiMS mapper numbers are unchanged.

| Extended mapper | v1 (`714f999`) | v2 (`7d36465`) |
|---|---|---|
| Compiled queries (rules) | 2017 (2017) | 3174 (2017; +1157 `security_4688`) |
| K, OTRF Sysmon | 11 | 11 |
| K, OTRF Security | 7 | **11** |
| K, ATLASv2 all sources | 6 | 6 (Security gains Execution) |
| K, all public data | 11 | 11 |
| Benign tag rate, ATLASv2 Sysmon / Security | 2.8e-4 / ~0 | 2.8e-4 / 1.0e-6 |
| OTRF technique recall (parent) | 0.38 | 0.38 |
| OTRF tactic recall (not informative) | 0.84 | 0.87 |
| Splunk technique / tactic recall (optimistic) | 0.76 / 0.87 | 0.77 / 0.89 |
| ATLASv2 Security GT event recall (provenance labels) | 0 / 4081 | 6 / 4081 |

K is the same 11 tactics in both versions: Resource Development, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Impact. **No Initial Access, Command and Control or Reconnaissance** as a primary tactic anywhere on public data.

## 2026-10-24: GATE: APT29 visibility CSV draft (`data/eval/visibility_apt29.csv`), needs Jack's sign-off before other actors are ported
**What:** 79 Windows steps from the ATT&CK Evals APT29 plan (`attackevals/ael@5594518`, `Enterprise/apt29/Emulation_Plan/yaml/APT29.yaml`; scenario 1 = steps 1–10, 58 steps; scenario 2 = steps 11–20, 21 steps). `drift_tactic` comes from mapper v2. Run: `results/20261024T154022Z-wp5_gate-b7db2a4`.

**How the draft is built** (`ctit/eval/visibility.py`):
- Each step's concrete artifacts are synthesized process-creation events (Sysmon EID 1): the executor (`powershell.exe <command>` or `cmd.exe /c <command>`, with **no parent image**), plus one child EID 1 for each command line that starts with a known Windows tool.
- `y` means an artifact is tagged with the step's own tactic.
- `partial` means an EID 1 exists but is tagged with another tactic, or not tagged at all (`drift_tactic` is then `—`).
- `n` means there is no Windows command.
- Result: **14 y, 65 partial, 0 n.**
  - `drift_tactic` = Execution for 56 steps, mostly generic PowerShell-content rules.
  - Discovery 6, Lateral Movement 2, Collection 2, one each of Defense Evasion, Resource Development, C2 and Credential Access.
  - `—` for 9 steps.
- The extra `brims_tactic` column is Execution on 78 of 79 steps.

**Review it for these limits:**
1. **Only process creation is modelled.** Registry (EID 12/13), file (11), network (3), process access (10, e.g. LSASS) and image-load artifacts are not synthesized. Many `partial` steps would likely be `y` with them, for example the persistence (registry run keys) and credential-access (LSASS) steps. Should I extend the synthesis to those event types (from command semantics), or will you hand-mark them?
2. The neutral-parent choice matters. A placeholder agent in `C:\Users\Public` made every step Execution; it was removed.
3. Zeek columns are `pending` until WP14.
4. One plan label is not a tactic (`stage-capabilities`, step 1 tool staging). It falls back to the ATT&CK technique's first tactic.

**Also written:** `data/eval/plans/<actor>_cited_sources.txt` holds the reports each plan cites (`cti_source`): APT29 11, menuPass 7, OilRig 0. Use these to set `cited_by_emulation_plan` in the manifest. OilRig's plan cites none, so the OilRig prior/eval disjointness has to be argued differently.

## 2026-10-24: GATE: H4 viability at K, decide before other actors are ported
**Actors:** APT29 (ael plan), menuPass and OilRig (CTID library `@4467a6e`; OilRig's 15 Linux steps dropped). **DPRK excluded:** the ER6 DPRK plan in `attackevals/ael` is markdown-only and its implants (FULLHOUSE.DOORED, STRATOFEAR) look macOS-targeted. That's your DPRK path decision.

**K (primary tactics the mapper emits on all public data):** extended v2 = 11 (above); BRiMS = 7 (Exec, Pers, PrivEsc, DE, CA, Disc, C2).

**Plan sizes:** APT29 79 steps / 77 transitions; OilRig 29 / 28; menuPass 15 / 14. All are Discovery-heavy (30/79, 20/29, 7/15).

**Pairwise JSD of joint edge distributions** (natural log, maximum ln 2 = 0.693):

| Sequence | α | APT29–OilRig | APT29–menuPass | OilRig–menuPass | Transitions (APT29/OilRig/menuPass) |
|---|---|---|---|---|---|
| Plan tactics, 14 | 0 | 0.350 | 0.318 | 0.290 | 77 / 28 / 14 |
| Plan tactics on K_extended | 0 | 0.330 | 0.318 | 0.268 | 77 / 25 / 14 |
| Plan tactics on K_BRiMS | 0 | 0.265 | 0.299 | 0.203 | 61 / 27 / 10 |
| **Visible, extended v2** (`drift_tactic`) | 0 | 0.509 | 0.496 | 0.332 | 68 / **14** / **4** |
| **Visible, BRiMS** (`brims_tactic`) | 0 | 0.009 | 0.009 | **0.000** | 77 / 27 / 14 |
| Plan tactics, 14 | 0.5 | 0.054 | 0.055 | 0.029 | |
| Visible, extended v2 | 0.5 | 0.117 | 0.113 | 0.023 | |
| Visible, BRiMS | 0.5 | 0.028 | 0.061 | 0.007 | |

**Reading:**
- At the plan level, projecting onto either K keeps actors apart. K_extended loses only OilRig's 3 C2 steps; K_BRiMS also drops Collection, Exfiltration, Lateral Movement and Impact.
- **What the mappers can actually see is the binding constraint.**
  - Under the BRiMS mapper, every actor's visible sequence collapses to Execution (JSD ≈ 0), so H4 cannot be tested with it. T4-under-BRiMS will be flat by construction.
  - Under the extended mapper, actors separate (0.33–0.51), but OilRig keeps only 14 visible transitions and menuPass only 4. That is too thin for a stable 3×3, let alone a 4×4, until visibility goes beyond process creation (limit 1 above) and/or Zeek.
- α = 0.5 over 196 cells swamps sequences this short, so α = 0 is the readable row.
- There is no null yet for "how much JSD is enough".

**Decision needed:**
- Is H4 viable at K = 11 (extended)? Options:
  - (a) proceed, after extending artifact synthesis beyond process creation and re-checking visible transition counts;
  - (b) proceed, but report H4 at plan level plus visible level, with the menuPass/OilRig sparsity stated;
  - (c) re-scope H4 (for example APT29 vs. pooled others) or add actors with richer Windows plans (Sandworm stretch: CTID plan available).
- DPRK path (plan vs. report-split).

### 2026-10-24 rerun: Sandworm added (core), DPRK stretch. Run `results/20261024T163912Z-wp5_gate-2b1e283`
**Changes since the first gate run:**
- Sandworm (CTID, 15 Windows steps, 14 transitions) is added.
- CALDERA `#{arg}` placeholders are now filled from each ability's `input_arguments` defaults.
- Cited-source lists now include the plan docs: APT29 78, menuPass 66, OilRig 34, Sandworm 26.

**Not done: artifact synthesis beyond process creation (your option (a)).** I couldn't complete that part in this session. The visibility drafts below still use process-creation artifacts only (executor plus child tools, neutral parent).

Alternatives:
1. You hand-mark registry/file/network/LSASS visibility in the CSV.
2. Derive per-step artifacts from real recorded telemetry: the OTRF APT29 execution for APT29, plus vendor detection write-ups the plans already ship (`Defense_Measures/*.md`). Only APT29 has a recording.

**Visible transitions per actor** (process-creation artifacts only):

| Actor | Steps | Draft visibility | Visible transitions, extended v2 | Visible transitions, BRiMS |
|---|---|---|---|---|
| APT29 | 79 | 14 y / 65 partial | 68 | 77 |
| OilRig | 29 | 12 y / 16 partial / 1 n | 14 | 27 |
| menuPass | 15 | 3 y / 12 partial | 7 | 14 |
| Sandworm | 15 | 4 y / 9 partial / 2 n | 5 | 12 |

**Pairwise JSD** (joint edge distributions, natural log, maximum 0.693):

| Sequence | α | APT29–OilRig | APT29–Sandworm | APT29–menuPass | OilRig–Sandworm | OilRig–menuPass | Sandworm–menuPass |
|---|---|---|---|---|---|---|---|
| Plan, 14 tactics | 0 | 0.350 | 0.465 | 0.318 | 0.379 | 0.290 | 0.439 |
| Plan on K_extended | 0 | 0.330 | 0.393 | 0.318 | 0.314 | 0.268 | 0.328 |
| Plan on K_BRiMS | 0 | 0.265 | 0.407 | 0.299 | 0.345 | 0.203 | 0.347 |
| Visible, extended v2 | 0 | 0.509 | 0.552 | 0.128 | 0.251 | 0.432 | 0.537 |
| Visible, BRiMS | 0 | 0.009 | 0.009 | 0.009 | 0.000 | 0.000 | 0.000 |
| Plan, 14 tactics | 0.5 | 0.054 | 0.079 | 0.055 | 0.043 | 0.029 | 0.023 |
| Plan on K_extended | 0.5 | 0.060 | 0.083 | 0.064 | 0.055 | 0.040 | 0.024 |
| Plan on K_BRiMS | 0.5 | 0.074 | 0.126 | 0.078 | 0.101 | 0.052 | 0.048 |
| Visible, extended v2 | 0.5 | 0.117 | 0.116 | 0.073 | 0.018 | 0.030 | 0.016 |
| Visible, BRiMS | 0.5 | 0.028 | 0.069 | 0.061 | 0.010 | 0.007 | 0.000 |

**Reading:**
- Sandworm is the most distinct actor at the plan level (it has C2 and Impact steps).
- With visible sequences under the extended mapper, every pair separates at α = 0. But Sandworm (5 transitions) and menuPass (7) are very thin, and at α = 0.5 the smoothing swamps every pair except those involving APT29.
- The BRiMS-mapper collapse (JSD ≈ 0) holds for all four actors.

**Still needed from you:** an H4 decision once visibility is settled (the method choice above), and the DPRK stretch decision.

## 2026-10-26: GATE: extraction prompts v1 (D2), approve before any extraction run
Drafts, uncommitted, in `prompts/`. Code: `ctit/cti/extract.py` (`93736d0`). Placeholders: `<<TACTICS>>` = the 14 tactic names as a bulleted list; `<<TEXT>>` = one ~2k-token chunk (200 overlap); `<<ACTOR>>` = actor name (memory prompt only).
Design choices to check:
- The report prompt does **not** name the actor, so report-conditioned priors can't lean on the model's memory of that actor via the name (H2). The memory prompt must name it.
- No system prompt; one user message per chunk. JSON list only; ```json fences are tolerated.
- Evidence spans are checked against the chunk (whitespace-collapsed substring). Hallucinated spans are counted; `require_evidence` (default False, spec-literal) would drop them from the counts. Your call.
- Counts are unweighted (confidence is recorded, not used), per spec §4.4.
- F: Opus 5.5 rejects temperature, so no sampling parameters are sent and the spec's 5-sample rule applies (SPEC_ISSUES 2026-10-26). Effort to pin: proposed `high`.

### prompts/extract_v1.txt
```
You are reading an excerpt from a cyber threat intelligence report. Extract the order in which the adversary moved between MITRE ATT&CK Enterprise tactics, as the excerpt describes it.

A transition is a pair (from_tactic, to_tactic): the excerpt describes the adversary doing something in from_tactic and then, next in the operation, doing something in to_tactic. Use only what the excerpt states or directly implies about ordering. Do not add steps from your own knowledge of the adversary, of the malware, or of typical intrusions. If the excerpt describes no ordered behaviour, return [].

Use only these tactic names, spelled exactly as written:
<<TACTICS>>

Return a JSON list and nothing else. Each element is an object with these keys:
- "from_tactic": one tactic name from the list above
- "to_tactic": one tactic name from the list above
- "technique_from": the ATT&CK technique ID for the earlier behaviour if the excerpt makes it clear (for example "T1059.001"), otherwise null
- "technique_to": the same for the later behaviour, otherwise null
- "evidence_span": a short passage copied verbatim from the excerpt that supports this transition
- "confidence": a number from 0 to 1 for how clearly the excerpt supports this ordering

Report each distinct transition the excerpt supports once per place it is described.

Excerpt:
<<TEXT>>
```

### prompts/memory_v1.txt
```
From your own knowledge, describe the order in which the threat actor <<ACTOR>> typically moves between MITRE ATT&CK Enterprise tactics during its intrusions. No report is provided.

A transition is a pair (from_tactic, to_tactic): the actor does something in from_tactic and then, next in the operation, does something in to_tactic. If you know nothing reliable about this actor's ordering, return [].

Use only these tactic names, spelled exactly as written:
<<TACTICS>>

Return a JSON list and nothing else. Each element is an object with these keys:
- "from_tactic": one tactic name from the list above
- "to_tactic": one tactic name from the list above
- "technique_from": the ATT&CK technique ID for the earlier behaviour if you know it (for example "T1059.001"), otherwise null
- "technique_to": the same for the later behaviour, otherwise null
- "evidence_span": one sentence on what you recall that supports this transition
- "confidence": a number from 0 to 1 for how sure you are of this ordering

List each distinct transition you believe the actor commonly makes once.
```

## 2026-10-26: v3 leaves the OpTC benign background nearly empty, and C5 failed (review)
- Under v3 the 50-host fit sample has K = {Defense Evasion} at 3.0e-6; v3h adds threat-hunting rules and reaches K = {Execution, Defense Evasion} at 2.4e-5. Almost all v2 benign tags were eCAR artifacts (bare image names, remote threads).
- Over 4 days, the 156 test hosts show K = 5 (PrivEsc 17,694, Discovery 8,126 tagged events), which the 22 Sep sample didn't. Which rules produce these isn't broken down yet.
- Visible transitions under v3 and v3h: APT29 27, OilRig 3, menuPass 3, Sandworm 1. These are process-creation drafts; the signature library is not wired into the gate.
- C5 failed on all three criteria, so the spec now says "hunting = case study". Please confirm.
- B6 raw eCAR (≈17.5 GB) is on hold per your instruction. The case-study framing still uses T9, so it is still needed if T9 stays.
