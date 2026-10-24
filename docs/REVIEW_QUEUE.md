
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
