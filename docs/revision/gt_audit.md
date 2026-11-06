# Phase 1: ground-truth audit (AICS-27 revision, internal review), 2026-11-05

Generated data: `results/revision/gt_audit/{config.yaml, metrics.json}` (git SHA recorded), produced by `scripts/revision/gt_audit.py`. Code: `ctit/eval/reference.py` (`build_reference`) and `ctit/map/frozen_tactics.py` (`to_frozen_tactic`). Tests: `tests/test_reference.py` and `tests/test_frozen_tactics.py`.

**Status (2026-11-05): approved by Jack.** The reference stands as is: APT29 split by scenario, cross-platform handoffs kept, menuPass's optional steps included. Phase 2 was skipped. Variants A and B were scored as sensitivities only; see `changed_conclusions.md`.

## Verdict

**Under the segment rules you specified, the new reference is identical to the old ground truth for all four plans.** The same transitions come out in the same order: the edge sets are the same (28 / 15 / 21 / 6) and L is the same (APT29 45, OilRig 17, Sandworm 25, menuPass 6). No edge is added or removed, and no seam transition is cut. The multi-tactic rule and the unified tactic mapping change no label, and the Sigma crosswalk changes no telemetry label.

**So Phase 2 (rescoring) is not triggered,** unless you adopt one of the two sensitivity variants below. Each would change edges and L. Neither is what your rules prescribe, as I read the plan documents.

Why nothing changes:
- **Independent scenarios.** Only APT29's *YAML* encodes more than one. APT29 is ATT&CK Evals R2: steps 1–10 (Day 1) and 11–20 (Day 2). The old code already split it at step 11 (`ctit/eval/plans.py:26`), and no pair crossed that boundary.
  - OilRig: one scenario (Steps 0–11).
  - Sandworm: the documents name two scenarios, but they run the same Steps 11–19, and the YAML encodes that chain once. See "Sandworm plan structure" below.
  - menuPass: the YAML encodes Scenario 1 only. Scenario 2 exists only as prose (`Emulation_Plan_Scenario2.md`) and was never part of the ground truth.

### Sandworm plan structure (why no transition crosses a scenario boundary or joins two paths)

This resolves the wording conflict between Phase 0 and this audit.

**The documents describe two scenarios but one procedure.** `README.md` lists a "Detection Scenario … (9 steps)" and a "Protection Scenario … (3 tests)".
- **Scenario 1 (Detection)** is Steps 11–19 (`Emulation_Plan_Scenario_1_README.md`, "## Step 11" … "## Step 19").
- **Scenario 2 (Protection)** regroups the **same** Steps 11–19 into Test 7 (Steps 11–14), Test 8 (Steps 15–17) and Test 9 (Steps 18–19), and ends "Scenario complete" (`Emulation_Plan_Scenario_2_README.md`).
- The infrastructure documents say "there is no change of infrastructure between Scenario 1 and Scenario 2". Scenario 1 exercises detection-only controls; Scenario 2 runs with protections enabled.
- `Operations_Flow` lists one chain, Steps 11–19 ("Steps start at 11 to follow emulation procedures"). Each step depends on the one before; for example, Step 15 uses "Frank Herbert's credentials, obtained from the previous step".

So the two scenarios are two executions of one ordered procedure under different security controls. They are not two different operations, and not alternatives.

**The plan file encodes that procedure once.** `data/eval/plans/Sandworm.yaml` has one `emulation_plan_details` entry and then 40 abilities, in file order:

```
11.A.1-3, 11.A.4, 12.A.1-2, 12.A.3, 12.A.4, 12.A.5,
13.A.1, 13.A.2, 13.A.2-5 ×2,
14.A.1–14.A.5,
15.A.1-3, 15.A.4-7, 15.A.7-10 ×2,
16.A.1–16.A.4-5,
17.A.1–17.A.4 (17.A.4 ×3), 17.A.6 ×2, 17.A.7, 17.A.8 ×2,
18.A.1, 18.A.1-2, 18.A.3, 18.A.3-4,
19.A ×2
```

The step numbers never decrease and no step range repeats, so there is no second copy of the chain. The repeated sub-step IDs are distinct actions (for example, 17.A.4 is "Log Keystrokes" on Windows, then "Let Keystroke Logger Run" on the attacker's Linux host, then "Verify Keystroke File" on Windows), each with one platform.

Therefore:
1. **No transition crosses a scenario boundary.** The ground truth contains only one scenario's worth of steps. No transition joins the end of Scenario 1 to the start of Scenario 2, because Scenario 2's copy of the steps is not in the file.
2. **No transition joins two alternative paths.** No step is offered as an alternative to another, either across platforms or across scenarios. The Linux↔Windows handoffs (listed under Sandworm below) are sequential in the documented flow.

**Steps 11–19 do not define two alternative paths, so no alternative-path variant applies.**

One related reading, for completeness; it is not an alternative path and is not adopted. If each Protection *test* were treated as a separately reset run, the chain would be cut at the two test boundaries:
- 14.A.5 Get SSH Keys → 15.A.1-3 Upload Agent to Windows Host: Credential Access → Lateral Movement. This edge occurs once, so cutting it would remove it.
- 17.A.8 Terminate RDP Session → 18.A.1 Prepare Tools: Lateral Movement → Command and Control. This edge occurs twice, so it would survive.

The documents describe the tests as one continuous flow ("Scenario complete" after Test 9; Step 15 uses Step 14's credentials), so I did not score this.
- **Alternative platform execution paths.** There are none. Every ability lists exactly one platform, and no step is offered as a Linux *or* Windows alternative. The Linux abilities in OilRig and Sandworm are **sequential** parts of the one operation:
  - OilRig: the attacker's Kali agent working the EWS and SQL hosts (Steps 5–11).
  - Sandworm: the Linux web server compromised first (Steps 11–15), then lateral movement to Windows. The attacker-side RDP session steps run from the Linux attack platform.

  The plans order Linux and Windows steps in one documented sequence, so a Linux↔Windows handoff is a real transition of the plan, not a seam between alternatives. `reference.PLATFORM_PATHS` is empty for all four actors; it is there so that a plan with real alternatives can declare them.

## Per plan

### APT29 (ATT&CK Evals R2), 79 steps, all Windows
| Segment | Steps | Transitions | Collapsed tactic sequence |
|---|---|---|---|
| Scenario 1 (Day 1) | 1.A – 10.B (58) | 33 | Exec > Collect > Disc > Exfil > Disc > DefEva > PrivEsc > DefEva > PrivEsc > DefEva > Disc > DefEva > Disc > CredAcc > Persist > DefEva > CredAcc > DefEva > CredAcc > DefEva > Collect > Exfil > DefEva > Exec > DefEva > LatMov > Collect > Disc > Exec > Exfil > DefEva > Impact > DefEva > LatMov |
| Scenario 2 (Day 2) | 11.A – 20.B (21) | 12 | Exec > DefEva > Disc > DefEva > CredAcc > Persist > Disc > LatMov > Collect > Exfil > Impact > CredAcc > Persist |

Old 28 edges / L 45 → new 28 / 45. Added: none. Removed: none. No platform handoffs.

### OilRig (CTID), 44 steps (29 Windows, 15 Linux)
| Segment | Steps | Transitions | Collapsed tactic sequence |
|---|---|---|---|
| Scenario (Steps 1–11) | 1.A.4 – 11.A.4 (44) | 17 | Disc > CredAcc > Exfil > C2 > Persist > DefEva > Disc > C2 > CredAcc > Exfil > DefEva > C2 > LatMov > C2 > Exec > Disc > Exfil > DefEva |

Old 15 / 17 → new 15 / 17. Added: none. Removed: none.

Platform handoffs that are tactic changes (kept; these are sequential in the plan). Each edge occurs once in the reference:

| From step (platform) | To step (platform) | Edge |
|---|---|---|
| 4.A.4 Set file hidden attribute (Windows) | 5.A.2 Current User, Kali agent (Linux) | DefEva → Disc |
| 6.A.4 Delete Mimikatz output, Kali agent (Linux) | 7.A.1 Download Plink (Windows) | DefEva → C2 |
| 7.A.2 Run Plink (Windows) | 7.A.4 RDP to WATERFALLS (Linux) | C2 → LatMov |

### Sandworm (CTID), 40 steps (15 Windows, 25 Linux)
| Segment | Steps | Transitions | Collapsed tactic sequence |
|---|---|---|---|
| Scenarios 1/2 (shared Steps 11–19) | 11.A.1-3 – 19.A (40) | 25 | C2 > Persist > Disc > CredAcc > C2 > PrivEsc > Persist > CredAcc > LatMov > Exec > Persist > Disc > C2 > CredAcc > C2 > CredAcc > Exfil > CredAcc > Disc > DefEva > LatMov > C2 > LatMov > C2 > Impact > LatMov |

Old 21 / 25 → new 21 / 25. Added: none. Removed: none.

Platform handoffs that are tactic changes (kept):

| From step (platform) | To step (platform) | Edge | Occurrences in reference |
|---|---|---|---|
| 15.A.7-10 Wait for lateral-move beacon (Linux) | 16.A.1 Windows discovery, current user (Windows) | Persist → Disc | **2** (also 11.A.4 → 12.A.1) |
| 17.A.8 Cleanup artifacts (Windows) | 17.A.8 Terminate RDP session to Gammu (Linux) | DefEva → LatMov | 1 |
| 19.A Execute NotPetya (Windows) | 19.A Terminate RDP session to DC (Linux) | Impact → LatMov | 1 |

### menuPass (CTID), 15 steps, all Windows
| Segment | Steps | Transitions | Collapsed tactic sequence |
|---|---|---|---|
| Scenario 1 (Steps 2–9) | 2.A – 7.1 (15) | 6 | Disc > CredAcc > LatMov > Collect > Exfil > Exec > Persist |

Old 6 / 6 → new 6 / 6. Added: none. Removed: none. No platform handoffs.

## Sensitivity variants (computed, NOT adopted; your call)

| Variant | Plan | Edges old → new | L old → new | Edges removed |
|---|---|---|---|---|
| A. Platform split: every maximal same-platform run is its own segment, which cuts the handoffs above | OilRig | 15 → 12 | 17 → 14 | C2→LatMov, DefEva→C2, DefEva→Disc |
| | Sandworm | 21 → 19 | 25 → 22 | DefEva→LatMov, Impact→LatMov |
| | APT29, menuPass | unchanged | unchanged | — |
| B. menuPass's two **Optional** steps (doc Step 8 "Execution (Optional)" = YAML 8.A; doc Step 9 "Persistence (Optional)" = YAML `7.1`) as separate segments | menuPass | 6 → 4 | 6 → 4 | Exfil→Exec, Exec→Persist |

**A seam transition that duplicates an existing edge (the case you asked to see separately):** Sandworm 15.A.7-10 → 16.A.1, Persistence → Discovery. Under variant A this transition is cut, but the edge survives through 11.A.4 → 12.A.1. **Edge-F1 for Sandworm would then move only through the two removed edges, while L (25 → 22) and every IG value would move through all three cut transitions.** No other cut transition duplicates an edge. Under the adopted reference nothing is cut, so the case does not arise.

Variant B matters most: menuPass's plan has only six edges, and two of them come from steps the plan itself marks Optional. They are also placed out of numeric order (YAML `8.A`, then `7.1`, after the Step 7 exfiltration). I kept them in plan order, because they are steps of the same scenario, not an independent scenario or an alternative platform path.

## Multi-tactic rule (a step with several tactic labels)

Every ability has a single `tactic` field, so no step carries several plan labels. The rule matters only where the step's **technique** maps to several ATT&CK tactics, or where the plan label is not a tactic:
- **27 steps are affected; the rule changes none of them.**
- **26 steps** (APT29 15, Sandworm 11; OilRig and menuPass none) have a multi-tactic technique. The plan's step-level label decides, as before. For example: APT29 3.A.3 T1548.002 [PrivEsc, DefEva] → Privilege Escalation (label); APT29 7.A.4 T1056.001 [Collection, CredAcc] → Collection (label); Sandworm 14.A.1 T1053.003 [Exec, Persist, PrivEsc] → Persistence (label). Full list: `gt_audit/metrics.json` → `multi_tactic`.
- **1 step** has a non-tactic label and falls back to the first-listed technique tactic: APT29 4.A.1 `stage-capabilities`, T1036.005 → Defense Evasion (its only tactic).
- For information (the rule keeps the plan label): **10 steps** carry a plan label that is not among their technique's ATT&CK tactics.
  - APT29: 1.A, 8.B, 10.B, 16.C, 20.B
  - OilRig: 2.A.9, 4.A.4
  - menuPass: 2.A (labelled Discovery, T1105 is C2), 5.A (labelled Lateral Movement, T1569.002 is Execution), 7.1 (labelled Persistence, T1553.005 is Defense Evasion)

## One mapping function

`to_frozen_tactic(label, source)` (`ctit/map/frozen_tactics.py`) is now the only route from a plan label, an extraction label, a Sigma tag, or an ATT&CK kill-chain phase to the 14 tactics. A label either maps to exactly one tactic or is dropped by a named rule, which is counted in `DROPS` and logged. The drop rules:

| Source | Rule |
|---|---|
| Extraction | Not an exact name |
| Plan | Label is not a tactic; falls back to the technique |
| Sigma | Technique tag, group/software tag, `attack.` tag that is not a tactic, or non-ATT&CK tag |
| ATT&CK | Kill-chain phase is not a tactic |

`tests/test_frozen_tactics.py` checks that it reproduces the old behaviour on:
- every plan label (178 steps)
- every tag in the pinned SigmaHQ `rules/windows`, and that `rule_tactics` rebuilds every compiled rule's tactic list (2,017 rules)
- every ATT&CK v18.1 / v19.2 kill-chain phase
- every tactic label in the cached extractions

**No telemetry label changes**, so the case studies need no rerun.

## Sigma crosswalk (r2026-07-01, `rules/windows`)

Columns:
- **Release:** rules in the release carrying the tag.
- **Mapper:** rules in the compiled mapper (v2, 2,017 rules).
- **Frozen v3:** rules in the frozen v3 subset (707).
- **Decides:** rules (mapper / v3) in which this tag is the first tactic tag, i.e. the tag that sets an event's tactic (`ctit/map/extended.py:107`).

Files: `results/revision/tables/sigma_crosswalk.{csv,tex}`.

| Tag | Frozen tactic | Release | Mapper | Frozen v3 | Decides (mapper / v3) |
|---|---|---|---|---|---|
| attack.reconnaissance | Reconnaissance | 12 | 7 | 0 | 5 / 0 |
| attack.resource-development | Resource Development | 22 | 20 | 11 | 16 / 10 |
| attack.initial-access | Initial Access | 63 | 58 | 31 | 31 / 20 |
| attack.execution | Execution | 693 | 553 | 182 | 337 / 121 |
| attack.persistence | Persistence | 528 | 470 | 155 | 264 / 84 |
| attack.privilege-escalation | Privilege Escalation | 480 | 440 | 121 | 287 / 90 |
| attack.defense-impairment\* | Defense Evasion | 302 | 245 | 63 | 136 / 38 |
| attack.stealth\* | Defense Evasion | 800 | 701 | 255 | 392 / 163 |
| attack.credential-access | Credential Access | 256 | 204 | 66 | 158 / 53 |
| attack.discovery | Discovery | 165 | 127 | 36 | 98 / 28 |
| attack.lateral-movement | Lateral Movement | 115 | 95 | 26 | 52 / 13 |
| attack.collection | Collection | 66 | 55 | 21 | 41 / 18 |
| attack.command-and-control | Command and Control | 185 | 163 | 65 | 128 / 53 |
| attack.exfiltration | Exfiltration | 47 | 36 | 7 | 29 / 7 |
| attack.impact | Impact | 61 | 47 | 9 | 43 / 9 |
| attack.ds0005 | dropped: `attack.` tag is not a tactic | 1 | | | |
| attack.gNNNN / attack.sNNNN | dropped: group/software tag (those rules are excluded by the leakage policy) | 62 tag instances | | | |
| attack.tNNNN[.NNN] | dropped: technique tag (tactic tags win; never needed) | 2,896 tag instances | | | |
| car.\*, cve.\*, stp.\*, detection.\* | dropped: not an ATT&CK tag | 61 / 12 / 6 / 1 | | | |

\* ATT&CK v19 split Defense Evasion into these two tags. The release has no `attack.defense-evasion` tag at all, so every Defense Evasion label in the telemetry comes through this fold. 13 compiled rules carry both tags.

The "Decides" column sums to 2,017 (mapper) and 707 (v3). 818 mapper rules and 250 frozen v3 rules carry more than one frozen tactic; for those the first tag in the rule's tag order decides the event's tactic. The compiled mapper's stored tactic lists equal what `to_frozen_tactic` gives today (0 mismatches).

## Released files

None is affected: the reference is unchanged, and `release/` holds only `cti_manifest.csv`.

## Decisions (resolved 2026-11-05)

1. Jack accepted the reference as is. Phase 2 was skipped. Variants A and B are scored as sensitivities only (`results/revision/sensitivity/`, `changed_conclusions.md` §3).
2. Phase 3 uses this reference. Its segment-respecting block bootstrap differs from the old circular one: APT29 blocks no longer cross the Day 1 / Day 2 boundary, and nothing wraps around. For OilRig, Sandworm and menuPass (one segment each), only the wraparound is removed.
