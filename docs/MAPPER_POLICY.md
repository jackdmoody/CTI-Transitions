# Extended tactic mapper: policy (spec §2.5)

**Current version: v2.** v1 (`714f999`) ran process_creation rules on Sysmon EID 1 only. v2 also runs them on Security 4688 (Jack, 2026-10-24, before any injection or scoring).

Code: `ctit/map/` (`sigma_rules.py` compiles, `extended.py` applies). The frozen rule set is
`ctit/map/compiled_rules.jsonl`, and `tests/test_extended_mapper.py` checks that it rebuilds
exactly from the pinned inputs. Any change to this policy or the rule set after the freeze
commit is a spec issue (CLAUDE.md).

## Pinned inputs
- SigmaHQ rules: submodule `third_party/sigma` at release `r2026-07-01` (`552f3fee420ef232a8e5790c4fae591847e32347`). Detection Rule License 1.1.
- pySigma 1.5.1, pySigma-backend-sqlite 2.0.0, pySigma-pipeline-sysmon 2.0.0, pySigma-pipeline-windows 2.0.1.
- ATT&CK Enterprise STIX v18.1 and v19.2 (sha256 in `ctit/map/attack.py`). v6.3 is used only to read the 2020 technique names in the OTRF APT29 plan during validation.

## Rule selection
Kept: every rule under `rules/windows/` that passes all of the following.
- `product: windows`, and either a Sysmon category (process_creation, registry_*, file_*, network_connection, process_access, image_load, dns_query, pipe_created, wmi_event, …) or `service: security | system | sysmon`.
- `status` is not `deprecated` or `unsupported`. Stable, test and experimental are all kept, and the level is recorded.
- **Leakage policy:** no `attack.gNNNN` (group) or `attack.sNNNN` (software) tag. This excludes **56 rules** in `r2026-07-01`. Actor- or tool-specific rules are written from CTI on those actors, so they could carry prior knowledge into the evaluation (approved by Jack).
- Has at least one ATT&CK tactic or technique tag.
- Converts with the pySigma SQLite backend.

Excluded directories: `rules-emerging-threats/` (campaign-specific), `rules-threat-hunting/`, `rules-dfir/`, `rules-compliance/`, `deprecated/`, `unsupported/`. PowerShell rules (`ps_*`) are excluded because PowerShell is the spec's secondary telemetry run.

No hand-written rules. Nothing is derived from emulation plans or evaluation data.

## Tactic per rule
1. The rule's own ATT&CK tactic tags, in the rule's tag order.
2. If a rule has no tactic tag: the tactics of its technique tags from ATT&CK v18.1, falling back to v19.2. In `r2026-07-01` this fallback is never needed (all 2017 kept rules have tactic tags).
3. **14-tactic scheme (approved by Jack):** ATT&CK v19.0 split Defense Evasion into Stealth and Defense Impairment. Both fold back into **Defense Evasion** through the lookup table `SHORTNAME` in `ctit/map/attack.py`. This keeps the mapper on the spec's 14 tactics, DRIFT and the emulation plans. It is reversible: delete the two alias entries to get the 15-tactic scheme back.

There is no other gap-filling. The earlier "gap-fill from ATT&CK data-component mappings" was dropped by Jack: no kept rule lacks a tactic, and ATT&CK v18+ replaced data components with detection strategies.

## Event sources per rule (v2)
- Every kept rule compiles with pySigma's Sysmon pipeline plus the Windows log-source pipeline. Sysmon categories become Sysmon EventIDs; `service: security|system` becomes the Channel.
- **process_creation rules also compile for Security 4688** with pySigma's `windows_audit_pipeline` (Image→NewProcessName, ParentImage→ParentProcessName, LogonId→SubjectLogonId). In `compiled_rules.jsonl` these carry `variant: security_4688`, and there are 1157 of them. Only process_creation is routed this way; the pipeline's 4657 registry mapping is not used.
- **Fields 4688 lacks** compared with Sysmon EID 1: OriginalFileName, Hashes (and IMPHASH/MD5/SHA1/SHA256), ParentCommandLine, Description, Product, Company, FileVersion, IntegrityLevel (4688 has MandatoryLabel instead), User and ParentUser (4688 has Subject/Target user fields), CurrentDirectory. Windows 7 4688 (ATLASv2) also lacks CommandLine and ParentProcessName.
  - A condition on a missing field evaluates as SQL NULL. A positive selection on it never matches; a `not`-filter on it also excludes the event. Both under-match, which is conservative, and the event is never tagged on a guess.


## Tactic per event (deterministic)
Each event matches zero or more rules. (A 4688 event can only match `security_4688` variants and a Sysmon event only `sysmon` variants, so the two variants of one rule never compete.) Its **primary rule** is the first by:
1. level (critical > high > medium > low > informational)
2. status (stable > test > experimental)
3. rule id (lexicographic)

The event's tactic is the primary rule's **first** tactic (the rule author's tag order), and its technique is that rule's first technique tag. Events with no match are unmapped (`""`) and are skipped in transition counting, as DRIFT skips unmapped events. Every matching rule id is also kept (`rule_ids`), but only for recall analysis.

## Matching semantics
- Queries come from pySigma's SQLite backend, run on an in-memory SQLite table of canonical events.
- Every text column is `COLLATE NOCASE`, because Sigma string matching is case-insensitive.
- `REGEXP` is Python `re`.
- `Channel` is normalized from `source`.
- A field that no event carries is added as all-NULL, so the rule can't match.
- Column names that differ only in case (for example `IpAddress` and `Ipaddress`) are merged.

## Reading the validation numbers (caveats, approved by Jack)
- **OTRF APT29 tactic recall is not informative.** OTRF has no per-event labels, so recall is pooled per plan step over its victim host and day. A mapper that tags most events (BRiMS: 84–90% of Sysmon) scores near-perfect tactic recall without locating anything. Technique recall is the informative OTRF number.
- **Splunk Attack Data recall is probably optimistic.** The samples are Atomic Red Team executions, and SigmaHQ rules are routinely developed and tested against Atomic Red Team telemetry. Treat it as an upper bound.
- **ATLASv2 is a limited robustness check** (spec §2.4). Its Sysmon has only EIDs 1 and 5, and its ground truth labels Security events in a provenance style (97% are 4663 object access). Event-level "recall" against it does not measure tactic tagging.
