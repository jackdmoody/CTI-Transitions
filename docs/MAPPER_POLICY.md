# Extended tactic mapper: policy (spec §2.5)

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
- **Leakage policy:** no `attack.gNNNN` (group) or `attack.sNNNN` (software) tag. Actor- or tool-specific rules are written from CTI on those actors, so they could carry prior knowledge into the evaluation.
- Has at least one ATT&CK tactic or technique tag.
- Converts with the pySigma SQLite backend.

Excluded directories: `rules-emerging-threats/` (campaign-specific), `rules-threat-hunting/`, `rules-dfir/`, `rules-compliance/`, `deprecated/`, `unsupported/`. PowerShell rules (`ps_*`) are excluded because PowerShell is the spec's secondary telemetry run.

No hand-written rules. Nothing is derived from emulation plans or evaluation data.

## Tactic per rule
1. The rule's own ATT&CK tactic tags, in the rule's tag order.
2. If a rule has no tactic tag: the tactics of its technique tags from ATT&CK v18.1, falling back to v19.2. In `r2026-07-01` this fallback is never needed (all 2017 kept rules have tactic tags).
3. **14-tactic scheme:** ATT&CK v19.0 split Defense Evasion into Stealth and Defense Impairment. Both collapse to **Defense Evasion**, so the mapper matches the spec's 14 tactics, DRIFT and the emulation plans. (Proposed; pending Jack's review.)

"Gap-fill from ATT&CK data-component mappings" is not implemented: no kept rule lacks a tactic. ATT&CK v18+ also replaced data components with detection strategies, so this needs a decision (see REVIEW_QUEUE).

## Tactic per event (deterministic)
Each event matches zero or more rules. Its **primary rule** is the first by:
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
