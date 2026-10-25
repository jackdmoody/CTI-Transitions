# W2 status (2026-10-25)

Deadline: AICS @ AAAI-27, **20 Nov**. Writing starts **7 Nov**, 13 days from now. Companion diagram: `docs/status_map.html`.

## What W2 is
An LLM reads threat-intelligence reports about an actor and compiles them into an ATT&CK tactic-transition prior. That prior then conditions DRIFT-style hunting over endpoint telemetry, scored per window as a likelihood ratio against role-based benign baselines. The hypotheses:
- **H1:** CTI conditioning beats unconditioned DRIFT.
- **H2:** report content matters, not just what the model memorized (report vs. no-report prior). **H2b:** the gap grows as public coverage of the actor shrinks.
- **H3:** a small open-weight model is enough (≥80% of the frontier model's edge-F1 and hunting lift).
- **H4:** the benefit is specific to the adversary (same-actor prior beats other actors' priors in a 4×4 actor matrix).

## Timeline by work package
All of this happened on 24–25 Oct. Commits are on `main`, unpushed.

| WP | Built | Passed / result | What broke, and the fix |
|---|---|---|---|
| Setup | DRIFT pinned as a submodule at `brims-2026`; adapter with a pin and clean-tree check; conda env `w2` (Py 3.12); API key from `.env` | API smoke call OK | DRIFT had no packaging or tag. Jack tagged it, and we switched from a pip dependency to a submodule (SPEC_ISSUES). I first guessed Python 3.11; corrected to 3.12. |
| Plan | §5 rewritten (mean log-LR per transition, role baseline from DRIFT counts, session windows); extended-mapper decision; WORKPLAN | Jack approved | DRIFT turned out to score whole hosts by JSD, with no transition model and no windows. Logged and redesigned. |
| WP1 | Run contract (`results/<id>/…`), call log, DRIFT parity harness | Adapter matches DRIFT's own driver on synthetic data (1e-6) | **Blocked:** the BRiMS parquet (range data) isn't on this machine, so the 3 parity tests skip. |
| WP3 | Manifest schema and `check_leakage.py`, now also cross-checking plan citations | Fixtures pass and fail as designed | The manifest is header-only and fails until reports are chosen. |
| WP4 | OTRF APT29 and ATLASv2 ingest to canonical parquet; role files | Counts match OTRF README | ATLASv2 lives on Box (12 GB), not Bitbucket. Its Sysmon has only EIDs 1 and 5 → demoted to a robustness check. |
| WP4b | Extended mapper: 2017 SigmaHQ rules, frozen v1 then **v2** (adds Security 4688) | Report run per version | The Sigma submodule was committed at the wrong pointer, then fixed. ATT&CK v19 tactic split → folded into Defense Evasion. |
| WP7a/b | ATTK and Uni priors; 14→K projection; output schema; Ollama client with a digest check | Tests; local weights match pins | `qwen3:4b` can't turn thinking off → `qwen3:4b-instruct`. |
| WP5 | Plan loaders (4 actors), visibility draft, cited-source lists, actor-JSD gate | Gate tables in REVIEW_QUEUE | A placeholder parent path made every step "Execution"; removed. I committed once with a failing test (amended), hence the new CLAUDE.md rule 7. |
| WP5 data | OTRF atomic ingest (110 archives); API_SURFACE doc | Coverage table | A filename collision overwrote outputs; tar.gz, Winlogbeat and `__MACOSX` entries needed handling. |
| WP5 injection | Signature library and tactic-level splice (**Jack, by hand**, `8cc7353`) | Library built: 590 rows | **Stalled sessions:** my attempts at event synthesis, and later the splice tests and gate wiring, were stopped mid-response by a safety classifier (Claude's content-safety filter) and are not done. `splice.py` is untested, and the gate has not been rerun with signatures. |

## Current state: data and mappers
- **Data:**
  - OTRF APT29: 642k events, 4 hosts.
  - ATLASv2: 32.1M events, 2 hosts, robustness only.
  - OTRF atomic: 110 datasets, 56 techniques.
  - Splunk full-XML samples: 62 files, 59 techniques.
  - Plans: APT29 79 Windows steps, OilRig 29, menuPass 15, Sandworm 15.
  - Range data and Zeek: none yet.
- **K (tactics actually emitted on public data):** extended v2 = **11** (no Initial Access, C2 or Reconnaissance as primary tactic); BRiMS = **7**.
- **Mapper quality:**

| | BRiMS | Extended v2 |
|---|---|---|
| Benign Sysmon tag rate (ATLASv2) | 0.26% | 0.028% |
| OTRF technique recall | 0.21 | 0.38 |
| Splunk technique / tactic recall (optimistic) | 0.26 / 0.63 | 0.77 / 0.89 |

  On OTRF, BRiMS tags 84–90% of Sysmon events, so OTRF tactic recall is not informative.
- **Signature library:** 89 techniques (extended) / 90 (BRiMS), 170 recordings, 45 files skipped. Plan steps with a real recording for their exact technique / parent technique:

| Actor | Extended | BRiMS |
|---|---|---|
| APT29 | 46% / 70% | 46% / 71% |
| menuPass | 53% / 60% | 53% / 60% |
| OilRig | 72% / 79% | 72% / 79% |
| Sandworm | 47% / 53% | 47% / 73% |

- **Gate so far** (process-creation drafts only):
  - Under BRiMS every actor collapses to Execution (actor JSD ≤ 0.009); this is a reported result.
  - Under the extended mapper, actors separate, but visible transitions are thin: menuPass 7, Sandworm 5.

## Waiting on you
1. **CTI manifest:** choose prior reports (≥2 per core actor; check them against `data/eval/plans/<actor>_cited_sources.txt`). This blocks WP6/WP7 extraction.
2. **BRiMS parquet path:** unblocks WP1 parity.
3. **APT29 visibility CSV sign-off.** You said you'd review it after the signature-based rerun, which isn't done.
4. **H4 viability at K = 11:** decide after the signature-based gate.
5. **DPRK stretch:** report-split or drop. Sandworm is core.
6. **Signature caveats:** how many signatures start with Execution (possibly the Atomic Red Team harness), and the 45 skipped files. Not analysed yet.
7. Pending since setup: your own **DPRK/OTRF notes** in PROGRESS.md.

## What's left (rough effort, in working days)
| | WP | Effort | Blocked on |
|---|---|---|---|
| ☐ | WP5 finish: splice tests, gate wired to signatures, rerun, your sign-off | 1 | splice work (not doable in my sessions) |
| ☐ | WP6: F extraction (prompts v1, chunking, evidence check), B-F | 1.5 | manifest |
| ☐ | WP7 rest: S and S_4B extraction, B-S, cost/latency | 1 | WP6 |
| ☐ | WP9: §5 scorer (fit-window role baseline, sessions, LR, per-window U) | 1.5 | — |
| ☐ | WP10: tactic-level injection into benign public hosts; variants and seeds; F2 | 1 | WP5 |
| ☐ | WP11: metrics and public end-to-end → T2, T6, T7 | 1.5 | WP9, WP10 |
| ☐ | WP1 parity | 0.5 | BRiMS parquet |
| ☐ | WP12: range ingest, roles, time split | 1 | range data |
| ☐ | WP13: visibility/sources for OilRig, menuPass, Sandworm | 1.5 | APT29 sign-off |
| ☐ | WP14: Zeek pre-flight and rules (**cut candidate**) | 1.5 | Zeek logs |
| ☐ | WP15: full grid and `make_tables.py` (T1–T8) | 1.5 | all above |

That's about **13.5 days of work in 13 calendar days** before 7 Nov, with several items blocked on inputs. It doesn't fit unless cuts start now. In spec order: DPRK stretch → appendix sweeps → secondary telemetry → ICS baseline → **Zeek/T8**. Dropping Zeek alone recovers ~1.5 days.
