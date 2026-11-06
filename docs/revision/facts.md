# Phase 0 facts (AICS-27 revision, internal review), 2026-11-05

Read-only phase: no model calls, and nothing outside `results/revision/` was written except the branch code noted at the end. Code citations are `file:line` at `main @ 2504489`, the code that produced the draft's numbers. Where the revision branch changed a line, the old line is cited and the change is noted. Tallies were produced by `scripts/revision/phase0_tally.py`, which writes `results/revision/phase0/{config.yaml, metrics.json}` (git SHA recorded there).

## Paths used

| What | Path used | Note |
|---|---|---|
| Current draft (for numbers and claims) | the 04 Nov draft PDF, not in the repo (4 Nov 09:04), read as text with `pdftotext -layout` | **No `.tex` source for this draft is in the repo.** `paper/w2_aics_draft.tex` (untracked) is the older v14d of 31 Oct: no GPT-6 Astra, no block marks, and IG is its Table 5. The 04NOV PDF is the only candidate whose tables match the task (Table 3 = IG with `*` marks, GPT-6 Astra columns, the R−B and OilRig IG intervals quoted in the task). Table numbering below follows it: T1 actors, T2 support recovery, T3 IG + Attr., T4 specificity, T5 R−B. |
| Internal review comments | annotated PDF, not in the repo | Its text layer is identical to the 04NOV draft; the comments are PDF annotations, not extracted. I worked from your task list. |
| Model list → cached priors | `configs/v2_priors.yaml` → `data/priors/<run>/<mode>/{R,B,oracle}_<actor>_<sample>.json` | F `20261027T223842Z-extraction-a686409/F`; Q, Q5 `20261027T223928Z-extraction-a686409/S`, `S-sampled`; M, M5 `20261028T005130Z-extraction-5528fd6/S`, `S-sampled`; M3, M35 `20261028T040137Z-extraction-d032eae/S_3B`, `S_3B-sampled`; G `20261031T155558Z-extraction-50913f7/G`. As-run priors (not the `__unwrap` / `__mv*` sensitivity folders). |
| Runs behind the draft's tables | `configs/paper_tables_v2.yaml` `sources:` | extraction report `20261031T172438Z-extraction_report-16049f4`, likelihood `20261031T172516Z-prior_likelihood-a0bb280`, R−B bootstrap + jackknife `20261031T174610Z-reading_bootstrap-d195210`, block marks `20261031T172545Z-ig_dependence-a0bb280`, case A `20261031T172546Z-case_a_v2-a0bb280`, case B `20261031T172917Z-…`, `20261031T173148Z-redteam_scoring-a0bb280`, `20261031T172645Z-case_b_scripted-a0bb280`. Tables: `results/paper_tables_v2/` (tables run `20261031T174624Z-paper_tables_v2-8d602b4`). |
| Emulation plans | `data/eval/plans/{APT29,OilRig,Sandworm,menuPass}.yaml`, docs in `data/eval/plans/docs/<actor>/` | Pinned in `data/eval/plans/SOURCES.txt`: APT29 from `ael@5594518d…` (ATT&CK Evals R2); the others from `ctid@4467a6ee…`. Not under `third_party/`. |
| Sigma rules | `third_party/sigma` at `552f3fee420ef232a8e5790c4fae591847e32347` (r2026-07-01) | The submodule was already initialised; I did not run `git submodule update --init`. |
| Frozen mapper | `ctit/map/compiled_rules.jsonl` (v2: 3,174 queries / 2,017 rules); `ctit/map/rules_v3.json` (frozen v3 subset: 707) | Policy: `docs/MAPPER_POLICY.md`. |
| Schema-failure analysis already in the repo | `results/20261028T122317Z-schema_failures-6b29976` | Classes the failed replies; the counts below come from the priors' `chunks` records. |
| `audit/` | `audit/evidence_sample.csv` exists | Not needed for these answers; nothing written there. |
| `release/` | `release/cti_manifest.csv` only | No release file depends on the plan ground truth or the priors. |

**Scoring reproduces the draft (the check required before Phase 1).** Recomputed from the cached priors with the new `build_reference()` ground truth and the shared chance draw (10,000 orderings, seed 20261027):
- Table 2, Claude Opus column: .371 (1.99), .396 (3.23), .372 (2.66), .300 (5.79). Matches the draft.
- Table 3, Claude Opus row: +.112, +.622, +.312, +.913 (prints +.11, +.62, +.31, +.91), Attr. 3/4 (the APT29 plan goes to the menuPass chain). Matches the draft.

Pre-existing transcription mismatch noticed in passing, not caused by this work: Table 2, GPT-6 Astra OilRig prints .342, but the source value is 0.34148 (`results/paper_tables_v2/t2_support_recovery.csv`, R-G row), which rounds to .341.

---

## 1. Are edges whose evidence quote fails the check removed before aggregation into C_a?

**No. No code path removes them.** Every scored prior counts edges whose only support is a failing quote.

- `ctit/experiments/extraction.py:120`: `write_prior` calls `extract.build_prior(res, alpha, meta=meta)` without `require_evidence`.
- `ctit/cti/extract.py:377,382`: `build_prior(..., require_evidence: bool = False)` → `counts(trans, require_evidence)`. In `ctit/cti/extract.py:341-347`, the filter `if require_evidence and t.get("evidence_ok") is False: continue` therefore never fires. When it is on, it tests the **strict** flag, not the fragment-aware one.
- Every saved prior records `"require_evidence": false` in its `meta`, and `extract.counts(all transitions)` reproduces every saved `counts` matrix exactly (asserted in `phase0_tally.py`).
- Downstream code rebuilds C_a from all transitions too: `ctit/experiments/v2_common.py:65-73` (`report_edges`, used by the report bootstrap and jackknife) adds every transition and checks that the sum equals the saved counts.
- History: the spec treats the check as a reported rate only (`docs/W2_EXPERIMENT_SPEC.md` §4 step 5: "Report both the strict and the fragment-aware hallucinated-span rate"). `docs/REVIEW_QUEUE.md:176` left filtering as "Your call" (`require_evidence` "default False, spec-literal"), and no later entry turns it on.
- **Paper text affected:** the draft says "spans that fail count as fabricated evidence … Each surviving edge counts once per report", which reads as if failing edges were dropped. They are not.

How much of C_a rests only on failing quotes (R priors; edges = nonzero cells, summed over samples; a count unit is one (report, edge)). Cells read: fragment-aware / strict edges that would vanish if failing transitions were dropped, then fragment-aware count units:

| Model | APT29 | OilRig | Sandworm | menuPass |
|---|---|---|---|---|
| Claude Opus (F, Σ5) | 0 / 5 of 219 edges; 1 of 317 units | 0 / 1 of 218; 0 of 328 | 0 / 10 of 164; 0 of 211 | 0 / 3 of 110; 0 of 159 |
| GPT-6 Astra (G, Σ5) | 0 / 0 of 273; 0 of 382 | 0 / 0 of 241; 0 of 411 | 0 / 0 of 191; 0 of 258 | 0 / 0 of 147; 0 of 220 |
| Qwen 14B t0 (Q) | 5 / 5 of 39; 11 of 59 | 3 / 3 of 24; 6 of 41 | 4 / 4 of 32; 5 of 40 | 4 / 5 of 31; 8 of 44 |
| Qwen 14B sampled (Q5, Σ5) | 4 / 6 of 224; 19 of 371 | 13 / 16 of 131; 29 of 225 | 62 / 64 of 187; 89 of 242 | 81 / 87 of 155; 115 of 221 |
| Ministral 14B t0 (M) | 10 / 10 of 32; 16 of 45 | 3 / 8 of 33; 9 of 47 | 1 / 1 of 15; 5 of 20 | 4 / 4 of 24; 9 of 33 |
| Ministral 14B sampled (M5, Σ5) | 30 / 31 of 207; 59 of 321 | 34 / 44 of 165; 67 of 246 | 22 / 23 of 91; 38 of 110 | 41 / 44 of 123; 58 of 156 |
| Ministral 3B t0 (M3) | 14 / 14 of 32; 18 of 38 | 19 / 19 of 34; 31 of 50 | 9 / 11 of 16; 9 of 16 | 15 / 17 of 29; 22 of 37 |
| Ministral 3B sampled (M35, Σ5) | 50 / 53 of 141; 77 of 182 | 88 / 92 of 163; 152 of 242 | 38 / 40 of 66; 43 of 71 | 69 / 82 of 151; 111 of 204 |

For the frontier models the question is moot under the fragment-aware check (F: 1 count unit; G: none). For the local models, 10–60% of edges rest only on failing quotes. Filtering would change those kernels, which the task forbids ("the kernels stay fixed"), so I report it and change nothing. A filtered-kernel sensitivity run is your decision.

## 2. Schema failures per model and actor

Counted from each saved prior's `chunks` records. A first-attempt failure has `attempts > 1` or `status = skipped_schema`; a chunk is lost if `status = skipped_schema` after the single retry. Retry logic: `ctit/cti/extract.py:288-303` (`ask`, `retries=1`; a fresh call, because the cache is keyed on the attempt, `ctit/experiments/extraction.py:49-53`). Calls cover every condition (R chunks + B generations + the oracle document).

| Model | Calls | First-attempt schema failures | Lost after retry | Refused | By condition and actor (first / lost of calls) |
|---|---|---|---|---|---|
| Claude Opus (F, ×5) | 185 | 1 | 0 | 11 | B Sandworm 1/0 of 5 |
| GPT-6 Astra (G, ×5) | 185 | 0 | 0 | 0 | — |
| Qwen 14B t0 (Q) | 37 | 1 | 1 | 0 | R APT29 1/1 of 9 |
| Qwen 14B sampled (Q5, ×5) | 185 | 7 | 7 | 0 | R APT29 4/4 of 45; R OilRig 3/3 of 40 |
| Ministral 14B t0 (M) | 37 | 8 | 8 | 0 | R APT29 2/2 of 9; R OilRig 1/1 of 8; R Sandworm 3/3 of 7; R menuPass 2/2 of 8 |
| Ministral 14B sampled (M5, ×5) | 185 | 32 | 32 | 0 | B Sandworm 1/1 of 5; R APT29 5/5 of 45; R OilRig 4/4 of 40; R Sandworm 13/13 of 35; R menuPass 9/9 of 40 |
| Ministral 3B t0 (M3) | 36 | 2 | 2 | 0 | R APT29 1/1 of 9; R menuPass 1/1 of 8 |
| Ministral 3B sampled (M35, ×5) | 180 | 12 | 11 | 0 | B menuPass 1/1 of 5; R APT29 5/5 of 45; R OilRig 3/3 of 40; R Sandworm 2/1 of 35; R menuPass 1/1 of 40 |

- **Ministral 14B: 40 of 222 first attempts fail (M 8/37 + M5 32/185), matching the draft. All 40 fail again on retry, so 40 chunks are lost.** One is an entire no-report generation (M5 B Sandworm s2, an empty prior). For R, the 14B Ministral loses 13 of 35 sampled Sandworm chunk-calls and 3 of 7 temperature-0 Sandworm chunks.
- Qwen 14B: 8 of 222 first attempts fail and all 8 are lost (R APT29 and OilRig only). Ministral 3B: 14 of 216 fail and 13 are lost (one M35 Sandworm retry succeeded). Claude Opus: 1 of 185 (the B Sandworm s4 wrapping case), recovered on retry, none lost. GPT-6 Astra: 0 of 185.
- **Retries for the local models are not independent second draws (added 2026-11-05).**
  - **Same options.** A retry is sent with exactly the same options as the first attempt: `ask()` passes only the attempt number (`ctit/cti/extract.py:292-294`), and `OllamaModel.chat` sends `self.options` unchanged (`ctit/llm/ollama.py:75-79`; `attempt` goes only to the call log, `:96`).
    - Temperature-0 runs (Q, M, M3) retry at **temperature 0** (`configs/models.yaml`: `options: {temperature: 0, num_ctx: 16384}`).
    - Sampled runs retry with the **same fixed seed** as their first attempt (`sampled: {..., seeds: [0, 1, 2, 3, 4]}`, `ctit/llm/ollama.py:63`).
  - **Fresh call.** The response cache is keyed on the attempt (`ctit/experiments/extraction.py:49-53`), so a retry is a fresh call, but a deterministic one.
  - **Byte-identical replies.** Comparing the cached first attempt (`<hash>.json`) with the retry (`<hash>.a2.json`) under `data/priors/cache/`, for the as-run models:

    | Model | Retries | Byte-identical to first attempt |
    |---|---|---|
    | Qwen 14B, t0 | 1 | 1 |
    | Qwen 14B, sampled | 7 | 7 |
    | Ministral 14B, t0 | 8 | 8 |
    | Ministral 14B, sampled | 32 | 29 |
    | Ministral 3B, t0 | 2 | 1 |
    | Ministral 3B, sampled | 12 | 10 |

    The few that differ do so only through Ollama's numerical nondeterminism. Of all 62 local retries, one recovered its chunk (Ministral 3B sampled, Sandworm). The other 61 failed again.
  - **API models differ.** Claude Opus takes no temperature, so its one retry was a different reply (and it succeeded); GPT-6 Astra never retried.
  - **Consequence.** For the local models, "one retry" amounts to repeating the same answer. The 04 Nov draft says only "invalid output gets one retry". The older v14d said "fixed-seed retries almost always repeated them". For the temperature-0 runs, the retry is the same request by construction.
- Refusals are separate: F refused 11 (5 OpTC oracle, 5 in R OilRig, 1 in R APT29), which matches the draft's "11 of 185".
- Failure classes (wrapping / multiple values / malformed) are in `results/20261028T122317Z-schema_failures-6b29976/metrics.json`. For Ministral 14B they are mostly multiple JSON values (23 of 40), then wrapping (12) and malformed (5).

## 3. How does the no-report condition B become a count matrix?

**One binary edge set per generation. Generations are not pooled.**
- One B job per actor (`ctit/experiments/extraction.py:110-111`), run once per sample (`:82` frontier samples, `:87` local: `t0` or seeds 0–4). Each B generation is its own document (`ctit/cti/extract.py:324-336`, `doc_id = memory:<actor>#s<k>`). Each (mode, cond, actor, sample) is saved as its own prior (`ctit/experiments/extraction.py:221-223`). Per-document counting makes each B matrix 0/1: `max_count = 1` in every non-empty B prior, checked in `phase0/metrics.json`.
- Multi-generation conditions are combined only at the statistic level: edge-F1 and F1 ÷ chance are means over generations (`ctit/experiments/paper_tables_v2.py:73-82`), and IG is the per-transition mean of log-scores over generations (`ctit/experiments/prior_likelihood.py:47-50`). So each B kernel is Eq. 1 with n_a = 1.
- Generations: Claude Opus ×5, GPT-6 Astra ×5 (API, no temperature); Qwen 14B and Ministral 14B ×1 at temperature 0 (the B rows of Tables 2, 3 and 5), plus ×5 sampled (Q5, M5; B-M5 is in the v2 tables but not the draft); Ministral 3B ×1 at t0 and ×5 sampled. B edge-set sizes: F 11–21, G 6–16, Q 12–13, M 12–13, M3 0 (all four t0 B priors are empty).
- Validation for B: the JSON parse with one retry (`extract.py:288-303`); `schema.validate` (`ctit/cti/schema.py:37-74`: the required keys, exact tactic names from the 14, i ≠ j, confidence in [0, 1], a non-empty `evidence_span`, technique-ID format); one count per (generation, edge). **No evidence check:** `evidence_ok = None` (`extract.py:333-335`), and the rates are set to None for B (`extraction.py:229-231`).

## 4. Block length and scheme behind Table 3's `*` marks

- Code: `ctit/experiments/ig_dependence.py:27-31` (`circular_blocks`); scheme described at `:8-12`. Config: `configs/ig_dependence.yaml`. Run: `results/20261031T172545Z-ig_dependence-a0bb280`.
- Scheme: a **circular** moving-block bootstrap over each plan's collapsed transitions in plan order, scenario after scenario, **treated as one circular sequence**. A block can therefore run across the APT29 scenario boundary and wrap from the end of the sequence back to the start. Each resample concatenates ⌈L/b⌉ blocks with uniformly drawn starts, truncated to L. **b ∈ {2, 3, 5}**, 2,000 replicates, seed `[20261031, b, crc32(actor)]`. Percentile 95% intervals.
- The i.i.d. comparator is the Table 3 interval: 1,000 replicates, seed 20261027 (`configs/prior_likelihood.yaml`), redrawn identically.
- **Mark rule:** `*` if the status (above / spans / below zero) at **any** of b = 2, 3, 5 differs from the i.i.d. status. The seven flagged cells match the draft's seven `*` marks:

| Prior | Plan | i.i.d. | b = 2 | b = 3 | b = 5 |
|---|---|---|---|---|---|
| R GPT-6 Astra | OilRig | above (lower bound +0.001) | spans | spans | above |
| R GPT-6 Astra | menuPass | spans | spans | spans | above |
| R Qwen sampled | OilRig | spans | below | spans | below |
| B GPT-6 Astra | menuPass | spans | above | spans | above |
| B Qwen | menuPass | spans | spans | above | above |
| B Ministral 14B | menuPass | spans | spans | spans | above |
| ATT&CK | APT29 | below | spans | spans | spans |

Four of the seven are menuPass (L = 6, so at b = 5 two blocks nearly cover the plan).

## 5. How plan ground truth is built today

- **Files:** `data/eval/plans/<actor>.yaml` (CALDERA-style YAML). APT29 has 79 abilities, OilRig 44, Sandworm 40, menuPass 15; the leading `emulation_plan_details` entry is skipped (`ctit/eval/plans.py:84`).
- **Platforms:** all of them. `load_plan(actor, platforms=None)` (`ctit/eval/recovery.py:34-37`, `ctit/experiments/v2_common.py:105-106`) keeps every ability (`plans.py:87`). Each ability lists exactly one platform. APT29 and menuPass are all Windows; OilRig has 29 Windows + 15 Linux and Sandworm 15 Windows + 25 Linux.
- **Order:** YAML file order (`plans.py:83-100`). **Scenarios:** split only for APT29, at step 11 (`plans.py:26`, `SCENARIO_STARTS = {"APT29": [11]}`; `_scenario`, `:58-61`). `sequences()` (`plans.py:125-132`) returns one tactic list per scenario. Each list is collapsed (`recovery.py:30-31`) and paired within the list (`prior_likelihood.py:38-40`), so no pair crosses the APT29 scenario boundary. Linux and Windows steps of OilRig and Sandworm are interleaved in one sequence, in file order.
- **Several tactic labels:** every ability has exactly one `tactic` field. The plan's own label is used when it names a tactic (`plans.py:47-51`). Otherwise the step falls back to the **first-listed** ATT&CK v18.1 tactic of its technique, in STIX `kill_chain_phases` order (`plans.py:52-55`, `ctit/map/attack.py:51-73`). This happens once, at APT29 4.A.1 (`stage-capabilities`, T1036.005 → Defense Evasion, its only tactic). The plan label also wins when it disagrees with the technique's ATT&CK tactics (10 steps; listed in `gt_audit.md`).
- Result: APT29 28 edges / L 45 (two scenarios: 33 + 12), OilRig 15 / 17, Sandworm 21 / 25, menuPass 6 / 6. These match Table 1 and the draft's L values.

## 6. How SigmaHQ r2026-07-01 tags map to the 14 tactics

- **Tactic tags, not technique tags.** `ctit/map/sigma_rules.py:59-77` (`rule_tactics`): every `attack.<shortname>` tag becomes a tactic through `attack.tactic_from_shortname` (`ctit/map/attack.py:29-34`), in the rule's tag order. Technique tags are used only when a rule has no tactic tag; that never happens in this release (`docs/MAPPER_POLICY.md`, "Tactic per rule" 2; all 2,017 compiled rules carry tactic tags, `tactic_provenance = rule_tag`).
- **Rules with several tactics:** the rule keeps all of them (`tactics` list), but an event takes **its primary rule's first tactic** (`ctit/map/extended.py:107`). The primary rule is chosen by level, then status, then id (`extended.py:34-36`). 818 of 2,017 compiled rules and 250 of the 707 frozen v3 rules carry more than one frozen tactic.
- **Tags outside the 14:** r2026-07-01 has **no `attack.defense-evasion` tag**. ATT&CK v19 split it into `attack.stealth` (800 rules in `rules/windows`) and `attack.defense-impairment` (302). Both fold into Defense Evasion through `SHORTNAME` (`attack.py:30`); 13 compiled rules carry both. Other `attack.` tags are not tactics and are dropped: technique tags (`attack.tNNNN[.NNN]`, 2,896 tag instances), group and software tags (62 instances; those rules are excluded from the mapper by the leakage policy), and one data-source tag `attack.ds0005` (1). Non-ATT&CK tags (`car.*` 61, `cve.*` 12, `stp.*` 6, `detection.*` 1) are ignored. The full crosswalk is in `results/revision/tables/sigma_crosswalk.{csv,tex}`.
- **One shared mapping function, or separate ones?** Before this revision there were **two routes**:
  1. A shortname lookup (`attack.SHORTNAME`) for plan labels (`plans.py:47-51`, plus an alias `defensive-evasion`), Sigma tags (`sigma_rules.py:65`), and ATT&CK STIX kill-chain phases (ATTK priors and the plan technique fallback; `attack.py:60`).
  2. An exact display-name test for extraction outputs (`ctit/cti/schema.py:45`: `it[k] not in TACTICS`), as the frozen prompt requires ("spelled exactly as written").

  Phase 1 replaces both with one function, `ctit.map.frozen_tactics.to_frozen_tactic(label, source)`, with explicit per-source rules. It reproduces both routes exactly, as `tests/test_frozen_tactics.py` checks over every plan label, every Sigma tag in the release, every ATT&CK kill-chain phase, and every tactic label in the cached extractions. The extraction side accepted every model label except one F output, `"Ingress Tool Transfer placeholder"`, which both routes reject.

---

### Code added on branch `revision/internal-review` (for traceability)

- `ctit/map/frozen_tactics.py` (new): `to_frozen_tactic`, `drop_reason`, and `DROPS` (a logged counter).
- `ctit/eval/plans.py`: `_tactic` routes through `to_frozen_tactic(label, "plan")`; `Step` gains a defaulted `platforms` field.
- `ctit/cti/schema.py:45`: routes through `to_frozen_tactic(x, "extraction")` (exact names, unchanged).
- `ctit/map/sigma_rules.py:65` and `ctit/map/attack.py:60`: route through `to_frozen_tactic`. The compiled rule set is unchanged, as the test asserts.
- `ctit/eval/reference.py` (new): `build_reference`.
- Scripts: `scripts/revision/phase0_tally.py` and `scripts/revision/gt_audit.py`.
- Tests: `tests/test_frozen_tactics.py` and `tests/test_reference.py`. The full suite passes (195 passed, 3 skipped).

---

## 7. Where the draft's text-only intervals come from, and which computation is right (added 2026-11-05)

### 7.1 The OilRig R − B IG intervals: [0.07, 0.69] / [0.03, 0.65] / [0.14, 0.64]

**Code and reproduction.** These come from `ctit/experiments/reading_bootstrap.py` (`one()`, lines 74–113) at `main @ 2504489`, with `configs/reading_bootstrap.yaml`: **2,000 resamples, seed 20261031**. They were not 1,000; the 1,000-resample setting belongs to Table 3 (`prior_likelihood`). The run is `results/20261031T174610Z-reading_bootstrap-d195210`.

I ran that experiment from a detached worktree at `2504489`, linking in `data/` and the pinned DRIFT and Sigma submodules. Its output is **byte-identical** to run d195210:

| | Point | 95% interval | Bootstrap median |
|---|---|---|---|
| Claude Opus | +0.609 | [0.074, 0.687] | 0.470 |
| GPT-6 Astra | +0.501 | [0.026, 0.651] | 0.411 |
| Ministral 14B | +0.562 | [0.140, 0.643] | 0.422 |

On this branch these code paths are unchanged since 2504489 (`git diff 2504489 -- ctit/experiments/{reading_bootstrap,v2_common,prior_likelihood,paper_tables,case_a_v2,ig_dependence}.py ctit/eval/recovery.py` is empty).

**What differs from the paired computation.** Only the resampling unit. Everything else is the same:

| Aspect | Draft (report-level) | My paired version (transition-level) |
|---|---|---|
| Statistic | Mean over the plan's transitions of log2(13 P̂_R) − log2(13 P̂_B) | Same. The point estimates are identical (+0.609 / +0.501 / +0.562). |
| Collapse step | Same plan pairs (`v2_common.plan_pairs`, equal to `build_reference`) | Same |
| Averaging over API runs | Per-transition mean over the samples. The bootstrap also resamples R's samples, and B's samples where there are several (`reading_bootstrap.py:88-90`). A single temperature-0 B is held fixed. | Samples fixed; per-transition mean over samples |
| Resampling unit | **Reports**: R is rebuilt by Eq. 1 from reports drawn with replacement. **Plan transitions are held fixed.** | **Plan transitions**, drawn i.i.d. or in blocks. **Kernels are held fixed.** |
| Pairing | R (from resampled reports) and B (from resampled generations) are drawn independently on the same fixed plan | R and B are scored on the same resampled transitions |

**Why the draft's points sit near the top of their intervals.** A bootstrap resample of n reports contains on average n(1 − (1 − 1/n)^n) distinct reports: **3.36 of 5** for OilRig. IG rises with the number of distinct reports, because each report adds plan edges to C_a. Averaged over all subsets of distinct reports, the R chain's OilRig IG is:

| Distinct reports | 2 | 3 | 4 | 5 |
|---|---|---|---|---|
| Claude Opus | 0.30 | 0.42 | 0.53 | 0.62 |
| GPT-6 Astra | 0.33 | 0.43 | 0.50 | 0.55 |
| Ministral 14B | 0.17 | 0.24 | 0.31 | 0.37 |

So the bootstrap distribution is centred on a smaller-corpus estimator. Opus's R-chain bootstrap median is 0.485, against a point estimate of 0.622, and the percentile interval inherits that shift. The paired interval has no such shift, because the kernels are fixed and only the plan is resampled. That accounts for the "large" change.

**Which is correct.** They answer different questions; neither is a bug.
- **Report-level** asks whether reading *these kinds of reports* improves the chain, so the uncertainty is over which reports were supplied. That is the question behind H2 ("reading or remembering"), and it is the unit Table 5 already uses for ΔF1 and Δenrichment.
  - Its percentile bootstrap is biased downward for this statistic: it is conservative, so an interval that clears zero still means something.
  - The leave-one-report-out jackknife never duplicates a report, and it is the better-centred companion.
  - The draft's rule, "clear only if the bootstrap and the jackknife both exclude zero", handles this.
- **Transition-level** asks whether these two fixed chains differ in how well they predict this plan, treating the plan's transitions as a sample of the actor's behaviour. It is the right unit for Table 3, which scores a fixed chain against a plan. For an R − B statement it ignores corpus variability.
- **For the paper's sentence ("reading's advantage …"), the report-level computation is the right one.** I have switched Table 5's ΔIG column back to it, under the same "clear" rule as ΔF1 and Δenrichment. I made that switch myself; your instruction didn't name the unit. The paired transition-level intervals stay in the supplement (`s_table5_all_models`).

  At 10,000 resamples (seed 20261105), all three are clear, so the draft's sentence holds with two endpoints updated:

  | | Point | Bootstrap 95% | Jackknife 95% |
  |---|---|---|---|
  | Claude Opus | +0.61 | [0.07, 0.69] | [0.28, 0.94] |
  | GPT-6 Astra | +0.50 | [0.02, 0.66] | [0.10, 0.90] |
  | Ministral 14B | +0.56 | [0.16, 0.64] | [0.06, 1.06] |

### 7.2 Every other interval that appears only in the text
I reproduced each one from the code at `2504489`. Same unit as now means only the resample count and the seed differ.

| Draft text | Source (code @ 2504489, run) | Unit | Reproduced | Adopted value |
|---|---|---|---|---|
| Results: menuPass "the frontier models' two conditions tie (−0.09 and −0.01, intervals spanning zero)" | `reading_bootstrap`, d195210, 2,000 | reports | yes: [−1.21, +0.37], [−0.67, +0.20] | 10,000: [−1.22, +0.37], [−0.68, +0.20]; spans |
| Results: "GPT-6 Astra's gap is clear (jackknife [−7.18, −4.56])" | `reading_bootstrap` jackknife, d195210 | leave-one-report-out (deterministic; Monte Carlo chance) | yes | exact chance: [−6.87, −4.26] |
| Results: Claude Opus "negative whichever report is left out (−7.35 to −3.59)" | same | same | yes | exact chance: −7.21 to −3.47 |
| Case A: ATT&CK "+0.76 bits per transition, 95% interval [0.50, 0.98]" | `case_a_v2.py`, run `20261031T172546Z-case_a_v2-a0bb280`, 1,000, seed 20261027 (prior_likelihood's draw order) | executed transitions, i.i.d. | yes (the worktree output equals the run) | 10,000: [0.50, 0.98] |
| Case A: "Claude Opus −0.12 [−0.33, 0.10], GPT-6 Astra −0.04 [−0.27, 0.19]" | same | same | yes | 10,000: [−0.34, 0.10], [−0.28, 0.19] |
| Case B | — | — | The 04 Nov text quotes AUPRC values only (.19–.37, .306, .28–.43, .18–.47, .38–.68 vs .19, .15–.19 vs .15); no interval appears in the text. | Host-cluster intervals rerun at 10,000 (`results/revision/final/case_b/`, supplement `s_case_b`); every AUPRC point is unchanged (asserted). |
| Discussion | — | — | No interval appears. | — |

No other text-only interval exists in the 04 Nov draft. The interval-bearing sentences in Results, Discussion and both case studies are all listed above.
