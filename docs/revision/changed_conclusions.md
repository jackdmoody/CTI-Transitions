# Changed conclusions: final, adopted settings (AICS-27 revision, internal review), 2026-11-05

This file compares the **04 Nov draft** (the 04 Nov PDF; not in the repo) with the analysis run under the **adopted settings** (Jack, 2026-11-05).

**Adopted settings**
- **Reference:** the segmented reference, identical to the draft's ground truth.
- **Chance:** exact hypergeometric for both F1 ÷ chance and percentiles. Monte Carlo is no longer on the main path; a tie-fixed Monte Carlo survives only as a unit test.
- **Resampling:** 10,000 resamples for every bootstrap (seed 20261105).
- **Table 3 marks:** bold and † come from the i.i.d. interval. `*` means the status changes under a moving-block bootstrap with blocks inside segments (b = 2, 3, 5; no wrap-around).
- **Table 5 "clear":** the report bootstrap and the leave-one-report-out jackknife both exclude zero, on the same side.

No model calls were made.

**Where things are**
- Results: `results/revision/final/` (`scenarios/*.json`, `claims.json`, `case_a/`).
- Drop-in tables: `results/revision/final/main/table{2,3,5}.tex`.
- Supplement: `results/revision/final/supplement/`.
- Code: `scripts/revision/final.py`, `scripts/revision/case_a_final.py`, `ctit/experiments/revision_engine.py` (branch `revision/internal-review`).
- **"Old" values** are the draft's. They are reproduced exactly by the draft-settings record (Monte Carlo chance, 1,000 / 2,000 resamples, circular blocks), which is `results/revision/sensitivity/base.json` at commit `c701c77`.
- The superseded interim analysis is in `changed_conclusions_interim_draft_settings.md`.

---

## (a) Main-text changes

Every number or status in the 04 Nov draft whose value changes under the adopted settings, old → new, with the sentence it appears in. Anything not listed is unchanged. Unchanged items include:
- every edge-F1 value, IG point estimate, and Attr. count;
- the H3 shares and the specificity matrix;
- the H2b correlations (−0.4, −1.0, +0.4, −0.8, recomputed under exact chance);
- the edge-count ratios 1.2–3.3 and 3.6–5.4;
- "80% of the plan's six edges with about 13 predicted edges";
- "11 of the 46 … 7";
- the smoothing caps ("about 0.52 for n_a = 6", "2.8 bits").

### Abstract
The text shown ("two 14B open-weight models each reach at least 80% … 7–30% … at most 0.5%") is **unchanged**. The abstract's opening is still "still working this".

### Introduction
- "(1) In ordering, yes: compiled models recover the plans' tactic transitions at two to six times the chance level, while a prior built from ATT&CK's structured data does no better than chance." **Unchanged** (Opus 1.99–5.78, GPT-6 Astra 2.21–3.30, ATT&CK 0.94–1.38).
- "(2) … reading clearly beats memory for only one of four actors under Claude Opus and each 14B model, and for none under GPT-6 Astra." **Unchanged.** The clear positive gaps are Opus OilRig, Qwen 14B Sandworm, and Ministral 14B OilRig; GPT-6 Astra's only clear gap is negative (menuPass).

### Metrics (Experimental Design)
These method sentences must change to match the adopted settings.
- "Edge-F1 is divided by the mean edge-F1 of 10,000 random edge sets of the same size" → **"Edge-F1 is divided by the exact expected edge-F1 of a random edge set of the same size (hypergeometric over the 182 edges); the ratio equals the plan edges recovered divided by the number expected by chance."**
- "IG is computed on each plan's transitions (APT29 45, OilRig 17, Sandworm 25, menuPass 6), with 95% intervals from resampling transitions." → add **"(10,000 resamples), and we mark cells whose status changes when blocks of 2, 3 or 5 consecutive transitions are resampled within one plan scenario"**.
- "Its 95% intervals come from resampling reports; … we call a gap clear only if a leave-one-report-out jackknife also excludes zero." → add **"(10,000 resamples)"**.

### Results: "The compiled models match the plans; the ATT&CK prior does not."

| Sentence | Old | New |
|---|---|---|
| "Claude Opus's report priors reach 2.0–5.8 times chance, at or above the 99.7th percentile for every actor" | 1.99–5.79; min 99.79 | 1.99–5.78; min 99.75. **Both claims hold.** |
| "GPT-6 Astra's reach 2.2–3.3 times, at or above the 97th" | 2.21–3.30; min 97.07 | 2.21–3.30; min 97.51. **Both claims hold.** |
| "Both 14B models exceed chance for every actor, though Qwen 14B on OilRig (88th percentile) and Ministral 14B on Sandworm (84th) fall short of the 95th" | Qwen OilRig 87.9; Ministral Sandworm 84.2 | **Qwen OilRig 92.6 → "93rd"**; Ministral Sandworm 84.1 (stays "84th"). Both are still short of the 95th. |
| "Ministral 3B falls below chance on APT29" | 0.81 | 0.81 (holds) |
| "In likelihood (Table 3), Claude Opus's and GPT-6 Astra's chains beat the uniform chain on all four plans, each clearly on two (OilRig and menuPass for Claude Opus, APT29 and OilRig for GPT-6 Astra)" | Opus 2 clear; GPT-6 Astra 2 clear | **Opus 2 clear (OilRig, menuPass); GPT-6 Astra 1 clear (APT29).** GPT-6 Astra OilRig is +.55, [−0.01, +1.08] at 10,000 resamples (was [+0.001, +1.08] at 1,000). → "…on all four plans, clearly on two for Claude Opus (OilRig and menuPass) and on one for GPT-6 Astra (APT29)" |
| "Ministral 14B's beat it on three, Qwen 14B's clearly only on menuPass, and Ministral 3B's clearly only on menuPass while falling clearly below uniform on APT29" | | **Unchanged** |
| "The ATT&CK prior … sits at chance on edges (0.94–1.38 times; for Sandworm its edge set is all 182 edges) and below uniform on every plan, clearly so for Sandworm and, under i.i.d. resampling, APT29." | | **Unchanged.** APT29 is clear under i.i.d. and carries `*`; Sandworm is clear under every scheme. |

**Clear Table 3 cells per model, above / below zero** (i.i.d.; draft → adopted). Only GPT-6 Astra's report-conditioned row changes:

| Prior | Draft | Adopted |
|---|---|---|
| R Claude Opus | 2 / 0 | 2 / 0 |
| R GPT-6 Astra | **2** / 0 | **1** / 0 |
| R Qwen 14B | 1 / 0 | 1 / 0 |
| R Qwen sampled | 1 / 0 | 1 / 0 |
| R Ministral 14B | 2 / 0 | 2 / 0 |
| R Ministral sampled | 1 / 0 | 1 / 0 |
| R Ministral 3B | 1 / 1 | 1 / 1 |
| B Claude Opus | 1 / 0 | 1 / 0 |
| B GPT-6 Astra | 0 / 0 | 0 / 0 |
| B Qwen 14B | 0 / 0 | 0 / 0 |
| B Ministral 14B | 0 / 1 | 0 / 1 |
| ATT&CK prior | 0 / 2 | 0 / 2 |

### Results: "Specificity is partial." and attribution
**Unchanged:** the edge-F1 margins (.085 / .047 / .076), rows passed, column-wise counts, Attr. 3 / 3 / 3 / 1 / 0, "memory chains at most 2", and "both frontier models confuse APT29 and menuPass".

### Results: "Reading versus remembering depends on the actor."

| Sentence | Old | New |
|---|---|---|
| "After the chance control (Table 5), reading clearly wins only for OilRig under Claude Opus, for no actor under GPT-6 Astra, for Sandworm under Qwen 14B, and for OilRig under Ministral 14B; every APT29 interval spans zero." | | **Unchanged.** Opus OilRig +1.86 (bootstrap [+1.29, +2.98], jackknife [+0.42, +3.30]); Qwen Sandworm +1.10 ([+0.11, +1.30], [+0.05, +2.16]); Ministral OilRig +3.31 ([+2.85, +3.88], [+2.05, +4.57]). Every APT29 interval spans zero. |
| "On menuPass, the comparison reverses for both frontier models. GPT-6 Astra's gap is clear (jackknife [−7.18, −4.56])" | −5.87; jackknife [−7.18, −4.56] | **−5.57; jackknife [−6.87, −4.26]** (bootstrap [−8.85, −3.47]); still clear |
| "and Claude Opus's is negative whichever report is left out (−7.35 to −3.59), although its jackknife interval reaches zero" | −5.23; −7.35 … −3.59 | **−5.08; −7.21 … −3.47**. The jackknife [−11.98, +1.81] still reaches zero; bootstrap [−10.73, −1.52]. |
| "Neither 14B model shows a clear reversal." | Qwen +0.16, Ministral −0.08 | **Qwen +0.23, Ministral +0.00.** Neither is negative, let alone clear, so the sentence holds. |
| "rank correlations … −0.4 for Claude Opus, −1.0 for GPT-6 Astra, +0.4 for Qwen 14B, whose OilRig and Sandworm gaps nearly tie, and −0.8 for Ministral 14B" | | **Unchanged** (Qwen +1.09 and +1.10) |
| "In likelihood (Table 3), reading's advantage excludes zero only for OilRig (Claude Opus +0.61 [0.07, 0.69] bits per transition, GPT-6 Astra +0.50 [0.03, 0.65], Ministral 14B +0.56 [0.14, 0.64])" | report-level, 2,000 resamples | **Holds; the resampling unit stays the same (reports), at 10,000 resamples:** Claude Opus +0.61 [0.07, 0.69], **GPT-6 Astra +0.50 [0.02, 0.66], Ministral 14B +0.56 [0.16, 0.64]**. Each is clear (jackknife [0.28, 0.94], [0.10, 0.90], [0.06, 1.06]). No other actor × model gap is clear. Optionally add "(and a leave-one-report-out jackknife)". See `facts.md` §7.1 for why these points sit near the top of their intervals. |
| "and on menuPass the frontier models' two conditions tie (−0.09 and −0.01, intervals spanning zero)" | report-level [−1.21, +0.37], [−0.67, +0.20] | **Holds:** [−1.22, +0.37], [−0.68, +0.20] at 10,000. |

**The same three OilRig gaps, resampled over plan transitions instead** (supplement only; kernels held fixed, the same resamples for R and B, 10,000):

| | R − B IG | i.i.d. 95% | b = 2 | b = 3 | b = 5 |
|---|---|---|---|---|---|
| Claude Opus | +0.61 | [+0.18, +1.02] | [+0.23, +0.96] | [+0.27, +0.96] | [+0.34, +0.96] |
| GPT-6 Astra | +0.50 | [−0.02, +1.00] | [−0.11, +0.95] | [−0.10, +0.94] | [+0.02, +1.01] |
| Ministral 14B | +0.56 | [+0.22, +0.91] | [+0.22, +0.91] | [+0.30, +0.92] | [+0.36, +0.92] |

These intervals answer a different question: whether two fixed chains differ on this plan. The report-level interval asks whether reading the reports helps, which is H2's question, so it is the one that belongs in the main text (`facts.md` §7.1). An earlier version of this file proposed the transition-level sentence; that proposal is withdrawn. If you want a robustness note, add: "Resampling plan transitions instead of reports, the OilRig gain stays above zero for Claude Opus and Ministral 14B, also in blocks, but not for GPT-6 Astra (+0.50 [−0.02, 1.00])."

### Table 2 (`final/main/table2.tex`)
Edge-F1 values are unchanged except one transcription fix. F1 ÷ chance changes at 2 dp in these cells:

| Prior | Old → new |
|---|---|
| R Claude Opus | Sandworm 2.66 → **2.65**; menuPass 5.79 → **5.78** |
| R GPT-6 Astra | Sandworm 2.23 → **2.22** |
| R Qwen 14B | menuPass 4.90 → **4.89** |
| R Ministral 14B | APT29 2.04 → **2.03**; OilRig 3.30 → **3.31**; Sandworm 1.74 → **1.73** |
| R Ministral 3B | Sandworm 1.63 → **1.62**; menuPass 4.17 → **4.18** |
| B Claude Opus | APT29 1.95 → **1.96**; menuPass 11.02 → **10.87** |
| B GPT-6 Astra | OilRig 2.35 → **2.37**; Sandworm 2.48 → **2.45**; menuPass 9.17 → **8.87** |
| B Qwen 14B | Sandworm 1.34 → **1.33**; menuPass 4.74 → **4.67** |
| B Ministral 14B | APT29 1.09 → **1.08**; Sandworm 1.34 → **1.33**; menuPass 5.14 → **5.06** |

- **Transcription fix:** R GPT-6 Astra OilRig edge-F1 .342 → **.341** (source 0.34148).
- **Caption:** state that chance is the exact expected edge-F1 of a same-size random edge set, and drop "10,000 random edge sets" wherever it appears.

### Table 3 (`final/main/table3.tex`)
- **R GPT-6 Astra OilRig:** "+.55\*" in bold → "+.55\*" **not bold**.
- **New `*` marks:** R Qwen 14B OilRig (−.17 → **−.17\***) and ATT&CK menuPass (−.92 → **−.92\***).
- All other values, bolds, †, the remaining `*` marks, and the Attr. counts are unchanged.
- **Caption:** "Bold: 95% interval above zero; †: below zero; \*: changes under block resampling." → "…(i.i.d. bootstrap over plan transitions, 10,000 resamples). \*: status changes under a moving-block bootstrap with blocks of 2, 3 or 5 consecutive transitions that stay within one plan scenario and never wrap around (10,000 resamples each)."
- **Marks:** the draft had 7 (circular, boundary-crossing); those now appear only in the supplement (`s_table3_intervals_and_old_marks`). The adopted rule gives 9:
  - R GPT-6 Astra: OilRig, menuPass
  - R Qwen: OilRig; R Qwen sampled: OilRig
  - B GPT-6 Astra, B Qwen, B Ministral: menuPass
  - ATT&CK: APT29, menuPass

### Table 5 (`final/main/table5.tex`; restructured)
The draft's Table 5 showed R − B in F1 ÷ chance, with intervals for the API models only. It is now **ΔF1, Δenrichment and ΔIG for the two frontier models**; the local models move to the supplement (`s_table5_all_models`) with their intervals.

Old → new for the cells the draft printed:

| Model | APT29 | OilRig | Sandworm | menuPass |
|---|---|---|---|---|
| Claude Opus | +0.03 [−0.86, +0.47] → **+0.03 [−0.85, +0.44]** | +1.87 [+1.33, +2.95] → **+1.86 [+1.29, +2.98]** (bold) | +0.80 [−0.10, +1.84] → **+0.80 [−0.05, +1.79]** | −5.23 [−10.84, −1.56] → **−5.08 [−10.73, −1.52]** |
| GPT-6 Astra | +0.56 [−0.41, +1.32] → **+0.56 [−0.41, +1.33]** | +0.37 [−0.56, +2.19] → **+0.34 [−0.56, +2.16]** | −0.25 [−1.73, +0.62] → **−0.22 [−1.69, +0.64]** | −5.87 [−9.05, −3.76] → **−5.57 [−8.85, −3.47]** (bold) |
| Qwen 14B (now supplement) | −0.17 | +1.09 | +1.10 (clear) | +0.16 → **+0.23** |
| Ministral 14B (now supplement) | +0.95 | +3.30 → **+3.31** (clear) | +0.40 | −0.08 → **+0.00** |

The new ΔF1 and ΔIG cells (bold = clear):

| Model | Metric | APT29 | OilRig | Sandworm | menuPass |
|---|---|---|---|---|---|
| Claude Opus | ΔF1 | +0.137 | **+0.280** | +0.189 | −0.195 |
| Claude Opus | ΔIG | +0.06 [−0.27, +0.11] | **+0.61** [+0.07, +0.69] | +0.33 [−0.11, +0.46] | −0.09 [−1.22, +0.37] |
| GPT-6 Astra | ΔF1 | **+0.273** | **+0.193** | +0.150 | **−0.143** |
| GPT-6 Astra | ΔIG | +0.30 [−0.19, +0.40] | **+0.50** [+0.02, +0.66] | +0.17 [−0.25, +0.32] | −0.01 [−0.68, +0.20] |

ΔIG uses the same report-level resampling and "clear" rule as ΔF1 and Δenrichment (`facts.md` §7.1); the transition-level ΔIG intervals are in the supplement. The drop-in caption states the report resampling (10,000) and the jackknife rule, and notes that report-resampled intervals tend to sit below the point estimate.

### Case study A

| Sentence | Old | New |
|---|---|---|
| "matches the plan at 2.07× chance" | | Unchanged |
| "Claude Opus's APT29 prior reaches 1.45× chance, no better than its OilRig prior" | 1.45 vs 1.45 | 1.45 vs 1.44 (same in substance) |
| "although GPT-6 Astra's (1.80×) beats its other actors' priors (1.09–1.64×)" | 1.80; 1.09–1.64 | **1.79; 1.08–1.63** |
| "the ATT&CK prior is the only one clearly above uniform (+0.76 bits per transition, 95% interval [0.50, 0.98])" | | Unchanged at 10,000 resamples |
| "(APT29 priors: Claude Opus −0.12 [−0.33, 0.10], GPT-6 Astra −0.04 [−0.27, 0.19])" | | **Claude Opus −0.12 [−0.34, 0.10]; GPT-6 Astra −0.04 [−0.28, 0.19]** |

Source: `final/case_a/metrics.json` and `final/supplement/s_case_a`.

### Case study B
**Unchanged:** "11 of the 46 positive windows contain no tactic change, and 7 contain one" and "a quarter of OpTC's attack windows contain no tactic change". The host-cluster bootstrap intervals were rerun at 10,000 resamples from the three draft runs' own configs (`results/revision/final/case_b/`, supplement `s_case_b`). Every AUPRC point is unchanged (asserted), and the intervals move by at most 0.05 (for example, collapsed R-F OilRig [0.32, 0.61] → [0.33, 0.58]). The text quotes no case-B interval, so no stated number or conclusion changes.

### Discussion and checklist
No number changes. "Resample reports, not only transitions, and check that a result survives leaving out each report in turn (bold in Table 5)" still describes Table 5's ΔF1 and Δenrichment.

### Limitations
- "Information-gain intervals treat plan transitions as independent; block resampling changes the status of seven cells (Table 3)." → **"…block resampling within plan scenarios changes the status of nine cells (Table 3)."** Optionally add that five of the nine are menuPass, whose six transitions admit only two blocks of five.
- "Ministral 14B failed the output schema on 40 of 222 first attempts, which removes chunks from its priors." **Unchanged.** Optionally add "none recovered on retry" (`facts.md` §2).

### Conclusion
**Unchanged:** "the result holds for two frontier models", "for menuPass both frontier models recover the plan better from memory than from the reports", and "uncertainty at the level of reports".

### Wording corrections from Phase 0 (not driven by resampling; see `facts.md`)
- Method, step 2: "Each surviving edge counts once per report" → "Each edge counts once per report". The evidence check is reported, not used to filter; §(b)1 gives the filtered sensitivity.
- Method, step 2: "invalid output gets one retry" → note that the local models' retry repeats the request with the same settings (temperature 0, or the same seed). 56 of the 62 local retries were byte-identical, and 1 of 62 recovered a chunk.

---

## (b) Sensitivity-only results (supplement)

These were run under the same adopted settings and scored only; none is adopted. Files are in `final/supplement/`: `s_<scenario>_{t2,t3,t5}`, `s_evidence_shares`, `s_h3_evidence`. Per-scenario JSON is in `final/scenarios/` and claim-level values in `final/claims.json`. Values are "adopted → sensitivity".

### 1. Evidence filtering
R kernels are rebuilt without edges whose quote fails the check: fragment-aware (`ev_fragments`) or strict (`ev_strict`). B and ATT&CK are unaffected.

**Supports:** *"Removing edges whose evidence quote fails the check leaves the frontier results and H3 intact but weakens the 14B models' reading-over-memory and likelihood results, which partly rest on unverifiable quotes."*

- **Exposure.**
  - Under the fragment-aware check, no Opus or GPT-6 Astra edge rests only on a failing quote.
  - The 14B models have 2–52% of edges resting only on failing quotes: at temperature 0, Qwen 13% and Ministral 7–31%; sampled, up to 52% (Qwen menuPass). Ministral 3B has 36–58%.
  - The strict check adds up to 6% for Opus (Sandworm).
  - Detail is in `s_evidence_shares` (edges and count units).
- **H3.** "≥ 80% of Opus's edge-F1 for three of four actors" **still holds for both 14B models**, under both checks, against Opus filtered or unfiltered, and for the same actors.
  - Qwen, fragment-aware: 104 / 56 / 88 / 101%.
  - Ministral, fragment-aware: 86 / 90 / 46 / 103%.
  - Ministral 3B under the fragment-aware check meets 80% on menuPass only (100%), so "none" becomes 1/4. Under the strict check it stays 0/4.
- **Table 2.**
  - Qwen OilRig moves above the 95th percentile (92.6 → 95.1).
  - Ministral 3B APT29 moves above chance (0.81 → 1.08).
  - Under the strict check, Opus's minimum percentile is 99.61, so "at or above the 99.7th" fails narrowly; the range becomes 1.95–5.94.
- **Table 3.**
  - R Ministral 14B OilRig loses bold: +.37 → +.24 [−.10, +.59] fragment-aware, +.20 strict.
  - R Ministral 3B APT29 loses †: −.24 → −.11 [−.26, +.06].
  - R Ministral 3B menuPass stays bold under the fragment-aware check but spans zero under the strict check ([.00, +.89]).
  - Attr. rises: Qwen 1 → 2, Qwen sampled 1 → 3 (strict 2), Ministral 3B 0 → 1.
- **Table 5.**
  - Qwen Sandworm +1.10 → +1.14 is **no longer clear** (jackknife [−0.04, +2.32]).
  - Ministral OilRig stays clear (+3.24; strict +3.40).
  - Ministral's report-level IG advantage on OilRig becomes not clear (+0.43; jackknife [−0.07, +0.93]). Its paired transition-level interval still excludes zero (+0.43 [+0.06, +0.81]).
  - Neither 14B model is negative on menuPass (Qwen +0.95, Ministral +1.01).
  - H2b: Qwen +0.4 → +0.2, Ministral −0.8 → −0.6.
  - R/B edge-count ratio: 1.2–3.3 → 1.1–2.8.
  - Opus and GPT-6 Astra: no bold or clear status changes under either check. Strict Opus values: APT29 −0.01, OilRig +1.82 (clear), Sandworm +0.97, menuPass −4.93 (leave-one-out −7.07 … −3.38).

### 2. Variant A: split at every Linux↔Windows handoff
Ground truth changes: OilRig 15 → 12 edges and L 17 → 14; Sandworm 21 → 19 edges and L 25 → 22.

**Supports:** *"Treating the plans' Linux↔Windows handoffs as boundaries leaves Claude Opus's results unchanged, makes Qwen 14B's OilRig reading gain clear, and turns GPT-6 Astra's OilRig gap negative, so the cross-model comparison on OilRig depends on how the plan's attacker-side steps are counted."*

- **Table 2.** Qwen OilRig moves above the 95th percentile (92.6 → 96.6). Ministral Sandworm moves from the 84.1th to the 87.5th percentile.
- **Table 3.**
  - Ministral 14B is above uniform on all four plans (Sandworm −.04 → +.01).
  - B Qwen OilRig becomes "below" (−.21). This status is degenerate: none of the OilRig plan's transitions is in B-Qwen's edge set, so every transition gets the same score and the interval has zero width.
  - ATT&CK Sandworm stays below (−.26).
  - New `*` marks: R Opus OilRig, ATT&CK OilRig (11 marks in total).
  - Attr.: Qwen sampled 1 → 2, Ministral sampled 2 → 3, Ministral 3B 0 → 1, B Qwen 1 → 0. Memory chains still manage at most 2.
- **Table 5.**
  - Opus OilRig: +1.86 → +1.45, still clear.
  - GPT-6 Astra OilRig: +0.34 → **−0.52**, not clear (only the jackknife excludes zero). GPT-6 Astra's report-level IG advantage on OilRig is no longer clear (+0.44, bootstrap [−0.01, +0.60]).
  - Qwen: **OilRig +2.53 becomes clear**; Sandworm +1.22 stays clear.
  - Ministral OilRig: +3.68, still clear.
  - H2b: GPT-6 Astra −1.0 → −0.8; Qwen +0.4 → +0.2.
- **H3.** Still 3/4 for both 14B models (Qwen OilRig 72%, Ministral Sandworm 51%).

### 3. Variant B: menuPass's Optional steps as separate segments
Ground truth changes: menuPass 6 → 4 edges and L 6 → 4.

**Supports:** *"The menuPass memory reversal does not depend on the plan's optional steps: without them, both frontier models' no-report priors still beat their report priors on edge-F1 and enrichment, and the likelihood difference stays unestablished."*

Your three questions, for menuPass under variant B:
- **Does no-report still beat report-conditioned on edge-F1? Yes, for both frontier models.**
  - Opus: R .308 vs B .460 (adopted .300 vs .495).
  - GPT-6 Astra: R .144 vs B .380 (adopted .181 vs .323).
- **On enrichment? Yes.**
  - Opus: R 8.28× vs B 13.60×. R − B is −5.32; bootstrap [−13.80, −0.15], jackknife [−15.80, +5.16], so **not clear** (as adopted). Leave-one-out range −8.65 … −3.01, still negative whichever report is left out.
  - GPT-6 Astra: R 3.73× vs B 13.30×. R − B is −9.58; bootstrap [−13.79, −5.91], jackknife [−13.10, −6.05], so **clear** (as adopted).
- **Does the likelihood difference remain unestablished? Yes.**
  - Opus: +0.11. Report-level [−1.56, +0.80]; paired over transitions [−0.17, +0.39].
  - GPT-6 Astra: −0.14. Report-level [−0.91, +0.13]; paired over transitions [−1.45, +0.95].
  - Both span zero under i.i.d. (GPT-6 Astra is below zero at b = 3 and b = 5, where menuPass's 4 transitions admit 2 or fewer blocks).
  - Opus's point estimate flips sign (−0.09 → +0.11).

Other stated conclusions that change under variant B:
- Opus R range: 1.99–5.78 → 1.99–8.28.
- GPT-6 Astra R range: 2.21–3.30 → 2.21–3.73, with a minimum percentile of 95.6, so "at or above the 97th" fails.
- Opus B menuPass recall: "80% of six edges" → 100% of four.
- **H3: 3/4 → 2/4 for both 14B models** (menuPass: Qwen 74%, Ministral 70%).
- Ministral 3B share range: 36–76% → 36–59%.
- Qwen and Ministral menuPass gaps: +2.37 and +1.90 (reading ahead; not clear).
- H2b: Qwen +0.4 → +1.0; Ministral −0.8 → 0.0.
- Attr.: Qwen 1 → 2.

---

## Release check
`release/` contains only `cti_manifest.csv`, which holds report IDs, URLs, publication dates and the SHA-256 of each extracted text. It is written by `scripts/release_manifest.py` from `data/cti/manifest.csv`, and it does not depend on the ground truth, the chance model, the resampling settings, or any prior.

**Under the adopted settings, nothing in `release/` needs regenerating.** The adopted reference is identical to the old ground truth, and no kernel was rebuilt.
