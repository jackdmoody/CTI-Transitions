# Final coding pass: summary (ALL POST HOC, 2026-10-31)

Everything here was added after the paper's results were seen, at Jack's request; nothing tunes anything.
Run IDs, design choices and status changes are logged in `docs/SPEC_ISSUES.md` (2026-10-31 entries).
Tables: `results/paper_tables_v2/` (CSV + LaTeX, gitignored).

## Phase 1

### Item 6: lookups (verbatim; file:line @ commit that introduced the line)

**a. Pre-registered H2 test.** `docs/W2_EXPERIMENT_SPEC.md:21` @ `414e5a3`:
> | H2 | The report content matters, not just model memory | Report-conditioned prior vs. no-report (parametric-memory) prior | Report > no-report on transition recovery and hunting |

The metrics it refers to, `docs/W2_EXPERIMENT_SPEC.md:200` @ `414e5a3`: "- Edge precision / recall / F1 (binary edges)"; the table, `:228` @ `414e5a3`: "- **T2** Transition recovery: rows {B-F, B-S, R-F, R-S, ATTK}, cols {edge P, R, F1, JSD, hallucination rate}, one block per actor"; the test, `:215` @ `414e5a3`: "- Uncertainty: mean ± 95% bootstrap CI over seeds. Paired Wilcoxon for R vs. U, R vs. B, S vs. F."
So: the pre-registration says "Report > no-report on transition recovery", reported per model (F, S) in one block per actor, with edge P/R/F1 and JSD. It does not name raw edge-F1 as the single criterion, and it gives no rule for aggregating across actors or models. The chance-normalized comparison is post hoc (`:206` @ `0f1483d`: "The R − B comparison (H2) and H2b are recomputed on F1 ÷ chance.").

**b. Hunting go/no-go (C5).** `docs/SPEC_ISSUES.md:95` @ `a44d741`:
> - **Rule (C5):** proceed with the full OpTC hunting evaluation under v3h only if, on the 50-host OpTC fit sample, benign K ≥ 4 **and** benign tag rate ≥ 1e-4, **and** every core actor has ≥ 10 visible transitions in the WP5 gate under v3h. Otherwise the spec says "hunting = case study": the paper leads with extraction (T2, T5, H2, H2b, H3), and hunting is shown on the OTRF APT29 recording and the OpTC red team.

Thresholds: benign K ≥ 4; benign tag rate ≥ 1e-4; ≥ 10 visible transitions for every core actor.

**c. The case B mixture λ weights.** `docs/W2_EXPERIMENT_SPEC.md:187` @ `3b81f46`:
> - **P_adv** is a first-order Markov model whose transition matrix is the CTI prior projected onto K. … It is optionally mixed with P_ben, λ ∈ {0.1, 0.3, 0.5}, chosen on a validation split, never test.

and `docs/SPEC_ISSUES.md:14` @ `4419b61`: "Mixed with P_role at λ ∈ {0.1, 0.3, 0.5}, chosen on validation only."
No document or code defines the mixture's form (which component λ weights, or whether it mixes rows or probabilities). It was never implemented: case B ran with λ = 0 (`docs/W2_EXPERIMENT_SPEC.md:216`, `ctit/experiments/redteam_scoring.py:12-13`, `metrics.json` `"lambda": 0.0`). A natural reading, P_adv,λ = (1 − λ) P_adv + λ P_ben, is not written anywhere.

**d. H2b sign.** `ctit/experiments/extraction_report.py:245-246` @ `5715a18`:
> `rho = np.corrcoef(ranks([gap[x]["ratio_gap"] for x in a]), ranks([-gap[x]["attack_references"] for x in a]))[0, 1]`
> `gap["_spearman_ratio_gap_vs_fewer_references"] = float(rho)`

The reported ρ is against the reference count reversed (rank of fewer references, i.e. coverage shrinking). Positive ρ = gap grows as coverage shrinks = the direction H2b predicts (`docs/W2_EXPERIMENT_SPEC.md:24` @ `414e5a3`: "Gap increases as coverage decreases"). The paper's −0.4 (F), +0.4 (Q), −0.8 (M) are this sign; against the reference count itself they are +0.4, −0.4, +0.8.

### Item 1: reading vs remembering, report-level bootstrap (2,000; R − B, 95% percentile intervals)

B held fixed for Q, M, M3 (single temperature-0 calls); F, Q5, M5 resample samples too. F1/chance undefined for M3 (empty B edge sets).

| Model | Actor | R − B, F1/chance | | R − B, IG bits | |
|---|---|---|---|---|---|
| F | APT29 | +0.03 [-0.86, +0.47] | spans | +0.06 [-0.28, +0.11] | spans |
| F | menuPass | -5.23 [-10.84, -1.56] | below | -0.09 [-1.21, +0.37] | spans |
| F | OilRig | +1.87 [+1.33, +2.95] | above | +0.61 [+0.07, +0.69] | above |
| F | Sandworm | +0.80 [-0.10, +1.84] | spans | +0.33 [-0.11, +0.46] | spans |
| M | APT29 | +0.95 [-0.28, +1.51] | spans | +0.17 [-0.18, +0.22] | spans |
| M | menuPass | -0.08 [-2.33, +5.29] | spans | +0.72 [-0.12, +0.96] | spans |
| M | OilRig | +3.30 [+2.84, +3.88] | above | +0.56 [+0.14, +0.64] | above |
| M | Sandworm | +0.40 [+0.11, +3.00] | above | -0.03 [-0.14, +0.05] | spans |
| M3 | APT29 | — [—, —] | — | -0.24 [-0.44, -0.08] | below |
| M3 | menuPass | — [—, —] | — | +0.89 [+0.06, +1.19] | above |
| M3 | OilRig | — [—, —] | — | +0.08 [-0.35, +0.20] | spans |
| M3 | Sandworm | — [—, —] | — | +0.01 [-0.13, +0.08] | spans |
| M5 | APT29 | -0.08 [-1.06, +0.55] | spans | +0.12 [-0.17, +0.18] | spans |
| M5 | menuPass | -0.62 [-3.07, +4.20] | spans | +0.64 [-0.24, +1.09] | spans |
| M5 | OilRig | +1.99 [+1.39, +3.08] | above | +0.26 [-0.09, +0.41] | spans |
| M5 | Sandworm | +1.04 [-0.16, +2.04] | spans | +0.07 [-0.14, +0.14] | spans |
| Q | APT29 | -0.17 [-1.03, +0.38] | spans | +0.02 [-0.30, +0.09] | spans |
| Q | menuPass | +0.16 [-1.36, +1.12] | spans | +0.68 [-0.16, +1.07] | spans |
| Q | OilRig | +1.09 [+0.00, +1.75] | spans | -0.06 [-0.31, +0.08] | spans |
| Q | Sandworm | +1.10 [+0.11, +1.31] | above | +0.25 [-0.05, +0.25] | spans |
| Q5 | APT29 | -0.15 [-0.94, +0.70] | spans | +0.00 [-0.34, +0.10] | spans |
| Q5 | menuPass | -0.61 [-3.17, +5.71] | spans | +0.51 [-0.27, +0.85] | spans |
| Q5 | OilRig | +1.23 [-0.49, +2.14] | spans | -0.10 [-0.43, +0.22] | spans |
| Q5 | Sandworm | +0.50 [-0.37, +1.12] | spans | +0.06 [-0.19, +0.14] | spans |

H2b (F1/chance gap vs coverage; positive ρ against fewer references = H2b's direction): F -0.40; M -0.80; M3 —; M5 -0.40; Q +0.40; Q5 -0.40

### Item 2: own-plan IG, i.i.d. vs circular block bootstrap (α = 0.5); cells whose status changes

| Prior | Actor | bits | i.i.d. | b = 2 | b = 3 | b = 5 |
|---|---|---|---|---|---|---|
| ATTK | APT29 | -0.61 | [-1.26, -0.00] below | [-1.26, +0.02] spans | [-1.35, +0.06] spans | [-1.35, +0.09] spans |
| B-M | menuPass | +0.32 | [-0.21, +0.85] spans | [-0.21, +0.59] spans | [-0.21, +0.85] spans | [+0.06, +0.59] above |
| B-Q | menuPass | +0.32 | [-0.21, +0.85] spans | [-0.21, +0.59] spans | [+0.32, +0.32] above | [+0.06, +0.59] above |
| R-Q5 | OilRig | -0.21 | [-0.43, +0.02] spans | [-0.40, -0.00] below | [-0.38, +0.01] spans | [-0.37, -0.04] below |

No other cell of Table 5 changes status. menuPass has 6 transitions, so its b ≥ 3 intervals are near-degenerate.

### Item 4: case A (executed OTRF APT29, 37 transitions, 22 edges): IG bits [95% i.i.d.]; F1/chance (percentile)

| Prior | APT29 | menuPass | OilRig | Sandworm |
|---|---|---|---|---|
| ATTK | +0.76 [+0.50, +0.98]; 1.38 (100) | +0.33 [+0.04, +0.63]; 1.66 (100) | +0.46 [+0.26, +0.64]; 1.38 (100) | +0.09 [-0.12, +0.29]; 1.00 (50) |
| B-F | -0.05 [-0.19, +0.10]; 1.42 (73) | +0.05 [-0.08, +0.18]; 1.25 (73) | +0.05 [-0.10, +0.22]; 1.60 (80) | -0.10 [-0.19, +0.02]; 0.96 (50) |
| B-M | +0.01 [-0.12, +0.16]; 1.39 (84) | -0.05 [-0.18, +0.09]; 1.39 (84) | +0.01 [-0.12, +0.16]; 1.39 (84) | +0.01 [-0.16, +0.18]; 1.93 (80) |
| B-Q | +0.01 [-0.16, +0.18]; 2.09 (84) | +0.01 [-0.16, +0.18]; 1.93 (80) | +0.01 [-0.16, +0.18]; 1.93 (80) | +0.01 [-0.16, +0.18]; 1.93 (80) |
| R-F | -0.12 [-0.33, +0.10]; 1.45 (85) | -0.10 [-0.32, +0.15]; 1.52 (79) | -0.10 [-0.38, +0.17]; 1.45 (86) | -0.43 [-0.63, -0.23]; 0.81 (33) |
| R-M | -0.23 [-0.47, +0.04]; 1.04 (55) | -0.08 [-0.31, +0.14]; 1.39 (77) | -0.20 [-0.40, +0.02]; 0.76 (31) | -0.20 [-0.33, -0.07]; 0.56 (29) |
| R-M3 | -0.22 [-0.38, -0.06]; 0.78 (33) | -0.03 [-0.23, +0.18]; 1.15 (64) | -0.14 [-0.37, +0.11]; 0.98 (50) | +0.08 [-0.08, +0.25]; 1.57 (80) |
| R-M5 | -0.06 [-0.27, +0.15]; 1.42 (84) | -0.01 [-0.21, +0.19]; 1.61 (82) | -0.25 [-0.42, -0.06]; 0.87 (40) | -0.18 [-0.31, -0.03]; 0.64 (31) |
| R-Q | -0.06 [-0.32, +0.22]; 1.71 (94) | -0.13 [-0.35, +0.08]; 1.35 (70) | -0.10 [-0.36, +0.19]; 1.39 (77) | -0.01 [-0.23, +0.19]; 1.57 (89) |
| R-Q5 | -0.05 [-0.28, +0.18]; 1.90 (96) | -0.13 [-0.33, +0.07]; 1.42 (75) | -0.08 [-0.29, +0.16]; 1.75 (90) | -0.11 [-0.27, +0.05]; 1.37 (76) |
| Uni | +0.00 [+0.00, +0.00]; — | +0.00 [+0.00, +0.00]; — | +0.00 [+0.00, +0.00]; — | +0.00 [+0.00, +0.00]; — |

### Item 5: case B collapsed, AUPRC [95% host-cluster]

(i) five xx01/xx51 hosts dropped: 402 windows, 29 positive. (ii) scripted job's two rules removed: 499 windows, 45 positive.

| Condition | (i) hosts dropped | (ii) rules removed |
|---|---|---|
| ATTK/APT29 | 0.609 [0.47, 0.75] | 0.277 [0.13, 0.40] |
| ATTK/OilRig | 0.609 [0.47, 0.75] | 0.212 [0.10, 0.32] |
| ATTK/Sandworm | 0.188 [0.08, 0.32] | 0.212 [0.10, 0.32] |
| ATTK/menuPass | 0.609 [0.47, 0.75] | 0.212 [0.10, 0.32] |
| R-F/APT29 | 0.469 [0.38, 0.56] | 0.150 [0.08, 0.22] |
| R-F/OilRig | 0.680 [0.56, 0.82] | 0.159 [0.08, 0.24] |
| R-F/Sandworm | 0.680 [0.56, 0.82] | 0.146 [0.07, 0.23] |
| R-F/menuPass | 0.384 [0.29, 0.48] | 0.186 [0.09, 0.29] |
| R-M/APT29 | 0.187 [0.08, 0.32] | 0.190 [0.10, 0.31] |
| R-M/OilRig | 0.187 [0.08, 0.32] | 0.124 [0.06, 0.21] |
| R-M/Sandworm | 0.187 [0.08, 0.32] | 0.146 [0.07, 0.23] |
| R-M/menuPass | 0.153 [0.05, 0.27] | 0.124 [0.06, 0.21] |
| R-M3/APT29 | 0.187 [0.08, 0.32] | 0.124 [0.06, 0.21] |
| R-M3/OilRig | 0.153 [0.05, 0.27] | 0.124 [0.06, 0.21] |
| R-M3/Sandworm | 0.188 [0.08, 0.32] | 0.146 [0.07, 0.23] |
| R-M3/menuPass | 0.187 [0.08, 0.32] | 0.124 [0.06, 0.21] |
| R-M5/APT29 | 0.187 [0.08, 0.32] | 0.137 [0.07, 0.23] |
| R-M5/OilRig | 0.153 [0.05, 0.27] | 0.128 [0.06, 0.21] |
| R-M5/Sandworm | 0.187 [0.08, 0.32] | 0.137 [0.07, 0.22] |
| R-M5/menuPass | 0.164 [0.06, 0.28] | 0.128 [0.06, 0.21] |
| R-Q/APT29 | 0.187 [0.08, 0.32] | 0.146 [0.07, 0.23] |
| R-Q/OilRig | 0.187 [0.08, 0.32] | 0.124 [0.06, 0.21] |
| R-Q/Sandworm | 0.153 [0.05, 0.27] | 0.146 [0.07, 0.23] |
| R-Q/menuPass | 0.153 [0.05, 0.27] | 0.124 [0.06, 0.21] |
| R-Q5/APT29 | 0.153 [0.06, 0.27] | 0.124 [0.06, 0.21] |
| R-Q5/OilRig | 0.160 [0.06, 0.27] | 0.124 [0.06, 0.21] |
| R-Q5/Sandworm | 0.164 [0.06, 0.28] | 0.124 [0.06, 0.21] |
| R-Q5/menuPass | 0.164 [0.06, 0.28] | 0.128 [0.06, 0.21] |
| U | 0.656 [0.53, 0.81] | 0.662 [0.55, 0.80] |
| Uni | 0.187 [0.08, 0.32] | 0.146 [0.07, 0.23] |
| oracle-M | 0.187 [0.08, 0.32] | 0.146 [0.07, 0.23] |
| oracle-M5 | 0.187 [0.08, 0.32] | 0.146 [0.07, 0.23] |
| oracle-Q | 0.187 [0.08, 0.32] | 0.146 [0.07, 0.23] |
| oracle-Q5 | 0.187 [0.08, 0.32] | 0.146 [0.07, 0.23] |

Oracle F: refused 5/5, no row. M3 has no oracle run.

### Item 7: number audit (`paper/number_audit.csv`, `scripts/number_audit.py`)
396 rows: 384 match, 3 rounding, 7 mismatch, 1 no source, 1 n/a (supplement S3 is not in the repo). Mismatches:
1. Table 2, ATTK/APT29 edge-F1 `.237`: source 38/160 = 0.2375, prints .238.
2. Table 2, B-Q/menuPass edge-F1 `.210`: source 4/19 = 0.2105, prints .211.
3. H2b "+0.4 for Qwen": `extraction_report` key is +0.2 (per-sample hypergeometric chance draws swap Qwen's OilRig/Sandworm gaps); recomputed from Table 2/3's shared-draw ratios it is +0.4. F −0.4 and M −0.8 match both.
4. "up to 123 transitions from one chunk": the saved priors and the response cache top out at 115 (menuPass-P06 chunk 1); 123 appears only in `docs/SPEC_ISSUES.md:210`.
5. "fabricated-evidence rate .07–.30 by actor for Qwen": Qwen's top is .2949 → .29 (the abstract's 7–30% still holds via Ministral .2985).
6. Table 5, R-M3/Sandworm `+.02`: source 0.0145 → +.01 (double rounding of the CSV's 0.0145).
7. "27, 3, 3, and 1 visible transitions per actor" (†): the gate gives APT29 27, OilRig 3, Sandworm 1, menuPass 3; a mismatch only if the paper's usual actor order is meant.
Rounding (difference of rounded ratios vs rounded exact difference), Table 3 F row: APT29 +0.04 (exact +0.03), OilRig +1.86 (+1.87), Sandworm +0.81 (+0.80).
No source: "one report covers core APT10 and four cover the MirrorFace/Earth Kasha subgroup" (no subgroup field anywhere; only the count of 5 checks).
Approximate matches worth a look: case A R-F APT29 1.4464 vs OilRig 1.4447 ("no better than"); "41–57 s" holds for first-call runs only; "19 of 24" counts empty-list replies (22 of 24 priors are empty).
