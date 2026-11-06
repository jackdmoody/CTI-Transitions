# docs/revision: committed copies of the AICS-27 revision deliverables

`results/` is gitignored, so these files are committed copies. The working originals live under `results/revision/`:
- `changed_conclusions.md`, `facts.md`, `gt_audit.md`;
- `tables/table{2,3,5}.tex` (= `results/revision/final/main/`).

Paths in the index below are relative to `results/revision/`.

---

# results/revision: index (AICS-27 revision, internal review)

Every file here was produced from cached priors. No model calls were made.

## Final: adopted settings
These are the files to use. Adopted settings (Jack, 2026-11-05):
- exact hypergeometric chance;
- 10,000 resamples for every bootstrap;
- Table 3 `*` from a moving-block bootstrap inside segments (b = 2, 3, 5; no wrap-around).

| Path | What |
|---|---|
| `changed_conclusions.md` | Final list of main-text changes (a) and sensitivity-only results (b), plus the release check |
| `final/main/table{2,3,5}.tex` | Drop-in LaTeX for the 04 Nov layout |
| `final/supplement/` | Supplement tables (CSV + LaTeX) |
| `final/scenarios/*.json`, `final/claims.json`, `final/case_a/`, `final/case_b/` | Numbers behind the tables. Each `config.yaml` records the git SHA, settings and seeds. |
| `facts.md`, `gt_audit.md`, `gt_audit/`, `phase0/` | Phase 0 facts and the Phase 1 ground-truth audit (settings-independent) |

Supplement tables in `final/supplement/`:
- `s_table5_all_models`: all models, including the local models' Table 5 intervals
- `s_table3_intervals_and_old_marks`: Table 3 intervals, with the old circular marks
- `s3a_enrichment_exact`
- `s3f_effective_smoothing`
- `s3g_case_b_changes`
- `s_case_a`
- `s_{ev_fragments,ev_strict,var_A,var_B}_{t2,t3,t5}`
- `s_evidence_shares`
- `s_h3_evidence`
- `sigma_crosswalk`

Scripts (branch `revision/internal-review`):
- `scripts/revision/final.py`
- `scripts/revision/case_a_final.py`
- `scripts/revision/gt_audit.py`
- `scripts/revision/phase0_tally.py`

## Superseded record: draft settings
Kept so the old values can be traced. Do not cite these.

| Path | What |
|---|---|
| `sensitivity/`, `phase3/`, `tables/` | Monte Carlo chance, 1,000 / 2,000 resamples (`sensitivity/base.json` reproduces the draft exactly), the first segment-block run, and interim sensitivities. Written at `c701c77` by `scripts/revision/{sensitivity,phase3,claims}.py`, which were removed in `ef300b5`. Check out `c701c77` to rerun them. |
| `changed_conclusions_interim_draft_settings.md` | The interim changed-conclusions list under those settings |

## Provenance of the final outputs
All commits are on branch `revision/internal-review`.

**Scoring run** (`final/scenarios/`, `final/claims.json`, `final/case_a/`):
- The code commit this run **started from is `ef300b5`**.
- Its `config.yaml` files record `ddf679e` because the script reads `HEAD` when it finishes. `ddf679e` is **docs-only** (`docs/PROGRESS.md`); its code is identical to `ef300b5`.
- A rerun from that code reproduced every output byte-for-byte.

**Later runs:**
- **Tables** (`final/main/`, `final/supplement/`): regenerated from the saved scenarios at `1b735fb` (`final.py --tables-only`; provenance in `final/config_tables.yaml`). The only change since `ef300b5` is that Table 5's ΔIG column moved from transition-level to report-level resampling, plus caption wording (`facts.md` §7.1). No scenario was rescored.
- **Case B** (`final/case_b/`, `supplement/s_case_b`): run at `294b771` (`scripts/revision/case_b_final.py`), host-cluster bootstrap 10,000.
- **Phase 0 tally and GT audit** (`phase0/`, `gt_audit/`): `c701c77`.

The committed copies are in `docs/revision/`, since `results/` is gitignored.
