# CTI-Transitions

Code for *Can LLMs Compile Cyber Threat Intelligence into Adversary Behavior Models? Evaluating Predictive Value and Quotation Fidelity*
(Jack Moody and Iain Cruickshank; submitted to AICS @ AAAI-27).

A language model reads cyber threat intelligence (CTI) reports on an actor and extracts the ATT&CK tactic
transitions they describe; counting each report once per transition and smoothing (Eq. 1 of the paper) gives
the actor's *report-supported predictive kernel*, a first-order Markov chain over the 14 ATT&CK tactics.
We compare report-conditioned kernels (**R**, from 23 reports on four actors) with no-report kernels (**B**,
actor name and aliases only), a kernel built from the actor's ATT&CK technique counts (**ATTK**) and the
uniform chain (**Uni**), across Claude Opus 5.5, GPT-6 Astra, Qwen3 14B and Ministral 3 14B and 3B. Each
kernel is scored against four public emulation plans (APT29, OilRig, Sandworm, menuPass) by edge-F1 relative
to size-matched chance and by information gain over the uniform chain, and two case studies score kernels on a
recorded APT29 emulation (OTRF) and the DARPA OpTC red-team execution. W2 is the project's internal name; it
appears in file names, configs and commit messages.

Terminology: code, configs and run names written before the paper's final wording say *prior* for a kernel
(`data/priors/`, `configs/v2_priors.yaml`) and *memory* for the no-report condition B (`prompts/memory_v1.txt`).
The docs are indexed in [`docs/README.md`](docs/README.md).

## Paper materials

- Supplement (all supplementary tables): [`paper/w2_aics_supplement.pdf`](paper/w2_aics_supplement.pdf),
  source [`paper/w2_aics_supplement.tex`](paper/w2_aics_supplement.tex).
- Prompts, frozen before the first full extraction run: [`prompts/extract_v1.txt`](prompts/extract_v1.txt)
  (report-conditioned extraction, R) and [`prompts/memory_v1.txt`](prompts/memory_v1.txt) (no-report baseline, B).
- Figure 1 source: [`paper/fig_method.tex`](paper/fig_method.tex) (standalone TikZ; `pdflatex` builds
  `paper/fig_method.pdf`) and the editable [`paper/fig_method.pptx`](paper/fig_method.pptx).
- Paper source: [`paper/w2_aics_submission.tex`](paper/w2_aics_submission.tex), with Tables 2, 3 and 5 inlined
  from [`paper/tables/`](paper/tables/). It compiles with the AAAI-27 author kit's `aaai2027.sty`/`aaai2027.bst`
  (not redistributed here).
- Scripts that rebuild the tables (no model calls; they read the saved model outputs under `data/priors/` and
  earlier runs under `results/`, so extraction must be run first; see below):
  - [`scripts/revision/final.py`](scripts/revision/final.py): Tables 2, 3 and 5 and every supplementary
    table, under the adopted settings (exact chance, 10,000 resamples, seed 20261105);
  - [`scripts/revision/case_a_final.py`](scripts/revision/case_a_final.py) and
    [`scripts/revision/case_b_final.py`](scripts/revision/case_b_final.py): the two case studies;
  - [`scripts/revision/make_supplement.py`](scripts/revision/make_supplement.py): assembles the supplement;
  - [`scripts/revision/claims_check.py`](scripts/revision/claims_check.py): checks every number in the paper
    against its source.

## Where each result comes from

Run IDs below are the ones the paper's numbers come from; outputs under `results/` and `data/` are local only.
`scripts/revision/claims_check.py` checks every number in the paper against these sources and names the source of
each in `results/revision/final/claims_check.csv`.

| Paper item | Produced by | Output |
|---|---|---|
| Table 1: actors, plan steps, ground-truth edges | Typed into the paper. Steps: `scripts/revision/gt_audit.py` (plans via `ctit/eval/plans.py`); GT edges: `scripts/revision/final.py` (`ctit/eval/reference.py`) | `results/revision/gt_audit/metrics.json`; `results/revision/final/claims.json` (`GT edges`) |
| Figure 1: study design | `paper/fig_method.tex` (standalone TikZ, `pdflatex`); schematic, no data | `paper/fig_method.pdf` (editable: `paper/fig_method.pptx`) |
| Table 2: support recovery (edge-F1, F1 ÷ chance) | `scripts/revision/final.py` | `results/revision/final/main/table2.tex` → `paper/tables/table2.tex` |
| Table 3: predictive fit (information gain) and attribution | `scripts/revision/final.py` | `results/revision/final/main/table3.tex` → `paper/tables/table3.tex` |
| Table 4: specificity (Claude Opus kernels × plans) | `configs/extraction_report.yaml` (run `20261031T172438Z-extraction_report-16049f4`, `h4`), packaged by `configs/paper_tables_v2.yaml`; typed into the paper; not recomputed by the revision | `results/paper_tables_v2/t4_h4_f1_matrix.csv` (rows `R-F`) |
| Table 5: R − B (ΔF1, Δenrichment, ΔIG) | `scripts/revision/final.py` | `results/revision/final/main/table5.tex` → `paper/tables/table5.tex` |
| Case study A: recorded APT29 emulation (OTRF) | `scripts/revision/case_a_final.py` (executed sequence from `ctit/experiments/otrf_case.py`) | `results/revision/final/case_a/metrics.json` |
| Case study B: OpTC red team | `configs/redteam_testset.yaml`, then `scripts/revision/case_b_final.py` (reruns the three saved case-B runs at 10,000 resamples); scripted-job diagnosis from `configs/redteam_diagnosis_S.yaml` (run `20261028T044917Z-redteam_diagnosis-ce77e76`) | `results/revision/final/case_b/{as_run,collapsed,scripted}/metrics.json` |
| Quote-match failure rates, schema failures | `configs/paper_tables_v2.yaml`; `scripts/revision/phase0_tally.py` | `results/paper_tables_v2/t_fabricated_evidence.csv`; `results/revision/phase0/metrics.json` |
| Supplement (Tables S1–S22) | `scripts/revision/final.py`, `case_a_final.py`, `case_b_final.py` write the tables; `scripts/revision/make_supplement.py` assembles them; `pdflatex` | `results/revision/final/supplement/*.tex` → `paper/w2_aics_supplement.tex` → `paper/w2_aics_supplement.pdf` |

## What is and isn't public

- **In git:** code, configs, the frozen prompts, tests, the paper and supplement sources, the supplement PDF, and
  [`release/cti_manifest.csv`](release/cti_manifest.csv).
- **Not in git:** `data/` (reports, emulation plans, ATT&CK, telemetry, and the saved model outputs under
  `data/priors/`), `results/` (every run's `config.yaml`, `metrics.json` and `calls.jsonl`) and `audit/`.
- **Model outputs are not redistributed.** Every extracted transition carries a verbatim evidence quotation from
  its report, so the outputs contain report text that belongs to the reports' publishers.
- **The corpus can be rebuilt.** `release/cti_manifest.csv` gives each report's URL, publication date and the
  SHA-256 of its extracted text, so the same text can be re-fetched and checked (see Data below).
- **Rebuilding the tables requires re-running extraction first.** That needs API keys for Claude Opus 5.5 and
  GPT-6 Astra (`ANTHROPIC_API_KEY`, `OPENAI_API_KEY` in `.env`) and a local Ollama with the pinned open-weight
  models. The API models are sampled (five runs each), so a fresh extraction need not reproduce the paper's
  numbers exactly. The case studies also need the public OTRF and OpTC data.

## Setup from a clean checkout

```bash
git clone --recurse-submodules https://github.com/jackdmoody/CTI-Transitions
cd CTI-Transitions
conda create -n w2 python=3.12
conda activate w2
pip install -r third_party/DRIFT/requirements.txt
pip install -e ".[dev,fetch,attack]"
cp .env.example .env        # then fill in the API keys (never commit .env)
pytest -q
```

`third_party/DRIFT` is pinned at tag `brims-2026` (`3517424`) and `third_party/sigma` at SigmaHQ
release `r2026-07-01`. `ctit/adapters/drift.py` refuses to run on any other DRIFT commit. Do not run
DRIFT's `setup_env.py` in this environment.

## Data (all gitignored, under `data/`)

| Input | Source | How |
|---|---|---|
| CTI reports (23 used for kernels + 1 excluded) | URLs in `release/cti_manifest.csv` | copy it to `data/cti/manifest.csv` (columns as `ctit/cti/manifest.py`), then `python scripts/fetch_cti.py`; the SHA-256 of each extracted text must match the manifest (`python scripts/release_manifest.py` checks) |
| Emulation plans | CTID Adversary Emulation Library `4467a6e` (menuPass, OilRig, Sandworm); ATT&CK Evaluations `ael` `5594518` (APT29) | clone at those commits under `data/eval/plans/` (`ctit/eval/plans.py`) |
| ATT&CK v18.1 | MITRE CTI STIX bundle | `ctit/map/attack.py` |
| OTRF APT29 (case A) | OTRF Security Datasets, APT29 day 1 and day 2 | `ctit/ingest/otrf.py` |
| DARPA OpTC (case B) | OpTC eCAR, Inria corrected labels (commit `644f41f`), `OpTCRedTeamGroundTruth.pdf` (FiveDirections/OpTC-data `b2673729`) | `scripts/fetch_optc_redteam.py`, `scripts/convert_optc_redteam.py`, `ctit/ingest/optc.py`; benign days are read from an eCAR-to-Sysmon conversion at `CTIT_OPTC_ROOT` |

Open-weight models run in Ollama 0.40.10 with the digests and Modelfiles pinned in
`configs/models.yaml` and `configs/modelfiles/`.

Qwen3 14B, as used in the paper: run `20261027T223928Z-extraction-a686409`, made with `configs/extraction_S.yaml`
at commit `a686409`, when slot `S` was Qwen (slot `S` is now Ministral 3 14B; the same pin is kept as slot
`S_qwen3_14b`). Ollama tag `qwen3:14b`, `ollama_id` `bdbd181c33f2`, weights sha256
`a8cc1361f3145dc01f6d77c6c82c9116b9ffe3c97b34716fe20418455876c40e` (14.8B, Q4_K_M), `think: false`, `num_ctx`
16384. Q (temperature 0): options `{temperature: 0, num_ctx: 16384}`. Q5 (five samples): options `{num_ctx: 16384}`
with seeds 0–4 and the digest's default sampling (temperature 0.6, top_k 20, top_p 0.95, repeat_penalty 1). To
rerun it, check out `a686409` (or point slot `S` at the `S_qwen3_14b` values) and run `configs/extraction_S.yaml`.

## Reproducing the results

Every `ctit.run` command writes `results/<UTC timestamp>-<experiment>-<git sha>/{config.yaml, metrics.json, calls.jsonl}`
and refuses to run on a dirty tree. The run IDs behind the paper are in `results/paper_tables*/README.md`
and `docs/PROGRESS.md`; each run's `config.yaml` can be passed back to `--config`.

There are two stages. The `ctit.run` commands below extract the kernels and produced the **pre-revision** tables
(31 Oct draft: Monte Carlo chance, 1,000 / 2,000 resamples), packaged in `results/paper_tables_v2/`. The
**final** tables come from `scripts/revision/` (adopted settings, 2026-11-05: exact chance, 10,000 resamples),
which rescore the same saved kernels without model calls. Table 4, the quote-match failure rates and the
refusal counts were not recomputed and come from the pre-revision runs. Table numbers in the comments are the
final paper's.

Extraction and pre-revision analyses:

```bash
python scripts/check_leakage.py                                   # must pass before extraction
python -m ctit.run --config configs/extraction_F.yaml             # Claude Opus 5.5 extraction (API)
python -m ctit.run --config configs/extraction_S.yaml             # 14B open-weight extraction (local Ollama; model slots in configs/models.yaml)
python -m ctit.run --config configs/extraction_S3B.yaml           # Ministral 3 3B extraction (local Ollama)
python -m ctit.run --config configs/extraction_report.yaml        # Table 4; quote-match check, refusals; pre-revision Tables 2 and 5
python -m ctit.run --config configs/prior_likelihood.yaml         # pre-revision Table 3 (IG, attribution); case A IG
python -m ctit.run --config configs/otrf_case.yaml                # case study A (pre-revision)
python -m ctit.run --config configs/redteam_testset.yaml          # case study B test set
python -m ctit.run --config configs/redteam_scoring.yaml          # case B as run
python -m ctit.run --config configs/redteam_scoring_collapsed.yaml  # case B collapsed (post hoc)
python -m ctit.run --config configs/redteam_diagnosis_S.yaml      # case B diagnosis (post hoc)
python -m ctit.run --config configs/paper_tables.yaml             # pre-revision tables as CSV (results/paper_tables/)
```

Post hoc v2 analyses (2026-10-31); their model list is `configs/v2_priors.yaml`:

```bash
python -m ctit.run --config configs/extraction_G.yaml        # GPT-6 Astra extraction (API)
python -m ctit.run --config configs/reading_bootstrap.yaml   # pre-revision Table 5: R - B with report-level bootstrap
python -m ctit.run --config configs/ig_dependence.yaml       # pre-revision Table 3: block-bootstrap IG intervals
python -m ctit.run --config configs/case_a_v2.yaml           # case A, every kernel
python -m ctit.run --config configs/case_b_scripted.yaml     # case B, scripted job removed
python -m ctit.run --config configs/evidence_audit.yaml      # audit sample (writes audit/, gitignored)
python -m ctit.run --config configs/paper_tables_v2.yaml     # results/paper_tables_v2 (CSV + LaTeX), incl. Table 4
```

Final tables (revision; no model calls):

```bash
python scripts/revision/gt_audit.py        # plan steps and ground-truth edges (Table 1)
python scripts/revision/phase0_tally.py    # schema-failure and evidence-check tallies
python scripts/revision/final.py           # Tables 2, 3, 5 and the supplement tables -> results/revision/final/
python scripts/revision/case_a_final.py    # case study A
python scripts/revision/case_b_final.py    # case study B
cp results/revision/final/main/table{2,3,5}.tex paper/tables/
python scripts/revision/make_supplement.py # paper/w2_aics_supplement.tex
python scripts/revision/claims_check.py    # every number in the paper against its source
```

`final.py` does not need the pre-revision record `results/revision/sensitivity/base.json` (written at `c701c77` by
scripts since removed). The supplement's "old" circular block marks come from the `configs/ig_dependence.yaml`
run, and the case-B "draft" intervals from `case_b_final.py`.

Run-specific inputs (the extraction run IDs each analysis reads) are set in the configs; after a
fresh extraction, point them at the new run IDs.
