# CTI-Transitions (W2)

Code for *Beyond CTI Reporting: Evaluating LLM-Compiled Threat Intelligence as Adversary Behavior Models*
(AICS @ AAAI-27). A language model compiles threat-intelligence reports into ATT&CK tactic-transition
priors (Markov chains, Eq. 1 of the paper), which are scored against MITRE emulation-plan ground truth
and in two case studies on public telemetry. The authoritative plan is `docs/W2_EXPERIMENT_SPEC.md`;
every deviation and post hoc analysis is logged in `docs/SPEC_ISSUES.md`.

Repository: https://github.com/jackdmoody/CTI-Transitions

Only public data is used. Nothing under `data/`, `results/` or `audit/` is in git: telemetry, report
text and model outputs are regenerated locally from the pinned sources below.

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
- Scripts that rebuild the tables (no model calls; they read the cached extractions under `results/`):
  - [`scripts/revision/final.py`](scripts/revision/final.py): Tables 2, 3 and 5 and every supplementary
    table, under the adopted settings (exact chance, 10,000 resamples, seed 20261105);
  - [`scripts/revision/case_a_final.py`](scripts/revision/case_a_final.py) and
    [`scripts/revision/case_b_final.py`](scripts/revision/case_b_final.py): the two case studies;
  - [`scripts/revision/make_supplement.py`](scripts/revision/make_supplement.py): assembles the supplement;
  - [`scripts/revision/claims_check.py`](scripts/revision/claims_check.py): checks every number in the paper
    against its source.

## Setup from a clean checkout

```bash
git clone --recurse-submodules <repository URL>
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
| CTI reports (23 prior + 1 excluded) | URLs in `release/cti_manifest.csv` | copy it to `data/cti/manifest.csv` (columns as `ctit/cti/manifest.py`), then `python scripts/fetch_cti.py`; the SHA-256 of each extracted text must match the manifest (`python scripts/release_manifest.py` checks) |
| Emulation plans | CTID Adversary Emulation Library `4467a6e` (menuPass, OilRig, Sandworm); ATT&CK Evaluations `ael` `5594518` (APT29) | clone at those commits under `data/eval/plans/` (`ctit/eval/plans.py`) |
| ATT&CK v18.1 | MITRE CTI STIX bundle | `ctit/map/attack.py` |
| OTRF APT29 (case A) | OTRF Security Datasets, APT29 day 1 and day 2 | `ctit/ingest/otrf.py` |
| DARPA OpTC (case B) | OpTC eCAR, Inria corrected labels (commit `644f41f`), `OpTCRedTeamGroundTruth.pdf` (FiveDirections/OpTC-data `b2673729`) | `scripts/fetch_optc_redteam.py`, `scripts/convert_optc_redteam.py`, `ctit/ingest/optc.py`; benign days are read from an eCAR-to-Sysmon conversion at `CTIT_OPTC_ROOT` |

Open-weight models run in Ollama 0.40.10 with the digests and Modelfiles pinned in
`configs/models.yaml` and `configs/modelfiles/`.

## Reproducing the results

Every command writes `results/<UTC timestamp>-<experiment>-<git sha>/{config.yaml, metrics.json, calls.jsonl}`
and refuses to run on a dirty tree. The run IDs behind the paper are in `results/paper_tables*/README.md`
and `docs/PROGRESS.md`; each run's `config.yaml` can be passed back to `--config`.

```bash
python scripts/check_leakage.py                                   # must pass before extraction
python -m ctit.run --config configs/extraction_F.yaml             # frontier extraction (API)
python -m ctit.run --config configs/extraction_S.yaml             # open-weight extraction (local Ollama)
python -m ctit.run --config configs/extraction_report.yaml        # Tables 2-4, evidence check, refusals
python -m ctit.run --config configs/prior_likelihood.yaml         # Table 5, attribution, case A IG
python -m ctit.run --config configs/otrf_case.yaml                # case study A
python -m ctit.run --config configs/redteam_testset.yaml          # case study B test set
python -m ctit.run --config configs/redteam_scoring.yaml          # case B as run
python -m ctit.run --config configs/redteam_scoring_collapsed.yaml  # case B collapsed (post hoc)
python -m ctit.run --config configs/redteam_diagnosis_S.yaml      # case B diagnosis (post hoc)
python -m ctit.run --config configs/paper_tables.yaml             # paper tables (CSV)
```

Post hoc v2 analyses (2026-10-31); their model list is `configs/v2_priors.yaml`:

```bash
python -m ctit.run --config configs/reading_bootstrap.yaml   # R - B with report-level bootstrap
python -m ctit.run --config configs/ig_dependence.yaml       # block-bootstrap IG intervals
python -m ctit.run --config configs/case_a_v2.yaml           # case A, every prior
python -m ctit.run --config configs/case_b_scripted.yaml     # case B, scripted job removed
python -m ctit.run --config configs/evidence_audit.yaml      # audit sample (writes audit/, gitignored)
python -m ctit.run --config configs/paper_tables_v2.yaml     # results/paper_tables_v2 (CSV + LaTeX)
```

Run-specific inputs (the extraction run IDs each analysis reads) are set in the configs; after a
fresh extraction, point them at the new run IDs.
