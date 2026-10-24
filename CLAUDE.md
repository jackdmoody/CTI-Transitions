# CLAUDE.md — CTI-Transitions (W2: CTI-Conditioned Transition Hunting)

## What this repo is
A standalone repo for the W2 paper for AICS @ AAAI-27 (deadline 20 Nov 2026). An LLM compiles threat-intelligence
reports into ATT&CK tactic-transition priors, which condition DRIFT-style hunting on endpoint (and Zeek) telemetry.
The authoritative plan is `docs/W2_EXPERIMENT_SPEC.md`. Read it before any task.

DRIFT (github.com/jackdmoody/DRIFT, SBP-BRiMS 2026) is a **pinned, read-only dependency**, not this repo.
- Depend on the tagged BRiMS commit via `pyproject.toml`. Never vendor or copy DRIFT source into this repo.
- All DRIFT imports go through `ctit/adapters/drift.py`. No other module imports `drift` directly.
- Never edit DRIFT. If DRIFT behavior needs to change, wrap or subclass it in the adapter and log why in `docs/SPEC_ISSUES.md`.
- `tests/test_drift_parity.py` must keep reproducing the BRiMS baseline number through the adapter.

## Hard rules
1. **The spec is fixed.** Do not change hypotheses (H1–H4, H2b), conditions, metrics, or table definitions. If something in the spec is wrong or infeasible, stop and write the issue to `docs/SPEC_ISSUES.md` with a proposed fix. Don't work around it silently.
2. **Never commit data.** Range telemetry, Zeek logs, OTRF and ATLASv2 data, CTI report text, model outputs over range data, and anything under `data/` stay out of git. Check `.gitignore` before every commit. If a file under `data/` is staged, unstage it and tell me.
3. **No range data leaves this machine.** Do not send range telemetry or derived per-host sequences to any external API. Only CTI report text and prompts go to the frontier model API.
4. **Leakage rule.** Prior sources and eval sources are disjoint per actor (spec §1). `scripts/check_leakage.py` must pass before any extraction or scoring run. Never build eval sequences from ATT&CK group mappings.
5. **Tune on validation only.** The test split is touched once per final run. Any hyperparameter chosen by looking at test results is a bug.
6. **Don't inflate visibility.** Never mark an emulation step `visible=y` without a concrete Sysmon event or Zeek log that the step's procedure produces. When unsure, mark `partial` and explain in `rationale`.

## Human gates — stop and ask Jack before proceeding past these
- APT29 visibility CSV (`data/eval/visibility_apt29.csv`) — sign-off before porting to other actors
- `drift/map/zeek_rules.yaml` — review before any Zeek-derived results
- DPRK eval-sequence path (plan vs. report-split) — decision by 22 Oct
- Hand-converted report-split eval sequences (if used)
- Any change to `prompts/*.txt` after the first full extraction run

When you hit a gate, write what you need reviewed and why to `docs/REVIEW_QUEUE.md`, then stop.

## How to work
- Work one work package (WP) per session. At the start, restate which spec section you're implementing and the acceptance check.
- Before writing code, read the DRIFT source you'll call (installed package) and reuse it through the adapter, especially preprocessing, the tactic mapper, and role baselines. Don't reimplement working BRiMS code.
- Write tests for each new module under `tests/`. A WP isn't done until its acceptance check passes and the tests pass.
- Commit at the end of each WP on `main` (or a WP branch), with message `W2/<WP>: <what>`. Small, reviewable commits. Never commit to the DRIFT repo.
- Every experiment run writes `results/<run_id>/{config.yaml, metrics.json, calls.jsonl}` with git SHA, model versions, and seeds. No result exists unless it is reproducible from its config.
- Log every LLM call (model, prompt hash, tokens, latency, cost) to `calls.jsonl`.
- Update `docs/PROGRESS.md` at the end of each session: what was done, what passed, what's next, any open issues. Keep it short.

## Environment
- Python version, package manager, and install command: <fill in>
- Frontier model API key: env var <fill in>. Pin the model version string in `configs/`.
- Open-weight model: served locally via <Ollama | vLLM | llama.cpp — fill in>. Record the weights hash.
- Data roots: `data/range/` (Sysmon), `data/zeek/`, `data/otrf/`, `data/atlasv2/`, `data/cti/`. All gitignored.

## Commands
- Tests: <fill in, e.g. `pytest -q`>
- Leakage check: `python scripts/check_leakage.py`
- DRIFT parity: `pytest tests/test_drift_parity.py`
- Public-data run: `python -m ctit.run --config configs/w2_public.yaml`
- Full grid (range data, local only): `python -m ctit.run --config configs/w2_grid.yaml`
- Tables: `python scripts/make_tables.py`
