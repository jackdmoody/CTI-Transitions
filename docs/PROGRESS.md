# Progress

## 2026-10-24: environment setup
- Done: DRIFT pinned as the submodule `third_party/DRIFT` @ `brims-2026` (`3517424`). `ctit/adapters/drift.py` loads it and checks the pin. Conda env `w2` (Python 3.12.15) has DRIFT's `requirements.txt` installed. `ANTHROPIC_API_KEY` is loaded from `.env` (`ctit/env.py`, template `.env.example`). CLAUDE.md Environment/Commands and spec §8 are updated.
- Passed: `pytest -q`, 7 tests (adapter pin check, wrong-commit and missing-submodule errors, sysmon_pipeline → mitre_tactic chain, dotenv loading).
- Next: planning session.
- Open: `.env` not created yet; Jack to fill in the key. The open-weight model (Ollama) isn't installed yet. `tests/test_drift_parity.py` is not written yet.
