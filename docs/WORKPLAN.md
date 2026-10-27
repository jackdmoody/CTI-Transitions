# Work plan (approved 2026-10-24)

**2026-10-26 (Jack):** range data is out of scope; open data only. WP1 BRiMS parity and WP12 (range ingest) are optional, run only if range data is ever used. Baselines are pooled by default.

Dependency order. One WP per session; each WP ends with its acceptance check passing, its tests passing, and a `W2/<WP>: …` commit. The public track (configs/w2_public.yaml) comes before any range data.

| WP | Scope | Acceptance check | Depends on |
|---|---|---|---|
| 1 | Run contract (`ctit/run.py`, `results/<run_id>/{config.yaml, metrics.json, calls.jsonl}`, git SHA, seeds, LLM call logger) and DRIFT parity through the adapter. Parity = BRiMS Table 5 `d(l1-eng-067) = 0.6153` (\|Δ\| < 5e-5), plus Table 1: 6,773,063 events, 2,141,479 tagged, 27 kept / 1 excluded, D = 41, and the Table 5 top-10 order. Data: BRiMS raw Sysmon parquet + `third_party/DRIFT/config/example_roles.json`, α 0.5, min_transitions 30 | `pytest tests/test_drift_parity.py` passes on the BRiMS parquet | — |
| 3 | §1 manifest + `scripts/check_leakage.py` | Passes on the real manifest; fails on 3 bad fixture manifests | 1 |
| 4 | Public ingest: OTRF APT29 and ATLASv2 Sysmon → canonical schema → tagged parquet; role files | Coverage report; ATLASv2 ground truth joined | 1 |
| 4b | Extended mapper in `ctit/map/` (spec §2.5). Sigma tooling: pySigma + Sysmon/Windows pipelines + SQLite backend. Primary-tactic policy in `docs/MAPPER_POLICY.md`. Frozen by commit | Report K, per-tactic benign tag rate on public data, recall vs. OTRF APT29 ground truth | 4 |
| 5 | APT29 plan → technique/tactic sequence; `visibility_apt29.csv` with `drift_tactic` from the extended mapper (**gate: Jack signs off**). Then: K across all available sources, every actor's ground truth projected onto K, pairwise actor JSD under both mappers → REVIEW_QUEUE (**gate: H4 viability**) | Both gates written to REVIEW_QUEUE | 4b |
| 6 | §4 extraction, F model (Anthropic) + B prompts | Priors and hallucination rate; every call logged | 3 (can run in parallel with 5) |
| 7 | S models under Ollama (`qwen3:14b`, size-curve model) + ATTK and Uni priors + the 14→K projection | Digests pinned; priors in the same format as F; projected rows sum to 1 | 6 |
| 9 | §5 scorer: fit-window role baseline, session windows, mean log-LR, per-window U, λ | P_adv = P_role ⇒ score 0; whole-host U equals DRIFT's peer JSD | 4b, 7 |
| 10 | §2.2 injection on the public track (APT29 into ATLASv2 benign hosts), variants, seeds, F2 | Seeds reproduce; one host renders | 5, 9 |
| 11 | §6 metrics + end-to-end public run → T6, T7, T2 (APT29) | `python -m ctit.run --config configs/w2_public.yaml` produces them | 10 |
| 12 | Range ingest, host_roles.csv, time split | No test-window data reaches the baseline fit | 11 |
| 13a–c | Port menuPass, OilRig, DPRK (one per session) | Each actor injected | 5's H4 gate, 12 |
| 14 | Zeek pre-flight, ingest, IP→host join, zeek_rules.yaml (**gate**) | Pre-flight passed, or Zeek dropped | 12 |
| 15 | Full grid + `make_tables.py` for T1–T8 | All tables produced by the script | 13, 14 |

WP2 was merged into WP1 and WP8 into WP7. After WP4b, WP5 and WP6 can run in parallel sessions.

DPRK plan check and OTRF availability check: Jack is doing these by hand (results go in PROGRESS.md).
