# API surface (as of `ea12db9` + this commit)

Entry points other code (or another person) can build on. Everything runs in the `w2` conda env from the repo root. Paths under `data/` are local and gitignored.

## Canonical event frame

Most functions below take or return a **canonical frame**: one row per Windows event, with every raw source field kept as a nullable string column, plus these core columns (`ctit/ingest/canonical.py`):

| column | type | meaning |
|---|---|---|
| `_timestamp` | `datetime64[ns, UTC]` | event time |
| `Hostname` | string | lowercase short host name |
| `source` | string | `sysmon` \| `security` \| `system` \| `powershell` |
| `EventID` | int64 | Windows / Sysmon event ID |
| `Channel` | string | original channel |
| *(all other raw fields)* | string | e.g. `Image`, `CommandLine`, `TargetObject`, `TargetFilename`, `DestinationIp`, … |

Rows are sorted by `Hostname`, then `_timestamp`. `canonical.to_frame(records: list[dict]) -> DataFrame` builds one from dicts that already carry the core columns.

## 1. Extended mapper (frozen v2)

```python
from ctit.map.extended import tag            # tag(df: DataFrame, rules: list[dict] | None = None) -> DataFrame
from ctit.map.sigma_rules import load_compiled  # load_compiled(path=COMPILED) -> list[dict]
```

- **Input:** a canonical frame. `rules=None` loads the frozen `ctit/map/compiled_rules.jsonl` (3174 queries, 2017 Sigma rules).
- **Output:** one row per input row, in input order. Columns:
  - `host`, `ts`, `source`, `event_id`
  - `technique`: the primary rule's first technique tag, or `""`
  - `tactic`: the primary rule's first tactic (14-tactic scheme), or `""` when unmapped
  - `rule_id`: primary rule
  - `n_rules`: number of matching rules
  - `rule_ids`: comma-joined ids of every matching rule, in priority order
- Policy: `docs/MAPPER_POLICY.md`. Each rule dict has `id, variant, title, path, level, status, tactics, techniques, tactic_provenance, where`.

```python
import pandas as pd
from ctit.map.extended import tag
df = pd.read_parquet("data/otrf/apt29/canonical/day1.parquet")
out = tag(df)                                   # ~12 s for 185k events
print(out.loc[out.tactic != "", ["host", "ts", "tactic", "rule_id"]].head())
```

## 2. BRiMS mapper (DRIFT, through the adapter)

```python
from ctit.map.coverage import brims_tag       # brims_tag(df: DataFrame) -> DataFrame
from ctit.adapters import drift               # the only module that imports DRIFT
```

- `brims_tag` runs `drift.normalize_schema` + `drift.build_tokens` separately for each `source`.
  - **Input:** a canonical frame.
  - **Output:** columns `host, ts, source, event_id, technique, tactic` (`""` when unmapped).
  - Rows come back **sorted by host and ts within each source, not in input order**. Join on `ts` (plus `host`) if you need alignment.
- For the BRiMS whole-host pipeline: `drift.ingest_raw_sysmon(path) -> IngestResult`, then `drift.apply_role_overrides(ingest, roles_file) -> int`, then `drift.run_brims_transition(ingest, min_transitions=30, alpha=0.5) -> TransitionRun`. `TransitionRun` has `host_ids, vectors (N, D), edges, roles, peer_jsd {host: {role, jsd, n_peers}}, excluded`.
- Other re-exports: `drift.StrataConfig, drift.normalize_schema, drift.build_tokens, drift.sessionize_host, drift.fit_gap_threshold, drift.build_vectors_union_vocab, drift.compute_peer_baseline_jsd`.

```python
import pandas as pd
from ctit.map.coverage import brims_tag, coverage
df = pd.read_parquet("data/otrf/apt29/canonical/day1.parquet")
b = brims_tag(df)
print(coverage(b)["K"])                         # {'sysmon': [...], 'all_sources': [...]}
```

## 3. Canonical-schema loaders

**Full-XML Splunk Attack Data samples** (`ctit/ingest/splunk.py`):
- `read_sample(path: Path) -> tuple[str, DataFrame] | None` returns `(technique, canonical frame)`.
- It returns `None` when the file isn't XML (classic-text exports) or its name doesn't match `<T…>_atomic_red_team_windows-{sysmon,security}.log`. It raises `xml.etree.ElementTree.ParseError` on malformed files (one known: `T1562.004…sysmon`).
- `splunk.SAMPLES` is the sample directory.

```python
from ctit.ingest import splunk
for p in sorted(splunk.SAMPLES.iterdir()):
    r = splunk.read_sample(p)
    if r: technique, df = r; print(technique, len(df))
```

**OTRF datasets** (`ctit/ingest/otrf.py`, Mordor JSON lines):
- `read_day(path: Path, sources=("sysmon","security","system")) -> list[dict]` returns canonical records (wrap with `canonical.to_frame`).
- Timestamps: Sysmon uses `UtcTime`; other channels use `EventTime` plus an offset measured from Sysmon rows (`measure_offset`). It raises if that offset is not constant.
- APT29 outputs are already written: `data/otrf/apt29/canonical/day{1,2}.parquet` and `roles.json`.
- **OTRF atomic** outputs: `data/otrf/atomic/canonical/<SDWIN-id>__<name>.parquet` (one per zip; several zips can share an SDWIN id), with `data/otrf/atomic/coverage.csv`. All raw fields are kept, including `Message`, plus `_ts_source` (which timestamp field was used). Written by `python -m ctit.ingest.otrf_atomic`. Read one with `ctit.ingest.otrf_atomic.read_zip(path) -> DataFrame | None`.

```python
from pathlib import Path
from ctit.ingest import canonical, otrf
df = canonical.to_frame(otrf.read_day(Path("data/otrf/apt29/json/apt29_evals_day1_manual_2020-05-01225525.json")))
print(df["source"].value_counts())
print(df[["_timestamp", "Hostname", "EventID", "Image"]].head())
```

**ATLASv2** (`ctit/ingest/atlasv2.py`): `read_file(path, host, source) -> list[dict]`. Already-written parts are at `data/atlasv2/canonical/<split>-<h>-<scenario>/<source>-part-NNNNN.parquet`.

## 4. Plans: per-step techniques (`ctit/eval/plans.py`)

- `load_plan(actor: str, path: Path | None = None) -> list[Step]`. It reads `data/eval/plans/<actor>.yaml` and keeps Windows steps only, in file order. Actors: `APT29, menuPass, OilRig, Sandworm`.
- `Step` fields:
  - `actor, index, step_id, ability_id, name`
  - `technique` (e.g. `T1059.001`)
  - `plan_tactic_label, tactic` (14-tactic name), `tactic_source` (`plan_label` \| `attack_technique`)
  - `executor, command` (`#{…}` placeholders already filled from `input_arguments` defaults)
  - `cti_source, scenario` (int; APT29 steps 11+ are scenario 2)
- `sequences(steps, tactic_of=lambda s: s.tactic) -> list[list[str]]` gives one tactic list per scenario; steps where `tactic_of` returns a falsy value are skipped.
- `cited_sources(actor) -> list[str]` gives normalized cited-report URLs.

```python
from ctit.eval import plans
steps = plans.load_plan("APT29")
for s in steps[:5]:
    print(s.step_id, s.technique, s.tactic, s.scenario)
print([len(seq) for seq in plans.sequences(steps)])   # [58, 21]
```

## 5. Visibility CSV

There's no dedicated loader: it's a plain CSV at `data/eval/visibility_apt29.csv`, written by the `wp5_gate` experiment from `ctit.eval.visibility.draft_rows(steps) -> DataFrame`. One row per Windows plan step. Columns:

`step_id, ability_id, name, technique, plan_tactic, expected_sysmon_events, visible_sysmon {y|partial|n}, expected_zeek_logs, visible_zeek (pending), drift_tactic (tactic or "—"), brims_tactic (tactic or "—"), n_artifacts, rationale`

Join it to `plans.load_plan(actor)` on `ability_id` (not `step_id`, which repeats). Spec §2.2 adds a `source` column (`otrf_apt29 | splunk_attack_data | otrf_atomic | process_only`), which isn't produced yet.

```python
import pandas as pd
from ctit.eval import plans
vis = pd.read_csv("data/eval/visibility_apt29.csv", keep_default_na=False)
tac = dict(zip(vis.ability_id, vis.drift_tactic))
seqs = plans.sequences(plans.load_plan("APT29"), tactic_of=lambda s: None if tac[s.ability_id] == "—" else tac[s.ability_id])
```

## 6. `wp5_gate` experiment inputs

Run with `python -m ctit.run --config configs/wp5_gate.yaml`. The tree must be clean (or pass `--allow-dirty`). It writes `results/<run_id>/{config.yaml, metrics.json, calls.jsonl}`.

Config keys:

| key | value |
|---|---|
| `experiment` | `wp5_gate` |
| `mapper_report` | path to a `mapper_report` run's `metrics.json`. Read: `otrf.K[<mapper>][<source>]` and `atlasv2[<mapper>].K[<split>][<source>]`, where `<mapper>` ∈ {`extended`, `brims`} |
| `actors` | list, e.g. `[APT29, menuPass, OilRig, Sandworm]` |
| `k_scope` | `otrf_sysmon` \| `otrf_all` \| `atlasv2_all` \| `public_all` |
| `alphas` | list of smoothing values, e.g. `[0.5, 0.0]` |

Files read: `data/eval/plans/<actor>.yaml` and `data/eval/plans/docs/<actor>/*.md` (for cited sources).

Files written: `data/eval/visibility_apt29.csv` and `data/eval/plans/<actor>_cited_sources.txt`.

`metrics.json` contains:
- `K`, `steps`, `visibility_draft`, `cited_sources`, `plan_tactic_counts`
- `jsd["alpha=<a>"][<variant>]` with fields `alphabet, alpha, n_transitions{actor}, tactics_present{actor}, jsd{"A|B": float}`
- variants: `plan_14, plan_on_K_extended, plan_on_K_brims, visible_extended, visible_brims`

Today the per-step tactics for `visible_*` come from `visibility.draft_rows`. A different per-step tactic source would replace that call in `ctit/experiments/wp5_gate.py`.

```python
import json, subprocess
out = subprocess.run(["python", "-m", "ctit.run", "--config", "configs/wp5_gate.yaml"],
                     capture_output=True, text=True, check=True).stdout.strip().splitlines()[-1]
m = json.load(open(f"{out}/metrics.json"))
print(m["jsd"]["alpha=0.0"]["visible_extended"]["n_transitions"])
```

## 7. Added 2026-10-26

**Mapper v3 and the v3h candidate** (`ctit/map/v3.py`):
- `load_v3() -> list[dict]` returns the frozen v3 queries (`rules_v3.json`); `load_v3h()` returns the candidate.
- Pass the result to `extended.tag(df, rules)`. Called without rules, `tag()` is still v2.
- Helpers: `referenced_fields(where)`, `accepted_sources(where)`, `evaluable(rule, fields)`.

**OpTC** (`ctit/ingest/optc.py`):
- `to_frame(df, normalize=True, carry=(), restore_bare=False, stats=None, dmap=None)`.
- `unique_rows(path, restore_bare=True, event_ids=None, stats=None) -> (frame with weight _w, drive map)`. Rows are de-duplicated without timestamps, which is exact for tagging.

**OpTC split and red team** (`ctit/eval/`):
- `optc_split`: `population()`, `redteam_hosts()`, `load_split() -> {fit, validation, test}`, `host_id(name)`.
- `optc_redteam`: `load_labels()`, `label_events(events, labels)` (needs `ProcessId`), `windows(tagged, malicious_ts=None, size=8)`, `inventory()`.

**Extraction** (`ctit/cti/extract.py`):
- `chunk(text, tokens=2000, overlap=200)`.
- `extract_report(model, template, text, doc_id, calls)` returns `[ChunkResult]`.
- `memory_transitions(model, template, actor, calls)`.
- `build_prior(results, alpha=0.5, require_evidence=False)` returns `{tactics, matrix, counts, meta}`.
- Models: `AnthropicModel(pin)` (F) or `ctit.llm.ollama.OllamaModel(slot)` (S). Both expose `chat(prompt, calls, system=None)`.

**Experiments** (`python -m ctit.run --config ...`):
- `configs/mapper_v3.yaml` and `configs/mapper_v3h.yaml`: per-step K and tag rate.
- `configs/benign_windows.yaml`: B5 window counts.
- `configs/wp5_gate_v3.yaml` and `configs/wp5_gate_v3h.yaml`: the gate under each mapper.
- `configs/redteam_day.yaml`: the C4 diagnostic.
