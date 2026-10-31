"""WP6 extraction run (spec §3, §4): CTI -> tactic-transition priors for F or S.

Conditions:
  R       report-conditioned, one prior per actor from its `used_for=prior` manifest docs
          (data/cti/reports/<doc_id>.txt), prompts/extract_v1.txt
  B       no-report, one call per actor per sample, prompts/memory_v1.txt with ATT&CK aliases
          (configs/actor_aliases.yaml)
  oracle  report-conditioned on OpTCRedTeamGroundTruth.pdf's text, same prompt (T9 upper bound)
Model modes (configs/models.yaml):
  F               claude-opus-5-5, pinned effort, `samples` samples, `workers` calls in parallel
  <slot>, <slot>-sampled   an open-weight slot (S = Ministral 3 14B since 2026-10-27, S_3B = Ministral 3 3B)
                  at temperature 0 (one sample) and at default sampling (seeds 0..4)
One prior per (mode, condition, actor, sample), aggregated per document (ctit.cti.extract).
check_leakage must pass first. Every API/Ollama call goes to calls.jsonl; responses are
cached under data/priors/cache/ (keyed by model, options, sample and prompt hash) so an
interrupted run resumes without re-calling. Priors and raw transitions (with evidence spans)
go to data/priors/<run_id>/ (gitignored).
"""
from __future__ import annotations

import hashlib
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import numpy as np
import yaml

from ctit.cti import extract, manifest
from ctit.eval import recovery
from ctit.llm.ollama import OllamaModel

REPO_ROOT = Path(__file__).resolve().parents[2]
PRIORS = REPO_ROOT / "data" / "priors"
ALIASES = REPO_ROOT / "configs" / "actor_aliases.yaml"
MODELS = REPO_ROOT / "configs" / "models.yaml"


class Cached:
    """Wraps a model: a response (or refusal) already in the cache is replayed without a call."""

    def __init__(self, model, key: str, root: Path = PRIORS / "cache"):
        self.model, self.name = model, model.name
        self.dir = root / hashlib.sha256(key.encode()).hexdigest()[:16]
        self.dir.mkdir(parents=True, exist_ok=True)
        (self.dir / "KEY.txt").write_text(key)
        self.hits = 0

    def chat(self, prompt: str, calls=None, *, system: str | None = None, attempt: int = 1) -> str:
        # keyed on the attempt too, so a schema retry is a fresh call, not a replay of the failure;
        # attempt 1 keeps the original file name
        h = hashlib.sha256(((system or '') + prompt).encode()).hexdigest()
        path = self.dir / (f"{h}.json" if attempt == 1 else f"{h}.a{attempt}.json")
        if path.exists():
            self.hits += 1
            rec = json.loads(path.read_text())
            if "refusal" in rec:
                raise extract.Refusal(rec["refusal"])
            if "incomplete" in rec:
                raise extract.Incomplete(rec["incomplete"])
            return rec["text"]
        try:
            text = self.model.chat(prompt, calls, system=system, attempt=attempt)
        except extract.Refusal as e:
            path.write_text(json.dumps({"refusal": str(e)}))
            raise
        except extract.Incomplete as e:  # G (POST HOC 2026-10-31): stored, so a replay is the same failure
            path.write_text(json.dumps({"incomplete": str(e)}))
            raise
        path.write_text(json.dumps({"text": text}))
        return text


def models_for(mode: str, pins: dict, budget: "extract.Budget | None" = None) -> list[tuple[str, object]]:
    """-> [(sample label, model)]. Frontier modes (F; G since 2026-10-31) are keyed in the cache as F
    always was: {"model", "options"} plus the sample."""
    if mode in pins.get("frontier", {}):
        pin = pins["frontier"][mode]
        key = json.dumps({"model": pin["model"], "options": pin["options"]}, sort_keys=True)
        make = (lambda: extract.OpenAIModel(pin, budget=budget)) if pin.get("provider") == "openai" \
            else (lambda: extract.AnthropicModel(pin))
        return [(f"s{i}", Cached(make(), f"{key}#s{i}")) for i in range(pin["samples"])]
    url = pins.get("ollama_server", {}).get("url", "http://127.0.0.1:11434")
    slot = mode.removesuffix("-sampled")
    if slot not in pins.get("open_weight", {}):
        raise ValueError(mode)
    samples = [None] if slot == mode else list(range(len(pins["open_weight"][slot]["sampled"]["seeds"])))
    out = []
    for i in samples:
        m = OllamaModel(slot, url=url, sample=i)
        m.verify()
        key = {"tag": m.pin["tag"], "w": m.pin["weights_sha256"], "o": m.options}
        if "template_sha256" in m.pin:  # the rendered prompt depends on the template (2026-10-27)
            key["t"] = m.pin["template_sha256"]
        out.append(("t0" if i is None else f"s{i}", Cached(m, json.dumps(key, sort_keys=True))))
    return out
    raise ValueError(mode)


def jobs(config: dict) -> list[dict]:
    """One job per (condition, actor, document): the unit a model is called on."""
    out = []
    header, rows = manifest.load()
    actors = config["actors"]
    if "R" in config["conditions"]:
        for r in rows:
            if r["used_for"] == "prior" and r["actor"] in actors:
                out.append({"cond": "R", "actor": r["actor"], "doc_id": r["doc_id"],
                            "text": (manifest.TEXT_DIR / f"{r['doc_id']}.txt").read_text()})
    if "B" in config["conditions"]:
        out += [{"cond": "B", "actor": a, "doc_id": f"memory:{a}"} for a in actors]
    if "oracle" in config["conditions"]:
        p = REPO_ROOT / config["oracle_text"]
        out.append({"cond": "oracle", "actor": "OpTC-redteam", "doc_id": "oracle", "text": p.read_text()})
    return out


def write_prior(dest: Path, res: list, alpha: float, meta: dict) -> dict:
    """Prior, raw transitions, chunk outcomes and rejections for one (mode, cond, actor, sample)."""
    p = extract.build_prior(res, alpha, meta=meta)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps({**p, "transitions": [t for r in res for t in r.transitions],
                                "chunks": [{"doc_id": r.doc_id, "index": r.index, "status": r.status,
                                            "attempts": r.attempts} for r in res],
                                "rejected": [[it, why] for r in res for it, why in r.rejected]}, indent=1))
    return p


def _run_job(job, model, templates, aliases, calls, ck):
    if job["cond"] == "B":
        return [extract.memory_transitions(model, templates["memory"], job["actor"], calls,
                                           aliases=aliases[job["actor"]]["aliases"])]
    return extract.extract_report(model, templates["report"], job["text"], job["doc_id"], calls, **ck)


def make_budget(config: dict) -> "extract.Budget | None":
    """`budget: {cap_usd, prior_runs}`: spend already logged by earlier runs of the same model counts
    toward the cap (POST HOC, 2026-10-31, G)."""
    b = config.get("budget")
    if not b:
        return None
    spent = 0.0
    for run in b.get("prior_runs", []):
        f = REPO_ROOT / "results" / run / "calls.jsonl"
        spent += sum(json.loads(x).get("cost_usd") or 0.0 for x in f.read_text().splitlines())
    return extract.Budget(b["cap_usd"], spent)


def smoke(config, pins, templates, todo, ck, calls, budget) -> dict:
    """Smoke test (POST HOC, 2026-10-31, G): the first `smoke.chunks` report chunks, sample s0, through the
    same cache as the full run (so these calls are reused there, not repeated). Reports per-call tokens,
    latency and parse status, and projects the full run's cost from F's logged input tokens on the same
    prompts (scaled by G/F input tokens on these chunks) and these calls' mean output tokens."""
    mode = config["modes"][0]
    _, model = models_for(mode, pins, budget)[0]
    n0 = sum(1 for _ in calls.path.read_text().splitlines()) if calls.path.exists() else 0
    rows = []
    for j in [j for j in todo if "text" in j]:
        for i, c in enumerate(extract.chunk(j["text"], **ck)):
            if len(rows) == config["smoke"]["chunks"]:
                break
            r = extract.extract_chunk(model, templates["report"], c, j["doc_id"], i, calls)
            rows.append({"chunk": f"{j['doc_id']}#{i}", "status": r.status, "attempts": r.attempts,
                         "transitions": len(r.transitions), "rejected": len(r.rejected),
                         "prompt_sha256": hashlib.sha256(extract.render(templates["report"], tactics=extract.tactic_list(),
                                                                        text=c).encode()).hexdigest()})
    recs = [json.loads(x) for x in calls.path.read_text().splitlines()][n0:]
    out = {"smoke": rows, "calls": recs}
    f_runs = config["smoke"].get("f_runs", [])
    f_in = {}
    for run in f_runs:
        for x in (REPO_ROOT / "results" / run / "calls.jsonl").read_text().splitlines():
            r = json.loads(x)
            if r.get("attempt", 1) == 1:
                f_in.setdefault(r["prompt_sha256"], []).append(r["input_tokens"])
    if recs and f_in:
        pin = pins["frontier"][mode]
        price = pin["usd_per_mtok"]
        ratio = np.mean([r["input_tokens"] / np.mean(f_in[r["prompt_sha256"]]) for r in recs if r["prompt_sha256"] in f_in])
        f_total_in = sum(v[0] for v in f_in.values()) * pins["frontier"]["F"]["samples"]
        n_calls = len(f_in) * pin["samples"]
        out_tok = np.mean([r["output_tokens"] for r in recs])
        proj = (ratio * f_total_in * price["input"] + n_calls * out_tok * price["output"]) / 1e6
        out["projection"] = {"calls": n_calls, "g_over_f_input_tokens": float(ratio), "input_tokens": float(ratio * f_total_in),
                             "output_tokens_per_call_assumed": float(out_tok), "usd": float(proj),
                             "note": "every call assumed to emit the smoke calls' mean output (R chunks; B calls are shorter)"}
    out["budget"] = {"cap_usd": budget.cap, "spent_usd": budget.spent} if budget else None
    return out


def run(config: dict, calls=None) -> dict:
    from scripts import check_leakage
    if check_leakage.main([]) != 0:
        raise RuntimeError("check_leakage.py failed: no extraction")
    pins = yaml.safe_load(MODELS.read_text())
    aliases = yaml.safe_load(ALIASES.read_text())["actors"]
    templates = {k: extract.load_prompt(v) for k, v in config["prompts"].items()}
    ck = {"tokens": config["chunk"]["tokens"], "overlap": config["chunk"]["overlap"]}
    alpha = config["alpha"]
    run_dir = PRIORS / (calls.path.parent.name if calls is not None else "adhoc")
    todo = jobs(config)
    truths = {a: recovery.ground_truth_counts(a) for a in config["actors"]}
    out: dict = {"prompt_sha256": {k: extract.template_sha256(v) for k, v in templates.items()},
                 "chunk": ck, "alpha": alpha, "modes": {},
                 "chunks_per_report": {j["doc_id"]: len(extract.chunk(j["text"], **ck)) for j in todo if "text" in j}}
    budget = make_budget(config)
    if "smoke" in config:
        return smoke(config, pins, templates, todo, ck, calls, budget)
    for mode in config["modes"]:
        samples = models_for(mode, pins, budget)
        results: dict = {}  # (cond, actor, sample) -> [ChunkResult]
        work = [(j, s, m) for s, m in samples for j in todo]
        with ThreadPoolExecutor(config.get("workers", {}).get(mode, 1)) as ex:
            futs = [(j, s, ex.submit(_run_job, j, m, templates, aliases, calls, ck)) for j, s, m in work]
            stopped = [f.exception() for _, _, f in futs if isinstance(f.exception(), extract.BudgetExceeded)]
            if stopped:  # stop cleanly: no priors written; completed responses stay cached, so a rerun resumes
                raise RuntimeError(f"budget cap reached, run stopped: {stopped[0]}")
            for j, s, f in futs:
                results.setdefault((j["cond"], j["actor"], s), []).extend(f.result())
        mo = {"hits_cached": sum(m.hits for _, m in samples), "priors": {}}
        for (cond, actor, s), res in sorted(results.items()):
            p = write_prior(run_dir / mode / f"{cond}_{actor}_{s}.json", res, alpha,
                            {"mode": mode, "cond": cond, "actor": actor, "sample": s})
            C = np.array(p["counts"])
            entry = {k: p["meta"][k] for k in ("chunks", "chunk_status", "retried", "transitions", "rejected_items",
                                               "rejected_by_reason", "hallucinated_span_rate",
                                               "hallucinated_span_rate_fragments")}
            entry["edges"] = int((C > 0).sum())
            if cond == "B":
                entry["hallucinated_span_rate"] = None  # recall, not verifiable (spec §6)
                entry["hallucinated_span_rate_fragments"] = None
            if actor in truths:
                entry["recovery"] = {**recovery.edge_prf(C, truths[actor]), "jsd": recovery.jsd(C, truths[actor], alpha)}
            mo["priors"].setdefault(f"{cond}/{actor}", {})[s] = entry
        for key, by_s in mo["priors"].items():
            e = [v["edges"] for v in by_s.values()]
            by_s["_summary"] = {"edges_mean": float(np.mean(e)), "edges_sd": float(np.std(e, ddof=1)) if len(e) > 1 else 0.0}
        out["modes"][mode] = mo
    if calls is not None and calls.path.exists():
        recs = [json.loads(line) for line in calls.path.read_text().splitlines()]
        out["usage"] = {m: {"calls": sum(r["model"].startswith(m) for r in recs),
                            "input_tokens": sum(r["input_tokens"] for r in recs if r["model"].startswith(m)),
                            "output_tokens": sum(r["output_tokens"] for r in recs if r["model"].startswith(m)),
                            "cost_usd": sum(r["cost_usd"] or 0 for r in recs if r["model"].startswith(m))}
                        for m in sorted({r["model"].split("#")[0] for r in recs})}
    out["priors_dir"] = str(run_dir.relative_to(REPO_ROOT)) if run_dir.is_relative_to(REPO_ROOT) else str(run_dir)
    return out
