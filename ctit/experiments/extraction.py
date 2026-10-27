"""WP6 extraction run (spec §3, §4): CTI -> tactic-transition priors for F or S.

Conditions:
  R       report-conditioned, one prior per actor from its `used_for=prior` manifest docs
          (data/cti/reports/<doc_id>.txt), prompts/extract_v1.txt
  B       no-report, one call per actor per sample, prompts/memory_v1.txt with ATT&CK aliases
          (configs/actor_aliases.yaml)
  oracle  report-conditioned on OpTCRedTeamGroundTruth.pdf's text, same prompt (T9 upper bound)
Model modes (configs/models.yaml):
  F               claude-opus-5-5, pinned effort, `samples` samples, `workers` calls in parallel
  S, S-sampled    qwen3:14b at temperature 0 (one sample) and at default sampling (seeds 0..4)
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

    def chat(self, prompt: str, calls=None, *, system: str | None = None) -> str:
        path = self.dir / f"{hashlib.sha256(((system or '') + prompt).encode()).hexdigest()}.json"
        if path.exists():
            self.hits += 1
            rec = json.loads(path.read_text())
            if "refusal" in rec:
                raise extract.Refusal(rec["refusal"])
            return rec["text"]
        try:
            text = self.model.chat(prompt, calls, system=system)
        except extract.Refusal as e:
            path.write_text(json.dumps({"refusal": str(e)}))
            raise
        path.write_text(json.dumps({"text": text}))
        return text


def models_for(mode: str, pins: dict) -> list[tuple[str, object]]:
    """-> [(sample label, model)]."""
    if mode == "F":
        pin = pins["frontier"]["F"]
        key = json.dumps({"model": pin["model"], "options": pin["options"]}, sort_keys=True)
        return [(f"s{i}", Cached(extract.AnthropicModel(pin), f"{key}#s{i}"))
                for i in range(pin["samples"])]
    url = pins.get("ollama_server", {}).get("url", "http://127.0.0.1:11434")
    if mode == "S":
        m = OllamaModel("S", url=url)
        m.verify()
        key = json.dumps({"tag": m.pin["tag"], "w": m.pin["weights_sha256"], "o": m.options}, sort_keys=True)
        return [("t0", Cached(m, key))]
    if mode == "S-sampled":
        out = []
        for i in range(len(OllamaModel("S").pin["sampled"]["seeds"])):
            m = OllamaModel("S", sample=i, url=url)
            m.verify()
            key = json.dumps({"tag": m.pin["tag"], "w": m.pin["weights_sha256"], "o": m.options}, sort_keys=True)
            out.append((f"s{i}", Cached(m, key)))
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


def _run_job(job, model, templates, aliases, calls, ck):
    if job["cond"] == "B":
        return [extract.memory_transitions(model, templates["memory"], job["actor"], calls,
                                           aliases=aliases[job["actor"]]["aliases"])]
    return extract.extract_report(model, templates["report"], job["text"], job["doc_id"], calls, **ck)


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
    for mode in config["modes"]:
        samples = models_for(mode, pins)
        results: dict = {}  # (cond, actor, sample) -> [ChunkResult]
        work = [(j, s, m) for s, m in samples for j in todo]
        with ThreadPoolExecutor(config.get("workers", {}).get(mode, 1)) as ex:
            futs = [(j, s, ex.submit(_run_job, j, m, templates, aliases, calls, ck)) for j, s, m in work]
            for j, s, f in futs:
                results.setdefault((j["cond"], j["actor"], s), []).extend(f.result())
        mo = {"hits_cached": sum(m.hits for _, m in samples), "priors": {}}
        for (cond, actor, s), res in sorted(results.items()):
            p = extract.build_prior(res, alpha, meta={"mode": mode, "cond": cond, "actor": actor, "sample": s})
            trans = [t for r in res for t in r.transitions]
            dest = run_dir / mode / f"{cond}_{actor}_{s}.json"
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(json.dumps({**p, "transitions": trans,
                                        "chunks": [{"doc_id": r.doc_id, "index": r.index, "status": r.status,
                                                    "attempts": r.attempts} for r in res],
                                        "rejected": [[it, why] for r in res for it, why in r.rejected]}, indent=1))
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
