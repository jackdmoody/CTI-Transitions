"""Paper tables as CSV (POST HOC packaging, 2026-10-28; Jack's request). No model calls.

Writes to `out_dir` (results/paper_tables/, gitignored) with a README line per file:
  a  support_recovery.csv      edge-F1, F1/chance and percentile per prior and actor. Computed here, not read
                               from the extraction report: every ratio uses ONE chance draw (common random
                               numbers): `draws` random orderings of the 182 off-diagonal cells, drawn once;
                               a k-edge chance set is the first k cells of each ordering, for every prior and
                               actor. Multi-sample priors: mean over samples of each sample's F1, ratio and
                               percentile.
  b  information_gain_own_plan.csv, information_gain_matrix.csv, attribution_counts.csv  (prior_likelihood)
  c  fabricated_evidence.csv   strict and fragment-aware hallucinated-span rates, R priors (extraction_report)
  d  refusals.csv              first-attempt calls and refusals per model and condition (response cache)
  e  case_b.csv                both versions: AUPRC [CI], AUROC [CI], Det@1% [CI] with realized FPR and ties
  f  open_models.csv           options as sent (calls.jsonl), request fields outside `options` (from the cache
                               keys, e.g. Qwen's think=false), the model's own default parameters (its Ollama
                               params layer, applied to anything not sent) and Ollama digests (configs/models.yaml)
  g  report_dates.csv          each CTI report's publication date next to its plan's release date
Every source result must come from a commit at or after `min_commit` (checked).
"""
from __future__ import annotations

import csv
import hashlib
import json
import subprocess
from pathlib import Path

import numpy as np
import yaml

from ctit.cti import extract, manifest, prior
from ctit.cti.manifest import load_actors
from ctit.eval import recovery
from ctit.experiments.extraction import ALIASES, MODELS, PRIORS, REPO_ROOT, jobs
from ctit.experiments.extraction_report import _caches
from ctit.experiments.redteam_scoring import run_dir
from ctit.experiments.schema_failures import _job_prompts
from ctit.llm.ollama import MANIFESTS

RESULTS = REPO_ROOT / "results"


def _source(run_id: str, min_commit: str) -> dict:
    """metrics of a result, after checking its commit descends from min_commit and was clean."""
    prov = yaml.safe_load((RESULTS / run_id / "config.yaml").read_text())["_provenance"]
    ok = subprocess.run(["git", "-C", str(REPO_ROOT), "merge-base", "--is-ancestor", min_commit, prov["git_sha"]]).returncode == 0
    if not ok or prov["git_dirty"]:
        raise RuntimeError(f"{run_id}: not from a clean commit at or after {min_commit}")
    return json.loads((RESULTS / run_id / "metrics.json").read_text())


def _write(path: Path, rows: list[dict]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    cols = list(dict.fromkeys(k for r in rows for k in r))
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows({k: (round(v, 4) if isinstance(v, float) else v) for k, v in r.items()} for r in rows)
    return len(rows)


def chance_orderings(draws: int, seed: int) -> np.ndarray:
    """(draws, N_OFF) random orderings of the off-diagonal cells, drawn once for the whole table."""
    return np.argsort(np.random.default_rng(seed).random((draws, recovery.N_OFF)), axis=1)


def chance_row(C: np.ndarray, G: np.ndarray, order: np.ndarray) -> dict:
    """edge_prf of C against G, with chance F1 from the shared orderings (first k cells per ordering)."""
    r = recovery.edge_prf(C, G)
    k, g = r["edges_extracted"], r["edges_truth"]
    if k == 0 or g == 0:
        c = np.zeros(len(order))
    else:
        truth = (G > 0)[recovery.OFF_DIAG]
        c = 2 * truth[order[:, :k]].sum(axis=1) / (k + g)
    mean = float(c.mean())
    return {"edges": k, "f1": r["f1"], "chance_mean": mean, "f1_over_chance": r["f1"] / mean if mean > 0 else None,
            "percentile": float(100 * ((c < r["f1"]).mean() + 0.5 * (c == r["f1"]).mean()))}


def _mean(xs):
    xs = [x for x in xs if x is not None]
    return float(np.mean(xs)) if xs else None


def support_recovery(config: dict) -> list[dict]:
    order = chance_orderings(config["chance"]["draws"], config["chance"]["seed"])
    groups = {a: v["attack_group"] for a, v in load_actors().items()}
    rows = []
    for a in config["actors"]:
        G = recovery.ground_truth_counts(a, all_platforms=True)
        priors = {}
        for name, (label, cond) in config["table_a"].items():
            run, sub = run_dir(config["priors"][label])
            files = sorted((PRIORS / run / sub).glob(f"{cond}_{a}_*.json"))
            priors[name] = [np.array(json.loads(f.read_text())["counts"]) for f in files]
        priors["ATTK"] = [prior.attk_counts(groups[a])[0]]
        for name, Cs in priors.items():
            rs = [chance_row(C, G, order) for C in Cs]
            rows.append({"prior": name, "actor": a, "samples": len(rs), "truth_edges": int(((G > 0) & recovery.OFF_DIAG).sum()),
                         "edges_mean": _mean([r["edges"] for r in rs]), "edge_f1": _mean([r["f1"] for r in rs]),
                         "edge_f1_sd": float(np.std([r["f1"] for r in rs], ddof=1)) if len(rs) > 1 else 0.0,
                         "chance_f1_mean": _mean([r["chance_mean"] for r in rs]),
                         "f1_over_chance": _mean([r["f1_over_chance"] for r in rs]),
                         "percentile": _mean([r["percentile"] for r in rs])})
    return rows


def information_gain(m: dict, names: list[str], actors: list[str]) -> tuple[list, list, list]:
    own, mat, attr = [], [], []
    for al, by_name in m["own_plan"].items():
        for name in names:
            for a in actors:
                s = by_name[name][a]
                own.append({"prior": name, "actor": a, "alpha": float(al), "bits_per_transition": s["bits"],
                            "ci95_lo": s["ci95"][0], "ci95_hi": s["ci95"][1], "samples": s["samples"],
                            "plan_transitions": m["transitions"][a]})
    for al, by_name in m["matrix"].items():
        for name in names:
            if name not in by_name:
                continue
            M = by_name[name]
            best = {ca: max(M, key=lambda ra: M[ra][ca]) for ca in actors}
            for ra in actors:
                mat.append({"prior": name, "alpha": float(al), "prior_actor": ra,
                            **{f"plan_{ca}": M[ra][ca] for ca in actors}})
            attr.append({"prior": name, "alpha": float(al), "plans_own_actor_best": sum(best[c] == c for c in actors),
                         "plans": len(actors), **{f"plan_{ca}_best_prior": best[ca] for ca in actors}})
    return own, mat, attr


def fabricated(m: dict, models: dict[str, str], actors: list[str]) -> list[dict]:
    rows = []
    for label, mode in models.items():
        for a in actors:
            e = m["modes"][mode][f"R/{a}"]
            sm, smp = e["summary"], e["samples"]
            rows.append({"model": label, "actor": a, "samples": len(smp),
                         "transitions_mean": _mean([v["transitions"] for v in smp.values()]),
                         "strict": sm["hallucinated_strict"]["mean"], "strict_sd": sm["hallucinated_strict"]["sd"],
                         "fragment_aware": sm["hallucinated_fragments"]["mean"],
                         "fragment_aware_sd": sm["hallucinated_fragments"]["sd"]})
    return rows


def refusals(config: dict) -> list[dict]:
    templates = {k: extract.load_prompt(v) for k, v in config["prompts"].items()}
    aliases = yaml.safe_load(ALIASES.read_text())["actors"]
    caches = _caches(PRIORS / "cache", config["ollama_labels"])
    prompts = [(j["cond"], j["doc_id"], i, p) for j in jobs(config)
               for i, p in _job_prompts(j, templates, aliases, config["chunk"])]
    rows = []
    for label, mode in config["refusal_models"].items():
        ds = [d for (m, s), d in sorted(caches.items()) if m == mode]
        for cond in config["conditions"]:
            calls = refused = 0
            chunks = set()
            for d in ds:
                for c, doc, i, p in prompts:
                    f = d / f"{hashlib.sha256(p.encode()).hexdigest()}.json"
                    if c != cond or not f.exists():
                        continue
                    calls += 1
                    if "refusal" in json.loads(f.read_text()):
                        refused += 1
                        chunks.add(f"{doc}#{i}")
            if calls:
                rows.append({"model": label, "condition": cond, "samples": len(ds), "first_attempt_calls": calls,
                             "refused_calls": refused, "refused_chunks": len(chunks),
                             "refused_chunk_ids": " ".join(sorted(chunks))})
    return rows


def case_b(results: dict[str, dict]) -> list[dict]:
    rows = []
    for version, m in results.items():
        for c, e in m["conditions"].items():
            p, ci = e["point"], e["ci95"]
            r = {"version": version, "condition": c, "samples": e["samples"],
                 "auprc": p["auprc"], "auprc_lo": ci["auprc"][0], "auprc_hi": ci["auprc"][1],
                 "auroc": p["auroc"], "auroc_lo": ci["auroc"][0], "auroc_hi": ci["auroc"][1],
                 "det_1fpr": p["det_1fpr"], "det_1fpr_lo": ci["det_1fpr"][0], "det_1fpr_hi": ci["det_1fpr"][1],
                 "fpr_realized": p["fpr_actual"], "base_rate": m["base_rate"]}
            ties = m.get("ties", {}).get(c)
            if ties:
                blocks = [t.get("threshold_inside_tie_block") for t in ties]
                r |= {"zero_share_positive": _mean([t["zero_share_positive"] for t in ties]),
                      "zero_share_negative": _mean([t["zero_share_negative"] for t in ties]),
                      "threshold_in_tie_block": f"{sum(b is not None for b in blocks)}/{len(blocks)}",
                      "tie_block_is_zero": f"{sum(bool(b and b['is_zero_block']) for b in blocks)}/{len(blocks)}",
                      "fpr_next_achievable": _mean([b["above_side"]["fpr"] for b in blocks if b]),
                      "det_next_achievable": _mean([b["above_side"]["det"] for b in blocks if b])}
            rows.append(r)
    return rows


def ollama_params(tag: str, manifests: Path = MANIFESTS) -> tuple[str | None, dict | None]:
    """(digest, contents) of the model's params layer: its defaults for any option not sent."""
    name, t = tag.split(":")
    f = manifests / name / t
    if not f.exists():
        return None, None
    for layer in json.loads(f.read_text())["layers"]:
        if layer["mediaType"].endswith(".params"):
            blob = manifests.parents[2] / "blobs" / layer["digest"].replace(":", "-")
            return layer["digest"], json.loads(blob.read_text())
    return None, None


def _request_extras(tag: str, setting_sampled: bool) -> dict:
    """Request fields sent outside `options` (OllamaModel.chat pops `think`), from the cache keys."""
    out = {}
    for d in (PRIORS / "cache").iterdir():
        k = (d / "KEY.txt").read_text() if (d / "KEY.txt").exists() else ""
        if '"tag"' in k:
            key = json.loads(k)
            if key["tag"] == tag and ("seed" in key["o"]) == setting_sampled and "think" in key["o"]:
                out["think"] = key["o"]["think"]
    return out


def open_models(config: dict) -> list[dict]:
    pins = yaml.safe_load(MODELS.read_text())
    by_tag = {p["tag"]: p for p in pins["open_weight"].values()}
    seen: dict[tuple, dict] = {}
    for run in config["model_runs"]:
        for line in (RESULTS / run / "calls.jsonl").read_text().splitlines():
            r = json.loads(line)
            tag = r["model"].split("#")[0]
            o = dict(r.get("options") or {})
            seed = o.pop("seed", None)
            k = (tag, json.dumps(o, sort_keys=True))
            e = seen.setdefault(k, {"seeds": set(), "calls": 0, "runs": set()})
            e["calls"] += 1
            e["runs"].add(run)
            if seed is not None:
                e["seeds"].add(seed)
    rows = []
    for (tag, o), e in sorted(seen.items()):
        p = by_tag.get(tag, {})
        pd_digest, pd = ollama_params(tag) if p else (None, None)
        if pd is None and p.get("modelfile"):  # built on the private server: its committed, pinned Modelfile
            pd_digest = "modelfile sha256:" + p["modelfile_sha256"]
            pd = {}
            for line in (REPO_ROOT / p["modelfile"]).read_text().splitlines():
                if line.startswith("PARAMETER "):
                    _, k, v = line.split(None, 2)
                    pd.setdefault(k, []).append(v)
            pd = {k: v[0] if len(v) == 1 else v for k, v in pd.items()}
        rows.append({"model": config["model_labels"].get(tag, tag), "tag": tag,
                     "setting": ("sampled" if e["seeds"] else "temperature 0" if '"temperature": 0' in o
                                 else "no sampling parameters"),
                     "options_sent": o,
                     "request_fields_outside_options": json.dumps(_request_extras(tag, bool(e["seeds"]))) if p else None,
                     "model_default_params": json.dumps(pd, sort_keys=True) if pd else None,
                     "default_params_source": pd_digest, "seeds": " ".join(map(str, sorted(e["seeds"]))), "calls": e["calls"],
                     "runs": " ".join(sorted(e["runs"])), "ollama_id": p.get("ollama_id"),
                     "weights_sha256": p.get("weights_sha256"), "template_sha256": p.get("template_sha256"),
                     "modelfile_sha256": p.get("modelfile_sha256"), "quantization": p.get("quantization"),
                     "ollama_version": pins.get("ollama_version") if p else None})
    return rows


def report_dates(config: dict) -> list[dict]:
    plans = yaml.safe_load((REPO_ROOT / config["plan_release_dates"]).read_text())["plans"]
    _, docs = manifest.load()
    rows = []
    for d in docs:
        if d["actor"] not in config["actors"]:
            continue
        p = plans[d["actor"]]
        pub = np.datetime64(d["pub_date"]) if d["pub_date"] else None
        rel = np.datetime64(p["release_date"])
        rows.append({"actor": d["actor"], "doc_id": d["doc_id"], "used_for": d["used_for"], "source_org": d["source_org"],
                     "pub_date": d["pub_date"], "plan_release_date": p["release_date"],
                     "days_before_plan": int((rel - pub).astype(int)) if pub is not None else None,
                     "published_after_plan": bool(pub > rel) if pub is not None else None,
                     "cited_by_emulation_plan": d["cited_by_emulation_plan"], "plan_release_source": p["source"]})
    return rows


def run(config: dict, calls=None) -> dict:
    src = {k: _source(v, config["min_commit"]) for k, v in config["sources"].items()}
    out_dir = REPO_ROOT / config["out_dir"]
    own, mat, attr = information_gain(src["likelihood"], config["table_b"], config["actors"])
    tables = {
        "a_support_recovery.csv": (support_recovery(config),
            "edge-F1, F1/chance (one shared chance draw for every cell) and chance percentile per prior and actor"),
        "b_information_gain_own_plan.csv": (own,
            "bits over uniform per own-plan transition with 95% bootstrap CI, per prior, actor and alpha"),
        "b_information_gain_matrix.csv": (mat,
            "full 4x4 information-gain matrices (prior actor x plan actor), per prior family and alpha"),
        "b_attribution_counts.csv": (attr,
            "plans whose highest-likelihood prior is their own actor's, and the best prior per plan"),
        "c_fabricated_evidence.csv": (fabricated(src["extraction"], config["table_c"], config["actors"]),
            "hallucinated evidence-span rate of R priors, strict and fragment-aware, per model and actor"),
        "d_refusals.csv": (refusals(config), "first-attempt calls and refusals per model and condition"),
        "e_case_b.csv": (case_b({"as_run": src["case_b_as_run"], "collapsed": src["case_b_collapsed"]}),
            "case B, both versions: AUPRC, AUROC, Det@1%FPR with 95% host-cluster CIs, realized FPR and ties"),
        "f_open_models.csv": (open_models(config),
            "options as actually sent (from calls.jsonl) and Ollama digests for each model and setting"),
        "g_report_dates.csv": (report_dates(config),
            "each CTI report's publication date next to its actor's emulation-plan release date"),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    counts = {name: _write(out_dir / name, rows) for name, (rows, _) in tables.items()}
    readme = ["# Paper tables (POST HOC packaging, 2026-10-28)", "",
              f"Sources (clean commits at or after {config['min_commit']}): "
              + ", ".join(f"{k} `{v}`" for k, v in config["sources"].items()) + ".", ""]
    readme += [f"- `{name}`: {desc}." for name, (_, desc) in tables.items()]
    (out_dir / "README.md").write_text("\n".join(readme) + "\n")
    return {"note": "POST HOC packaging (2026-10-28): paper tables", "out_dir": config["out_dir"],
            "sources": config["sources"], "rows": counts}
