"""WP6 results from saved extraction runs (spec §4, §6; SPEC_ISSUES 2026-10-27). No model calls.

Reads the priors that `extraction` runs wrote (data/priors/<run_id>/<mode>/<cond>_<actor>_<sample>.json)
and the response cache, and reports per mode and prior:
- refusals per report and chunk (from the cache: a refused prompt is stored as a refusal);
- edges extracted, schema rejections by reason;
- hallucinated-span rate, strict and fragment-aware (pre-registered 2026-10-27), R and oracle only,
  recomputed here from the saved spans and the re-chunked source text;
- transition recovery (edge P/R/F1, JSD) vs. the plan ground truth, all platforms (primary) and
  Windows-only (appendix), and JSD of the per-mention variant; mean ± sd over samples;
- H4 at the prior level: the 4×4 prior-actor × plan-actor matrix per mode (R priors);
- H3 sensitivity: S and S-sampled with the chunks F refused (in any sample) removed.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np

from ctit.cti import extract
from ctit.eval import recovery
from ctit.experiments.extraction import PRIORS, jobs
from ctit.map.attack import TACTICS


def _caches(root: Path) -> dict[tuple[str, str], Path]:
    """(mode, sample) -> cache dir, from each dir's KEY.txt."""
    out = {}
    for d in root.iterdir():
        k = (d / "KEY.txt").read_text() if (d / "KEY.txt").exists() else ""
        if k.startswith('{"model": "claude'):
            out[("F", "s" + k.rsplit("#s", 1)[1])] = d
        elif '"tag"' in k:
            o = json.loads(k)["o"]
            out[("S", "t0") if "seed" not in o else ("S-sampled", f"s{o['seed']}")] = d
    return out


def _prompts(config: dict, templates: dict) -> list[tuple[str, str, int, str]]:
    """(cond, doc_id, chunk index, prompt) for every report chunk."""
    out = []
    for j in jobs(config):
        if "text" in j:
            for i, c in enumerate(extract.chunk(j["text"], **config["chunk"])):
                out.append((j["cond"], j["doc_id"], i, extract.render(templates["report"], tactics=extract.tactic_list(), text=c)))
    return out


def _sd(x):
    return float(np.std(x, ddof=1)) if len(x) > 1 else 0.0


def run(config: dict, calls=None) -> dict:
    templates = {k: extract.load_prompt(v) for k, v in config["prompts"].items()}
    alpha = config["alpha"]
    caches = _caches(PRIORS / "cache")
    chunks = _prompts(config, templates)
    texts = {j["doc_id"]: extract.chunk(j["text"], **config["chunk"]) for j in jobs(config) if "text" in j}
    truth = {v: {a: recovery.ground_truth_counts(a, all_platforms=(v == "all")) for a in config["actors"]}
             for v in ("all", "windows")}
    out: dict = {"ground_truth": {v: {a: {"transitions": int(G.sum()), "edges": int((G > 0).sum())}
                                      for a, G in t.items()} for v, t in truth.items()},
                 "refusals": {}, "modes": {}, "h4": {}, "h3_sensitivity": {}}
    # refusals per (mode, sample) and chunk
    refused: dict[str, set] = {}
    for (mode, s), d in sorted(caches.items()):
        for cond, doc, i, p in chunks:
            f = d / f"{hashlib.sha256(p.encode()).hexdigest()}.json"
            if f.exists() and "refusal" in json.loads(f.read_text()):
                out["refusals"].setdefault(mode, {}).setdefault(f"{doc}#{i}", []).append(s)
                refused.setdefault(mode, set()).add((doc, i))
    for mode, by_chunk in out["refusals"].items():
        n_samples = len({s for (m, s) in caches if m == mode})
        out["refusals"][mode] = {k: f"{len(v)}/{n_samples}" for k, v in sorted(by_chunk.items())}
    loaded: dict = {}
    for mode, run_id in config["runs"].items():
        for f in sorted((PRIORS / run_id / mode).glob("*.json")):
            d = json.loads(f.read_text())
            m = d["meta"]
            loaded.setdefault(mode, {}).setdefault((m["cond"], m["actor"]), {})[m["sample"]] = d
    for mode, priors in loaded.items():
        mo = {}
        for (cond, actor), by_s in sorted(priors.items()):
            rows = {}
            for s, d in sorted(by_s.items()):
                C, M = np.array(d["counts"]), np.array(d["counts_mentions"])
                tr = d["transitions"]
                checked = [t for t in tr if cond != "B" and t.get("evidence_ok") is not None]
                frag = [extract.evidence_ok_fragments(t["evidence_span"], texts[t["doc_id"]][t["chunk"]]) for t in checked]
                r = {"edges": int((C > 0).sum()), "transitions": len(tr),
                     "rejected_by_reason": d["meta"].get("rejected_by_reason", {}),
                     "hallucinated_strict": (sum(not t["evidence_ok"] for t in checked) / len(checked)) if checked else None,
                     "hallucinated_fragments": (sum(not x for x in frag) / len(frag)) if frag else None}
                if actor in truth["all"]:
                    for v in ("all", "windows"):
                        G = truth[v][actor]
                        r[f"recovery_{v}"] = {**recovery.edge_prf(C, G), "jsd": recovery.jsd(C, G, alpha),
                                              "jsd_mentions": recovery.jsd(M, G, alpha)}
                rows[s] = r
            summ = {"edges": [rows[s]["edges"] for s in rows]}
            for k in ("hallucinated_strict", "hallucinated_fragments"):
                vals = [rows[s][k] for s in rows if rows[s][k] is not None]
                summ[k] = {"mean": float(np.mean(vals)), "sd": _sd(vals)} if vals else None
            if actor in truth["all"]:
                for v in ("all", "windows"):
                    for k in ("f1", "precision", "recall", "jsd"):
                        vals = [rows[s][f"recovery_{v}"][k] for s in rows]
                        summ[f"{k}_{v}"] = {"mean": float(np.mean(vals)), "sd": _sd(vals)}
            mo[f"{cond}/{actor}"] = {"samples": rows, "summary": summ}
        out["modes"][mode] = mo
        # H4: R priors, per sample, then mean over samples per cell
        rp = {a: by_s for (c, a), by_s in priors.items() if c == "R" and a in truth["all"]}
        if rp:
            mats = [recovery.matrix({a: np.array(by_s[s]["counts"]) for a, by_s in rp.items()}, truth["all"], alpha)
                    for s in sorted(next(iter(rp.values())))]
            out["h4"][mode] = {k: {ra: {ca: float(np.mean([m[k][ra][ca] for m in mats])) for ca in mats[0][k][ra]}
                                   for ra in mats[0][k]} for k in ("f1", "jsd")}
            out["h4"][mode]["diag_margin"] = {ra: {k: float(np.mean([m["diag_margin"][ra][k] for m in mats]))
                                                   for k in ("f1", "jsd")} for ra in mats[0]["diag_margin"]}
    # H3 sensitivity: S without the chunks F refused in any sample
    drop = refused.get("F", set())
    for mode in ("S", "S-sampled"):
        if mode not in loaded:
            continue
        res = {}
        for (cond, actor), by_s in sorted(loaded[mode].items()):
            if cond != "R" or actor not in truth["all"]:
                continue
            vals = []
            for s, d in by_s.items():
                keep = [t for t in d["transitions"] if (t["doc_id"], t["chunk"]) not in drop]
                C = extract.counts(keep)
                vals.append({**recovery.edge_prf(C, truth["all"][actor]), "jsd": recovery.jsd(C, truth["all"][actor], alpha)})
            res[actor] = {k: {"mean": float(np.mean([x[k] for x in vals])), "sd": _sd([x[k] for x in vals])}
                          for k in ("f1", "jsd")}
        out["h3_sensitivity"][mode] = {"dropped_chunks": sorted(f"{d}#{i}" for d, i in drop), "R": res}
    out["tactics"] = list(TACTICS)
    out["alpha"] = alpha
    return out
