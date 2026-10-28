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
Post hoc (2026-10-27, added after the results were seen; SPEC_ISSUES), under "post_hoc":
- edge-count chance control for every prior and for the ATTK and Uni baselines (edge-F1 of a
  random set of the same number of distinct off-diagonal edges; ctit.eval.recovery), with
  precision and recall;
- R - B on the chance-normalized edge-F1 (F1 / chance mean), and H2b (that gap vs. the
  actor's ATT&CK group-page reference count, descriptive);
- H4: JSD at the extra alphas, and the 4x4 matrix of chance-normalized edge-F1;
- H4 column-wise (secondary, approved 2026-10-27): per plan actor, matched prior minus the best
  other actor's prior, read from the pre-registered matrix; reported next to the row-wise result.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import numpy as np

from ctit.cti import extract, prior
from ctit.cti.manifest import load_actors
from ctit.eval import recovery
from ctit.experiments.extraction import PRIORS, jobs
from ctit.map import attack
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
    if "post_hoc" in config:
        out["post_hoc"] = post_hoc(config, loaded, truth["all"])
        # H4 column-wise (post hoc secondary, approved by Jack 2026-10-27): per plan actor (column),
        # the matched prior minus the best other actor's prior, from the pre-registered matrix
        out["post_hoc"]["h4_colwise"] = {mode: h4_colwise(h) for mode, h in out["h4"].items() if len(h["f1"]) > 1}
    out["tactics"] = list(TACTICS)
    out["alpha"] = alpha
    return out


def h4_colwise(h: dict) -> dict:
    """Per column (plan actor): matched prior minus the best other prior (edge-F1); for JSD the
    best other prior's JSD minus the matched one's, so > 0 means the matched prior is closer."""
    return {"f1": {ca: h["f1"][ca][ca] - max(h["f1"][ra][ca] for ra in h["f1"] if ra != ca) for ca in h["f1"]},
            "jsd": {ca: min(h["jsd"][ra][ca] for ra in h["jsd"] if ra != ca) - h["jsd"][ca][ca] for ca in h["jsd"]}}


CHANCE_KEYS = ("f1", "precision", "recall", "edges_extracted", "chance_mean", "f1_over_chance", "percentile")


def _summ(vals: list[dict]) -> dict:
    out = {}
    for k in CHANCE_KEYS:
        x = [v[k] for v in vals if v[k] is not None]
        out[k] = {"mean": float(np.mean(x)), "sd": _sd(x)} if x else None
    return out


def reference_count(group_id: str, version: str = "18.1") -> int:
    """H2b public-coverage proxy: references on the ATT&CK group page (the mitre-attack ID excluded)."""
    g = next(o for o in attack._bundle(version) if o["type"] == "intrusion-set" and attack._ext_id(o) == group_id)
    return sum(r.get("source_name") != "mitre-attack" for r in g.get("external_references", []))


def post_hoc(config: dict, loaded: dict, G: dict) -> dict:
    ph = config["post_hoc"]
    draws, rng = ph["draws"], np.random.default_rng(ph["seed"])
    groups = {a: v["attack_group"] for a, v in load_actors().items()}
    out: dict = {"note": "post hoc: added 2026-10-27 after the results were seen (SPEC_ISSUES)",
                 "draws": draws, "seed": ph["seed"], "chance": {}, "r_minus_b": {}, "h4": {}}
    ch = out["chance"]
    for mode, priors in sorted(loaded.items()):
        for (cond, actor), by_s in sorted(priors.items()):
            if actor in G:
                ch[f"{mode}/{cond}/{actor}"] = _summ([recovery.chance_control(np.array(by_s[s]["counts"]), G[actor], draws, rng)
                                                      for s in sorted(by_s)])
    for actor in config["actors"]:
        ch[f"baseline/ATTK/{actor}"] = _summ([recovery.chance_control(prior.attk_counts(groups[actor])[0], G[actor], draws, rng)])
        ch[f"baseline/Uni/{actor}"] = _summ([recovery.chance_control(np.ones((len(TACTICS),) * 2), G[actor], draws, rng)])
    refs = {a: reference_count(groups[a]) for a in config["actors"]}
    for mode in loaded:
        gap = {}
        for a in config["actors"]:
            r, b = ch.get(f"{mode}/R/{a}"), ch.get(f"{mode}/B/{a}")
            if r and b:
                gap[a] = {"f1_gap": r["f1"]["mean"] - b["f1"]["mean"],
                          "ratio_gap": (r["f1_over_chance"]["mean"] - b["f1_over_chance"]["mean"]
                                        if r["f1_over_chance"] and b["f1_over_chance"] else None),
                          "attack_references": refs[a]}
        if len(gap) > 2 and all(v["ratio_gap"] is not None for v in gap.values()):
            ranks = lambda xs: np.argsort(np.argsort(xs))
            a = list(gap)
            rho = np.corrcoef(ranks([gap[x]["ratio_gap"] for x in a]), ranks([-gap[x]["attack_references"] for x in a]))[0, 1]
            gap["_spearman_ratio_gap_vs_fewer_references"] = float(rho)
        out["r_minus_b"][mode] = gap
    for mode, priors in sorted(loaded.items()):
        rp = {a: by_s for (c, a), by_s in priors.items() if c == "R" and a in G}
        if not rp:
            continue
        samples = sorted(next(iter(rp.values())))
        h = {}
        for al in ph["h4_alphas"]:
            mats = [recovery.matrix({a: np.array(by_s[s]["counts"]) for a, by_s in rp.items()}, G, al) for s in samples]
            h[f"jsd_alpha_{al}"] = {ra: {ca: float(np.mean([m["jsd"][ra][ca] for m in mats])) for ca in G} for ra in rp}
            if len(G) > 1:
                h[f"jsd_alpha_{al}_margin"] = {ra: float(np.mean([m["diag_margin"][ra]["jsd"] for m in mats])) for ra in rp}
        ratio = {ra: {ca: float(np.mean([recovery.chance_control(np.array(rp[ra][s]["counts"]), G[ca], draws, rng)["f1_over_chance"] or 0.0
                                          for s in samples])) for ca in G} for ra in rp}
        h["f1_over_chance"] = ratio
        if len(G) > 1:
            h["f1_over_chance_margin"] = {ra: ratio[ra][ra] - max(ratio[ra][c] for c in G if c != ra) for ra in rp}
        out["h4"][mode] = h
    return out
