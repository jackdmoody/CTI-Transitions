"""Evidence audit sample for hand labeling (POST HOC, 2026-10-31; Jack's final coding pass, item 3).
No model calls.

From the R extractions of each label in `models`, every transition whose evidence span fails the
fragment-aware check (ctit.cti.extract.evidence_ok_fragments, recomputed against the re-chunked
source) is a candidate. Per label, `n` spans are drawn without replacement with a generator seeded
from (seed, label), spread over actors as evenly as possible (equal quotas; an actor with fewer
candidates gives its spare quota to the others in actor order); `n: all` takes every failing span.
Each row: model, actor, report, chunk, sample, claimed transition, the span, whether it passes the
strict check, and the closest passage in the source chunk (best fuzzy match: difflib ratio over
windows of the span's length on the normalized chunk, coarse then refined) with its score.
The CSV holds CTI report text, so it is written under audit/ (gitignored), never committed.
"""
from __future__ import annotations

import csv
import difflib
import zlib

import numpy as np

from ctit.cti import extract
from ctit.experiments import v2_common as v2
from ctit.experiments.extraction import REPO_ROOT, jobs


def closest(span: str, source: str) -> tuple[str, float]:
    """Best-matching window of the source (normalized like the fragment check) and its difflib ratio."""
    s, src = extract._norm_frag(span), extract._norm_frag(source)
    n = len(s)
    if not n or not src:
        return "", 0.0
    if n >= len(src):
        return src, difflib.SequenceMatcher(None, s, src, autojunk=False).ratio()
    ratio = lambda i: difflib.SequenceMatcher(None, s, src[i:i + n], autojunk=False).ratio()
    step = max(1, n // 8)
    best = max(range(0, len(src) - n + 1, step), key=ratio)
    lo, hi = max(0, best - step), min(len(src) - n, best + step)
    best = max(range(lo, hi + 1), key=ratio)
    return src[best:best + n], ratio(best)


def candidates(spec, actors: list[str], texts: dict) -> list[dict]:
    rows = []
    for a in actors:
        for d in v2.load(spec, "R", a):
            for t in d["transitions"]:
                src = texts[t["doc_id"]][t["chunk"]]
                if not extract.evidence_ok_fragments(t["evidence_span"], src):
                    rows.append({"actor": a, "report": t["doc_id"], "chunk_id": f"{t['doc_id']}#{t['chunk']}",
                                 "sample": d["meta"]["sample"],
                                 "claimed_transition": f"{t['from_tactic']} -> {t['to_tactic']}",
                                 "evidence_span": t["evidence_span"], "strict_ok": t["evidence_ok"], "_src": src})
    return rows


def draw(rows: list[dict], actors: list[str], n, rng: np.random.Generator) -> list[dict]:
    if n == "all":
        return rows
    by = {a: [r for r in rows if r["actor"] == a] for a in actors}
    quota = {a: 0 for a in actors}
    left = min(n, len(rows))
    while left:  # one at a time round-robin over actors with candidates left: as even as possible
        for a in actors:
            if left and quota[a] < len(by[a]):
                quota[a] += 1
                left -= 1
    out = []
    for a in actors:
        idx = sorted(rng.choice(len(by[a]), quota[a], replace=False)) if quota[a] else []
        out += [by[a][i] for i in idx]
    return out


def run(config: dict, calls=None) -> dict:
    texts = {j["doc_id"]: extract.chunk(j["text"], **config["chunk"]) for j in jobs({**config, "conditions": ["R"]})}
    actors = config["actors"]
    rows, summary = [], {}
    for label, opt in config["models"].items():
        cand = candidates(config["priors"][label], actors, texts)
        rng = np.random.default_rng([config["seed"], zlib.crc32(label.encode())])
        picked = draw(cand, actors, opt["n"], rng)
        summary[label] = {"failing_spans": len(cand), "sampled": len(picked),
                          "by_actor": {a: [sum(r["actor"] == a for r in cand), sum(r["actor"] == a for r in picked)]
                                       for a in actors}}
        for r in picked:
            passage, score = closest(r["evidence_span"], r.pop("_src"))
            rows.append({"model": label, **r, "closest_passage": passage, "match_score": round(score, 4), "label": ""})
    out = REPO_ROOT / config["out"]
    out.parent.mkdir(parents=True, exist_ok=True)
    cols = ["model", "actor", "report", "chunk_id", "sample", "claimed_transition", "evidence_span", "strict_ok",
            "closest_passage", "match_score", "label"]
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)
    return {"note": "POST HOC (2026-10-31): evidence audit sample; labels: invented / paraphrase / wrong location / other",
            "out": config["out"], "rows": len(rows), "per_model": summary,
            "sha256_of_csv": __import__("hashlib").sha256(out.read_bytes()).hexdigest()}
