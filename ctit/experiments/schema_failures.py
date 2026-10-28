"""Schema failures per model and mode, and the wrapping-only fix (POST HOC; SPEC_ISSUES 2026-10-27
21:14 EDT and its 21:15 clarification). No model calls: everything is replayed from the response cache.

1. Every cached response (first attempts and retries) that `ctit.cti.schema.parse` rejects is listed
   with its parser message and a class:
   - wrapping: exactly one JSON value, a list of objects, with only a fence (unclosed or mismatched)
     or prose before or after it;
   - multiple_values: the first JSON value decodes, and another JSON value (or attempted value)
     follows it. Choosing one of them is a content decision, so it is not a wrapping gap; reported
     apart, not fixed;
   - malformed: the first JSON value does not decode (bad escape, trailing comma, truncation ...);
   - not_list: decodes, but is not a list of objects;
   - no_json: no '[' or '{' at all.
   The JSON value is the one starting at the first '[' or '{' in the text, so a failed outer list is
   never replaced by something nested inside it. JSON content is never changed.
2. Fix variant: every job is replayed from the cache through the run-time code path
   (ctit.experiments.extraction._run_job, so validation and evidence checks are unchanged). A first
   attempt of class `wrapping` is handed to the parser as its JSON substring; every other response is
   replayed as cached, so all other chunks keep their as-run outcome. The priors go to
   data/priors/<run>/<mode>__unwrap/. The as-run replay (no fix) must reproduce the saved priors exactly.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import numpy as np
import yaml

from ctit.cti import extract, schema
from ctit.experiments.extraction import ALIASES, PRIORS, _run_job, jobs, write_prior
from ctit.experiments.extraction_report import _caches
from ctit.experiments.redteam_scoring import run_dir

FENCE_ONLY = re.compile(r"^\s*(```[A-Za-z]*\s*)*$")
SUFFIX = "__unwrap"


def _next_value(s: str, start: int = 0):
    """-> (index of the first '[' or '{' at or after start, decoded value or None, end or None, error)."""
    i = next((k for k in range(start, len(s)) if s[k] in "[{"), None)
    if i is None:
        return None, None, None, None
    try:
        v, end = json.JSONDecoder().raw_decode(s, i)
        return i, v, end, None
    except json.JSONDecodeError as e:
        return i, None, None, str(e)


def classify(text: str) -> dict:
    """-> {"class", "message", "detail", "json"} (json: the substring to parse, wrapping only)."""
    try:
        schema.parse(text)
        return {"class": "ok", "message": None, "detail": None, "json": None}
    except schema.SchemaError as e:
        msg = str(e)
    out = {"class": None, "message": msg, "detail": None, "json": None}
    i, v, end, err = _next_value(text)
    if i is None:
        return out | {"class": "no_json"}
    if err is not None:
        return out | {"class": "malformed", "detail": err}
    j, v2, _, err2 = _next_value(text, end)
    if j is not None:
        same = err2 is None and v2 == v
        return out | {"class": "multiple_values",
                      "detail": f"first value {_shape(v)}; next value {'malformed' if err2 else _shape(v2)}"
                                + (" (identical)" if same else "")}
    if not isinstance(v, list) or not all(isinstance(x, dict) for x in v):
        return out | {"class": "not_list", "detail": _shape(v)}
    pre, post = text[:i], text[end:]
    where = [f"{side}: {'fence' if FENCE_ONLY.match(part) else 'prose'}"
             for side, part in (("before", pre), ("after", post)) if part.strip()]
    return out | {"class": "wrapping", "detail": "; ".join(where), "json": text[i:end]}


def _shape(v) -> str:
    if isinstance(v, list):
        return f"list of {len(v)}" + ("" if all(isinstance(x, dict) for x in v) else " (not all objects)")
    return type(v).__name__


class Replay:
    """A model that only reads the cache (no calls). unwrap=True hands the parser the JSON substring of
    a first attempt whose class is `wrapping`."""

    def __init__(self, d: Path, unwrap: bool):
        self.dir, self.unwrap, self.name, self.used = d, unwrap, d.name, []

    def chat(self, prompt: str, calls=None, *, system: str | None = None, attempt: int = 1) -> str:
        h = hashlib.sha256(((system or "") + prompt).encode()).hexdigest()
        rec = json.loads((self.dir / (f"{h}.json" if attempt == 1 else f"{h}.a{attempt}.json")).read_text())
        if "refusal" in rec:
            raise extract.Refusal(rec["refusal"])
        if self.unwrap and attempt == 1:
            c = classify(rec["text"])
            if c["class"] == "wrapping":
                self.used.append(h)
                return c["json"]
        return rec["text"]


def _job_prompts(job, templates, aliases, ck) -> list[tuple[int, str]]:
    if job["cond"] == "B":
        return [(0, extract.render(templates["memory"], tactics=extract.tactic_list(), actor=job["actor"],
                                   aliases=", ".join(aliases[job["actor"]]["aliases"])))]
    return [(i, extract.render(templates["report"], tactics=extract.tactic_list(), text=c))
            for i, c in enumerate(extract.chunk(job["text"], **ck))]


def run(config: dict, calls=None) -> dict:
    templates = {k: extract.load_prompt(v) for k, v in config["prompts"].items()}
    aliases = yaml.safe_load(ALIASES.read_text())["actors"]
    ck = config["chunk"]
    caches = _caches(PRIORS / "cache", config["ollama_labels"])
    todo = jobs(config)
    out: dict = {"note": "POST HOC (2026-10-27 21:14 EDT rule): schema failures and the wrapping-only fix",
                 "failures": {}, "counts": {}, "fix": {}}
    for mode, spec in config["runs"].items():
        run_id, sub = run_dir(spec)
        src = PRIORS / run_id / (sub or mode)
        samples = sorted(s for (m, s) in caches if m == mode)
        rows, fix = [], {}
        groups: dict[tuple[str, str], list[dict]] = {}
        for job in todo:
            groups.setdefault((job["cond"], job["actor"]), []).append(job)
        for s in samples:
            d = caches[(mode, s)]
            for (cond, actor), group in groups.items():
                asrun = src / f"{cond}_{actor}_{s}.json"
                if not asrun.exists():
                    continue
                for job, (i, p) in ((j, x) for j in group for x in _job_prompts(j, templates, aliases, ck)):
                    h = hashlib.sha256(p.encode()).hexdigest()
                    for attempt, name in ((1, f"{h}.json"), (2, f"{h}.a2.json")):
                        f = d / name
                        rec = json.loads(f.read_text()) if f.exists() else {}
                        if "text" not in rec:
                            continue
                        c = classify(rec["text"])
                        if c["class"] != "ok":
                            rows.append({"sample": s, "cond": job["cond"], "actor": job["actor"],
                                         "doc": job["doc_id"], "chunk": i, "attempt": attempt,
                                         **{k: c[k] for k in ("class", "message", "detail")},
                                         "used_in_fix": attempt == 1 and c["class"] == "wrapping"})
                # replay both ways through the run-time code path
                saved = json.loads(asrun.read_text())
                meta = {k: saved["meta"][k] for k in ("mode", "cond", "actor", "sample")}
                plain = [r for j in group for r in _run_job(j, Replay(d, False), templates, aliases, None, ck)]
                C0 = extract.build_prior(plain, config["alpha"])["counts"]
                if C0 != saved["counts"]:
                    raise RuntimeError(f"replay does not reproduce {asrun}")
                m = Replay(d, True)
                res = [r for j in group for r in _run_job(j, m, templates, aliases, None, ck)]
                p = write_prior(PRIORS / run_id / f"{sub or mode}{SUFFIX}" / asrun.name, res, config["alpha"],
                                meta | {"variant": "wrapping-only fix (post hoc)"})
                if m.used:
                    C1 = np.array(p["counts"])
                    fix[f"{cond}/{actor}/{s}"] = {
                        "chunks_fixed": len(m.used), "edges_as_run": int((np.array(C0) > 0).sum()),
                        "edges_fixed": int((C1 > 0).sum()), "counts_changed": p["counts"] != C0}
        out["failures"][mode] = rows
        cnt: dict = {}
        for r in rows:
            k = f"attempt{r['attempt']}"
            cnt.setdefault(k, {}).setdefault(r["class"], 0)
            cnt[k][r["class"]] += 1
        out["counts"][mode] = cnt
        out["fix"][mode] = {"priors_dir": f"{run_id}/{sub or mode}{SUFFIX}", "changed": fix,
                            "first_attempts_fixed": sum(v["chunks_fixed"] for v in fix.values()),
                            "priors_with_changed_counts": sum(v["counts_changed"] for v in fix.values())}
    return out
