"""CTI -> tactic-transition prior (spec §4). One code path for F (Anthropic API) and S (Ollama).

1. chunk(): ~6k tokens with 300 overlap, identical for F and S (2026-10-27). No tokenizer is
   pinned, so token counts are approximated as characters / 4 and chunk edges snap to
   whitespace (deterministic).
2. The prompt template (prompts/extract_v1.txt) is filled with <<TACTICS>> and <<TEXT>>;
   memory_v1.txt (no-report condition, §4.6) gets <<TACTICS>>, <<ACTOR>> and <<ALIASES>>
   (configs/actor_aliases.yaml).
3. The response is parsed and validated with ctit.cti.schema (14 tactics only, no
   self-transitions). A response that isn't a JSON list of objects is retried once, then
   logged and skipped.
4. Evidence check (§4.5): an evidence_span must be a substring of the chunk it came from,
   after collapsing whitespace (strict). Fragment-aware variant (pre-registered 2026-10-27,
   before any recovery metric): split the span on "..." and "\u2026"; normalize whitespace,
   curly quotes and dashes on both sides; every fragment of >= 8 characters must appear
   verbatim in the source, in order. A span with no fragment of >= 8 characters fails.
   Both rates are reported. Unsupported spans (strict) are counted and, with
   require_evidence=True, left out of the counts.
5. Aggregation (2026-10-27): one count per (document, edge): an edge seen in several chunks
   or places of one report counts once for that report, and a no-report sample is one
   document. Prior = row-normalized (C + alpha), so each report weighs the same whatever
   its length. The raw per-mention counts are kept as an appendix variant. One prior is
   built per model sample; F and S-sampled report mean ± sd over their 5 samples.

Models are anything with .name and .chat(prompt, calls, system=None) -> str. AnthropicModel
wraps the pinned frontier model; ctit.llm.ollama.OllamaModel already has that shape.
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from ctit.cti import prior, schema
from ctit.map.attack import TACTICS

REPO_ROOT = Path(__file__).resolve().parents[2]
PROMPTS = REPO_ROOT / "prompts"
CHARS_PER_TOKEN = 4
_WS = re.compile(r"\s+")


# ----------------------------------------------------------------------------- chunking

CHUNK_TOKENS, CHUNK_OVERLAP = 6000, 300


def chunk(text: str, tokens: int = CHUNK_TOKENS, overlap: int = CHUNK_OVERLAP,
          chars_per_token: int = CHARS_PER_TOKEN) -> list[str]:
    size, step = tokens * chars_per_token, (tokens - overlap) * chars_per_token
    if len(text) <= size:
        return [text] if text.strip() else []
    out, start = [], 0
    while start < len(text):
        end = min(start + size, len(text))
        if end < len(text):  # snap the end back to whitespace
            ws = text.rfind(" ", start + step, end)
            end = ws if ws > start else end
        out.append(text[start:end])
        if end >= len(text):
            break
        nxt = start + step
        ws = text.rfind(" ", start, nxt)  # snap the next start back to whitespace
        start = ws + 1 if ws > start else nxt
    return out


# ----------------------------------------------------------------------------- prompts

def load_prompt(name: str, root: Path = PROMPTS) -> str:
    return (root / name).read_text()


def render(template: str, **fields: str) -> str:
    out = template
    for k, v in fields.items():
        out = out.replace(f"<<{k.upper()}>>", v)
    if re.search(r"<<[A-Z_]+>>", out):
        raise ValueError(f"unfilled placeholder in prompt: {re.findall(r'<<[A-Z_]+>>', out)}")
    return out


def tactic_list() -> str:
    return "\n".join(f"- {t}" for t in TACTICS)


# ----------------------------------------------------------------------------- evidence

def normalize(s: str) -> str:
    return _WS.sub(" ", s).strip()


def evidence_ok(span: str, source: str) -> bool:
    return bool(normalize(span)) and normalize(span) in normalize(source)


_PUNCT = str.maketrans({"\u2018": "'", "\u2019": "'", "\u201a": "'", "\u201b": "'", "\u2032": "'",
                        "\u201c": '"', "\u201d": '"', "\u201e": '"', "\u201f": '"', "\u2033": '"',
                        "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-", "\u2014": "-",
                        "\u2015": "-", "\u2212": "-"})
_ELLIPSIS = re.compile(r"\.\.\.|\u2026")
MIN_FRAGMENT = 8


def _norm_frag(s: str) -> str:
    return normalize(s.translate(_PUNCT))


def evidence_ok_fragments(span: str, source: str) -> bool:
    frags = [f for f in (_norm_frag(x) for x in _ELLIPSIS.split(span)) if len(f) >= MIN_FRAGMENT]
    if not frags:
        return False
    src, pos = _norm_frag(source), 0
    for f in frags:
        i = src.find(f, pos)
        if i < 0:
            return False
        pos = i + len(f)
    return True


# ----------------------------------------------------------------------------- models

class AnthropicModel:
    """The pinned frontier model (configs/models.yaml: frontier.F). Opus 5.5 rejects sampling
    parameters and can't disable thinking, so only `effort` and `max_tokens` are sent. A
    refusal (stop_reason "refusal") raises Refusal; no server-side fallback model is used,
    because a different model answering would contaminate the F condition."""

    def __init__(self, pin: dict, client=None):
        self.pin = pin
        self.name = pin["model"]
        self._client = client

    @property
    def client(self):
        if self._client is None:
            import anthropic

            from ctit.env import anthropic_api_key
            self._client = anthropic.Anthropic(api_key=anthropic_api_key(), max_retries=8)
        return self._client

    def chat(self, prompt: str, calls=None, *, system: str | None = None, attempt: int = 1) -> str:
        import time
        opts = dict(self.pin.get("options", {}))
        kwargs = {"model": self.name, "max_tokens": int(opts.get("max_tokens", 16000)),
                  "messages": [{"role": "user", "content": prompt}]}
        if system:
            kwargs["system"] = system
        if "effort" in opts:
            kwargs["output_config"] = {"effort": opts["effort"]}
        t0 = time.monotonic()
        resp = self.client.messages.create(**kwargs)
        latency = time.monotonic() - t0
        u = resp.usage
        price = self.pin.get("usd_per_mtok", {})
        cost = ((u.input_tokens * price["input"] + u.output_tokens * price["output"]) / 1e6
                if price else None)
        if calls is not None:
            calls.log(model=self.name, prompt=(system or "") + prompt, input_tokens=u.input_tokens,
                      output_tokens=u.output_tokens, latency_s=latency, cost_usd=cost,
                      stop_reason=resp.stop_reason, request_id=getattr(resp, "_request_id", None),
                      options=opts, attempt=attempt)
        if resp.stop_reason == "refusal":
            raise Refusal(str(getattr(resp, "stop_details", None)))
        return "".join(b.text for b in resp.content if b.type == "text")


class Refusal(RuntimeError):
    pass


# ----------------------------------------------------------------------------- extraction

@dataclass
class ChunkResult:
    doc_id: str
    index: int
    status: str                      # ok | skipped_schema | refused
    attempts: int
    transitions: list[dict] = field(default_factory=list)
    rejected: list[tuple[dict, str]] = field(default_factory=list)


def ask(model, prompt: str, calls=None, retries: int = 1) -> tuple[list[dict] | None, int, str]:
    """-> (items or None, attempts, status). Retries a schema failure `retries` times. Each attempt
    is passed to the model, so a caching wrapper stores it separately and a retry is a fresh call
    (SPEC_ISSUES 2026-10-27: the cache used to replay the failed response)."""
    for attempt in range(1, retries + 2):
        try:
            text = model.chat(prompt, calls, attempt=attempt)
        except Refusal:
            return None, attempt, "refused"
        try:
            return schema.parse(text), attempt, "ok"
        except schema.SchemaError:
            continue
    return None, retries + 1, "skipped_schema"


def extract_chunk(model, template: str, text: str, doc_id: str, index: int, calls=None) -> ChunkResult:
    items, attempts, status = ask(model, render(template, tactics=tactic_list(), text=text), calls)
    res = ChunkResult(doc_id, index, status, attempts)
    if items is None:
        return res
    ok, res.rejected = schema.validate(items)
    for t in ok:
        t["evidence_ok"] = evidence_ok(t["evidence_span"], text)
        t["evidence_ok_fragments"] = evidence_ok_fragments(t["evidence_span"], text)
        t["doc_id"], t["chunk"] = doc_id, index
    res.transitions = ok
    return res


def extract_report(model, template: str, text: str, doc_id: str, calls=None, **chunk_kw) -> list[ChunkResult]:
    return [extract_chunk(model, template, c, doc_id, i, calls) for i, c in enumerate(chunk(text, **chunk_kw))]


def memory_transitions(model, template: str, actor: str, calls=None, aliases: list[str] = (),
                       sample: int | None = None) -> ChunkResult:
    """No-report condition (§4.6): one call per sample, same output schema, no source text to
    check. Each sample is its own document for aggregation."""
    prompt = render(template, tactics=tactic_list(), actor=actor, aliases=", ".join(aliases))
    items, attempts, status = ask(model, prompt, calls)
    res = ChunkResult(f"memory:{actor}" + ("" if sample is None else f"#s{sample}"), 0, status, attempts)
    if items is not None:
        res.transitions, res.rejected = schema.validate(items)
        for t in res.transitions:
            t["evidence_ok"] = None
            t["doc_id"], t["chunk"] = res.doc_id, 0
    return res


# ----------------------------------------------------------------------------- aggregation

def counts(transitions: list[dict], require_evidence: bool = False, per_document: bool = True) -> np.ndarray:
    """per_document=True: one count per (doc_id, edge) (primary). False: every mention counts."""
    C = np.zeros((len(TACTICS), len(TACTICS)))
    seen = set()
    for t in transitions:
        if require_evidence and t.get("evidence_ok") is False:
            continue
        key = (t.get("doc_id"), t["from_tactic"], t["to_tactic"])
        if per_document and key in seen:
            continue
        seen.add(key)
        C[prior.INDEX[t["from_tactic"]], prior.INDEX[t["to_tactic"]]] += 1
    return C


def summarize(results: list[ChunkResult]) -> dict:
    trans = [t for r in results for t in r.transitions]
    checked = [t for t in trans if t.get("evidence_ok") is not None]
    return {
        "chunks": len(results),
        "chunk_status": {s: sum(r.status == s for r in results) for s in ("ok", "skipped_schema", "refused")},
        "retried": sum(r.attempts > 1 for r in results),
        "transitions": len(trans),
        "rejected_items": sum(len(r.rejected) for r in results),
        "rejected_by_reason": dict(Counter(_reason(why) for r in results for _, why in r.rejected)),
        "chunks_per_doc": dict(Counter(r.doc_id for r in results)),
        "hallucinated_span_rate": (sum(not t["evidence_ok"] for t in checked) / len(checked)) if checked else None,
        "hallucinated_span_rate_fragments": (sum(not t["evidence_ok_fragments"] for t in checked) / len(checked))
        if checked else None,
    }


def _reason(why: str) -> str:
    return why.split(":")[0].split(" (")[0]


def build_prior(results: list[ChunkResult], alpha: float = prior.ALPHA, require_evidence: bool = False,
                meta: dict | None = None) -> dict:
    """Primary prior from per-document counts; the per-mention counts and their prior are the
    appendix variant."""
    trans = [t for r in results for t in r.transitions]
    C = counts(trans, require_evidence)
    M = counts(trans, require_evidence, per_document=False)
    return {"tactics": list(TACTICS), "matrix": prior.from_counts(C, alpha).tolist(), "counts": C.astype(int).tolist(),
            "matrix_mentions": prior.from_counts(M, alpha).tolist(), "counts_mentions": M.astype(int).tolist(),
            "meta": {"alpha": alpha, "require_evidence": require_evidence, "aggregation": "per_document",
                     **summarize(results), **(meta or {})}}


def template_sha256(template: str) -> str:
    return hashlib.sha256(template.encode()).hexdigest()
