"""CTI -> tactic-transition prior (spec §4). One code path for F (Anthropic API) and S (Ollama).

1. chunk(): ~2k tokens with 200 overlap. No tokenizer is pinned, so token counts are
   approximated as characters / 4 and chunk edges snap to whitespace (deterministic).
2. The prompt template (prompts/extract_v1.txt) is filled with <<TACTICS>> and <<TEXT>>;
   memory_v1.txt (no-report condition, §4.6) gets <<TACTICS>> and <<ACTOR>>.
3. The response is parsed and validated with ctit.cti.schema (14 tactics only). A response
   that isn't a JSON list of objects is retried once, then logged and skipped.
4. Evidence check (§4.5): an evidence_span must be a substring of the chunk it came from,
   after collapsing whitespace. Unsupported spans are counted (hallucinated-span rate) and,
   with require_evidence=True, left out of the counts.
5. Aggregation: count matrix C over the 14 tactics, prior = row-normalized (C + alpha).

Models are anything with .name and .chat(prompt, calls, system=None) -> str. AnthropicModel
wraps the pinned frontier model; ctit.llm.ollama.OllamaModel already has that shape.
"""
from __future__ import annotations

import hashlib
import re
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

def chunk(text: str, tokens: int = 2000, overlap: int = 200,
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
            self._client = anthropic.Anthropic(api_key=anthropic_api_key())
        return self._client

    def chat(self, prompt: str, calls=None, *, system: str | None = None) -> str:
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
                      options=opts)
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
    """-> (items or None, attempts, status). Retries a schema failure `retries` times."""
    for attempt in range(1, retries + 2):
        try:
            text = model.chat(prompt, calls)
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
        t["doc_id"], t["chunk"] = doc_id, index
    res.transitions = ok
    return res


def extract_report(model, template: str, text: str, doc_id: str, calls=None, **chunk_kw) -> list[ChunkResult]:
    return [extract_chunk(model, template, c, doc_id, i, calls) for i, c in enumerate(chunk(text, **chunk_kw))]


def memory_transitions(model, template: str, actor: str, calls=None) -> ChunkResult:
    """No-report condition (§4.6): one call, same output schema, no source text to check."""
    items, attempts, status = ask(model, render(template, tactics=tactic_list(), actor=actor), calls)
    res = ChunkResult(f"memory:{actor}", 0, status, attempts)
    if items is not None:
        res.transitions, res.rejected = schema.validate(items)
        for t in res.transitions:
            t["evidence_ok"] = None
    return res


# ----------------------------------------------------------------------------- aggregation

def counts(transitions: list[dict], require_evidence: bool = False) -> np.ndarray:
    C = np.zeros((len(TACTICS), len(TACTICS)))
    for t in transitions:
        if require_evidence and t.get("evidence_ok") is False:
            continue
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
        "hallucinated_span_rate": (sum(not t["evidence_ok"] for t in checked) / len(checked)) if checked else None,
    }


def build_prior(results: list[ChunkResult], alpha: float = prior.ALPHA, require_evidence: bool = False,
                meta: dict | None = None) -> dict:
    C = counts([t for r in results for t in r.transitions], require_evidence)
    P = prior.from_counts(C, alpha)
    return {"tactics": list(TACTICS), "matrix": P.tolist(), "counts": C.astype(int).tolist(),
            "meta": {"alpha": alpha, "require_evidence": require_evidence, **summarize(results), **(meta or {})}}


def template_sha256(template: str) -> str:
    return hashlib.sha256(template.encode()).hexdigest()
