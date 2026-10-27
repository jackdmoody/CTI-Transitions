"""Local open-weight models (spec §3, S) through Ollama's HTTP API on localhost.

Pinned in configs/models.yaml: tag, weights_sha256 (GGUF model layer), and options.
verify() refuses to run a model whose local weights differ from the pin. Every call is
logged to the run's calls.jsonl (prompt hash only).
"""
from __future__ import annotations

import json
import time
import urllib.request
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
MODELS = REPO_ROOT / "configs" / "models.yaml"
OLLAMA_URL = "http://127.0.0.1:11434"
MANIFESTS = Path.home() / ".ollama" / "models" / "manifests" / "registry.ollama.ai" / "library"
MODEL_LAYER = "application/vnd.ollama.image.model"


class DigestMismatch(RuntimeError):
    pass


def pinned(slot: str, path: Path = MODELS) -> dict:
    return yaml.safe_load(path.read_text())["open_weight"][slot]


def local_weights_digest(tag: str, manifests: Path = MANIFESTS) -> str:
    name, _, version = tag.partition(":")
    manifest = json.loads((manifests / name / (version or "latest")).read_text())
    (layer,) = [l for l in manifest["layers"] if l["mediaType"] == MODEL_LAYER]
    return layer["digest"].removeprefix("sha256:")


class OllamaModel:
    """sample=None runs the pinned `options` (temperature 0). sample=i runs the pinned
    `sampled` mode (the model's default sampling) with seed `sampled.seeds[i]` (spec §3)."""

    def __init__(self, slot: str, *, url: str = OLLAMA_URL, models_path: Path = MODELS,
                 manifests: Path = MANIFESTS, sample: int | None = None):
        self.slot = slot
        self.pin = pinned(slot, models_path)
        self.url = url
        self.manifests = manifests
        if sample is None:
            self.options = dict(self.pin.get("options", {}))
        else:
            sampled = self.pin["sampled"]
            self.options = {**sampled["options"], "seed": sampled["seeds"][sample]}
        self.name = self.pin["tag"] if sample is None else f"{self.pin['tag']}#sample{sample}"

    def verify(self) -> None:
        got = local_weights_digest(self.pin["tag"], self.manifests)
        if got != self.pin["weights_sha256"]:
            raise DigestMismatch(f"{self.pin['tag']}: local weights {got} != pinned {self.pin['weights_sha256']}")

    def chat(self, prompt: str, calls=None, *, system: str | None = None) -> str:
        opts = dict(self.options)
        think = opts.pop("think", None)
        body = {
            "model": self.pin["tag"], "stream": False, "options": opts,
            "messages": ([{"role": "system", "content": system}] if system else [])
                        + [{"role": "user", "content": prompt}],
        }
        if think is not None:
            body["think"] = think
        req = urllib.request.Request(f"{self.url}/api/chat", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"})
        t0 = time.monotonic()
        with urllib.request.urlopen(req, timeout=600) as resp:
            out = json.loads(resp.read())
        latency = time.monotonic() - t0
        if calls is not None:
            calls.log(model=self.pin["tag"], prompt=(system or "") + prompt,
                      input_tokens=int(out.get("prompt_eval_count", 0)),
                      output_tokens=int(out.get("eval_count", 0)),
                      latency_s=latency, cost_usd=0.0,
                      weights_sha256=self.pin["weights_sha256"], options=opts)
        return out["message"]["content"]
