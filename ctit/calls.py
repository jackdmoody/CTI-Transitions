"""Append-only LLM call log (results/<run_id>/calls.jsonl). Stores a prompt hash, never the prompt."""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path


def prompt_sha256(prompt: str) -> str:
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


class CallLogger:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.touch()

    def log(
        self,
        *,
        model: str,
        prompt: str,
        input_tokens: int,
        output_tokens: int,
        latency_s: float,
        cost_usd: float | None,
        **extra,
    ) -> dict:
        record = {
            "ts": time.time(),
            "model": model,
            "prompt_sha256": prompt_sha256(prompt),
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "latency_s": latency_s,
            "cost_usd": cost_usd,
            **extra,
        }
        with self.path.open("a") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")
        return record
