"""Secrets come from a gitignored .env at the repo root (template: .env.example)."""
from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

REPO_ROOT = Path(__file__).resolve().parents[1]
ANTHROPIC_API_KEY_VAR = "ANTHROPIC_API_KEY"


def anthropic_api_key() -> str:
    # A value already set in the shell wins over .env.
    load_dotenv(REPO_ROOT / ".env", override=False)
    key = os.environ.get(ANTHROPIC_API_KEY_VAR)
    if not key:
        raise RuntimeError(
            f"{ANTHROPIC_API_KEY_VAR} is not set. Copy .env.example to .env at "
            f"{REPO_ROOT} and fill it in."
        )
    return key
