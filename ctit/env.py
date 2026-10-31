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


OPENAI_API_KEY_VAR = "OPENAI_API_KEY"  # G, second frontier API (approved by Jack 2026-10-31; CLAUDE.md rule 3)


def openai_api_key() -> str:
    load_dotenv(REPO_ROOT / ".env", override=False)
    key = os.environ.get(OPENAI_API_KEY_VAR)
    if not key:
        raise RuntimeError(f"{OPENAI_API_KEY_VAR} is not set in {REPO_ROOT / '.env'}.")
    return key
