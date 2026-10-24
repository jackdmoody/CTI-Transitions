"""Extraction output schema (spec §4.2-4.3), shared by F and S models.

A model returns a JSON list of
  {from_tactic, to_tactic, technique_from?, technique_to?, evidence_span, confidence}.
Tactics must be one of the 14 Enterprise tactics (exact names); other labels are rejected.
"""
from __future__ import annotations

import json
import re

from ctit.map.attack import TACTICS

TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
REQUIRED = ("from_tactic", "to_tactic", "evidence_span", "confidence")


class SchemaError(ValueError):
    """The response is not a JSON list of objects (retry once, then log and skip)."""


def parse(text: str) -> list:
    text = text.strip()
    fence = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, re.DOTALL)
    if fence:
        text = fence.group(1)
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise SchemaError(f"not JSON: {e}") from e
    if not isinstance(data, list) or not all(isinstance(x, dict) for x in data):
        raise SchemaError("expected a JSON list of objects")
    return data


def validate(items: list[dict]) -> tuple[list[dict], list[tuple[dict, str]]]:
    """-> (accepted transitions, [(rejected item, reason)])."""
    ok, rejected = [], []
    for it in items:
        missing = [k for k in REQUIRED if k not in it]
        if missing:
            rejected.append((it, f"missing {missing}"))
            continue
        bad = [k for k in ("from_tactic", "to_tactic") if it[k] not in TACTICS]
        if bad:
            rejected.append((it, f"not an Enterprise tactic: {[it[k] for k in bad]}"))
            continue
        try:
            conf = float(it["confidence"])
        except (TypeError, ValueError):
            rejected.append((it, "confidence not a number"))
            continue
        if not 0.0 <= conf <= 1.0:
            rejected.append((it, "confidence outside [0, 1]"))
            continue
        if not isinstance(it["evidence_span"], str) or not it["evidence_span"].strip():
            rejected.append((it, "empty evidence_span"))
            continue
        clean = {"from_tactic": it["from_tactic"], "to_tactic": it["to_tactic"],
                 "evidence_span": it["evidence_span"], "confidence": conf}
        for k in ("technique_from", "technique_to"):
            v = it.get(k)
            if v not in (None, ""):
                if not (isinstance(v, str) and TECHNIQUE_RE.match(v.upper())):
                    rejected.append((it, f"bad {k}: {v!r}"))
                    break
                clean[k] = v.upper()
        else:
            ok.append(clean)
    return ok, rejected
