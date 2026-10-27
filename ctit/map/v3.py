"""Extended mapper v3 (SPEC_ISSUES 2026-10-26, B3): a frozen subset of the v2 compiled rules.

v3 = v2 rules minus, in order:
  a) level: informational (general policy);
  b) rules outside the shared subset: a rule is kept only if it is field-evaluable both on the
     OpTC conversion (ctit.ingest.optc.FIELDS) and on the Sysmon technique recordings;
  c) after restoring OpTC image paths where possible (ctit.ingest.optc, restore_bare):
     c2) rules whose path conditions still can't be evaluated on OpTC: they matched an event
         through a path field that holds a bare image name (no directory);
     c3) the create_remote_thread category.
The same subset applies to benign and injected events. The rule ids per step are frozen in
ctit/map/rules_v3.json (written by scripts/freeze_mapper_v3.py; committed = frozen).
"""
from __future__ import annotations

import json
import re
from functools import lru_cache
from pathlib import Path

from ctit.map.sigma_rules import load_compiled

RULES_V3 = Path(__file__).with_name("rules_v3.json")
MAPPER_VERSION = 3
PATH_FIELDS = ("Image", "ParentImage", "SourceImage", "TargetImage", "NewProcessName", "ParentProcessName")
REMOTE_THREAD = "rules/windows/create_remote_thread/"

_LITERAL = re.compile(r"'(?:[^']|'')*'")
_IDENT = re.compile(r"\b([A-Za-z_][A-Za-z0-9_.]*)\b")
_SQL_WORDS = {"AND", "OR", "NOT", "LIKE", "ESCAPE", "IN", "IS", "NULL", "REGEXP", "COALESCE",
              "COLLATE", "NOCASE", "GLOB", "LOWER", "UPPER", "CAST", "AS", "TEXT", "INTEGER"}
_CHANNEL = re.compile(r"Channel='([^']*)'")
_EID_EQ = re.compile(r"\bEventID=(\d+)")
_EID_IN = re.compile(r"\bEventID IN \(([\d, ]+)\)")


@lru_cache(maxsize=8192)
def referenced_fields(where: str) -> frozenset[str]:
    """Field names a compiled query reads (string literals removed first)."""
    bare = _LITERAL.sub("''", where)
    return frozenset(w for w in _IDENT.findall(bare) if w.upper() not in _SQL_WORDS and not w.isdigit())


def accepted_sources(where: str) -> tuple[set[str], set[int]]:
    """(channels, event ids) a query can match; an empty set means unconstrained."""
    eids = {int(x) for x in _EID_EQ.findall(where)}
    for grp in _EID_IN.findall(where):
        eids |= {int(x) for x in grp.split(",")}
    return set(_CHANNEL.findall(where)), eids


def evaluable(rule: dict, fields: dict[tuple[str, int], set[str]]) -> bool:
    """True if, for some (Channel, EventID) the rule accepts and the data has, every field the
    rule references is a non-null column there."""
    need = referenced_fields(rule["where"]) - {"Channel", "EventID"}
    chans, eids = accepted_sources(rule["where"])
    for (ch, eid), have in fields.items():
        if (not chans or ch in chans) and (not eids or eid in eids) and need <= have:
            return True
    return False


def bare_path_fields(row: dict) -> set[str]:
    """Path fields of one event that hold a bare name (non-empty, no backslash)."""
    return {f for f in PATH_FIELDS if isinstance(row.get(f), str) and row[f] and "\\" not in row[f]}


def load_frozen(path: Path = RULES_V3) -> dict:
    return json.loads(path.read_text())


def load_v3(path: Path = RULES_V3, base: list[dict] | None = None) -> list[dict]:
    """The v3 rule list: v2 compiled queries whose (id, variant) is in the frozen keep list."""
    keep = {(k["id"], k["variant"]) for k in load_frozen(path)["keep"]}
    return [r for r in (base if base is not None else load_compiled()) if (r["id"], r["variant"]) in keep]
