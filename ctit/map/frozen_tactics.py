"""One label -> frozen-tactic mapping for every source (AICS-27 revision, internal review; 2026-11-05).

Before this module the 14-tactic scheme was reached by two routes: a shortname lookup
(ctit.map.attack.SHORTNAME, used by the plans, the Sigma tags and the ATT&CK STIX kill-chain phases)
and an exact display-name test (ctit.cti.schema, used by the extractions). to_frozen_tactic() is now
the single entry point for all of them; its per-source rules reproduce the old behaviour exactly
(tests/test_frozen_tactics.py checks that against every label in the plans, the cached extractions and
the pinned SigmaHQ release), so no frozen output changes.

Rules, in order, for a label from `source`:
- extraction: the frozen prompt (prompts/extract_v1.txt) asks for the 14 names "spelled exactly as
  written", so only an exact display name is accepted; anything else is dropped ("not an exact tactic
  name"), as ctit.cti.schema always did.
- plan: the label is normalized (lowercase, spaces -> '-', alias 'defensive-evasion' ->
  'defense-evasion') and looked up as an ATT&CK shortname. A label that is not a tactic (CALDERA's
  'stage-capabilities') is dropped here ("plan label is not a tactic"); the caller then falls back to
  the step technique's first-listed ATT&CK tactic (ctit.eval.plans).
- sigma: only tags 'attack.<shortname>' can name a tactic. Technique tags (attack.tNNNN[.NNN]),
  group/software tags (attack.gNNNN / attack.sNNNN), other 'attack.' tags and non-ATT&CK tags are dropped
  by name ("technique tag", "group/software tag", "attack tag is not a tactic", "not an attack tag").
- attack: a STIX kill-chain phase name, looked up as a shortname.
In every source, ATT&CK v19's 'stealth' and 'defense-impairment' fold into Defense Evasion (the
reversible lookup of docs/MAPPER_POLICY.md); for extraction they are not exact names, so they drop.
Every drop is counted in DROPS[(source, label, reason)] and logged at DEBUG level.
"""
from __future__ import annotations

import logging
import re
from collections import Counter

from ctit.map.attack import SHORTNAME, TACTICS

log = logging.getLogger(__name__)
SOURCES = ("plan", "extraction", "sigma", "attack")
PLAN_ALIASES = {"defensive-evasion": "defense-evasion"}  # as ctit.eval.plans.LABEL_ALIASES
FOLDED = {"stealth": "Defense Evasion", "defense-impairment": "Defense Evasion"}  # ATT&CK v19 split
_TECHNIQUE_TAG = re.compile(r"^attack\.t\d{4}(\.\d{3})?$", re.IGNORECASE)
_GROUP_SOFTWARE_TAG = re.compile(r"^attack\.[gs]\d{4}$", re.IGNORECASE)
DROPS: Counter = Counter()


def _drop(source: str, label, reason: str) -> None:
    DROPS[(source, str(label), reason)] += 1
    log.debug("to_frozen_tactic: dropped %r from %s (%s)", label, source, reason)


def drop_reason(label, source: str) -> str | None:
    """Why `label` from `source` maps to no frozen tactic, or None if it maps to one."""
    if source not in SOURCES:
        raise ValueError(f"unknown source {source!r}; one of {SOURCES}")
    if not isinstance(label, str):
        return "not a string"
    if source == "extraction":
        return None if label in TACTICS else "not an exact tactic name"
    if source == "sigma":
        if not label.lower().startswith("attack."):
            return "not an attack tag"
        if _TECHNIQUE_TAG.match(label):
            return "technique tag"
        if _GROUP_SOFTWARE_TAG.match(label):
            return "group/software tag"
        return None if label[len("attack."):].lower() in SHORTNAME else "attack tag is not a tactic"
    key = label.strip().lower().replace(" ", "-")
    if source == "plan":
        key = PLAN_ALIASES.get(key, key)
        return None if key in SHORTNAME else "plan label is not a tactic"
    return None if key in SHORTNAME else "kill-chain phase is not a tactic"  # attack


def to_frozen_tactic(label, source: str) -> str | None:
    """The frozen tactic (one of ctit.map.attack.TACTICS) that `label` from `source` names, or None if an
    explicit rule drops it (counted in DROPS and logged). See the module docstring for the rules."""
    reason = drop_reason(label, source)
    if reason is not None:
        _drop(source, label, reason)
        return None
    if source == "extraction":
        return label
    if source == "sigma":
        return SHORTNAME[label[len("attack."):].lower()]
    key = label.strip().lower().replace(" ", "-")
    return SHORTNAME[PLAN_ALIASES.get(key, key) if source == "plan" else key]
