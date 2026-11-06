"""ATT&CK reference data for the extended mapper (spec §2.5), on the 14-tactic scheme.

ATT&CK v19.0 split Defense Evasion into Stealth and Defense Impairment. The spec, DRIFT
and the emulation plans use the 14 pre-v19 tactics, so both new tactics collapse to
Defense Evasion here (docs/MAPPER_POLICY.md). Technique -> tactic lookups use v18.1 (the
last 14-tactic release) and fall back to v19.2 (collapsed) for techniques added in v19.
"""
from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
STIX_DIR = REPO_ROOT / "data" / "attack_stix"
STIX = {  # version -> sha256 of enterprise-attack-<version>.json
    "18.1": "f857d8f78f2f0c0b7db321a711a39fba98546c1e3076a657684850c83d0962fb",  # attack-stix-data
    "19.2": "dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4",  # attack-stix-data
    # mitre/cti tag ATT&CK-v6.3: the 2020 names the APT29 evals plan uses (validation only)
    "6.3": "c7b416f938e5bbfbc99832bb544b63197b6f1fbd4a3186f7571fb5be646f3917",
}

TACTICS = [  # ATT&CK Enterprise kill-chain order, 14-tactic scheme
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact",
]
SHORTNAME = {t.lower().replace(" ", "-"): t for t in TACTICS}
SHORTNAME.update({"stealth": "Defense Evasion", "defense-impairment": "Defense Evasion"})


def tactic_from_shortname(shortname: str) -> str | None:
    return SHORTNAME.get(shortname.lower())


@lru_cache(maxsize=None)
def _bundle(version: str) -> list[dict]:
    path = STIX_DIR / f"enterprise-attack-{version}.json"
    raw = path.read_bytes()
    if hashlib.sha256(raw).hexdigest() != STIX[version]:
        raise ValueError(f"{path} does not match the pinned sha256")
    return json.loads(raw)["objects"]


def _ext_id(obj: dict) -> str | None:
    return next((r["external_id"].upper() for r in obj.get("external_references", [])
                 if r.get("source_name") == "mitre-attack"), None)


@lru_cache(maxsize=None)
def _technique_tactics(version: str) -> dict[str, list[str]]:
    from ctit.map.frozen_tactics import to_frozen_tactic  # shared mapping (2026-11-05); no import cycle
    out: dict[str, list[str]] = {}
    for obj in _bundle(version):
        if obj["type"] != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext_id = _ext_id(obj)
        tactics = []
        for phase in obj.get("kill_chain_phases", []):
            t = to_frozen_tactic(phase["phase_name"], "attack")
            if phase["kill_chain_name"] == "mitre-attack" and t and t not in tactics:
                tactics.append(t)
        out[ext_id] = tactics
    return out


def technique_tactics(technique_id: str) -> list[str]:
    tid = technique_id.upper()
    for version in ("18.1", "19.2"):
        tactics = _technique_tactics(version).get(tid)
        if tactics:
            return tactics
    return []


@lru_cache(maxsize=None)
def technique_names(version: str) -> dict[str, str]:
    """Lowercased technique name -> ID (includes revoked/deprecated ones)."""
    return {obj["name"].strip().lower(): _ext_id(obj) for obj in _bundle(version)
            if obj["type"] == "attack-pattern" and _ext_id(obj)}


@lru_cache(maxsize=None)
def current_id(technique_id: str) -> str:
    """Follow revoked-by relationships in v18.1 (e.g. T1050 New Service -> T1543.003)."""
    objs = _bundle("18.1")
    by_stix = {o["id"]: o for o in objs if o["type"] == "attack-pattern"}
    by_ext = {_ext_id(o): o for o in by_stix.values() if _ext_id(o)}
    revoked = {r["source_ref"]: r["target_ref"] for r in objs
               if r["type"] == "relationship" and r.get("relationship_type") == "revoked-by"}
    obj = by_ext.get(technique_id.upper())
    seen = set()
    while obj is not None and obj["id"] in revoked and obj["id"] not in seen:
        seen.add(obj["id"])
        obj = by_stix.get(revoked[obj["id"]])
    return _ext_id(obj) if obj is not None else technique_id.upper()
