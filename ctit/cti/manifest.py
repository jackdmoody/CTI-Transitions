"""CTI manifest (spec §1): data/cti/manifest.csv, one row per saved report text.

The manifest lives under data/ (gitignored). This module is its schema and the leakage
rules; scripts/check_leakage.py is the CLI.
"""
from __future__ import annotations

import csv
import hashlib
import re
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = REPO_ROOT / "data" / "cti" / "manifest.csv"
TEXT_DIR = REPO_ROOT / "data" / "cti" / "text"  # saved report text: <doc_id>.txt
ACTORS_PATH = REPO_ROOT / "configs" / "actors.yaml"

COLUMNS = [
    "doc_id", "actor", "nation", "source_org", "url", "pub_date", "sha256",
    "used_for", "cited_by_emulation_plan",
]
USED_FOR = {"prior", "eval"}
YES_NO = {"y", "n"}
MIN_PRIOR_DOCS = 2
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# Eval sequences must never come from ATT&CK group mappings (those are the ATTK baseline).
ATTACK_GROUP_URL_RE = re.compile(r"attack\.mitre\.org/groups/", re.IGNORECASE)


def write_empty(path: Path = MANIFEST_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="") as f:
        csv.writer(f).writerow(COLUMNS)


def load(path: Path = MANIFEST_PATH) -> tuple[list[str], list[dict]]:
    with Path(path).open(newline="") as f:
        reader = csv.DictReader(f)
        return list(reader.fieldnames or []), list(reader)


def load_actors(path: Path = ACTORS_PATH) -> dict[str, dict]:
    return yaml.safe_load(Path(path).read_text())["actors"]


def check(
    header: list[str],
    rows: list[dict],
    actors: dict[str, dict],
    *,
    text_dir: Path | None = None,
) -> list[str]:
    """Return every violation; empty means the manifest passes."""
    if header != COLUMNS:
        return [f"header must be exactly {COLUMNS}, got {header}"]

    errors: list[str] = []
    seen_ids: set[str] = set()
    for n, r in enumerate(rows, start=2):  # line 1 is the header
        where = f"line {n} ({r['doc_id'] or '<no doc_id>'})"
        if not r["doc_id"]:
            errors.append(f"{where}: empty doc_id")
        elif r["doc_id"] in seen_ids:
            errors.append(f"{where}: duplicate doc_id")
        seen_ids.add(r["doc_id"])
        if r["actor"] not in actors:
            errors.append(f"{where}: unknown actor {r['actor']!r} (configs/actors.yaml)")
        elif r["nation"] != actors[r["actor"]]["nation"]:
            errors.append(f"{where}: nation {r['nation']!r} != {actors[r['actor']]['nation']!r}")
        if r["used_for"] not in USED_FOR:
            errors.append(f"{where}: used_for must be one of {sorted(USED_FOR)}")
        if r["cited_by_emulation_plan"] not in YES_NO:
            errors.append(f"{where}: cited_by_emulation_plan must be y or n")
        if not SHA256_RE.match(r["sha256"]):
            errors.append(f"{where}: sha256 must be 64 lowercase hex chars")
        if not DATE_RE.match(r["pub_date"]):
            errors.append(f"{where}: pub_date must be YYYY-MM-DD")
        if not r["url"]:
            errors.append(f"{where}: empty url")

        # Leakage rules (spec §1).
        if r["used_for"] == "prior" and r["cited_by_emulation_plan"] == "y":
            errors.append(f"{where}: LEAKAGE: prior doc is cited by the emulation plan")
        if r["used_for"] == "eval" and ATTACK_GROUP_URL_RE.search(r["url"]):
            errors.append(f"{where}: LEAKAGE: eval doc is an ATT&CK group mapping")

        if text_dir is not None and SHA256_RE.match(r["sha256"]):
            text = text_dir / f"{r['doc_id']}.txt"
            if not text.exists():
                errors.append(f"{where}: saved text {text} missing")
            elif hashlib.sha256(text.read_bytes()).hexdigest() != r["sha256"]:
                errors.append(f"{where}: sha256 does not match {text}")

    # A document in both roles, matched by content hash or URL, not just doc_id.
    for key in ("sha256", "url"):
        roles_by_key: dict[str, set[str]] = {}
        for r in rows:
            if r[key]:
                roles_by_key.setdefault(r[key], set()).add(r["used_for"])
        for value, roles in sorted(roles_by_key.items()):
            if {"prior", "eval"} <= roles:
                errors.append(f"LEAKAGE: same {key} used as both prior and eval: {value}")

    priors: dict[str, int] = {}
    present: set[str] = set()
    for r in rows:
        present.add(r["actor"])
        if r["used_for"] == "prior":
            priors[r["actor"]] = priors.get(r["actor"], 0) + 1
    for actor, info in actors.items():
        if info["core"] or actor in present:
            if priors.get(actor, 0) < MIN_PRIOR_DOCS:
                errors.append(
                    f"actor {actor}: {priors.get(actor, 0)} prior docs, need >= {MIN_PRIOR_DOCS}"
                )
    return errors
