"""Compile SigmaHQ Windows rules to SQLite queries with tactics (spec §2.5).

    python -m ctit.map.sigma_rules   # writes ctit/map/compiled_rules.jsonl (committed = frozen)

Rule selection and the tactic policy are documented in docs/MAPPER_POLICY.md.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

from sigma.backends.sqlite import sqliteBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.sysmon import sysmon_pipeline
from sigma.pipelines.windows import windows_logsource_pipeline

from ctit.map import attack

REPO_ROOT = Path(__file__).resolve().parents[2]
SIGMA_ROOT = REPO_ROOT / "third_party" / "sigma"
SIGMA_TAG = "r2026-07-01"
SIGMA_COMMIT = "552f3fee420ef232a8e5790c4fae591847e32347"
RULES_DIR = SIGMA_ROOT / "rules" / "windows"  # not rules-emerging-threats / -threat-hunting / -dfir
COMPILED = Path(__file__).with_name("compiled_rules.jsonl")

SYSMON_CATEGORIES = {
    "process_creation", "network_connection", "process_access", "create_remote_thread",
    "image_load", "driver_load", "file_event", "file_access", "file_change", "file_delete",
    "file_rename", "file_executable_detected", "registry_add", "registry_delete",
    "registry_set", "registry_rename", "registry_event", "dns_query", "pipe_created",
    "wmi_event", "create_stream_hash", "raw_access_thread", "process_tampering",
    "sysmon_status", "sysmon_error", "clipboard_capture", "process_termination",
}
SERVICES = {"security", "system", "sysmon"}
EXCLUDED_STATUS = {"deprecated", "unsupported"}
LEVEL_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}
STATUS_RANK = {"stable": 2, "test": 1, "experimental": 0}
GROUP_OR_SOFTWARE_TAG = re.compile(r"^attack\.[gs]\d{4}$")
TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$")


def _sigma_commit() -> str:
    head = subprocess.run(["git", "-C", str(SIGMA_ROOT), "rev-parse", "HEAD"],
                          capture_output=True, text=True, check=True).stdout.strip()
    if head != SIGMA_COMMIT:
        raise RuntimeError(f"third_party/sigma is at {head}, expected {SIGMA_COMMIT} ({SIGMA_TAG})")
    return head


def rule_tactics(tags: list[str]) -> tuple[list[str], list[str], str]:
    """(tactics in the rule's tag order, technique ids, provenance). Tactic tags win; else
    ATT&CK technique -> tactic for each technique tag, in tag order."""
    tactics, techniques = [], []
    for tag in tags:
        if tag.startswith("attack."):
            t = attack.tactic_from_shortname(tag[len("attack."):])
            if t and t not in tactics:
                tactics.append(t)
            m = TECHNIQUE_TAG.match(tag)
            if m:
                techniques.append(m.group(1).upper())
    if tactics:
        return tactics, techniques, "rule_tag"
    for tid in techniques:
        for t in attack.technique_tactics(tid):
            if t not in tactics:
                tactics.append(t)
    return tactics, techniques, "attack_technique" if tactics else "none"


def select(rule) -> str | None:
    """Reason to skip a rule, or None to keep it."""
    ls = rule.logsource
    if ls.product != "windows":
        return "not product windows"
    if not ((ls.category in SYSMON_CATEGORIES) or (ls.service in SERVICES and ls.category is None)):
        return f"logsource {ls.category or ls.service}"
    if rule.status is not None and str(rule.status) in EXCLUDED_STATUS:
        return f"status {rule.status}"
    tags = [str(t) for t in rule.tags]
    if any(GROUP_OR_SOFTWARE_TAG.match(t) for t in tags):
        return "actor/software-specific tag (leakage policy)"
    return None


def compile_rules() -> tuple[list[dict], Counter]:
    _sigma_commit()
    backend = sqliteBackend(sysmon_pipeline() + windows_logsource_pipeline())
    compiled, skipped = [], Counter()
    for path in sorted(RULES_DIR.rglob("*.yml")):
        try:
            coll = SigmaCollection.from_yaml(path.read_text())
        except Exception as e:  # noqa: BLE001 - record and move on
            skipped[f"parse error: {type(e).__name__}"] += 1
            continue
        for rule in coll.rules:
            reason = select(rule)
            tags = [str(t) for t in rule.tags]
            tactics, techniques, provenance = rule_tactics(tags)
            if reason is None and not tactics:
                reason = "no ATT&CK tactic or technique tag"
            if reason:
                skipped[reason] += 1
                continue
            try:
                (query,) = backend.convert(SigmaCollection([rule]))
            except Exception as e:  # noqa: BLE001
                skipped[f"convert error: {type(e).__name__}"] += 1
                continue
            if not query.startswith("SELECT * FROM logs WHERE "):
                skipped["unexpected query shape"] += 1
                continue
            compiled.append({
                "id": str(rule.id),
                "title": rule.title,
                "path": str(path.relative_to(SIGMA_ROOT)),
                "level": str(rule.level) if rule.level else "informational",
                "status": str(rule.status) if rule.status else "experimental",
                "tactics": tactics,
                "techniques": techniques,
                "tactic_provenance": provenance,
                "where": query[len("SELECT * FROM logs WHERE "):],
            })
    compiled.sort(key=lambda r: r["id"])
    return compiled, skipped


def load_compiled(path: Path = COMPILED) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def main() -> int:
    compiled, skipped = compile_rules()
    with COMPILED.open("w") as f:
        for r in compiled:
            f.write(json.dumps(r, sort_keys=True) + "\n")
    print(f"compiled {len(compiled)} rules -> {COMPILED}")
    print("tactic provenance:", dict(Counter(r["tactic_provenance"] for r in compiled)))
    print("skipped:", dict(skipped.most_common()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
