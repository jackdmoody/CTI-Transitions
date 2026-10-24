"""Emulation plans -> ordered ground-truth steps (spec §1, §2.2). Eval artifacts only:
nothing here may feed a prior.

Plans (CALDERA-style YAML) live in data/eval/plans/<actor>.yaml, pinned in SOURCES.txt.
Steps keep file order. Only `windows` abilities are used (spec §2.3: no macOS/Linux steps
on Windows hosts). Tactic = the plan's own tactic label, normalized to the 14-tactic
scheme; if the label isn't a tactic (e.g. CALDERA's "stage-capabilities"), the first
ATT&CK v18.1 tactic of the step's technique.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from ctit.map import attack

REPO_ROOT = Path(__file__).resolve().parents[2]
PLANS = REPO_ROOT / "data" / "eval" / "plans"
LABEL_ALIASES = {"defensive-evasion": "defense-evasion"}
# Where a plan's scenarios break (no transition across the boundary): first step number of
# each later scenario.
SCENARIO_STARTS = {"APT29": [11]}  # Round 2: steps 1-10 scenario 1, 11-20 scenario 2


@dataclass
class Step:
    actor: str
    index: int  # file order among kept steps
    step_id: str  # plan procedure_step
    ability_id: str
    name: str
    technique: str
    plan_tactic_label: str
    tactic: str
    tactic_source: str  # plan_label | attack_technique
    executor: str
    command: str
    cti_source: str | None
    scenario: int


def _tactic(label: str, technique: str) -> tuple[str, str]:
    key = LABEL_ALIASES.get(label.strip().lower().replace(" ", "-"), label.strip().lower().replace(" ", "-"))
    t = attack.tactic_from_shortname(key)
    if t:
        return t, "plan_label"
    tactics = attack.technique_tactics(technique)
    if not tactics:
        raise ValueError(f"no tactic for label {label!r} / technique {technique}")
    return tactics[0], "attack_technique"


def _scenario(actor: str, step_id: str) -> int:
    m = re.match(r"(\d+)", step_id)
    n = int(m.group(1)) if m else 0
    return 1 + sum(n >= s for s in SCENARIO_STARTS.get(actor, []))


def load_plan(actor: str, path: Path | None = None) -> list[Step]:
    doc = yaml.safe_load((path or PLANS / f"{actor}.yaml").read_text())
    steps = []
    for ab in doc:
        if not isinstance(ab, dict) or "technique" not in ab:
            continue
        platforms = ab.get("platforms") or {}
        if "windows" not in platforms:
            continue
        executor, command = next(iter(platforms["windows"].items()))
        command = (command or {}).get("command") or ""
        technique = str(ab["technique"]["attack_id"]).upper()
        tactic, source = _tactic(str(ab["tactic"]), technique)
        step_id = str(ab.get("procedure_step", ""))
        steps.append(Step(
            actor=actor, index=len(steps), step_id=step_id, ability_id=str(ab["id"]),
            name=str(ab.get("name", "")), technique=technique, plan_tactic_label=str(ab["tactic"]),
            tactic=tactic, tactic_source=source, executor=str(executor), command=command,
            cti_source=ab.get("cti_source"), scenario=_scenario(actor, step_id),
        ))
    return steps


def cited_sources(actor: str) -> list[str]:
    """URLs the plan cites (cti_source): these may never be prior sources (spec §1)."""
    return sorted({s.cti_source for s in load_plan(actor) if s.cti_source})


def sequences(steps: list[Step], tactic_of=lambda s: s.tactic) -> list[list[str]]:
    """Ordered tactic sequences, one per scenario; steps whose tactic_of() is falsy are skipped."""
    out: dict[int, list[str]] = {}
    for s in steps:
        t = tactic_of(s)
        if t:
            out.setdefault(s.scenario, []).append(t)
    return [out[k] for k in sorted(out)]
