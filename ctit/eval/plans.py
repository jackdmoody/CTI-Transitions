"""Emulation plans -> ordered ground-truth steps (spec §1, §2.2). Eval artifacts only:
nothing here may feed a prior.

Plans (CALDERA-style YAML) live in data/eval/plans/<actor>.yaml, pinned in SOURCES.txt.
Steps keep file order. By default only `windows` abilities are used (spec §2.3: no
macOS/Linux steps on Windows hosts; injection and visibility). Extraction ground truth uses
every platform (load_plan(..., platforms=None); spec §6, 2026-10-27). Tactic = the plan's own tactic label, normalized to the 14-tactic
scheme; if the label isn't a tactic (e.g. CALDERA's "stage-capabilities"), the first
ATT&CK v18.1 tactic of the step's technique.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from ctit.map import attack
from ctit.map.frozen_tactics import to_frozen_tactic

REPO_ROOT = Path(__file__).resolve().parents[2]
PLANS = REPO_ROOT / "data" / "eval" / "plans"
LABEL_ALIASES = {"defensive-evasion": "defense-evasion"}
# Where a plan's scenarios break (no transition across the boundary): first step number of
# each later scenario.
SCENARIO_STARTS = {"APT29": [11]}  # Round 2: steps 1-10 scenario 1, 11-20 scenario 2
# (Sandworm's Windows steps are all in its one detection scenario, steps 16-19.)


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
    platforms: tuple[str, ...] = ()  # the ability's platform keys, file order (2026-11-05, build_reference)


def _tactic(label: str, technique: str) -> tuple[str, str]:
    # One mapping for every source (ctit.map.frozen_tactics, 2026-11-05); same result as the old
    # LABEL_ALIASES + shortname lookup (tests/test_frozen_tactics.py).
    t = to_frozen_tactic(label, "plan")
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


_PLACEHOLDER = re.compile(r"#\{([^}]+)\}")


def substitute(command: str, input_arguments: dict) -> str:
    """Fill CALDERA #{name} placeholders with the ability's own input_arguments defaults
    (part of the plan); placeholders without a default become their bare name."""
    def repl(m):
        arg = input_arguments.get(m.group(1))
        if isinstance(arg, dict) and arg.get("default") not in (None, ""):
            return str(arg["default"])
        return m.group(1).split(".")[-1]
    return _PLACEHOLDER.sub(repl, command)


def load_plan(actor: str, path: Path | None = None, platforms: tuple[str, ...] | None = ("windows",)) -> list[Step]:
    """platforms: abilities with any of these platforms are kept; None keeps every step.
    A step's executor/command come from its windows entry if it has one, else its first."""
    doc = yaml.safe_load((path or PLANS / f"{actor}.yaml").read_text())
    steps = []
    for ab in doc:
        if not isinstance(ab, dict) or "technique" not in ab:
            continue
        plats = ab.get("platforms") or {}
        if platforms is not None and not set(plats) & set(platforms):
            continue
        entry = plats.get("windows") or next(iter(plats.values()), {}) or {}
        executor, command = next(iter(entry.items()), ("", {}))
        command = substitute((command or {}).get("command") or "", ab.get("input_arguments") or {})
        technique = str(ab["technique"]["attack_id"]).upper()
        tactic, source = _tactic(str(ab["tactic"]), technique)
        step_id = str(ab.get("procedure_step", ""))
        steps.append(Step(
            actor=actor, index=len(steps), step_id=step_id, ability_id=str(ab["id"]),
            name=str(ab.get("name", "")), technique=technique, plan_tactic_label=str(ab["tactic"]),
            tactic=tactic, tactic_source=source, executor=str(executor), command=command,
            cti_source=ab.get("cti_source"), scenario=_scenario(actor, step_id), platforms=tuple(plats),
        ))
    return steps


DOCS = PLANS / "docs"  # <actor>/*.md: the plan's README, Intelligence Summary, Operations Flow, ...
_URL = re.compile(r"https?://[^\s)>\]\"'|<`]+")
# Links in plan docs that are not reports: ATT&CK pages, lab IPs, badges, licenses, socials.
_NOT_A_REPORT = re.compile(
    r"^https?://(attack\.mitre\.org|(10|192\.168|172\.(1[6-9]|2\d|3[01]))\.|127\.|localhost|"
    r"img\.shields\.io|opensource\.org|www\.apache\.org|creativecommons\.org|"
    r"(www\.)?(twitter|x|linkedin)\.com)", re.IGNORECASE)


def cited_sources(actor: str) -> list[str]:
    """Reports the plan cites, which may never be prior sources (spec §1): every step's
    cti_source plus every report URL in the plan's markdown docs. Normalized with
    ctit.cti.manifest.normalize_url. Over-inclusive on purpose."""
    from ctit.cti.manifest import normalize_url

    urls = {s.cti_source for s in load_plan(actor) if s.cti_source}
    for md in sorted((DOCS / actor).glob("*.md")):
        urls.update(_URL.findall(md.read_text(errors="replace")))
    return sorted({n for u in urls if not _NOT_A_REPORT.match(u) and (n := normalize_url(u)) and "/" in n})


def sequences(steps: list[Step], tactic_of=lambda s: s.tactic) -> list[list[str]]:
    """Ordered tactic sequences, one per scenario; steps whose tactic_of() is falsy are skipped."""
    out: dict[int, list[str]] = {}
    for s in steps:
        t = tactic_of(s)
        if t:
            out.setdefault(s.scenario, []).append(t)
    return [out[k] for k in sorted(out)]
