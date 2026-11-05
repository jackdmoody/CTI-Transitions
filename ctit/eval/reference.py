"""Segmented plan ground truth (AICS-27 revision, internal review; 2026-11-05). Eval artifact only.

build_reference(actor) returns the plan as a list of segments: one per independent scenario and one per
alternative platform execution path. Within a segment, consecutive repeated tactics are collapsed;
edges and transitions are counted only inside a segment, never across a boundary.

Segment structure is declared, from each plan's own documentation (data/eval/plans/docs/, pinned in
SOURCES.txt), not inferred from the YAML:
- SCENARIOS: APT29 (ATT&CK Evaluations Round 2) has two independent scenarios, steps 1-10 (Day 1) and
  11-20 (Day 2). The CTID YAMLs for OilRig, Sandworm and menuPass each encode one scenario: OilRig has
  one (Emulation_Plan_README.md, Steps 0-11); Sandworm's Scenarios 1 and 2 are the same Steps 11-19
  (detections vs. protections, Emulation_Plan_Scenario_{1,2}_README.md) and the YAML encodes that chain
  once; menuPass's YAML encodes Scenario 1 (Steps 2-9; Scenario 2 is documented only in prose).
- PLATFORM_PATHS: alternative executions of the same step on different platforms. None of the four
  YAMLs has one: every ability lists exactly one platform, and the Linux abilities in OilRig and
  Sandworm are sequential parts of the one operation (the attacker's Kali agent, or the Linux victim
  before lateral movement to Windows), so they stay in their scenario's segment. The table exists so
  that a plan with real alternatives can declare them (step id -> path name).
Multi-tactic rule: a step's tactic is the plan's own step-level label when it names a tactic, otherwise
the first-listed ATT&CK v18.1 tactic of the step's technique (ctit.eval.plans._tactic, through
ctit.map.frozen_tactics.to_frozen_tactic). tactic_rule() reports which branch each step took.
"""
from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np

from ctit.eval import plans
from ctit.map import attack
from ctit.map.attack import TACTICS
from ctit.map.frozen_tactics import to_frozen_tactic

IDX = {t: i for i, t in enumerate(TACTICS)}
SCENARIOS: dict[str, list[tuple[int, str]]] = {  # actor -> [(first step number, scenario name)]
    "APT29": [(1, "Scenario 1 (Day 1, steps 1-10)"), (11, "Scenario 2 (Day 2, steps 11-20)")],
    "OilRig": [(0, "Scenario (steps 1-11)")],
    "Sandworm": [(0, "Scenarios 1/2 (shared steps 11-19)")],
    "menuPass": [(0, "Scenario 1 (steps 2-9)")],
}
PLATFORM_PATHS: dict[str, dict[str, str]] = {}  # actor -> {procedure_step: path name}; none declared


@dataclass
class Segment:
    actor: str
    scenario: str
    path: str
    steps: list = field(default_factory=list)  # plans.Step, file order

    @property
    def tactics(self) -> list[str]:
        seq = [s.tactic for s in self.steps]
        return [t for i, t in enumerate(seq) if i == 0 or t != seq[i - 1]]

    @property
    def pairs(self) -> list[tuple[str, str]]:
        t = self.tactics
        return list(zip(t, t[1:]))


def _step_number(step_id: str) -> int:
    import re
    m = re.match(r"(\d+)", step_id)
    return int(m.group(1)) if m else 0


def scenario_of(actor: str, step_id: str) -> str:
    starts = SCENARIOS.get(actor, [(0, "Scenario")])
    n = _step_number(step_id)
    name = starts[0][1]
    for first, nm in starts:
        if n >= first:
            name = nm
    return name


def build_reference(actor: str, steps: list | None = None, split_platforms: bool = False) -> list[Segment]:
    """Segments of `actor`'s plan (all platforms), in plan order. split_platforms=True is a SENSITIVITY
    variant only (not the reference): every maximal run of same-platform steps is its own segment, which
    also cuts the plans' sequential Linux <-> Windows handoffs."""
    steps = plans.load_plan(actor, platforms=None) if steps is None else steps
    paths = PLATFORM_PATHS.get(actor, {})
    segs: list[Segment] = []
    for s in steps:
        scen = scenario_of(actor, s.step_id)
        path = paths.get(s.step_id, "main")
        if split_platforms:
            path = "+".join(s.platforms) or "?"
        if segs and segs[-1].scenario == scen and segs[-1].path == path:
            segs[-1].steps.append(s)
        elif not split_platforms and any(g.scenario == scen and g.path == path for g in segs):
            next(g for g in segs if g.scenario == scen and g.path == path).steps.append(s)
        else:
            segs.append(Segment(actor, scen, path, [s]))
    return segs


def pairs_array(segments: list[Segment]) -> np.ndarray:
    """(L, 2) tactic-index pairs, segment by segment (no pair crosses a boundary)."""
    return np.array([(IDX[a], IDX[b]) for g in segments for a, b in g.pairs], dtype=int).reshape(-1, 2)


def segment_ids(segments: list[Segment]) -> np.ndarray:
    """(L,) the segment index of each transition in pairs_array order."""
    return np.array([i for i, g in enumerate(segments) for _ in g.pairs], dtype=int)


def counts(segments: list[Segment]) -> np.ndarray:
    C = np.zeros((len(TACTICS), len(TACTICS)))
    for a, b in pairs_array(segments):
        C[a, b] += 1
    return C


def tactic_rule(step) -> dict:
    """Which branch of the multi-tactic rule a step took, and the technique's ATT&CK tactics."""
    tech = attack.technique_tactics(step.technique)
    label_tactic = to_frozen_tactic(step.plan_tactic_label, "plan")
    return {"step": step.step_id, "name": step.name, "label": step.plan_tactic_label, "technique": step.technique,
            "technique_tactics": tech, "tactic": step.tactic,
            "rule": "plan label" if label_tactic else "first-listed technique tactic",
            "multi_tactic_technique": len(tech) > 1,
            "label_differs_from_technique": bool(label_tactic) and label_tactic not in tech}
