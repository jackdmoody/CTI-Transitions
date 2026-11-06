"""build_reference: segments, collapse within a segment, no transition across a boundary."""
from __future__ import annotations

import numpy as np
import pytest

from ctit.eval import plans, recovery
from ctit.eval import reference as ref


def _step(i, sid, tactic, platform="windows", actor="X"):
    return plans.Step(actor=actor, index=i, step_id=sid, ability_id=str(i), name=sid, technique="T1082",
                      plan_tactic_label=tactic, tactic=tactic, tactic_source="plan_label", executor="", command="",
                      cti_source=None, scenario=1, platforms=(platform,))


@pytest.fixture
def two_scenarios(monkeypatch):
    monkeypatch.setitem(ref.SCENARIOS, "X", [(1, "S1"), (3, "S2")])
    return [_step(0, "1.A", "Discovery"), _step(1, "1.B", "Discovery"), _step(2, "2.A", "Collection"),
            _step(3, "3.A", "Collection"), _step(4, "3.B", "Exfiltration"), _step(5, "4.A", "Exfiltration")]


def test_segments_collapse_within_and_never_cross(two_scenarios):
    segs = ref.build_reference("X", two_scenarios)
    assert [g.scenario for g in segs] == ["S1", "S2"]
    assert segs[0].tactics == ["Discovery", "Collection"]
    # S2 starts with Collection: the repeat across the boundary is not collapsed into S1, and
    # Collection -> Collection is not a transition
    assert segs[1].tactics == ["Collection", "Exfiltration"]
    P = ref.pairs_array(segs)
    assert len(P) == 2 and ref.segment_ids(segs).tolist() == [0, 1]
    C = ref.counts(segs)
    assert C.sum() == 2 and np.trace(C) == 0


def test_boundary_edge_is_not_counted(monkeypatch):
    monkeypatch.setitem(ref.SCENARIOS, "X", [(1, "S1"), (2, "S2")])
    steps = [_step(0, "1.A", "Discovery"), _step(1, "2.A", "Impact")]
    segs = ref.build_reference("X", steps)
    assert ref.counts(segs).sum() == 0 and len(ref.pairs_array(segs)) == 0


def test_declared_platform_paths_are_separate_segments(monkeypatch):
    monkeypatch.setitem(ref.SCENARIOS, "X", [(0, "S")])
    monkeypatch.setitem(ref.PLATFORM_PATHS, "X", {"2.L": "linux path"})
    steps = [_step(0, "1.A", "Discovery"), _step(1, "2.W", "Collection"),
             _step(2, "2.L", "Execution", "linux"), _step(3, "3.A", "Exfiltration")]
    segs = ref.build_reference("X", steps)
    assert [(g.path, g.tactics) for g in segs] == [("main", ["Discovery", "Collection", "Exfiltration"]),
                                                  ("linux path", ["Execution"])]


def test_platform_split_sensitivity(two_scenarios):
    two_scenarios[2].platforms = ("linux",)
    segs = ref.build_reference("X", two_scenarios, split_platforms=True)
    # S1 windows [Disc, Disc], S1 linux [Collect], S2 windows [Collect, Exfil, Exfil]
    assert [(g.scenario, g.path) for g in segs] == [("S1", "windows"), ("S1", "linux"), ("S2", "windows")]
    I = ref.IDX
    assert ref.pairs_array(segs).tolist() == [[I["Collection"], I["Exfiltration"]]]


@pytest.mark.parametrize("actor,edges,L", [("APT29", 28, 45), ("OilRig", 15, 17), ("Sandworm", 21, 25),
                                           ("menuPass", 6, 6)])
def test_real_plans_reproduce_the_paper_ground_truth(actor, edges, L):
    if not (plans.PLANS / f"{actor}.yaml").exists():
        pytest.skip("plan files not present")
    from ctit.experiments import v2_common as v2
    segs = ref.build_reference(actor)
    assert int((ref.counts(segs) > 0).sum()) == edges and len(ref.pairs_array(segs)) == L
    assert np.array_equal(ref.counts(segs), recovery.ground_truth_counts(actor))
    assert np.array_equal(ref.pairs_array(segs), v2.plan_pairs(actor))


def test_multi_tactic_rule():
    try:
        tech = __import__("ctit.map.attack", fromlist=["x"]).technique_tactics("T1548.002")
    except FileNotFoundError:
        pytest.skip("ATT&CK STIX not present")
    assert len(tech) > 1
    # the plan's own step-level label wins when it names a tactic ...
    assert plans._tactic("defense-evasion", "T1548.002") == ("Defense Evasion", "plan_label")
    # ... otherwise the technique's first-listed tactic
    assert plans._tactic("stage-capabilities", "T1548.002") == (tech[0], "attack_technique")
