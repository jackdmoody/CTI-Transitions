import numpy as np

from ctit.eval import actor_jsd, plans, visibility

PLAN = """
- emulation_plan_details: {adversary_name: X}
- id: a1
  name: whoami
  tactic: discovery
  technique: {attack_id: T1033, name: x}
  procedure_step: "1.A"
  cti_source: https://example.org/r1
  platforms: {windows: {cmd: {command: "whoami /all"}}}
- id: a2
  name: weird label
  tactic: stage-capabilities
  technique: {attack_id: T1003.001, name: x}
  procedure_step: "11.A"
  platforms: {windows: {psh: {command: "Get-Process"}}}
- id: a3
  name: linux only
  tactic: discovery
  technique: {attack_id: T1082, name: x}
  procedure_step: "2.A"
  platforms: {linux: {sh: {command: "uname -a"}}}
"""


def test_load_plan(tmp_path):
    path = tmp_path / "X.yaml"
    path.write_text(PLAN)
    steps = plans.load_plan("APT29", path)
    assert [s.ability_id for s in steps] == ["a1", "a2"]  # linux step dropped
    assert steps[0].tactic == "Discovery" and steps[0].tactic_source == "plan_label"
    assert steps[1].tactic == "Credential Access" and steps[1].tactic_source == "attack_technique"
    assert [s.scenario for s in steps] == [1, 2]  # APT29 step 11+ is scenario 2
    assert plans.sequences(steps) == [["Discovery"], ["Credential Access"]]


def test_artifacts_child_tool_and_neutral_parent(tmp_path):
    path = tmp_path / "X.yaml"
    path.write_text(PLAN)
    s = plans.load_plan("APT29", path)[0]
    arts = visibility.artifacts(s)
    assert [a["artifact"] for a in arts] == ["executor", "child:whoami"]
    assert arts[0]["ParentImage"] is None
    assert arts[1]["Image"].endswith("whoami.exe")


def test_projection_and_jsd():
    seqs = [["Execution", "Discovery", "Collection", "Discovery"]]
    proj = actor_jsd.project_sequences(seqs, ["Execution", "Discovery"])
    assert proj == [["Execution", "Discovery", "Discovery"]]
    C = actor_jsd.counts(proj, ["Execution", "Discovery"])
    np.testing.assert_array_equal(C, [[0, 1], [0, 1]])
    r = actor_jsd.pairwise({"A": seqs, "B": seqs, "C": [["Execution", "Execution"]]}, ["Execution", "Discovery", "Collection"], 0.0)
    assert r["jsd"]["A|B"] == 0.0 and r["jsd"]["A|C"] > 0
