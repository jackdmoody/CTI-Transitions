import pytest

from ctit.map import v3
from ctit.map.sigma_rules import load_compiled

WHERE = ("Channel='Microsoft-Windows-Sysmon/Operational' AND (EventID=1 AND ((Image LIKE '%\\\\reg.exe' "
         "ESCAPE '\\' AND CommandLine LIKE '%Image=x AND y%' ESCAPE '\\') AND NOT COALESCE((ParentImage IS NULL), 0)))")


def test_referenced_fields_ignore_literals():
    assert v3.referenced_fields(WHERE) == {"Channel", "EventID", "Image", "CommandLine", "ParentImage"}


def test_accepted_sources():
    assert v3.accepted_sources(WHERE) == ({"Microsoft-Windows-Sysmon/Operational"}, {1})
    assert v3.accepted_sources("Channel='Security' AND EventID IN (4634, 4647)") == ({"Security"}, {4634, 4647})


def test_evaluable_needs_every_field_on_one_source():
    rule = {"where": WHERE}
    sysmon = "Microsoft-Windows-Sysmon/Operational"
    assert v3.evaluable(rule, {(sysmon, 1): {"Image", "CommandLine", "ParentImage"}})
    assert not v3.evaluable(rule, {(sysmon, 1): {"Image", "CommandLine"}})
    assert not v3.evaluable(rule, {(sysmon, 3): {"Image", "CommandLine", "ParentImage"}})


def test_bare_path_fields():
    assert v3.bare_path_fields({"Image": "PING.EXE", "ParentImage": r"C:\x\cmd.exe", "TargetImage": None}) == {"Image"}


@pytest.mark.skipif(not v3.RULES_V3.exists(), reason="v3 not frozen yet")
def test_frozen_v3_policy():
    frozen = v3.load_frozen()
    rules = v3.load_v3()
    base = {(r["id"], r["variant"]) for r in load_compiled()}
    keep = {(r["id"], r["variant"]) for r in rules}
    assert keep <= base and len(keep) == len(frozen["keep"])
    assert all(r["level"] != "informational" for r in rules)
    assert not any(r["path"].startswith(v3.REMOTE_THREAD) for r in rules)
    assert all(r["variant"] == "sysmon" for r in rules)  # OpTC has no Security 4688
    assert "User Logoff Event" in frozen["dropped"]["a_informational"]["titles"]
    assert not any(r["title"] == "User Logoff Event" for r in rules)
    dropped_c2 = {(d["id"], d["variant"]) for d in frozen["dropped"]["c2_path_unevaluable"]["list"]}
    assert not dropped_c2 & keep
