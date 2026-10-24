import json

import pandas as pd
import pytest

from ctit.map import attack, extended, sigma_rules, validate

HAVE_STIX = all((attack.STIX_DIR / f"enterprise-attack-{v}.json").exists() for v in attack.STIX)
needs_stix = pytest.mark.skipif(not HAVE_STIX, reason="ATT&CK STIX files not in data/attack_stix")


def test_tactic_collapse_and_order():
    assert attack.tactic_from_shortname("stealth") == "Defense Evasion"
    assert attack.tactic_from_shortname("defense-impairment") == "Defense Evasion"
    tactics, techniques, prov = sigma_rules.rule_tactics(
        ["attack.privilege-escalation", "attack.stealth", "attack.t1548.002", "attack.defense-impairment"])
    assert tactics == ["Privilege Escalation", "Defense Evasion"]
    assert techniques == ["T1548.002"] and prov == "rule_tag"


@needs_stix
def test_technique_fallback_and_revocation():
    tactics, _, prov = sigma_rules.rule_tactics(["attack.t1003.001"])
    assert tactics == ["Credential Access"] and prov == "attack_technique"
    assert attack.current_id("T1050") == "T1543.003"  # New Service (v6) -> Windows Service


def _rule(id_, where, tactics, level="medium", status="test", techniques=()):
    return {"id": id_, "where": where, "tactics": list(tactics), "techniques": list(techniques),
            "level": level, "status": status}


def _events():
    return pd.DataFrame({
        "_timestamp": pd.to_datetime(["2024-01-01T00:00:00Z"] * 4),
        "Hostname": ["h1", "h1", "h2", "h2"],
        "source": ["sysmon", "sysmon", "security", "sysmon"],
        "EventID": [1, 1, 4688, 13],
        "Channel": ["Microsoft-Windows-Sysmon/Operational", "x", "security", "x"],
        "Image": ["C:\\Windows\\System32\\CMD.EXE", "C:\\a\\b.exe", None, None],
        "TargetObject": [None, None, None, "HKLM\\Software\\Run\\x"],
        "IpAddress": [None, None, "10.0.0.1", None],
        "Ipaddress": [None, None, None, None],
    }).astype({c: "string" for c in ["Hostname", "source", "Channel", "Image", "TargetObject", "IpAddress", "Ipaddress"]})


def test_tag_priority_case_regex_and_missing_columns():
    rules = [
        _rule("b-low", "EventID=1 AND Image LIKE '%\\\\cmd.exe' ESCAPE '\\'", ["Execution"], level="low"),
        _rule("a-high", "Image='c:\\windows\\system32\\cmd.exe'", ["Discovery"], level="high"),
        _rule("c-re", "TargetObject REGEXP '\\\\Run\\\\'", ["Persistence"], techniques=["T1547.001"]),
        _rule("d-missing", "NotAField='x'", ["Impact"]),
        _rule("e-security", "Channel='Security' AND EventID=4688 AND IpAddress='10.0.0.1'", ["Lateral Movement"]),
    ]
    out = extended.tag(_events(), rules)
    assert list(out["tactic"]) == ["Discovery", "", "Lateral Movement", "Persistence"]
    assert out.loc[0, "rule_ids"] == "a-high,b-low" and out.loc[0, "n_rules"] == 2
    assert out.loc[3, "technique"] == "T1547.001"


def test_frozen_ruleset_matches_pinned_sigma():
    """compiled_rules.jsonl is reproducible from third_party/sigma at the pinned commit."""
    compiled, _ = sigma_rules.compile_rules()
    frozen = sigma_rules.load_compiled()
    assert [json.dumps(r, sort_keys=True) for r in compiled] == [json.dumps(r, sort_keys=True) for r in frozen]
    assert all(r["tactics"] and r["where"] for r in frozen)
    assert all(r["path"].startswith("rules/windows/") for r in frozen)


def test_step_recall():
    steps = [{"day": "day1", "step": "1.A", "host": "h", "techniques": ["T1059", "T1003"],
              "tactics": ["Execution", "Credential Access"]}]
    pooled = {"day1": {"h": ({"T1059"}, {"Execution", "Discovery"})}}
    r = validate.step_recall(steps, pooled)
    assert r["technique_recall"] == 0.5 and r["tactic_recall"] == 0.5


def test_v2_process_creation_runs_on_4688():
    frozen = sigma_rules.load_compiled()
    assert {r["variant"] for r in frozen} == {"sysmon", "security_4688"}
    v4688 = [r for r in frozen if r["variant"] == "security_4688"]
    assert all("EventID=4688" in r["where"] and "Channel='Security'" in r["where"] for r in v4688)
    whoami = [r for r in v4688 if "whoami.exe" in r["where"].lower() and "NewProcessName" in r["where"]]
    assert whoami
    ev = pd.DataFrame({
        "_timestamp": pd.to_datetime(["2024-01-01T00:00:00Z"] * 2), "Hostname": ["h", "h"],
        "source": ["security", "sysmon"], "EventID": [4688, 4688], "Channel": ["Security", "x"],
        "NewProcessName": ["C:\\Windows\\System32\\whoami.exe"] * 2,
        "CommandLine": ["whoami /all"] * 2,
    })
    out = extended.tag(ev, whoami)
    assert out.loc[0, "tactic"] != ""  # Security 4688 matches
    assert out.loc[1, "tactic"] == ""  # same fields on a non-Security channel do not
