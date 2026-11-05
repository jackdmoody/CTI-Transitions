"""to_frozen_tactic: every label from each source maps to exactly one of the 14 tactics, or is dropped by an
explicit rule that is logged; and the shared mapping reproduces the old per-source behaviour exactly."""
from __future__ import annotations

import json
import logging
import re

import pytest
import yaml

from ctit.map import attack
from ctit.map.attack import SHORTNAME, TACTICS
from ctit.map.frozen_tactics import DROPS, drop_reason, to_frozen_tactic

REASONS = {"not an exact tactic name", "plan label is not a tactic", "technique tag", "group/software tag",
           "attack tag is not a tactic", "not an attack tag", "kill-chain phase is not a tactic", "not a string"}


def _exactly_one_or_dropped(label, source):
    t = to_frozen_tactic(label, source)
    r = drop_reason(label, source)
    assert (t is None) == (r is not None), (label, source)
    if t is None:
        assert r in REASONS
    else:
        assert t in TACTICS
    return t


# old behaviour, verbatim from before 2026-11-05
def _old_plan(label):
    key = {"defensive-evasion": "defense-evasion"}.get(label.strip().lower().replace(" ", "-"),
                                                      label.strip().lower().replace(" ", "-"))
    return SHORTNAME.get(key.lower())


def _old_sigma(tag):
    return SHORTNAME.get(tag[len("attack."):].lower()) if tag.startswith("attack.") else None


def test_every_tactic_every_source():
    for t in TACTICS:
        short = t.lower().replace(" ", "-")
        assert to_frozen_tactic(t, "extraction") == t
        assert to_frozen_tactic(t, "plan") == t
        assert to_frozen_tactic(short, "plan") == t
        assert to_frozen_tactic(f"attack.{short}", "sigma") == t
        assert to_frozen_tactic(short, "attack") == t


def test_v19_split_folds_to_defense_evasion():
    for lab in ("stealth", "defense-impairment"):
        assert to_frozen_tactic(lab, "plan") == "Defense Evasion"
        assert to_frozen_tactic(lab, "attack") == "Defense Evasion"
        assert to_frozen_tactic(f"attack.{lab}", "sigma") == "Defense Evasion"
    assert to_frozen_tactic("defensive-evasion", "plan") == "Defense Evasion"
    # extraction: only the exact names the frozen prompt lists
    assert to_frozen_tactic("Stealth", "extraction") is None
    assert to_frozen_tactic("command-and-control", "extraction") is None


@pytest.mark.parametrize("label,source,reason", [
    ("stage-capabilities", "plan", "plan label is not a tactic"),
    ("attack.t1003.001", "sigma", "technique tag"),
    ("attack.g0007", "sigma", "group/software tag"),
    ("attack.s0002", "sigma", "group/software tag"),
    ("attack.ds0005", "sigma", "attack tag is not a tactic"),
    ("car.2013-05-004", "sigma", "not an attack tag"),
    ("Ingress Tool Transfer placeholder", "extraction", "not an exact tactic name"),
    (None, "extraction", "not a string"),
])
def test_explicit_drops_are_logged(label, source, reason, caplog):
    before = DROPS[(source, str(label), reason)]
    with caplog.at_level(logging.DEBUG, logger="ctit.map.frozen_tactics"):
        assert to_frozen_tactic(label, source) is None
    assert DROPS[(source, str(label), reason)] == before + 1
    assert any("dropped" in r.message and reason in r.message for r in caplog.records)


def test_unknown_source_raises():
    with pytest.raises(ValueError):
        to_frozen_tactic("Discovery", "nope")


def test_every_plan_label():
    from ctit.eval import plans
    seen = 0
    for actor in ("APT29", "OilRig", "Sandworm", "menuPass"):
        if not (plans.PLANS / f"{actor}.yaml").exists():
            pytest.skip("plan files not present")
        for s in plans.load_plan(actor, platforms=None):
            assert _exactly_one_or_dropped(s.plan_tactic_label, "plan") == _old_plan(s.plan_tactic_label)
            assert s.tactic in TACTICS
            seen += 1
    assert seen == 79 + 44 + 40 + 15


def test_every_sigma_tag_and_compiled_rules_unchanged():
    from ctit.map import sigma_rules
    if not sigma_rules.RULES_DIR.exists():
        pytest.skip("third_party/sigma not initialised")
    tags_by_rule = {}
    for p in sorted(sigma_rules.RULES_DIR.rglob("*.yml")):
        for doc in yaml.safe_load_all(p.read_text()):
            if isinstance(doc, dict) and "id" in doc:
                tags_by_rule[str(doc["id"])] = [str(t) for t in doc.get("tags") or []]
    for tags in tags_by_rule.values():
        for tag in tags:
            assert _exactly_one_or_dropped(tag, "sigma") == _old_sigma(tag)
    # the frozen compiled mapper's tactic lists are what rule_tactics gives through the shared mapping
    for r in sigma_rules.load_compiled():
        tactics, _, prov = sigma_rules.rule_tactics(tags_by_rule[r["id"]])
        assert tactics == r["tactics"] and prov == r["tactic_provenance"], r["id"]


def test_every_attack_kill_chain_phase():
    for version in ("18.1", "19.2"):
        try:
            objs = attack._bundle(version)
        except FileNotFoundError:
            pytest.skip("ATT&CK STIX not present")
        phases = {ph["phase_name"] for o in objs if o["type"] == "attack-pattern"
                  for ph in o.get("kill_chain_phases", []) if ph["kill_chain_name"] == "mitre-attack"}
        for ph in phases:
            assert _exactly_one_or_dropped(ph, "attack") == SHORTNAME.get(ph.lower())


def test_every_cached_extraction_label():
    """Every tactic label a model returned in the cached priors (accepted or rejected) is accepted by the
    shared mapping iff it was accepted before (an exact name)."""
    from ctit.experiments import v2_common as v2
    cfg = yaml.safe_load(open(v2.REPO_ROOT / "configs" / "v2_priors.yaml"))
    n = 0
    for spec in cfg["priors"].values():
        d = v2.prior_dir(spec)
        if not d.exists():
            pytest.skip("cached priors not present")
        for f in d.glob("*.json"):
            p = json.loads(f.read_text())
            items = p["transitions"] + [it for it, _ in p["rejected"]]
            for it in items:
                for k in ("from_tactic", "to_tactic"):
                    if k in it:
                        lab = it[k]
                        assert (_exactly_one_or_dropped(lab, "extraction") is not None) == (lab in TACTICS)
                        n += 1
    assert n > 0


def test_schema_validate_uses_exact_names():
    from ctit.cti import schema
    ok, rej = schema.validate([
        {"from_tactic": "Discovery", "to_tactic": "Collection", "evidence_span": "x", "confidence": 0.5},
        {"from_tactic": "discovery", "to_tactic": "Collection", "evidence_span": "x", "confidence": 0.5},
        {"from_tactic": "Stealth", "to_tactic": "Collection", "evidence_span": "x", "confidence": 0.5},
    ])
    assert len(ok) == 1 and [re.match(r"not an Enterprise tactic", w) is not None for _, w in rej] == [True, True]
