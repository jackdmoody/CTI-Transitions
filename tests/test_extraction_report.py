"""extraction_report on synthetic saved runs: refusal table, both evidence rates, H3 sensitivity."""
import hashlib
import json

import pytest

from ctit.cti import extract
from ctit.experiments import extraction_report as rep

TEXT = "They sent a phishing email. Then the loader ran PowerShell and created a scheduled task."
CFG = {"actors": ["APT29"], "conditions": ["R"], "alpha": 0.5, "chunk": {"tokens": 6000, "overlap": 300},
       "prompts": {"report": "extract_v1.txt", "memory": "memory_v1.txt"}, "runs": {"F": "runF", "S": "runS"}}


def _t(a, b, span, ok):
    return {"from_tactic": a, "to_tactic": b, "evidence_span": span, "confidence": 1.0,
            "evidence_ok": ok, "doc_id": "APT29-P01", "chunk": 0}


def test_report(tmp_path, monkeypatch):
    monkeypatch.setattr(rep, "PRIORS", tmp_path)
    monkeypatch.setattr(rep, "jobs", lambda c: [{"cond": "R", "actor": "APT29", "doc_id": "APT29-P01", "text": TEXT}])
    prompt = extract.render(extract.load_prompt("extract_v1.txt"), tactics=extract.tactic_list(), text=TEXT)
    h = hashlib.sha256(prompt.encode()).hexdigest()
    for name, key, refused in (("f0", '{"model": "claude-opus-5-5", "options": {}}#s0', True),
                               ("f1", '{"model": "claude-opus-5-5", "options": {}}#s1', False),
                               ("s0", json.dumps({"tag": "q", "w": "x", "o": {"temperature": 0}}), False)):
        d = tmp_path / "cache" / name
        d.mkdir(parents=True)
        (d / "KEY.txt").write_text(key)
        (d / f"{h}.json").write_text(json.dumps({"refusal": "x"} if refused else {"text": "[]"}))
    trans = [_t("Initial Access", "Execution", "They sent a phishing email.", True),
             _t("Execution", "Persistence", "loader ran PowerShell ... created a scheduled task", False)]
    C = extract.counts(trans)
    for run, mode, sample in (("runF", "F", "s1"), ("runS", "S", "t0")):
        p = tmp_path / run / mode
        p.mkdir(parents=True)
        (p / f"R_APT29_{sample}.json").write_text(json.dumps({
            "counts": C.astype(int).tolist(), "counts_mentions": C.astype(int).tolist(), "transitions": trans,
            "meta": {"cond": "R", "actor": "APT29", "sample": sample}}))
    out = rep.run(CFG)
    assert out["refusals"] == {"F": {"APT29-P01#0": "1/2"}}
    r = out["modes"]["F"]["R/APT29"]["samples"]["s1"]
    assert r["hallucinated_strict"] == 0.5 and r["hallucinated_fragments"] == 0.0
    assert "recovery_all" in r and "recovery_windows" in r
    sens = out["h3_sensitivity"]["S"]
    assert sens["dropped_chunks"] == ["APT29-P01#0"] and sens["R"]["APT29"]["f1"]["mean"] == 0.0


def test_post_hoc_chance_and_baselines(tmp_path, monkeypatch):
    import numpy as np
    from ctit.eval import recovery
    G = {"APT29": recovery.ground_truth_counts("APT29")}
    C = (G["APT29"] > 0).astype(int)
    loaded = {"F": {("R", "APT29"): {"s0": {"counts": C.tolist()}}, ("B", "APT29"): {"s0": {"counts": (C * 0).tolist()}}}}
    cfg = {"actors": ["APT29"], "post_hoc": {"draws": 500, "seed": 1, "h4_alphas": [0.1]}}
    out = rep.post_hoc(cfg, loaded, G)
    r = out["chance"]["F/R/APT29"]
    assert r["f1"]["mean"] == 1.0 and r["percentile"]["mean"] > 99
    assert out["chance"]["baseline/Uni/APT29"]["recall"]["mean"] == 1.0
    assert out["chance"]["baseline/Uni/APT29"]["edges_extracted"]["mean"] == 182
    assert out["h4"]["F"]["f1_over_chance"]["APT29"]["APT29"] > 1
    assert "jsd_alpha_0.1" in out["h4"]["F"] and out["r_minus_b"]["F"]["APT29"]["f1_gap"] == 1.0


def test_h4_colwise_reads_the_preregistered_matrix():
    h = {"f1": {"A": {"A": .4, "B": .1}, "B": {"A": .5, "B": .3}},
         "jsd": {"A": {"A": .1, "B": .2}, "B": {"A": .05, "B": .1}}}
    col = rep.h4_colwise(h)
    assert col["f1"] == pytest.approx({"A": -0.1, "B": 0.2})
    assert col["jsd"] == pytest.approx({"A": -0.05, "B": 0.1})
