"""extraction_report on synthetic saved runs: refusal table, both evidence rates, H3 sensitivity."""
import hashlib
import json

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
