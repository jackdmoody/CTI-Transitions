"""Extraction (spec §4) with recorded responses only: no API and no Ollama calls."""
import json

import numpy as np
import pytest

from ctit.cti import extract, prior
from ctit.map.attack import TACTICS

TEMPLATE = "Tactics:\n<<TACTICS>>\nExcerpt:\n<<TEXT>>"
MEMORY = "Actor: <<ACTOR>>\n<<TACTICS>>"
REPORT = ("The actor sent spearphishing emails with malicious attachments. "
          "After the victim opened the document, a PowerShell loader ran and then "
          "the implant created a scheduled task for persistence.")


class Replay:
    """A model that returns recorded responses in order and records prompts it was given."""
    name = "replay"

    def __init__(self, responses):
        self.responses = list(responses)
        self.prompts = []

    def chat(self, prompt, calls=None, *, system=None):
        self.prompts.append(prompt)
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def _t(a, b, span, conf=0.9, **kw):
    return {"from_tactic": a, "to_tactic": b, "evidence_span": span, "confidence": conf, **kw}


GOOD = json.dumps([
    _t("Initial Access", "Execution", "After the victim opened the document, a PowerShell loader ran"),
    _t("Execution", "Persistence", "the implant created a scheduled task   for persistence"),  # whitespace differs
    _t("Execution", "Exfiltration", "the actor stole 4 GB of data"),  # not in the text
])


def test_render_fills_and_rejects_unfilled():
    p = extract.render(TEMPLATE, tactics=extract.tactic_list(), text="x")
    assert "- Defense Evasion" in p and "<<" not in p
    with pytest.raises(ValueError):
        extract.render(TEMPLATE, tactics="t")


def test_chunking_overlap_and_coverage():
    words = [f"w{i}" for i in range(5000)]
    text = " ".join(words)
    chunks = extract.chunk(text, tokens=200, overlap=20)
    assert len(chunks) > 1
    assert all(len(c) <= 800 for c in chunks)
    assert set(" ".join(chunks).split()) == set(words)  # nothing lost
    assert set(chunks[0].split()) & set(chunks[1].split())  # overlap
    assert extract.chunk("short text") == ["short text"]
    assert extract.chunk("   ") == []


def test_labels_outside_the_14_tactics_are_rejected():
    bad = json.dumps([_t("Initial Access", "Execution", "a PowerShell loader ran"),
                      _t("Stealth", "Execution", "a PowerShell loader ran"),
                      _t("Execution", "Lateral Movment", "a PowerShell loader ran")])
    r = extract.extract_chunk(Replay([bad]), TEMPLATE, REPORT, "d1", 0)
    assert r.status == "ok" and len(r.transitions) == 1 and len(r.rejected) == 2
    assert all(t["from_tactic"] in TACTICS and t["to_tactic"] in TACTICS for t in r.transitions)


def test_evidence_span_check():
    r = extract.extract_chunk(Replay([GOOD]), TEMPLATE, REPORT, "d1", 0)
    assert [t["evidence_ok"] for t in r.transitions] == [True, True, False]
    s = extract.summarize([r])
    assert s["hallucinated_span_rate"] == pytest.approx(1 / 3)
    assert extract.evidence_ok("a  PowerShell\nloader ran", REPORT)
    assert not extract.evidence_ok("   ", REPORT)


def test_retry_once_then_skip():
    ok = extract.extract_chunk(Replay(["not json", GOOD]), TEMPLATE, REPORT, "d1", 0)
    assert ok.status == "ok" and ok.attempts == 2 and len(ok.transitions) == 3
    m = Replay(["not json", '{"a": 1}', GOOD])
    bad = extract.extract_chunk(m, TEMPLATE, REPORT, "d1", 0)
    assert bad.status == "skipped_schema" and bad.attempts == 2 and bad.transitions == []
    assert len(m.prompts) == 2  # one retry only; the third response is never requested


def test_refusal_is_not_retried():
    m = Replay([extract.Refusal("cyber"), GOOD])
    r = extract.extract_chunk(m, TEMPLATE, REPORT, "d1", 0)
    assert r.status == "refused" and len(m.prompts) == 1


def test_fenced_json_is_accepted():
    r = extract.extract_chunk(Replay(["```json\n" + GOOD + "\n```"]), TEMPLATE, REPORT, "d1", 0)
    assert r.status == "ok" and len(r.transitions) == 3


def test_aggregation_math():
    r = extract.extract_chunk(Replay([GOOD]), TEMPLATE, REPORT, "d1", 0)
    r2 = extract.extract_chunk(Replay([json.dumps([_t("Initial Access", "Execution", "a PowerShell loader ran")])]),
                               TEMPLATE, REPORT, "d2", 0)
    out = extract.build_prior([r, r2], alpha=0.5)
    C, P = np.array(out["counts"]), np.array(out["matrix"])
    ia, ex, pe, xf = (prior.INDEX[t] for t in ("Initial Access", "Execution", "Persistence", "Exfiltration"))
    assert C[ia, ex] == 2 and C[ex, pe] == 1 and C[ex, xf] == 1 and C.sum() == 4
    assert np.allclose(P.sum(axis=1), 1.0)
    n = len(TACTICS)
    assert P[ia, ex] == pytest.approx((2 + 0.5) / (2 + 0.5 * n))
    assert P[0, 0] == pytest.approx(1 / n)  # an empty row is uniform
    strict = np.array(extract.build_prior([r, r2], require_evidence=True)["counts"])
    assert strict[ex, xf] == 0 and strict.sum() == 3


def test_memory_condition_same_schema_no_evidence_check():
    m = Replay([json.dumps([_t("Initial Access", "Execution", "Known for spearphishing then scripts.")])])
    r = extract.memory_transitions(m, MEMORY, "APT29")
    assert "Actor: APT29" in m.prompts[0]
    assert r.status == "ok" and r.transitions[0]["evidence_ok"] is None
    assert extract.summarize([r])["hallucinated_span_rate"] is None


def test_extract_report_chunks_and_tags_doc():
    text = " ".join([REPORT] * 40)
    chunks = extract.chunk(text, tokens=200, overlap=20)
    m = Replay([GOOD] * len(chunks))
    res = extract.extract_report(m, TEMPLATE, text, "doc", tokens=200, overlap=20)
    assert len(res) == len(chunks) == len(m.prompts)
    assert {t["doc_id"] for r in res for t in r.transitions} == {"doc"}


def test_anthropic_model_logs_and_detects_refusal(tmp_path):
    from types import SimpleNamespace

    from ctit.calls import CallLogger

    def resp(stop):
        return SimpleNamespace(stop_reason=stop, stop_details=None,
                               usage=SimpleNamespace(input_tokens=1000, output_tokens=200),
                               content=[SimpleNamespace(type="thinking", thinking=""),
                                        SimpleNamespace(type="text", text="[]")])

    sent = []

    class Client:
        class messages:
            @staticmethod
            def create(**kw):
                sent.append(kw)
                return resp("end_turn" if len(sent) == 1 else "refusal")

    pin = {"model": "claude-opus-5-5", "options": {"effort": "high", "max_tokens": 8000},
           "usd_per_mtok": {"input": 4.0, "output": 20.0}}
    m = extract.AnthropicModel(pin, client=Client())
    calls = CallLogger(tmp_path / "calls.jsonl")
    assert m.chat("UNIQUE-PROMPT-TEXT", calls) == "[]"
    assert "temperature" not in sent[0] and sent[0]["output_config"] == {"effort": "high"}
    rec = json.loads((tmp_path / "calls.jsonl").read_text().splitlines()[0])
    assert rec["cost_usd"] == pytest.approx((1000 * 4 + 200 * 20) / 1e6) and "UNIQUE-PROMPT-TEXT" not in json.dumps(rec)
    with pytest.raises(extract.Refusal):
        m.chat("again", calls)


def test_self_transitions_rejected_and_counted_by_reason():
    bad = json.dumps([_t("Execution", "Execution", "a PowerShell loader ran"),
                      _t("Initial Access", "Execution", "a PowerShell loader ran")])
    r = extract.extract_chunk(Replay([bad]), TEMPLATE, REPORT, "d1", 0)
    assert len(r.transitions) == 1 and "self-transition" in r.rejected[0][1]
    assert extract.summarize([r])["rejected_by_reason"] == {"self-transition": 1}


def test_default_chunking_is_6k_with_300_overlap():
    assert (extract.CHUNK_TOKENS, extract.CHUNK_OVERLAP) == (6000, 300)
    text = " ".join(f"w{i}" for i in range(12000))  # 76,889 chars
    chunks = extract.chunk(text)
    assert all(len(c) <= 24000 for c in chunks) and len(chunks) == -(-(len(text) - 24000) // 22800) + 1


def test_one_count_per_report_and_edge_with_mentions_kept():
    one = json.dumps([_t("Initial Access", "Execution", "a PowerShell loader ran")])
    r_a0 = extract.extract_chunk(Replay([one]), TEMPLATE, REPORT, "a", 0)
    r_a1 = extract.extract_chunk(Replay([one]), TEMPLATE, REPORT, "a", 1)   # same report, next chunk
    r_b0 = extract.extract_chunk(Replay([one]), TEMPLATE, REPORT, "b", 0)   # another report
    out = extract.build_prior([r_a0, r_a1, r_b0], alpha=0.5)
    ia, ex = prior.INDEX["Initial Access"], prior.INDEX["Execution"]
    assert np.array(out["counts"])[ia, ex] == 2
    assert np.array(out["counts_mentions"])[ia, ex] == 3
    assert out["meta"]["chunks_per_doc"] == {"a": 2, "b": 1}


def test_memory_prompt_gets_aliases_and_samples_are_separate_documents():
    tmpl = "Actor: <<ACTOR>> (<<ALIASES>>)\n<<TACTICS>>"
    resp = json.dumps([_t("Initial Access", "Execution", "Recalled."), _t("Initial Access", "Execution", "Again.")])
    m = Replay([resp, resp])
    r0 = extract.memory_transitions(m, tmpl, "APT29", aliases=["Cozy Bear", "NOBELIUM"], sample=0)
    r1 = extract.memory_transitions(m, tmpl, "APT29", aliases=["Cozy Bear", "NOBELIUM"], sample=1)
    assert "Actor: APT29 (Cozy Bear, NOBELIUM)" in m.prompts[0]
    assert {r0.doc_id, r1.doc_id} == {"memory:APT29#s0", "memory:APT29#s1"}
    C = np.array(extract.build_prior([r0])["counts"])
    assert C[prior.INDEX["Initial Access"], prior.INDEX["Execution"]] == 1  # one count per sample


def test_approved_prompts_render():
    rep = extract.load_prompt("extract_v1.txt")
    mem = extract.load_prompt("memory_v1.txt")
    p = extract.render(rep, tactics=extract.tactic_list(), text="EXCERPT")
    assert "<excerpt>\nEXCERPT\n</excerpt>" in p and "different tactics" in p
    q = extract.render(mem, tactics=extract.tactic_list(), actor="APT29", aliases="Cozy Bear")
    assert "APT29 (also tracked as: Cozy Bear)" in q


def test_fragment_aware_evidence_check():
    src = "The implant created a “scheduled task” for persistence — then it beaconed out."
    ok = extract.evidence_ok_fragments
    assert ok('The implant created a "scheduled task" ... it beaconed out.', src)
    assert ok("created a “scheduled task”… then it beaconed", src)
    assert ok("persistence - then it beaconed", src)          # dash normalized
    assert not ok("then it beaconed ... The implant created", src)  # out of order
    assert not ok("The implant created ... exfiltrated 4 GB", src)  # a fragment is missing
    assert ok("The implant created ... it ... then it beaconed", src)  # "it" < 8 chars is ignored
    assert not ok("it ... then", src)                               # nothing >= 8 chars to check
    assert not extract.evidence_ok('The implant created a "scheduled task"', src)  # strict unchanged


def test_summary_reports_both_rates():
    resp = json.dumps([_t("Initial Access", "Execution", "spearphishing emails ... a PowerShell loader ran"),
                       _t("Execution", "Persistence", "the implant created a scheduled task")])
    r = extract.extract_chunk(Replay([resp]), TEMPLATE, REPORT, "d1", 0)
    s = extract.summarize([r])
    assert s["hallucinated_span_rate"] == 0.5 and s["hallucinated_span_rate_fragments"] == 0.0
