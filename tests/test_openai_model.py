"""G (POST HOC, 2026-10-31): OpenAIModel matches F's protocol, without network calls."""
import json
from types import SimpleNamespace as NS

import pytest

from ctit.calls import CallLogger
from ctit.cti import extract
from ctit.experiments.extraction import Cached

PIN = {"provider": "openai", "model": "gpt-6-astra", "options": {"reasoning_effort": "high", "max_output_tokens": 32000},
       "samples": 5, "usd_per_mtok": {"input": 10.0, "output": 50.0}}
OK = '[{"from_tactic": "Execution", "to_tactic": "Persistence", "evidence_span": "x", "confidence": 0.9}]'


def resp(text=OK, status="completed", refusal=None, reason=None):
    content = [NS(type="refusal", refusal=refusal)] if refusal else [NS(type="output_text", text=text)]
    return NS(id="resp_1", model="gpt-6-astra-2026-10-01", status=status, temperature=1.0, top_p=1.0,
              incomplete_details=NS(reason=reason) if reason else None, output_text="" if refusal else text,
              output=[NS(type="reasoning"), NS(type="message", content=content)],
              usage=NS(input_tokens=1000, output_tokens=3000, output_tokens_details=NS(reasoning_tokens=2500),
                       input_tokens_details=NS(cached_tokens=0)))


class Client:
    def __init__(self, *rs):
        self.rs, self.sent = list(rs), []
        self.responses = NS(create=self._create)

    def _create(self, **kw):
        self.sent.append(kw)
        return self.rs.pop(0)


def test_request_is_user_message_only(tmp_path):
    c = Client(resp())
    calls = CallLogger(tmp_path / "calls.jsonl")
    m = extract.OpenAIModel(PIN, client=c)
    assert m.chat("PROMPT", calls) == OK
    sent = c.sent[0]
    assert set(sent) == {"model", "input", "reasoning", "max_output_tokens"}
    assert sent["input"] == [{"role": "user", "content": "PROMPT"}]
    assert sent["reasoning"] == {"effort": "high"} and sent["max_output_tokens"] == 32000
    rec = json.loads(calls.path.read_text())
    assert rec["model_returned"] == "gpt-6-astra-2026-10-01" and rec["response_id"] == "resp_1"
    assert rec["reasoning_tokens"] == 2500 and rec["cost_usd"] == pytest.approx((1000 * 10 + 3000 * 50) / 1e6)
    assert "PROMPT" not in calls.path.read_text()


def test_refusal_and_incomplete(tmp_path):
    m = extract.OpenAIModel(PIN, client=Client(resp(refusal="no")))
    with pytest.raises(extract.Refusal):
        m.chat("p")
    # incomplete -> schema failure -> one retry (a fresh call), as for F
    c = Client(resp(text="[", status="incomplete", reason="max_output_tokens"), resp())
    items, attempts, status = extract.ask(Cached(extract.OpenAIModel(PIN, client=c), "k", root=tmp_path), "p")
    assert status == "ok" and attempts == 2 and len(c.sent) == 2
    # the cached incomplete replays as the same failure
    c2 = Client()
    with pytest.raises(extract.Incomplete):
        Cached(extract.OpenAIModel(PIN, client=c2), "k", root=tmp_path).chat("p")
    assert c2.sent == []


def test_budget_stops_before_call():
    c = Client(resp())
    m = extract.OpenAIModel(PIN, client=c, budget=extract.Budget(cap_usd=1.0))  # worst case ~ $1.60 per call
    with pytest.raises(extract.BudgetExceeded):
        m.chat("p")
    assert c.sent == []
    b = extract.Budget(cap_usd=10.0)
    m = extract.OpenAIModel(PIN, client=Client(resp()), budget=b)
    m.chat("p")
    assert b.reserved == pytest.approx(0) and b.spent == pytest.approx(0.16)
