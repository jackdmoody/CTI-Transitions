import io
import json

import pytest
import yaml

from ctit.calls import CallLogger
from ctit.cti import schema
from ctit.llm import ollama


def test_parse_and_validate():
    text = '```json\n[{"from_tactic": "Execution", "to_tactic": "Discovery", "evidence_span": "ran whoami", "confidence": 0.8, "technique_to": "t1033"},' \
           ' {"from_tactic": "Stealth", "to_tactic": "Discovery", "evidence_span": "x", "confidence": 0.5},' \
           ' {"from_tactic": "Execution", "to_tactic": "Impact", "evidence_span": "", "confidence": 0.5},' \
           ' {"from_tactic": "Execution", "to_tactic": "Impact", "evidence_span": "y", "confidence": 2}]\n```'
    ok, rejected = schema.validate(schema.parse(text))
    assert ok == [{"from_tactic": "Execution", "to_tactic": "Discovery", "evidence_span": "ran whoami",
                   "confidence": 0.8, "technique_to": "T1033"}]
    assert [r for _, r in rejected] == ["not an Enterprise tactic: ['Stealth']", "empty evidence_span",
                                        "confidence outside [0, 1]"]


def test_parse_rejects_non_list():
    with pytest.raises(schema.SchemaError):
        schema.parse('{"from_tactic": "Execution"}')
    with pytest.raises(schema.SchemaError):
        schema.parse("not json")


def _setup(tmp_path, digest="abc"):
    tmp_path.mkdir(parents=True, exist_ok=True)
    models = tmp_path / "models.yaml"
    models.write_text(yaml.safe_dump({"open_weight": {"S": {
        "tag": "qwen3:14b", "weights_sha256": "abc",
        "options": {"temperature": 0, "num_ctx": 8192, "think": False}}}}))
    man = tmp_path / "manifests" / "qwen3"
    man.mkdir(parents=True)
    (man / "14b").write_text(json.dumps({"layers": [
        {"mediaType": ollama.MODEL_LAYER, "digest": f"sha256:{digest}"},
        {"mediaType": "application/vnd.ollama.image.template", "digest": "sha256:t"}]}))
    return models, tmp_path / "manifests"


def test_verify_digest(tmp_path):
    models, man = _setup(tmp_path)
    ollama.OllamaModel("S", models_path=models, manifests=man).verify()
    models, man = _setup(tmp_path / "bad", digest="zzz")
    with pytest.raises(ollama.DigestMismatch):
        ollama.OllamaModel("S", models_path=models, manifests=man).verify()


def test_chat_sends_pinned_options_and_logs(tmp_path, monkeypatch):
    models, man = _setup(tmp_path)
    sent = {}

    def fake_urlopen(req, timeout):
        sent.update(json.loads(req.data))
        return io.BytesIO(json.dumps({"message": {"content": "[]"}, "prompt_eval_count": 12,
                                      "eval_count": 3}).encode())

    monkeypatch.setattr(ollama.urllib.request, "urlopen", fake_urlopen)
    calls = CallLogger(tmp_path / "calls.jsonl")
    out = ollama.OllamaModel("S", models_path=models, manifests=man).chat("hello", calls)
    assert out == "[]"
    assert sent["think"] is False and sent["options"] == {"temperature": 0, "num_ctx": 8192}
    rec = json.loads((tmp_path / "calls.jsonl").read_text())
    assert rec["input_tokens"] == 12 and rec["weights_sha256"] == "abc" and "hello" not in json.dumps(rec)
