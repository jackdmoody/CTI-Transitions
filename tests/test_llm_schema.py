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


def test_sampled_mode_sends_seed_and_no_temperature(tmp_path, monkeypatch):
    models, man = _setup(tmp_path)
    cfg = yaml.safe_load(models.read_text())
    cfg["open_weight"]["S"]["sampled"] = {"options": {"num_ctx": 8192, "think": False}, "seeds": [0, 1, 2, 3, 4]}
    models.write_text(yaml.safe_dump(cfg))
    sent = {}

    def fake_urlopen(req, timeout):
        sent.update(json.loads(req.data))
        return io.BytesIO(json.dumps({"message": {"content": "[]"}}).encode())

    monkeypatch.setattr(ollama.urllib.request, "urlopen", fake_urlopen)
    m = ollama.OllamaModel("S", models_path=models, manifests=man, sample=3)
    m.chat("hello")
    assert sent["options"] == {"num_ctx": 8192, "seed": 3} and sent["think"] is False
    assert m.name.endswith("#sample3")


def test_pinned_sampling_matches_spec():
    """Spec §3 (2026-10-27): F sends no sampling parameters, effort pinned, 5 samples;
    S primary at temperature 0, S sampled at default sampling with 5 seeds. S and S_3B are
    Ministral 3 Instruct (no thinking mode; Modelfile default temperature 0.15, sent explicitly);
    the superseded Qwen pin keeps the settings its run used (thinking off)."""
    cfg = yaml.safe_load(ollama.MODELS.read_text())
    f = cfg["frontier"]["F"]
    assert "temperature" not in f["options"] and f["options"]["effort"] and f["samples"] == 5
    for slot in ("S", "S_3B"):
        s = cfg["open_weight"][slot]
        assert s["tag"].startswith("ministral-3-nosys:") and "-instruct-" in s["tag"]
        assert s["base_tag"].startswith("ministral-3:") and "-instruct-" in s["base_tag"]
        assert s["options"] == {"temperature": 0, "num_ctx": 16384}
        assert s["sampled"]["options"] == {"temperature": 0.15, "num_ctx": 16384}
        assert len(s["sampled"]["seeds"]) == 5
    q = cfg["open_weight"]["S_qwen3_14b"]
    assert q["tag"] == "qwen3:14b" and q["options"]["think"] is False
    assert "temperature" not in q["sampled"]["options"] and q["sampled"]["options"]["think"] is False


def test_ministral_modelfiles_have_no_default_system_prompt():
    """SPEC_ISSUES 2026-10-27: the pinned Modelfiles drop the template's default system prompt
    (persona and current date) and are committed with their sha256."""
    import hashlib
    cfg = yaml.safe_load(ollama.MODELS.read_text())["open_weight"]
    for slot in ("S", "S_3B"):
        path = ollama.REPO_ROOT / cfg[slot]["modelfile"]
        raw = path.read_text()
        assert hashlib.sha256(raw.encode()).hexdigest() == cfg[slot]["modelfile_sha256"]
        text = "\n".join(line for line in raw.splitlines() if not line.startswith("# "))  # header comment out
        assert "currentDate" not in text and "yesterdayDate" not in text and "Le Chat" not in text
        assert "[SYSTEM_PROMPT]{{ .Content }}[/SYSTEM_PROMPT]" in text  # a caller's system message still renders
        assert cfg[slot]["weights_sha256"] in text  # FROM the official weights blob


def test_template_digest_is_verified(tmp_path):
    models, man = _setup(tmp_path)
    cfg = yaml.safe_load(models.read_text())
    cfg["open_weight"]["S"]["template_sha256"] = "other"
    models.write_text(yaml.safe_dump(cfg))
    with pytest.raises(ollama.DigestMismatch, match="template"):
        ollama.OllamaModel("S", models_path=models, manifests=man).verify()
