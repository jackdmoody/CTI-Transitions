"""schema_failures: the wrapping-only classifier never changes JSON content, and the replay uses a
fixed first attempt only when its class is `wrapping`."""
import hashlib
import json

import pytest

from ctit.cti import extract
from ctit.experiments import schema_failures as sf

ITEM = '{"from_tactic": "Initial Access", "to_tactic": "Execution", "evidence_span": "x", "confidence": 0.5}'


@pytest.mark.parametrize("text, cls, detail", [
    (f"[{ITEM}]", "ok", None),
    (f"```json\n[{ITEM}]\n```", "ok", None),
    (f"```json\n[{ITEM}]", "wrapping", "before: fence"),                       # unclosed fence
    (f"```json\n[{ITEM}]\n```\n\n**Note** a guess.", "wrapping", "before: fence; after: prose"),
    ("[]\n(The excerpt has no ordered transitions.)", "wrapping", "after: prose"),
    (f"Here you go:\n[{ITEM}]", "wrapping", "before: prose"),
    ("[]\n```json\n[]\n```", "multiple_values", "first value list of 0; next value list of 0 (identical)"),
    (f"[]\n```json\n[{ITEM}]\n```", "multiple_values", "first value list of 0; next value list of 1"),
    ('```json\n[{"evidence_span": "C:\\Users\\x"}]\n```', "malformed", None),  # bad escape
    (f"```json\n[{ITEM},]\n```", "malformed", None),                           # trailing comma
    (f"[{ITEM[:-10]}", "malformed", None),                                     # truncated
    ('{"transitions": []}', "not_list", "dict"),
    ("No transitions.", "no_json", None),
])
def test_classify(text, cls, detail):
    c = sf.classify(text)
    assert c["class"] == cls
    if detail is not None:
        assert c["detail"] == detail
    if cls == "wrapping":
        assert c["json"] in text  # a substring: content unchanged
        assert json.loads(c["json"]) is not None


def test_first_bracket_only():
    # the outer list fails; a nested object that would decode is not picked instead
    c = sf.classify('[{"a": "C:\\x"}, ' + ITEM + "]")
    assert c["class"] == "malformed"


def _write(d, prompt, attempt, rec):
    h = hashlib.sha256(prompt.encode()).hexdigest()
    (d / (f"{h}.json" if attempt == 1 else f"{h}.a{attempt}.json")).write_text(json.dumps(rec))


def test_replay(tmp_path):
    p = "prompt"
    _write(tmp_path, p, 1, {"text": f"[{ITEM}]\n(prose)"})
    _write(tmp_path, p, 2, {"text": "[]"})
    as_run = sf.Replay(tmp_path, unwrap=False)
    assert extract.ask(as_run, p)[1:] == (2, "ok")
    assert extract.ask(as_run, p)[0] == []
    fixed = sf.Replay(tmp_path, unwrap=True)
    items, attempts, status = extract.ask(fixed, p)
    assert (attempts, status, len(items), len(fixed.used)) == (1, "ok", 1, 1)


def test_replay_keeps_as_run_for_other_classes(tmp_path):
    p = "prompt"
    _write(tmp_path, p, 1, {"text": "[]\n```json\n[" + ITEM + "]\n```"})  # multiple values: not fixed
    _write(tmp_path, p, 2, {"text": "[]\n```json\n[" + ITEM + "]\n```"})
    m = sf.Replay(tmp_path, unwrap=True)
    assert extract.ask(m, p)[1:] == (2, "skipped_schema") and m.used == []


def test_replay_refusal_and_no_calls(tmp_path):
    _write(tmp_path, "r", 1, {"refusal": "no"})
    with pytest.raises(extract.Refusal):
        sf.Replay(tmp_path, True).chat("r")
    with pytest.raises(FileNotFoundError):  # never calls a model
        sf.Replay(tmp_path, True).chat("missing")
