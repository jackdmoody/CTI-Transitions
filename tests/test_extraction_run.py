"""Extraction runner with replayed responses: caching, refusals, per-sample priors. No API/Ollama."""
import json

import pytest

from ctit.calls import CallLogger
from ctit.cti import extract
from ctit.experiments import extraction

RESP = json.dumps([{"from_tactic": "Initial Access", "to_tactic": "Execution",
                    "evidence_span": "then ran", "confidence": 0.9}])


class Replay:
    def __init__(self, name, out):
        self.name, self.out, self.n = name, out, 0

    def chat(self, prompt, calls=None, *, system=None, attempt=1):
        self.n += 1
        if isinstance(self.out, Exception):
            raise self.out
        return self.out


def test_cache_replays_text_and_refusals(tmp_path):
    m = Replay("x", RESP)
    c = extraction.Cached(m, "k", root=tmp_path)
    assert c.chat("p") == RESP and c.chat("p") == RESP and m.n == 1 and c.hits == 1
    r = Replay("y", extract.Refusal("no"))
    c = extraction.Cached(r, "k2", root=tmp_path)
    for _ in range(2):
        with pytest.raises(extract.Refusal):
            c.chat("p")
    assert r.n == 1


def test_run_builds_one_prior_per_sample(tmp_path, monkeypatch):
    monkeypatch.setattr("scripts.check_leakage.main", lambda argv: 0)
    monkeypatch.setattr(extraction, "PRIORS", tmp_path / "priors")
    monkeypatch.setattr(extraction, "jobs", lambda config: [
        {"cond": "R", "actor": "APT29", "doc_id": "APT29-P01", "text": "they phished and then ran a loader"},
        {"cond": "B", "actor": "APT29", "doc_id": "memory:APT29"}])
    monkeypatch.setattr(extraction, "models_for", lambda mode, pins: [
        (f"s{i}", extraction.Cached(Replay("replay", RESP), f"k{i}", root=tmp_path / "cache")) for i in range(2)])
    (tmp_path / "run1").mkdir()
    calls = CallLogger(tmp_path / "run1" / "calls.jsonl")
    cfg = {"actors": ["APT29"], "conditions": ["R", "B"], "modes": ["F"], "alpha": 0.5,
           "prompts": {"report": "extract_v1.txt", "memory": "memory_v1.txt"},
           "chunk": {"tokens": 6000, "overlap": 300}, "workers": {"F": 2}}
    out = extraction.run(cfg, calls)
    pri = out["modes"]["F"]["priors"]
    assert set(pri) == {"R/APT29", "B/APT29"} and set(pri["R/APT29"]) == {"s0", "s1", "_summary"}
    assert pri["R/APT29"]["s0"]["hallucinated_span_rate"] == 0.0
    assert pri["B/APT29"]["s0"]["hallucinated_span_rate"] is None
    assert pri["R/APT29"]["s0"]["edges"] == 1 and "recovery" in pri["R/APT29"]["s0"]
    assert (tmp_path / "priors" / "run1" / "F" / "R_APT29_s0.json").exists()


class Seq:
    """Returns its responses in order: a fresh call gets the next one."""
    name = "seq"

    def __init__(self, out):
        self.out, self.n = list(out), 0

    def chat(self, prompt, calls=None, *, system=None, attempt=1):
        self.n += 1
        return self.out.pop(0)


def test_schema_retry_through_cache_is_a_fresh_call(tmp_path):
    m = Seq(["```json\n[", RESP])
    c = extraction.Cached(m, "k", root=tmp_path)
    items, attempts, status = extract.ask(c, "p")
    assert status == "ok" and attempts == 2 and m.n == 2
    # a second run replays both attempts from the cache without calling the model
    items, attempts, status = extract.ask(extraction.Cached(m, "k", root=tmp_path), "p")
    assert status == "ok" and attempts == 2 and m.n == 2


def test_attempt_one_keeps_the_original_cache_file(tmp_path):
    import hashlib
    c = extraction.Cached(Replay("x", RESP), "k", root=tmp_path)
    c.chat("p")
    assert (c.dir / f"{hashlib.sha256(b'p').hexdigest()}.json").exists()


def test_models_for_open_weight_slots(monkeypatch):
    made = []

    class Fake:
        def __init__(self, slot, *, url, sample=None):
            self.pin = {"tag": slot, "weights_sha256": "w"}
            self.options, self.name = {"seed": sample}, slot
            made.append((slot, sample))

        def verify(self):
            pass

    monkeypatch.setattr(extraction, "OllamaModel", Fake)
    monkeypatch.setattr(extraction, "Cached", lambda m, key: m)  # no cache dirs in data/
    pins = {"open_weight": {"S_3B": {"sampled": {"seeds": [0, 1, 2]}}}}
    assert [s for s, _ in extraction.models_for("S_3B", pins)] == ["t0"]
    assert [s for s, _ in extraction.models_for("S_3B-sampled", pins)] == ["s0", "s1", "s2"]
    assert made == [("S_3B", None), ("S_3B", 0), ("S_3B", 1), ("S_3B", 2)]
    with pytest.raises(ValueError):
        extraction.models_for("S_7B", pins)
