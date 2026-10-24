import json

import pytest
import yaml

from ctit import run as ctit_run
from ctit.calls import CallLogger, prompt_sha256


@pytest.fixture
def fake_experiment(monkeypatch):
    def experiment(config, calls):
        calls.log(model="m", prompt="secret prompt", input_tokens=3, output_tokens=1,
                  latency_s=0.1, cost_usd=0.0)
        return {"answer": config["x"] * 2}
    monkeypatch.setitem(ctit_run.EXPERIMENTS, "fake", experiment)
    monkeypatch.setattr(ctit_run, "git_state", lambda: ("a" * 40, False))


def _config(tmp_path, **extra):
    path = tmp_path / "c.yaml"
    path.write_text(yaml.safe_dump({"experiment": "fake", "x": 21, "seeds": [1, 2], **extra}))
    return path


def test_run_writes_contract_files(tmp_path, fake_experiment):
    out = ctit_run.run(_config(tmp_path), results_root=tmp_path / "results")
    assert sorted(p.name for p in out.iterdir()) == ["calls.jsonl", "config.yaml", "metrics.json"]
    assert json.loads((out / "metrics.json").read_text()) == {"answer": 42}
    prov = yaml.safe_load((out / "config.yaml").read_text())["_provenance"]
    assert prov["git_sha"] == "a" * 40 and prov["seeds"] == [1, 2]
    assert len(prov["drift_commit"]) == 40


def test_rerun_from_written_config(tmp_path, fake_experiment):
    first = ctit_run.run(_config(tmp_path), results_root=tmp_path / "r1")
    second = ctit_run.run(first / "config.yaml", results_root=tmp_path / "r2")
    assert (first / "metrics.json").read_text() == (second / "metrics.json").read_text()


def test_dirty_tree_refused(tmp_path, fake_experiment, monkeypatch):
    monkeypatch.setattr(ctit_run, "git_state", lambda: ("b" * 40, True))
    with pytest.raises(RuntimeError, match="uncommitted"):
        ctit_run.run(_config(tmp_path), results_root=tmp_path / "results")
    out = ctit_run.run(_config(tmp_path), allow_dirty=True, results_root=tmp_path / "results")
    assert out.name.endswith("-dirty")


def test_call_log_has_hash_not_prompt(tmp_path):
    log = CallLogger(tmp_path / "calls.jsonl")
    log.log(model="m", prompt="do not store me", input_tokens=1, output_tokens=1,
            latency_s=0.0, cost_usd=None)
    text = (tmp_path / "calls.jsonl").read_text()
    assert "do not store me" not in text
    assert json.loads(text)["prompt_sha256"] == prompt_sha256("do not store me")
