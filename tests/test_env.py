import pytest

from ctit import env


def test_key_from_dotenv(monkeypatch, tmp_path):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    (tmp_path / ".env").write_text("ANTHROPIC_API_KEY=test-value\n")
    monkeypatch.setattr(env, "REPO_ROOT", tmp_path)
    assert env.anthropic_api_key() == "test-value"


def test_missing_key_raises(monkeypatch, tmp_path):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.setattr(env, "REPO_ROOT", tmp_path)
    with pytest.raises(RuntimeError, match=".env.example"):
        env.anthropic_api_key()
