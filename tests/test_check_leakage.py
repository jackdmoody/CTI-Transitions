from pathlib import Path

import pytest

from ctit.cti import manifest
from scripts import check_leakage

FIXTURES = Path(__file__).parent / "fixtures" / "manifests"


def _check(name):
    header, rows = manifest.load(FIXTURES / f"{name}.csv")
    return manifest.check(header, rows, manifest.load_actors())


def test_good_manifest_passes():
    assert _check("good") == []


@pytest.mark.parametrize("name, expected", [
    ("bad_cited_prior", "prior doc is cited by the emulation plan"),
    ("bad_both_roles", "used as both prior and eval"),
    ("bad_too_few_priors", "actor OilRig: 1 prior docs"),
    ("bad_group_mapping_eval", "eval doc is an ATT&CK group mapping"),
])
def test_bad_manifests_fail(name, expected):
    errors = _check(name)
    assert any(expected in e for e in errors), errors


def test_empty_manifest_fails_on_missing_priors(tmp_path):
    path = tmp_path / "manifest.csv"
    manifest.write_empty(path)
    header, rows = manifest.load(path)
    errors = manifest.check(header, rows, manifest.load_actors())
    assert {e.split(":")[0] for e in errors} == {"actor APT29", "actor menuPass", "actor OilRig", "actor Sandworm"}


def test_wrong_header_fails(tmp_path):
    path = tmp_path / "m.csv"
    path.write_text("doc_id,actor\n")
    assert "header must be exactly" in manifest.check(*manifest.load(path), manifest.load_actors())[0]


def test_text_hash_verified(tmp_path):
    header, rows = manifest.load(FIXTURES / "good.csv")
    rows = rows[:1]
    (tmp_path / f"{rows[0]['doc_id']}.txt").write_text("not the fixture text")
    errors = manifest.check(header, rows, {"APT29": {"nation": "Russia", "core": False}}, text_dir=tmp_path)
    assert any("sha256 does not match" in e for e in errors)


def test_cli_exit_codes(capsys):
    assert check_leakage.main(["--manifest", str(FIXTURES / "good.csv"), "--no-verify-text"]) == 0
    assert check_leakage.main(["--manifest", str(FIXTURES / "bad_cited_prior.csv"), "--no-verify-text"]) == 1


def test_cited_url_must_be_marked_y():
    header, rows = manifest.load(FIXTURES / "good.csv")
    actors = manifest.load_actors()
    url = rows[0]["url"]  # an APT29 prior, marked cited_by_emulation_plan=n
    cited = {"APT29": {manifest.normalize_url(url.replace("https://", "https://www."))}}
    errors = manifest.check(header, rows, actors, cited=cited)
    assert any("cited by the APT29 emulation plan" in e for e in errors)
    assert manifest.check(header, rows, actors, cited={"APT29": set()}) == []


def test_normalize_url():
    assert manifest.normalize_url("https://www.Example.org/a/b/|") == "example.org/a/b"
    assert manifest.normalize_url("http://example.org/a/<br>") == "example.org/a"
