import numpy as np
import pandas as pd
import pytest
import yaml

from ctit.eval import optc_redteam, optc_split


def test_draw_is_seeded_disjoint_and_sized():
    hosts = [f"sysclient{i:04d}" for i in range(446)]
    a, b = optc_split.draw(hosts, 7), optc_split.draw(list(reversed(hosts)), 7)
    assert a == b  # input order doesn't matter
    assert {k: len(v) for k, v in a.items()} == {"fit": 223, "validation": 67, "test": 156}
    assert set(a["fit"]).isdisjoint(a["validation"]) and set(a["fit"]).isdisjoint(a["test"])
    assert set(a["validation"]).isdisjoint(a["test"])
    assert optc_split.draw(hosts, 8) != a


def test_committed_split_excludes_redteam_and_is_complete():
    split = optc_split.load_split()
    red = set(optc_split.redteam_hosts())
    allh = [h for v in split.values() for h in v]
    assert len(allh) == len(set(allh)) == 446
    assert not red & set(allh)
    doc = yaml.safe_load(optc_split.SPLIT.read_text())
    assert doc["counts"] == {"fit": 223, "validation": 67, "test": 156}


def test_host_id():
    assert optc_split.host_id("SysClient0052.systemia.com.parquet") == "sysclient0052"
    assert optc_split.host_id("Sysclient0201") == "sysclient0201"


def _labels():
    return pd.DataFrame({
        "scenario": ["sc1", "sc1"], "host": ["sysclient0201", "sysclient0201"], "pid": [100, 200],
        "start": pd.to_datetime(["2019-09-23T15:00:00Z", "2019-09-23T16:00:00Z"]),
        "end": pd.to_datetime(["2019-09-23T15:10:00Z", "2019-09-23T16:10:00Z"])})


def test_label_events_needs_host_pid_and_time():
    ev = pd.DataFrame({
        "Hostname": ["sysclient0201", "sysclient0201", "sysclient0201", "sysclient0402"],
        "_timestamp": pd.to_datetime(["2019-09-23T15:05:00Z", "2019-09-23T15:20:00Z",
                                      "2019-09-23T16:05:00Z", "2019-09-23T15:05:00Z"]),
        "ProcessId": ["100", "100", "999", "100"]})
    assert optc_redteam.label_events(ev, _labels()).tolist() == [True, False, False, False]


def test_windows_positive_if_any_event_malicious():
    ts = pd.date_range("2019-09-23T15:00:00Z", periods=17, freq="1min")
    tagged = pd.DataFrame({"Hostname": "sysclient0201", "_timestamp": ts, "tactic": "Execution",
                           "malicious": [False] * 9 + [True] + [False] * 7})
    w = optc_redteam.windows(tagged)
    assert len(w) == 2  # 17 tagged events -> 2 full windows, the 17th dropped
    assert w["positive"].tolist() == [False, True]
    mal = {"sysclient0201": np.array([ts[3].to_datetime64()])}
    assert optc_redteam.windows(tagged, mal)["positive_span"].tolist() == [True, False]


@pytest.mark.skipif(not optc_redteam.LABELS.exists(), reason="Inria labels not on this machine")
def test_real_labels_load():
    lab = optc_redteam.load_labels()
    assert set(lab["scenario"]) == {"sc1", "sc2", "sc3"}
    assert lab["start"].dt.tz is not None and (lab["end"] >= lab["start"]).all()
    red = set(optc_split.redteam_hosts()) | {"dc1"}
    assert set(lab["host"]) <= red
