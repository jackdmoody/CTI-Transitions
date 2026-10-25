import json
import tarfile
import zipfile

import pandas as pd

from ctit.ingest import otrf_atomic


def test_techniques_from_metadata():
    meta = {"attack_mappings": [{"technique": "T1003", "sub-technique": "001"},
                                {"technique": "t1021", "sub-technique": None},
                                {"technique": "T1003", "sub-technique": "1"}]}
    assert otrf_atomic.techniques(meta) == ["T1003.001", "T1021"]


def test_flatten_winlogbeat():
    r = {"log_name": "Microsoft-Windows-Sysmon/Operational", "event_id": 3, "computer_name": "HFDC01.shire.com",
         "event_data": {"Image": "C:\\x.exe", "UtcTime": "2019-05-18 20:19:20.052"}, "@timestamp": "2019-05-18T20:19:21Z"}
    flat = otrf_atomic.flatten_winlogbeat(r)
    assert flat["Channel"] == r["log_name"] and flat["EventID"] == 3 and flat["Image"] == "C:\\x.exe"
    assert otrf_atomic.flatten_winlogbeat({"Channel": "Security"}) == {"Channel": "Security"}


def _rows():
    return [
        {"Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "WS1.lab", "EventID": 1,
         "UtcTime": "2020-09-21 17:09:43.000", "EventTime": "2020-09-21 13:09:43", "Image": "C:\\a.exe"},
        {"Channel": "security", "Hostname": "WS1.lab", "EventID": 4688, "EventTime": "2020-09-21 13:09:44"},
        {"Channel": "Security", "Hostname": "WS1.lab", "EventID": 4624, "TimeCreated": "2022-01-01T00:00:01.5Z"},
        {"Channel": "Windows PowerShell", "Hostname": "WS1.lab", "EventID": 400, "@timestamp": "2022-01-01T00:00:00Z"},
    ]


def test_read_zip_skips_resource_forks_and_orders_timestamps(tmp_path):
    path = tmp_path / "SDWIN-1__x.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("x.json", "\n".join(json.dumps(r) for r in _rows()))
        z.writestr("__MACOSX/._x.json", b"\x00\x05\x16\x07binary")
    df = otrf_atomic.read_zip(path)
    assert len(df) == 3  # PowerShell is not a kept source
    by_id = df.set_index("EventID")
    assert by_id.loc[1, "_ts_source"] == "UtcTime"
    assert by_id.loc[4688, "_timestamp"] == pd.Timestamp("2020-09-21 17:09:44", tz="UTC")  # EventTime + 4h
    assert by_id.loc[4688, "_ts_source"] == "EventTime"
    assert by_id.loc[4624, "_ts_source"] == "TimeCreated"
    assert set(df["Hostname"]) == {"ws1"}


def test_read_tar_gz(tmp_path):
    src = tmp_path / "x.json"
    src.write_text(json.dumps({"log_name": "Security", "event_id": 4624, "computer_name": "DC.lab",
                               "event_data": {"LogonType": "3"}, "@timestamp": "2019-05-18T20:19:20.052Z"}) + "\n")
    path = tmp_path / "SDWIN-2__y.tar.gz"
    with tarfile.open(path, "w:gz") as t:
        t.add(src, arcname="y.json")
    df = otrf_atomic.read_zip(path)
    assert list(df["EventID"]) == [4624] and df.loc[0, "LogonType"] == "3" and df.loc[0, "_ts_source"] == "@timestamp"
