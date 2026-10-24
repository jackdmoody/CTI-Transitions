import json

import pandas as pd
import pytest

from ctit.ingest import canonical, otrf
from ctit.map.coverage import brims_tag, coverage

SYSMON = "Microsoft-Windows-Sysmon/Operational"


def _write(path, rows):
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))


def _sysmon(i, host="SCRANTON.dmevals.local", eid=1, image="C:\\Windows\\System32\\cmd.exe"):
    return {"Channel": SYSMON, "Hostname": host, "EventID": eid, "Image": image,
            "CommandLine": "cmd.exe /c whoami", "ParentImage": "C:\\Windows\\explorer.exe",
            "UtcTime": f"2020-05-02 02:55:{i:02d}.123", "EventTime": f"2020-05-01 22:55:{i:02d}",
            "Message": "dropped", "Task": 1}


def test_read_day_offsets_sources_and_fields(tmp_path):
    path = tmp_path / "day.json"
    _write(path, [_sysmon(i) for i in range(10)] + [
        {"Channel": "security", "Hostname": "NEWYORK.dmevals.local", "EventID": 4768,
         "EventTime": "2020-05-01 23:00:00", "TargetUserName": "pam"},
        {"Channel": "Windows PowerShell", "Hostname": "SCRANTON.dmevals.local", "EventID": 400,
         "EventTime": "2020-05-01 23:00:00"},
    ])
    df = canonical.to_frame(otrf.read_day(path))
    assert set(df["source"]) == {"sysmon", "security"}  # PowerShell not in default sources
    sec = df[df["source"] == "security"].iloc[0]
    assert sec["_timestamp"] == pd.Timestamp("2020-05-02 03:00:00", tz="UTC")  # EventTime + 4h
    assert df.loc[df["source"] == "sysmon", "_timestamp"].iloc[0] == pd.Timestamp("2020-05-02 02:55:00.123", tz="UTC")
    assert "Message" not in df.columns and df["Task"].dtype == "string"
    assert set(df["Hostname"]) == {"scranton", "newyork"}
    assert otrf.infer_roles([df]) == {"newyork": "dc", "scranton": "workstation"}


def test_inconsistent_offset_raises(tmp_path):
    rows = [_sysmon(i) for i in range(10)]
    rows += [dict(_sysmon(i), EventTime=f"2020-05-02 02:55:{i:02d}") for i in range(10)]
    path = tmp_path / "day.json"
    _write(path, rows)
    with pytest.raises(ValueError, match="not constant"):
        otrf.measure_offset(path)


def test_brims_coverage_on_canonical(tmp_path):
    path = tmp_path / "day.json"
    _write(path, [_sysmon(i) for i in range(5)] + [_sysmon(9, eid=13, image="C:\\x.exe")])
    tagged = brims_tag(canonical.to_frame(otrf.read_day(path)))
    report = coverage(tagged)
    # cmd.exe -> T1059.003 Execution; Sysmon 13 (registry set) -> T1547.001 Persistence
    assert report["tactic_counts"] == {"Execution": 5, "Persistence": 1}
    assert report["K"]["sysmon"] == ["Execution", "Persistence"]
    assert report["by_source"]["sysmon"]["tag_rate"] == 1.0
