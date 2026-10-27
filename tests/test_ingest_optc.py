import pandas as pd

from ctit.ingest import optc


def _frame(rows):
    cols = ["ts", "host", "event_id", "image", "parent_image", "cmdline", "user", "dest_ip", "dest_port", "protocol",
            "target_image", "target_object", "target_filename", "registry_event_type", "logon_type"]
    df = pd.DataFrame([{c: r.get(c, "") for c in cols} for r in rows])
    df["ts"] = pd.to_datetime(df["ts"], utc=True)
    return df


ROWS = [
    # Volume 2 is the system drive here (C:); volume 1 is D:. Neither is assumed.
    {"ts": "2019-09-22T10:00:00Z", "host": "SysClient0201.systemia.com", "event_id": 1,
     "image": r"\Device\HarddiskVolume2\Windows\System32\cmd.exe",
     "parent_image": r"\Device\HarddiskVolume2\Windows\explorer.exe",
     "cmdline": r'"C:\Windows\System32\cmd.exe" /c whoami', "user": r"CORP\bob"},
    {"ts": "2019-09-22T10:00:01Z", "host": "SysClient0201.systemia.com", "event_id": 1,
     "image": r"\Device\HarddiskVolume1\tools\x.exe", "parent_image": r"\Device\HarddiskVolume2\Windows\System32\cmd.exe",
     "cmdline": r"D:\tools\x.exe -q", "user": r"CORP\bob"},
    {"ts": "2019-09-22T10:00:02Z", "host": "SysClient0201.systemia.com", "event_id": 13,
     "image": r"\Device\HarddiskVolume2\Windows\System32\reg.exe",
     "target_object": r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\x", "registry_event_type": "SetValue"},
    {"ts": "2019-09-22T10:00:03Z", "host": "SysClient0201.systemia.com", "event_id": 12,
     "image": r"\Device\HarddiskVolume3\a.exe", "target_object": r"\REGISTRY\USER\S-1-5-21-1\Software\x"},
    {"ts": "2019-09-22T10:00:04Z", "host": "SysClient0201.systemia.com", "event_id": 11,
     "image": "System", "target_filename": r"\Device\HarddiskVolume2\Users\bob\a.txt"},
    {"ts": "2019-09-22T10:00:05Z", "host": "SysClient0201.systemia.com", "event_id": 9999, "image": "x"},
]


def test_drive_map_from_evidence():
    df = _frame(ROWS)
    p = df[df.event_id == 1]
    m = optc.drive_map(p["image"], p["cmdline"])
    assert m["2"] == {"letter": "C", "votes": 1, "conflicts": {}, "system32": True}
    assert m["1"]["letter"] == "D" and not m["1"]["system32"]


def test_to_frame_normalizes_paths_and_hives():
    out, dmap = optc.to_frame(_frame(ROWS))
    assert list(out["EventID"]) == [1, 1, 13, 12, 11]  # unknown event id dropped
    assert set(out["source"]) == {"sysmon"} and set(out["Hostname"]) == {"sysclient0201"}
    assert out.loc[0, "Image"] == r"C:\Windows\System32\cmd.exe"
    assert out.loc[0, "ParentImage"] == r"C:\Windows\explorer.exe"
    assert out.loc[1, "Image"] == r"D:\tools\x.exe"
    assert out.loc[2, "TargetObject"] == r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\x"
    assert out.loc[3, "TargetObject"] == r"HKU\S-1-5-21-1\Software\x"
    assert out.loc[3, "Image"] == r"\Device\HarddiskVolume3\a.exe"  # no evidence for volume 3: left as-is
    assert out.loc[4, "TargetFilename"] == r"C:\Users\bob\a.txt"
    assert pd.isna(out.loc[4, "CommandLine"])


def test_to_frame_without_normalization_keeps_kernel_forms():
    out, dmap = optc.to_frame(_frame(ROWS), normalize=False)
    assert dmap == {}
    assert out.loc[0, "Image"] == r"\Device\HarddiskVolume2\Windows\System32\cmd.exe"
    assert out.loc[2, "TargetObject"].startswith("\\REGISTRY\\MACHINE\\")


def test_registry_prefix_is_whole_segment():
    assert optc.normalize_registry(r"\REGISTRY\MACHINEX\a") == r"\REGISTRY\MACHINEX\a"
    assert optc.normalize_registry(r"\Registry\Machine\SYSTEM") == r"HKLM\SYSTEM"


def test_carry_column_survives_sort():
    df = _frame(ROWS).assign(_w=[5, 4, 3, 2, 1, 0])
    out, _ = optc.to_frame(df, carry=("_w",))
    assert list(out["_w"]) == [5, 4, 3, 2, 1]
