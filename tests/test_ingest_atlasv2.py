import pandas as pd

from ctit.ingest import atlasv2, canonical

XML = """<?xml version="1.0" encoding="UTF-8"?>
<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Sysmon" Guid="{x}"/>
    <EventID>1</EventID>
    <TimeCreated SystemTime="2022-07-19T15:01:02.345678900Z"/>
    <Execution ProcessID="1" ThreadID="2"/>
    <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
    <Computer>DESKTOP-1</Computer>
  </System>
  <EventData>
    <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
    <Data Name="CommandLine">cmd /c whoami</Data>
    <Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
  </EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Eventlog"/>
    <EventID>1102</EventID>
    <TimeCreated SystemTime="2022-07-19T15:01:03Z"/>
    <Channel>Security</Channel>
    <Computer>DESKTOP-1</Computer>
  </System>
  <UserData><LogFileCleared xmlns="x"><SubjectUserName>bob</SubjectUserName></LogFileCleared></UserData>
</Event>
</Events>
"""


def test_read_file(tmp_path):
    path = tmp_path / "sysmon-h1-s1.xml"
    path.write_text(XML)
    df = canonical.to_frame(atlasv2.read_file(path, "atlas-h1", "sysmon"))
    assert list(df["EventID"]) == [1, 1102]
    first = df.iloc[0]
    assert first["Image"].endswith("cmd.exe") and first["Computer"] == "DESKTOP-1"
    assert first["_timestamp"] == pd.Timestamp("2022-07-19T15:01:02.345678900Z")
    assert df.iloc[1]["SubjectUserName"] == "bob"
    assert set(df["Hostname"]) == {"atlas-h1"}


def test_write_group_chunks(tmp_path, monkeypatch):
    path = tmp_path / "sysmon-h1-s1.xml"
    path.write_text(XML)
    monkeypatch.setattr(atlasv2, "CHUNK", 1)
    counts = atlasv2.write_group([path], "atlas-h1", tmp_path / "out")
    assert counts == {"sysmon": 2}
    parts = sorted(p.name for p in (tmp_path / "out").iterdir())
    assert parts == ["sysmon-part-00000.parquet", "sysmon-part-00001.parquet"]
