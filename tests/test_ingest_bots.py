import gzip
import io
import json

import pytest

from ctit.ingest import bots, canonical

SYSMON_RAW = (
    "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
    "<Provider Name='Microsoft-Windows-Sysmon'/><EventID>1</EventID>"
    "<TimeCreated SystemTime='2017-08-31T10:00:01.500000000Z'/>"
    "<Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>wrk-01.corp.local</Computer>"
    "</System><EventData><Data Name='Image'>C:\\Windows\\System32\\whoami.exe</Data>"
    "<Data Name='CommandLine'>whoami /all</Data><Data Name='ParentImage'>C:\\Windows\\System32\\cmd.exe</Data>"
    "</EventData></Event>"
)
SECURITY_RAW = (
    "08/31/2017 10:00:02 AM\nLogName=Security\nSourceName=Microsoft Windows security auditing.\n"
    "EventCode=4688\nComputerName=wrk-01.corp.local\nTaskCategory=Process Creation\n"
    "Message=A new process has been created.\n\nCreator Subject:\n\tSecurity ID:\t\tCORP\\bob\n"
    "\tAccount Name:\t\tbob\n\tAccount Domain:\t\tCORP\n\nTarget Subject:\n\tAccount Name:\t\t-\n\n"
    "Process Information:\n\tNew Process ID:\t\t0x1a4\n\tNew Process Name:\tC:\\Windows\\System32\\net.exe\n"
    "\tCreator Process ID:\t0x99\n\tCreator Process Name:\tC:\\Windows\\System32\\cmd.exe\n"
    "\tProcess Command Line:\tnet group \"domain admins\" /domain\n\nToken Elevation Type indicates ..."
)


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        out.append((n & 0x7F) | (0x80 if n > 0x7F else 0))
        n >>= 7
        if not n:
            return bytes(out)


def _string(op: int, s: str) -> bytes:
    return bytes([op]) + _varint(len(s)) + s.encode()


def _event(raw: str) -> bytes:
    # stream id (8), offset, sub-offset, index-time delta, sub-seconds, 1 metadata pair, raw
    body = bytes(8) + b"\x00\x00\x05\x00\x01" + b"\x10\x02" + raw.encode()
    return b"\x29" + _varint(len(body)) + body


def journal() -> bytes:
    return b"".join([
        b"\x0a\x01\x05" + (1504173600).to_bytes(4, "little"),
        _string(3, "host::WRK-01"), _string(4, "source::WinEventLog:Security"),
        _string(5, "sourcetype::WinEventLog:Security"), _string(4, "source::XmlWinEventLog:Sysmon"),
        _string(5, "sourcetype::XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"),
        _string(6, "punct"), _string(6, "_::"),
        b"\x1f\x01\x01\x01" + (1504173602).to_bytes(4, "little"), _event(SECURITY_RAW), b"\x00\x00",
        b"\x16\x02\x02", _event(SYSMON_RAW),
    ])


def test_iter_journal_tracks_state():
    events = list(bots.iter_journal(journal()))
    assert [(h, st, t) for h, _, st, t, _ in events] == [
        ("WRK-01", "WinEventLog:Security", 1504173602),
        ("WRK-01", "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational", 1504173602),
    ]
    assert events[0][4].decode() == SECURITY_RAW
    assert events[1][4].decode() == SYSMON_RAW
    only = list(bots.iter_journal(journal(), sourcetypes={bots.SYSMON_ST}))
    assert len(only) == 1 and only[0][4].decode() == SYSMON_RAW
    # Streaming: records straddle every chunk boundary.
    for chunk in (1, 7, 64):
        assert list(bots.iter_journal(io.BytesIO(journal()), chunk=chunk)) == events
    with pytest.raises(ValueError):
        list(bots.iter_journal(io.BytesIO(journal()[:-5]), chunk=7))


def test_classic_record_uses_xml_names():
    rec = bots.classic_record(SECURITY_RAW)
    assert rec["EventID"] == "4688" and rec["Channel"] == "Security"
    assert rec["NewProcessName"] == "C:\\Windows\\System32\\net.exe"
    assert rec["CommandLine"] == 'net group "domain admins" /domain'
    assert rec["ParentProcessName"] == "C:\\Windows\\System32\\cmd.exe"
    assert rec["SubjectUserName"] == "bob" and rec["TargetUserName"] == "-"
    assert rec["Computer"] == "wrk-01.corp.local"


def test_to_record_and_frame():
    recs = [bots.to_record(SECURITY_RAW, 1504173602, "WRK-01"), bots.to_record(SYSMON_RAW, 1504173602, "WRK-01")]
    df = canonical.to_frame(recs)
    assert list(df["source"]) == ["sysmon", "security"]  # sorted by time: Sysmon keeps its own 10:00:01.5
    assert set(df["Hostname"]) == {"wrk-01"}
    assert list(df["EventID"]) == [1, 4688]
    assert df.loc[1, "_timestamp"].isoformat() == "2017-08-31T10:00:02+00:00"
    assert bots.to_record("08/31/2017\nLogName=Application\nEventCode=1\nMessage=x", 0, "h") is None


def test_read_v1(tmp_path):
    path = tmp_path / "v1.json.gz"
    rows = [{"preview": False, "result": {"host": "wrk-01", "_time": "2017-08-31 04:00:02.000 MDT", "_raw": SECURITY_RAW}},
            {"preview": False, "lastrow": True}]
    with gzip.open(path, "wt") as f:
        f.write("\n".join(json.dumps(r) for r in rows))
    (rec,) = bots.read_v1(path)
    assert rec["_timestamp"] == "2017-08-31T10:00:02+00:00" and rec["EventID"] == 4688
