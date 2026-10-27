"""Splunk Boss of the SOC (BOTS) v1/v2/v3 -> canonical records (corpus check, docs/CORPUS_CHECK.md).

Two input shapes:
- BOTSv1 json-by-sourcetype exports: one JSON object per line, the event under "result",
  its original text in result["_raw"] and Splunk's event time in result["_time"].
- BOTSv2/v3 pre-indexed Splunk buckets: rawdata/journal.gz. iter_journal() decodes the
  journal without Splunk and yields (host, source, sourcetype, epoch seconds, raw text).

Two raw formats:
- XmlWinEventLog (Sysmon): one <Event> element; parsed with atlasv2.event_record.
- Classic WinEventLog (Security): "Key=Value" header lines, then "Message=" and the rendered
  message. Message labels become the XML EventData names the Sigma rules use (e.g.
  "Process Command Line" -> CommandLine, "Account Name" under "Subject:" -> SubjectUserName).
  This is a best-effort inversion of the rendered text: multi-line values (e.g. 4698 Task
  Content) are cut at the first line.
"""
from __future__ import annotations

import gzip
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ctit.ingest import canonical
from ctit.ingest.atlasv2 import _core, event_record

SYSMON_ST = "xmlwineventlog:microsoft-windows-sysmon/operational"
SECURITY_ST = "wineventlog:security"

# ---------------------------------------------------------------- Splunk journal decoding
# Record opcodes (byte 0 of each record), reverse-engineered from BOTSv3 buckets and checked
# against each bucket's Hosts.data / SourceTypes.data counts (docs/CORPUS_CHECK.md):
#   0x00 nop (padding) | 0x03/0x04/0x05 new host/source/sourcetype string (ids from 1)
#   0x06 new metadata string | 0x09 private blob | 0x0a header (version, align, base index time)
#   0x10-0x1f set active state; flag bits 8=host id, 4=source id, 2=sourcetype id (varints,
#             in that order), 1=event base time (uint32 LE epoch seconds)
#   0x20-0x2b event: varint length, then the body (see _event_raw)
_TZ = {"UTC": 0, "GMT": 0, "MDT": -6, "MST": -7, "EDT": -4, "EST": -5, "CDT": -5, "CST": -6, "PDT": -7, "PST": -8}


def _varint(b: bytes, i: int) -> tuple[int, int]:
    out = shift = 0
    while True:
        x = b[i]
        i += 1
        out |= (x & 0x7F) << shift
        shift += 7
        if not x & 0x80:
            return out, i


def _event_raw(body: bytes) -> tuple[int, bytes]:
    """Event body: stream id (8 bytes), stream offset, sub-offset, index-time delta,
    sub-seconds, metadata count, that many (key, value) varint pairs, then the raw text.
    Returns (sub-seconds, raw)."""
    i = 8
    for _ in range(3):
        _, i = _varint(body, i)
    subsec, i = _varint(body, i)
    n, i = _varint(body, i)
    for _ in range(2 * n):
        _, i = _varint(body, i)
    return subsec, body[i:]


class _Short(Exception):
    """The buffer ends inside a record; read more and retry from the record start."""


def _need(data: bytes, i: int, n: int) -> None:
    if i + n > len(data):
        raise _Short


def iter_journal(stream, sourcetypes: set[str] | None = None, chunk: int = 1 << 26):
    """Yield (host, source, sourcetype, epoch_seconds, raw_bytes) for every event in a
    decompressed journal (bytes or a binary file object, read in chunks).
    sourcetypes (lowercase, without the "sourcetype::" prefix) filters before the raw is sliced."""
    read = (lambda _n, _b=[stream]: _b.pop() if _b else b"") if isinstance(stream, bytes) else stream.read
    hosts, sources, sts = [None], [None], [None]
    host = source = st = 0
    base = 0
    data, i, eof = b"", 0, False
    while True:
        if i >= len(data) or not eof and len(data) - i < chunk // 2:
            more = b"" if eof else read(chunk)
            eof = eof or not more
            data, i = data[i:] + more, 0
            if not data:
                return
        start = i
        try:
            op = data[i]
            i += 1
            if op == 0:
                continue
            if op in (3, 4, 5, 6, 9):
                n, i = _varint(data, i)
                _need(data, i, n)
                s = data[i:i + n]
                i += n
                if op in (3, 4, 5):
                    (hosts, sources, sts)[op - 3].append(s.decode("utf-8", "replace").split("::", 1)[-1])
            elif op == 0x0A:
                _need(data, i, 6)
                i += 6
            elif 0x10 <= op <= 0x1F:
                h, so, t = host, source, st
                if op & 8:
                    h, i = _varint(data, i)
                if op & 4:
                    so, i = _varint(data, i)
                if op & 2:
                    t, i = _varint(data, i)
                if op & 1:
                    _need(data, i, 4)
                    base = int.from_bytes(data[i:i + 4], "little")
                    i += 4
                host, source, st = h, so, t
            elif 0x20 <= op <= 0x2B:
                n, i = _varint(data, i)
                _need(data, i, n)
                body = data[i:i + n]
                i += n
                if sourcetypes is None or sts[st].lower() in sourcetypes:
                    _, raw = _event_raw(body)
                    yield hosts[host], sources[source], sts[st], base, raw
            else:
                raise ValueError(f"unknown journal opcode {op:#x}")
        except (_Short, IndexError):
            if eof:
                raise ValueError("journal ends inside a record") from None
            i = start
            more = read(chunk)
            eof = not more
            data, i = data[i:] + more, 0


def read_journal(path: Path, sourcetypes: set[str] | None = None):
    with gzip.open(path, "rb") as f:
        yield from iter_journal(f, sourcetypes)


# ---------------------------------------------------------------- raw -> canonical record
_SUBJECT = {"subject", "creator subject"}
_TARGET = {"new logon", "target subject", "target account", "account for which logon failed",
           "account information", "account whose credentials were used", "member", "logon account"}
_PARTY = {"Security ID": "Sid", "Account Name": "UserName", "Account Domain": "DomainName", "Logon ID": "LogonId"}
_RENAME = {
    "Process Command Line": "CommandLine", "Creator Process Name": "ParentProcessName",
    "Creator Process ID": "ProcessId", "Source Network Address": "IpAddress", "Source Address": "IpAddress",
    "Source Port": "IpPort", "Accesses": "AccessList", "Process ID": "ProcessId",
}
_HEADER = re.compile(r"^([A-Za-z]+)=(.*)$")
_FIELD = re.compile(r"^\t+([^:\t][^:]*):\t*(.*)$")


def classic_record(raw: str) -> dict:
    """Classic WinEventLog text -> flat dict with XML-style field names."""
    head, _, message = raw.partition("\nMessage=")
    rec: dict = {}
    for line in head.splitlines():
        m = _HEADER.match(line)
        if m:
            rec[m.group(1)] = m.group(2)
    section = ""
    for line in message.splitlines():
        if not line.strip():
            continue
        m = _FIELD.match(line)
        if not m:
            section = line.strip().rstrip(":").lower() if line.rstrip().endswith(":") else ""
            continue
        label, value = m.group(1).strip(), m.group(2).strip()
        if label in _PARTY and section in _SUBJECT | _TARGET:
            name = ("Subject" if section in _SUBJECT else "Target") + _PARTY[label]
        else:
            name = _RENAME.get(label, label.replace(" ", ""))
        rec.setdefault(name, value)
    rec["Channel"] = rec.get("LogName", "")
    rec["EventID"] = rec.get("EventCode", "")
    # XML events carry Computer; DRIFT's normalize_schema reads it before Hostname.
    rec["Computer"] = rec.pop("ComputerName", "")
    return rec


def to_record(raw: str, epoch: float | None, splunk_host: str) -> dict | None:
    """One raw Windows event -> canonical record (core columns set), or None if not Sysmon/Security."""
    if raw.lstrip().startswith("<Event"):
        rec = event_record(ET.fromstring(raw))
        source = canonical.source_of(rec.get("Channel"))
        if source is None:
            return None
        if not rec.get("SystemTime"):
            rec["SystemTime"] = datetime.fromtimestamp(epoch, timezone.utc).isoformat()
        return _core(rec, canonical.short_host(rec.get("Computer") or splunk_host), source)
    rec = classic_record(raw)
    source = canonical.source_of(rec["Channel"])
    if source is None or not rec["EventID"].isdigit() or epoch is None:
        return None
    rec["SystemTime"] = datetime.fromtimestamp(epoch, timezone.utc).isoformat()
    return _core(rec, canonical.short_host(rec.get("Computer") or splunk_host), source)


def v1_epoch(t: str) -> float:
    """BOTSv1 _time ('2016-08-28 17:58:59.000 MDT') -> epoch seconds."""
    stamp, zone = t.rsplit(" ", 1)
    local = datetime.strptime(stamp, "%Y-%m-%d %H:%M:%S.%f")
    return (local - timedelta(hours=_TZ[zone])).replace(tzinfo=timezone.utc).timestamp()


def read_v1(path: Path, hosts: set[str] | None = None):
    """Yield canonical records from a BOTSv1 json-by-sourcetype .json.gz export."""
    with gzip.open(path, "rt") as f:
        for line in f:
            r = json.loads(line).get("result")
            if not r or (hosts is not None and r.get("host", "").lower() not in hosts):
                continue
            rec = to_record(r["_raw"], v1_epoch(r["_time"]), r.get("host", ""))
            if rec is not None:
                yield rec
