"""Raw DARPA OpTC eCAR -> the STRATA-E host-day columns, plus pid and ppid (B6, SPEC_ISSUES 2026-10-27).

The STRATA-E conversion (read by ctit.ingest.optc) dropped pid, which the Inria labels need.
This re-implements that conversion for the attack days so its output reads through
ctit.ingest.optc unchanged, with two extra columns:
  pid   the acting process (for PROCESS CREATE: the new process, as Sysmon EID 1 ProcessId)
  ppid  its parent
Object/action -> event id and the field rules follow strata-e-eval
protocol/ecar_to_sysmon_map.csv and adapters/ecar_to_strata.py (commit used for the
2019-09-19..24 conversion); the table is copied into MAP below. Parity against the STRATA-E
parquet on 23 Sep is checked in tests/test_ecar.py (unit) and by scripts/convert_optc_redteam.py
(per-host row counts and per-event-id counts).
"""
from __future__ import annotations

import gzip
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

import pyarrow as pa
import pyarrow.parquet as pq

# (object, action) -> (event id, logon type). Pairs not listed are dropped (counted).
MAP: dict[tuple[str, str], tuple[int, int | None]] = {
    ("PROCESS", "CREATE"): (1, None), ("PROCESS", "TERMINATE"): (5, None), ("PROCESS", "OPEN"): (10, None),
    ("THREAD", "REMOTE_CREATE"): (8, None), ("FLOW", "START"): (3, None), ("MODULE", "LOAD"): (7, None),
    ("FILE", "CREATE"): (11, None), ("FILE", "DELETE"): (23, None),
    ("REGISTRY", "ADD"): (12, None), ("REGISTRY", "REMOVE"): (12, None), ("REGISTRY", "EDIT"): (13, None),
    ("TASK", "CREATE"): (4698, None), ("TASK", "MODIFY"): (4702, None), ("TASK", "DELETE"): (4699, None),
    ("SERVICE", "CREATE"): (7045, None), ("SHELL", "COMMAND"): (4103, None),
    ("USER_SESSION", "LOGIN"): (4624, None), ("USER_SESSION", "INTERACTIVE"): (4624, 2),
    ("USER_SESSION", "RDP"): (4624, 10), ("USER_SESSION", "UNLOCK"): (4624, 7),
    ("USER_SESSION", "REMOTE"): (4624, None), ("USER_SESSION", "LOGOUT"): (4634, None),
    ("USER_SESSION", "GRANT"): (4672, None),
}
L4 = {"6": "tcp", "17": "udp"}
STRINGS = ["host", "image", "parent_image", "cmdline", "user", "dest_ip", "dest_port", "protocol",
           "target_image", "target_object", "target_filename", "registry_event_type", "image_resolved"]
SCHEMA = pa.schema([("ts", pa.timestamp("ns", tz="UTC")), ("event_id", pa.int64()),
                    *[(c, pa.string()) for c in STRINGS],
                    ("logon_type", pa.int64()), ("pid", pa.int64()), ("ppid", pa.int64())])


def _registry_event_type(action: str, has_value: bool) -> str:
    if action == "EDIT":
        return "SetValue"
    if action == "REMOVE":
        return "DeleteValue" if has_value else "DeleteKey"
    return "" if has_value else "CreateKey"   # ADD with a value has no EID-12 equivalent


@dataclass
class ProcessTable:
    """Process UUID and (host, pid) -> image, built causally from records already seen."""
    by_uuid: dict[str, str] = field(default_factory=dict)
    by_pid: dict[tuple[str, int], str] = field(default_factory=dict)

    def learn(self, r: dict) -> None:
        img = (r.get("properties") or {}).get("image_path")
        if not img:
            return
        if r["object"] == "PROCESS" and r["action"] == "CREATE":
            self._set(r["objectID"], img)
            if r.get("pid", -1) not in (-1, None):
                self.by_pid[(r["hostname"], int(r["pid"]))] = img
        elif r.get("actorID"):
            self._set(r["actorID"], img)

    def _set(self, uuid: str, img: str) -> None:
        old = self.by_uuid.get(uuid)
        if old is None or ("\\" not in old and "\\" in img):
            self.by_uuid[uuid] = img

    def full_path(self, uuid: str | None) -> str:
        img = self.by_uuid.get(uuid or "", "")
        return img if "\\" in img else ""


def _pid(v) -> int | None:
    try:
        v = int(v)
    except (TypeError, ValueError):
        return None
    return None if v < 0 else v


def convert(records: Iterable[dict], table: ProcessTable, stats: Counter) -> Iterator[dict]:
    """Yield one output row per mapped eCAR record."""
    for r in records:
        key = (r.get("object"), r.get("action"))
        m = MAP.get(key)
        stats[f"{key[0]}/{key[1]}:{'mapped' if m else 'dropped'}"] += 1
        if m is None:
            table.learn(r)
            continue
        eid, logon = m
        p = r.get("properties") or {}
        row = {"ts": r["timestamp"], "host": r["hostname"], "event_id": eid,
               "image": p.get("image_path", ""),
               "user": p.get("user") or p.get("user_name") or r.get("principal") or "",
               "logon_type": logon, "pid": _pid(r.get("pid")), "ppid": _pid(r.get("ppid"))}
        if eid == 1:
            row["cmdline"] = p.get("command_line", "")
            parent = p.get("parent_image_path", "")
            if not parent and row["ppid"] is not None:
                parent = table.by_pid.get((r["hostname"], row["ppid"]), "")
            row["parent_image"] = parent
        elif eid == 3:
            row["dest_ip"] = p.get("dest_ip", "")
            row["dest_port"] = p.get("dest_port", "")
            l4 = str(p.get("l4protocol", ""))
            row["protocol"] = L4.get(l4, l4)
        elif eid in (10, 8):
            row["target_image"] = table.by_uuid.get(r.get("objectID") if eid == 10 else p.get("tgt_pid_uuid"), "")
        elif eid in (12, 13):
            row["target_object"] = p.get("key", "") + ("\\" + p["value"] if p.get("value") else "")
            row["registry_event_type"] = _registry_event_type(key[1], bool(p.get("value")))
        if eid in (11, 23):
            row["target_filename"] = p.get("file_path", "")
        img = row["image"]
        row["image_resolved"] = img if "\\" in img else table.full_path(r.get("actorID"))
        table.learn(r)
        yield row


def read_ecar(path: Path) -> Iterator[dict]:
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def _batch(rows: list[dict]) -> pa.Table:
    import pandas as pd
    cols = {c: [r.get(c, "") for r in rows] for c in STRINGS}
    ts = pd.to_datetime([r["ts"] for r in rows], utc=True, format="ISO8601")
    return pa.table({"ts": pa.array(ts.as_unit("ns"), type=pa.timestamp("ns", tz="UTC")),
                     "event_id": pa.array([r["event_id"] for r in rows], pa.int64()),
                     **{c: pa.array(v, pa.string()) for c, v in cols.items()},
                     "logon_type": pa.array([r["logon_type"] for r in rows], pa.int64()),
                     "pid": pa.array([r["pid"] for r in rows], pa.int64()),
                     "ppid": pa.array([r["ppid"] for r in rows], pa.int64())}, schema=SCHEMA)


def convert_file(src: Path, out: Path, table: ProcessTable | None = None, chunk: int = 250_000) -> dict:
    """Stream one eCAR host-day file to parquet. Returns rows, per-event-id counts, pair counts."""
    table = table if table is not None else ProcessTable()
    stats: Counter = Counter()
    eids: Counter = Counter()
    out.parent.mkdir(parents=True, exist_ok=True)
    tmp = out.with_name(out.name + ".part")
    rows, buf = 0, []
    with pq.ParquetWriter(tmp, SCHEMA) as w:
        for row in convert(read_ecar(src), table, stats):
            buf.append(row)
            if len(buf) >= chunk:
                w.write_table(_batch(buf))
                rows += len(buf)
                eids.update(r["event_id"] for r in buf)
                buf = []
        if buf:
            w.write_table(_batch(buf))
            rows += len(buf)
            eids.update(r["event_id"] for r in buf)
    tmp.replace(out)
    return {"rows": rows, "event_ids": dict(sorted(eids.items())), "pairs": dict(sorted(stats.items()))}
