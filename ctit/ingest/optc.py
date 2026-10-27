"""DARPA OpTC (STRATA-E's eCAR->Sysmon-like parquet) -> W2 canonical frame (corpus check).

Input: one host-day parquet from the STRATA-E conversion (columns ts, host, event_id, image,
parent_image, cmdline, user, dest_ip, ...; mapping in strata-e-eval/protocol/ecar_to_sysmon_map.csv).
That conversion is read only; outputs go under data/.

eCAR values use kernel forms; Sysmon (and the Sigma rules) use Win32 forms, so values are
normalized here, never in the mapper:
  \\Device\\HarddiskVolumeN\\...  -> X:\\...  (volume -> drive letter derived per host, see drive_map)
  \\REGISTRY\\MACHINE\\...       -> HKLM\\...
  \\REGISTRY\\USER\\...          -> HKU\\...
Volumes with no evidence for a letter are left as-is and reported.

Bare image names (B3c, 2026-10-26). eCAR records some processes with a bare image name
(PING.EXE) instead of a path. restore_bare=True takes the full path from the conversion's
image_resolved column, which STRATA-E resolves causally through the process table by the
acting process's GUID (actorID), for every event type except process creation: on EID 1,
actorID is the parent, so image_resolved there is the parent's image and is never used.
On raw eCAR samples the new process's own GUID and pid never carry a full path either
(0/2,020 and 2/1,799 bare creates restorable), so EID 1 bare names stay bare.
"""
from __future__ import annotations

import re
from collections import Counter

import pandas as pd

from ctit.ingest import canonical

# eCAR-derived column -> Sigma field, per event id (fields with non-zero fill in the conversion).
FIELDS = {
    1: {"image": "Image", "parent_image": "ParentImage", "cmdline": "CommandLine", "user": "User"},
    3: {"image": "Image", "user": "User", "dest_ip": "DestinationIp", "dest_port": "DestinationPort", "protocol": "Protocol"},
    5: {"image": "Image", "user": "User"},
    7: {"image": "Image", "user": "User"},  # module path (ImageLoaded) is not in the conversion
    8: {"image": "SourceImage", "target_image": "TargetImage", "user": "SourceUser"},
    10: {"image": "SourceImage", "target_image": "TargetImage", "user": "SourceUser"},
    11: {"image": "Image", "user": "User", "target_filename": "TargetFilename"},
    23: {"image": "Image", "user": "User", "target_filename": "TargetFilename"},
    12: {"image": "Image", "user": "User", "target_object": "TargetObject", "registry_event_type": "EventType"},
    13: {"image": "Image", "user": "User", "target_object": "TargetObject", "registry_event_type": "EventType"},
    4624: {"logon_type": "LogonType"}, 4634: {}, 4672: {}, 4698: {}, 4699: {}, 4702: {}, 7045: {},
}
PATH_FIELDS = ("Image", "ParentImage", "SourceImage", "TargetImage", "TargetFilename")
SOURCE = {eid: ("security" if 4000 <= eid < 5000 else "system" if eid == 7045 else "sysmon") for eid in FIELDS}
CHANNEL = {"sysmon": "Microsoft-Windows-Sysmon/Operational", "security": "Security", "system": "System"}

_VOLUME = re.compile(r"^\\device\\harddiskvolume(\d+)\\", re.IGNORECASE)
_DRIVE = re.compile(r'^"?([A-Za-z]):(\\[^"]*?)(?:"|\s|$)')
_HIVES = ((re.compile(r"^\\registry\\machine(?=\\|$)", re.IGNORECASE), "HKLM"),
          (re.compile(r"^\\registry\\user(?=\\|$)", re.IGNORECASE), "HKU"))


def drive_map(images: pd.Series, cmdlines: pd.Series) -> dict[str, dict]:
    """Volume number -> drive letter for one host, from process-create rows whose command
    line starts with the image's own Win32 path: image \\Device\\HarddiskVolumeN\\rest with
    command line X:\\rest votes N -> X. The volume holding \\Windows\\System32 is reported too.

    Returns {N: {"letter": X, "votes": n, "conflicts": {other: n}, "system32": bool}}."""
    votes: dict[str, Counter] = {}
    sys32: set[str] = set()
    for img, cmd in zip(images.astype("string").fillna(""), cmdlines.astype("string").fillna("")):
        m = _VOLUME.match(img)
        if not m:
            continue
        n, rest = m.group(1), img[m.end() - 1:]
        if rest.lower().startswith("\\windows\\system32\\"):
            sys32.add(n)
        d = _DRIVE.match(cmd)
        if d and d.group(2).lower() == rest.lower():
            votes.setdefault(n, Counter())[d.group(1).upper()] += 1
    out = {}
    for n in sorted(set(votes) | sys32, key=int):
        c = votes.get(n, Counter())
        if c:
            (letter, k), *rest = c.most_common()
            out[n] = {"letter": letter, "votes": k, "conflicts": dict(rest), "system32": n in sys32}
        else:
            out[n] = {"letter": None, "votes": 0, "conflicts": {}, "system32": n in sys32}
    return out


def normalize_path(value, letters: dict[str, str]):
    if value is None or value is pd.NA or not isinstance(value, str):
        return value
    m = _VOLUME.match(value)
    if m and m.group(1) in letters:
        return f"{letters[m.group(1)]}:{value[m.end() - 1:]}"
    return value


def normalize_registry(value):
    if not isinstance(value, str):
        return value
    for rx, hive in _HIVES:
        if rx.match(value):
            return rx.sub(hive, value, count=1)
    return value


def is_bare(values: pd.Series) -> pd.Series:
    v = values.astype("string").fillna("")
    return (v != "") & ~v.str.contains("\\", regex=False)


def restore_images(df: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    """Replace bare `image` values with `image_resolved` paths on non-process-create rows."""
    if "image_resolved" not in df:
        return df, 0
    res = df["image_resolved"].astype("string").fillna("")
    hit = is_bare(df["image"]) & (df["event_id"] != 1) & res.str.contains("\\", regex=False)
    n = int(hit.sum())
    if n:
        df = df.copy()
        df.loc[hit, "image"] = res[hit]
    return df, n


def to_frame(df: pd.DataFrame, normalize: bool = True, carry: tuple[str, ...] = (),
             restore_bare: bool = False, stats: dict | None = None,
             dmap: dict | None = None) -> tuple[pd.DataFrame, dict]:
    """One STRATA-E OpTC host-day frame -> (W2 canonical frame, per-host drive map log).
    Rows with event ids outside FIELDS are dropped (the caller counts them if needed).
    carry: extra input columns copied through unchanged (e.g. a row weight).
    restore_bare: see the module docstring; the number of restored rows is added to
    stats["restored"] when stats is given.
    dmap: a drive map computed beforehand (e.g. on all rows before de-duplication)."""
    if restore_bare:
        df, n = restore_images(df)
        if stats is not None:
            stats["restored"] = stats.get("restored", 0) + n
    if dmap is None:
        procs = df[df["event_id"] == 1]
        dmap = drive_map(procs["image"], procs["cmdline"]) if normalize else {}
    letters = {n: v["letter"] for n, v in dmap.items() if v["letter"]}
    parts = []
    for eid, g in df.groupby("event_id", sort=True):
        eid = int(eid)
        if eid not in FIELDS:
            continue
        m = FIELDS[eid]
        p = g[list(m)].rename(columns=m).astype("string").replace("", pd.NA)
        if normalize:
            for col in p.columns.intersection(PATH_FIELDS):
                p[col] = p[col].map(lambda v: normalize_path(v, letters), na_action="ignore").astype("string")
            if "TargetObject" in p:
                p["TargetObject"] = p["TargetObject"].map(normalize_registry, na_action="ignore").astype("string")
        src = SOURCE[eid]
        p.insert(0, "_timestamp", g["ts"].to_numpy())
        p.insert(1, "Hostname", g["host"].map(canonical.short_host).to_numpy())
        p.insert(2, "source", src)
        p.insert(3, "EventID", eid)
        p.insert(4, "Channel", CHANNEL[src])
        for col in carry:
            p[col] = g[col].to_numpy()
        parts.append(p)
    out = pd.concat(parts, ignore_index=True)
    out["_timestamp"] = pd.to_datetime(out["_timestamp"], utc=True)
    for col in out.columns:
        if col not in ("_timestamp", "EventID", *carry):
            out[col] = out[col].astype("string")
    rest = sorted(c for c in out.columns if c not in canonical.CORE_COLUMNS)
    out = out[canonical.CORE_COLUMNS + rest].sort_values(["Hostname", "_timestamp"], kind="stable").reset_index(drop=True)
    return out, dmap


READ_COLUMNS = ["host", "event_id", "image", "parent_image", "cmdline", "user", "dest_ip", "dest_port", "protocol",
                "target_image", "target_object", "target_filename", "registry_event_type", "logon_type",
                "image_resolved"]


def unique_rows(path, restore_bare: bool = True, event_ids=None, stats: dict | None = None) -> tuple[pd.DataFrame, dict]:
    """One STRATA-E host-day parquet -> (canonical frame of its distinct rows, drive map).

    Timestamps are dropped and identical rows collapse into one with weight `_w` (their event
    count). Exact for tagging: identical rows get identical tags. The drive map is computed on
    all process-create rows before collapsing. event_ids: keep only these event ids."""
    import pyarrow.parquet as pq

    cols = [c for c in READ_COLUMNS if c in pq.read_schema(path).names]
    filters = [("event_id", "in", sorted(event_ids))] if event_ids is not None else None
    df = pq.read_table(path, columns=cols, filters=filters).to_pandas()
    df = df[df["event_id"].isin(FIELDS)]
    if stats is not None:
        stats["events"] = stats.get("events", 0) + len(df)
    if restore_bare:
        df, n = restore_images(df)
        if stats is not None:
            stats["restored"] = stats.get("restored", 0) + n
    procs = df[df["event_id"] == 1]
    dmap = drive_map(procs["image"], procs["cmdline"])
    keys = [c for c in df.columns if c != "image_resolved"]
    u = df[keys].astype({c: "string" for c in keys if c not in ("event_id", "logon_type")})
    u = u.groupby(keys, dropna=False, sort=False).size().rename("_w").reset_index()
    u["ts"] = pd.Timestamp("2019-09-22", tz="UTC")  # placeholder: timestamps are not part of a row's identity
    out, dmap = to_frame(u, carry=("_w",), dmap=dmap)
    return out, dmap
