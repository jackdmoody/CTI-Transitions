"""OpTC real-attack test set (B6, SPEC_ISSUES 2026-10-26).

Hosts: the 29 red-team targets (configs/optc_redteam.yaml); never in any baseline.
Days: their benign days (19–22 Sep) plus the attack days (23–25 Sep).
Labels: Inria corrected-release process labels, one row per malicious process
(host, pid, start, end), children included (ground_truth_corrected_sc{1,2,3}_updated.csv).
An event is malicious if its host and acting-process pid match a label row and its time is
inside [start, end]. A window (B4: 8 consecutive tagged events on one host) is positive if
one of its events is malicious; `positive_span` also records whether any malicious event of
that host falls inside the window's time span, tagged or not.

Event-level labels need each event's pid. The STRATA-E conversion dropped pid, so the
attack days must be re-converted from raw eCAR with pid kept (see `inventory`).
"""
from __future__ import annotations

import os
from pathlib import Path

import numpy as np
import pandas as pd
import yaml

from ctit.eval import optc_split

LABELS = Path(os.environ.get("CTIT_OPTC_LABELS", Path(__file__).resolve().parents[2] / "data/optc/labels"))
ATTACK_DAYS = ("2019-09-23", "2019-09-24", "2019-09-25")
WINDOW = 8


def load_labels(root: Path = LABELS) -> pd.DataFrame:
    """Columns: scenario, host (canonical short name), pid, start, end (UTC), open_ended.
    An end of "Infinity" (process still running when the data ends) becomes Timestamp.max."""
    parts = []
    for sc in ("sc1", "sc2", "sc3"):
        df = pd.read_csv(root / f"ground_truth_corrected_{sc}_updated.csv", header=None,
                         names=["host", "pid", "start", "end"])
        df.insert(0, "scenario", sc)
        parts.append(df)
    df = pd.concat(parts, ignore_index=True)
    df["host"] = df["host"].map(optc_split.host_id)
    df["pid"] = df["pid"].astype("int64")
    df["open_ended"] = df["end"].astype(str).eq("Infinity")  # process alive at the end of the data
    df.loc[df["open_ended"], "end"] = pd.NA
    for c in ("start", "end"):
        df[c] = pd.to_datetime(df[c], utc=True, format="ISO8601")
    df["end"] = df["end"].fillna(pd.Timestamp.max.tz_localize("UTC"))
    return df


def label_events(events: pd.DataFrame, labels: pd.DataFrame) -> np.ndarray:
    """Malicious flag per event. events: Hostname, _timestamp (UTC), ProcessId."""
    flag = np.zeros(len(events), dtype=bool)
    if events.empty:
        return flag
    ev = events.reset_index(drop=True)
    pid = pd.to_numeric(ev["ProcessId"], errors="coerce")
    for (host, p), g in labels.groupby(["host", "pid"]):
        sel = ((ev["Hostname"] == host) & (pid == p)).to_numpy()
        if not sel.any():
            continue
        ts = ev.loc[sel, "_timestamp"]
        inside = np.zeros(sel.sum(), dtype=bool)
        for s, e in zip(g["start"], g["end"]):
            inside |= ((ts >= s) & (ts <= e)).to_numpy()
        idx = np.flatnonzero(sel)
        flag[idx[inside]] = True
    return flag


def windows(tagged: pd.DataFrame, malicious_ts: dict[str, np.ndarray] | None = None,
            size: int = WINDOW) -> pd.DataFrame:
    """Fixed windows of `size` consecutive tagged events per host (a trailing partial window
    is dropped). tagged: Hostname, _timestamp, tactic, malicious. Returns one row per window:
    host, start, end, tactics, positive, positive_span."""
    rows = []
    for host, g in tagged.sort_values(["Hostname", "_timestamp"], kind="stable").groupby("Hostname", sort=True):
        mal_ts = (malicious_ts or {}).get(host, np.array([], dtype="datetime64[ns]"))
        for i in range(0, len(g) - size + 1, size):
            w = g.iloc[i:i + size]
            start, end = w["_timestamp"].iloc[0], w["_timestamp"].iloc[-1]
            span = bool(len(mal_ts)) and bool(((mal_ts >= start.to_datetime64()) & (mal_ts <= end.to_datetime64())).any())
            rows.append({"host": host, "start": start, "end": end, "tactics": list(w["tactic"]),
                         "positive": bool(w["malicious"].any()), "positive_span": span})
    return pd.DataFrame(rows, columns=["host", "start", "end", "tactics", "positive", "positive_span"])


def inventory(root: Path = optc_split.OPTC_ROOT, redteam: Path = optc_split.REDTEAM) -> dict:
    """Which red-team host-days the local conversion has, per day."""
    cfg = yaml.safe_load(redteam.read_text())
    out = {}
    for day in optc_split.BENIGN_DAYS + ATTACK_DAYS:
        have = optc_split.day_hosts(day, root)
        out[day] = {"present": sorted(h for h in cfg["targets"] if h in have),
                    "missing": sorted(h for h in cfg["targets"] if h not in have)}
    return out
