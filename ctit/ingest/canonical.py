"""W2 canonical raw-event parquet: one row per Windows event, every source field kept
as a string column (the extended Sigma mapper needs raw field names), plus:

  _timestamp : datetime64[ns, UTC]  (DRIFT's normalize_schema picks this first)
  Hostname   : lowercase short host name
  source     : sysmon | security | system | powershell
  EventID    : int
  Channel    : original channel string

DRIFT's normalize_schema/build_tokens read these files directly (ctit.adapters.drift.ingest_raw_sysmon).
"""
from __future__ import annotations

import pandas as pd

CHANNEL_SOURCE = {
    "microsoft-windows-sysmon/operational": "sysmon",
    "security": "security",
    "system": "system",
    "microsoft-windows-powershell/operational": "powershell",
    "windows powershell": "powershell",
}
DEFAULT_SOURCES = ("sysmon", "security", "system")  # PowerShell is the spec's secondary run
CORE_COLUMNS = ["_timestamp", "Hostname", "source", "EventID", "Channel"]


def source_of(channel: str | None) -> str | None:
    return CHANNEL_SOURCE.get((channel or "").lower())


def short_host(name: str) -> str:
    return str(name).split(".")[0].lower()


def to_frame(records: list[dict]) -> pd.DataFrame:
    """records already carry the core columns; everything else becomes nullable strings."""
    df = pd.DataFrame.from_records(records)
    df["_timestamp"] = pd.to_datetime(df["_timestamp"], utc=True, format="ISO8601")
    df["EventID"] = df["EventID"].astype("int64")
    for col in df.columns:
        if col not in ("_timestamp", "EventID"):
            df[col] = df[col].astype("string")
    rest = sorted(c for c in df.columns if c not in CORE_COLUMNS)
    return df[CORE_COLUMNS + rest].sort_values(["Hostname", "_timestamp"], kind="stable").reset_index(drop=True)
