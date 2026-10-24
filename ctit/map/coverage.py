"""Mapper coverage and reachable tactic set K over canonical parquet (spec §2.5, T1)."""
from __future__ import annotations

import pandas as pd

from ctit.adapters import drift

ENTERPRISE_TACTICS = [
    "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
    "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
    "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact",
]


def brims_tag(df: pd.DataFrame) -> pd.DataFrame:
    """BRiMS mapper (DRIFT normalize_schema + build_tokens) per source.

    normalize_schema keeps only canonical columns and re-sorts, so each source is tagged
    separately and labelled afterwards. Returns host, ts, source, event_id, technique, tactic.
    """
    cfg = drift.StrataConfig()
    parts = []
    for source, group in df.groupby("source", sort=True):
        tagged = drift.build_tokens(drift.normalize_schema(group, cfg))
        parts.append(pd.DataFrame({
            "host": tagged["host"], "ts": tagged["ts"], "source": source,
            "event_id": tagged["event_id"].astype("int64"),
            "technique": tagged["mitre_technique"].fillna("").astype(str),
            "tactic": tagged["mitre_tactic"].fillna("").astype(str),
        }))
    return pd.concat(parts, ignore_index=True)


def coverage(tagged: pd.DataFrame) -> dict:
    """Per-source tag rate, per-tactic counts, and K for Sysmon-only and all sources."""
    out: dict = {"by_source": {}, "tactic_counts": {}, "K": {}}
    for source, g in tagged.groupby("source"):
        out["by_source"][source] = {
            "events": int(len(g)),
            "tagged": int((g["tactic"] != "").sum()),
            "tag_rate": float((g["tactic"] != "").mean()),
        }
    hit = tagged[tagged["tactic"] != ""]
    out["tactic_counts"] = {t: int(n) for t, n in hit["tactic"].value_counts().sort_index().items()}
    order = {t: i for i, t in enumerate(ENTERPRISE_TACTICS)}
    out["K"]["sysmon"] = sorted(hit.loc[hit["source"] == "sysmon", "tactic"].unique(), key=order.get)
    out["K"]["all_sources"] = sorted(hit["tactic"].unique(), key=order.get)
    return out
