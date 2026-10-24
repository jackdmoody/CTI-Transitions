"""Extended tactic mapper (spec §2.5): apply the frozen compiled Sigma rules to canonical
events in an in-memory SQLite table. Output has the same columns as
ctit.map.coverage.brims_tag, plus rule_id (primary), n_rules and rule_ids (all matches).

Matching follows Sigma semantics as emitted by pySigma's SQLite backend: every text column
is COLLATE NOCASE (Sigma string matches are case-insensitive) and REGEXP is Python re.
Primary-rule policy (docs/MAPPER_POLICY.md): highest level, then status, then rule id;
the event's tactic is that rule's first tactic.
"""
from __future__ import annotations

import re
import sqlite3
from functools import lru_cache

import numpy as np
import pandas as pd

from ctit.map.sigma_rules import LEVEL_RANK, STATUS_RANK, load_compiled

CHANNEL = {"sysmon": "Microsoft-Windows-Sysmon/Operational", "security": "Security", "system": "System"}
_NO_SUCH_COLUMN = re.compile(r"no such column: (\S+)")


@lru_cache(maxsize=4096)
def _compile(pattern: str):
    return re.compile(pattern)


def _regexp(pattern, value):
    return value is not None and _compile(pattern).search(str(value)) is not None


def _priority(rule: dict) -> tuple:
    # Sort key: best rule first.
    return (-LEVEL_RANK[rule["level"]], -STATUS_RANK.get(rule["status"], 0), rule["id"])


def _merge_case_duplicates(df: pd.DataFrame) -> pd.DataFrame:
    """SQLite column names are case-insensitive; some logs carry e.g. IpAddress and Ipaddress.
    Coalesce each such group into the most common spelling (non-null count, then name)."""
    groups: dict[str, list[str]] = {}
    for c in df.columns:
        groups.setdefault(c.lower(), []).append(c)
    dupes = {k: v for k, v in groups.items() if len(v) > 1}
    if not dupes:
        return df
    df = df.copy()
    for cols in dupes.values():
        keep = sorted(cols, key=lambda c: (-df[c].notna().sum(), c))[0]
        for c in cols:
            if c != keep:
                df[keep] = df[keep].fillna(df[c])
                df = df.drop(columns=c)
    return df


def _connect(df: pd.DataFrame) -> sqlite3.Connection:
    df = _merge_case_duplicates(df)
    con = sqlite3.connect(":memory:")
    con.create_function("regexp", 2, _regexp, deterministic=True)
    cols = [c for c in df.columns if c != "EventID"]
    defs = ", ".join(['"EventID" INTEGER'] + [f'"{c}" TEXT COLLATE NOCASE' for c in cols])
    con.execute(f"CREATE TABLE logs ({defs})")
    frame = df[["EventID"] + cols].copy()
    frame["Channel"] = df["source"].map(CHANNEL).fillna(df["Channel"])
    frame["_timestamp"] = frame["_timestamp"].astype(str)
    frame = frame.astype(object).where(frame.notna(), None)
    placeholders = ", ".join("?" * (len(cols) + 1))
    con.executemany(f"INSERT INTO logs VALUES ({placeholders})", frame.itertuples(index=False, name=None))
    con.execute('CREATE INDEX ix ON logs ("Channel", "EventID")')
    return con


def _matches(con: sqlite3.Connection, where: str) -> list[int]:
    while True:
        try:
            return [r[0] for r in con.execute(f"SELECT rowid FROM logs WHERE {where}")]
        except sqlite3.OperationalError as e:
            m = _NO_SUCH_COLUMN.search(str(e))
            if not m:
                raise
            # Field the data never carries: add it as all-NULL so the rule simply can't match.
            con.execute(f'ALTER TABLE logs ADD COLUMN "{m.group(1).strip(chr(34))}" TEXT COLLATE NOCASE')


def tag(df: pd.DataFrame, rules: list[dict] | None = None) -> pd.DataFrame:
    rules = sorted(rules if rules is not None else load_compiled(), key=_priority)
    df = df.reset_index(drop=True)
    con = _connect(df)
    best = np.full(len(df), -1, dtype=np.int64)  # index into `rules` of the best match
    n_rules = np.zeros(len(df), dtype=np.int64)
    all_hits: dict[int, list[str]] = {}
    for i, rule in enumerate(rules):  # best-priority first, so the first hit per row wins
        rows = np.asarray(_matches(con, rule["where"]), dtype=np.int64) - 1  # rowid is 1-based
        if rows.size:
            n_rules[rows] += 1
            unset = rows[best[rows] < 0]
            best[unset] = i
            for r in rows.tolist():
                all_hits.setdefault(r, []).append(rule["id"])
    con.close()
    hit = best >= 0
    tactic = np.full(len(df), "", dtype=object)
    technique = np.full(len(df), "", dtype=object)
    rule_id = np.full(len(df), "", dtype=object)
    tactic[hit] = [rules[i]["tactics"][0] for i in best[hit]]
    technique[hit] = [(rules[i]["techniques"] or [""])[0] for i in best[hit]]
    rule_id[hit] = [rules[i]["id"] for i in best[hit]]
    return pd.DataFrame({
        "host": df["Hostname"].astype(str), "ts": df["_timestamp"], "source": df["source"].astype(str),
        "event_id": df["EventID"].astype("int64"), "technique": technique, "tactic": tactic,
        "rule_id": rule_id, "n_rules": n_rules,
        # Every matching rule, priority order; used for recall (any rule), not for tactic.
        "rule_ids": [",".join(all_hits.get(r, ())) for r in range(len(df))],
    })
