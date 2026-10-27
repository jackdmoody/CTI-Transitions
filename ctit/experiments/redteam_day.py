"""C4 diagnostic (SPEC_ISSUES 2026-10-26): does the mapper see the OpTC intrusion on 23 Sep?

Analysis only: no scoring, no detection metrics. On the already-converted 23 Sep data,
compare the red-team targets in the population against a seeded random sample of clean
hosts of the same size, under each configured mapper: tag rate, K, per-tactic counts. Also
counts tagged events on target hosts that fall inside a labelled malicious process's
[start, end] on that host. The conversion has no pid, so that count is a time-overlap upper
bound, not event-level labels.
"""
from __future__ import annotations

import random
from collections import Counter
from pathlib import Path

import pandas as pd
import pyarrow.parquet as pq

from ctit.eval import optc_redteam, optc_split
from ctit.ingest import optc
from ctit.map import v3
from ctit.map.attack import TACTICS
from ctit.map.extended import tag

ORDER = {t: i for i, t in enumerate(TACTICS)}
LOADERS = {"v3": v3.load_v3, "v3h": v3.load_v3h}
READ = [c for c in optc.READ_COLUMNS] + ["ts"]


def _host_frame(path: Path) -> pd.DataFrame:
    """Full host-day as a canonical frame (timestamps kept), restored images."""
    df = pq.read_table(path, columns=[c for c in READ if c in pq.read_schema(path).names]).to_pandas()
    out, _ = optc.to_frame(df[df["event_id"].isin(optc.FIELDS)], restore_bare=True)
    return out


def _group_stats(tagged: list[pd.DataFrame], events: int) -> dict:
    t = pd.concat(tagged, ignore_index=True)
    hit = t[t["tactic"] != ""]
    return {"events": events, "tagged": int(len(hit)), "tag_rate": len(hit) / events if events else None,
            "K": sorted(set(hit["tactic"]), key=ORDER.get),
            "per_tactic": {k: int(v) for k, v in hit["tactic"].value_counts().items()},
            "hosts_with_tags": int(hit["host"].nunique()),
            "top_rules": Counter(hit["rule_id"]).most_common(5)}


def run(config: dict, calls=None) -> dict:
    day = config["day"]
    red_all = optc_split.redteam_hosts()
    have = optc_split.day_hosts(day)
    pop = set(optc_split.population())
    red = sorted(h for h in red_all if h in pop and h in have)
    clean = sorted(h for h in pop - set(red_all) if h in have)
    ctrl = sorted(random.Random(config["seed"]).sample(clean, len(red)))
    labels = optc_redteam.load_labels()
    rules = {m: LOADERS[m]() for m in config["mappers"]}
    out: dict = {"day": day, "redteam_hosts": red, "control_hosts": ctrl, "mappers": {}}
    acc: dict = {m: {"red": [], "ctrl": [], "inside": Counter()} for m in rules}
    ev = {"red": 0, "ctrl": 0}
    for group, hosts in (("red", red), ("ctrl", ctrl)):
        for h in hosts:
            path = optc_split.OPTC_ROOT / day / f"SysClient{h[-4:]}.systemia.com.parquet"
            frame = _host_frame(path)
            ev[group] += len(frame)
            for m, rs in rules.items():
                t = tag(frame, rs)
                acc[m][group].append(t)
                if group == "red":
                    lab = labels[labels["host"] == h]
                    hit = t[t["tactic"] != ""]
                    ts = pd.to_datetime(hit["ts"], utc=True)
                    inside = pd.Series(False, index=hit.index)
                    for s, e in zip(lab["start"], lab["end"]):
                        inside |= (ts >= s) & (ts <= e)
                    acc[m]["inside"]["tagged_in_label_intervals"] += int(inside.sum())
                    for tac in hit.loc[inside, "tactic"]:
                        acc[m]["inside"][f"tactic:{tac}"] += 1
    for m in rules:
        out["mappers"][m] = {"redteam": _group_stats(acc[m]["red"], ev["red"]),
                             "control": _group_stats(acc[m]["ctrl"], ev["ctrl"]),
                             "redteam_time_overlap_upper_bound": dict(acc[m]["inside"])}
    return out
