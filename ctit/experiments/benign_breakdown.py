"""C4 follow-up (SPEC_ISSUES 2026-10-27): which rules make the benign tags on the OpTC test hosts?

Analysis only: no scoring. For the configured split on 19–22 Sep (bare images restored, as in
B5), tag every host-day under each configured mapper and report, per day: total events (all
rows of the host-day files), tagged events, tag rate, K and per-tactic counts; and per tactic
the rules that produced the tags, with the share coming from the rules that drive the 23 Sep
red-team tags (C4). Rows whose (Channel, EventID) no rule accepts are not read for tagging,
but they count in the tag-rate denominator.
"""
from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor

import pandas as pd
import pyarrow.parquet as pq

from ctit.eval import optc_split
from ctit.experiments.benign_windows import accepted
from ctit.experiments.redteam_day import LOADERS, ORDER
from ctit.ingest import optc
from ctit.map.extended import tag


def _host_day(args):
    path, eids = args
    u, _ = optc.unique_rows(path, restore_bare=True, event_ids=eids)
    return path.parent.name, optc_split.host_id(path.name), pq.ParquetFile(path).metadata.num_rows, u


def run(config: dict, calls=None) -> dict:
    split = optc_split.load_split()[config["split"]]
    rules = {m: LOADERS[m]() for m in config["mappers"]}
    eids = set()
    for rs in rules.values():
        for c, es in accepted(rs).items():
            eids |= {e for e in es if optc.SOURCE.get(e) and optc.CHANNEL[optc.SOURCE[e]] == c}
    jobs = [(optc_split.OPTC_ROOT / day / f"SysClient{h[-4:]}.systemia.com.parquet", sorted(eids))
            for day in optc_split.BENIGN_DAYS for h in split]
    jobs = [j for j in jobs if j[0].exists()]
    parts, totals = [], {}
    with ProcessPoolExecutor(config.get("workers", 4)) as ex:
        for day, host, n, u in ex.map(_host_day, jobs, chunksize=4):
            totals[day] = totals.get(day, 0) + n
            parts.append(u.assign(Hostname=host, _day=day))
    df = pd.concat(parts, ignore_index=True)
    content = [c for c in df.columns if c not in ("_w", "Hostname", "_day", "_timestamp")]
    df["_key"] = pd.util.hash_pandas_object(df[content].astype("string"), index=False).to_numpy()
    distinct = df.drop_duplicates("_key").reset_index(drop=True)
    focus = set(config["redteam_rules"])
    out: dict = {"split": config["split"], "hosts": len(split), "host_days": len(jobs),
                 "events_by_day": totals, "mappers": {}}
    for m, rs in rules.items():
        title = {r["id"]: r["title"] for r in rs}
        t = tag(distinct.drop(columns=["_w", "_day", "_key"]), rs)
        k2 = dict(zip(distinct["_key"], zip(t["tactic"], t["rule_id"])))
        tr = df["_key"].map(k2)
        hit = df.assign(tactic=tr.str[0], rule_id=tr.str[1])
        hit = hit[hit["tactic"] != ""]
        by_day = {}
        for day in optc_split.BENIGN_DAYS:
            h = hit[hit["_day"] == day]
            n = int(h["_w"].sum())
            per_tac = {k: int(v) for k, v in h.groupby("tactic")["_w"].sum().items()}
            by_day[day] = {"events": totals.get(day, 0), "tagged": n,
                           "tag_rate": n / totals[day] if totals.get(day) else None,
                           "K": sorted(per_tac, key=ORDER.get), "per_tactic": per_tac,
                           "hosts_with_tags": int(h["Hostname"].nunique())}
        rules_by = {}
        for tac in config["tactics"]:
            h = hit[hit["tactic"] == tac]
            g = h.groupby(["rule_id", "_day"])["_w"].sum().unstack(fill_value=0)
            g["total"] = g.sum(axis=1)
            g = g.sort_values("total", ascending=False)
            hosts = h.groupby("rule_id")["Hostname"].nunique()
            rules_by[tac] = {
                "tagged": int(h["_w"].sum()),
                "share_from_redteam_rules": float(h.loc[h["rule_id"].isin(focus), "_w"].sum() / h["_w"].sum())
                if len(h) else None,
                "rules": [{"rule_id": rid, "title": title.get(rid), "hosts": int(hosts[rid]),
                           "by_day": {d: int(row[d]) for d in g.columns if d != "total"},
                           "total": int(row["total"])} for rid, row in g.head(config.get("top", 10)).iterrows()],
            }
        out["mappers"][m] = {"by_day": by_day, "rules_by_tactic": rules_by,
                             "redteam_rules": {r: title.get(r) for r in focus}}
    return out
