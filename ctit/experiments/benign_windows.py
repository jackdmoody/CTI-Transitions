"""B5 (SPEC_ISSUES 2026-10-26): benign window counts under the primary window definition (B4).

Window = 8 consecutive tagged events on one host (non-overlapping), so a host with n tagged
events gives floor(n / 8) windows. Counted over all benign days per host, and also with
windows confined to one day. Mapper: frozen v3 (ctit/map/rules_v3.json).
  OpTC: the configured split(s) of configs/optc_split.yaml, 19–22 Sep, bare images restored.
  ATLASv2: the benign split, Sysmon only and Sysmon + Security.
Pre-registered rule (decided before any scoring): Det@0.1%FPR is kept only if the OpTC test
hosts give >= 5,000 benign windows; ATLASv2 is kept only if it gives >= 500.
Only rows whose (Channel, EventID) some v3 rule accepts are read; other rows can't be tagged.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pandas as pd

from ctit.eval import optc_split
from ctit.ingest import optc
from ctit.map import v3
from ctit.map.extended import tag

REPO_ROOT = Path(__file__).resolve().parents[2]
ATLAS = REPO_ROOT / "data" / "atlasv2" / "canonical"
WINDOW = 8


def accepted(rules: list[dict]) -> dict[str, set[int]]:
    """Channel -> event ids some rule accepts (an unconstrained rule makes this None-free:
    it is reported, and such rules don't exist in v3)."""
    out: dict[str, set[int]] = defaultdict(set)
    for r in rules:
        chans, eids = v3.accepted_sources(r["where"])
        if not chans or not eids:
            raise ValueError(f"rule {r['id']} has no Channel/EventID constraint")
        for c in chans:
            out[c] |= eids
    return dict(out)


def _host_day(args):
    path, eids = args
    u, _ = optc.unique_rows(path, restore_bare=True, event_ids=eids)
    return path.parent.name, optc_split.host_id(path.name), u


def windows(counts: dict, size: int = WINDOW) -> int:
    return int(sum(n // size for n in counts.values()))


def optc_counts(hosts: list[str], rules: list[dict], workers: int) -> dict:
    acc = accepted(rules)
    eids = sorted({e for c, es in acc.items() for e in es
                   if (optc.SOURCE.get(e) and optc.CHANNEL[optc.SOURCE[e]] == c)})
    jobs = []
    for day in optc_split.BENIGN_DAYS:
        for h in hosts:
            jobs.append((optc_split.OPTC_ROOT / day / f"SysClient{h[-4:]}.systemia.com.parquet", eids))
    parts = []
    with ProcessPoolExecutor(workers) as ex:
        for day, host, u in ex.map(_host_day, jobs, chunksize=4):
            parts.append(u.assign(Hostname=host, _day=day))
    df = pd.concat(parts, ignore_index=True)
    content = [c for c in df.columns if c not in ("_w", "Hostname", "_day", "_timestamp")]
    df["_key"] = pd.util.hash_pandas_object(df[content].astype("string"), index=False).to_numpy()
    distinct = df.drop_duplicates("_key").reset_index(drop=True)
    t = tag(distinct.drop(columns=["_w", "_day", "_key"]), rules)
    tac = dict(zip(distinct["_key"], t["tactic"]))
    df["tactic"] = df["_key"].map(tac)
    hit = df[df["tactic"] != ""]
    per_host = hit.groupby("Hostname")["_w"].sum().astype(int).to_dict()
    per_host_day = hit.groupby(["Hostname", "_day"])["_w"].sum().astype(int).to_dict()
    return {
        "event_ids_read": eids, "hosts": len(hosts), "host_days": len(jobs),
        "events_read": int(df["_w"].sum()), "distinct_rows": int(len(distinct)),
        "tagged_events": int(hit["_w"].sum()),
        "tagged_by_tactic": {k: int(v) for k, v in hit.groupby("tactic")["_w"].sum().items()},
        "hosts_with_tags": len(per_host),
        "tagged_per_host_quantiles": {q: float(pd.Series(list(per_host.values()) + [0] * (len(hosts) - len(per_host))).quantile(q))
                                      for q in (0.1, 0.5, 0.9)},
        "windows": windows(per_host), "windows_within_day": windows(per_host_day),
        "top_rules": Counter({r: int(w) for r, w in zip(
            df.loc[df["tactic"] != "", "_key"].map(dict(zip(distinct["_key"], t["rule_id"]))),
            df.loc[df["tactic"] != "", "_w"])}).most_common(5),
    }


def atlas_counts(rules: list[dict]) -> dict:
    acc = accepted(rules)
    out = {}
    tagged = {"sysmon": Counter(), "security": Counter()}
    for part in sorted(ATLAS.glob("benign-*/*.parquet")):
        src = part.stem.split("-")[0]
        df = pd.read_parquet(part)
        ch = df["Channel"].astype("string")
        keep = pd.Series(False, index=df.index)
        for c, es in acc.items():
            keep |= (ch == c) & df["EventID"].isin(es)
        if src == "sysmon":  # Channel may be absent on some rows; canonical source is authoritative
            keep |= (df["source"] == "sysmon") & df["EventID"].isin(acc.get("Microsoft-Windows-Sysmon/Operational", ()))
        df = df[keep]
        if df.empty:
            continue
        t = tag(df.reset_index(drop=True), rules)
        for host, n in t.loc[t["tactic"] != ""].groupby("host").size().items():
            tagged[src][host] += int(n)
    both = tagged["sysmon"] + tagged["security"]
    out = {"tagged_sysmon": dict(tagged["sysmon"]), "tagged_security": dict(tagged["security"]),
           "windows_sysmon": windows(tagged["sysmon"]), "windows_sysmon_security": windows(both)}
    return out


def run(config: dict, calls=None) -> dict:
    rules = v3.load_v3()
    split = optc_split.load_split()
    out: dict = {"mapper": "v3", "window": WINDOW, "optc": {}}
    for s in config["splits"]:
        out["optc"][s] = optc_counts(split[s], rules, config.get("workers", 4))
    out["atlasv2"] = atlas_counts(rules)
    test_windows = out["optc"].get("test", {}).get("windows")
    out["preregistered"] = {
        "det_at_0.1pct_fpr_kept": None if test_windows is None else test_windows >= 5000,
        "atlasv2_kept": out["atlasv2"]["windows_sysmon_security"] >= 500,
    }
    return out
