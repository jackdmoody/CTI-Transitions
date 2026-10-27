"""B6 diagnostic (SPEC_ISSUES 2026-10-27): do the mapper's tags on red-team hosts fall on the
labelled attack?

Analysis only: no scoring. Attack days 23–25 Sep, the 29 targets, frozen v3, bare images
restored, Inria labels (ctit.eval.optc_redteam). Per host-day: labelled-malicious events,
tagged events, tagged ∩ malicious. Every tag that is not on a labelled event is put in the
first matching class, as a check for label gaps:
  labelled_pid_outside_interval  its pid is a labelled pid, but its time is outside that pid's rows
  descendant                     its process descends (process-create tree of the host-day) from
                                 a labelled process created inside the label's interval
  inside_label_time              its time is inside some label interval of the host (any pid;
                                 open-ended rows count only up to `open_end_cap` after start)
  elsewhere                      none of the above
Rules are reported for malicious and non-malicious tags, with the C4 rules called out.
"""
from __future__ import annotations

from collections import Counter
from concurrent.futures import ProcessPoolExecutor

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import yaml

from ctit.eval import optc_redteam, optc_split
from ctit.experiments.redteam_testset import _path
from ctit.ingest import optc
from ctit.map import v3
from ctit.map.extended import tag

CLASSES = ("malicious", "labelled_pid_outside_interval", "descendant", "inside_label_time", "elsewhere")


def _naive(s: pd.Series) -> np.ndarray:
    return pd.to_datetime(s, utc=True).dt.tz_convert(None).to_numpy()


def descendants(creates: pd.DataFrame, labels: pd.DataFrame) -> pd.DataFrame:
    """Processes created (EID 1: pid = new process, ppid = parent) whose parent is a labelled
    process inside its label interval, or a descendant already found. Returns pid and the
    creation time; a pid's descendant status lasts until that pid is created again."""
    lab = {}
    for p, s, e in zip(labels["pid"], _naive(labels["start"]), _naive(labels["end"])):
        lab.setdefault(int(p), []).append((s, e))
    live: dict[int, bool] = {}  # pid -> currently a descendant
    out = []
    for p, pp, t in zip(creates["pid"], creates["ppid"], _naive(creates["ts"])):
        if pd.isna(p):
            continue
        p = int(p)
        parent_lab = (not pd.isna(pp)) and any(s <= t <= e for s, e in lab.get(int(pp), ()))
        parent_desc = (not pd.isna(pp)) and live.get(int(pp), False)
        live[p] = bool(parent_lab or parent_desc)
        if live[p]:
            out.append((p, t))
    return pd.DataFrame(out, columns=["pid", "created"])


def classify(tagged: pd.DataFrame, labels: pd.DataFrame, creates: pd.DataFrame, cap: pd.Timedelta) -> np.ndarray:
    """tagged: ts (naive UTC), pid, malicious."""
    n = len(tagged)
    cls = np.full(n, "elsewhere", dtype=object)
    ts, pid = tagged["ts"].to_numpy(), tagged["pid"].to_numpy()
    lab_pids = set(labels["pid"].astype(int))
    in_pid = np.array([(not pd.isna(p)) and int(p) in lab_pids for p in pid], dtype=bool)
    # descendant: latest create of this pid at or before ts is a descendant create
    desc = np.zeros(n, dtype=bool)
    if len(creates):
        allc = creates.assign(created=_naive(creates["ts"])).dropna(subset=["pid"]).sort_values("created")
        d = descendants(creates, labels)
        dset = set(zip(d["pid"], d["created"]))
        by_pid = {int(p): g["created"].to_numpy() for p, g in allc.groupby("pid")}
        for i in range(n):
            if pd.isna(pid[i]):
                continue
            c = by_pid.get(int(pid[i]))
            if c is None:
                continue
            k = np.searchsorted(c, ts[i], side="right") - 1
            desc[i] = k >= 0 and (int(pid[i]), c[k]) in dset
    s = _naive(labels["start"])
    e = np.minimum(_naive(labels["end"]), s + cap.to_timedelta64())
    inside = np.zeros(n, dtype=bool)
    for a, b in zip(s, e):
        inside |= (ts >= a) & (ts <= b)
    mal = tagged["malicious"].to_numpy(bool)
    cls[inside] = "inside_label_time"
    cls[desc] = "descendant"
    cls[in_pid] = "labelled_pid_outside_interval"
    cls[mal] = "malicious"
    return cls


def _host_day(args):
    day, host, labels, cap = args
    path = _path(day, host)
    rules = v3.load_v3()
    raw = pq.read_table(path, columns=optc.READ_COLUMNS + ["ts", "pid", "ppid"]).to_pandas()
    ts = pd.to_datetime(raw["ts"], utc=True)
    mal_all = optc_redteam.label_events(pd.DataFrame({"Hostname": host, "_timestamp": ts, "ProcessId": raw["pid"]}),
                                        labels)
    acc = set()
    for r in rules:
        acc |= v3.accepted_sources(r["where"])[1]
    keep = raw["event_id"].isin(acc & set(optc.FIELDS)).to_numpy()
    sub = raw[keep].assign(_mal=mal_all[keep])
    frame, _ = optc.to_frame(sub, restore_bare=True, carry=("_mal", "pid", "ppid"))
    t = tag(frame, rules)
    sel = (t["tactic"] != "").to_numpy()
    tagged = pd.DataFrame({"ts": frame["_timestamp"].dt.tz_convert(None).to_numpy()[sel],
                           "pid": frame["pid"].to_numpy()[sel], "malicious": frame["_mal"].to_numpy(bool)[sel],
                           "tactic": t["tactic"].to_numpy()[sel], "rule_id": t["rule_id"].to_numpy()[sel]})
    creates = raw.loc[raw["event_id"] == 1, ["ts", "pid", "ppid"]]
    tagged["cls"] = classify(tagged, labels, creates, cap) if len(labels) else \
        np.where(tagged["malicious"], "malicious", "elsewhere")
    stats = {"day": day, "host": host, "events": int(len(raw)), "malicious_events": int(mal_all.sum()),
             "tagged": int(len(tagged)), "tagged_malicious": int(tagged["malicious"].sum())}
    return stats, tagged.assign(host=host, day=day).drop(columns=["ts", "pid"])


def run(config: dict, calls=None) -> dict:
    cfg = yaml.safe_load(optc_split.REDTEAM.read_text())
    hosts = [optc_split.host_id(h) for h in cfg["targets"]]
    labels = optc_redteam.load_labels()
    cap = pd.Timedelta(config.get("open_end_cap", "4h"))
    jobs = [(d, h, labels[labels["host"] == h].reset_index(drop=True), cap)
            for h in hosts for d in optc_redteam.ATTACK_DAYS if _path(d, h).exists()]
    stats, tagged = [], []
    with ProcessPoolExecutor(config.get("workers", 3)) as ex:
        for s, t in ex.map(_host_day, jobs):
            stats.append(s)
            tagged.append(t)
    st = pd.DataFrame(stats)
    tg = pd.concat(tagged, ignore_index=True)
    titles = {r["id"]: r["title"] for r in v3.load_v3()}
    focus = config["c4_rules"]

    def top(df, k=10):
        return [{"rule_id": r, "title": titles.get(r), "tactic": tac, "n": int(n)}
                for (r, tac), n in df.groupby(["rule_id", "tactic"]).size().sort_values(ascending=False).head(k).items()]

    per_rule_cls = tg.groupby(["rule_id", "cls"]).size().unstack(fill_value=0)
    return {
        "mapper": "v3", "host_days": len(jobs), "open_end_cap": str(cap),
        "per_host_day": st.sort_values(["host", "day"]).to_dict(orient="records"),
        "totals": {"events": int(st["events"].sum()), "malicious_events": int(st["malicious_events"].sum()),
                   "tagged": int(st["tagged"].sum()), "tagged_malicious": int(st["tagged_malicious"].sum())},
        "by_day": {d: {k: int(v) for k, v in r.items()} for d, r in
                   st.groupby("day")[["events", "malicious_events", "tagged", "tagged_malicious"]].sum().iterrows()},
        "tag_classes": {k: int(v) for k, v in Counter(tg["cls"]).items()},
        "tag_classes_by_tactic": {tac: {k: int(v) for k, v in g["cls"].value_counts().items()}
                                  for tac, g in tg.groupby("tactic")},
        "top_rules_malicious": top(tg[tg["malicious"]]),
        "top_rules_non_malicious": top(tg[~tg["malicious"]]),
        "c4_rules": {r: {"title": titles.get(r),
                         "by_class": {c: int(per_rule_cls.loc[r, c]) if r in per_rule_cls.index and c in per_rule_cls
                                      else 0 for c in CLASSES},
                         "hosts": int(tg.loc[tg["rule_id"] == r, "host"].nunique()),
                         "by_day": tg[tg["rule_id"] == r].groupby("day").size().astype(int).to_dict()}
                     for r in focus},
    }
