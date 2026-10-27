"""B6 real-attack test set (spec §7 T9; SPEC_ISSUES 2026-10-26 B6, 2026-10-27).

Hosts: the 29 OpTC red-team targets. Days: their benign days 19–22 Sep (STRATA-E conversion;
every event negative) and the attack days 23–25 Sep (re-converted from raw eCAR with pid
kept, scripts/convert_optc_redteam.py). Mapper: frozen v3, bare images restored.
Labels: Inria corrected-release process labels (ctit.eval.optc_redteam.load_labels): an
event is malicious if its host and acting pid match a label row and its time is inside
[start, end]. Windows: 8 consecutive tagged events per host over all its days (B4); a window
is positive if one of its events is malicious; positive_span records whether any malicious
event (tagged or not) of that host falls in its time span.
Writes the windows to data/eval/optc_redteam_windows.parquet (gitignored). No scoring.
"""
from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import yaml

from ctit.eval import optc_redteam, optc_split
from ctit.ingest import optc
from ctit.map import v3
from ctit.map.extended import tag

REPO_ROOT = Path(__file__).resolve().parents[2]
ATTACK_ROOT = REPO_ROOT / "data" / "optc_redteam" / "canonical"
OUT = REPO_ROOT / "data" / "eval" / "optc_redteam_windows.parquet"
READ = optc.READ_COLUMNS + ["ts"]


def _path(day: str, host: str) -> Path:
    root = ATTACK_ROOT if day in optc_redteam.ATTACK_DAYS else optc_split.OPTC_ROOT
    return root / day / f"SysClient{host[-4:]}.systemia.com.parquet"


def label_coverage(ts: pd.Series, pid: pd.Series, labels: pd.DataFrame) -> np.ndarray:
    """Per label row: does any event with that pid fall inside [start, end]?"""
    hit = np.zeros(len(labels), dtype=bool)
    t = ts.dt.tz_convert(None).to_numpy()  # UTC, as datetime64
    order = np.argsort(t, kind="stable")
    t, p = t[order], pid.to_numpy()[order]
    for i, (lp, s, e) in enumerate(zip(labels["pid"], labels["start"], labels["end"])):
        tt = t[p == lp]
        if len(tt):
            k = np.searchsorted(tt, s.tz_convert(None).to_datetime64())
            hit[i] = k < len(tt) and tt[k] <= e.tz_convert(None).to_datetime64()
    return hit


def _host_day(args):
    day, host, labels = args
    path = _path(day, host)
    rules = v3.load_v3()
    cols = [c for c in READ + ["pid"] if c in pq.read_schema(path).names]
    raw = pq.read_table(path, columns=cols).to_pandas()
    attack = "pid" in raw
    ts = pd.to_datetime(raw["ts"], utc=True)
    if attack:
        ev = pd.DataFrame({"Hostname": host, "_timestamp": ts, "ProcessId": raw["pid"]})
        mal_all = optc_redteam.label_events(ev, labels)
        covered = label_coverage(ts, raw["pid"], labels)
    else:
        mal_all, covered = np.zeros(len(raw), dtype=bool), np.zeros(len(labels), dtype=bool)
    acc = set()
    for r in rules:
        acc |= v3.accepted_sources(r["where"])[1]
    keep = raw["event_id"].isin(acc & set(optc.FIELDS)).to_numpy()
    sub = raw[keep].assign(_mal=mal_all[keep])
    frame, _ = optc.to_frame(sub, restore_bare=True, carry=("_mal",))
    t = tag(frame, rules)  # row-aligned with frame
    sel = (t["tactic"] != "").to_numpy()
    hit = t[sel]
    tagged = pd.DataFrame({"Hostname": host, "_day": day, "_timestamp": hit["ts"].to_numpy(),
                           "EventID": hit["event_id"].to_numpy(), "tactic": hit["tactic"].to_numpy(),
                           "rule_id": hit["rule_id"].to_numpy(),
                           "malicious": frame["_mal"].to_numpy(bool)[sel]})
    stats = {"day": day, "host": host, "events": int(len(raw)), "malicious_events": int(mal_all.sum()),
             "malicious_taggable_eid": int(sub["_mal"].sum()), "tagged": int(len(tagged)),
             "malicious_tagged": int(tagged["malicious"].sum()),
             "label_rows": int(len(labels)), "label_rows_covered": int(covered.sum())}
    return stats, tagged, ts.dt.tz_convert(None).to_numpy()[mal_all]


def run(config: dict, calls=None) -> dict:
    cfg = yaml.safe_load(optc_split.REDTEAM.read_text())
    hosts = [optc_split.host_id(h) for h in cfg["targets"]]
    labels = optc_redteam.load_labels()
    jobs = []
    for h in hosts:
        lab = labels[labels["host"] == h].reset_index(drop=True)
        for day in optc_split.BENIGN_DAYS + optc_redteam.ATTACK_DAYS:
            if _path(day, h).exists():
                jobs.append((day, h, lab if day in optc_redteam.ATTACK_DAYS else lab.iloc[:0]))
    stats, tagged, mal = [], [], {}
    with ProcessPoolExecutor(config.get("workers", 4)) as ex:
        for s, t, m in ex.map(_host_day, jobs):
            stats.append(s)
            tagged.append(t)
            mal.setdefault(s["host"], []).append(m)
    st = pd.DataFrame(stats)
    tg = pd.concat(tagged, ignore_index=True)
    mal_ts = {h: np.sort(np.concatenate(v)) for h, v in mal.items()}
    win = optc_redteam.windows(tg, mal_ts)
    win["day"] = win["start"].dt.tz_convert("America/New_York").dt.strftime("%Y-%m-%d")
    win["attack_day"] = win["day"].isin(optc_redteam.ATTACK_DAYS)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    win.to_parquet(OUT, index=False)
    # Label rows per host count once (coverage is per attack day; a row is covered if any day covers it).
    lab_h = labels[labels["host"].isin(hosts)]
    cov = st[st["day"].isin(optc_redteam.ATTACK_DAYS)].groupby("host")["label_rows_covered"].sum()
    by_day = st.groupby("day")[["events", "malicious_events", "malicious_taggable_eid", "tagged",
                                "malicious_tagged"]].sum()
    wd = win.groupby("day").agg(windows=("positive", "size"), positive=("positive", "sum"),
                                positive_span=("positive_span", "sum"))
    pos_tac = win.loc[win["positive"], "tactics"].explode().value_counts()
    mal_rules = tg[tg["malicious"]].groupby(["tactic", "rule_id"]).size().sort_values(ascending=False)
    titles = {r["id"]: r["title"] for r in v3.load_v3()}
    return {
        "mapper": "v3", "window": optc_redteam.WINDOW, "hosts": len(hosts), "host_days": len(jobs),
        "host_days_by_day": st.groupby("day").size().to_dict(),
        "labels": {"rows_on_targets": int(len(lab_h)), "rows_other_hosts": int(len(labels) - len(lab_h)),
                   "rows_matched_by_some_event_upper": int(cov.sum()),
                   "hosts_with_label_rows": int(lab_h["host"].nunique())},
        "by_day": {d: {k: int(v) for k, v in r.items()} for d, r in by_day.iterrows()},
        "windows_by_day": {d: {k: int(v) for k, v in r.items()} for d, r in wd.iterrows()},
        "windows": int(len(win)), "positive_windows": int(win["positive"].sum()),
        "positive_span_windows": int(win["positive_span"].sum()),
        "positive_windows_by_host": win[win["positive"]].groupby("host").size().astype(int).to_dict(),
        "tactics_in_positive_windows": {k: int(v) for k, v in pos_tac.items()},
        "malicious_tagged_by_rule": [{"tactic": t, "rule_id": r, "title": titles.get(r), "n": int(n)}
                                     for (t, r), n in mal_rules.head(15).items()],
        "windows_file": str(OUT.relative_to(REPO_ROOT)),
    }
