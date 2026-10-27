"""Convert the raw red-team eCAR (scripts/fetch_optc_redteam.py) to host-day parquet with pid kept.

Output: data/optc_redteam/canonical/<day>/SysClientNNNN.systemia.com.parquet, same columns as
the STRATA-E conversion plus pid/ppid (ctit.ingest.ecar). The process table is carried across
a host's days (23 -> 24 -> 25 Sep), as STRATA-E did; it starts empty on 23 Sep, so targets of
processes started before then stay unresolved. Where the STRATA-E file for the same host-day
exists, per-event-id row counts are compared and logged. Summary:
data/optc_redteam/canonical/convert_report.json.

    python scripts/convert_optc_redteam.py [--workers 6]
"""
from __future__ import annotations

import argparse
import json
import sys
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pyarrow.parquet as pq

from ctit.eval import optc_split
from ctit.ingest import ecar

REPO_ROOT = Path(__file__).resolve().parents[1]
RAW = REPO_ROOT / "data" / "optc_redteam" / "raw"
OUT = REPO_ROOT / "data" / "optc_redteam" / "canonical"
DAYS = ("2019-09-23", "2019-09-24", "2019-09-25")


def strata_counts(day: str, host: str) -> dict | None:
    p = optc_split.OPTC_ROOT / day / f"SysClient{host}.systemia.com.parquet"
    if not p.exists():
        return None
    t = pq.read_table(p, columns=["event_id"]).column("event_id").value_counts()
    return {int(x["values"]): int(x["counts"]) for x in t.to_pylist()}


def convert_host(host: str) -> dict:
    table = ecar.ProcessTable()
    out = {}
    for day in DAYS:
        src = RAW / day / f"sysclient{host}.json.gz"
        if not src.exists():
            continue
        s = ecar.convert_file(src, OUT / day / f"SysClient{host}.systemia.com.parquet", table)
        ref = strata_counts(day, host)
        s["strata_event_ids"] = ref
        s["event_ids_match_strata"] = None if ref is None else ref == s["event_ids"]
        s.pop("pairs")
        out[day] = s
    return {host: out}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--workers", type=int, default=6)
    args = p.parse_args(argv)
    hosts = sorted({f.name[9:13] for f in RAW.glob("*/sysclient*.json.gz")})
    report = {}
    with ProcessPoolExecutor(args.workers) as ex:
        for res in ex.map(convert_host, hosts):
            report.update(res)
            (h, days), = res.items()
            print(h, {d: (v["rows"], v["event_ids_match_strata"]) for d, v in days.items()}, flush=True)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "convert_report.json").write_text(json.dumps(report, indent=1, sort_keys=True))
    bad = [(h, d) for h, days in report.items() for d, v in days.items() if v["event_ids_match_strata"] is False]
    print(f"{len(hosts)} hosts; event-id counts differ from STRATA-E on {len(bad)} host-days: {bad}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
