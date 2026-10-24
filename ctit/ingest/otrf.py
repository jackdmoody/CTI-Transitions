"""OTRF Security-Datasets APT29 evals (spec §2.3b) -> canonical parquet + role file.

    python -m ctit.ingest.otrf

Inputs: data/otrf/apt29/json/apt29_evals_day{1,2}_manual_*.json (JSON lines, one event each).
Outputs: data/otrf/apt29/canonical/day{1,2}.parquet, data/otrf/apt29/roles.json.

Timestamps: Sysmon rows use UtcTime (ms). Other channels only carry EventTime, which is
local time; its offset to UTC is measured from Sysmon rows (UtcTime - EventTime) and must
be a single constant, else ingest fails.
"""
from __future__ import annotations

import json
import statistics
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ctit.ingest import canonical

REPO_ROOT = Path(__file__).resolve().parents[2]
OTRF_ROOT = REPO_ROOT / "data" / "otrf" / "apt29"
DROP_FIELDS = {"Message"}  # free-text duplicate of the parsed fields
DC_EVENT_IDS = {4768, 4769}  # Kerberos TGT/TGS issued: only a DC logs these


def _parse(ts: str) -> datetime:
    return datetime.strptime(ts[:19], "%Y-%m-%d %H:%M:%S")


def measure_offset(path: Path, sample: int = 5000) -> timedelta:
    offsets = Counter()
    with path.open() as f:
        for line in f:
            r = json.loads(line)
            if canonical.source_of(r.get("Channel")) == "sysmon" and r.get("UtcTime") and r.get("EventTime"):
                offsets[round((_parse(r["UtcTime"]) - _parse(r["EventTime"])).total_seconds() / 60)] += 1
                if sum(offsets.values()) >= sample:
                    break
    (minutes, n), *rest = offsets.most_common()
    if rest and sum(c for _, c in rest) > 0.001 * n:
        raise ValueError(f"EventTime->UTC offset is not constant in {path}: {offsets.most_common(5)}")
    return timedelta(minutes=minutes)


def read_day(path: Path, sources=canonical.DEFAULT_SOURCES) -> list[dict]:
    offset = measure_offset(path)
    records = []
    with path.open() as f:
        for line in f:
            r = json.loads(line)
            source = canonical.source_of(r.get("Channel"))
            if source not in sources:
                continue
            if source == "sysmon" and r.get("UtcTime"):
                ts = datetime.strptime(r["UtcTime"], "%Y-%m-%d %H:%M:%S.%f")
            else:
                ts = _parse(r["EventTime"]) + offset
            rec = {k: (v if isinstance(v, str) else json.dumps(v)) for k, v in r.items() if k not in DROP_FIELDS}
            rec.update(
                _timestamp=ts.replace(tzinfo=timezone.utc),
                Hostname=canonical.short_host(r["Hostname"]),
                source=source,
                EventID=int(r["EventID"]),
                Channel=r["Channel"],
            )
            records.append(rec)
    return records


def infer_roles(frames) -> dict[str, str]:
    """dc if the host logged Kerberos ticket issuance (4768/4769) on its Security channel, else workstation."""
    hosts, dcs = set(), set()
    for df in frames:
        hosts.update(df["Hostname"].unique())
        sec = df[(df["source"] == "security") & df["EventID"].isin(DC_EVENT_IDS)]
        dcs.update(sec["Hostname"].unique())
    return {h: ("dc" if h in dcs else "workstation") for h in sorted(hosts)}


def main() -> int:
    out_dir = OTRF_ROOT / "canonical"
    out_dir.mkdir(parents=True, exist_ok=True)
    frames = []
    for day in ("day1", "day2"):
        (src,) = sorted((OTRF_ROOT / "json").glob(f"apt29_evals_{day}_manual_*.json"))
        df = canonical.to_frame(read_day(src))
        df.to_parquet(out_dir / f"{day}.parquet", index=False, row_group_size=200_000)
        print(f"{day}: {len(df):,} events, hosts={sorted(df['Hostname'].unique())}, "
              f"sources={df['source'].value_counts().to_dict()}")
        frames.append(df)
    roles = infer_roles(frames)
    (OTRF_ROOT / "roles.json").write_text(json.dumps(roles, indent=2) + "\n")
    print("roles:", roles)
    return 0


if __name__ == "__main__":
    sys.exit(main())
