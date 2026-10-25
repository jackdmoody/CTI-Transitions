"""OTRF Security-Datasets atomic Windows host datasets -> canonical parquet + coverage.

    python -m ctit.ingest.otrf_atomic

Inputs: data/otrf/atomic/raw/<SDWIN-id>__<name>.zip or .tar.gz (JSON lines; some archives
hold several files) and data/otrf/atomic/metadata/<SDWIN-id>.yaml (ATT&CK mappings), pinned in
data/otrf/atomic/SOURCES.txt.
Outputs: data/otrf/atomic/canonical/<SDWIN-id>__<name>.parquet (one per zip; all raw fields kept, including
Message) and data/otrf/atomic/coverage.csv (per technique, next to the full-XML Splunk
samples).

Timestamps differ across datasets. Per record, the first present wins:
Sysmon UtcTime -> TimeCreated -> @timestamp -> EventTime + offset. The offset is measured
from Sysmon UtcTime when possible, else 0. Naive times are taken as UTC. The field used is
kept in `_ts_source`. Only relative timing within one dataset is relied on.
"""
from __future__ import annotations

import json
import sys
import tarfile
import zipfile
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
import yaml

from ctit.ingest import canonical, splunk

REPO_ROOT = Path(__file__).resolve().parents[2]
ROOT = REPO_ROOT / "data" / "otrf" / "atomic"
SOURCES = ("sysmon", "security", "system")


def techniques(meta: dict) -> list[str]:
    out = []
    for m in meta.get("attack_mappings") or []:
        t = str(m.get("technique", "")).upper()
        if not t.startswith("T"):
            continue
        sub = m.get("sub-technique")
        out.append(f"{t}.{int(sub):03d}" if sub not in (None, "", "None") else t)
    return sorted(set(out))


def _eventtime_offset(rows: list[dict]) -> timedelta:
    diffs = Counter()
    for r in rows:
        if canonical.source_of(r.get("Channel")) == "sysmon" and r.get("UtcTime") and r.get("EventTime"):
            d = datetime.strptime(r["UtcTime"][:19], "%Y-%m-%d %H:%M:%S") - datetime.strptime(r["EventTime"][:19], "%Y-%m-%d %H:%M:%S")
            diffs[round(d.total_seconds() / 60)] += 1
    return timedelta(minutes=diffs.most_common(1)[0][0]) if diffs else timedelta(0)


def _timestamp(r: dict, offset: timedelta) -> tuple[pd.Timestamp, str]:
    if canonical.source_of(r.get("Channel")) == "sysmon" and r.get("UtcTime"):
        return pd.Timestamp(r["UtcTime"], tz="UTC"), "UtcTime"
    for key in ("TimeCreated", "@timestamp"):
        if r.get(key):
            ts = pd.Timestamp(r[key])
            return (ts.tz_localize("UTC") if ts.tzinfo is None else ts.tz_convert("UTC")), key
    return pd.Timestamp(datetime.strptime(r["EventTime"][:19], "%Y-%m-%d %H:%M:%S") + offset, tz="UTC"), "EventTime"


def _members(path: Path):
    """Yield (name, binary file) for each data file in a .zip or .tar.gz archive. macOS
    resource forks (__MACOSX/, ._*) are not data and are skipped."""
    def is_data(n: str) -> bool:
        return not n.endswith("/") and not n.startswith("__MACOSX/") and not Path(n).name.startswith("._")
    if path.name.endswith(".tar.gz"):
        with tarfile.open(path, "r:gz") as t:
            for m in sorted((m for m in t.getmembers() if m.isfile() and is_data(m.name)), key=lambda m: m.name):
                yield m.name, t.extractfile(m)
    else:
        with zipfile.ZipFile(path) as z:
            for name in sorted(n for n in z.namelist() if is_data(n)):
                with z.open(name) as f:
                    yield name, f


def flatten_winlogbeat(r: dict) -> dict:
    """2019-era Winlogbeat records (log_name, event_id, computer_name, nested event_data)
    -> the flat layout used by the other OTRF datasets. Field values are unchanged."""
    if "Channel" in r or "log_name" not in r:
        return r
    flat = {k: v for k, v in r.items() if k != "event_data"}
    flat.update(r.get("event_data") or {})
    flat.update(Channel=r["log_name"], EventID=r.get("event_id"), Hostname=r.get("computer_name"))
    return flat


def read_zip(path: Path) -> pd.DataFrame | None:
    rows = []
    for _, f in _members(path):
        for line in f:
            line = line.strip()
            if line:
                rows.append(flatten_winlogbeat(json.loads(line)))
    rows = [r for r in rows if canonical.source_of(r.get("Channel")) in SOURCES and r.get("Hostname")]
    if not rows:
        return None
    offset = _eventtime_offset(rows)
    records = []
    for r in rows:
        ts, used = _timestamp(r, offset)
        rec = {k: (v if isinstance(v, str) else json.dumps(v)) for k, v in r.items()}
        rec.update(_timestamp=ts, _ts_source=used, Hostname=canonical.short_host(r["Hostname"]),
                   source=canonical.source_of(r["Channel"]), EventID=int(r["EventID"]), Channel=r["Channel"])
        records.append(rec)
    return canonical.to_frame(records)


def main() -> int:
    out_dir = ROOT / "canonical"
    out_dir.mkdir(parents=True, exist_ok=True)
    per_tech: dict[str, Counter] = defaultdict(Counter)
    skipped = []
    for z in sorted(p for p in (ROOT / "raw").glob("SDWIN-*") if p.name.endswith((".zip", ".tar.gz"))):
        sd_id = z.name.split("__")[0]
        meta = yaml.safe_load((ROOT / "metadata" / f"{sd_id}.yaml").read_text())
        try:
            df = read_zip(z)
        except Exception as e:  # noqa: BLE001 - record and continue
            skipped.append(f"{z.name}: {type(e).__name__}: {e}")
            continue
        if df is None:
            skipped.append(f"{z.name}: no Sysmon/Security/System events")
            continue
        stem = z.name.removesuffix(".tar.gz").removesuffix(".zip")
        df.to_parquet(out_dir / f"{stem}.parquet", index=False)  # several archives can share one SDWIN id
        for t in techniques(meta) or ["(unmapped)"]:
            c = per_tech[t]
            c["otrf_atomic_datasets"] += 1
            for src, n in df["source"].value_counts().items():
                c[f"otrf_atomic_{src}_events"] += int(n)
    for p in sorted(splunk.SAMPLES.iterdir()):
        try:
            r = splunk.read_sample(p)
        except Exception as e:  # noqa: BLE001
            skipped.append(f"{p.name}: {type(e).__name__}")
            continue
        if r:
            t, df = r
            per_tech[t]["splunk_xml_samples"] += 1
            per_tech[t]["splunk_xml_events"] += len(df)
    cov = pd.DataFrame([{"technique": t, **c} for t, c in per_tech.items()]).fillna(0).sort_values("technique")
    num = [c for c in cov.columns if c != "technique"]
    cov[num] = cov[num].astype(int)
    cov.to_csv(ROOT / "coverage.csv", index=False)
    both = ((cov.get("otrf_atomic_datasets", 0) > 0) & (cov.get("splunk_xml_samples", 0) > 0)).sum()
    print(f"datasets ingested: {len(list(out_dir.glob('*.parquet')))}; skipped: {len(skipped)}")
    for s in skipped:
        print("  skip", s)
    print(f"techniques: {len(cov)} total; OTRF atomic {int((cov.get('otrf_atomic_datasets', 0) > 0).sum())}; "
          f"Splunk XML {int((cov.get('splunk_xml_samples', 0) > 0).sum())}; both {int(both)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
