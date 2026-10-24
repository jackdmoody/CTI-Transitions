"""ATLASv2 (spec §2.4) Sysmon + Security XML -> canonical parquet + role file.

    python -m ctit.ingest.atlasv2

Inputs: data/atlasv2/extracted/atlasv2/data/{benign,attack}/h{1,2}/{sysmon,msft-security}/*.xml
(Event Viewer exports). Outputs: data/atlasv2/canonical/<split>-<host>-<scenario>/<source>-part-NNNNN.parquet,
data/atlasv2/groundtruth_record_ids.json (Security EventRecordIDs per attack scenario),
data/atlasv2/roles.json. Hosts are named atlas-h1 / atlas-h2.
"""
from __future__ import annotations

import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

from ctit.ingest import canonical

REPO_ROOT = Path(__file__).resolve().parents[2]
ATLAS_ROOT = REPO_ROOT / "data" / "atlasv2"
DATA_DIR = ATLAS_ROOT / "extracted" / "atlasv2" / "data"
FILE_RE = re.compile(r"^(sysmon|msft-security)-(h\d)-(.+)\.xml$")
SOURCE = {"sysmon": "sysmon", "msft-security": "security"}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def iter_events(path: Path):
    """Yield one dict per <Event>: System fields + EventData/UserData name/value pairs."""
    root = None
    for event, elem in ET.iterparse(path, events=("start", "end")):
        if root is None:
            root = elem
        if event != "end" or _local(elem.tag) != "Event":
            continue
        rec = event_record(elem)
        root.clear()  # drop finished <Event>s from the tree; files are up to 20 GB
        yield rec


def event_record(elem) -> dict:
    """One Windows <Event> element -> flat dict."""
    rec: dict = {}
    for child in elem:
        name = _local(child.tag)
        if name == "System":
            for s in child:
                sname = _local(s.tag)
                if sname == "TimeCreated":
                    rec["SystemTime"] = s.get("SystemTime")
                elif sname == "Provider":
                    rec["ProviderName"] = s.get("Name")
                elif sname == "Execution":
                    rec["ProcessID"], rec["ThreadID"] = s.get("ProcessID"), s.get("ThreadID")
                elif sname == "Security":
                    rec["SecurityUserID"] = s.get("UserID")
                elif s.text is not None:
                    rec[sname] = s.text
        elif name == "EventData":
            for d in child:
                if d.get("Name"):
                    rec[d.get("Name")] = d.text
        elif name == "UserData":
            for payload in child:
                for d in payload:
                    rec[_local(d.tag)] = d.text
    return rec


def _core(rec: dict, host: str, source: str) -> dict:
    rec.update(
        _timestamp=rec.pop("SystemTime"), Hostname=host, source=source,
        EventID=int(rec["EventID"]), Channel=rec.get("Channel", ""),
    )
    return rec


def read_file(path: Path, host: str, source: str) -> list[dict]:
    return [_core(rec, host, source) for rec in iter_events(path)]


CHUNK = 500_000  # events per parquet part; Security XML is ~35 GB, so stream it


def write_group(paths: list[Path], host: str, out: Path) -> dict[str, int]:
    """Stream each XML file into out/<source>-part-NNNNN.parquet; returns events per source."""
    out.mkdir(parents=True, exist_ok=True)
    counts: dict[str, int] = {}
    for p in paths:
        source = SOURCE[FILE_RE.match(p.name).group(1)]
        buf, part = [], 0

        def flush():
            nonlocal buf, part
            if buf:
                canonical.to_frame(buf).to_parquet(out / f"{source}-part-{part:05d}.parquet", index=False)
                part += 1
                buf = []

        for rec in iter_events(p):
            buf.append(_core(rec, host, source))
            counts[source] = counts.get(source, 0) + 1
            if len(buf) >= CHUNK:
                flush()
        flush()
    return counts


def main() -> int:
    out_root = ATLAS_ROOT / "canonical"
    groups: dict[tuple[str, str, str], list[Path]] = {}
    for path in sorted(DATA_DIR.glob("*/h*/*/*.xml")):
        m = FILE_RE.match(path.name)
        if m:
            groups.setdefault((path.parts[-4], m.group(2), m.group(3)), []).append(path)
    hosts = set()
    for (split, h, scenario), paths in sorted(groups.items()):
        host = f"atlas-{h}"
        hosts.add(host)
        name = f"{split}-{h}-{scenario}"
        counts = write_group(paths, host, out_root / name)
        print(f"{name}: {counts}", flush=True)
    # Ground truth: Security EventRecordIDs per attack scenario (ATLASv2 README).
    labels = {}
    for gt in sorted(DATA_DIR.glob("attack/h*/msft-security/groundtruth/*")):
        labels[gt.name] = [int(x) for x in gt.read_text().split()]
    (ATLAS_ROOT / "groundtruth_record_ids.json").write_text(json.dumps(labels) + "\n")
    # Both ATLASv2 hosts are single-user Windows 7 desktops (ATLASv2 README).
    roles = {h: "workstation" for h in sorted(hosts)}
    (ATLAS_ROOT / "roles.json").write_text(json.dumps(roles, indent=2) + "\n")
    print("roles:", roles, "ground-truth scenarios:", {k: len(v) for k, v in labels.items()})
    return 0


if __name__ == "__main__":
    sys.exit(main())
