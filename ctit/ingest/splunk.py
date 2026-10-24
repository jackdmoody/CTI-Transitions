"""Splunk Attack Data atomic_red_team samples (mapper validation only, WP4b).

Files: data/splunk_attack_data/samples/<technique>_atomic_red_team_windows-{sysmon,security}.log,
one XML <Event> per line. Classic-text (non-XML) Security exports are skipped.
"""
from __future__ import annotations

import io
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from ctit.ingest import canonical
from ctit.ingest.atlasv2 import _core, event_record

REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLES = REPO_ROOT / "data" / "splunk_attack_data" / "samples"
NAME_RE = re.compile(r"^(T\d{4}(?:\.\d{3})?)_atomic_red_team_windows-(sysmon|security)\.log$")


def is_xml(path: Path) -> bool:
    with path.open("rb") as f:
        return f.read(6) == b"<Event"


def read_sample(path: Path):
    """-> (technique, canonical DataFrame) or None for non-XML files."""
    m = NAME_RE.match(path.name)
    if not m or not is_xml(path):
        return None
    technique, source = m.group(1), m.group(2)
    # Events can span lines (newlines inside field values), so parse the file as one document.
    body = path.read_bytes().replace(b"<?xml", b"<!--xml").replace(b"?>", b"-->")
    records = []
    for _, elem in ET.iterparse(io.BytesIO(b"<Events>" + body + b"</Events>"), events=("end",)):
        if elem.tag.rsplit("}", 1)[-1] == "Event":
            rec = event_record(elem)
            records.append(_core(rec, canonical.short_host(rec.get("Computer", "unknown")), source))
            elem.clear()
    if not records:
        return None
    return technique, canonical.to_frame(records)
