"""Public CTI manifest for the release (POST HOC, 2026-10-31; Jack's final coding pass, item 9).

Reads data/cti/manifest.csv, checks every sha256 against the SHA-256 of the extracted text in
data/cti/reports/<doc_id>.txt, and writes release/cti_manifest.csv: URLs, dates, hashes and roles,
never the text. The oracle document (OpTC red-team ground truth) is listed with its own hash.

    python scripts/release_manifest.py
"""
from __future__ import annotations

import csv
import hashlib
import sys
from pathlib import Path

from ctit.cti import manifest

REPO_ROOT = Path(__file__).resolve().parents[1]
OUT = REPO_ROOT / "release" / "cti_manifest.csv"
ORACLE = REPO_ROOT / "data" / "optc_check" / "groundtruth" / "OpTCRedTeamGroundTruth.txt"
ORACLE_ROW = {"doc_id": "oracle", "actor": "OpTC-redteam", "nation": "", "source_org": "DARPA / FiveDirections",
              "url": "https://github.com/FiveDirections/OpTC-data (OpTCRedTeamGroundTruth.pdf, commit b2673729)",
              "pub_date": "", "used_for": "oracle (case study B only)", "cited_by_emulation_plan": "",
              "note": "text extracted from the PDF; sha256 of that text"}
COLS = ["doc_id", "actor", "nation", "source_org", "url", "pub_date", "sha256_extracted_text", "used_for",
        "cited_by_emulation_plan", "note"]


def main() -> int:
    _, rows = manifest.load()
    out, bad = [], []
    for r in rows:
        text = manifest.TEXT_DIR / f"{r['doc_id']}.txt"
        h = hashlib.sha256(text.read_bytes()).hexdigest() if text.exists() else None
        if h != r["sha256"]:
            bad.append(r["doc_id"])
        out.append({**{k: r.get(k, "") for k in COLS if k != "sha256_extracted_text"}, "sha256_extracted_text": r["sha256"]})
    out.append({**ORACLE_ROW, "sha256_extracted_text": hashlib.sha256(ORACLE.read_bytes()).hexdigest()})
    if bad:
        print("sha256 mismatch:", " ".join(bad), file=sys.stderr)
        return 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS)
        w.writeheader()
        w.writerows(out)
    print(f"{OUT.relative_to(REPO_ROOT)}: {len(out)} rows, every hash verified")
    return 0


if __name__ == "__main__":
    sys.exit(main())
