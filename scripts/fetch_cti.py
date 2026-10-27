"""Fetch every report in data/cti/manifest.csv (spec §1; SPEC_ISSUES 2026-10-27 Part B).

For each row: GET the URL (redirects followed), keep the raw response under
data/cti/raw/<doc_id>.<html|pdf>, save readable text to data/cti/reports/<doc_id>.txt
(HTML via trafilatura with boilerplate removed, PDF via pdftotext), and fill the sha256
column with the hash of the saved text. The page's own publication date and the final URL
are written to data/cti/fetch_report.json; dates are corrected in the manifest by hand.
No LLM calls. Everything written is under data/ (gitignored).

    python scripts/fetch_cti.py [--only DOC_ID ...]
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import requests

from ctit.cti import manifest

CTI = manifest.MANIFEST_PATH.parent
RAW = CTI / "raw"
UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"


def to_text(content: bytes, ctype: str) -> tuple[str, str | None, str]:
    """-> (text, page date or None, kind)."""
    if "pdf" in ctype or content[:5] == b"%PDF-":
        with tempfile.NamedTemporaryFile(suffix=".pdf") as f:
            f.write(content)
            f.flush()
            text = subprocess.run(["pdftotext", "-layout", f.name, "-"], check=True,
                                  capture_output=True).stdout.decode("utf-8", "replace")
        return text, None, "pdf"
    import trafilatura
    html = content.decode("utf-8", "replace")
    text = trafilatura.extract(html, include_comments=False, include_tables=True, favor_recall=True) or ""
    meta = trafilatura.extract_metadata(html)
    return text, (meta.date if meta else None), "html"


def fetch(row: dict) -> dict:
    out = {"doc_id": row["doc_id"], "url": row["url"]}
    try:
        r = requests.get(row["url"], headers={"User-Agent": UA}, timeout=60, allow_redirects=True)
        out.update(status=r.status_code, final_url=r.url,
                   redirects=[h.headers.get("location") for h in r.history])
        r.raise_for_status()
        text, date, kind = to_text(r.content, r.headers.get("content-type", ""))
    except Exception as e:  # recorded, not raised: one bad URL shouldn't stop the batch
        out.update(ok=False, error=f"{type(e).__name__}: {e}")
        return out
    RAW.mkdir(parents=True, exist_ok=True)
    (RAW / f"{row['doc_id']}.{kind}").write_bytes(r.content)
    path = manifest.TEXT_DIR / f"{row['doc_id']}.txt"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    out.update(ok=bool(text.strip()), kind=kind, words=len(text.split()), page_date=date,
               sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--only", nargs="*")
    args = p.parse_args(argv)
    header, rows = manifest.load()
    report_path = CTI / "fetch_report.json"
    report = json.loads(report_path.read_text()) if report_path.exists() else {}
    for row in rows:
        if args.only and row["doc_id"] not in args.only:
            continue
        res = fetch(row)
        report[row["doc_id"]] = res
        if res.get("ok"):
            row["sha256"] = res["sha256"]
        print(json.dumps({k: res.get(k) for k in ("doc_id", "ok", "status", "words", "page_date", "error")}))
    with manifest.MANIFEST_PATH.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=header)
        w.writeheader()
        w.writerows(rows)
    report_path.write_text(json.dumps(report, indent=1))
    return 0 if all(v.get("ok") for v in report.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
