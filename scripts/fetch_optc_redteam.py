"""Download raw eCAR for the OpTC red-team targets on the attack days (B6, SPEC_ISSUES 2026-10-27).

Source: the Inria corrected OpTC release on Recherche Data Gouv (doi:10.57745/UXCWOC), one tar
per day. Each host-day is one gzipped eCAR JSON-lines member of that tar; its byte offset and
size come from the per-day tar indexes already built by STRATA-E
($CTIT_OPTC_INDEX/<day>.json, default data/optc/index/; read only). Each member is range-fetched,
checked for exact length and a full gzip CRC pass, and written to
data/optc_redteam/raw/<day>/sysclientNNNN.json.gz with its sha256 in
data/optc_redteam/raw/fetch_manifest.json. Already-verified files are skipped.

    python scripts/fetch_optc_redteam.py [--workers 4] [--days 2019-09-23 ...]
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
import sys
import time
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import requests
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
INDEX = Path(os.environ.get("CTIT_OPTC_INDEX", REPO_ROOT / "data/optc/index"))
OUT = REPO_ROOT / "data" / "optc_redteam" / "raw"
DATAVERSE = "https://entrepot.recherche.data.gouv.fr"
ACCESS = DATAVERSE + "/api/access/datafile/{id}"
DAYS = ("2019-09-23", "2019-09-24", "2019-09-25")
UA = "ctit/w2 (research; github.com/jackdmoody)"


class Signed:
    """The access API 303-redirects to a short-lived signed S3 URL; refresh before expiry."""

    def __init__(self, file_id: int):
        self.file_id, self.url, self.expires = file_id, None, 0.0

    def get(self) -> str:
        if self.url is None or time.time() > self.expires - 60:
            r = requests.get(ACCESS.format(id=self.file_id), allow_redirects=False, timeout=60,
                             headers={"User-Agent": UA})
            loc = r.headers["Location"]
            self.url = loc
            self.expires = time.time() + int(parse_qs(urlparse(loc).query).get("X-Amz-Expires", ["600"])[0])
        return self.url


def gzip_ok(path: Path) -> int:
    """Full decompression (CRC32 and length checked by gzip); returns the line count."""
    n = 0
    with gzip.open(path, "rb") as f:
        for _ in f:
            n += 1
    return n


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def fetch(job: dict, signed: Signed) -> dict:
    dest = OUT / job["day"] / f"sysclient{job['host']}.json.gz"
    dest.parent.mkdir(parents=True, exist_ok=True)
    start, end = job["offset"], job["offset"] + job["size"] - 1
    for attempt in range(8):
        try:
            tmp = dest.with_suffix(".part")
            with requests.get(signed.get(), headers={"User-Agent": UA, "Range": f"bytes={start}-{end}"},
                              stream=True, timeout=300) as r:
                if r.status_code in (400, 403):
                    signed.url = None
                r.raise_for_status()
                if r.status_code != 206:
                    raise RuntimeError(f"expected 206 Partial Content, got {r.status_code}")
                with tmp.open("wb") as f:
                    for b in r.iter_content(1 << 20):
                        f.write(b)
            if tmp.stat().st_size != job["size"]:
                raise RuntimeError(f"length {tmp.stat().st_size} != {job['size']}")
            lines = gzip_ok(tmp)
            tmp.replace(dest)
            return {**job, "path": str(dest.relative_to(REPO_ROOT)), "sha256": sha256(dest), "events": lines}
        except (requests.RequestException, RuntimeError, OSError, EOFError, zlib.error) as e:
            print(f"retry {attempt + 1} {job['day']} {job['host']}: {e}", flush=True)
            time.sleep(min(60, 5 * 2 ** attempt))
    raise RuntimeError(f"giving up on {job['day']} {job['host']}")


def jobs(days, targets) -> list[dict]:
    out = []
    for day in days:
        idx = json.loads((INDEX / f"{day}.json").read_text())
        for m in idx["members"]:
            host = m["name"].split("sysclient")[-1][:4]
            if f"sysclient{host}" in targets:
                out.append({"day": day, "host": host, "member": m["name"], "offset": m["offset"],
                            "size": m["size"], "tar_id": idx["tar"]["id"], "tar": idx["tar"]["name"],
                            "tar_md5": idx["tar"]["md5"]})
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--days", nargs="*", default=list(DAYS))
    args = p.parse_args(argv)
    targets = set(yaml.safe_load((REPO_ROOT / "configs" / "optc_redteam.yaml").read_text())["targets"])
    todo = jobs(args.days, targets)
    man_path = OUT / "fetch_manifest.json"
    man = json.loads(man_path.read_text()) if man_path.exists() else {}
    todo = [j for j in todo if f"{j['day']}/{j['host']}" not in man]
    print(f"{len(todo)} members, {sum(j['size'] for j in todo) / 1e9:.2f} GB to fetch", flush=True)
    signed = {tid: Signed(tid) for tid in {j["tar_id"] for j in todo}}
    failed = 0
    with ThreadPoolExecutor(args.workers) as ex:
        futs = {ex.submit(fetch, j, signed[j["tar_id"]]): j for j in todo}
        for f in as_completed(futs):
            j = futs[f]
            try:
                rec = f.result()
            except RuntimeError as e:
                failed += 1
                print(f"FAIL {e}", flush=True)
                continue
            man[f"{j['day']}/{j['host']}"] = rec
            man_path.write_text(json.dumps(man, indent=1, sort_keys=True))
            print(f"ok {j['day']} {j['host']} {j['size'] / 1e6:.0f} MB {rec['events']:,} events", flush=True)
    man_path.write_text(json.dumps(man, indent=1, sort_keys=True))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
