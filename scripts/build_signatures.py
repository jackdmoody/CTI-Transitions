#!/usr/bin/env python
"""Build the technique tactic-signature library (spec §2.2).

For every public per-technique recording, run the frozen extended mapper and the
BRiMS mapper and store the tactic subsequence each mapper actually emits, with
relative timing. Raw telemetry is only read; nothing is modified or written back.

Sources (full raw fields only, per W2 decision):
  - Splunk Attack Data full-XML samples   (ctit.ingest.splunk.SAMPLES)
  - OTRF atomic Windows datasets           (data/otrf/atomic/canonical/*.parquet)
The 470-file lowercase DRIFT-style corpus is deliberately excluded: it lacks fields
the Sigma rules need and would understate the extended mapper.

Usage (repo root, w2 env):
  python scripts/build_signatures.py
  python scripts/build_signatures.py --out data/eval/tactic_signatures.parquet
  python scripts/build_signatures.py --mapper-version 2   # the earlier v2 library
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pandas as pd
import yaml

from ctit.ingest import splunk
from ctit.map.coverage import brims_tag
from ctit.map.extended import tag as ext_tag

ATOMIC_CANON = Path("data/otrf/atomic/canonical")
ATOMIC_META = Path("data/otrf/atomic/metadata")
DEFAULT_OUT = Path("data/eval/tactic_signatures.parquet")
TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
MAPPERS = ("extended", "brims")
MAX_UNMATCHED_FRAC = 0.2  # fail loudly if OTRF archives can't be tied to techniques


# ----------------------------------------------------------------------------- helpers

def parent(technique: str) -> str:
    return technique.split(".")[0] if technique else ""


def _strip_archive_ext(name: str) -> str:
    for ext in (".tar.gz", ".zip", ".json", ".parquet"):
        if name.endswith(ext):
            return name[: -len(ext)]
    return name


def _load_meta(path: Path) -> dict:
    text = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix == ".json":
        return json.loads(text) or {}
    return yaml.safe_load(text) or {}


def atomic_technique_map() -> dict[str, set[str]]:
    """Archive stem -> ATT&CK technique IDs, from OTRF metadata files."""
    out: dict[str, set[str]] = {}
    files = sorted(list(ATOMIC_META.glob("*.y*ml")) + list(ATOMIC_META.glob("*.json")))
    if not files:
        sys.exit(f"No OTRF metadata files found in {ATOMIC_META}")
    for p in files:
        meta = _load_meta(p)
        techs: set[str] = set()
        for m in meta.get("attack_mappings") or []:
            t = str(m.get("technique") or "").strip()
            sub = m.get("sub-technique", m.get("sub_technique"))
            if sub not in (None, "", "None", "none"):
                t = f"{t}.{str(sub).strip().zfill(3)}"
            if TECH_RE.match(t):
                techs.add(t)
        for f in meta.get("files") or []:
            stem = _strip_archive_ext(Path(str(f.get("link") or "")).name)
            if stem:
                out[stem] = techs
    return out


def collapse(tactics: list[str], rel_s: list[float]) -> tuple[list[str], list[float]]:
    """Collapse consecutive repeats of the same tactic, keeping the first timestamp."""
    ct, cr = [], []
    for t, r in zip(tactics, rel_s):
        if not ct or ct[-1] != t:
            ct.append(t)
            cr.append(r)
    return ct, cr


EXT_RULES: list[dict] | None = None  # None = frozen v2 (tag's default); --mapper-version 3 sets v3


def tag_with(df: pd.DataFrame, mapper: str) -> pd.DataFrame:
    return ext_tag(df, EXT_RULES) if mapper == "extended" else brims_tag(df)


def per_host_sequences(tagged: pd.DataFrame):
    """Yield (host, tactics, rel_s, n_tagged) from a mapper output frame."""
    tagged = tagged[tagged["tactic"].astype(str) != ""]
    for host, g in tagged.groupby("host", sort=True):
        g = g.assign(_ts=pd.to_datetime(g["ts"], utc=True)).sort_values("_ts", kind="stable")
        rel = (g["_ts"] - g["_ts"].iloc[0]).dt.total_seconds().round(3).tolist()
        yield str(host), g["tactic"].astype(str).tolist(), rel, len(g)


def signature_rows(df: pd.DataFrame, techniques: set[str], source: str, recording: str) -> list[dict]:
    rows = []
    n_events_by_host = df.groupby("Hostname").size().to_dict() if "Hostname" in df else {}
    for mapper in MAPPERS:
        tagged = tag_with(df, mapper)
        for host, tactics, rel, n_tagged in per_host_sequences(tagged):
            ct, cr = collapse(tactics, rel)
            for tech in sorted(techniques):
                rows.append({
                    "technique": tech,
                    "parent": parent(tech),
                    "source": source,
                    "recording": recording,
                    "host": host,
                    "mapper": mapper,
                    "tactics": tactics,
                    "rel_s": rel,
                    "tactics_collapsed": ct,
                    "rel_s_collapsed": cr,
                    "n_events": int(n_events_by_host.get(host, 0)),
                    "n_tagged": int(n_tagged),
                })
    return rows


# ----------------------------------------------------------------------------- sources

def splunk_rows() -> tuple[list[dict], list[str]]:
    rows, skipped = [], []
    for p in sorted(Path(splunk.SAMPLES).iterdir()):
        try:
            r = splunk.read_sample(p)
        except ET.ParseError as e:
            skipped.append(f"{p.name}: ParseError {e}")
            continue
        if r is None:
            skipped.append(f"{p.name}: not a full-XML technique sample")
            continue
        technique, df = r
        if not TECH_RE.match(technique):
            skipped.append(f"{p.name}: bad technique id {technique!r}")
            continue
        rows += signature_rows(df, {technique}, "splunk_attack_data", p.name)
    return rows, skipped


def otrf_atomic_rows() -> tuple[list[dict], list[str]]:
    tmap = atomic_technique_map()
    rows, skipped, unmatched = [], [], 0
    files = sorted(ATOMIC_CANON.glob("*.parquet"))
    if not files:
        sys.exit(f"No OTRF atomic canonical files in {ATOMIC_CANON}")
    for p in files:
        name = p.stem.split("__", 1)[1] if "__" in p.stem else p.stem
        techs = tmap.get(name) or tmap.get(_strip_archive_ext(name))
        if not techs:
            unmatched += 1
            skipped.append(f"{p.name}: no technique mapping in metadata")
            continue
        techs = {t for t in techs if t != "T0000"}  # OTRF placeholder
        if not techs:
            skipped.append(f"{p.name}: placeholder technique only")
            continue
        rows += signature_rows(pd.read_parquet(p), techs, "otrf_atomic", p.name)
    if files and unmatched / len(files) > MAX_UNMATCHED_FRAC:
        sys.exit(f"{unmatched}/{len(files)} OTRF archives unmatched to metadata; "
                 "check archive naming vs metadata 'files' links before trusting output.")
    return rows, skipped


# ----------------------------------------------------------------------------- main

def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--mapper-version", choices=("2", "3", "3h"), default="3")
    args = ap.parse_args()
    global EXT_RULES
    if args.mapper_version == "3":
        from ctit.map.v3 import load_v3
        EXT_RULES = load_v3()
    elif args.mapper_version == "3h":  # candidate (SPEC_ISSUES 2026-10-26, Part C)
        from ctit.map.v3 import load_v3h
        EXT_RULES = load_v3h()

    s_rows, s_skip = splunk_rows()
    o_rows, o_skip = otrf_atomic_rows()
    df = pd.DataFrame(s_rows + o_rows)
    if df.empty:
        sys.exit("No signatures produced.")
    df = df.sort_values(["mapper", "technique", "source", "recording", "host"], kind="stable").reset_index(drop=True)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(args.out, index=False)

    nonempty = df[df["tactics_collapsed"].map(len) > 0]
    summary = {
        "rows": int(len(df)),
        "rows_nonempty": int(len(nonempty)),
        "techniques_with_signature": {
            m: int(nonempty.loc[nonempty.mapper == m, "technique"].nunique()) for m in MAPPERS
        },
        "recordings": int(df["recording"].nunique()),
        "extended_mapper_version": args.mapper_version,
        "skipped": s_skip + o_skip,
    }
    summary_path = args.out.with_suffix(".summary.json")
    summary_path.write_text(json.dumps(summary, indent=2))
    print(json.dumps({k: v for k, v in summary.items() if k != "skipped"}, indent=2))
    print(f"skipped: {len(summary['skipped'])} (see {summary_path})")
    print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
