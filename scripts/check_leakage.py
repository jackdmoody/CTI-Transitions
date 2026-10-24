"""Fail (exit 1) if the CTI manifest breaks the spec §1 leakage rules. Run before any
extraction or scoring.

    python scripts/check_leakage.py [--manifest PATH] [--no-verify-text]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from ctit.cti import manifest


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--manifest", type=Path, default=manifest.MANIFEST_PATH)
    p.add_argument("--actors", type=Path, default=manifest.ACTORS_PATH)
    p.add_argument("--no-verify-text", action="store_true",
                   help="skip checking sha256 against data/cti/text/<doc_id>.txt")
    args = p.parse_args(argv)

    if not args.manifest.exists():
        print(f"FAIL: manifest not found: {args.manifest}")
        return 1
    header, rows = manifest.load(args.manifest)
    actors = manifest.load_actors(args.actors)
    errors = manifest.check(
        header, rows, actors,
        text_dir=None if args.no_verify_text else manifest.TEXT_DIR,
        cited=manifest.load_cited(actors),
    )
    if errors:
        print(f"FAIL: {len(errors)} problem(s) in {args.manifest}")
        for e in errors:
            print(f"  - {e}")
        return 1
    print(f"OK: {len(rows)} docs, leakage rules pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
