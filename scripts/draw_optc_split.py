#!/usr/bin/env python
"""Draw the OpTC host split once (B2) and write configs/optc_split.yaml.

Refuses to run if the split file exists: the split is drawn once, before any scoring, and
never redrawn.

    python scripts/draw_optc_split.py --seed 20261026
"""
from __future__ import annotations

import argparse
import hashlib
import sys

import yaml

from ctit.eval import optc_split as s


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed", type=int, required=True)
    args = ap.parse_args()
    if s.SPLIT.exists():
        sys.exit(f"{s.SPLIT} exists; the split is never redrawn.")
    pop = s.population()
    red = set(s.redteam_hosts())
    clean = [h for h in pop if h not in red]
    split = s.draw(clean, args.seed)
    doc = {
        "seed": args.seed,
        "fractions": s.FRACTIONS,
        "days": list(s.BENIGN_DAYS),
        "population": {"hosts": len(pop), "redteam_in_population": sorted(red & set(pop)),
                       "redteam_not_in_population": sorted(red - set(pop)), "clean": len(clean),
                       "sha256_clean_list": hashlib.sha256("\n".join(clean).encode()).hexdigest()},
        "counts": {k: len(v) for k, v in split.items()},
        "hosts": split,
    }
    header = ("# OpTC host split (B2), drawn once on 2026-10-26 by scripts/draw_optc_split.py before any\n"
              "# scoring. Never redraw. fit = baseline; validation = alpha/lambda tuning only; test = touched\n"
              "# once per final run. All 4 benign days for each host.\n")
    s.SPLIT.write_text(header + yaml.safe_dump(doc, sort_keys=False, width=110))
    print(doc["population"], doc["counts"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
