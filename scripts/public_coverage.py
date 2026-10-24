"""BRiMS-mapper coverage and K on the public datasets (WP4). Local data only.

    python scripts/public_coverage.py otrf|atlasv2 [--workers N]
Writes data/<dataset>/coverage_brims.json; tagged events go to data/<dataset>/tagged_brims/.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import pandas as pd

from ctit.map.coverage import ENTERPRISE_TACTICS, brims_tag

REPO_ROOT = Path(__file__).resolve().parents[1]
DATASETS = {
    "otrf": REPO_ROOT / "data" / "otrf" / "apt29",
    "atlasv2": REPO_ROOT / "data" / "atlasv2",
}


def _part(args) -> tuple[Counter, Counter]:
    root, part = args
    canon = root / "canonical"
    name = "__".join(part.relative_to(canon).with_suffix("").parts)
    tagged = brims_tag(pd.read_parquet(part))
    tagged.to_parquet(root / "tagged_brims" / f"{name}.parquet", index=False)
    hit = tagged["tactic"] != ""
    return Counter(tagged["source"]), Counter(zip(tagged.loc[hit, "source"], tagged.loc[hit, "tactic"]))


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("dataset", choices=sorted(DATASETS))
    p.add_argument("--workers", type=int, default=4)
    args = p.parse_args(argv)
    root = DATASETS[args.dataset]
    (root / "tagged_brims").mkdir(exist_ok=True)
    parts = sorted((root / "canonical").rglob("*.parquet"))
    events, tagged = Counter(), Counter()
    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        for ev, tg in pool.map(_part, [(root, p) for p in parts]):
            events.update(ev)
            tagged.update(tg)
    order = {t: i for i, t in enumerate(ENTERPRISE_TACTICS)}
    report = {
        "by_source": {s: {"events": n, "tagged": sum(c for (src, _), c in tagged.items() if src == s),
                          "tag_rate": sum(c for (src, _), c in tagged.items() if src == s) / n}
                      for s, n in sorted(events.items())},
        "tactic_counts": {t: sum(c for (_, tt), c in tagged.items() if tt == t)
                          for t in sorted({t for _, t in tagged}, key=order.get)},
        "K": {"sysmon": sorted({t for s, t in tagged if s == "sysmon"}, key=order.get),
              "all_sources": sorted({t for _, t in tagged}, key=order.get)},
    }
    (root / "coverage_brims.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
