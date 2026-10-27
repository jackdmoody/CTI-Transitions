"""DARPA OpTC host population and the fixed host split (spec §2.1, SPEC_ISSUES 2026-10-26).

Population: hosts with a converted eCAR file on every benign day (19–22 Sep 2019) in the
STRATA-E conversion (read only, under OPTC_ROOT). Clean hosts = population minus every
red-team target in configs/optc_redteam.yaml. The split is by host, drawn once with a fixed
seed (scripts/draw_optc_split.py writes configs/optc_split.yaml and refuses to redraw it).
"""
from __future__ import annotations

import os
import random
from pathlib import Path

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
OPTC_ROOT = Path(os.environ.get("CTIT_OPTC_ROOT", Path(__file__).resolve().parents[2] / "data/optc/canonical"))
BENIGN_DAYS = ("2019-09-19", "2019-09-20", "2019-09-21", "2019-09-22")
REDTEAM = REPO_ROOT / "configs" / "optc_redteam.yaml"
SPLIT = REPO_ROOT / "configs" / "optc_split.yaml"
FRACTIONS = {"fit": 0.50, "validation": 0.15, "test": 0.35}


def host_id(name: str) -> str:
    """'SysClient0052.systemia.com' / 'sysclient0052' -> 'sysclient0052' (canonical short host)."""
    return name.split(".")[0].lower()


def day_hosts(day: str, root: Path = OPTC_ROOT) -> set[str]:
    d = root / day
    return {host_id(p.name) for p in d.glob("*.parquet")} if d.is_dir() else set()


def population(root: Path = OPTC_ROOT, days=BENIGN_DAYS) -> list[str]:
    sets = [day_hosts(d, root) for d in days]
    return sorted(set.intersection(*sets)) if sets else []


def redteam_hosts(path: Path = REDTEAM) -> list[str]:
    return sorted(yaml.safe_load(path.read_text())["targets"])


def draw(clean: list[str], seed: int, fractions: dict = FRACTIONS) -> dict[str, list[str]]:
    """Seeded shuffle of the sorted clean hosts, cut into fit / validation / test."""
    hosts = sorted(clean)
    random.Random(seed).shuffle(hosts)
    n_fit = round(len(hosts) * fractions["fit"])
    n_val = round(len(hosts) * fractions["validation"])
    return {"fit": sorted(hosts[:n_fit]), "validation": sorted(hosts[n_fit:n_fit + n_val]),
            "test": sorted(hosts[n_fit + n_val:])}


def load_split(path: Path = SPLIT) -> dict[str, list[str]]:
    s = yaml.safe_load(path.read_text())
    return {k: s["hosts"][k] for k in ("fit", "validation", "test")}
