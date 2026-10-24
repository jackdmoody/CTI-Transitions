"""WP7 (part): non-LLM priors per actor -> data/priors/<actor>/{ATTK,Uni}.json (14 tactics).

Projection onto K happens at scoring time (ctit.cti.prior.project), once K is fixed at the
WP5 gate. No LLM calls.
"""
from __future__ import annotations

import hashlib
from pathlib import Path

from ctit.cti import prior
from ctit.cti.manifest import load_actors

REPO_ROOT = Path(__file__).resolve().parents[2]
PRIORS = REPO_ROOT / "data" / "priors"


def run(config: dict, calls=None) -> dict:
    alpha = config.get("alpha", prior.ALPHA)
    version = config.get("attack_version", "18.1")
    out: dict = {"alpha": alpha, "attack_version": version, "priors": {}}
    for actor, info in load_actors().items():
        counts, meta = prior.attk_counts(info["attack_group"], version)
        written = {}
        for cond, matrix, m in (
            ("ATTK", prior.from_counts(counts, alpha), {**meta, "condition": "ATTK", "alpha": alpha}),
            ("Uni", prior.uniform(), {"condition": "Uni"}),
        ):
            path = PRIORS / actor / f"{cond}.json"
            prior.save(path, matrix, {**m, "actor": actor})
            written[cond] = {"path": str(path.relative_to(REPO_ROOT)),
                             "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        out["priors"][actor] = {**written, "n_techniques": meta["n_techniques"],
                                "tactic_counts": meta["tactic_counts"]}
    return out
