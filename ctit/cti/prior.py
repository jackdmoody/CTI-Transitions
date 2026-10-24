"""Tactic-transition priors (spec §3, §4, §5).

A prior is a row-stochastic matrix over the 14 Enterprise tactics (ctit.map.attack.TACTICS),
P[i, j] = P(next tactic j | current tactic i). Stored as JSON:
  {"tactics": [...], "matrix": [[...]], "meta": {...}}
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from ctit.map import attack

TACTICS = attack.TACTICS
INDEX = {t: i for i, t in enumerate(TACTICS)}
ALPHA = 0.5  # spec §4


def from_counts(counts: np.ndarray, alpha: float = ALPHA) -> np.ndarray:
    """Row-normalized (C + alpha)."""
    c = np.asarray(counts, dtype=float) + alpha
    return c / c.sum(axis=1, keepdims=True)


def uniform(n: int = len(TACTICS)) -> np.ndarray:
    """Uni condition: every transition equally likely."""
    return np.full((n, n), 1.0 / n)


def attk_counts(group_id: str, version: str = "18.1") -> tuple[np.ndarray, dict]:
    """ATTK baseline (spec §3): the group's ATT&CK technique set -> tactic co-occurrence.

    No order: n_t = number of the group's techniques under tactic t (a multi-tactic
    technique counts once under each), and C[i, j] = n_i * n_j. After row-normalization,
    every row is the group's tactic-frequency profile. Uses only direct intrusion-set
    "uses" attack-pattern relationships (not techniques reached via software).
    """
    objs = attack._bundle(version)
    group = next(o for o in objs if o["type"] == "intrusion-set" and attack._ext_id(o) == group_id.upper())
    patterns = {o["id"]: o for o in objs if o["type"] == "attack-pattern"
                and not o.get("revoked") and not o.get("x_mitre_deprecated")}
    techniques = sorted({
        attack._ext_id(patterns[r["target_ref"]]) for r in objs
        if r["type"] == "relationship" and r.get("relationship_type") == "uses"
        and r["source_ref"] == group["id"] and r["target_ref"] in patterns
        and not r.get("revoked") and not r.get("x_mitre_deprecated")
    })
    n = np.zeros(len(TACTICS))
    for tid in techniques:
        for t in attack.technique_tactics(tid):
            n[INDEX[t]] += 1
    meta = {"group_id": group_id, "group_name": group["name"], "attack_version": version,
            "n_techniques": len(techniques), "tactic_counts": dict(zip(TACTICS, n.astype(int).tolist()))}
    return np.outer(n, n), meta


def project(P: np.ndarray, keep: list[str], tactics: list[str] = TACTICS) -> np.ndarray:
    """Project a transition matrix onto the observable tactics `keep` (spec §5).

    Unobservable tactics are skipped, as DRIFT skips unmapped events: from an observable
    tactic the chain may pass through any number of unobservable ones before the next
    observable one. Absorbing-chain marginalization:
        T_obs = T_KK + T_KU (I - T_UU)^-1 T_UK
    Rows of T_obs sum to 1 whenever every unobservable state can reach K (true for any
    alpha > 0 prior).
    """
    k = [tactics.index(t) for t in keep]
    u = [i for i in range(len(tactics)) if i not in k]
    P = np.asarray(P, dtype=float)
    T_KK, T_KU, T_UK, T_UU = P[np.ix_(k, k)], P[np.ix_(k, u)], P[np.ix_(u, k)], P[np.ix_(u, u)]
    if not u:
        return T_KK.copy()
    return T_KK + T_KU @ np.linalg.solve(np.eye(len(u)) - T_UU, T_UK)


def save(path: Path, matrix: np.ndarray, meta: dict, tactics: list[str] = TACTICS) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps({"tactics": list(tactics), "matrix": np.asarray(matrix).tolist(),
                                      "meta": meta}, indent=1) + "\n")


def load(path: Path) -> tuple[np.ndarray, list[str], dict]:
    d = json.loads(Path(path).read_text())
    return np.array(d["matrix"]), d["tactics"], d["meta"]
