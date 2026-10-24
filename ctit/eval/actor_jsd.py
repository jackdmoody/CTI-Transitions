"""WP5 gate: actor ground-truth transition matrices and their pairwise JSD (spec §2.5, H4).

A sequence set (one list per scenario) gives counts C[a, b] of consecutive tactic pairs
within a scenario. Projecting onto K drops tactics outside K, so transitions skip over
them, as DRIFT skips unmapped events. Each actor's matrix is turned into a joint edge
distribution (C + alpha), normalized over all K x K cells as DRIFT's vectors are, and actors
are compared by JSD (natural log, in [0, ln 2]; observational.score.jsd).
"""
from __future__ import annotations

from itertools import combinations

import numpy as np

from ctit.adapters.drift import observational


def project_sequences(seqs: list[list[str]], keep: list[str]) -> list[list[str]]:
    k = set(keep)
    return [[t for t in s if t in k] for s in seqs]


def counts(seqs: list[list[str]], alphabet: list[str]) -> np.ndarray:
    idx = {t: i for i, t in enumerate(alphabet)}
    C = np.zeros((len(alphabet), len(alphabet)))
    for s in seqs:
        for a, b in zip(s[:-1], s[1:]):
            C[idx[a], idx[b]] += 1
    return C


def edge_distribution(C: np.ndarray, alpha: float) -> np.ndarray:
    v = (C + alpha).ravel()
    return v / v.sum()


def pairwise(seqs_by_actor: dict[str, list[list[str]]], alphabet: list[str], alpha: float) -> dict:
    mats = {a: counts(s, alphabet) for a, s in seqs_by_actor.items()}
    out = {"alphabet": alphabet, "alpha": alpha,
           "n_transitions": {a: int(m.sum()) for a, m in mats.items()},
           "tactics_present": {a: [alphabet[i] for i in np.nonzero(m.sum(0) + m.sum(1))[0]] for a, m in mats.items()},
           "jsd": {}}
    for a, b in combinations(sorted(mats), 2):
        if mats[a].sum() == 0 or mats[b].sum() == 0:
            out["jsd"][f"{a}|{b}"] = None
            continue
        pa, pb = edge_distribution(mats[a], alpha), edge_distribution(mats[b], alpha)
        out["jsd"][f"{a}|{b}"] = observational.jsd(pa, pb)
    return out
