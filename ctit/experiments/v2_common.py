"""Shared helpers for the v2 analyses (POST HOC, 2026-10-31; Jack's final coding pass). No model calls.

Every v2 experiment reads its model list from config, as a `priors` map of label -> {run, mode}
(the saved priors under data/priors/<run>/<mode>/<cond>_<actor>_<sample>.json), so a model is
added by adding a line to the config and rerunning, with no code change.

- load(): the saved priors of one label, per condition and actor, one entry per sample.
- report_edges(): per sample, per report, the binary edge matrix the report supports, so a
  report-level resample rebuilds Eq. 1's counts (each edge once per report) by summation.
- ChanceTable: the shared chance draw of paper table a (`draws` random orderings of the 182
  off-diagonal cells, drawn once with one seed); the chance mean depends only on the edge-set
  size k and the truth, so it is tabulated per k.
- plan_pairs(): each plan's collapsed transitions with multiplicity, in plan order (scenario by
  scenario), as ctit.experiments.prior_likelihood.
"""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np

from ctit.cti import manifest, prior
from ctit.cti.manifest import load_actors
from ctit.eval import plans, recovery
from ctit.experiments.extraction import PRIORS, REPO_ROOT
from ctit.experiments.paper_tables import chance_orderings
from ctit.experiments.prior_likelihood import pairs
from ctit.experiments.redteam_scoring import run_dir
from ctit.map.attack import TACTICS

N = len(TACTICS)


def prior_dir(spec) -> Path:
    run, sub = run_dir(spec)
    return PRIORS / run / sub


def load(spec, cond: str, actor: str) -> list[dict]:
    """Saved prior JSONs (counts, transitions, chunks) of one label, condition and actor, by sample."""
    return [json.loads(f.read_text()) for f in sorted(prior_dir(spec).glob(f"{cond}_{actor}_*.json"))]


def counts(spec, cond: str, actor: str) -> list[np.ndarray]:
    return [np.array(d["counts"], dtype=float) for d in load(spec, cond, actor)]


def family_counts(config: dict, name: str, actor: str) -> list[np.ndarray]:
    """'<cond>-<label>' (e.g. R-F, B-Q), 'ATTK' or 'Uni' -> count matrices, one per sample."""
    if name == "ATTK":
        return [prior.attk_counts(load_actors()[actor]["attack_group"])[0]]
    if name == "Uni":
        return [np.zeros((N, N))]
    cond, label = name.split("-", 1)
    return counts(config["priors"][label], cond, actor)


def prior_reports(actor: str) -> list[str]:
    """The actor's prior documents (manifest rows used_for=prior), sorted."""
    _, rows = manifest.load()
    return sorted(r["doc_id"] for r in rows if r["actor"] == actor and r["used_for"] == "prior")


def report_edges(d: dict, reports: list[str]) -> np.ndarray:
    """(n_reports, 14, 14) binary: the edges each report supports in one saved prior."""
    E = np.zeros((len(reports), N, N))
    pos = {r: i for i, r in enumerate(reports)}
    for t in d["transitions"]:
        E[pos[t["doc_id"]], prior.INDEX[t["from_tactic"]], prior.INDEX[t["to_tactic"]]] = 1
    if not np.array_equal(E.sum(axis=0), np.array(d["counts"])):
        raise RuntimeError(f"per-report edges do not rebuild the saved counts ({d['meta']['mode']} {d['meta']['actor']})")
    return E


class ChanceTable:
    """Chance edge-F1 for every edge-set size k against one truth, from the shared orderings."""

    def __init__(self, truth: np.ndarray, order: np.ndarray):
        t = ((truth > 0) & recovery.OFF_DIAG)[recovery.OFF_DIAG]
        self.g = int(t.sum())
        hits = np.cumsum(t[order], axis=1)  # draws x 182: true positives among the first k cells
        k = np.arange(1, recovery.N_OFF + 1)
        self.f1 = 2 * hits / (k + self.g)  # draws x k
        self.mean = np.concatenate([[0.0], self.f1.mean(axis=0)])  # index by k

    def ratio(self, f1: float, k: int) -> float | None:
        return f1 / self.mean[k] if self.mean[k] > 0 else None

    def percentile(self, f1: float, k: int) -> float:
        c = self.f1[:, k - 1] if k > 0 else np.zeros(len(self.f1))
        return float(100 * ((c < f1).mean() + 0.5 * (c == f1).mean()))


def shared_chance(config: dict) -> np.ndarray:
    ch = config["chance"]
    return chance_orderings(ch["draws"], ch["seed"])


def f1_k(C: np.ndarray, G: np.ndarray) -> tuple[float, int]:
    r = recovery.edge_prf(C, G)
    return r["f1"], r["edges_extracted"]


def plan_pairs(actor: str) -> np.ndarray:
    return pairs([recovery.collapse(s) for s in plans.sequences(plans.load_plan(actor, platforms=None))])


def status(lo: float, hi: float) -> str:
    """'above' (interval above zero), 'below' or 'spans'."""
    return "above" if lo > 0 else "below" if hi < 0 else "spans"


def results_root() -> Path:
    return REPO_ROOT / "results"
