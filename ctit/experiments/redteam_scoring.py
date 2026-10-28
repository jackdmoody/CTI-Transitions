"""Case study B (spec §5, §7 T9; SPEC_ISSUES 2026-10-27): hunting on the OpTC red-team test set.

Test set: data/eval/optc_redteam_windows.parquet (redteam_testset; 29 targets, benign 19-22 Sep
and attack 23-25 Sep, windows of 8 tagged events, positive = contains a labelled-malicious
event). Mapper v3 throughout.
- K = the tactics v3 can emit (each rule's primary tactic), fixed by the frozen rule set.
- P_ben: pooled tactic-transition counts over the fit hosts (configs/optc_split.yaml), benign
  days 19-22 Sep, each host's tagged events in time order over all its days (DRIFT ingest
  semantics: untagged events skipped), + alpha over K x K, row-normalized. Cached to
  data/eval/optc_fit_transitions_v3.json.
- LR conditions (Uni, ATTK, R, oracle): mean log-LR per transition, P_adv = prior projected onto
  K (ctit.cti.prior.project). lambda = 0 (no mixing with P_ben): the validation hosts have no
  attack windows, so lambda can't be tuned there, and the test split is never used for tuning.
- U: JSD between a window's (counts + alpha) edge distribution over K x K and the mean of the
  fit hosts' distributions (hosts with >= BRIMS_MIN_TRANSITIONS transitions).
Metrics: AUPRC, AUROC, Det@1%FPR (threshold = 99th percentile of the negative windows' scores,
detected if strictly above), TTD (per attacked host: index of the first positive window above
that threshold among its positive windows in time order / their number, 1 if none; mean over
hosts). Conditions with several samples (F, S-sampled): the metric is averaged over samples.
95% CIs: host-cluster bootstrap (hosts resampled with replacement), percentile intervals.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from ctit.adapters.drift import BRIMS_MIN_TRANSITIONS, observational
from ctit.cti import prior
from ctit.eval import optc_redteam, optc_split
from ctit.experiments import redteam_testset
from ctit.map import v3
from ctit.map.attack import TACTICS

REPO_ROOT = Path(__file__).resolve().parents[2]
WINDOWS = REPO_ROOT / "data" / "eval" / "optc_redteam_windows.parquet"
FIT_CACHE = REPO_ROOT / "data" / "eval" / "optc_fit_transitions_v3.json"
PRIORS = REPO_ROOT / "data" / "priors"


def reachable(rules: list[dict]) -> list[str]:
    emitted = {r["tactics"][0] for r in rules}
    return [t for t in TACTICS if t in emitted]


def _fit_host(args) -> tuple[str, dict]:
    host, drop = args if isinstance(args, tuple) else (args, ())
    labels0 = optc_redteam.load_labels().iloc[:0]
    parts = []
    for day in optc_split.BENIGN_DAYS:
        if redteam_testset._path(day, host).exists():
            _, t, _ = redteam_testset._host_day((day, host, labels0))
            parts.append(t.loc[~t["rule_id"].isin(drop), ["_timestamp", "tactic"]])
    seq = pd.concat(parts).sort_values("_timestamp", kind="stable")["tactic"].tolist() if parts else []
    return host, {f"{a}|{b}": n for (a, b), n in Counter(zip(seq, seq[1:])).items()}


def fit_counts(hosts: list[str], workers: int, drop: tuple[str, ...] = (), cache: Path = FIT_CACHE) -> dict[str, dict]:
    """host -> {"from|to": count}, cached for this host list and the frozen v3 rule file. `drop`:
    rule ids whose tags are removed before transitions are counted (diagnosis, post hoc)."""
    key = hashlib.sha256((v3.RULES_V3.read_bytes() + ",".join(hosts).encode()
                          + (("|drop:" + ",".join(drop)).encode() if drop else b""))).hexdigest()
    if cache.exists():
        c = json.loads(cache.read_text())
        if c["key"] == key:
            return c["hosts"]
    with ProcessPoolExecutor(workers) as ex:
        out = dict(ex.map(_fit_host, [(h, tuple(drop)) for h in hosts]))
    cache.write_text(json.dumps({"key": key, "hosts": out}))
    return out


def matrix(counts: dict, K: list[str]) -> np.ndarray:
    idx = {t: i for i, t in enumerate(K)}
    M = np.zeros((len(K), len(K)))
    for e, n in counts.items():
        a, b = e.split("|")
        M[idx[a], idx[b]] += n
    return M


def lr_scores(seqs: np.ndarray, P_adv: np.ndarray, P_ben: np.ndarray) -> np.ndarray:
    a, b = seqs[:, :-1], seqs[:, 1:]
    return (np.log(P_adv[a, b]) - np.log(P_ben[a, b])).mean(axis=1)


def u_scores(seqs: np.ndarray, base: np.ndarray, alpha: float) -> np.ndarray:
    n = int(np.sqrt(base.size))
    C = np.zeros((len(seqs), n * n))
    for j in range(seqs.shape[1] - 1):
        np.add.at(C, (np.arange(len(seqs)), seqs[:, j] * n + seqs[:, j + 1]), 1)
    V = (C + alpha) / (C + alpha).sum(axis=1, keepdims=True)
    return np.array([observational.jsd(v, base) for v in V])


def metrics(score: np.ndarray, y: np.ndarray, host: np.ndarray) -> dict:
    thr = np.quantile(score[~y], 0.99)
    det = score > thr
    ttd = []
    for h in np.unique(host[y]):  # windows are in time order within a host
        d = det[(host == h) & y]
        ttd.append(np.argmax(d) / len(d) if d.any() else 1.0)
    return {"auprc": float(average_precision_score(y, score)), "auroc": float(roc_auc_score(y, score)),
            "det_1fpr": float(det[y].mean()), "fpr_actual": float(det[~y].mean()), "ttd": float(np.mean(ttd))}


def _priors(config: dict, K: list[str]) -> dict[str, list[np.ndarray]]:
    """condition -> P_adv per sample, projected onto K."""
    out = {"Uni": [prior.project(prior.uniform(), K)]}
    for a in config["actors"]:
        out[f"ATTK/{a}"] = [prior.project(prior.load(PRIORS / a / "ATTK.json")[0], K)]
    for mode, run in config["runs"].items():
        label = {"F": "F", "S": "S", "S-sampled": "S-sampled"}[mode]
        for cond, actors in (("R", config["actors"]), ("oracle", ["OpTC-redteam"])):
            if cond == "oracle" and mode not in config["oracle_modes"]:
                continue
            for a in actors:
                files = sorted((PRIORS / run / mode).glob(f"{cond}_{a}_*.json"))
                if files:
                    name = f"{cond}-{label}" + ("" if cond == "oracle" else f"/{a}")
                    out[name] = [prior.project(np.array(json.loads(f.read_text())["matrix"]), K) for f in files]
    return out


def baseline(fit: dict[str, dict], K: list[str], alpha: float) -> dict:
    """P_ben (pooled, row-normalized) and U's baseline mean edge distribution from fit-host counts."""
    pooled = sum((matrix(c, K) for c in fit.values()), np.zeros((len(K), len(K))))
    vecs = [(m + alpha) / (m + alpha).sum() for m in (matrix(c, K).ravel() for c in fit.values())
            if m.sum() >= BRIMS_MIN_TRANSITIONS]
    return {"P_ben": (pooled + alpha) / (pooled + alpha).sum(axis=1, keepdims=True),
            "base": np.mean(vecs, axis=0), "pooled": pooled, "u_hosts": len(vecs)}


def evaluate(scores: dict[str, list[np.ndarray]], y: np.ndarray, host: np.ndarray, n_boot: int,
             rng: np.random.Generator) -> tuple[dict, int]:
    """Point metrics (mean over a condition's samples) and host-cluster bootstrap 95% CIs."""
    point = {c: {k: float(np.mean([metrics(s, y, host)[k] for s in ss])) for k in
                 ("auprc", "auroc", "det_1fpr", "fpr_actual", "ttd")} for c, ss in scores.items()}
    per_sample = {c: [metrics(s, y, host) for s in ss] for c, ss in scores.items() if len(ss) > 1}
    hosts = np.unique(host)
    rows = {h: np.flatnonzero(host == h) for h in hosts}
    boot: dict[str, list[dict]] = {c: [] for c in scores}
    skipped = 0
    for _ in range(n_boot):
        pick = rng.choice(hosts, size=len(hosts), replace=True)
        idx = np.concatenate([rows[h] for h in pick])
        # a host drawn twice is relabelled so its windows count as a separate cluster in TTD
        hb = np.concatenate([np.full(len(rows[h]), f"{h}#{i}") for i, h in enumerate(pick)])
        if y[idx].all() or not y[idx].any():
            skipped += 1
            continue
        for c, ss in scores.items():
            ms = [metrics(s[idx], y[idx], hb) for s in ss]
            boot[c].append({k: np.mean([m[k] for m in ms]) for k in ms[0]})
    ci = {c: {k: [float(np.percentile([b[k] for b in bs], 2.5)), float(np.percentile([b[k] for b in bs], 97.5))]
              for k in ("auprc", "auroc", "det_1fpr", "ttd")} for c, bs in boot.items()}
    return {c: {"point": point[c], "ci95": ci[c], "samples": len(scores[c]),
                **({"per_sample": per_sample[c]} if c in per_sample else {})} for c in scores}, skipped


def run(config: dict, calls=None) -> dict:
    alpha, rng = config["alpha"], np.random.default_rng(config["bootstrap"]["seed"])
    K = reachable(v3.load_v3())
    ki = {t: i for i, t in enumerate(K)}
    win = pd.read_parquet(WINDOWS).sort_values(["host", "start"], kind="stable").reset_index(drop=True)
    seqs = np.array([[ki[t] for t in ts] for ts in win["tactics"]])
    y, host = win["positive"].to_numpy(bool), win["host"].to_numpy()

    fit = fit_counts(optc_split.load_split()["fit"], config.get("workers", 4))
    b = baseline(fit, K, alpha)
    scores = {"U": [u_scores(seqs, b["base"], alpha)]}
    for name, Ps in _priors(config, K).items():
        scores[name] = [lr_scores(seqs, P, b["P_ben"]) for P in Ps]
    conditions, skipped = evaluate(scores, y, host, config["bootstrap"]["n"], rng)
    return {
        "K": K, "alpha": alpha, "lambda": 0.0, "windows": int(len(win)), "positive": int(y.sum()),
        "base_rate": float(y.mean()), "hosts": int(len(np.unique(host))), "attacked_hosts": int(len(np.unique(host[y]))),
        "fit_hosts": len(fit), "fit_transitions": int(b["pooled"].sum()), "u_baseline_hosts": b["u_hosts"],
        "bootstrap": {**config["bootstrap"], "skipped_resamples": skipped},
        "conditions": conditions,
        "oracle_F": "refused (5/5)",
    }
