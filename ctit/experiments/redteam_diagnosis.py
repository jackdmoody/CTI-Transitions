"""Case study B diagnosis (POST HOC, 2026-10-27, SPEC_ISSUES): why ATTK leads and why U is inverted.

Diagnostics, not tuning: every analysis below is run and reported, nothing is selected from them,
and the case study B numbers (redteam_scoring) stand as reported. Same test set, K, P_ben, alpha,
lambda = 0, metrics and host-cluster bootstrap as redteam_scoring.
 a. How ATTK is built for scoring; mean row entropy (bits) of every prior as used (projected onto K).
 b. Score decomposition for <prior> - Uni: each transition's summed log P_prior - log P_Uni (/ 7,
    its share of the window score) over positive and over negative windows; top 10 each. Tactic
    and Sigma-rule composition of positive vs. negative windows.
 c. Controls: (1) ATTK's edge set, uniform weights at ATTK's count scale; (2) destination-tactic
    frequency only (every row = the group's tactic profile n); (3) actor-agnostic ATTK from all
    ATT&CK 18.1 groups' technique-tactic counts, built as ATTK; (4) R priors at alpha 0.01, 0.1.
 d. Scripted job removed: (i) windows on xx01/xx51 hosts dropped; (ii) tags of the two scripted-
    job rules dropped from the test events and from the fit baseline, windows rebuilt.
 e. Positive windows per attacked host; leave-one-host-out AUPRC for ATTK, Uni and U.
 f. U: per-edge JSD contributions over positive vs. negative windows, and U under d(i), d(ii).
Test-window events with rule ids are cached in data/eval/optc_redteam_tagged.parquet (rebuilt
with redteam_testset._host_day; the windows are checked against optc_redteam_windows.parquet).
"""
from __future__ import annotations

import json
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import numpy as np
import pandas as pd
import yaml
from sklearn.metrics import average_precision_score

from ctit.cti import prior
from ctit.cti.manifest import load_actors
from ctit.eval import optc_redteam, optc_split
from ctit.experiments import redteam_scoring as rs
from ctit.experiments import redteam_testset
from ctit.map import attack, v3
from ctit.map.attack import TACTICS

REPO_ROOT = Path(__file__).resolve().parents[2]
TAGGED = REPO_ROOT / "data" / "eval" / "optc_redteam_tagged.parquet"
FIT_NOSCRIPT = REPO_ROOT / "data" / "eval" / "optc_fit_transitions_v3_noscript.json"


# ----------------------------------------------------------------------------- data

def test_tagged(workers: int) -> pd.DataFrame:
    """Every tagged event of the test set (benign and attack days), with rule id and label."""
    if TAGGED.exists():
        return pd.read_parquet(TAGGED)
    cfg = yaml.safe_load(optc_split.REDTEAM.read_text())
    labels = optc_redteam.load_labels()
    jobs = []
    for h in (optc_split.host_id(x) for x in cfg["targets"]):
        lab = labels[labels["host"] == h].reset_index(drop=True)
        for day in optc_split.BENIGN_DAYS + optc_redteam.ATTACK_DAYS:
            if redteam_testset._path(day, h).exists():
                jobs.append((day, h, lab if day in optc_redteam.ATTACK_DAYS else lab.iloc[:0]))
    with ProcessPoolExecutor(workers) as ex:
        tg = pd.concat([t for _, t, _ in ex.map(redteam_testset._host_day, jobs)], ignore_index=True)
    tg.to_parquet(TAGGED, index=False)
    return tg


def windows(tagged: pd.DataFrame, size: int = optc_redteam.WINDOW) -> pd.DataFrame:
    """As ctit.eval.optc_redteam.windows (same order and cut), keeping each event's rule id."""
    rows = []
    for host, g in tagged.sort_values(["Hostname", "_timestamp"], kind="stable").groupby("Hostname", sort=True):
        for i in range(0, len(g) - size + 1, size):
            w = g.iloc[i:i + size]
            rows.append({"host": host, "start": w["_timestamp"].iloc[0], "tactics": list(w["tactic"]),
                         "rules": list(w["rule_id"]), "positive": bool(w["malicious"].any())})
    return pd.DataFrame(rows)


# ----------------------------------------------------------------------------- priors

def attk_all_tactic_counts(version: str = "18.1") -> np.ndarray:
    """Actor-agnostic n: summed over every ATT&CK group, each group's techniques counted per
    tactic exactly as prior.attk_counts does for one group."""
    objs = attack._bundle(version)
    patterns = {o["id"]: o for o in objs if o["type"] == "attack-pattern"
                and not o.get("revoked") and not o.get("x_mitre_deprecated")}
    groups = {o["id"] for o in objs if o["type"] == "intrusion-set"
              and not o.get("revoked") and not o.get("x_mitre_deprecated")}
    uses: dict[str, set] = {}
    for r in objs:
        if (r["type"] == "relationship" and r.get("relationship_type") == "uses" and r["source_ref"] in groups
                and r["target_ref"] in patterns and not r.get("revoked") and not r.get("x_mitre_deprecated")):
            uses.setdefault(r["source_ref"], set()).add(attack._ext_id(patterns[r["target_ref"]]))
    n = np.zeros(len(TACTICS))
    for techniques in uses.values():
        for tid in techniques:
            for t in attack.technique_tactics(tid):
                n[TACTICS.index(t)] += 1
    return n


def entropy_bits(P: np.ndarray) -> float:
    """Mean row entropy (bits) of a row-stochastic matrix."""
    return float(np.mean(-(P * np.log2(np.where(P > 0, P, 1))).sum(axis=1)))


def counts_files(config: dict) -> dict[str, list[np.ndarray]]:
    """'R-<mode>/<actor>' and 'oracle-<mode>' -> raw count matrices per sample (14 x 14)."""
    out = {}
    for mode, run in config["runs"].items():
        for cond, actors in (("R", config["actors"]), ("oracle", ["OpTC-redteam"])):
            if cond == "oracle" and mode not in config.get("oracle_modes", []):
                continue
            for a in actors:
                files = sorted((rs.PRIORS / run / mode).glob(f"{cond}_{a}_*.json"))
                if files:
                    out[f"{cond}-{mode}" + ("" if cond == "oracle" else f"/{a}")] = \
                        [np.array(json.loads(f.read_text())["counts"]) for f in files]
    return out


# ----------------------------------------------------------------------------- analyses

def decompose(seqs: np.ndarray, y: np.ndarray, d: np.ndarray, K: list[str], top: int = 10) -> dict:
    """d = log P_prior - log P_Uni (K x K). Each transition's share of the window score
    (d / number of transitions per window), summed over positive and over negative windows."""
    n_t = seqs.shape[1] - 1
    out = {}
    for label, sel in (("positive", y), ("negative", ~y)):
        C = np.zeros_like(d)
        np.add.at(C, (seqs[sel, :-1].ravel(), seqs[sel, 1:].ravel()), 1)
        contrib = C * d / n_t
        order = np.argsort(-np.abs(contrib).ravel())[:top]
        out[label] = {"windows": int(sel.sum()), "total": float(contrib.sum()),
                      "per_window": float(contrib.sum() / max(sel.sum(), 1)),
                      "top": [{"transition": f"{K[i // len(K)]} -> {K[i % len(K)]}",
                               "count": int(C.ravel()[i]), "log_ratio": float(d.ravel()[i]),
                               "sum": float(contrib.ravel()[i]),
                               "per_window": float(contrib.ravel()[i] / max(sel.sum(), 1))} for i in order]}
    return out


def composition(win: pd.DataFrame, titles: dict, tactic_of: dict, top: int = 12) -> dict:
    out = {}
    for label, sel in (("positive", win["positive"]), ("negative", ~win["positive"])):
        tac = pd.Series([t for ts in win.loc[sel, "tactics"] for t in ts]).value_counts(normalize=True)
        rules = pd.Series([r for rr in win.loc[sel, "rules"] for r in rr]).value_counts()
        out[label] = {"tactic_share": {k: round(float(v), 4) for k, v in tac.items()},
                      "rules": [{"rule": titles.get(r, r), "tactic": tactic_of.get(r), "tokens": int(n)}
                                for r, n in rules.head(top).items()]}
    return out


def u_contrib(seqs: np.ndarray, y: np.ndarray, base: np.ndarray, alpha: float, K: list[str], top: int = 10) -> dict:
    """Per-edge JSD terms: JSD(p, q) = sum_e [p_e log(p_e/m_e) + q_e log(q_e/m_e)] / 2."""
    n = len(K)
    C = np.zeros((len(seqs), n * n))
    for j in range(seqs.shape[1] - 1):
        np.add.at(C, (np.arange(len(seqs)), seqs[:, j] * n + seqs[:, j + 1]), 1)
    P = (C + alpha) / (C + alpha).sum(axis=1, keepdims=True)
    M = (P + base) / 2
    T = 0.5 * (P * np.log(P / M) + base * np.log(base / M))
    pos, neg = T[y].mean(axis=0), T[~y].mean(axis=0)
    name = lambda i: f"{K[i // n]} -> {K[i % n]}"
    diff = neg - pos
    return {"baseline_top_edges": [{"edge": name(i), "p": float(base[i])} for i in np.argsort(-base)[:top]],
            "mean_u": {"positive": float(T[y].sum(axis=1).mean()), "negative": float(T[~y].sum(axis=1).mean())},
            "top_positive": [{"edge": name(i), "per_window": float(pos[i])} for i in np.argsort(-pos)[:top]],
            "top_negative": [{"edge": name(i), "per_window": float(neg[i])} for i in np.argsort(-neg)[:top]],
            "top_neg_minus_pos": [{"edge": name(i), "neg_minus_pos": float(diff[i]),
                                   "share_windows_with_edge_pos": float((C[y][:, i] > 0).mean()),
                                   "share_windows_with_edge_neg": float((C[~y][:, i] > 0).mean())}
                                  for i in np.argsort(-np.abs(diff))[:top]]}


def scripted(host: str) -> bool:
    return int(host[-4:]) % 50 == 1  # xx01 / xx51


def _eval(scores: dict, y: np.ndarray, host: np.ndarray, n_boot: int, seed: int) -> dict:
    return rs.evaluate(scores, y, host, n_boot, np.random.default_rng(seed))[0]


def _lead(conds: dict) -> dict:
    """Does ATTK still lead (best ATTK AUPRC vs. best of Uni / R / oracle), is U still inverted?"""
    ap = {c: v["point"]["auprc"] for c, v in conds.items()}
    attk = max((v, c) for c, v in ap.items() if c.startswith("ATTK/"))
    rest = max((v, c) for c, v in ap.items() if c == "Uni" or c.startswith(("R-", "oracle-")))
    return {"best_attk": {"condition": attk[1], "auprc": attk[0]},
            "best_uni_r_oracle": {"condition": rest[1], "auprc": rest[0]},
            "attk_leads": attk[0] > rest[0], "u_auroc": conds["U"]["point"]["auroc"],
            "u_inverted": conds["U"]["point"]["auroc"] < 0.5}


def run(config: dict, calls=None) -> dict:
    alpha, n_boot, seed = config["alpha"], config["bootstrap"]["n"], config["bootstrap"]["seed"]
    rules = v3.load_v3()
    titles = {r["id"]: r["title"] for r in rules}
    tactic_of = {r["id"]: r["tactics"][0] for r in rules}
    K = rs.reachable(rules)
    ki = {t: i for i, t in enumerate(K)}
    drop = tuple(config["scripted_rules"])
    groups = {a: v["attack_group"] for a, v in load_actors().items()}
    workers = config.get("workers", 3)
    proj = lambda C, al: prior.project(prior.from_counts(C, al), K)
    seq_of = lambda w: np.array([[ki[t] for t in ts] for ts in w["tactics"]])

    tagged = test_tagged(workers)
    win = windows(tagged)
    saved = pd.read_parquet(rs.WINDOWS)
    if not (len(win) == len(saved) and all(list(a) == list(b) for a, b in zip(win["tactics"], saved["tactics"]))
            and (win["positive"].to_numpy() == saved["positive"].to_numpy()).all()):
        raise RuntimeError("rebuilt windows differ from optc_redteam_windows.parquet")
    seqs, y, host = seq_of(win), win["positive"].to_numpy(bool), win["host"].to_numpy()
    fit_hosts = optc_split.load_split()["fit"]
    b = rs.baseline(rs.fit_counts(fit_hosts, workers), K, alpha)
    b2 = rs.baseline(rs.fit_counts(fit_hosts, workers, drop=drop, cache=FIT_NOSCRIPT), K, alpha)

    main = rs._priors(config, K)  # Uni, ATTK/<actor>, R-<mode>/<actor>, oracle-<mode>
    raw = counts_files(config)
    attk = {a: prior.attk_counts(groups[a])[0] for a in config["actors"]}
    out: dict = {"note": "POST HOC diagnosis (2026-10-27): every analysis is reported; nothing is selected from it",
                 "K": K, "alpha": alpha}

    # a. ATTK as built; row entropy of every prior as used; share of each row's mass that is alpha
    alpha_share = lambda C: float(np.mean(len(TACTICS) * alpha / (C.sum(axis=1) + len(TACTICS) * alpha)))
    out["a_attk_build"] = {a: {"tactic_counts_n": dict(zip(TACTICS, prior.attk_counts(groups[a])[1]["tactic_counts"].values())),
                               "count_max": float(C.max()), "count_mean_nonzero": float(C[C > 0].mean()),
                               "row_mass_alpha_share": alpha_share(C)} for a, C in attk.items()}
    out["a_row_mass_alpha_share"] = {n: float(np.mean([alpha_share(C) for C in Cs])) for n, Cs in raw.items()}
    out["a_entropy_bits"] = {n: float(np.mean([entropy_bits(P) for P in Ps])) for n, Ps in main.items()}
    out["a_entropy_bits"]["P_ben"] = entropy_bits(b["P_ben"])
    out["a_entropy_max_bits"] = float(np.log2(len(K)))

    # b. decomposition vs. Uni, and window composition
    logU = np.log(main["Uni"][0])
    out["b_decomposition"] = {n: decompose(seqs, y, np.mean([np.log(P) for P in Ps], axis=0) - logU, K)
                              for n, Ps in main.items() if n != "Uni"}
    out["b_composition"] = composition(win, titles, tactic_of)

    # c. controls, scored with the reference conditions
    ctrl = {}
    for a, C in attk.items():
        ctrl[f"c1_edgeset_uniform/{a}"] = [proj((C > 0) * C[C > 0].mean(), alpha)]
        n = np.sqrt(np.diag(C))  # C = n n^T
        ctrl[f"c2_destination_only/{a}"] = [proj(np.outer(np.full(len(n), n.mean()), n), alpha)]
    n_all = attk_all_tactic_counts()
    ctrl["c3_all_groups"] = [proj(np.outer(n_all, n_all), alpha)]
    for n, Cs in raw.items():
        if n.startswith("R-"):
            for al in config["alphas"]:
                ctrl[f"c4_alpha{al}/{n}"] = [proj(C, al) for C in Cs]
    scores = {"U": [rs.u_scores(seqs, b["base"], alpha)]}
    scores.update({n: [rs.lr_scores(seqs, P, b["P_ben"]) for P in Ps] for n, Ps in {**main, **ctrl}.items()})
    out["c_all_groups_tactic_counts"] = dict(zip(TACTICS, n_all.astype(int).tolist()))
    out["c_entropy_bits"] = {n: float(np.mean([entropy_bits(P) for P in Ps])) for n, Ps in ctrl.items()}
    out["c_controls"] = _eval(scores, y, host, n_boot, seed)

    # d. scripted job removed
    base_scores = {n: v for n, v in scores.items() if n == "U" or n in main}
    keep = ~np.array([scripted(h) for h in host])
    sub = {n: [s[keep] for s in ss] for n, ss in base_scores.items()}
    d1 = _eval(sub, y[keep], host[keep], n_boot, seed)
    win2 = windows(tagged[~tagged["rule_id"].isin(drop)])
    seqs2, y2, host2 = seq_of(win2), win2["positive"].to_numpy(bool), win2["host"].to_numpy()
    sc2 = {"U": [rs.u_scores(seqs2, b2["base"], alpha)]}
    sc2.update({n: [rs.lr_scores(seqs2, P, b2["P_ben"]) for P in Ps] for n, Ps in main.items()})
    d2 = _eval(sc2, y2, host2, n_boot, seed)
    out["d_scripted_removed"] = {
        "primary": {"windows": int(len(y)), "positive": int(y.sum()), **_lead(out["c_controls"])},
        "i_drop_xx01_xx51_hosts": {"hosts_dropped": sorted({h for h in host if scripted(h)}),
                                   "windows": int(keep.sum()), "positive": int(y[keep].sum()), **_lead(d1), "conditions": d1},
        "ii_drop_scripted_rule_tags": {"rules": [titles[r] for r in drop], "windows": int(len(y2)),
                                       "positive": int(y2.sum()), "fit_transitions": int(b2["pooled"].sum()),
                                       **_lead(d2), "conditions": d2}}

    # e. per host
    pos_by_host = pd.Series(host[y]).value_counts().sort_index()
    loho = {}
    for h in np.unique(host):
        m = host != h
        if y[m].any():
            loho[h] = {n: float(average_precision_score(y[m], np.mean([s[m] for s in scores[n]], axis=0)))
                       for n in ["U", "Uni"] + [f"ATTK/{a}" for a in config["actors"]]}
    out["e_positive_windows_by_host"] = {h: int(v) for h, v in pos_by_host.items()}
    out["e_loho_auprc"] = loho
    out["e_loho_summary"] = {n: {"min": float(min(v[n] for v in loho.values())), "max": float(max(v[n] for v in loho.values())),
                                 "host_at_max": max(loho, key=lambda h: loho[h][n])}
                             for n in next(iter(loho.values()))}

    # f. U
    out["f_u_primary"] = u_contrib(seqs, y, b["base"], alpha, K)
    out["f_u_drop_hosts"] = u_contrib(seqs[keep], y[keep], b["base"], alpha, K)
    out["f_u_drop_rules"] = u_contrib(seqs2, y2, b2["base"], alpha, K)
    return out
