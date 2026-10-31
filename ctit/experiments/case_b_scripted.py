"""Case study B, collapsed scoring, with the scripted benign job removed two ways (POST HOC,
2026-10-31; Jack's final coding pass, item 5). No model calls.

Exactly the diagnosis's item d (ctit.experiments.redteam_diagnosis, collapsed version), for every
condition the config lists: U, Uni, ATTK per actor, every label's R prior per actor and every
oracle in `oracle_modes`:
  (i)  the five xx01/xx51 hosts dropped: the full test set's collapsed scores, restricted to the
       other hosts' windows (baseline as in the primary scoring);
  (ii) only the scripted job's two rules removed: their tags dropped from the test events and the
       fit hosts, windows rebuilt, baseline rebuilt without them.
AUPRC, AUROC and Det@1%FPR with 95% host-cluster bootstrap intervals (rs.evaluate; one host draw
per resample shared by every condition, so adding a condition changes no other interval).
"""
from __future__ import annotations

import numpy as np

from ctit.cti import prior
from ctit.cti.manifest import load_actors
from ctit.eval import optc_split
from ctit.experiments import redteam_diagnosis as rd, redteam_scoring as rs, v2_common as v2
from ctit.map import v3
from ctit.map.attack import TACTICS


def conditions(config: dict) -> tuple[dict[str, list[np.ndarray]], dict[str, str]]:
    """Uni, ATTK/<actor>, R-<label>/<actor> for `labels`, oracle-<label> for `oracle_modes`. An oracle
    sample whose only chunk was refused has no prior and is left out (F refused 5/5); a label whose
    every oracle sample was refused has no oracle row."""
    groups = {a: v["attack_group"] for a, v in load_actors().items()}
    out = {"Uni": [np.zeros((len(TACTICS),) * 2)]}
    out |= {f"ATTK/{a}": [prior.attk_counts(groups[a])[0]] for a in config["actors"]}
    refused = {}
    for label in config["labels"]:
        spec = config["priors"][label]
        for a in config["actors"]:
            Cs = v2.counts(spec, "R", a)
            if Cs:
                out[f"R-{label}/{a}"] = Cs
        if label in config.get("oracle_modes", []):
            ds = v2.load(spec, "oracle", "OpTC-redteam")
            ok = [d for d in ds if any(c["status"] != "refused" for c in d["chunks"])]
            refused[label] = f"{len(ds) - len(ok)}/{len(ds)}"
            if ok:
                out[f"oracle-{label}"] = [np.array(d["counts"], dtype=float) for d in ok]
    return out, refused


def run(config: dict, calls=None) -> dict:
    alpha, n_boot, seed = config["alpha"], config["bootstrap"]["n"], config["bootstrap"]["seed"]
    rules = v3.load_v3()
    K = rs.reachable(rules)
    ki = {t: i for i, t in enumerate(K)}
    drop = tuple(config["scripted_rules"])
    workers = config.get("workers", 3)
    seq_of = lambda w: np.array([[ki[t] for t in ts] for ts in w["tactics"]])
    tagged = rd.test_tagged(workers)
    win = rd.windows(tagged)
    y, host = win["positive"].to_numpy(bool), win["host"].to_numpy()
    fit_hosts = optc_split.load_split()["fit"]
    b = rs.baseline(rs.fit_counts(fit_hosts, workers), K, alpha)
    b2 = rs.baseline(rs.fit_counts(fit_hosts, workers, drop=drop, cache=rd.FIT_NOSCRIPT), K, alpha)
    counts, oracle_refused = conditions(config)

    def score(w, base):
        pr = rs.collapsed_pairs(w["tactics"], ki)
        P = rs.offdiag(base["pooled"] + alpha)
        return {"U": [rs.u_scores(seq_of(w), base["base"], alpha)],
                **{n: [rs.lr_scores_collapsed(len(w), pr, rs.collapsed_prior(C, alpha, K), P) for C in Cs]
                   for n, Cs in counts.items()}}

    keep = ~np.array([rd.scripted(h) for h in host])
    full = score(win, b)
    win2 = rd.windows(tagged[~tagged["rule_id"].isin(drop)])
    y2, host2 = win2["positive"].to_numpy(bool), win2["host"].to_numpy()
    titles = {r["id"]: r["title"] for r in rules}
    return {
        "note": "POST HOC (2026-10-31): case B collapsed, scripted job removed (diagnosis item d), every listed prior",
        "version": "collapsed", "oracle_samples_refused": oracle_refused, "alpha": alpha, "lambda": 0.0, "bootstrap": config["bootstrap"],
        "i_drop_xx01_xx51_hosts": {
            "hosts_dropped": sorted({h for h in host if rd.scripted(h)}), "windows": int(keep.sum()),
            "positive": int(y[keep].sum()),
            "conditions": rd._eval({n: [s[keep] for s in ss] for n, ss in full.items()}, y[keep], host[keep], n_boot, seed)},
        "ii_drop_scripted_rule_tags": {
            "rules": [titles[r] for r in drop], "windows": int(len(y2)), "positive": int(y2.sum()),
            "fit_transitions": int(b2["pooled"].sum()),
            "conditions": rd._eval(score(win2, b2), y2, host2, n_boot, seed)},
    }
