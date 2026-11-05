"""Rescoring engine for the AICS-27 revision (internal review; 2026-11-05). No model calls: cached priors only.

scorecard(cfg, variant, filt) recomputes, for one ground-truth reference and one evidence filter:
- t2: support recovery (edge-F1, F1 / chance, chance percentile) per family x actor, as
  ctit.experiments.paper_tables_v2 (multi-sample: mean over samples; chance from the shared draw);
- t3: own-plan IG (bits over uniform per transition) with the draft's i.i.d. interval (1,000 resamples,
  seed 20261027, drawn in prior_likelihood's actor order), and attribution (Attr.) per family;
- rb: R - B, report-level bootstrap and leave-one-report-out jackknife, exactly as
  ctit.experiments.reading_bootstrap (same seeds and draw order), plus raw edge-F1;
- h3: each local model's share of Claude Opus's edge-F1.
`variant`: 'adopted' (ctit.eval.reference.build_reference), 'A' or 'B' (sensitivity variants).
`filt`: None (as run), 'fragments' or 'strict': R kernels rebuilt with every transition whose evidence quote
fails that check removed before Eq. 1 aggregation (B has no evidence check and is never filtered).
With variant='adopted' and filt=None every number reproduces the draft (tests/test_revision_engine.py).

Phase 3 helpers: segment_blocks() (moving-block bootstrap inside segments, no wrap-around), exact
hypergeometric chance (exact_chance), the enrichment identity, and effective smoothing (smoothing()).
"""
from __future__ import annotations

import math
import zlib
from dataclasses import dataclass

import numpy as np
from scipy.stats import hypergeom
from scipy.stats import t as student_t

from ctit.cti import prior
from ctit.cti.manifest import load_actors
from ctit.eval import recovery
from ctit.eval import reference as ref
from ctit.experiments import v2_common as v2
from ctit.experiments.paper_tables import chance_orderings
from ctit.experiments.prior_likelihood import bits, conditional

ALPHA = 0.5
K = 14
N_OFF = recovery.N_OFF  # 182
ACTORS = ["APT29", "OilRig", "Sandworm", "menuPass"]          # paper order
ACTORS_LIK = ["APT29", "menuPass", "OilRig", "Sandworm"]      # prior_likelihood's i.i.d. draw order
R_LABELS = ["F", "G", "Q", "Q5", "M", "M5", "M3"]
B_LABELS = ["F", "G", "Q", "M"]
FAMILIES = [f"R-{x}" for x in R_LABELS] + [f"B-{x}" for x in B_LABELS] + ["ATTK"]
PAIRS = ["F", "G", "Q", "Q5", "M", "M5", "M3"]
NAMES = {"F": "Claude Opus", "G": "GPT-6 Astra", "Q": "Qwen 14B", "Q5": "Qwen 14B sampled", "M": "Ministral 14B",
         "M5": "Ministral 14B sampled", "M3": "Ministral 3B", "M35": "Ministral 3B sampled"}
CHANCE = {"draws": 10000, "seed": 20261027}
IID_DRAFT = {"n_boot": 1000, "seed": 20261027}
RB = {"n_boot": 2000, "seed": 20261031}
FILTER_FLAG = {"fragments": "evidence_ok_fragments", "strict": "evidence_ok"}


# ----------------------------------------------------------------------------- references

@dataclass
class Ref:
    actor: str
    variant: str
    segments: list
    G: np.ndarray       # 14 x 14 transition counts (no pair across a segment boundary)
    pairs: np.ndarray   # (L, 2)
    seg: np.ndarray     # (L,) segment index of each transition

    @property
    def L(self) -> int:
        return len(self.pairs)

    @property
    def g(self) -> int:
        return int(((self.G > 0) & recovery.OFF_DIAG).sum())


def reference(actor: str, variant: str = "adopted") -> Ref:
    segs = ref.variant_segments(actor, variant)
    return Ref(actor, variant, segs, ref.counts(segs), ref.pairs_array(segs), ref.segment_ids(segs))


# ----------------------------------------------------------------------------- kernels

def r_tensor(cfg: dict, label: str, actor: str, filt: str | None = None) -> np.ndarray:
    """(samples, reports, 14, 14) binary: the edges each report supports, after the evidence filter."""
    reports = v2.prior_reports(actor)
    pos = {r: i for i, r in enumerate(reports)}
    ds = v2.load(cfg["priors"][label], "R", actor)
    E = np.zeros((len(ds), len(reports), K, K))
    for s, d in enumerate(ds):
        for t in d["transitions"]:
            if filt is not None and t.get(FILTER_FLAG[filt]) is False:
                continue
            E[s, pos[t["doc_id"]], prior.INDEX[t["from_tactic"]], prior.INDEX[t["to_tactic"]]] = 1
        if filt is None and not np.array_equal(E[s].sum(axis=0), np.array(d["counts"])):
            raise RuntimeError(f"per-report edges do not rebuild the saved counts ({label} {actor})")
    return E


def b_counts(cfg: dict, label: str, actor: str) -> list[np.ndarray]:
    return v2.counts(cfg["priors"][label], "B", actor)


def attk_counts(actor: str) -> list[np.ndarray]:
    return [prior.attk_counts(load_actors()[actor]["attack_group"])[0]]


def family_counts(cfg: dict, name: str, actor: str, filt: str | None = None) -> list[np.ndarray]:
    if name == "ATTK":
        return attk_counts(actor)
    cond, label = name.split("-", 1)
    if cond == "R":
        return list(r_tensor(cfg, label, actor, filt).sum(axis=1))
    return b_counts(cfg, label, actor)


# ----------------------------------------------------------------------------- statistics

def per_transition(Cs: list[np.ndarray], pr: np.ndarray, alpha: float = ALPHA) -> np.ndarray:
    """(L,) log2(13 P) per plan transition, mean over samples (prior_likelihood.score)."""
    return np.mean([bits(conditional(C, alpha), pr) for C in Cs], axis=0)


def status(lo: float, hi: float) -> str:
    return v2.status(lo, hi)


def ci(m: np.ndarray, idx: np.ndarray) -> list[float]:
    return [float(x) for x in np.percentile(m[idx].mean(axis=1), [2.5, 97.5])]


def iid_indices(refs: dict, n: int, seed: int) -> dict:
    rng = np.random.default_rng(seed)
    return {a: rng.integers(0, refs[a].L, (n, refs[a].L)) for a in ACTORS_LIK}


def t2_cell(Cs: list[np.ndarray], R: Ref, ch: v2.ChanceTable) -> dict:
    rs = [recovery.edge_prf(C, R.G) for C in Cs]
    ratios = [ch.ratio(r["f1"], r["edges_extracted"]) for r in rs]
    ok = [x for x in ratios if x is not None]
    m = lambda k: float(np.mean([r[k] for r in rs]))
    return {"samples": len(Cs), "truth_edges": R.g, "edges_mean": m("edges_extracted"), "edge_f1": m("f1"),
            "precision": m("precision"), "recall": m("recall"),
            "f1_over_chance": float(np.mean(ok)) if ok else None,
            "percentile": float(np.mean([ch.percentile(r["f1"], r["edges_extracted"]) for r in rs]))}


def _nanmean(x) -> float:
    x = np.asarray(x, dtype=float)
    return float(np.nanmean(x)) if (~np.isnan(x)).any() else np.nan


def _ratio(C, G, ch) -> float:
    f1, k = v2.f1_k(C, G)
    r = ch.ratio(f1, k)
    return np.nan if r is None else r


def _ig(C, pr, alpha) -> float:
    return float(bits(conditional(C, alpha), pr).mean())


def jackknife(point, reps: np.ndarray) -> dict:
    n = len(reps)
    if point is None or np.isnan(reps).any():
        return {"replicates": [None if np.isnan(x) else float(x) for x in reps], "min": None, "max": None,
                "se": None, "ci95": None}
    se = float(np.sqrt((n - 1) / n * ((reps - reps.mean()) ** 2).sum()))
    q = float(student_t.ppf(0.975, n - 1))
    return {"replicates": [float(x) for x in reps], "min": float(reps.min()), "max": float(reps.max()),
            "se": se, "t_quantile": q, "ci95": [point - q * se, point + q * se]}


def _ci(x: np.ndarray) -> dict:
    ok = x[~np.isnan(x)]
    if not len(ok):
        return {"ci95": None, "undefined_resamples": int(len(x))}
    return {"ci95": [float(np.percentile(ok, 2.5)), float(np.percentile(ok, 97.5))], "median": float(np.median(ok)),
            "undefined_resamples": int(np.isnan(x).sum())}


def rb_one(E: np.ndarray, B: list[np.ndarray], R: Ref, ch: v2.ChanceTable, alpha: float, n_boot: int,
           rng: np.random.Generator) -> dict:
    """R - B for one label and actor; reading_bootstrap.one generalised to a given E (filtered or not) and
    reference, with raw edge-F1 added (it draws nothing). Same draw order, so as-run inputs reproduce it."""
    G, pr = R.G, R.pairs
    f1 = lambda C: v2.f1_k(C, G)[0]
    stat = lambda Cs: (_nanmean([_ratio(C, G, ch) for C in Cs]), float(np.mean([_ig(C, pr, alpha) for C in Cs])),
                       float(np.mean([f1(C) for C in Cs])))
    r_pt, b_pt = stat(E.sum(axis=1)), stat(B)
    B_ratio = np.array([_ratio(C, G, ch) for C in B])
    B_ig = np.array([_ig(C, pr, alpha) for C in B])
    B_f1 = np.array([f1(C) for C in B])
    nS, nR, nB = E.shape[0], E.shape[1], len(B)
    boot = np.full((n_boot, 6), np.nan)  # R ratio, B ratio, R ig, B ig, R f1, B f1
    for b in range(n_boot):
        idx_r = rng.integers(0, nR, nR)
        idx_s = rng.integers(0, nS, nS) if nS > 1 else np.zeros(1, dtype=int)
        idx_b = rng.integers(0, nB, nB) if nB > 1 else np.zeros(1, dtype=int)
        Cs = E[idx_s][:, idx_r].sum(axis=1)
        boot[b, 0] = _nanmean([_ratio(C, G, ch) for C in Cs])
        boot[b, 1] = _nanmean(B_ratio[idx_b])
        boot[b, 2] = np.mean([_ig(C, pr, alpha) for C in Cs])
        boot[b, 3] = B_ig[idx_b].mean()
        boot[b, 4] = np.mean([f1(C) for C in Cs])
        boot[b, 5] = B_f1[idx_b].mean()
    jk = np.array([stat(E[:, np.arange(nR) != i].sum(axis=1)) for i in range(nR)])
    pt = lambda x: None if x is None or np.isnan(x) else float(x)
    gap = lambda i: (pt(r_pt[i] - b_pt[i]) if not (np.isnan(r_pt[i]) or np.isnan(b_pt[i])) else None)
    out = {"reports": nR, "r_samples": nS, "b_samples": nB}
    for key, i, j in (("f1_over_chance", 0, 0), ("ig_bits", 2, 1), ("edge_f1", 4, 2)):
        out[key] = {"R": pt(r_pt[j]), "B": pt(b_pt[j]),
                    "R_minus_B": {"point": gap(j), **_ci(boot[:, i] - boot[:, i + 1]),
                                  "jackknife": jackknife(gap(j), jk[:, j] - b_pt[j])}}
    return out


def clear(rb_entry: dict) -> str:
    """'above' / 'below' if both the bootstrap and the jackknife interval exclude zero on the same side
    (the draft's 'clear'); otherwise 'not clear'."""
    b, j = rb_entry.get("ci95"), (rb_entry.get("jackknife") or {}).get("ci95")
    if b is None or j is None:
        return "undefined"
    sb, sj = status(*b), status(*j)
    return sb if sb == sj and sb != "spans" else "not clear"


# ----------------------------------------------------------------------------- scorecard

def scorecard(cfg: dict, variant: str = "adopted", filt: str | None = None, with_rb: bool = True) -> dict:
    refs = {a: reference(a, variant) for a in ACTORS}
    order = chance_orderings(CHANCE["draws"], CHANCE["seed"])
    ch = {a: v2.ChanceTable(refs[a].G, order) for a in ACTORS}
    counts = {name: {a: family_counts(cfg, name, a, filt) for a in ACTORS} for name in FAMILIES}
    out: dict = {"variant": variant, "filter": filt,
                 "reference": {a: {"edges": refs[a].g, "L": refs[a].L, "segments": len(refs[a].segments)} for a in ACTORS},
                 "t2": {}, "t3": {}, "attr": {}, "rb": {}, "h3": {}}
    for name, by_a in counts.items():
        out["t2"][name] = {a: t2_cell(Cs, refs[a], ch[a]) for a, Cs in by_a.items()}
    idx = iid_indices(refs, IID_DRAFT["n_boot"], IID_DRAFT["seed"])
    for name, by_a in counts.items():
        cells = {}
        for a, Cs in by_a.items():
            m = per_transition(Cs, refs[a].pairs)
            c = ci(m, idx[a])
            cells[a] = {"bits": float(m.mean()), "ci95": c, "status": status(*c)}
        out["t3"][name] = cells
        # attribution: each plan to the actor whose chain gives it the highest likelihood
        sc = {ra: {ca: float(per_transition(by_a[ra], refs[ca].pairs).mean()) for ca in ACTORS} for ra in ACTORS}
        best = {ca: max(ACTORS, key=lambda ra: sc[ra][ca]) for ca in ACTORS}
        out["attr"][name] = {"n": sum(best[a] == a for a in ACTORS), "plan_to": best, "matrix": sc}
    f_f1 = {a: out["t2"]["R-F"][a]["edge_f1"] for a in ACTORS}
    for lab in ("Q", "Q5", "M", "M5", "M3", "G"):
        sh = {a: out["t2"][f"R-{lab}"][a]["edge_f1"] / f_f1[a] for a in ACTORS}
        out["h3"][lab] = {"share": sh, "meets_80": sum(v >= 0.8 for v in sh.values())}
    if with_rb:
        for a in ACTORS:
            for lab in PAIRS:
                rng = np.random.default_rng([RB["seed"], zlib.crc32(lab.encode()), zlib.crc32(a.encode())])
                E = r_tensor(cfg, lab, a, filt)
                e = rb_one(E, b_counts(cfg, lab, a), refs[a], ch[a], ALPHA, RB["n_boot"], rng)
                for key in ("f1_over_chance", "ig_bits", "edge_f1"):
                    e[key]["R_minus_B"]["clear"] = clear(e[key]["R_minus_B"])
                out["rb"].setdefault(lab, {})[a] = e
    return out


# ----------------------------------------------------------------------------- Phase 3 helpers

def segment_blocks(seg: np.ndarray, b: int, n: int, rng: np.random.Generator) -> np.ndarray:
    """(n, L) moving-block bootstrap indices that respect segments: a block is b consecutive transitions
    inside one segment (a segment shorter than b is one whole block); no block crosses a boundary and none
    wraps around. Blocks are drawn uniformly from all admissible blocks and concatenated until L is reached,
    then truncated to L."""
    L = len(seg)
    blocks = block_list(seg, b)
    lens = np.array([len(x) for x in blocks])
    if (lens == lens[0]).all():
        B = np.stack(blocks)
        k = -(-L // lens[0])
        return B[rng.integers(0, len(B), (n, k))].reshape(n, -1)[:, :L]
    out = np.empty((n, L), dtype=int)
    for r in range(n):
        got: list[int] = []
        while len(got) < L:
            got.extend(blocks[rng.integers(0, len(blocks))].tolist())
        out[r] = got[:L]
    return out


def block_list(seg: np.ndarray, b: int) -> list[np.ndarray]:
    """Every admissible block: b consecutive transitions inside one segment, or a whole segment shorter than b."""
    blocks = []
    for s in np.unique(seg):
        pos = np.flatnonzero(seg == s)
        blocks += [pos] if len(pos) <= b else [pos[i:i + b] for i in range(len(pos) - b + 1)]
    return blocks


def admissible_blocks(seg: np.ndarray, b: int) -> int:
    return len(block_list(seg, b))


def exact_chance(k: int, g: int, tp: int) -> dict:
    """Edge-F1 of a random k-edge set against g truth edges: TP ~ Hypergeometric(182, g, k).
    Mean F1 = 2 E[TP] / (k + g) with E[TP] = k g / 182; percentile = 100 (P(TP < tp) + P(TP = tp) / 2)."""
    if k == 0 or g == 0:
        return {"mean_f1": 0.0, "expected_tp": 0.0, "percentile": 50.0 if tp == 0 else 100.0, "ratio": None}
    h = hypergeom(N_OFF, g, k)
    etp = k * g / N_OFF
    mean_f1 = 2 * etp / (k + g)
    f1 = 2 * tp / (k + g)
    return {"mean_f1": mean_f1, "expected_tp": etp, "percentile": float(100 * (h.cdf(tp - 1) + 0.5 * h.pmf(tp))),
            "ratio": f1 / mean_f1}


def smoothing(Cs: list[np.ndarray], n_docs: int | None, alpha: float = ALPHA) -> dict:
    """Effective smoothing of Eq. 1 kernels. n_docs: reports (R) or 1 (one B generation); None = ATTK."""
    off = [np.where(np.eye(K, dtype=bool), 0, C) for C in Cs]
    rows = np.concatenate([C.sum(axis=1) for C in off])
    fitted = [conditional(C, alpha).max() for C in Cs]
    out = {"samples": len(Cs), "row_total_max": float(rows.max()), "row_total_sum_mean": float(np.mean([C.sum() for C in off])),
           "nonempty_rows_mean": float(np.mean([(C.sum(axis=1) > 0).sum() for C in off])),
           "fitted_max_row_prob": float(max(fitted)), "fitted_max_row_prob_mean": float(np.mean(fitted)),
           "fitted_bits": float(math.log2((K - 1) * max(fitted)))}
    if n_docs is not None:
        cap = (n_docs + alpha) / (n_docs + (K - 1) * alpha)
        out.update({"n_docs": n_docs, "cap": cap, "cap_bits": math.log2((K - 1) * cap)})
    else:  # ATTK, C = n n^T: row i of Eq. 1 tends to n_j / sum_{k != i} n_k as counts grow; no report cap
        n = np.sqrt(np.diag(Cs[0]))
        lim = max((n[j] / (n.sum() - n[i])) for i in range(K) for j in range(K) if j != i and n.sum() - n[i] > 0)
        out.update({"n_docs": None, "cap": float(lim), "cap_bits": math.log2((K - 1) * lim),
                    "cap_note": "no report cap: limit of max_j n_j / sum_{k != i} n_k as counts grow"})
    return out
