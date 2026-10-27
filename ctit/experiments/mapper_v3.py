"""Mapper v3 (B3, SPEC_ISSUES 2026-10-26): per-step rule exclusions, benign tag rate and K.

One tagging pass with every v2 query keeps all matching rules per row (rule_ids, priority
order), so each step's primary rule is the first match still in that step's keep set.
  OpTC side: a seeded sample of fit-split hosts on one benign day, distinct rows weighted by
             event count (ctit.ingest.optc.unique_rows), with bare-image restoration (c1).
  Recording side: the Sysmon technique recordings the signature library uses.
Steps: v2 -> a (no informational) -> b (shared subset) -> c1 (restore images; rules
unchanged) -> c2 (no path-unevaluable rules) -> c3 (no create_remote_thread) = v3.
c2 is decided on fit hosts only. With freeze: true and no ctit/map/rules_v3.json yet, the
v3 keep list is written there (commit = freeze).
"""
from __future__ import annotations

import json
import random
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path

import pandas as pd

from ctit.eval import optc_split
from ctit.ingest import optc, splunk
from ctit.map import v3
from ctit.map.attack import TACTICS
from ctit.map.extended import CHANNEL, tag
from ctit.map.sigma_rules import load_compiled

REPO_ROOT = Path(__file__).resolve().parents[2]
CACHE = REPO_ROOT / "data" / "cache" / "mapper_v3"
sys.path.insert(0, str(REPO_ROOT / "scripts"))
ORDER = {t: i for i, t in enumerate(TACTICS)}


def _variant(event_id: int, source: str) -> str:
    return "security_4688" if (source == "security" and event_id == 4688) else "sysmon"


def recordings() -> list[tuple[str, pd.DataFrame]]:
    """(name, canonical frame) for every recording build_signatures.py uses."""
    import build_signatures as bs
    out = []
    for p in sorted(Path(splunk.SAMPLES).iterdir()):
        try:
            r = splunk.read_sample(p)
        except ET.ParseError:
            continue
        if r and bs.TECH_RE.match(r[0]):
            out.append((p.name, r[1]))
    tmap = bs.atomic_technique_map()
    for p in sorted(bs.ATOMIC_CANON.glob("*.parquet")):
        name = p.stem.split("__", 1)[1] if "__" in p.stem else p.stem
        techs = tmap.get(name) or tmap.get(bs._strip_archive_ext(name))
        if techs and techs - {"T0000"}:
            out.append((p.name, pd.read_parquet(p)))
    return out


def field_sets(frames) -> dict[tuple[str, int], set[str]]:
    fields: dict[tuple[str, int], set[str]] = defaultdict(set)
    for df in frames:
        ch = df["source"].map(CHANNEL).fillna(df["Channel"])
        for (c, e), g in df.assign(_ch=ch).groupby(["_ch", "EventID"]):
            fields[(c, int(e))] |= {col for col in g.columns if g[col].notna().any()}
    return dict(fields)


def optc_fields() -> dict[tuple[str, int], set[str]]:
    core = {"Hostname", "_timestamp", "source", "Channel", "EventID"}
    return {(optc.CHANNEL[optc.SOURCE[e]], e): set(m.values()) | core for e, m in optc.FIELDS.items()}


def optc_sample(hosts: list[str], day: str) -> tuple[pd.DataFrame, dict]:
    """Distinct rows over the sampled host-days, collapsed across hosts (weights summed)."""
    parts, stats = [], {}
    for h in hosts:
        path = next((optc_split.OPTC_ROOT / day).glob(f"*{h[-4:]}.systemia.com.parquet"))
        u, _ = optc.unique_rows(path, restore_bare=True, stats=stats)
        parts.append(u)
    df = pd.concat(parts, ignore_index=True)
    keys = [c for c in df.columns if c not in ("_w", "Hostname", "_timestamp")]
    df = (df.astype({c: "string" for c in keys if c != "EventID"})
            .groupby(keys, dropna=False, sort=False)["_w"].sum().reset_index())
    df["Hostname"] = "sample"
    df["_timestamp"] = pd.Timestamp(day, tz="UTC")
    return df, stats


def _cached_tag(name: str, df: pd.DataFrame, rules: list[dict]) -> pd.DataFrame:
    path = CACHE / f"{name}.tagged.parquet"
    if path.exists():
        return pd.read_parquet(path)
    out = tag(df, rules)
    path.parent.mkdir(parents=True, exist_ok=True)
    out.to_parquet(path, index=False)
    return out


def primary(tagged: pd.DataFrame, keep: set[tuple[str, str]], by_id: dict) -> pd.Series:
    """Primary tactic per row under a keep set of (id, variant)."""
    out = []
    for ids, eid, src in zip(tagged["rule_ids"], tagged["event_id"], tagged["source"]):
        var = _variant(int(eid), src)
        hit = next((i for i in ids.split(",") if i and (i, var) in keep), None) if ids else None
        out.append(by_id[(hit, var)]["tactics"][0] if hit else "")
    return pd.Series(out, index=tagged.index, dtype=object)


def primary_rule(tagged: pd.DataFrame, keep: set[tuple[str, str]]) -> pd.Series:
    out = []
    for ids, eid, src in zip(tagged["rule_ids"], tagged["event_id"], tagged["source"]):
        var = _variant(int(eid), src)
        out.append(next((i for i in ids.split(",") if i and (i, var) in keep), "") if ids else "")
    return pd.Series(out, index=tagged.index, dtype=object)


def step_metrics(tagged: pd.DataFrame, weight: pd.Series, keep: set, by_id: dict, title: dict) -> dict:
    tac = primary(tagged, keep, by_id)
    rid = primary_rule(tagged, keep)
    m: dict = {"K": sorted({t for t in tac if t}, key=ORDER.get)}
    for src in ("sysmon", "security"):
        sel = tagged["source"] == src
        tot = float(weight[sel].sum())
        hit = sel & (tac != "")
        m[src] = {
            "events": tot, "tagged": float(weight[hit].sum()),
            "tag_rate": float(weight[hit].sum() / tot) if tot else None,
            "per_tactic_rate": {t: float(weight[sel & (tac == t)].sum() / tot)
                                for t in sorted(set(tac[hit]), key=ORDER.get)} if tot else {},
            "top_rules": [{"id": r, "title": title[r], "events": float(w)}
                          for r, w in weight[hit].groupby(rid[hit]).sum().sort_values(ascending=False).head(5).items()],
        }
    return m


def run(config: dict, calls=None) -> dict:
    rules = load_compiled()
    by_id = {(r["id"], r["variant"]): r for r in rules}
    title = {r["id"]: r["title"] for r in rules}
    s0 = set(by_id)

    # a) informational
    informational = {k for k in s0 if by_id[k]["level"] == "informational"}
    sa = s0 - informational

    # b) shared subset (field-evaluable on both sides)
    recs = recordings()
    rec_fields = field_sets(df for _, df in recs)
    opt_fields = optc_fields()
    ev_o = {k for k in s0 if v3.evaluable(by_id[k], opt_fields)}
    ev_r = {k for k in s0 if v3.evaluable(by_id[k], rec_fields)}
    shared = ev_o & ev_r
    sb = sa & shared

    # OpTC fit-host sample (restored images, c1) and recordings, tagged once with every v2 query
    split = optc_split.load_split()
    hosts = sorted(random.Random(config["sample_seed"]).sample(split["fit"], config["sample_hosts"]))
    sample, sample_stats = optc_sample(hosts, config["sample_day"])
    t_opt = _cached_tag(f"optc_fit_{config['sample_day']}_{config['sample_seed']}_{len(hosts)}", sample, rules)
    w_opt = sample["_w"].astype(float).reset_index(drop=True)
    rec_cache = CACHE / "recordings.tagged.parquet"
    if rec_cache.exists():
        t_rec = pd.read_parquet(rec_cache)
    else:
        t_rec = pd.concat([tag(df, rules).assign(recording=name) for name, df in recs], ignore_index=True)
        t_rec.to_parquet(rec_cache, index=False)
    w_rec = pd.Series(1.0, index=t_rec.index)

    # c2) rules that matched a sampled event through a path field holding a bare name
    path_bad: dict[tuple[str, str], float] = Counter()
    cols = [c for c in v3.PATH_FIELDS if c in sample.columns]
    for i, row in enumerate(sample[cols].itertuples(index=False)):
        ids = t_opt.at[i, "rule_ids"]
        if not ids:
            continue
        bare = v3.bare_path_fields(dict(zip(cols, row)))
        if not bare:
            continue
        var = _variant(int(t_opt.at[i, "event_id"]), t_opt.at[i, "source"])
        for rid in ids.split(","):
            k = (rid, var)
            if k in sb and v3.referenced_fields(by_id[k]["where"]) & bare:
                path_bad[k] += w_opt[i]
    sc2 = sb - set(path_bad)
    # c3) create_remote_thread category
    remote = {k for k in s0 if by_id[k]["path"].startswith(v3.REMOTE_THREAD)}
    sc3 = sc2 - remote

    steps = {"v2": s0, "a_no_informational": sa, "b_shared_subset": sb, "c1_restore_images": sb,
             "c2_no_path_unevaluable": sc2, "c3_no_remote_thread": sc3}
    n_rules = lambda s: len({i for i, _ in s})  # noqa: E731
    out: dict = {
        "sample": {"day": config["sample_day"], "seed": config["sample_seed"], "hosts": hosts,
                   "distinct_rows": int(len(sample)), **{k: int(v) for k, v in sample_stats.items()}},
        "recordings": len(recs),
        "evaluable": {"optc": len(ev_o), "recordings": len(ev_r), "shared": len(shared)},
        "dropped": {
            "a_informational": {"queries": len(informational), "rules": n_rules(informational),
                                "titles": sorted({by_id[k]["title"] for k in informational})},
            "b_not_shared": {"queries": len(sa - sb), "rules": n_rules(sa) - n_rules(sb)},
            "c2_path_unevaluable": {"queries": len(sb - sc2), "rules": n_rules(sb - sc2),
                                    "list": [{"id": k[0], "variant": k[1], "title": by_id[k]["title"],
                                              "bare_events_matched": float(w)}
                                             for k, w in sorted(path_bad.items(), key=lambda x: -x[1])]},
            "c3_create_remote_thread": {"queries": len(sc2 - sc3), "rules": n_rules(sc2 - sc3),
                                        "titles": sorted({by_id[k]["title"] for k in sc2 - sc3})},
        },
        "steps": {},
    }
    for name, keep in steps.items():
        out["steps"][name] = {
            "queries": len(keep), "rules": n_rules(keep),
            "optc": step_metrics(t_opt, w_opt, keep, by_id, title),
            "recordings": step_metrics(t_rec, w_rec, keep, by_id, title),
        }
    if config.get("freeze") and not v3.RULES_V3.exists():
        v3.RULES_V3.write_text(json.dumps({
            "version": v3.MAPPER_VERSION, "base": "ctit/map/compiled_rules.jsonl (v2, 7d36465)",
            "sample": out["sample"], "dropped": out["dropped"],
            "keep": [{"id": i, "variant": v, "title": by_id[(i, v)]["title"]} for i, v in sorted(sc3)],
        }, indent=1) + "\n")
        out["frozen"] = str(v3.RULES_V3.relative_to(REPO_ROOT))
    return out
