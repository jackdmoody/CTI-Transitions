## 2026-10-24: DRIFT dependency mechanism (§8), resolved by Jack

**Issue.** §8 said to depend on DRIFT as `drift @ git+...@brims-2026` in `pyproject.toml`. DRIFT has no package metadata (no `pyproject.toml`/`setup.py`). Its code is `scripts/pipeline_drivers/sysmon_pipeline/` plus an `observational` package shipped as `observational.tar.gz`, so it can't be pip-installed from the tag.

**Decision (Jack).** Pin DRIFT as the git submodule `third_party/DRIFT` at `brims-2026` (`3517424`). `ctit/adapters/drift.py` adds DRIFT's packages to `sys.path`, extracting the tarball to the gitignored `.cache/drift/`, and verifies the submodule HEAD and a clean tree. The allowance to add a `pyproject.toml` to DRIFT is removed, and DRIFT is never modified. §8 and CLAUDE.md are updated to match.

## 2026-10-24: §5 likelihood-ratio scoring vs. DRIFT's scorer (approved by Jack, with a change)

**Issue.** §5 defined score(s) = log P_adv(s) − log P_role(s), with P_role as "DRIFT's role-indexed benign transition model", scored per sliding window of "DRIFT default" length. DRIFT at `brims-2026` has neither. Its role baseline is the leave-one-out mean of same-role hosts' *joint* edge distributions (`build_vectors_union_vocab`, α = 0.5, edge list built from the data). Its score is the JSD between a host and that mean (`compute_peer_baseline_jsd`). It computes one score per whole host, with no conditional P(b|a), no windows and no fit/test time split.

**Decision.**
1. *P_role:* for each role r, sum the fit-window tactic-transition counts (DRIFT ingest semantics, unmapped events skipped) over role-r hosts. Add α = 0.5 over a fixed K×K list of edges (K = the mapper's reachable tactics) and normalize each row. Without row-normalization this equals DRIFT's role-mean vector in DRIFT's counts and smoothing, and a test asserts it.
2. *Window:* a DRIFT session (`sessionize_host`, τ from `fit_gap_threshold` per host, fitted on the fit window only). Windows with fewer than 2 tagged events are skipped and counted. The appendix sweeps fixed windows of 8, 16 and 32 tagged events.
3. *P_adv:* the 14-tactic CTI prior projected onto K, with unreachable tactics skipped like DRIFT's unmapped events, via absorbing-chain marginalization: T_obs = T_KK + T_KU (I − T_UU)⁻¹ T_UK. Mixed with P_role at λ ∈ {0.1, 0.3, 0.5}, chosen on validation only.
4. *Window score = mean log-LR per transition:* (1/(n−1)) Σ_t [log P_adv(s_t | s_{t−1}) − log P_role(s_t | s_{t−1})]. The summed version is reported in the appendix only. (Jack's change from the draft, which used the sum.)
5. *U* stays DRIFT's scorer: the JSD between a window's smoothed edge distribution and the role-r fit-window mean, over the same fixed edge list. For whole hosts this reduces to the BRiMS score.
6. *Separating scorer from prior:* Uni (likelihood ratio with a uniform P_adv) is the like-for-like comparison for R. R − Uni is reported as the CTI effect and Uni − U as the scorer effect.
7. The §5 alternative becomes a per-edge JSD contribution weighted by the projected P_adv, kept as an appendix ablation.

§5 is updated to match.

## 2026-10-24: §2.2 / §4: injected tactics the DRIFT mapper can't produce (approved by Jack)

**Issue.** `build_tokens` assigns tactics only through `_map_mitre_technique`.
- Over Sysmon alone it produces Execution, Defense Evasion, Credential Access, Persistence and Command and Control.
- Discovery (4798), Privilege Escalation (4672) and Kerberos (4768) need Security-log event IDs. BRiMS's D = 41 > 25 implies those were present.
- Lateral Movement and Collection are in `MITRE_TECHNIQUE_DB`, but no rule produces them.
- Initial Access, Reconnaissance, Resource Development, Exfiltration and Impact are absent.
- `T1105` (bitsadmin) maps to a technique missing from the DB, so its tactic is `""`.

Injecting steps as tactics the mapper can't produce creates events benign data can never contain. That overstates every condition's detection and breaks agreement with real OTRF events (T7).

**Decision.**
- `visibility_<actor>.csv` gains a `drift_tactic` column: the tactic the **extended mapper** (next entry) produces from the step's concrete artifact, or `—`.
- `drift_tactic` is what gets injected. Steps with `—` count toward recovery metrics only, like `visible = n`.
- Priors are projected onto K (previous entry).
- T1 reports K and mapper coverage.

## 2026-10-24: extended tactic mapper, W2-side (approved by Jack)

**Issue.** Given the reachability gap above, a K of roughly 5–7 tactics may be too small to tell actors apart (H4).

**Decision.**
- Add a W2-side mapper in `ctit/map/`, built from SigmaHQ Windows rules (Sysmon and Security) pinned to one commit, with tactic taken from each rule's ATT&CK tags.
- Gaps are filled only from ATT&CK data-component mappings. There are no hand-written rules derived from emulation plans or eval data.
- A deterministic primary-tactic policy for multi-tactic techniques is documented in `docs/MAPPER_POLICY.md`.
- The mapper is frozen (committed) before any injection or scoring.
- All W2 conditions, U included, use the extended mapper.
- DRIFT's mapper is untouched and used only for the parity test and as the "BRiMS mapper" reference.
- T4 is reported under both mappers.
- WP5 adds a gate: K under the extended mapper, actor ground truth projected onto K, and pairwise JSD between actor transition matrices under both mappers. Jack decides whether H4 is viable at that K before other actors are ported.

Spec §2, §4, §7 and §8 and CLAUDE.md are updated.

## 2026-10-24: open-weight model slots (§3, approved)

- S primary: `qwen3:14b` under Ollama, thinking off, `num_ctx` ≥ 8192, digest pinned.
- The second slot changes from "robustness" to a size curve (approved). Model: `qwen3:4b-instruct` (Qwen3-4B-Instruct-2507, non-thinking). `qwen3:4b` was rejected because it can't switch thinking off. F = `claude-opus-5-5`, temperature 0.

## 2026-10-24: ATT&CK v19 tactic split (§2.5, §4), approved by Jack

**Issue.** ATT&CK v19.0 (2026-04-28) replaced Defense Evasion with Stealth and Defense Impairment, giving 15 tactics. SigmaHQ `r2026-07-01` uses the new tags (800 Stealth, 302 Defense Impairment). The spec (§4, "14 Enterprise ATT&CK tactics"), DRIFT and the 2020 emulation plans use 14.

**Proposed fix.** The extended mapper collapses both to Defense Evasion (`ctit/map/attack.py`, `docs/MAPPER_POLICY.md`). Technique→tactic lookups use ATT&CK v18.1, the last 14-tactic release. Extraction prompts keep 14 tactics. This is reversible: one lookup table.

## 2026-10-24: Sigma process_creation rules vs. Security 4688 (§2.5), approved by Jack (mapper v2)

**Issue.** The frozen mapper applies process_creation rules to Sysmon EID 1 only. Security 4688 events (ATLASv2, and any range host without full Sysmon) get no process-based tactics.

**Proposed fix.** Before final sign-off, also evaluate process_creation rules on 4688 via a field mapping (NewProcessName→Image, ParentProcessName→ParentImage, CommandLine). Re-freeze and re-run the report.

## 2026-10-24: data-component gap-fill dropped; ATLASv2 demoted (§2.4, §2.5, §7), decided by Jack
- The extended mapper's "gap-fill from ATT&CK data-component mappings" is removed from the spec and CLAUDE.md. No kept rule lacks a tactic, and ATT&CK v18+ replaced data components.
- ATLASv2 becomes a limited robustness check (T6, limits stated). OTRF APT29 is the primary public real-execution benchmark.

## 2026-10-24: actor set and OilRig citations (§0 H4, §1, §2.3, §9), decided by Jack
- Sandworm is promoted to core (CTID plan, Windows steps 16–19 only). DPRK becomes a stretch actor via the report-split fallback: the ER6 DPRK plan is macOS-targeted. H4's 4×4 is now APT29/menuPass/OilRig/Sandworm, and the cut order is updated.
- OilRig: the plan YAML has no `cti_source`, but the plan's markdown docs cite ~25 reports. So the temporal fallback (priors must post-date the plan) is not needed. Cited sources for every actor are now YAML `cti_source` plus report URLs in the plan docs, and `check_leakage.py` cross-checks `cited_by_emulation_plan` against them.
