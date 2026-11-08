# docs/

What each file is. Older files say *prior* for a kernel and *memory* for the no-report condition B; the paper's
terms are in the top-level [README](../README.md).

## Records of the study

| File | What |
|---|---|
| [`W2_EXPERIMENT_SPEC.md`](W2_EXPERIMENT_SPEC.md) | The pre-registered plan (hypotheses, conditions, metrics, work packages), written for coding agents. Kept as written; the paper's framing changed afterwards. |
| [`SPEC_ISSUES.md`](SPEC_ISSUES.md) | Every deviation from the spec and every post hoc analysis, dated, with the decision taken (through 2026-10-31). |
| [`MAPPER_POLICY.md`](MAPPER_POLICY.md) | Rules for the SigmaHQ-based tactic mapper and its versions; v3 frozen 2026-10-26 before any scoring. |
| [`CORPUS_CHECK.md`](CORPUS_CHECK.md) | Screening of open benign Windows corpora (Splunk BOTS v1–v3, DARPA OpTC) against pre-set pass criteria (2026-10-26). |
| [`revision/README.md`](revision/README.md) | Index of the revision outputs under `results/revision/` and their provenance (commits, settings). |
| [`revision/changed_conclusions.md`](revision/changed_conclusions.md) | Final list of what changed between the 04 Nov draft and the paper under the adopted settings (2026-11-05), and what stayed sensitivity-only. |
| [`revision/facts.md`](revision/facts.md) | Read-only facts about the draft-era code and runs that the revision relied on (paths, counts, settings), with code citations (2026-11-05). |
| [`revision/gt_audit.md`](revision/gt_audit.md) | Audit of the emulation-plan ground truth (segments, cross-platform handoffs, optional steps) and the two variants scored in the supplement (2026-11-05). |
| [`revision/tables/`](revision/tables/) | Committed copies of the paper's Tables 2, 3 and 5 (identical to `paper/tables/`). |

## Working logs

Kept for provenance. Files marked *stale* describe the project as of their date and are not updated.

| File | What |
|---|---|
| [`PROGRESS.md`](PROGRESS.md) | Session-by-session log: what was run, what passed, run IDs (current). |
| [`STATUS.md`](STATUS.md) | *Stale (2026-10-25).* Status summary under the original hunting framing (H1–H4). |
| [`status_map.html`](status_map.html) | *Stale (2026-10-25).* Pipeline status diagram companion to `STATUS.md`. |
| [`WORKPLAN.md`](WORKPLAN.md) | *Stale (2026-10-26).* Work-package order and acceptance checks for the coding sessions. |
| [`API_SURFACE.md`](API_SURFACE.md) | *Stale (2026-10-26).* Code entry points (event frame, mapper, scoring) as of `ea12db9`. |
| [`REVIEW_QUEUE.md`](REVIEW_QUEUE.md) | *Stale (2026-10-27).* Items that were held for sign-off at the project's human gates (mapper, visibility, gates). |
| [`V2_SUMMARY.md`](V2_SUMMARY.md) | *Stale (2026-10-31).* Summary of the post hoc v2 analyses behind the pre-revision tables; superseded by `revision/`. |
