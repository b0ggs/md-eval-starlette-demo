# Product A Finish Checklist

This is the binding scope for the remaining Product A work. Changing this file, its file allowlist, or its budgets requires Wade's approval before implementation continues.

## Finish line

A stranger with Docker and their own eligible Codex login can clone the repository, run `python3 run_product_a.py`, acquire a verified fixed runtime on first use, approve one fresh hash-bound experiment, and receive preserved evidence, a report, and the descriptive results tally.

## Fixed experiment

- The bundled 18 tasks; bundled MD versus empty No-MD; `gpt-5.6-sol`, high.
- Two paired repeats: 36 attempts per arm, 72 planned calls, concurrency 12.
- Keep the registered whole-pair infrastructure replacements: four pairs, 80 invocations maximum.
- No selective retry, manual retry, partial resume, or new experiment knobs.
- Complete-task analysis only; no pooled cross-run p-values.

## Three steps only

1. Checkpoint the exact current v1 runner and evidence in Git history; never edit historical requests, approvals, raw evidence, tasks, controls, or `analysis.json`.
2. Ship one fixed `linux/amd64` runtime from the qualified public Codex 0.153.4 artifact, three existing wheel profiles, and one pinned host-mounted Python 3.11.5 tree. Use narrow build inputs; never publish the opaque local images.
3. Prove the one-command path from a clean clone, run the offline suite once, then request separate approval for one full v2 experiment and the public release/tag.

## UX boundary

- First use: one default-No runtime-download question.
- Every experiment: one default-No paid-call question showing 18/72/80/model/hash.
- Readiness precedes request creation. Approval binds that fresh request hash and is consumed once.
- Credential presence can be checked; freshness, entitlement, and model access cannot be promised before a service call.

## Engineering boundary

- Reuse the existing Product A lifecycle; do not copy it into another 1,500-line v2 module.
- New first-party production growth: at most 500 physical lines.
- New test growth, including the budget guard: at most 250 physical lines.
- No production Python file added for this finish may exceed 180 lines.
- Only paths enumerated in `tests/test_product_a_scope_budget.py` may be added or expanded.
- If the public runtime cannot fit these limits without weakening containment or evidence integrity, stop and ask Wade. Do not silently raise a limit.

## Not included

Product B, task/model/MD configurability, a general runtime manager, statistical redesign, native Windows, multi-architecture work, signing infrastructure, unrelated cleanup, real calls, publishing, merge, or push without the applicable approval.
