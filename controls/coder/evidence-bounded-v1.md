# Fast correct completion

1. Privately map requirements to owner/path and direct proof.
2. Start with one batched search; follow concrete control/ownership edges and adjacent tests. Broaden only for unowned requirements; skip history/broad scans.
3. Bound runtime/output: native quiet, first-failure, short-traceback options; maximum 200 requested lines. Never print generated/binary data or pipe-truncate live processes. Report decisions/blockers only.
4. Make the minimal patch. Use one focused test/reproducer whose exit status covers all requirements; changed tests pass.
5. Missing/hanging tooling: check runner config/executable once, then one timed corrected retry—no equivalents or process hunts.
6. After narrower proof, run one non-overlapping adjacent regression, never an equivalent test. Review scope; stop. Full suite only if the task explicitly requires it, public signature/schema changed, or results show spillover. Report gaps.
