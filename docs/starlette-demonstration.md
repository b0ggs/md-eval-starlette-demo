# Starlette demonstration

This is the focused record for MD Eval's completed 18-task Starlette
demonstration. It explains what was compared, what the tasks cover, how the
registered and exploratory results differ, and how to reproduce the report
without a model call.

The experiment is a **finite-known-set development replication**. It is not the
frozen v7 confirmation and is not evidence that the observed effect generalizes
outside this model, repository, instruction file, or task distribution.

## Design

- Repository/domain: Starlette, a Python ASGI framework.
- Arms: the current MD (`controls/coder/evidence-bounded-v1.md`) and an empty
  No MD control (`controls/coder/null-m2.md`).
- Runtime: the same `gpt-5.6-sol` model, high reasoning setting, harness, task
  bytes, and mechanical checker policy in both arms.
- Cohort: 18 mechanically admitted tasks, with two paired repeats per task.
- Pairing: arm order reverses between each task's two repeats; the two arms in a
  pair run sequentially on the same worker.
- Execution: 36 atomic pairs, 72 subject invocations, peak concurrency 12, and
  zero replacements.
- Correctness: 34 of 36 MD attempts and 34 of 36 No MD attempts resolved.

Every attempt remains in the evidence, including incorrect completions and a
timeout. The [per-task outcome table](../reports/STARLETTE_EIGHTEEN_TWO_REPEAT_V2_REPORT.md#per-task-outcomes)
shows correctness and descriptive resource measurements for all 18 tasks.

## Results

### Registered primary analysis

| Endpoint | Result | Reason |
|---|---|---|
| Wall time | **INCONCLUSIVE** | Fewer than two jointly normal and resolved pairs for at least one task |
| Tokens | **INCONCLUSIVE** | Fewer than two jointly normal and resolved pairs for at least one task |

The preregistered analysis required exactly two usable common pairs for every
task before either efficiency endpoint could support a conclusion.
`confirm-starlette-exception-context` supplied one usable pair;
`confirm-starlette-malformed-host` supplied none. The registered analysis
therefore stops at `INCONCLUSIVE` even though the correctness gate itself
passes.

### Post-hoc exploratory complete-case sensitivity

The complete-case analysis was selected after outcomes were known. It keeps the
16 tasks with two usable pairs, treats tasks as the inferential units, and uses
the same task-level log-ratio calculation on that subset. It is informative but
cannot be relabeled registered or confirmatory.

| Endpoint | Tasks | Reduction | 95% reduction CI | t (df) | Two-sided p | Result |
|---|---:|---:|---:|---:|---:|---|
| Wall time | 16 | 41.8854% | 32.3133%–50.1038% | -7.587268 (15) | 1.6430678e-06 | Significant |
| Tokens | 16 | 33.0927% | 21.6050%–42.8970% | -5.405728 (15) | 7.2894331e-05 | Significant |

### Incomplete pairs and failed attempts

No failed observation was silently dropped from the record or the correctness
totals.

| Attempt | Task | Arm | Outcome |
|---|---|---|---|
| `pair-05-r2-a1-candidate` | `confirm-starlette-exception-context` | MD | Checker unresolved after a normal completion |
| `pair-12-r1-a1-candidate` | `confirm-starlette-malformed-host` | MD | Checker unresolved after a normal completion |
| `pair-12-r1-a2-control` | `confirm-starlette-malformed-host` | No MD | Subject timeout |
| `pair-12-r2-a1-control` | `confirm-starlette-malformed-host` | No MD | Checker unresolved after a normal completion |

Resource means shown for a task with fewer than two usable pairs are descriptive
only. They are not inputs to the registered endpoint or the 16-task
complete-case calculation.

## The 18 tasks

These descriptions paraphrase the public issue contracts. They intentionally
omit private checker details, hidden fixtures, omission probes, and reference
solution structure. Outcome numbers are in the
[canonical per-task table](../reports/STARLETTE_EIGHTEEN_TWO_REPEAT_V2_REPORT.md#per-task-outcomes).

### ASGI and WebSocket lifecycle (3)

| Task ID | Public description |
|---|---|
| `full-starlette-websocket-denial` | Make streaming and file responses work as WebSocket handshake denials while preserving their normal HTTP behavior. |
| `confirm-starlette-http-disconnect` | Stop a streaming response cleanly when an ASGI send reports that the HTTP client disconnected. |
| `confirm-starlette-ws-disconnected` | Give application-side operations after a WebSocket disconnect a distinct error without changing peer-disconnect or protocol-validation behavior. |

### Middleware policy and response semantics (4)

| Task ID | Public description |
|---|---|
| `confirm-starlette-cors-origin` | Echo the request origin for credentialed wildcard CORS responses and mark the response as varying by Origin. |
| `confirm-starlette-cors-private-network` | Add an explicit CORS opt-in for private-network preflights while continuing to deny them by default. |
| `confirm-starlette-session-tracking` | Write session cookies only after modification and vary cached responses when session data is accessed. |
| `confirm-starlette-gzip-vary` | Mark compressible responses as varying by Accept-Encoding even when gzip is not selected, without altering identity or pre-encoded bodies. |

### Exceptions and resource lifetime (3)

| Task ID | Public description |
|---|---|
| `confirm-starlette-exception-context` | Preserve an application exception's meaningful cause or context as it passes through HTTP middleware. |
| `confirm-starlette-background-exception` | Propagate response background-task failures through HTTP middleware instead of losing them after the body finishes. |
| `confirm-starlette-form-context-cleanup` | Let request-form parsing be used as an async context manager that closes uploaded files on both normal and exceptional exit. |

### Files, byte ranges, and cache validators (4)

| Task ID | Public description |
|---|---|
| `confirm-starlette-uploadfile-rollover` | Move an upload write to the thread pool when it will spill a spooled file to disk while retaining the in-memory fast path. |
| `confirm-starlette-range-crlf` | Produce standards-compliant multipart byte-range framing with accurate body lengths for streamed GET and HEAD responses. |
| `confirm-starlette-suffix-range` | Clamp an oversized suffix range to the whole file and return accurate partial-response headers. |
| `confirm-starlette-staticfiles-weak-etag` | Recognize matching weak ETags in comma-separated cache validators with valid HTTP whitespace and return an empty 304 response. |

### State, routing, authority, and client integration (4)

| Task ID | Public description |
|---|---|
| `confirm-starlette-state-mapping` | Make request and lifespan state mapping-compatible while preserving attribute access and shared typed mapping values. |
| `confirm-starlette-malformed-host` | Validate Host authorities consistently across URL creation, host policy, and redirects, using safe fallbacks or a bad-request response. |
| `confirm-starlette-debug-extension` | Preserve arbitrary TestClient response debug metadata while retaining template and context compatibility. |
| `confirm-starlette-root-path-boundary` | Strip a root path only at a complete path-segment boundary so similarly prefixed routes still match. |

## Preserved artifacts

The active demonstration record is:

- [approved request](../runs/dev-v2/starlette-eighteen-two-repeat-v2/REQUEST.json)
  and [matching approval](../runs/dev-v2/starlette-eighteen-two-repeat-v2/APPROVED.json);
- [run seal](../runs/dev-v2/starlette-eighteen-two-repeat-v2/live-evidence/run-seal.json)
  and [execution manifest](../runs/dev-v2/starlette-eighteen-two-repeat-v2/live-evidence/execution-manifest.json);
- [raw attempts](../runs/dev-v2/starlette-eighteen-two-repeat-v2/live-evidence/attempts.jsonl),
  [pairs](../runs/dev-v2/starlette-eighteen-two-repeat-v2/live-evidence/pairs.jsonl),
  and [scheduler events](../runs/dev-v2/starlette-eighteen-two-repeat-v2/live-evidence/scheduler-events.jsonl);
- [final workspace evidence](../runs/dev-v2/starlette-eighteen-two-repeat-v2/live-evidence/workspaces/);
- [registered analysis](../runs/dev-v2/starlette-eighteen-two-repeat-v2/live-evidence/analysis.json);
  and
- [canonical Markdown report](../reports/STARLETTE_EIGHTEEN_TWO_REPEAT_V2_REPORT.md).

The execution manifest hashes the run records, analysis, seal, and every
workspace evidence file. The request binds the tasks, controls, ledgers,
containment/runtime components, runner, and statistical primitives.

## Reproduce without a model call

The top-level [README](../README.md#reproduce-everything-offline) is the
canonical quick-start. From the repository root, this equivalent sequence uses
only local files and the Python standard library:

```bash
DEMO_REPORT_DIR="$(mktemp -d)"
DEMO_REGENERATED_REPORT="$DEMO_REPORT_DIR/STARLETTE_EIGHTEEN_TWO_REPEAT_V2_REPORT.md"

PYTHONDONTWRITEBYTECODE=1 python3 -m tooling.starlette_demo verify-tasks
PYTHONDONTWRITEBYTECODE=1 python3 -m tooling.starlette_demo verify
PYTHONDONTWRITEBYTECODE=1 python3 -m tooling.starlette_demo report \
  --report-path "$DEMO_REGENERATED_REPORT"

cmp reports/STARLETTE_EIGHTEEN_TWO_REPEAT_V2_REPORT.md \
  "$DEMO_REGENERATED_REPORT"
```

The verifier checks the preserved request and approval, component and task
bindings, schedule and run seal, raw record hashes and invariants, all final
workspace evidence, and a fresh recomputation of the registered analysis. The
reporter runs that verifier again before it writes to the new output path. A
zero exit from `cmp` proves that reproduction matches the canonical report
byte-for-byte. No step checks authentication, uses the network, or invokes a
model.

## Frozen runner boundary

Replay and live execution are deliberately separate. The preserved v2 batch is
immutable and must not be overwritten or used as a new launch target.

The exact historical lifecycle implementation is
[`tooling/starlette_eighteen_task_experiment.py`](../tooling/starlette_eighteen_task_experiment.py).
It is retained because the approved request binds its bytes. The public
`tooling.starlette_demo` entry point exposes only task verification, evidence
verification, and report reproduction; it cannot launch subjects. Creating a
new live experiment or a configurable benchmark toolkit is outside this
repository's scope.
