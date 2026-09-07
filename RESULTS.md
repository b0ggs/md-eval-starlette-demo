# Product A results

## Verified fresh runs: correctness tally

MD: **4/36 failed; 32/36 passed (11.1% failure).**

No-MD: **2/36 failed; 34/36 passed (5.6% failure).**

Counted replications: **1**.

These totals are descriptive. Resource effects, confidence intervals, and p-values are shown per run only; they are not pooled into a cross-run significance claim.

### Paired correctness outcomes

| Both passed | Both failed | MD-only failed | No-MD-only failed | Total pairs |
|---:|---:|---:|---:|---:|
| 31 | 1 | 3 | 1 | 36 |

`MD-only failed` means No-MD passed that pair; `No-MD-only failed` means MD passed.

### Run ledger

| Run | Created (UTC) | MD | No-MD | Both pass / both fail / MD-only fail / No-MD-only fail | Report |
|---:|---|---:|---:|---:|---|
| 1 (`product-a-28d43ee1189e43c7a2b987689aa923`) | 2026-09-06T11:41:20.030275+00:00 | 4/36 failed | 2/36 failed | 31 / 1 / 3 / 1 | [REPORT.md](runs/product-a/product-a-28d43ee1189e43c7a2b987689aa923/REPORT.md) |

## Every fresh-run failure

| Run | Scope | Attempt | Task | Repeat | Arm | Reason | Mechanical code | Termination |
|---:|---|---|---|---:|---|---|---|---|
| 1 | raw invocation | pair-04-r2-a1-candidate | confirm-starlette-cors-private-network | 2 | MD | mechanical checker did not resolve the task | checker_unresolved | normal_incorrect_completion |
| 1 | raw invocation | pair-05-r1-a2-candidate | confirm-starlette-exception-context | 1 | MD | mechanical checker did not resolve the task | checker_unresolved | normal_incorrect_completion |
| 1 | raw invocation | pair-05-r1-a1-control | confirm-starlette-exception-context | 1 | No-MD | mechanical checker did not resolve the task | checker_unresolved | normal_incorrect_completion |
| 1 | raw invocation | pair-12-r1-a1-candidate | confirm-starlette-malformed-host | 1 | MD | mechanical checker did not resolve the task | checker_unresolved | normal_incorrect_completion |
| 1 | raw invocation | pair-01-r1-a2-control | full-starlette-websocket-denial | 1 | No-MD | mechanical checker did not resolve the task | checker_unresolved | normal_incorrect_completion |
| 1 | raw invocation | pair-01-r2-a2-candidate | full-starlette-websocket-denial | 2 | MD | mechanical checker did not resolve the task | checker_unresolved | normal_incorrect_completion |

## Per-run complete-task resource results

Negative change favors MD. Each row is the run's existing frozen analysis; no cross-run effect or p-value is calculated here.

| Run | Endpoint | Eligible tasks | Effect (MD vs No-MD) | 95% change CI | Two-sided p | Classification |
|---:|---|---:|---:|---:|---:|---|
| 1 | Wall | 14 | -52.1051% | -58.4265% to -44.8225% | 4.5821128e-08 | **significantly favorable** |
| 1 | Token | 14 | -36.0641% | -43.0229% to -28.2553% | 1.3304513e-06 | **significantly favorable** |

### Fresh-run exclusions

| Run | Task | Usable paired repeats | Reasons |
|---:|---|---:|---|
| 1 | full-starlette-websocket-denial | 0/2 | repeat 2: MD did not pass: checker_unresolved; repeat 1: No-MD did not pass: checker_unresolved |
| 1 | confirm-starlette-cors-private-network | 1/2 | repeat 2: MD did not pass: checker_unresolved |
| 1 | confirm-starlette-exception-context | 1/2 | repeat 1: No-MD did not pass: checker_unresolved, MD did not pass: checker_unresolved |
| 1 | confirm-starlette-malformed-host | 1/2 | repeat 1: MD did not pass: checker_unresolved |

### Reproducibility fingerprints

| Run | Request SHA-256 | Analysis-rule SHA-256 | Runner SHA-256 | Subject invocations |
|---:|---|---|---|---:|
| 1 | `2fde00f0154c9051a692414c9a55df04f86e2b59e241d07e533ba0f9d95027eb` | `26592fbfc0b7f0c6ea87d63c62173dfea39c3cfc80dd4723bcc3df1bb0fd5508` | `8a5c5be505508d0af2351cb96ea4769efeb7504f6f4b55b0d7003d41973cd854` | 72 |

## Prepared or uncounted Product A requests

| Run | Created (UTC) | State | Request |
|---|---|---|---|
| `product-a-b909824f58ec4029b2e63cb74c12a8` | 2026-09-06T11:34:41.928266+00:00 | approval consumed during preflight; zero subject calls recorded; **not counted** | [REQUEST.json](runs/product-a/product-a-b909824f58ec4029b2e63cb74c12a8/REQUEST.json) |

## Bundled historical example (separate; not pooled)

MD: **2/36 failed; 34/36 passed (5.6% failure).**

No-MD: **2/36 failed; 34/36 passed (5.6% failure).**

Eligible complete tasks: **16/18**.

| Endpoint | Eligible tasks | Effect (MD vs No-MD) | 95% CI | Two-sided p | Classification |
|---|---:|---:|---:|---:|---|
| Wall | 16 | 41.8854% reduction | 32.3133% to 50.1038% reduction | 1.6430678e-06 | **significantly favorable** |
| Token | 16 | 33.0927% reduction | 21.6050% to 42.8970% reduction | 7.2894331e-05 | **significantly favorable** |

The historical all-18 registered endpoint was unavailable. Its n=16 complete-task analysis was not historically preregistered, so it remains a labeled post-hoc example.

See the [full historical report](reports/STARLETTE_EIGHTEEN_TWO_REPEAT_V2_REPORT.md) for its failures, exclusions, and per-task results.

## Statistical guardrail

This dashboard totals correctness outcomes only. It does **not** pool p-values, combine confidence intervals, count significant runs as proof, or introduce a new cross-run hypothesis test. A formal cross-run method can be selected separately before using future runs for confirmatory inference.
