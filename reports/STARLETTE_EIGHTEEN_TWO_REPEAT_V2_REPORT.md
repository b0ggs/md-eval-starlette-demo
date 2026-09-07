# Starlette 18-task MD/no-MD outcome report

## Pass/fail

- **MD: 2/36 failed; 34/36 passed.**
- **No-MD: 2/36 failed; 34/36 passed.**

## Every failure and reason

| Attempt | Task | Arm | Reason | Termination |
|---|---|---|---|---|
| pair-05-r2-a1-candidate | confirm-starlette-exception-context | MD | checker_unresolved | normal_incorrect_completion |
| pair-12-r1-a1-candidate | confirm-starlette-malformed-host | MD | checker_unresolved | normal_incorrect_completion |
| pair-12-r1-a2-control | confirm-starlette-malformed-host | No-MD | subject_timeout | subject_timeout |
| pair-12-r2-a1-control | confirm-starlette-malformed-host | No-MD | checker_unresolved | normal_incorrect_completion |

## Complete-task analysis: significant n=16 results

A task is eligible only when both paired repeats are usable, meaning both arms finished normally, were valid, and passed. Both repeats from every eligible task are analyzed; a lone surviving repeat is neither used nor displayed as a resource estimate.

| Endpoint | Eligible tasks | Effect (MD vs No-MD) | 95% CI | Two-sided p | Classification |
|---|---:|---:|---:|---:|---|
| Wall time | 16 | 41.8854% reduction | 32.3133%–50.1038% reduction | 1.6430678e-06 | **significantly favorable** |
| Tokens | 16 | 33.0927% reduction | 21.6050%–42.8970% reduction | 7.2894331e-05 | **significantly favorable** |

The effect is the geometric mean of task-level MD/No-MD ratios, shown as a percent reduction. Each task-level ratio compares arithmetic means across its two usable paired repeats. The confidence interval and two-sided p-value use the existing one-sample t procedure on task log ratios.

### Eligibility and exclusions

- Eligible: **16/18 tasks**, comprising 32 usable paired repeats.
- Excluded `confirm-starlette-exception-context`: 1/2 paired repeats usable — repeat 2 MD: checker_unresolved (normal_incorrect_completion).
- Excluded `confirm-starlette-malformed-host`: 0/2 paired repeats usable — repeat 1 MD: checker_unresolved (normal_incorrect_completion); repeat 1 No-MD: subject_timeout (subject_timeout); repeat 2 No-MD: checker_unresolved (normal_incorrect_completion).

### Historical registration disclosure

The stricter historically registered all-18 endpoint was unavailable and **not estimable** because fewer than two jointly normal and resolved pairs for at least one task. The complete-task n=16 rule and the results above were not historically preregistered; they are a post-hoc complete-task analysis.

## Execution context

Purpose: finite-known-set development replication; not the frozen v7 confirmation

- Correctness gate passes: true
- Attempts / pairs / invocations: 72 / 36 / 72
- Replacements / peak concurrency: 0 / 12

## Per-task outcomes

Negative change means MD used less of the resource. Resource estimates are shown only for tasks with both usable paired repeats.

| Task | MD pass | No-MD pass | Usable pairs | Wall MD / No-MD | Wall change | Token MD / No-MD | Token change |
|---|---:|---:|---:|---:|---:|---:|---:|
| full-starlette-websocket-denial | 2/2 | 2/2 | 2/2 | 393.8 / 699.7s | -43.7% | 53,220 / 91,277 | -41.7% |
| confirm-starlette-cors-origin | 2/2 | 2/2 | 2/2 | 234.1 / 302.4s | -22.6% | 27,184 / 48,783 | -44.3% |
| confirm-starlette-state-mapping | 2/2 | 2/2 | 2/2 | 446.8 / 519.6s | -14.0% | 82,992 / 55,908 | +48.4% |
| confirm-starlette-cors-private-network | 2/2 | 2/2 | 2/2 | 154.8 / 393.3s | -60.7% | 35,053 / 60,716 | -42.3% |
| confirm-starlette-exception-context | 1/2 | 2/2 | 1/2 | — | — | — | — |
| confirm-starlette-uploadfile-rollover | 2/2 | 2/2 | 2/2 | 202.6 / 327.2s | -38.1% | 37,329 / 55,634 | -32.9% |
| confirm-starlette-background-exception | 2/2 | 2/2 | 2/2 | 301.1 / 543.1s | -44.5% | 46,750 / 67,606 | -30.8% |
| confirm-starlette-http-disconnect | 2/2 | 2/2 | 2/2 | 111.5 / 341.7s | -67.4% | 24,224 / 42,787 | -43.4% |
| confirm-starlette-session-tracking | 2/2 | 2/2 | 2/2 | 278.6 / 516.6s | -46.1% | 41,696 / 67,034 | -37.8% |
| confirm-starlette-range-crlf | 2/2 | 2/2 | 2/2 | 365.6 / 474.8s | -23.0% | 50,678 / 55,938 | -9.4% |
| confirm-starlette-gzip-vary | 2/2 | 2/2 | 2/2 | 314.4 / 428.1s | -26.6% | 35,013 / 77,478 | -54.8% |
| confirm-starlette-malformed-host | 1/2 | 0/2 | 0/2 | — | — | — | — |
| confirm-starlette-ws-disconnected | 2/2 | 2/2 | 2/2 | 239.0 / 323.1s | -26.0% | 54,200 / 55,818 | -2.9% |
| confirm-starlette-debug-extension | 2/2 | 2/2 | 2/2 | 150.8 / 380.8s | -60.4% | 36,998 / 74,043 | -50.0% |
| confirm-starlette-suffix-range | 2/2 | 2/2 | 2/2 | 173.6 / 346.5s | -49.9% | 32,736 / 48,960 | -33.1% |
| confirm-starlette-form-context-cleanup | 2/2 | 2/2 | 2/2 | 297.2 / 556.1s | -46.5% | 41,712 / 68,080 | -38.7% |
| confirm-starlette-staticfiles-weak-etag | 2/2 | 2/2 | 2/2 | 229.1 / 280.5s | -18.3% | 30,764 / 37,070 | -17.0% |
| confirm-starlette-root-path-boundary | 2/2 | 2/2 | 2/2 | 147.7 / 281.8s | -47.6% | 28,133 / 53,596 | -47.5% |
