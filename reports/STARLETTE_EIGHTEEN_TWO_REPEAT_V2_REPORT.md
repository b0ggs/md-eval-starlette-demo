# Starlette 18-task MD/no-MD outcome report

Purpose: finite-known-set development replication; not the frozen v7 confirmation

## Correctness and execution

- MD resolved: 34/36
- No MD resolved: 34/36
- Correctness gate passes: true
- Attempts / pairs / invocations: 72 / 36 / 72
- Replacements / peak concurrency: 0 / 12

## Per-task outcomes

Negative change means MD used less of the resource.

| Task | MD | No MD | Usable pairs | Wall MD / No MD | Wall change | Token MD / No MD | Token change |
|---|---:|---:|---:|---:|---:|---:|---:|
| full-starlette-websocket-denial | 2/2 | 2/2 | 2/2 | 393.8 / 699.7s | -43.7% | 53,220 / 91,277 | -41.7% |
| confirm-starlette-cors-origin | 2/2 | 2/2 | 2/2 | 234.1 / 302.4s | -22.6% | 27,184 / 48,783 | -44.3% |
| confirm-starlette-state-mapping | 2/2 | 2/2 | 2/2 | 446.8 / 519.6s | -14.0% | 82,992 / 55,908 | +48.4% |
| confirm-starlette-cors-private-network | 2/2 | 2/2 | 2/2 | 154.8 / 393.3s | -60.7% | 35,053 / 60,716 | -42.3% |
| confirm-starlette-exception-context | 1/2 | 2/2 | 1/2 | 270.5 / 611.6s | -55.8% | 30,564 / 70,399 | -56.6% |
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

Resource means for tasks with fewer than two usable pairs are descriptive only.

## Failures and timeouts

| Attempt | Task | Arm | Reason | Termination |
|---|---|---|---|---|
| pair-05-r2-a1-candidate | confirm-starlette-exception-context | MD | checker_unresolved | normal_incorrect_completion |
| pair-12-r1-a1-candidate | confirm-starlette-malformed-host | MD | checker_unresolved | normal_incorrect_completion |
| pair-12-r1-a2-control | confirm-starlette-malformed-host | No MD | subject_timeout | subject_timeout |
| pair-12-r2-a1-control | confirm-starlette-malformed-host | No MD | checker_unresolved | normal_incorrect_completion |

## Registered primary analysis

- Wall: **inconclusive** — fewer than two jointly normal and resolved pairs for at least one task
- Token: **inconclusive** — fewer than two jointly normal and resolved pairs for at least one task

## Post-hoc exploratory complete-case sensitivity

This does not replace the registered primary analysis.

| Endpoint | Tasks | Reduction | 95% reduction CI | t (df) | Two-sided p | Result |
|---|---:|---:|---:|---:|---:|---|
| Wall | 16 | 41.8854% | 32.3133%–50.1038% | -7.587268 (15) | 1.6430678e-06 | Significant |
| Token | 16 | 33.0927% | 21.6050%–42.8970% | -5.405728 (15) | 7.2894331e-05 | Significant |
