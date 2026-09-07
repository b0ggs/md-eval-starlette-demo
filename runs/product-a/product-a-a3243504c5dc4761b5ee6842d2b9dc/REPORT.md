MD: **4/36 failed; 32/36 passed.**

No-MD: **7/36 failed; 29/36 passed.**

# Product A: fresh Starlette MD versus No-MD report

## Failures

| Scope | Attempt | Task | Repeat | Arm | Reason | Mechanical code | Termination |
|---|---|---|---:|---|---|---|---|
| raw invocation | pair-07-r1-a1-control | confirm-starlette-background-exception | 1 | No-MD | subject exceeded the fixed execution timeout | subject_timeout | subject_timeout |
| raw invocation | pair-07-r2-a2-control | confirm-starlette-background-exception | 2 | No-MD | subject exceeded the fixed execution timeout | subject_timeout | subject_timeout |
| raw invocation | pair-05-r1-a2-candidate | confirm-starlette-exception-context | 1 | MD | mechanical checker did not resolve the task | checker_unresolved | normal_incorrect_completion |
| raw invocation | pair-12-r1-a1-candidate | confirm-starlette-malformed-host | 1 | MD | subject exceeded the fixed execution timeout | subject_timeout | subject_timeout |
| raw invocation | pair-12-r1-a2-control | confirm-starlette-malformed-host | 1 | No-MD | subject exceeded the fixed execution timeout | subject_timeout | subject_timeout |
| raw invocation | pair-12-r2-a2-candidate | confirm-starlette-malformed-host | 2 | MD | subject exceeded the fixed execution timeout | subject_timeout | subject_timeout |
| raw invocation | pair-12-r2-a1-control | confirm-starlette-malformed-host | 2 | No-MD | subject exceeded the fixed execution timeout | subject_timeout | subject_timeout |
| raw invocation | pair-03-r2-a1-control | confirm-starlette-state-mapping | 2 | No-MD | subject exceeded the fixed execution timeout | subject_timeout | subject_timeout |
| raw invocation | pair-01-r1-a2-control | full-starlette-websocket-denial | 1 | No-MD | subject exceeded the fixed execution timeout | subject_timeout | subject_timeout |
| raw invocation | pair-01-r2-a2-candidate | full-starlette-websocket-denial | 2 | MD | mechanical checker did not resolve the task | checker_unresolved | normal_incorrect_completion |
| raw invocation | pair-01-r2-a1-control | full-starlette-websocket-denial | 2 | No-MD | subject exceeded the fixed execution timeout | subject_timeout | subject_timeout |

## Eligible complete tasks

Eligible task count: **13/18**.

A task contributes only when both paired repeats pass jointly for MD and No-MD; a lone surviving repeat is never analyzed.

### Exclusions

| Task | Usable paired repeats | Reasons |
|---|---:|---|
| full-starlette-websocket-denial | 0/2 | repeat 2: No-MD did not pass: subject_timeout, No-MD token telemetry is missing or invalid, MD did not pass: checker_unresolved; repeat 1: No-MD did not pass: subject_timeout, No-MD token telemetry is missing or invalid |
| confirm-starlette-state-mapping | 1/2 | repeat 2: No-MD did not pass: subject_timeout, No-MD token telemetry is missing or invalid |
| confirm-starlette-exception-context | 1/2 | repeat 1: MD did not pass: checker_unresolved |
| confirm-starlette-background-exception | 0/2 | repeat 2: No-MD did not pass: subject_timeout, No-MD token telemetry is missing or invalid; repeat 1: No-MD did not pass: subject_timeout, No-MD token telemetry is missing or invalid |
| confirm-starlette-malformed-host | 0/2 | repeat 1: MD did not pass: subject_timeout, MD token telemetry is missing or invalid, No-MD did not pass: subject_timeout, No-MD token telemetry is missing or invalid; repeat 2: No-MD did not pass: subject_timeout, No-MD token telemetry is missing or invalid, MD did not pass: subject_timeout, MD token telemetry is missing or invalid |

## Complete-task inference

Negative resource change favors MD.

| Endpoint | Eligible tasks | Effect (MD vs No-MD) | 95% change CI | Two-sided p | Classification |
|---|---:|---:|---:|---:|---|
| Wall | 13 | -46.3731% | -53.8057%–-37.7445% | 9.8247125e-07 | **significantly favorable** |
| Token | 13 | -35.3073% | -45.2952%–-23.4958% | 0.00010583914 | **significantly favorable** |
