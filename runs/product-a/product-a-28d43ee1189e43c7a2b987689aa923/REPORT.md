MD: **4/36 failed; 32/36 passed.**

No-MD: **2/36 failed; 34/36 passed.**

# Product A: fresh Starlette MD versus No-MD report

## Failures

| Scope | Attempt | Task | Repeat | Arm | Reason | Mechanical code | Termination |
|---|---|---|---:|---|---|---|---|
| raw invocation | pair-04-r2-a1-candidate | confirm-starlette-cors-private-network | 2 | MD | mechanical checker did not resolve the task | checker_unresolved | normal_incorrect_completion |
| raw invocation | pair-05-r1-a2-candidate | confirm-starlette-exception-context | 1 | MD | mechanical checker did not resolve the task | checker_unresolved | normal_incorrect_completion |
| raw invocation | pair-05-r1-a1-control | confirm-starlette-exception-context | 1 | No-MD | mechanical checker did not resolve the task | checker_unresolved | normal_incorrect_completion |
| raw invocation | pair-12-r1-a1-candidate | confirm-starlette-malformed-host | 1 | MD | mechanical checker did not resolve the task | checker_unresolved | normal_incorrect_completion |
| raw invocation | pair-01-r1-a2-control | full-starlette-websocket-denial | 1 | No-MD | mechanical checker did not resolve the task | checker_unresolved | normal_incorrect_completion |
| raw invocation | pair-01-r2-a2-candidate | full-starlette-websocket-denial | 2 | MD | mechanical checker did not resolve the task | checker_unresolved | normal_incorrect_completion |

## Eligible complete tasks

Eligible task count: **14/18**.

A task contributes only when both paired repeats pass jointly for MD and No-MD; a lone surviving repeat is never analyzed.

### Exclusions

| Task | Usable paired repeats | Reasons |
|---|---:|---|
| full-starlette-websocket-denial | 0/2 | repeat 2: MD did not pass: checker_unresolved; repeat 1: No-MD did not pass: checker_unresolved |
| confirm-starlette-cors-private-network | 1/2 | repeat 2: MD did not pass: checker_unresolved |
| confirm-starlette-exception-context | 1/2 | repeat 1: No-MD did not pass: checker_unresolved, MD did not pass: checker_unresolved |
| confirm-starlette-malformed-host | 1/2 | repeat 1: MD did not pass: checker_unresolved |

## Complete-task inference

Negative resource change favors MD.

| Endpoint | Eligible tasks | Effect (MD vs No-MD) | 95% change CI | Two-sided p | Classification |
|---|---:|---:|---:|---:|---|
| Wall | 14 | -52.1051% | -58.4265%–-44.8225% | 4.5821128e-08 | **significantly favorable** |
| Token | 14 | -36.0641% | -43.0229%–-28.2553% | 1.3304513e-06 | **significantly favorable** |
