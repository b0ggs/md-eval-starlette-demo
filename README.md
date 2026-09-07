# MD Eval: Starlette demonstration

This repository is a self-contained, offline-reproducible case study of whether
a repository instruction file helped the same coding model solve the same
Starlette tasks. It contains the 18 task fixtures, frozen controls, raw run
evidence, integrity bindings, analysis, and report code needed to inspect the
experiment without credentials, network access, or model calls.

This is the standalone demonstration only. It is not an instruction optimizer,
a hosted benchmark, or a configurable toolkit for new experiments.

## Fresh Product A result

The fixed Product A workflow completed a new approved run on September 6,
2026. It made exactly 72 fresh subject calls across all 18 tasks, with zero
replacements and observed peak concurrency of 12. The
[generated report](runs/product-a/product-a-28d43ee1189e43c7a2b987689aa923/REPORT.md),
[approved request](runs/product-a/product-a-28d43ee1189e43c7a2b987689aa923/REQUEST.json),
and [raw evidence](runs/product-a/product-a-28d43ee1189e43c7a2b987689aa923/live-evidence/)
are preserved together. The request SHA-256 is
`2fde00f0154c9051a692414c9a55df04f86e2b59e241d07e533ba0f9d95027eb`;
the generated report SHA-256 is
`4909adaf1dcb63bf908f35dce688a255d02a7441f893b33df4aa7de5aa2d9a28`.

| Arm | Failed | Passed |
|---|---:|---:|
| MD | **4/36** | 32/36 |
| No-MD | **2/36** | 34/36 |

The report lists all six failed attempts and their mechanical reasons. Fourteen
tasks had both usable paired repeats; the other four tasks were excluded in
full, so no lone surviving repeat entered either resource analysis.

| Endpoint | Eligible tasks | Reduction with MD | 95% reduction CI | Two-sided p | Classification |
|---|---:|---:|---:|---:|---|
| Wall time | 14 | 52.1051% | 44.8225%–58.4265% | 4.5821128e-08 | **Significantly favorable** |
| Tokens | 14 | 36.0641% | 28.2553%–43.0229% | 1.3304513e-06 | **Significantly favorable** |

These resource results use the complete-task rule frozen in the approved
request before launch. They do not override the top-level correctness result:
MD had four failed attempts and No-MD had two.

An [earlier prepared request](runs/product-a/product-a-b909824f58ec4029b2e63cb74c12a8/)
was approved and consumed but produced no execution-evidence directory and
made zero subject calls. Its request, approval, and one-use consumption record
are retained for auditability but are not part of the experimental results
above.

## Running results

[RESULTS.md](RESULTS.md) is the automatically generated dashboard for all
completed, verified fresh Product A runs in this checkout. It totals attempts,
failures, and paired correctness outcomes by arm; lists every failure by run,
task, repeat, and reason; and shows each run's existing wall-time and token
effect, confidence interval, p-value, eligible-task count, exclusions, and
classification.

The cumulative section is descriptive. It does not pool p-values, invent a
cross-run significance test, or treat the number of individually significant
runs as evidence. The bundled historical experiment is displayed separately
and is not included in the fresh cumulative totals. Approved launches that
made no model calls are disclosed but are not counted as experiments.

## Historical example: what was tested

The experiment compared the frozen
[MD control](controls/coder/evidence-bounded-v1.md) with an empty
[No-MD control](controls/coder/null-m2.md). Both arms used `gpt-5.6-sol` at the
high reasoning setting with the same coding harness, task bytes, and mechanical
checker policy. Each of 18 mechanically admitted Starlette tasks received two
paired repetitions with reversed arm order.

The design asks a narrow practical question: on this known task set, did the
instruction file improve correctness or reduce the resources used by the same
model? Every attempt—including incorrect completions and one timeout—remains
in the preserved evidence.

| Design or outcome | Preserved result |
|---|---:|
| Tasks | 18 |
| Paired repeats per task | 2 |
| Atomic pairs | 36 |
| Subject invocations | 72 |
| Peak concurrency | 12 |
| Replacements | 0 |
| Failed attempts | MD 2/36; No MD 2/36 |
| Passed attempts | MD 34/36; No MD 34/36 |

In total, the experiment made 72 subject-model calls (72 recorded subject
invocations), with no replacement calls.

## Historical example: results

### Failures first

The historical run had **2 failures in 36 attempts per arm** (34/36 passed in
each arm). All four failures remain in the evidence:

| Task | Arm | Failure |
|---|---|---|
| `confirm-starlette-exception-context` | MD | Checker unresolved after a normal completion |
| `confirm-starlette-malformed-host` | MD | Checker unresolved after a normal completion |
| `confirm-starlette-malformed-host` | No MD | Subject timeout |
| `confirm-starlette-malformed-host` | No MD | Checker unresolved after a normal completion |

### Complete-task analysis

The analysis retains a task only when **both** of its paired repeats are usable
in both arms; it never uses a lone surviving repeat. Sixteen tasks met that
rule, contributing 32 usable pairs. Both estimated resource effects are
statistically significantly favorable to MD.

| Endpoint | Eligible tasks | Reduction | 95% reduction CI | df | Two-sided p | Result |
|---|---:|---:|---:|---:|---:|---|
| Wall time | 16 | 41.8854% | 32.3133%–50.1038% | 15 | 1.6430678e-06 | **Significantly favorable** |
| Tokens | 16 | 33.0927% | 21.6050%–42.8970% | 15 | 7.2894331e-05 | **Significantly favorable** |

Historical registration disclosure: the stricter all-18 registered endpoint
was unavailable because it required both usable repeats for every task.
The 16-task complete-task analysis shown above was not historically
preregistered; it was selected after outcomes were known. That limitation does
not make its estimable, statistically significant result “inconclusive.”

The [canonical report](reports/STARLETTE_EIGHTEEN_TWO_REPEAT_V2_REPORT.md)
contains per-task correctness and resource measurements. The
[case study](docs/starlette-demonstration.md) explains the method, failures,
artifact structure, and interpretation in detail.

## Task categories

The public descriptions summarize issue contracts without exposing hidden
checker details or reference-solution structure.

| Area | Count | Examples |
|---|---:|---|
| ASGI and WebSocket lifecycle | 3 | WebSocket denial responses, HTTP disconnect handling, disconnected WebSocket API states |
| Middleware policy and response semantics | 4 | CORS origins, private-network preflights, session tracking, gzip negotiation |
| Exceptions and resource lifetime | 3 | Exception chaining, background-task failures, form/upload cleanup |
| Files, byte ranges, and cache validators | 4 | Upload rollover, multipart ranges, suffix ranges, weak ETags |
| State, routing, authority, and client integration | 4 | Lifespan state, malformed Host handling, root-path boundaries, TestClient debug metadata |

See [the complete 18-task taxonomy](docs/starlette-demonstration.md#the-18-tasks)
for every task ID and a one-sentence description.

## Run a fresh fixed Product A experiment

From the repository root, the normal workflow is one command:

```bash
python3 run_product_a.py
```

It checks readiness without calling a model, shows the fixed experiment and
its exact request hash, then waits for one explicit confirmation before any
paid calls.

### Before the first live run

A fresh experiment requires:

- Git, Python 3.10 or newer, and a running `linux/amd64` Docker daemon.
- A Codex account with access to `gpt-5.6-sol` and a file-based Codex login at
  `~/.codex/auth.json`. Run `codex login`; if your installation uses the OS
  keyring, set `cli_auth_credentials_store = "file"` in
  `~/.codex/config.toml` and log in again. Treat `auth.json` like a password.

The host Codex CLI is used only to establish that login. The experiment runs
the checksum-pinned Codex 0.153.4 binary inside its fixed containers. It never
places credentials in a build context or image layer; a temporary copy is
mounted only for isolated readiness checks and approved execution, never into
the task workspace or preserved evidence.

On first use, the command offers to pull three immutable public image digests
and extract the pinned Python 3.11.5 tree into the user's cache. Entering
anything other than `y` or `yes` declines and exits before creating a request.
Later runs verify and reuse those artifacts. If Docker is installed at a
nonstandard path, set `MDSEVAL_DOCKER` to its executable.

### What the command does

After the runtime and login are ready, the command creates a new, unapproved
request, prints its run directory and SHA-256, and performs a bounded,
zero-model-call readiness check. If readiness passes, it prints the key fixed
design parameters; `REQUEST.json` contains the complete binding:

- 18 bundled tasks and the bundled MD versus empty No-MD control.
- Two paired repeats per task: 36 attempts per arm and 72 planned calls.
- `gpt-5.6-sol` with high reasoning.
- Maximum concurrency 12, with a hard ceiling of 80 model calls.

It then asks exactly once:

```text
Proceed with up to 80 live model calls? Type YES to continue [NO]:
```

Only the full word `YES`, case-insensitively, approves the displayed request.
Pressing Enter, sending end-of-file, or entering anything else leaves the
request unapproved, makes no model calls, and exits successfully. After `YES`,
the command binds approval to that request hash, runs the sealed experiment,
verifies the evidence, writes the run report, and refreshes
[RESULTS.md](RESULTS.md). The terminal may be quiet for long stretches after
approval; leave it running. A completed example took about 52 minutes, though
actual runtime and account charges vary.

Each invocation creates a new `runs/product-a/product-a-<nonce>/` directory.
A successful run contains:

- `REQUEST.json`, `APPROVED.json`, and `CONSUMED_APPROVAL.json` for its
  authorization trail.
- `live-evidence/` with the sealed raw evidence and `analysis.json`.
- `REPORT.md` with that run's failures-first correctness summary and resource
  analysis.

Normal failed task attempts are experimental results: they remain in the
evidence, appear in `REPORT.md`, and count in `RESULTS.md`. Review raw evidence,
which includes model event streams and workspace changes, before sharing it.

### Failure recovery

If readiness fails, the command exits before the approval question and makes
no model calls. Fix the reported prerequisite and run the command again; the
abandoned request remains unapproved and is not counted in `RESULTS.md`.

For defense in depth, the sealed runner repeats readiness after approval. Once
approved, the request is consumed before that final check or any model call.
If that final readiness check fails or live execution is incomplete, the
command exits nonzero and preserves the available artifacts. The consumed run
cannot be resumed or extended; inspect the failure, correct it, and invoke
`python3 run_product_a.py` again for a complete fresh experiment.

Do not launch another paid run when execution already completed and only a
later local step failed. If `live-evidence/execution-manifest.json` says
`"status": "complete"` but `REPORT.md` is absent, finish the existing run with:

```bash
python3 run_product_a.py --verify-report RUN_DIRECTORY
```

If `REPORT.md` already exists and only the root dashboard refresh failed, run:

```bash
python3 -m tooling.starlette_product_a_results
```

Only completed runs that pass evidence verification are added to `RESULTS.md`.

### Frozen v1 audit workflow

The public runtime keeps prepare, hash-bound approval, execution, and reporting
inside the one command so a new user does not need to shuttle paths and hashes
between commands. The four commands below remain available to inspect the
checkpointed v1 lifecycle and its historical local runtime; they are not the
portable v2 launch path.

```bash
python3 -m tooling.starlette_product_a prepare
python3 -m tooling.starlette_product_a approve RUN_DIRECTORY REQUEST_SHA256
python3 -m tooling.starlette_product_a run RUN_DIRECTORY
python3 -m tooling.starlette_product_a verify-report RUN_DIRECTORY
```

The `approve` step is an explicit authorization for those exact request bytes.
`run` consumes the approval before preflight or backend work, so it cannot be
reused, including after a failed launch attempt. Starting over requires another
`prepare` and therefore a new directory, request, hash, and approval.

Every approved run attempts the complete fixed design: 18 tasks, two paired
repeats per task, and both MD and No-MD arms in every repeat. That is 36 atomic
pairs and 72 planned fresh model calls. Subject concurrency is capped at 12;
up to four qualifying whole-pair replacements may add eight calls, and the hard
ceiling is 80 subject invocations. The controls are the bundled MD and empty
No-MD files, and both arms use `gpt-5.6-sol` with high reasoning.

`verify-report` verifies the sealed evidence and writes the run's Markdown
report to `RUN_DIRECTORY/REPORT.md`; raw evidence remains under
`RUN_DIRECTORY/live-evidence/`. The report starts with failure/pass counts for
each arm across the 36 terminal repeat outcomes and lists every failed raw
invocation with its reason, including a failure later superseded by a permitted
replacement. Efficiency analysis includes only tasks for which both paired
repeats are usable in both arms. A task with one usable repeat and one failed
repeat is excluded rather than contributing the lone survivor. For each
endpoint the report gives the eligible task count, exclusions, effect,
confidence interval, p-value, and one of the four fixed classifications:
significantly favorable, significantly unfavorable, nonsignificant, or not
estimable.

Refresh the root dashboard independently, without launching a model, with:

```bash
python3 -m tooling.starlette_product_a_results
```

Within the lower-level lifecycle, only `run` can invoke the live backend. Do
not execute it unless you intend to authorize and pay for a fresh
72-to-80-call experiment. CI never invokes `approve` or `run`; it covers the
lifecycle with injected offline fakes.

A fork can run its own local replications with the same one-command workflow
once all prerequisites are available. Importing third-party run directories or
automatically contributing fork results to an upstream tally is not supported;
`RESULTS.md` summarizes only the verified runs in its own checkout.

## Reproduce the historical example offline

Requirements: Git and Python 3.10 or newer. The demonstration code uses only
the Python standard library. From the repository root, run:

```bash
python3 -m unittest discover -s tests -v
python3 -m tooling.starlette_demo verify-tasks
python3 -m tooling.starlette_demo verify
```

`verify-tasks` calls the frozen `taskcheck` once for each included fixture and
runs its pristine and arm-neutrality checker probes. The work is parallelized
locally but every fixture receives an independent taskcheck result.
`verify` checks the approved request, task and component bindings, controls,
contamination specification, schedule, run seal, raw records, all final
workspace evidence, and a fresh recomputation of the registered analysis. Its
expected result is:

```json
{"attempt_records": 72, "base_pairs": 36, "pair_records": 36, "peak": 12, "replacement_pairs": 0, "subject_invocations": 72}
```

Regenerate the report at a new temporary path, prove byte identity, and confirm
its SHA-256:

```bash
DEMO_REPORT_DIR="$(mktemp -d)"
DEMO_REPORT="$DEMO_REPORT_DIR/STARLETTE_EIGHTEEN_TWO_REPEAT_V2_REPORT.md"

python3 -m tooling.starlette_demo report --report-path "$DEMO_REPORT"
cmp reports/STARLETTE_EIGHTEEN_TWO_REPEAT_V2_REPORT.md "$DEMO_REPORT"
python3 -c 'from hashlib import sha256; from pathlib import Path; print(sha256(Path("reports/STARLETTE_EIGHTEEN_TWO_REPEAT_V2_REPORT.md").read_bytes()).hexdigest())'
```

The expected digest is
`ee7042110ed9dee2fae4346886716722fad0edc638dd991ba853fb001516bf17`.
A successful `cmp` prints nothing and exits zero. These commands do not inspect
authentication, access the network, or invoke a model.

## Repository map

- `run_product_a.py` — one-command readiness, confirmation, execution,
  verification, and dashboard workflow for a fresh fixed run.
- `RESULTS.md` — generated descriptive tally of verified fresh runs, with the
  bundled historical example kept separate.
- `docs/starlette-demonstration.md` — detailed case study and task taxonomy.
- `runs/product-a/product-a-28d43ee1189e43c7a2b987689aa923/` — current
  fresh Product A request, approval, verified evidence, analysis, and report.
- `reports/STARLETTE_EIGHTEEN_TWO_REPEAT_V2_REPORT.md` — bundled historical v2
  report.
- `tasks/` — exactly the 18 demonstrated fixtures plus their integrity ledgers.
- `runs/dev-v2/starlette-eighteen-two-repeat-v2/` — bundled historical approved
  request and raw, hash-anchored experiment evidence.
- `controls/` — the MD and empty No-MD controls used in the experiment.
- `tooling/starlette_demo.py` — offline-only public verification and report
  reproduction entry point for the historical example.
- `tooling/starlette_product_a.py` — fixed prepare, approve, run, and
  verify/report lifecycle for fresh Product A experiments.
- `runtime/product-a-v2/` — auditable fixed-image recipe, dependency notices,
  and immutable public runtime lock.
- `tooling/starlette_product_a_runtime.py` — first-use acquisition and the
  temporary v2 binding around the frozen v1 lifecycle.
- `tooling/starlette_product_a_results.py` — offline dashboard generator for
  verified Product A results.
- `tooling/`, `scripts/`, and `src/` — the minimal frozen implementation and
  import closure needed to validate the preserved run.

The source-wide task and exposure ledgers are retained byte-for-byte because
the approved request hashes them. The separate 18-entry demonstration ledger
lets `taskcheck` validate this intentionally restricted fixture set without
copying any unrelated task directories.

## Provenance and limitations

The task fixtures, controls, bundled historical evidence, and historically
request-bound implementation files were copied byte-for-byte from the
authoritative `MDs_EVAL` source at commit
`6e8e985318203f3818fefad07e3a9b43a7a9e300`. The Product A lifecycle and fresh
evidence were created in this repository, which has independent Git history.

The bundled historical run was a finite-known-set development replication. It
was not the frozen v7 confirmation. Equal historical correctness does not
establish equivalence, and its post-hoc analysis may be affected by selection,
task familiarity, shared harness behavior, or properties of this model and task
distribution. Neither the historical result nor the fresh Product A result
should be generalized to other models, repositories, instruction files, or
task populations.

The frozen historical live-run implementation is retained only because its
request binds the exact bytes. `tooling.starlette_demo` remains an offline-only
entry point for the preserved run. Fresh execution is isolated in the fixed
`tooling.starlette_product_a` lifecycle described above, and CI never launches
subjects.

## License

Original demonstration code and documentation are released under the
[MIT License](LICENSE). The embedded Starlette fixture copies retain their
original BSD license notices in every `public`, `blind`, and `reference` tree;
those notices continue to govern the corresponding upstream material.
