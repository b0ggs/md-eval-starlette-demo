# MD Eval: Starlette demonstration

**Can a short set of [MD instructions](controls/coder/evidence-bounded-v1.md) help an LLM (codex 5.6 sol) work faster and use fewer resources while still passing the same tests?**

This project compares the same coding tasks with and without MD instructions.
The MD instructions are succinct and give information about where to look, what
to test, and when to stop. This repo includes the results and detailed records
so you can check the findings without running the AI again.

The fixed experiment uses 18 real Starlette tasks. You can rerun it with one
command or verify the included evidence completely offline.

## Latest result

The latest verified experiment ran all 18 tasks twice in each condition. That
produced 36 attempts with the MD, 36 attempts without it, and 72 model calls in
total.

### How often did each condition fail?

| Condition | Failed | Passed |
|---|---:|---:|
| With the MD instructions | **4/36** | 32/36 |
| Without the MD instructions | **7/36** | 29/36 |

The MD condition had three fewer failed attempts in this run. These are observed
counts; no statistical test was performed on the difference in correctness.

### Did the MD reduce time and tokens?

Thirteen tasks had complete results for both conditions in both repeats. The
other five tasks were excluded from this analysis rather than using only a
surviving repeat.

| Measure | Change with the MD | 95% confidence interval | p-value |
|---|---:|---:|---:|
| Wall-clock time | **46.4% lower** | 37.7%–53.8% lower | 0.00000098 |
| Tokens used | **35.3% fewer** | 23.5%–45.3% fewer | 0.000106 |

Both reductions were statistically significant under the analysis rule fixed
before the run. Here, “lower” and “fewer” always mean compared with the matched
runs without the MD instructions.

Across the two completed fresh experiments, the MD condition failed 8 of 72
attempts and the No-MD condition failed 9 of 72. Those cumulative failure counts
are descriptive. Time and token statistics are calculated separately for each
experiment rather than pooled across runs.

[Read the latest report](runs/product-a/product-a-a3243504c5dc4761b5ee6842d2b9dc/REPORT.md)
or [see every verified run](RESULTS.md).

## How the experiment stays controlled

```text
public task + MD or empty file
        → isolated model workspace
        → preserved events and file changes
        → separate offline checker
        → verified report
```

Each attempt begins with a fresh temporary copy of only the public task files.
The runner adds either the MD instructions or an empty file, creates a clean Git
baseline, and starts the model. The model never receives the reference solution
or the private checker.

The attempt runs inside a checksum-pinned container:

- The task code is writable, while its Git metadata and the Python runtime are
  read-only.
- Commands run by the model cannot reach the network, credentials, host
  configuration, or evaluator output.
- Only the Codex client can reach the model API, through an allowlisted proxy.
- Web search, apps, plugins, MCP tools, skills, and subagents are disabled.

Before any paid calls, the runner actively tests these boundaries and verifies
the exact runtime identities. It stops if a forbidden operation succeeds or a
runtime hash differs.

After the model finishes, a separate container with no network access adds the
private tests and runs the mechanical checker twice. A disagreement is rejected
as nondeterministic. The runner preserves the model events, file changes,
checker result, timing, token counts, and file hashes for later inspection.

## Run the experiment

### Requirements

- Git and Python 3.10 or newer.
- A running Docker daemon capable of running `linux/amd64` containers.
- The Codex CLI, used to establish the local login.
- A Codex account with access to `gpt-5.6-sol`.
- A file-based Codex login at `~/.codex/auth.json`.

Run `codex login` first. If Codex stores credentials in the OS keyring, set
`cli_auth_credentials_store = "file"` in `~/.codex/config.toml` and log in
again. Treat `auth.json` like a password. If Docker is installed at a
nonstandard path, set `MDSEVAL_DOCKER` to its executable.

Then, from the repository root, run:

```bash
python3 run_product_a.py
```

On first use, the command offers to download and verify three immutable public
container images and a pinned Python 3.11.5 runtime. Declining exits before a
request is created or a model is called. Later runs reuse the verified local
runtime.

When readiness passes, the command displays the exact request hash and design:

```text
18 tasks · 72 planned calls · 80 maximum
gpt-5.6-sol · high reasoning · maximum concurrency 12

Proceed with up to 80 live model calls? Type YES to continue [NO]:
```

Only `YES` approves the displayed request. Anything else exits without model
calls. Approval is bound to that exact request hash and can be used only once.

The experiment normally makes 72 calls. Up to four whole-pair replacements are
allowed only for qualifying infrastructure failures, giving a hard ceiling of
80 calls. Scientific failures are preserved, not selectively retried.

When the run finishes, the command verifies its evidence, writes `REPORT.md` in
the new run directory, and refreshes [RESULTS.md](RESULTS.md). The latest run
took about 69 minutes after approval; runtime and account charges vary.

### If something stops

A readiness failure happens before approval and makes no model calls. An
incomplete approved run is preserved but cannot be resumed or selectively
retried. If execution finished but its report is missing, recover it without
another experiment:

```bash
python3 run_product_a.py --verify-report RUN_DIRECTORY
```

Only completed runs whose evidence verifies are included in `RESULTS.md`.

## Verify the included evidence offline

These commands require only Git and Python 3.10 or newer. They do not inspect
authentication, use the network, or call a model.

```bash
python3 -m tooling.starlette_demo verify-tasks
python3 -m tooling.starlette_demo verify
python3 -m tooling.starlette_demo report --report-path /tmp/starlette-report.md
cmp reports/STARLETTE_EIGHTEEN_TWO_REPEAT_V2_REPORT.md /tmp/starlette-report.md
python3 -m unittest discover -s tests -v
```

These commands verify the 18 tasks, all 72 attempt records, 36 pairs, final
workspaces, analysis, and byte-identical historical report.

## What the 18 tasks cover

| Area | Tasks | Examples |
|---|---:|---|
| ASGI and WebSocket lifecycle | 3 | WebSocket denial, HTTP disconnects, disconnected WebSocket states |
| Middleware and response behavior | 4 | CORS, private-network preflights, sessions, gzip negotiation |
| Exceptions and resource lifetime | 3 | Exception chaining, background failures, form/upload cleanup |
| Files, ranges, and cache validators | 4 | Upload rollover, multipart ranges, suffix ranges, weak ETags |
| State, routing, and client integration | 4 | Lifespan state, malformed hosts, root paths, TestClient metadata |

[See all 18 task descriptions](docs/starlette-demonstration.md#the-18-tasks).

## Historical experiment

The bundled earlier experiment also made 72 calls. Both conditions passed 34 of
36 attempts. Its 16 complete tasks showed 41.9% lower wall time and 33.1% fewer
tokens with the MD, but that 16-task analysis was selected after the outcomes
were known and is therefore exploratory.

[Read the historical report](reports/STARLETTE_EIGHTEEN_TWO_REPEAT_V2_REPORT.md)
or the [detailed case study](docs/starlette-demonstration.md).

<details>
<summary>Exact historical design and audit values</summary>

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

| Measure | Eligible tasks | Exact reduction | 95% reduction CI | Two-sided p | Result |
|---|---:|---:|---:|---:|---|
| Wall-clock time | 16 | 41.8854% | 32.3133%–50.1038% | 1.6430678e-06 | **Significantly favorable** |
| Tokens used | 16 | 33.0927% | 21.6050%–42.8970% | 7.2894331e-05 | **Significantly favorable** |

The historical run was a finite-known-set development replication, not the frozen v7 confirmation.
Its all-18 registered endpoint was unavailable because
two tasks lacked complete paired results. The 16-task method was not historically
preregistered; it was selected after outcomes were known.

</details>

## Repository guide

- [`run_product_a.py`](run_product_a.py) runs a fresh fixed experiment.
- [`RESULTS.md`](RESULTS.md) summarizes completed, verified fresh runs.
- [`tasks/`](tasks/) and [`controls/`](controls/) contain the fixed experiment.
- [`runtime/product-a-v2/`](runtime/product-a-v2/) contains the public runtime.
- [`runs/product-a/`](runs/product-a/) contains fresh evidence and reports.
- [`tooling/`](tooling/) and [`scripts/`](scripts/) contain the implementation.

## Limits

- This is a fixed Starlette demonstration, not a configurable benchmark or an
  instruction optimizer.
- The result applies only to this model, runtime, MD, and known task set.
  Correctness counts are descriptive, and incomplete tasks are excluded from
  resource analysis under each run's fixed rule.
- Runs from different machines or runtimes are not pooled. Forks can run local
  replications, but automatic contribution to an upstream tally is not yet
  supported.

The historical fixtures and evidence were copied from the authoritative
`MDs_EVAL` repository at commit
`6e8e985318203f3818fefad07e3a9b43a7a9e300`. They remain unchanged so their
integrity bindings can still be verified.

## License

Original demonstration code and documentation are released under the
[MIT License](LICENSE). Embedded Starlette fixtures retain their BSD license
notices in the corresponding `public`, `blind`, and `reference` trees.
