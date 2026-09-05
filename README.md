# MD Eval: Starlette demonstration

This repository is a self-contained, offline-reproducible case study of whether
a repository instruction file helped the same coding model solve the same
Starlette tasks. It contains the 18 task fixtures, frozen controls, raw run
evidence, integrity bindings, analysis, and report code needed to inspect the
experiment without credentials, network access, or model calls.

This is the standalone demonstration only. It is not an instruction optimizer,
a hosted benchmark, or a configurable toolkit for new experiments.

## What was tested

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
| Resolved attempts | MD 34/36; No MD 34/36 |

In total, the experiment made 72 subject-model calls (72 recorded subject
invocations), with no replacement calls.

## Results

### Registered endpoints

| Endpoint | Result |
|---|---|
| Wall time | **INCONCLUSIVE** |
| Tokens | **INCONCLUSIVE** |

The registered analysis required two jointly normal, mechanically resolved
pairs for every task. `confirm-starlette-exception-context` had one usable pair
and `confirm-starlette-malformed-host` had none, so the complete-pair
requirement was not met. The registered wall-time and token endpoints therefore
do not support a directional conclusion.

### Explicitly post-hoc complete-case analysis

After outcomes were known, an exploratory analysis retained the 16 tasks with
two usable pairs. These estimates are informative but do not replace the
registered inconclusive result.

| Endpoint | Tasks | Reduction | 95% reduction CI | df | Two-sided p |
|---|---:|---:|---:|---:|---:|
| Wall time | 16 | 41.8854% | 32.3133%–50.1038% | 15 | 1.6430678e-06 |
| Tokens | 16 | 33.0927% | 21.6050%–42.8970% | 15 | 7.2894331e-05 |

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

## Reproduce everything offline

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
`e58b48c24a29c211c9dcbe4c26e86df8b69440e578987258ac1d2462f60f61f8`.
A successful `cmp` prints nothing and exits zero. These commands do not inspect
authentication, access the network, or invoke a model.

## Repository map

- `docs/starlette-demonstration.md` — detailed case study and task taxonomy.
- `reports/STARLETTE_EIGHTEEN_TWO_REPEAT_V2_REPORT.md` — canonical v2 report.
- `tasks/` — exactly the 18 demonstrated fixtures plus their integrity ledgers.
- `runs/dev-v2/starlette-eighteen-two-repeat-v2/` — approved request and raw,
  hash-anchored experiment evidence.
- `controls/` — the MD and empty No-MD controls used in the experiment.
- `tooling/starlette_demo.py` — offline-only public verification and report
  reproduction entry point.
- `tooling/`, `scripts/`, and `src/` — the minimal frozen implementation and
  import closure needed to validate the preserved run.

The source-wide task and exposure ledgers are retained byte-for-byte because
the approved request hashes them. The separate 18-entry demonstration ledger
lets `taskcheck` validate this intentionally restricted fixture set without
copying any unrelated task directories.

## Provenance and limitations

All task fixtures, controls, hash-bound implementation files, and preserved
evidence were copied byte-for-byte from the authoritative `MDs_EVAL` source at
commit `6e8e985318203f3818fefad07e3a9b43a7a9e300`. This repository has new,
independent Git history.

This was a finite-known-set development replication, not the frozen v7 confirmation.
Equal correctness does not establish equivalence, and the
post-hoc analysis may be affected by selection, task familiarity, shared
harness behavior, or properties of this model and task distribution. The
result should not be generalized to other models, repositories, instruction
files, or task populations.

The frozen live-run implementation is retained only because the request binds
its exact bytes. The documented public entry point and CI perform offline
verification and report reproduction only; they never launch subjects.

## License

Original demonstration code and documentation are released under the
[MIT License](LICENSE). The embedded Starlette fixture copies retain their
original BSD license notices in every `public`, `blind`, and `reference` tree;
those notices continue to govern the corresponding upstream material.
