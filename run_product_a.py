#!/usr/bin/env python3
"""Run the fixed Product A experiment through one interactive confirmation."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import sys
from typing import Any, Callable, Iterator, Mapping, Sequence

from scripts import run_batch
from scripts.contain import runtime as sealed
from tooling import starlette_product_a as product_a
from tooling import starlette_product_a_runtime as public_runtime
from tooling.starlette_demo import demo_task_registry


ROOT = Path(__file__).resolve().parent


class ProductAUXError(RuntimeError):
    """Raised when the interactive launch cannot safely continue."""


@contextmanager
def _product_a_spec() -> Iterator[None]:
    """Temporarily select the same contamination spec as the sealed runner."""

    previous = sealed.SPEC
    sealed.SPEC = ROOT / product_a.SPEC_PATH
    try:
        yield
    finally:
        sealed.SPEC = previous


def live_readiness_check(run_dir: Path) -> dict[str, Any]:
    """Run the sealed launch preflight without approving or calling a model.

    The approved runner repeats this check at its execution boundary so that a
    passing result cannot be reused after the environment or request changes.
    """

    run_dir = product_a._validate_run_boundary(run_dir, product_a.RUNS_ROOT)
    request = product_a._read_json(run_dir / product_a.REQUEST_FILENAME)
    product_a._validate_request(ROOT, run_dir, request)
    inner_request = product_a._execution_request(ROOT, request["run_id"])
    if (
        product_a._digest_bytes(product_a._canonical_bytes(inner_request))
        != request["sealed_attempt_request_sha256"]
    ):
        raise ProductAUXError("the prepared request no longer matches the fixed execution")

    with _product_a_spec(), demo_task_registry():
        result = run_batch.preflight_request(
            inner_request,
            deadline_seconds=product_a.PREFLIGHT_DEADLINE_SECONDS,
        )
    return dict(result)


def _prepare() -> Mapping[str, Any]:
    return product_a.prepare(runs_root=product_a.RUNS_ROOT, repo=ROOT)


def _approve(run_dir: Path, request_sha256: str) -> Mapping[str, Any]:
    return product_a.approve(
        run_dir,
        request_sha256,
        repo=ROOT,
        allowed_runs_root=product_a.RUNS_ROOT,
    )


def _run(run_dir: Path) -> Mapping[str, Any]:
    return product_a.run_approved(
        run_dir,
        repo=ROOT,
        allowed_runs_root=product_a.RUNS_ROOT,
    )


def _verify(run_dir: Path) -> Mapping[str, Any]:
    return product_a.verify_and_report(
        run_dir,
        repo=ROOT,
        allowed_runs_root=product_a.RUNS_ROOT,
    )


def _refresh_results() -> Path:
    from tooling.starlette_product_a_results import refresh_results

    return refresh_results(repo_root=ROOT)


def _readiness_failure(result: Mapping[str, Any]) -> str:
    checks = result.get("failed_checks")
    if isinstance(checks, list) and checks:
        names = ", ".join(str(item) for item in checks)
    else:
        names = "unknown check"
    errors = result.get("errors")
    if not isinstance(errors, Mapping) or not errors:
        return f"readiness check failed: {names}"
    details = "; ".join(f"{name}: {message}" for name, message in errors.items())
    return f"readiness check failed: {names} ({details})"


def _run_ready(
    *,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
    prepare_fn: Callable[[], Mapping[str, Any]] | None = None,
    readiness_fn: Callable[[Path], Mapping[str, Any]] = live_readiness_check,
    approve_fn: Callable[[Path, str], Mapping[str, Any]] | None = None,
    run_fn: Callable[[Path], Mapping[str, Any]] | None = None,
    verify_fn: Callable[[Path], Mapping[str, Any]] | None = None,
) -> dict[str, Any]:
    """Run the existing fixed lifecycle after artifact readiness succeeds."""

    prepare_fn = prepare_fn or _prepare
    approve_fn = approve_fn or _approve
    run_fn = run_fn or _run
    verify_fn = verify_fn or _verify

    output_fn("Preparing a fresh fixed Product A request...")
    prepared = dict(prepare_fn())
    try:
        run_dir = Path(str(prepared["run_directory"])).absolute()
        request_sha256 = str(prepared["request_sha256"])
    except KeyError as exc:
        raise ProductAUXError("prepare did not return a complete request identity") from exc

    output_fn(f"Prepared run directory: {run_dir}")
    output_fn(f"Prepared request SHA-256: {request_sha256}")
    output_fn("Running zero-model-call readiness checks (inputs, auth, and runtime)...")
    readiness = dict(readiness_fn(run_dir))
    if readiness.get("status") != "PASS":
        raise ProductAUXError(_readiness_failure(readiness))
    seals = readiness.get("seals")
    if not isinstance(seals, Mapping) or set(seals) != set(product_a.TASK_IDS):
        raise ProductAUXError("readiness check returned incomplete task seals")

    output_fn("")
    output_fn("Product A is ready")
    output_fn(f"  Tasks: {len(product_a.TASK_IDS)} bundled Starlette tasks")
    output_fn("  Arms: bundled MD versus empty No-MD")
    output_fn(f"  Repeats: {product_a.REPEATS} paired repeats per task")
    output_fn(
        f"  Calls: {product_a.PLANNED_CALLS} planned; "
        f"{product_a.MAX_SUBJECT_INVOCATIONS} maximum"
    )
    output_fn(f"  Model: {product_a.MODEL}, {product_a.REASONING_EFFORT} reasoning")
    output_fn(f"  Maximum concurrency: {product_a.WORKERS}")
    output_fn(f"  Run directory: {run_dir}")
    output_fn(f"  Request SHA-256: {request_sha256}")
    output_fn(
        "  Safety: the sealed runner repeats readiness after approval and before calls."
    )
    output_fn("  Expected runtime: about an hour; the terminal may be quiet during calls.")
    output_fn("")

    try:
        answer = input_fn(
            f"Proceed with up to {product_a.MAX_SUBJECT_INVOCATIONS} live model calls? "
            "Type YES to continue [NO]: "
        )
    except EOFError:
        answer = ""
    if answer.strip().upper() != "YES":
        output_fn("Cancelled. The request remains unapproved; no model calls were made.")
        return {
            "status": "cancelled",
            "run_directory": str(run_dir),
            "request_sha256": request_sha256,
        }

    output_fn("Approving the displayed request and starting the sealed run...")
    approval = dict(approve_fn(run_dir, request_sha256))
    if approval.get("request_sha256") != request_sha256:
        raise ProductAUXError("approval did not bind the displayed request hash")
    manifest = dict(run_fn(run_dir))
    output_fn("Run finished. Verifying preserved evidence and writing its report...")
    verified = dict(verify_fn(run_dir))
    output_fn(f"Verified report: {verified.get('report', run_dir / product_a.REPORT_FILENAME)}")
    return {
        "status": "completed",
        "run_directory": str(run_dir),
        "request_sha256": request_sha256,
        "approval": approval,
        "manifest": manifest,
        "verification": verified,
    }


def run_interactive(
    *,
    input_fn: Callable[[str], str] = input,
    output_fn: Callable[[str], None] = print,
    runtime_fn: Callable[..., Any] | None = None,
    prepare_fn: Callable[[], Mapping[str, Any]] | None = None,
    readiness_fn: Callable[[Path], Mapping[str, Any]] = live_readiness_check,
    approve_fn: Callable[[Path, str], Mapping[str, Any]] | None = None,
    run_fn: Callable[[Path], Mapping[str, Any]] | None = None,
    verify_fn: Callable[[Path], Mapping[str, Any]] | None = None,
    refresh_results_fn: Callable[[], Path] | None = None,
) -> dict[str, Any]:
    """Acquire the fixed runtime before creating and approving a fresh request."""

    runtime_fn = runtime_fn or public_runtime.activate
    with runtime_fn(input_fn, output_fn) as ready:
        if not ready:
            return {"status": "cancelled", "stage": "runtime"}
        result = _run_ready(
            input_fn=input_fn, output_fn=output_fn, prepare_fn=prepare_fn,
            readiness_fn=readiness_fn, approve_fn=approve_fn, run_fn=run_fn,
            verify_fn=verify_fn,
        )
    if result["status"] == "completed":
        results_path = Path((refresh_results_fn or _refresh_results)()).absolute()
        result["results"] = str(results_path)
        output_fn(f"Updated results dashboard: {results_path}")
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Prepare and run the one fixed Product A experiment. Readiness checks "
            "run before one explicit YES/NO confirmation."
        )
    )
    parser.add_argument(
        "--verify-report", metavar="RUN_DIRECTORY", type=Path,
        help="recover reporting for an already completed public-runtime run",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.verify_report:
            with public_runtime.protocol():
                verified = _verify(args.verify_report.absolute())
            results = _refresh_results()
            print(f"Verified report: {verified['report']}")
            print(f"Updated results dashboard: {results.absolute()}")
            return 0
        result = run_interactive()
    except KeyboardInterrupt:
        print(
            "\nInterrupted. Inspect the newest Product A run directory before retrying; "
            "its approval and execution state depends on when interruption occurred.",
            file=sys.stderr,
        )
        return 130
    except (
        ProductAUXError,
        public_runtime.RuntimeSetupError,
        product_a.ProductAError,
        product_a.atomic.EvidenceError,
        product_a.live.ShakeoutError,
        run_batch.BatchError,
        product_a.taskcheck.TaskError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0 if result["status"] in {"cancelled", "completed"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
