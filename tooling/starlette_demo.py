#!/usr/bin/env python3
"""Offline-only entry point for the standalone Starlette demonstration."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from hashlib import sha256
import json
from pathlib import Path
import sys
from typing import Any, Iterator, Sequence


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from tooling import report_starlette_eighteen as report  # noqa: E402
from tooling import starlette_eighteen_task_experiment as experiment  # noqa: E402
from tooling import taskcheck  # noqa: E402


BATCH = ROOT / experiment.BATCH_PATH
EVIDENCE = ROOT / experiment.OUTPUT_PATH
CANONICAL_REPORT = ROOT / "reports/STARLETTE_EIGHTEEN_TWO_REPEAT_V2_REPORT.md"
SOURCE_TASK_LEDGER = ROOT / "tasks/ledger.jsonl"
SOURCE_EXPOSURE_LEDGER = ROOT / "tasks/exposures.jsonl"
DEMO_TASK_LEDGER = ROOT / "verification/starlette-task-ledger.jsonl"
EXPECTED_REPORT_SHA256 = (
    "e58b48c24a29c211c9dcbe4c26e86df8b69440e578987258ac1d2462f60f61f8"
)
EXPECTED_REQUEST_SHA256 = (
    "e64856701e1537bfe6ff826f321b62f750450b24d8fe24d6fc7d5497acca8137"
)
EXPECTED_APPROVAL_SHA256 = (
    "2799426a352e01a91dae4068ead5208b01181c2e36fbfb19e1535c4014c2cd18"
)
EXPECTED_DEMO_LEDGER_SHA256 = (
    "2c4b1ca42f788ea4b043bed5f09b1e9492a18dd71ea2061ec2e9550adab45ab2"
)


class DemoError(RuntimeError):
    """Raised when the public demonstration is incomplete or inconsistent."""


def _verify_release_anchors() -> None:
    expected = {
        BATCH / "REQUEST.json": EXPECTED_REQUEST_SHA256,
        BATCH / "APPROVED.json": EXPECTED_APPROVAL_SHA256,
        DEMO_TASK_LEDGER: EXPECTED_DEMO_LEDGER_SHA256,
    }
    for artifact, wanted in expected.items():
        actual = sha256(artifact.read_bytes()).hexdigest()
        if actual != wanted:
            raise DemoError(f"release anchor differs: {artifact.relative_to(ROOT)}")


def verify_tasks(*, run_checkers: bool = False) -> list[dict[str, Any]]:
    """Verify each included fixture with the frozen taskcheck."""
    _verify_release_anchors()
    expected = set(experiment.TASK_IDS)
    children = list((ROOT / "tasks").iterdir())
    unsafe = [child.name for child in children if child.is_symlink()]
    unexpected_files = sorted(
        child.name
        for child in children
        if child.is_file() and child.name not in {"ledger.jsonl", "exposures.jsonl"}
    )
    actual = {child.name for child in children if child.is_dir()}
    if unsafe or unexpected_files:
        raise DemoError(
            f"task root has unsafe or unexpected entries: {unsafe + unexpected_files}"
        )
    if actual != expected:
        raise DemoError(
            f"task fixture inventory differs: expected {len(expected)}, found {len(actual)}"
        )

    request = experiment.atomic._read_canonical_json(BATCH / "REQUEST.json")
    request_hashes = {
        row["task_id"]: row["manifest_sha256"] for row in request["tasks"]
    }
    def verify_one(task_id: str) -> dict[str, Any]:
        manifest = ROOT / "tasks" / task_id / "manifest.json"
        manifest_sha256 = sha256(manifest.read_bytes()).hexdigest()
        if manifest_sha256 != request_hashes.get(task_id):
            raise DemoError(f"request manifest binding differs: {task_id}")
        result = taskcheck.verify(
            ROOT / "tasks" / task_id,
            ledger=DEMO_TASK_LEDGER,
            exposures=SOURCE_EXPOSURE_LEDGER,
            md_filename="CODER.md" if run_checkers else None,
        )
        if result["manifest_sha256"] != manifest_sha256:
            raise DemoError(f"request manifest binding differs: {task_id}")
        return result

    if run_checkers:
        with ThreadPoolExecutor(max_workers=2) as executor:
            return list(executor.map(verify_one, experiment.TASK_IDS))
    return [verify_one(task_id) for task_id in experiment.TASK_IDS]


@contextmanager
def demo_task_registry() -> Iterator[None]:
    """Route frozen default task admission through the 18-task public ledger."""
    original_verify = taskcheck.verify

    def verify_public_task(
        task_dir: Path,
        ledger: Path | None = None,
        exposures: Path | None = None,
        md_filename: str | None = None,
    ) -> dict[str, Any]:
        return original_verify(
            task_dir,
            ledger=DEMO_TASK_LEDGER if ledger is None else ledger,
            exposures=SOURCE_EXPOSURE_LEDGER if exposures is None else exposures,
            md_filename=md_filename,
        )

    taskcheck.verify = verify_public_task
    try:
        yield
    finally:
        taskcheck.verify = original_verify


def verify_evidence() -> dict[str, int]:
    """Run the unchanged frozen verifier against the preserved evidence."""
    verify_tasks()
    with demo_task_registry():
        result = experiment.verify(ROOT, BATCH, EVIDENCE)
    digest = sha256(CANONICAL_REPORT.read_bytes()).hexdigest()
    if digest != EXPECTED_REPORT_SHA256:
        raise DemoError(f"canonical report SHA-256 differs: {digest}")
    return result


def reproduce_report(destination: Path) -> dict[str, Any]:
    """Verify all inputs, then reproduce the canonical report at a new path."""
    destination = destination.absolute()
    resolved = destination.resolve(strict=False)
    if destination.is_symlink() or resolved == ROOT or ROOT in resolved.parents:
        raise DemoError("report path must be new and outside the repository")
    if destination.exists():
        raise DemoError("report path already exists")
    verify_tasks()
    try:
        with demo_task_registry():
            result = report.write_report(BATCH, EVIDENCE, destination)
        if result["report_sha256"] != EXPECTED_REPORT_SHA256:
            raise DemoError(
                f"reproduced report SHA-256 differs: {result['report_sha256']}"
            )
        if destination.read_bytes() != CANONICAL_REPORT.read_bytes():
            raise DemoError("reproduced report is not byte-identical to canonical report")
        return result
    except BaseException:
        if destination.is_file() and not destination.is_symlink():
            destination.unlink()
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("verify-tasks", help="verify all 18 fixtures individually")
    commands.add_parser("verify", help="verify fixtures, bindings, and evidence")
    reproduce = commands.add_parser("report", help="reproduce the canonical report")
    reproduce.add_argument("--report-path", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "verify-tasks":
            tasks = verify_tasks(run_checkers=True)
            result: object = {
                "task_count": len(tasks),
                "tasks": [row["task_id"] for row in tasks],
                "verified": len(tasks),
            }
        elif args.command == "verify":
            result = verify_evidence()
        else:
            result = reproduce_report(args.report_path.absolute())
    except (
        DemoError,
        OSError,
        ValueError,
        KeyError,
        json.JSONDecodeError,
        report.ReportError,
        experiment.ExperimentError,
        experiment.atomic.EvidenceError,
        experiment.live.ShakeoutError,
        experiment.run_batch.BatchError,
        taskcheck.TaskError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
