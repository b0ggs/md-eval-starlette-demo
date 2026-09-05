#!/usr/bin/env python3
"""Frozen analyzer for the Starlette atomic-pair protocol.

The analyzer is deliberately independent of the execution machinery.  It accepts
either the durable run directory written by ``starlette_atomic_pairs`` or an
equivalent normalized dictionary.  Validation is fail-closed: no estimates are
returned unless the schedule, seal, manifest, records, scheduler lifecycle, and
replacement graph are internally consistent.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import random
import statistics
import sys
import tempfile
from typing import Any, Iterable, Mapping, Sequence


ANALYSIS_SCHEMA_VERSION = "starlette-atomic-pair-analysis-v1"
SCHEDULE_SCHEMA_VERSION = "starlette-atomic-pair-schedule-v1"
RUN_SEAL_SCHEMA_VERSION = "starlette-atomic-pair-run-seal-v1"
ATTEMPT_SCHEMA_VERSION = "starlette-atomic-pair-attempt-v1"
PAIR_SCHEMA_VERSION = "starlette-atomic-pair-result-v1"
EVENT_SCHEMA_VERSION = "starlette-atomic-pair-scheduler-event-v1"
MANIFEST_SCHEMA_VERSION = "starlette-atomic-pair-manifest-v1"
EXPECTED_TASKS = 12
EXPECTED_REPEATS = 3
EXPECTED_ROOT_PAIRS = EXPECTED_TASKS * EXPECTED_REPEATS
EXPECTED_ARMS = ("candidate", "control")
EXPECTED_WORKERS = 12
EXPECTED_TIMEOUT_SECONDS = 900.0
ALPHA = 0.05
FINALIZED_PREREGISTRATION_SHA256 = (
    "565388658f593a14c931757bf1cfe7095c062bd9e332297b1e3225bef5fddcc1"
)
FROZEN_CANDIDATE_SHA256 = (
    "c0d56e29ade34c24278b976e84b29e47324c11a23399ca882239daffc9762c74"
)
FROZEN_CONTROL_SHA256 = (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)
# Filled with the exact bytes of tests/fixtures/starlette_analyzer_fixture.json.
# Only that frozen file may exercise the event-less, current-code-hash-independent
# fixture path.  General normalized dictionaries remain fully validated inputs.
FROZEN_SYNTHETIC_FIXTURE_SHA256 = (
    "fd83a203f31b6eb9e9b1b5ada23ce35f5b341cc4007c2762cecfe49d916ed5bf"
)
HASH_NAMES = (
    "preregistration_sha256",
    "runner_sha256",
    "candidate_sha256",
    "control_sha256",
    "task_manifest_sha256",
    "runtime_manifest_sha256",
    "analyzer_sha256",
)


class AnalysisError(ValueError):
    """Raised when evidence is not safe to analyze."""


class _LoadedRunRecords(dict[str, Any]):
    """Marker for records whose directory-only evidence was verified."""


class _TrustedSyntheticFixtureRecords(dict[str, Any]):
    """Private marker created only after exact frozen-fixture byte validation."""


def _fail(message: str) -> "NoReturn":  # type: ignore[name-defined]
    raise AnalysisError(message)


def _canonical_json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def _canonical_jsonl_bytes(values: Sequence[Mapping[str, Any]]) -> bytes:
    return b"".join(_canonical_json_bytes(value) for value in values)


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_hash(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _mapping(value: Any, where: str) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        _fail(f"{where} must be an object")
    return value


def _list(value: Any, where: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(f"{where} must be an array")
    return value


def _string(value: Any, where: str, *, nonempty: bool = True) -> str:
    if not isinstance(value, str) or (nonempty and not value):
        _fail(f"{where} must be a non-empty string")
    return value


def _boolean(value: Any, where: str) -> bool:
    if type(value) is not bool:
        _fail(f"{where} must be boolean")
    return value


def _integer(
    value: Any,
    where: str,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if type(value) is not int:
        _fail(f"{where} must be an integer")
    if minimum is not None and value < minimum:
        _fail(f"{where} must be >= {minimum}")
    if maximum is not None and value > maximum:
        _fail(f"{where} must be <= {maximum}")
    return value


def _finite_number(
    value: Any,
    where: str,
    *,
    minimum: float | None = None,
    strictly_positive: bool = False,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        _fail(f"{where} must be a finite number")
    result = float(value)
    if not math.isfinite(result):
        _fail(f"{where} must be a finite number")
    if minimum is not None and result < minimum:
        _fail(f"{where} must be >= {minimum}")
    if strictly_positive and result <= 0:
        _fail(f"{where} must be > 0")
    return result


def _required(record: Mapping[str, Any], key: str, where: str) -> Any:
    if key not in record:
        _fail(f"{where}.{key} is required")
    return record[key]


def _field(
    record: Mapping[str, Any],
    names: Sequence[str],
    where: str,
    *,
    required: bool = True,
) -> Any:
    present = [name for name in names if name in record]
    if not present:
        if required:
            _fail(f"{where}.{names[0]} is required")
        return None
    first = record[present[0]]
    if any(record[name] != first for name in present[1:]):
        _fail(f"{where} has conflicting aliases: {', '.join(present)}")
    return first


def _close(actual: float, expected: float) -> bool:
    return math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-12)


def _validate_hash(value: Any, where: str) -> str:
    if not _is_hash(value):
        _fail(f"{where} must be a lowercase SHA-256 hex digest")
    return value


def _regularized_incomplete_beta(x: float, a: float, b: float) -> float:
    """Return I_x(a, b), using a stable continued fraction.

    This is the classic modified-Lentz evaluation from Numerical Recipes, with
    symmetry used to keep the continued fraction in its well-conditioned tail.
    It is more than sufficient for the registered df=11 test and is also kept
    general for direct numerical unit tests.
    """

    if not (0.0 <= x <= 1.0) or a <= 0.0 or b <= 0.0:
        raise ValueError("invalid incomplete-beta arguments")
    if x == 0.0:
        return 0.0
    if x == 1.0:
        return 1.0

    def fraction(aa: float, bb: float, xx: float) -> float:
        max_iterations = 400
        epsilon = 3.0e-15
        tiny = sys.float_info.min / epsilon
        qab = aa + bb
        qap = aa + 1.0
        qam = aa - 1.0
        c = 1.0
        d = 1.0 - qab * xx / qap
        if abs(d) < tiny:
            d = tiny
        d = 1.0 / d
        result = d
        for iteration in range(1, max_iterations + 1):
            twice = 2 * iteration
            term = (
                iteration
                * (bb - iteration)
                * xx
                / ((qam + twice) * (aa + twice))
            )
            d = 1.0 + term * d
            if abs(d) < tiny:
                d = tiny
            c = 1.0 + term / c
            if abs(c) < tiny:
                c = tiny
            d = 1.0 / d
            result *= d * c

            term = -(
                (aa + iteration)
                * (qab + iteration)
                * xx
                / ((aa + twice) * (qap + twice))
            )
            d = 1.0 + term * d
            if abs(d) < tiny:
                d = tiny
            c = 1.0 + term / c
            if abs(c) < tiny:
                c = tiny
            d = 1.0 / d
            delta = d * c
            result *= delta
            if abs(delta - 1.0) <= epsilon:
                return result
        raise ArithmeticError("incomplete-beta continued fraction did not converge")

    log_front = (
        math.lgamma(a + b)
        - math.lgamma(a)
        - math.lgamma(b)
        + a * math.log(x)
        + b * math.log1p(-x)
    )
    front = math.exp(log_front)
    if x < (a + 1.0) / (a + b + 2.0):
        result = front * fraction(a, b, x) / a
    else:
        result = 1.0 - front * fraction(b, a, 1.0 - x) / b
    return min(1.0, max(0.0, result))


def student_t_cdf(value: float, degrees_of_freedom: int) -> float:
    """CDF of Student's t distribution, implemented with the stdlib only."""

    if degrees_of_freedom <= 0:
        raise ValueError("degrees_of_freedom must be positive")
    if math.isnan(value):
        raise ValueError("value must not be NaN")
    if value == math.inf:
        return 1.0
    if value == -math.inf:
        return 0.0
    if value == 0.0:
        return 0.5
    df = float(degrees_of_freedom)
    beta = _regularized_incomplete_beta(
        df / (df + value * value), df / 2.0, 0.5
    )
    if value > 0.0:
        return 1.0 - 0.5 * beta
    return 0.5 * beta


def student_t_two_sided_p(value: float, degrees_of_freedom: int) -> float:
    if math.isnan(value):
        raise ValueError("value must not be NaN")
    if math.isinf(value):
        return 0.0
    if degrees_of_freedom <= 0:
        raise ValueError("degrees_of_freedom must be positive")
    df = float(degrees_of_freedom)
    return _regularized_incomplete_beta(
        df / (df + value * value), df / 2.0, 0.5
    )


def student_t_quantile(probability: float, degrees_of_freedom: int) -> float:
    """Inverse Student-t CDF by bracketed bisection."""

    if not 0.0 < probability < 1.0:
        raise ValueError("probability must be strictly between zero and one")
    if degrees_of_freedom <= 0:
        raise ValueError("degrees_of_freedom must be positive")
    if probability == 0.5:
        return 0.0
    if probability < 0.5:
        return -student_t_quantile(1.0 - probability, degrees_of_freedom)
    lower = 0.0
    upper = 1.0
    while student_t_cdf(upper, degrees_of_freedom) < probability:
        upper *= 2.0
        if not math.isfinite(upper):
            raise ArithmeticError("could not bracket Student-t quantile")
    for _ in range(100):
        middle = (lower + upper) / 2.0
        if student_t_cdf(middle, degrees_of_freedom) < probability:
            lower = middle
        else:
            upper = middle
    return (lower + upper) / 2.0


def _parse_json(data: bytes, where: str) -> Mapping[str, Any]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AnalysisError(f"{where} is not UTF-8") from error
    try:
        value = json.loads(text, parse_constant=lambda token: _fail(
            f"{where} contains non-finite JSON number {token}"
        ))
    except (json.JSONDecodeError, TypeError) as error:
        raise AnalysisError(f"{where} is not valid JSON: {error}") from error
    result = _mapping(value, where)
    if data != _canonical_json_bytes(result):
        _fail(f"{where} is not canonical JSON")
    return result


def _parse_jsonl(data: bytes, where: str) -> list[Mapping[str, Any]]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AnalysisError(f"{where} is not UTF-8") from error
    records: list[Mapping[str, Any]] = []
    if text and not text.endswith("\n"):
        _fail(f"{where} must end with a newline")
    for line_number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            _fail(f"{where}:{line_number} is blank")
        try:
            value = json.loads(
                line,
                parse_constant=lambda token: _fail(
                    f"{where}:{line_number} contains non-finite JSON number {token}"
                ),
            )
        except (json.JSONDecodeError, TypeError) as error:
            raise AnalysisError(
                f"{where}:{line_number} is not valid JSON: {error}"
            ) from error
        records.append(_mapping(value, f"{where}:{line_number}"))
        if (line + "\n").encode("utf-8") != _canonical_json_bytes(records[-1]):
            _fail(f"{where}:{line_number} is not canonical JSON")
    return records


def load_run_directory(run_directory: str | os.PathLike[str]) -> dict[str, Any]:
    """Load the registered run artifacts and verify directory-only evidence."""

    directory = Path(run_directory)
    if directory.is_symlink() or not directory.is_dir():
        _fail(f"run directory does not exist: {directory}")
    names = {
        "schedule": "schedule.json",
        "run_seal": "run-seal.json",
        "attempts": "attempts.jsonl",
        "pairs": "pairs.jsonl",
        "scheduler_events": "scheduler-events.jsonl",
        "manifest": "manifest.json",
    }
    raw: dict[str, bytes] = {}
    for key, filename in names.items():
        path = directory / filename
        if path.is_symlink() or not path.is_file():
            _fail(f"required artifact is missing: {filename}")
        try:
            raw[key] = path.read_bytes()
        except OSError as error:
            raise AnalysisError(f"cannot read {filename}: {error}") from error
    manifest = _parse_json(raw["manifest"], "manifest.json")
    run_seal = _parse_json(raw["run_seal"], "run-seal.json")
    live_mode = run_seal.get("mode") == "live_approved"
    workspace_root = directory / "workspaces"
    if workspace_root.is_symlink() or not workspace_root.is_dir():
        _fail("required workspaces directory is missing or unsafe")
    workspace_manifest = _mapping(
        _required(manifest, "workspace_evidence_sha256", "manifest"),
        "manifest.workspace_evidence_sha256",
    )
    actual_workspace_files: dict[str, Path] = {}
    for path in workspace_root.rglob("*"):
        if path.is_symlink():
            _fail(f"workspace evidence contains a symlink: {path}")
        if path.is_file():
            relative = path.relative_to(directory).as_posix()
            actual_workspace_files[relative] = path
        elif not path.is_dir():
            _fail(f"workspace evidence contains an unsafe entry: {path}")
    if set(actual_workspace_files) != set(workspace_manifest):
        _fail("workspace evidence inventory mismatch")
    verified_workspace_evidence: dict[str, Mapping[str, Any]] = {}
    for relative, path in actual_workspace_files.items():
        expected = _validate_hash(
            workspace_manifest[relative],
            f"manifest.workspace_evidence_sha256.{relative}",
        )
        evidence_bytes = path.read_bytes()
        if _sha256_bytes(evidence_bytes) != expected:
            _fail(f"workspace evidence hash mismatch: {relative}")
        if relative.endswith("/stub-evidence.json"):
            verified_workspace_evidence[relative] = _parse_json(
                evidence_bytes, relative
            )
        elif not live_mode:
            _fail(f"offline workspace contains unexpected evidence: {relative}")

    result: _LoadedRunRecords = _LoadedRunRecords({
        "schedule": _parse_json(raw["schedule"], "schedule.json"),
        "run_seal": run_seal,
        "attempts": _parse_jsonl(raw["attempts"], "attempts.jsonl"),
        "pairs": _parse_jsonl(raw["pairs"], "pairs.jsonl"),
        "scheduler_events": _parse_jsonl(
            raw["scheduler_events"], "scheduler-events.jsonl"
        ),
        "manifest": manifest,
        "_artifact_sha256": {
            key: _sha256_bytes(value) for key, value in raw.items()
        },
        "_artifact_sizes": {key: len(value) for key, value in raw.items()},
        "_verified_workspace_paths": sorted(actual_workspace_files),
        "_verified_workspace_evidence": verified_workspace_evidence,
    })
    return result


def _normalized_artifact_hashes(records: Mapping[str, Any]) -> dict[str, str]:
    result = {
        "schedule": _sha256_bytes(_canonical_json_bytes(records["schedule"])),
        "run_seal": _sha256_bytes(_canonical_json_bytes(records["run_seal"])),
        "attempts": _sha256_bytes(_canonical_jsonl_bytes(records["attempts"])),
        "pairs": _sha256_bytes(_canonical_jsonl_bytes(records["pairs"])),
        "manifest": _sha256_bytes(_canonical_json_bytes(records["manifest"])),
    }
    if "scheduler_events" in records:
        result["scheduler_events"] = _sha256_bytes(
            _canonical_jsonl_bytes(records["scheduler_events"])
        )
    return result


def _normalized_artifact_sizes(records: Mapping[str, Any]) -> dict[str, int]:
    values = {
        "schedule": _canonical_json_bytes(records["schedule"]),
        "run_seal": _canonical_json_bytes(records["run_seal"]),
        "attempts": _canonical_jsonl_bytes(records["attempts"]),
        "pairs": _canonical_jsonl_bytes(records["pairs"]),
        "manifest": _canonical_json_bytes(records["manifest"]),
    }
    if "scheduler_events" in records:
        values["scheduler_events"] = _canonical_jsonl_bytes(
            records["scheduler_events"]
        )
    return {key: len(value) for key, value in values.items()}


def _validate_schedule(
    schedule: Mapping[str, Any],
) -> tuple[list[str], dict[str, Mapping[str, Any]], dict[str, int]]:
    if _string(
        _required(schedule, "schema_version", "schedule"),
        "schedule.schema_version",
    ) != SCHEDULE_SCHEMA_VERSION:
        _fail("unsupported schedule.schema_version")
    randomization_seed = _string(
        _required(schedule, "randomization_seed", "schedule"),
        "schedule.randomization_seed",
    )
    worker_count = _integer(
        _required(schedule, "worker_count", "schedule"),
        "schedule.worker_count",
        minimum=1,
    )
    if worker_count != EXPECTED_WORKERS:
        _fail(f"schedule.worker_count must be {EXPECTED_WORKERS}")

    task_ids = [
        _string(value, f"schedule.task_ids[{index}]")
        for index, value in enumerate(
            _list(_required(schedule, "task_ids", "schedule"), "schedule.task_ids")
        )
    ]
    if len(task_ids) != EXPECTED_TASKS:
        _fail(f"schedule must contain exactly {EXPECTED_TASKS} task IDs")
    if len(set(task_ids)) != len(task_ids):
        _fail("schedule.task_ids contains duplicates")
    if _integer(
        _required(schedule, "task_count", "schedule"),
        "schedule.task_count",
        minimum=0,
    ) != EXPECTED_TASKS:
        _fail(f"schedule.task_count must be {EXPECTED_TASKS}")
    if _integer(
        _required(schedule, "repeats_per_task", "schedule"),
        "schedule.repeats_per_task",
        minimum=0,
    ) != EXPECTED_REPEATS:
        _fail(f"schedule.repeats_per_task must be {EXPECTED_REPEATS}")

    raw_pairs = _list(_required(schedule, "pairs", "schedule"), "schedule.pairs")
    if len(raw_pairs) != EXPECTED_ROOT_PAIRS:
        _fail(f"schedule must contain exactly {EXPECTED_ROOT_PAIRS} root pairs")
    if _integer(
        _required(schedule, "pair_count", "schedule"),
        "schedule.pair_count",
        minimum=0,
    ) != EXPECTED_ROOT_PAIRS:
        _fail(f"schedule.pair_count must be {EXPECTED_ROOT_PAIRS}")
    roots: dict[str, Mapping[str, Any]] = {}
    queue_positions: dict[str, int] = {}
    combinations: set[tuple[str, int]] = set()
    first_by_task: dict[str, list[str]] = {task_id: [] for task_id in task_ids}
    first_by_repeat: dict[int, list[str]] = {
        repeat_id: [] for repeat_id in range(1, EXPECTED_REPEATS + 1)
    }

    for index, raw_pair in enumerate(raw_pairs):
        where = f"schedule.pairs[{index}]"
        pair = _mapping(raw_pair, where)
        pair_id = _string(_required(pair, "pair_id", where), f"{where}.pair_id")
        root_pair_id = _string(
            _required(pair, "root_pair_id", where), f"{where}.root_pair_id"
        )
        if pair_id != root_pair_id:
            _fail(f"{where} must identify a root pair")
        if root_pair_id in roots:
            _fail(f"duplicate scheduled root pair: {root_pair_id}")
        task_id = _string(_required(pair, "task_id", where), f"{where}.task_id")
        if task_id not in first_by_task:
            _fail(f"{where}.task_id is unexpected: {task_id}")
        repeat_id = _integer(
            _required(pair, "repeat_id", where),
            f"{where}.repeat_id",
            minimum=1,
            maximum=EXPECTED_REPEATS,
        )
        combination = (task_id, repeat_id)
        if combination in combinations:
            _fail(f"duplicate scheduled task/repeat: {task_id}/{repeat_id}")
        combinations.add(combination)
        first_arm = _string(
            _required(pair, "first_arm", where), f"{where}.first_arm"
        )
        second_arm = _string(
            _required(pair, "second_arm", where), f"{where}.second_arm"
        )
        if {first_arm, second_arm} != set(EXPECTED_ARMS):
            _fail(f"{where} must contain candidate and control once each")
        arm_order = _string(
            _required(pair, "arm_order", where), f"{where}.arm_order"
        )
        expected_order = "M" if first_arm == "candidate" else "N"
        if arm_order != expected_order:
            _fail(f"{where}.arm_order disagrees with first_arm")
        queue_position = _integer(
            _required(pair, "queue_position", where),
            f"{where}.queue_position",
            minimum=1,
            maximum=EXPECTED_ROOT_PAIRS,
        )
        if queue_position in queue_positions.values():
            _fail(f"duplicate schedule queue position: {queue_position}")
        sequence = _string(
            _required(pair, "sequence", where), f"{where}.sequence"
        )
        if len(sequence) != EXPECTED_REPEATS or any(
            symbol not in "MN" for symbol in sequence
        ):
            _fail(f"{where}.sequence is invalid")
        roots[root_pair_id] = pair
        queue_positions[root_pair_id] = queue_position
        first_by_task[task_id].append(first_arm)
        first_by_repeat[repeat_id].append(first_arm)

    expected_combinations = {
        (task_id, repeat_id)
        for task_id in task_ids
        for repeat_id in range(1, EXPECTED_REPEATS + 1)
    }
    if combinations != expected_combinations:
        _fail("schedule is missing or contains unexpected task/repeat combinations")
    for repeat_id, first_arms in first_by_repeat.items():
        if first_arms.count("candidate") != 6 or first_arms.count("control") != 6:
            _fail(f"repeat {repeat_id} does not have balanced arm order")
    candidate_first_twice = sum(
        first_arms.count("candidate") == 2 for first_arms in first_by_task.values()
    )
    control_first_twice = sum(
        first_arms.count("control") == 2 for first_arms in first_by_task.values()
    )
    if candidate_first_twice != 6 or control_first_twice != 6:
        _fail("task-level arm order is not balanced six/six")

    raw_assignments = _list(
        _required(schedule, "sequence_assignments", "schedule"),
        "schedule.sequence_assignments",
    )
    if len(raw_assignments) != EXPECTED_TASKS:
        _fail("schedule.sequence_assignments must contain one row per task")
    assignments: dict[str, str] = {}
    for index, raw_assignment in enumerate(raw_assignments):
        where = f"schedule.sequence_assignments[{index}]"
        assignment = _mapping(raw_assignment, where)
        task_id = _string(
            _required(assignment, "task_id", where), f"{where}.task_id"
        )
        sequence = _string(
            _required(assignment, "sequence", where), f"{where}.sequence"
        )
        if task_id not in first_by_task or task_id in assignments:
            _fail(f"{where} has duplicate or unexpected task_id")
        actual = "".join(
            "M" if arm == "candidate" else "N" for arm in first_by_task[task_id]
        )
        # Schedule records may be queue-randomized, so derive by repeat order.
        by_repeat = {
            _integer(pair["repeat_id"], "schedule pair repeat"): pair["first_arm"]
            for pair in roots.values()
            if pair["task_id"] == task_id
        }
        actual = "".join(
            "M" if by_repeat[repeat_id] == "candidate" else "N"
            for repeat_id in range(1, EXPECTED_REPEATS + 1)
        )
        if sequence != actual:
            _fail(f"{where}.sequence disagrees with scheduled pairs")
        assignments[task_id] = sequence
    required_sequences = {"MMN", "MNM", "NMM", "NNM", "NMN", "MNN"}
    if set(assignments.values()) != required_sequences or any(
        list(assignments.values()).count(sequence) != 2
        for sequence in required_sequences
    ):
        _fail("sequence assignments must use each registered sequence twice")
    generator = random.Random(randomization_seed)
    assignment_order = list(task_ids)
    generator.shuffle(assignment_order)
    registered_sequences = ("MMN", "MNM", "NMM", "NNM", "NMN", "MNN")
    expected_sequence_by_task: dict[str, str] = {}
    for sequence_index, sequence in enumerate(registered_sequences):
        for task_id in assignment_order[sequence_index * 2 : sequence_index * 2 + 2]:
            expected_sequence_by_task[task_id] = sequence
    expected_pairs: list[dict[str, Any]] = []
    for task_index, task_id in enumerate(task_ids, 1):
        sequence = expected_sequence_by_task[task_id]
        for repeat_id, symbol in enumerate(sequence, 1):
            first_arm = "candidate" if symbol == "M" else "control"
            second_arm = "control" if first_arm == "candidate" else "candidate"
            pair_id = f"pair-{task_index:02d}-r{repeat_id}"
            expected_pairs.append(
                {
                    "arm_order": symbol,
                    "first_arm": first_arm,
                    "pair_id": pair_id,
                    "queue_position": 0,
                    "repeat_id": repeat_id,
                    "root_pair_id": pair_id,
                    "second_arm": second_arm,
                    "sequence": sequence,
                    "task_id": task_id,
                }
            )
    generator.shuffle(expected_pairs)
    for queue_position, pair in enumerate(expected_pairs, 1):
        pair["queue_position"] = queue_position
    expected_schedule = {
        "pair_count": EXPECTED_ROOT_PAIRS,
        "pairs": expected_pairs,
        "randomization_seed": randomization_seed,
        "repeats_per_task": EXPECTED_REPEATS,
        "schema_version": SCHEDULE_SCHEMA_VERSION,
        "sequence_assignments": [
            {"sequence": expected_sequence_by_task[task_id], "task_id": task_id}
            for task_id in task_ids
        ],
        "task_count": EXPECTED_TASKS,
        "task_ids": list(task_ids),
        "worker_count": EXPECTED_WORKERS,
    }
    if schedule != expected_schedule:
        _fail("schedule does not reproduce from its frozen randomization seed")
    return task_ids, roots, queue_positions


def _validate_run_seal(
    seal: Mapping[str, Any],
    artifact_hashes: Mapping[str, str],
    task_ids: Sequence[str],
    *,
    enforce_current_hashes: bool,
) -> tuple[str, str, int]:
    if _string(
        _required(seal, "schema_version", "run_seal"),
        "run_seal.schema_version",
    ) != RUN_SEAL_SCHEMA_VERSION:
        _fail("unsupported run_seal.schema_version")
    mode = _string(_required(seal, "mode", "run_seal"), "run_seal.mode")
    if mode not in {"offline_stub", "live_approved"}:
        _fail("run_seal.mode is unsupported")
    live_mode = mode == "live_approved"
    live_calls = _required(seal, "live_model_calls", "run_seal")
    if (live_mode and live_calls is not None) or (not live_mode and live_calls != 0):
        _fail("run_seal live-call marker conflicts with mode")
    run_id = _string(_required(seal, "run_id", "run_seal"), "run_seal.run_id")
    preregistration_hash = ""
    for name in HASH_NAMES:
        digest = _validate_hash(
            _required(seal, name, "run_seal"), f"run_seal.{name}"
        )
        if name == "preregistration_sha256":
            preregistration_hash = digest
    if preregistration_hash != FINALIZED_PREREGISTRATION_SHA256:
        _fail("run_seal.preregistration_sha256 does not match the finalized protocol")
    if seal["candidate_sha256"] != FROZEN_CANDIDATE_SHA256:
        _fail("run_seal.candidate_sha256 does not match the frozen candidate")
    if seal["control_sha256"] != FROZEN_CONTROL_SHA256:
        _fail("run_seal.control_sha256 does not match the frozen control")
    if enforce_current_hashes:
        runner_path = Path(__file__).with_name("starlette_atomic_pairs.py")
        if not runner_path.is_file() or _sha256_bytes(runner_path.read_bytes()) != seal[
            "runner_sha256"
        ]:
            _fail("run_seal.runner_sha256 does not match current runner bytes")
        if _sha256_bytes(Path(__file__).read_bytes()) != seal["analyzer_sha256"]:
            _fail("run_seal.analyzer_sha256 does not match current analyzer bytes")
        expected_runtime_hash = _sha256_bytes(
            _canonical_json_bytes(
                {
                    "live_model_calls": 0,
                    "mode": "offline_stub",
                    "network_access": False,
                    "provider_integration": False,
                    "subject_timeout_seconds": 900,
                    "worker_count": 12,
                }
            )
        )
        if not live_mode and seal["runtime_manifest_sha256"] != expected_runtime_hash:
            _fail("run_seal.runtime_manifest_sha256 mismatch")
        expected_task_hash = _sha256_bytes(
            _canonical_json_bytes(
                {
                    "mode": "offline_synthetic",
                    "tasks": [
                        {
                            "task_id": task_id,
                            "task_sha256": _sha256_bytes(
                                f"offline-synthetic-starlette-task-v1:{task_id}".encode(
                                    "utf-8"
                                )
                            ),
                        }
                        for task_id in task_ids
                    ],
                }
            )
        )
        if not live_mode and seal["task_manifest_sha256"] != expected_task_hash:
            _fail("run_seal.task_manifest_sha256 mismatch")
    schedule_hash = _validate_hash(
        _required(seal, "schedule_sha256", "run_seal"),
        "run_seal.schedule_sha256",
    )
    if schedule_hash != artifact_hashes["schedule"]:
        _fail("run seal schedule hash mismatch")
    worker_count = _integer(
        _required(seal, "worker_count", "run_seal"),
        "run_seal.worker_count",
        minimum=1,
    )
    if worker_count != EXPECTED_WORKERS:
        _fail(f"run_seal.worker_count must be {EXPECTED_WORKERS}")
    timeout = _finite_number(
        _field(
            seal,
            ("subject_timeout_seconds", "timeout_limit_seconds"),
            "run_seal",
        ),
        "run_seal.subject_timeout_seconds",
        strictly_positive=True,
    )
    if timeout != EXPECTED_TIMEOUT_SECONDS:
        _fail(f"run_seal subject timeout must be {EXPECTED_TIMEOUT_SECONDS:g}")
    replacement_policy = _mapping(
        _required(seal, "replacement_policy", "run_seal"),
        "run_seal.replacement_policy",
    )
    replacement_limit = _required(replacement_policy, "limit", "run_seal.replacement_policy")
    if live_mode:
        replacement_ceiling = _integer(
            replacement_limit, "run_seal.replacement_policy.limit", minimum=0
        )
        if (
            _string(_required(replacement_policy, "source", "run_seal.replacement_policy"),
                    "run_seal.replacement_policy.source") != "approved_live_request"
            or replacement_policy.get("generation_limit") != 1
            or replacement_policy.get("selection")
            != "eligible_roots_by_ascending_base_queue_position"
            or not isinstance(replacement_policy.get("reason_codes"), list)
        ):
            _fail("run_seal live replacement policy is invalid")
        for field in ("request_sha256", "approval_sha256"):
            _validate_hash(_required(seal, field, "run_seal"), f"run_seal.{field}")
        if seal.get("planned_live_model_calls") != 72 or seal.get("max_live_model_calls") != 80:
            _fail("run_seal live call plan/cap mismatch")
    elif replacement_limit is not None:
        replacement_ceiling = _integer(
            replacement_limit,
            "run_seal.replacement_policy.limit",
            minimum=0,
        )
        expected_source = "explicit_synthetic_offline_fixture"
    else:
        replacement_ceiling = 0
        expected_source = "deferred_no_offline_default"
    if not live_mode and _string(
        _required(replacement_policy, "source", "run_seal.replacement_policy"),
        "run_seal.replacement_policy.source",
    ) != expected_source:
        _fail("run_seal replacement policy source disagrees with limit")
    created = _string(_required(seal, "created_utc", "run_seal"), "run_seal.created_utc")
    try:
        from datetime import datetime

        parsed = datetime.fromisoformat(created.replace("Z", "+00:00"))
    except ValueError as error:
        raise AnalysisError("run_seal.created_utc is not ISO-8601") from error
    if parsed.tzinfo is None:
        _fail("run_seal.created_utc must include a timezone")
    return run_id, preregistration_hash, replacement_ceiling


_NORMAL_TERMINATION_CLASSES = {
    "normal_completion",
    "normal_incorrect_completion",
    "refusal",
    "subject_early_stop",
}
_TERMINATION_CLASSES = _NORMAL_TERMINATION_CLASSES | {
    "subject_timeout",
    "replaceable_infrastructure_failure",
    "late_infrastructure_failure",
    "unclassified_abnormal_termination",
}


def _validate_token_fields(
    attempt: Mapping[str, Any], where: str
) -> tuple[float | None, dict[str, int | None]]:
    names = (
        "input_tokens",
        "cached_input_tokens",
        "uncached_input_tokens",
        "output_tokens",
        "reasoning_tokens",
        "total_tokens",
        "uncached_input_plus_output_token_proxy",
    )
    nested = _mapping(
        _required(attempt, "token_components", where), f"{where}.token_components"
    )
    values: dict[str, int | None] = {}
    for name in names:
        value = _required(attempt, name, where)
        if _required(nested, name, f"{where}.token_components") != value:
            _fail(f"{where}.token_components.{name} disagrees with flat field")
        if value is None:
            values[name] = None
        else:
            values[name] = _integer(value, f"{where}.{name}", minimum=0)

    input_tokens = values["input_tokens"]
    cached_tokens = values["cached_input_tokens"]
    output_tokens = values["output_tokens"]
    reasoning_tokens = values["reasoning_tokens"]
    uncached_tokens = values["uncached_input_tokens"]
    total_tokens = values["total_tokens"]
    recorded_proxy = values["uncached_input_plus_output_token_proxy"]
    if input_tokens is not None and cached_tokens is not None:
        if cached_tokens > input_tokens:
            _fail(f"{where}.cached_input_tokens exceeds input_tokens")
        expected_uncached = input_tokens - cached_tokens
        if uncached_tokens is not None and uncached_tokens != expected_uncached:
            _fail(f"{where}.uncached_input_tokens arithmetic mismatch")
    if reasoning_tokens is not None and output_tokens is not None:
        if reasoning_tokens > output_tokens:
            _fail(f"{where}.reasoning_tokens exceeds output_tokens")
    if input_tokens is not None and output_tokens is not None and total_tokens is not None:
        if total_tokens != input_tokens + output_tokens:
            _fail(f"{where}.total_tokens arithmetic mismatch")

    if "token_proxy" in attempt and attempt["token_proxy"] != recorded_proxy:
        _fail(f"{where}.token_proxy disagrees with registered proxy field")
    proxy: float | None = None
    if input_tokens is not None and cached_tokens is not None and output_tokens is not None:
        proxy_value = input_tokens - cached_tokens + output_tokens
        if recorded_proxy is not None and recorded_proxy != proxy_value:
            _fail(f"{where}.token_proxy arithmetic mismatch")
        try:
            proxy = float(proxy_value)
        except OverflowError as error:
            raise AnalysisError(f"{where}.token_proxy is too large") from error
        if not math.isfinite(proxy):
            _fail(f"{where}.token_proxy must be finite")
    elif recorded_proxy is not None:
        # Preserve provider telemetry, but do not treat an unauditable derived
        # field as a deterministic reconstruction of the registered endpoint.
        proxy = None
    return proxy, values


def _validate_attempt(
    raw_attempt: Any,
    index: int,
    *,
    run_id: str,
    run_seal_sha256: str,
    scheduled_roots: Mapping[str, Mapping[str, Any]],
    live_mode: bool,
    allow_legacy_invocation_marker: bool = False,
) -> dict[str, Any]:
    where = f"attempts[{index}]"
    attempt = _mapping(raw_attempt, where)
    if _string(
        _required(attempt, "schema_version", where), f"{where}.schema_version"
    ) != ATTEMPT_SCHEMA_VERSION:
        _fail(f"unsupported {where}.schema_version")
    if _string(_required(attempt, "run_id", where), f"{where}.run_id") != run_id:
        _fail(f"{where}.run_id mismatch")
    if _validate_hash(
        _required(attempt, "run_seal_sha256", where),
        f"{where}.run_seal_sha256",
    ) != run_seal_sha256:
        _fail(f"{where}.run_seal_sha256 mismatch")
    attempt_id = _string(
        _required(attempt, "attempt_id", where), f"{where}.attempt_id"
    )
    pair_id = _string(_required(attempt, "pair_id", where), f"{where}.pair_id")
    root_pair_id = _string(
        _required(attempt, "root_pair_id", where), f"{where}.root_pair_id"
    )
    if root_pair_id not in scheduled_roots:
        _fail(f"{where}.root_pair_id is unexpected")
    replacement_for_pair_id = _required(attempt, "replacement_for_pair_id", where)
    if replacement_for_pair_id is not None:
        _string(replacement_for_pair_id, f"{where}.replacement_for_pair_id")
    replacement_pair_id = _required(attempt, "replacement_pair_id", where)
    if replacement_pair_id is not None:
        _string(replacement_pair_id, f"{where}.replacement_pair_id")
    replacement_generation = _integer(
        _required(attempt, "replacement_generation", where),
        f"{where}.replacement_generation",
        minimum=0,
    )
    task_id = _string(_required(attempt, "task_id", where), f"{where}.task_id")
    repeat_id = _integer(
        _required(attempt, "repeat_id", where),
        f"{where}.repeat_id",
        minimum=1,
        maximum=EXPECTED_REPEATS,
    )
    scheduled = scheduled_roots[root_pair_id]
    if task_id != scheduled["task_id"] or repeat_id != scheduled["repeat_id"]:
        _fail(f"{where} task/repeat disagrees with scheduled root")
    arm = _string(_required(attempt, "arm", where), f"{where}.arm")
    if arm not in EXPECTED_ARMS:
        _fail(f"{where}.arm is unexpected: {arm}")
    arm_index = _integer(
        _required(attempt, "arm_index", where),
        f"{where}.arm_index",
        minimum=1,
        maximum=2,
    )
    first_arm = _string(
        _required(attempt, "first_arm", where), f"{where}.first_arm"
    )
    second_arm = _string(
        _required(attempt, "second_arm", where), f"{where}.second_arm"
    )
    if first_arm != scheduled["first_arm"] or second_arm != scheduled["second_arm"]:
        _fail(f"{where} arm order disagrees with schedule")
    if arm != (first_arm if arm_index == 1 else second_arm):
        _fail(f"{where}.arm disagrees with arm_index")
    worker_id = _string(
        _required(attempt, "worker_id", where), f"{where}.worker_id"
    )
    workspace_path = _string(
        _required(attempt, "workspace_path", where), f"{where}.workspace_path"
    )
    workspace_parts = Path(workspace_path).parts
    if (
        Path(workspace_path).is_absolute()
        or len(workspace_parts) != 2
        or workspace_parts[0] != "workspaces"
        or workspace_parts[1] != attempt_id
        or ".." in workspace_parts
    ):
        _fail(f"{where}.workspace_path is unsafe or disagrees with attempt_id")
    arm_order = _string(
        _required(attempt, "arm_order", where), f"{where}.arm_order"
    )
    if arm_order != ("M" if first_arm == "candidate" else "N"):
        _fail(f"{where}.arm_order disagrees with first_arm")
    queue_position = _integer(
        _required(attempt, "queue_position", where),
        f"{where}.queue_position",
        minimum=1,
    )
    for native_field in (
        "pair_enqueued_monotonic",
        "pair_claimed_monotonic",
        "attempt_start_monotonic",
        "subject_start_monotonic",
        "subject_end_monotonic",
        "attempt_end_monotonic",
        "executor_start_monotonic",
        "executor_end_monotonic",
        "queue_delay_seconds",
        "subject_wall_seconds",
        "total_attempt_duration_seconds",
        "retry_count",
        "rate_limit_count",
        "retry_events",
        "rate_limit_events",
    ):
        _required(attempt, native_field, where)
    for emitted_alias in (
        "enqueued_monotonic",
        "attempt_started_monotonic",
        "attempt_ended_monotonic",
        "queue_duration_seconds",
        "subject_duration_seconds",
        "attempt_duration_seconds",
        "retries",
        "rate_limits",
        "token_proxy",
    ):
        _required(attempt, emitted_alias, where)

    enqueued = _finite_number(
        _field(
            attempt,
            ("pair_enqueued_monotonic", "enqueued_monotonic"),
            where,
        ),
        f"{where}.pair_enqueued_monotonic",
        minimum=0.0,
    )
    claimed = _finite_number(
        _required(attempt, "pair_claimed_monotonic", where),
        f"{where}.pair_claimed_monotonic",
        minimum=0.0,
    )
    attempt_start = _finite_number(
        _field(
            attempt,
            ("attempt_start_monotonic", "attempt_started_monotonic"),
            where,
        ),
        f"{where}.attempt_start_monotonic",
        minimum=0.0,
    )
    subject_start = _finite_number(
        _field(
            attempt,
            ("subject_start_monotonic", "subject_started_monotonic"),
            where,
        ),
        f"{where}.subject_start_monotonic",
        minimum=0.0,
    )
    subject_end = _finite_number(
        _field(
            attempt,
            ("subject_end_monotonic", "subject_ended_monotonic"),
            where,
        ),
        f"{where}.subject_end_monotonic",
        minimum=0.0,
    )
    attempt_end = _finite_number(
        _field(
            attempt,
            ("attempt_end_monotonic", "attempt_ended_monotonic"),
            where,
        ),
        f"{where}.attempt_end_monotonic",
        minimum=0.0,
    )
    if not enqueued <= claimed <= attempt_start <= subject_start <= subject_end <= attempt_end:
        _fail(f"{where} contains impossible monotonic timestamps")
    executor_start = _finite_number(
        _required(attempt, "executor_start_monotonic", where),
        f"{where}.executor_start_monotonic",
        minimum=0.0,
    )
    executor_end = _finite_number(
        _required(attempt, "executor_end_monotonic", where),
        f"{where}.executor_end_monotonic",
        minimum=0.0,
    )
    if not live_mode and not subject_start <= executor_start <= executor_end <= subject_end:
        _fail(f"{where} contains impossible executor timestamps")
    if live_mode and not executor_start <= executor_end <= attempt_end:
        _fail(f"{where} contains impossible live executor timestamps")
    queue_duration = _finite_number(
        _field(
            attempt,
            ("queue_delay_seconds", "queue_duration_seconds", "queue_seconds"),
            where,
        ),
        f"{where}.queue_delay_seconds",
        minimum=0.0,
    )
    subject_duration = _finite_number(
        _field(
            attempt,
            ("subject_wall_seconds", "subject_duration_seconds", "wall_duration_seconds"),
            where,
        ),
        f"{where}.subject_wall_seconds",
        minimum=0.0,
    )
    attempt_duration = _finite_number(
        _field(
            attempt,
            ("total_attempt_duration_seconds", "attempt_duration_seconds"),
            where,
        ),
        f"{where}.total_attempt_duration_seconds",
        minimum=0.0,
    )
    if not _close(queue_duration, claimed - enqueued):
        _fail(f"{where}.queue_delay_seconds arithmetic mismatch")
    if not _close(subject_duration, subject_end - subject_start):
        _fail(f"{where}.subject_wall_seconds arithmetic mismatch")
    if not _close(attempt_duration, attempt_end - attempt_start):
        _fail(f"{where}.total_attempt_duration_seconds arithmetic mismatch")

    valid = _boolean(_required(attempt, "valid", where), f"{where}.valid")
    resolved = _boolean(_required(attempt, "resolved", where), f"{where}.resolved")
    normal = _boolean(
        _required(attempt, "normal_terminal_record", where),
        f"{where}.normal_terminal_record",
    )
    subject_timeout = _boolean(
        _required(attempt, "subject_timeout", where), f"{where}.subject_timeout"
    )
    synthetic_timeout_fault = _boolean(
        _required(attempt, "synthetic_timeout_fault", where),
        f"{where}.synthetic_timeout_fault",
    )
    infrastructure_failure = _boolean(
        _required(attempt, "infrastructure_failure", where),
        f"{where}.infrastructure_failure",
    )
    usable_subject_output = _boolean(
        _required(attempt, "usable_subject_output", where),
        f"{where}.usable_subject_output",
    )
    subject_workspace_changed = _boolean(
        _required(attempt, "subject_workspace_changed", where),
        f"{where}.subject_workspace_changed",
    )
    evidence_preserved = _boolean(
        _required(attempt, "evidence_preserved", where),
        f"{where}.evidence_preserved",
    )
    checker_results_preserved = _boolean(
        _required(attempt, "checker_results_preserved", where),
        f"{where}.checker_results_preserved",
    )
    integrity_checks_passed = _boolean(
        _required(attempt, "integrity_checks_passed", where),
        f"{where}.integrity_checks_passed",
    )
    subject_invocation_started = _boolean(
        False
        if allow_legacy_invocation_marker
        and "subject_invocation_started" not in attempt
        else _required(attempt, "subject_invocation_started", where),
        f"{where}.subject_invocation_started",
    )
    termination_class = _string(
        _required(attempt, "termination_class", where),
        f"{where}.termination_class",
    )
    if termination_class not in _TERMINATION_CLASSES:
        _fail(f"{where}.termination_class is unexpected")
    _string(
        _field(attempt, ("mechanical_reason_code", "reason_code"), where),
        f"{where}.mechanical_reason_code",
    )
    retries = _integer(
        _field(attempt, ("retry_count", "retries"), where),
        f"{where}.retry_count",
        minimum=0,
    )
    rate_limits = _integer(
        _field(attempt, ("rate_limit_count", "rate_limits"), where),
        f"{where}.rate_limit_count",
        minimum=0,
    )
    for event_name, count in (
        ("retry_events", retries),
        ("rate_limit_events", rate_limits),
    ):
        events = _list(
            _required(attempt, event_name, where), f"{where}.{event_name}"
        )
        expected_events = [
            {"index": event_index, "source": (
                "live_event_stream" if live_mode else "synthetic_offline_fixture"
            )}
            for event_index in range(1, count + 1)
        ]
        if events != expected_events:
            _fail(f"{where}.{event_name} disagrees with its registered count")
    trajectory_length = _integer(
        _required(attempt, "trajectory_length", where),
        f"{where}.trajectory_length",
        minimum=0,
    )
    del retries, rate_limits, trajectory_length
    if _finite_number(
        _required(attempt, "subject_timeout_limit_seconds", where),
        f"{where}.subject_timeout_limit_seconds",
        strictly_positive=True,
    ) != EXPECTED_TIMEOUT_SECONDS:
        _fail(f"{where}.subject_timeout_limit_seconds mismatch")

    if normal != (termination_class in _NORMAL_TERMINATION_CLASSES):
        _fail(f"{where}.normal_terminal_record disagrees with termination_class")
    if termination_class == "normal_incorrect_completion" and resolved:
        _fail(f"{where} normal incorrect completion cannot be resolved")
    if subject_timeout != (termination_class == "subject_timeout"):
        _fail(f"{where}.subject_timeout disagrees with termination_class")
    if synthetic_timeout_fault != (
        not live_mode and termination_class == "subject_timeout"
    ):
        _fail(
            f"{where}.synthetic_timeout_fault disagrees with termination_class"
        )
    if infrastructure_failure != (
        termination_class
        in {"replaceable_infrastructure_failure", "late_infrastructure_failure"}
    ):
        _fail(f"{where}.infrastructure_failure disagrees with termination_class")
    timeout_tolerance = max(0.001, EXPECTED_TIMEOUT_SECONDS * 1e-6)
    if not subject_timeout and subject_duration >= EXPECTED_TIMEOUT_SECONDS:
        _fail(f"{where} non-timeout termination reaches the frozen subject timeout")
    # This implementation accepts offline-stub evidence only.  The runner marks
    # an injected timeout fault explicitly because a deterministic preflight must
    # not spend 900 wall-clock seconds.  An unmarked/live timeout is therefore not
    # representable in this schema and cannot use the short-duration exception.
    if not live_mode and synthetic_timeout_fault and not (
        0.0 < subject_duration <= EXPECTED_TIMEOUT_SECONDS + timeout_tolerance
    ):
        _fail(f"{where} synthetic timeout duration is inconsistent with the limit")
    if termination_class in _NORMAL_TERMINATION_CLASSES | {"subject_timeout"}:
        if not valid:
            _fail(f"{where} scientific termination must be valid")
    elif termination_class == "replaceable_infrastructure_failure" and valid:
        _fail(f"{where} replaceable infrastructure failure cannot be valid")
    elif termination_class in {
        "late_infrastructure_failure",
        "unclassified_abnormal_termination",
    } and valid != (usable_subject_output or subject_workspace_changed):
        _fail(f"{where} abnormal validity disagrees with usable subject evidence")
    if resolved and not (
        valid
        and evidence_preserved
        and checker_results_preserved
        and integrity_checks_passed
    ):
        _fail(f"{where}.resolved lacks valid preserved checker evidence")
    if infrastructure_failure and usable_subject_output:
        if termination_class == "replaceable_infrastructure_failure":
            _fail(f"{where} replaceable infrastructure failure has usable subject output")
    if termination_class == "replaceable_infrastructure_failure" and subject_workspace_changed:
        _fail(f"{where} replaceable infrastructure failure changed the workspace")
    if valid and not evidence_preserved:
        _fail(f"{where} valid attempt lacks preserved evidence")

    token_proxy, token_fields = _validate_token_fields(attempt, where)
    return {
        "record": attempt,
        "attempt_id": attempt_id,
        "pair_id": pair_id,
        "root_pair_id": root_pair_id,
        "replacement_for_pair_id": replacement_for_pair_id,
        "replacement_pair_id": replacement_pair_id,
        "replacement_generation": replacement_generation,
        "task_id": task_id,
        "repeat_id": repeat_id,
        "arm": arm,
        "arm_index": arm_index,
        "first_arm": first_arm,
        "second_arm": second_arm,
        "worker_id": worker_id,
        "workspace_path": workspace_path,
        "queue_position": queue_position,
        "enqueued": enqueued,
        "claimed": claimed,
        "attempt_start": attempt_start,
        "subject_start": subject_start,
        "subject_end": subject_end,
        "attempt_end": attempt_end,
        "executor_start": executor_start,
        "executor_end": executor_end,
        "wall": subject_duration,
        "valid": valid,
        "resolved": resolved,
        "normal": normal,
        "subject_timeout": subject_timeout,
        "synthetic_timeout_fault": synthetic_timeout_fault,
        "infrastructure_failure": infrastructure_failure,
        "usable_subject_output": usable_subject_output,
        "subject_workspace_changed": subject_workspace_changed,
        "evidence_preserved": evidence_preserved,
        "checker_results_preserved": checker_results_preserved,
        "integrity_checks_passed": integrity_checks_passed,
        "subject_invocation_started": subject_invocation_started,
        "termination_class": termination_class,
        "token_proxy": token_proxy,
        "token_fields": token_fields,
    }


def _validate_pair(
    raw_pair: Any,
    index: int,
    *,
    run_id: str,
    run_seal_sha256: str,
    scheduled_roots: Mapping[str, Mapping[str, Any]],
    attempts_by_id: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    where = f"pairs[{index}]"
    pair = _mapping(raw_pair, where)
    if _string(
        _required(pair, "schema_version", where), f"{where}.schema_version"
    ) != PAIR_SCHEMA_VERSION:
        _fail(f"unsupported {where}.schema_version")
    if _string(_required(pair, "run_id", where), f"{where}.run_id") != run_id:
        _fail(f"{where}.run_id mismatch")
    if _validate_hash(
        _required(pair, "run_seal_sha256", where), f"{where}.run_seal_sha256"
    ) != run_seal_sha256:
        _fail(f"{where}.run_seal_sha256 mismatch")
    pair_id = _string(_required(pair, "pair_id", where), f"{where}.pair_id")
    root_pair_id = _string(
        _required(pair, "root_pair_id", where), f"{where}.root_pair_id"
    )
    if root_pair_id not in scheduled_roots:
        _fail(f"{where}.root_pair_id is unexpected")
    replacement_for = _required(pair, "replacement_for_pair_id", where)
    if replacement_for is not None:
        _string(replacement_for, f"{where}.replacement_for_pair_id")
    replacement_pair_id = _required(pair, "replacement_pair_id", where)
    if replacement_pair_id is not None:
        _string(replacement_pair_id, f"{where}.replacement_pair_id")
    generation = _integer(
        _required(pair, "replacement_generation", where),
        f"{where}.replacement_generation",
        minimum=0,
    )
    if (generation == 0) != (pair_id == root_pair_id and replacement_for is None):
        _fail(f"{where} has invalid root/replacement generation linkage")
    if generation > 0 and replacement_for is None:
        _fail(f"{where} replacement is missing its parent")

    scheduled = scheduled_roots[root_pair_id]
    task_id = _string(_required(pair, "task_id", where), f"{where}.task_id")
    repeat_id = _integer(
        _required(pair, "repeat_id", where),
        f"{where}.repeat_id",
        minimum=1,
        maximum=EXPECTED_REPEATS,
    )
    first_arm = _string(
        _required(pair, "first_arm", where), f"{where}.first_arm"
    )
    second_arm = _string(
        _required(pair, "second_arm", where), f"{where}.second_arm"
    )
    if (
        task_id != scheduled["task_id"]
        or repeat_id != scheduled["repeat_id"]
        or first_arm != scheduled["first_arm"]
        or second_arm != scheduled["second_arm"]
    ):
        _fail(f"{where} disagrees with scheduled root")
    worker_id = _string(_required(pair, "worker_id", where), f"{where}.worker_id")
    if _string(_required(pair, "arm_order", where), f"{where}.arm_order") != (
        "M" if first_arm == "candidate" else "N"
    ):
        _fail(f"{where}.arm_order disagrees with first_arm")
    queue_position = _integer(
        _required(pair, "queue_position", where),
        f"{where}.queue_position",
        minimum=1,
    )
    for emitted_alias in (
        "pair_claimed_monotonic",
        "pair_completed_monotonic",
        "pair_end_monotonic",
        "resource_exclusion_reason",
    ):
        _required(pair, emitted_alias, where)
    status_raw = _string(_required(pair, "status", where), f"{where}.status")
    if status_raw not in {"complete", "superseded", "incomplete"}:
        _fail(f"{where}.status is unexpected")
    status = status_raw
    structural_valid = _boolean(
        _required(pair, "structural_valid", where), f"{where}.structural_valid"
    )
    if not structural_valid:
        _fail(f"{where} is not structurally valid")
    exclusion_reason = _field(
        pair,
        ("exclusion_reason", "resource_exclusion_reason"),
        where,
    )
    if exclusion_reason is not None:
        _string(exclusion_reason, f"{where}.resource_exclusion_reason")

    raw_attempt_ids = _list(
        _required(pair, "attempt_ids", where), f"{where}.attempt_ids"
    )
    attempt_ids = [
        _string(value, f"{where}.attempt_ids[{position}]")
        for position, value in enumerate(raw_attempt_ids)
    ]
    if len(set(attempt_ids)) != len(attempt_ids):
        _fail(f"{where}.attempt_ids contains duplicates")
    if any(attempt_id not in attempts_by_id for attempt_id in attempt_ids):
        _fail(f"{where}.attempt_ids references a missing attempt")
    pair_attempts = [attempts_by_id[attempt_id] for attempt_id in attempt_ids]
    if [attempt["arm_index"] for attempt in pair_attempts] != list(
        range(1, len(pair_attempts) + 1)
    ):
        _fail(f"{where}.attempt_ids are not in frozen arm order")
    for attempt in pair_attempts:
        if (
            attempt["pair_id"] != pair_id
            or attempt["root_pair_id"] != root_pair_id
            or attempt["replacement_for_pair_id"] != replacement_for
            or attempt["task_id"] != task_id
            or attempt["repeat_id"] != repeat_id
            or attempt["first_arm"] != first_arm
            or attempt["second_arm"] != second_arm
            or attempt["worker_id"] != worker_id
            or attempt["replacement_generation"] != generation
            or attempt["queue_position"] != queue_position
        ):
            _fail(f"{where} disagrees with referenced attempt {attempt['attempt_id']}")
        if attempt["replacement_pair_id"] != replacement_pair_id:
            _fail(f"{where} replacement child disagrees with referenced attempt")

    enqueued = _finite_number(
        _field(
            pair,
            ("enqueued_monotonic", "pair_enqueued_monotonic"),
            where,
        ),
        f"{where}.enqueued_monotonic",
        minimum=0.0,
    )
    claimed_values = {attempt["claimed"] for attempt in pair_attempts}
    if len(claimed_values) != 1:
        _fail(f"{where} attempts disagree on pair claimed time")
    claimed = next(iter(claimed_values))
    if "pair_claimed_monotonic" in pair:
        recorded_claimed = _finite_number(
            pair["pair_claimed_monotonic"],
            f"{where}.pair_claimed_monotonic",
            minimum=0.0,
        )
        if recorded_claimed != claimed:
            _fail(f"{where}.pair_claimed_monotonic disagrees with attempts")
    started = _finite_number(
        _field(
            pair,
            ("started_monotonic", "pair_start_monotonic"),
            where,
        ),
        f"{where}.started_monotonic",
        minimum=0.0,
    )
    completed = _finite_number(
        _field(
            pair,
            ("completed_monotonic", "pair_end_monotonic", "pair_completed_monotonic"),
            where,
        ),
        f"{where}.completed_monotonic",
        minimum=0.0,
    )
    pair_duration = _finite_number(
        _required(pair, "pair_duration_seconds", where),
        f"{where}.pair_duration_seconds",
        minimum=0.0,
    )
    if not enqueued <= claimed <= started <= completed:
        _fail(f"{where} contains impossible monotonic timestamps")
    if not _close(pair_duration, completed - claimed):
        _fail(f"{where}.pair_duration_seconds arithmetic mismatch")
    queue_delay = _finite_number(
        _field(
            pair,
            ("queue_delay_seconds", "queue_duration_seconds"),
            where,
        ),
        f"{where}.queue_delay_seconds",
        minimum=0.0,
    )
    if not _close(queue_delay, claimed - enqueued):
        _fail(f"{where}.queue_delay_seconds arithmetic mismatch")
    for attempt in pair_attempts:
        if attempt["enqueued"] != enqueued:
            _fail(f"{where} enqueued time disagrees with an attempt")
        if attempt["claimed"] != claimed:
            _fail(f"{where} claimed time disagrees with an attempt")
        if attempt["attempt_start"] < started or attempt["attempt_end"] > completed:
            _fail(f"{where} bounds do not contain a referenced attempt")

    mechanical_reason_codes = _list(
        _required(pair, "mechanical_reason_codes", where),
        f"{where}.mechanical_reason_codes",
    )
    termination_classes = _list(
        _required(pair, "termination_classes", where),
        f"{where}.termination_classes",
    )
    if mechanical_reason_codes != [
        attempt["record"]["mechanical_reason_code"] for attempt in pair_attempts
    ]:
        _fail(f"{where}.mechanical_reason_codes disagree with attempts")
    if termination_classes != [
        attempt["termination_class"] for attempt in pair_attempts
    ]:
        _fail(f"{where}.termination_classes disagree with attempts")

    if status == "complete":
        if replacement_pair_id is not None:
            _fail(f"{where} complete terminal pair has a replacement")
        if len(pair_attempts) != 2:
            _fail(f"{where} complete terminal pair must reference exactly two attempts")
        by_arm = {attempt["arm"]: attempt for attempt in pair_attempts}
        if set(by_arm) != set(EXPECTED_ARMS):
            _fail(f"{where} complete terminal pair is missing or duplicates an arm")
        by_index = {attempt["arm_index"]: attempt for attempt in pair_attempts}
        if set(by_index) != {1, 2}:
            _fail(f"{where} complete terminal pair has invalid arm indices")
        if any(
            attempt["termination_class"]
            == "replaceable_infrastructure_failure"
            for attempt in pair_attempts
        ):
            _fail(
                f"{where} complete pair contains a replaceable infrastructure failure"
            )
        if by_index[1]["attempt_end"] > by_index[2]["attempt_start"]:
            _fail(f"{where} arm attempts overlap or execute out of order")
        arm_gap = _required(pair, "arm_gap_seconds", where)
        expected_gap = by_index[2]["subject_start"] - by_index[1]["subject_end"]
        if not _close(
            _finite_number(arm_gap, f"{where}.arm_gap_seconds", minimum=0.0),
            expected_gap,
        ):
            _fail(f"{where}.arm_gap_seconds arithmetic mismatch")
    elif status == "superseded":
        if replacement_pair_id is None:
            _fail(f"{where} superseded pair has no replacement_pair_id")
        if len(pair_attempts) != 1:
            _fail(f"{where} superseded pair must preserve exactly one failed first arm")
        if (
            pair_attempts[0]["arm_index"] != 1
            or pair_attempts[0]["termination_class"]
            != "replaceable_infrastructure_failure"
        ):
            _fail(f"{where} was superseded without a first-arm replaceable failure")
        if any(
            attempt["valid"]
            or attempt["resolved"]
            or attempt["normal"]
            or attempt["usable_subject_output"]
            for attempt in pair_attempts
        ):
            _fail(f"{where} superseded pair contains usable scientific work")
        if not pair_attempts[0]["evidence_preserved"]:
            _fail(f"{where} superseded pair lacks preserved failure evidence")
        if _required(pair, "arm_gap_seconds", where) is not None:
            _fail(f"{where}.arm_gap_seconds must be null for an incomplete pair")
    else:
        if replacement_pair_id is not None:
            _fail(f"{where} terminal incomplete pair cannot point to a replacement")
        if len(pair_attempts) != 1:
            _fail(f"{where} explicit incomplete pair must preserve exactly one attempt")
        attempt = pair_attempts[0]
        if attempt["arm_index"] != 1 or attempt["termination_class"] != (
            "replaceable_infrastructure_failure"
        ):
            _fail(
                f"{where} explicit incomplete pair must end after a first-arm "
                "replaceable infrastructure failure"
            )
        if (
            attempt["valid"]
            or attempt["resolved"]
            or attempt["normal"]
            or attempt["usable_subject_output"]
        ):
            _fail(f"{where} incomplete pair contains usable scientific work")
        if not attempt["evidence_preserved"]:
            _fail(f"{where} incomplete pair lacks preserved failure evidence")
        if _required(pair, "arm_gap_seconds", where) is not None:
            _fail(f"{where}.arm_gap_seconds must be null for an incomplete pair")

    if len(pair_attempts) != 2:
        derived_exclusion_reason = "missing_arm"
    else:
        derived_exclusion_reason = None
        for attempt in pair_attempts:
            if not attempt["valid"]:
                derived_exclusion_reason = "invalid_attempt"
                break
            if not attempt["normal"]:
                derived_exclusion_reason = "non_normal_terminal_record"
                break
            if not attempt["resolved"]:
                derived_exclusion_reason = "mechanically_unresolved"
                break
            if not math.isfinite(attempt["wall"]) or attempt["wall"] <= 0.0:
                derived_exclusion_reason = "invalid_wall_duration"
                break
    eligible = derived_exclusion_reason is None
    if exclusion_reason != derived_exclusion_reason:
        _fail(f"{where}.exclusion_reason disagrees with attempt evidence")
    if _boolean(
        _required(pair, "resource_eligible", where), f"{where}.resource_eligible"
    ) != eligible:
        _fail(f"{where}.resource_eligible disagrees with attempt evidence")
    token_complete = eligible and all(
        attempt["token_proxy"] is not None for attempt in pair_attempts
    )
    if _boolean(
        _required(pair, "token_telemetry_complete", where),
        f"{where}.token_telemetry_complete",
    ) != token_complete:
        _fail(f"{where}.token_telemetry_complete disagrees with attempt evidence")

    return {
        "record": pair,
        "pair_id": pair_id,
        "root_pair_id": root_pair_id,
        "replacement_for_pair_id": replacement_for,
        "replacement_pair_id": replacement_pair_id,
        "replacement_generation": generation,
        "task_id": task_id,
        "repeat_id": repeat_id,
        "first_arm": first_arm,
        "second_arm": second_arm,
        "worker_id": worker_id,
        "queue_position": queue_position,
        "status": status,
        "attempt_ids": attempt_ids,
        "attempts": pair_attempts,
        "enqueued": enqueued,
        "claimed": claimed,
        "started": started,
        "completed": completed,
        "exclusion_reason": exclusion_reason,
    }


def _resolve_replacement_chains(
    pairs: Sequence[Mapping[str, Any]],
    scheduled_roots: Mapping[str, Mapping[str, Any]],
) -> tuple[dict[str, Mapping[str, Any]], list[Mapping[str, Any]]]:
    pairs_by_id: dict[str, Mapping[str, Any]] = {}
    by_root: dict[str, list[Mapping[str, Any]]] = {
        root_pair_id: [] for root_pair_id in scheduled_roots
    }
    for pair in pairs:
        pair_id = pair["pair_id"]
        if pair_id in pairs_by_id:
            _fail(f"duplicate pair record: {pair_id}")
        pairs_by_id[pair_id] = pair
        by_root[pair["root_pair_id"]].append(pair)

    terminals: dict[str, Mapping[str, Any]] = {}
    superseded: list[Mapping[str, Any]] = []
    for root_pair_id, chain_records in by_root.items():
        if not chain_records:
            _fail(f"missing pair record for scheduled root: {root_pair_id}")
        roots = [pair for pair in chain_records if pair["pair_id"] == root_pair_id]
        if len(roots) != 1:
            _fail(f"replacement chain has missing/duplicate root: {root_pair_id}")
        seen: set[str] = set()
        current = roots[0]
        expected_generation = 0
        while True:
            pair_id = current["pair_id"]
            if pair_id in seen:
                _fail(f"replacement chain cycle at {pair_id}")
            seen.add(pair_id)
            if current["replacement_generation"] != expected_generation:
                _fail(f"replacement generation gap at {pair_id}")
            child_id = current["replacement_pair_id"]
            if child_id is None:
                if current["status"] not in {"complete", "incomplete"}:
                    _fail(f"replacement chain has no explicit terminal pair: {root_pair_id}")
                terminals[root_pair_id] = current
                break
            if current["status"] != "superseded":
                _fail(f"non-superseded pair points to replacement: {pair_id}")
            if child_id not in pairs_by_id:
                _fail(f"replacement chain child is missing: {child_id}")
            child = pairs_by_id[child_id]
            if child["root_pair_id"] != root_pair_id:
                _fail(f"replacement child changes root: {child_id}")
            if child["replacement_for_pair_id"] != pair_id:
                _fail(f"replacement child does not point back to parent: {child_id}")
            superseded.append(current)
            current = child
            expected_generation += 1
        if seen != {pair["pair_id"] for pair in chain_records}:
            _fail(f"replacement chain contains an orphan or branch: {root_pair_id}")
    if len(terminals) != EXPECTED_ROOT_PAIRS:
        _fail(f"expected {EXPECTED_ROOT_PAIRS} terminal pairs")
    return terminals, superseded


def _manifest_artifact_hashes(manifest: Mapping[str, Any]) -> Mapping[str, Any]:
    value = _required(manifest, "artifact_sha256", "manifest")
    return _mapping(value, "manifest.artifact_sha256")


def _validate_manifest(
    manifest: Mapping[str, Any],
    *,
    artifact_hashes: Mapping[str, str],
    artifact_sizes: Mapping[str, Any] | None,
    run_id: str,
    run_seal_sha256: str,
    attempts_count: int,
    started_invocation_count: int,
    pair_records_count: int,
    superseded_count: int,
    complete_terminal_count: int,
    scheduler_event_count: int | None,
    preregistration_sha256: str,
    live_mode: bool,
) -> None:
    if _string(
        _required(manifest, "schema_version", "manifest"),
        "manifest.schema_version",
    ) != MANIFEST_SCHEMA_VERSION:
        _fail("unsupported manifest.schema_version")
    if _string(_required(manifest, "run_id", "manifest"), "manifest.run_id") != run_id:
        _fail("manifest.run_id mismatch")
    if _validate_hash(
        _required(manifest, "run_seal_sha256", "manifest"),
        "manifest.run_seal_sha256",
    ) != run_seal_sha256:
        _fail("manifest.run_seal_sha256 mismatch")
    if _validate_hash(
        _required(manifest, "preregistration_sha256", "manifest"),
        "manifest.preregistration_sha256",
    ) != preregistration_sha256:
        _fail("manifest.preregistration_sha256 mismatch")
    if _string(_required(manifest, "status", "manifest"), "manifest.status") != "complete":
        _fail("manifest.status must be complete")
    worker_count = _integer(
        _required(manifest, "worker_count", "manifest"),
        "manifest.worker_count",
        minimum=1,
    )
    if worker_count != EXPECTED_WORKERS:
        _fail(f"manifest.worker_count must be {EXPECTED_WORKERS}")
    if _integer(
        _required(manifest, "task_count", "manifest"),
        "manifest.task_count",
        minimum=0,
    ) != EXPECTED_TASKS:
        _fail(f"manifest.task_count must be {EXPECTED_TASKS}")
    if _integer(
        _required(manifest, "repeats", "manifest"),
        "manifest.repeats",
        minimum=0,
    ) != EXPECTED_REPEATS:
        _fail(f"manifest.repeats must be {EXPECTED_REPEATS}")

    actual_hashes = _manifest_artifact_hashes(manifest)
    filename_for_key = {
        "schedule": "schedule.json",
        "run_seal": "run-seal.json",
        "attempts": "attempts.jsonl",
        "pairs": "pairs.jsonl",
    }
    if "scheduler_events" in artifact_hashes:
        filename_for_key["scheduler_events"] = "scheduler-events.jsonl"
    for key, filename in filename_for_key.items():
        digest = actual_hashes.get(filename, actual_hashes.get(key))
        if _validate_hash(digest, f"manifest.artifact_sha256.{filename}") != artifact_hashes[key]:
            _fail(f"manifest hash mismatch for {filename}")
    expected_artifact_names = set(filename_for_key.values())
    if set(actual_hashes) != expected_artifact_names:
        _fail("manifest.artifact_sha256 inventory mismatch")

    raw_counts = _mapping(
        _required(manifest, "record_counts", "manifest"),
        "manifest.record_counts",
    )
    expected_counts = {
        "scheduled_root_pairs": EXPECTED_ROOT_PAIRS,
        "terminal_pairs": complete_terminal_count,
        "pair_records": pair_records_count,
        "superseded_pairs": superseded_count,
        "attempt_records": attempts_count,
    }
    for key, expected in expected_counts.items():
        actual = _integer(
            _required(raw_counts, key, "manifest.record_counts"),
            f"manifest.record_counts.{key}",
            minimum=0,
        )
        if actual != expected:
            _fail(f"manifest.record_counts.{key} mismatch")
    scalar_counts = {
        "attempt_record_count": attempts_count,
        "pair_record_count": pair_records_count,
        "planned_pair_count": EXPECTED_ROOT_PAIRS,
        "planned_attempt_count": EXPECTED_ROOT_PAIRS * 2,
        "completed_root_pair_count": complete_terminal_count,
        "replacement_pair_count": superseded_count,
    }
    for key, expected in scalar_counts.items():
        if _integer(
            _required(manifest, key, "manifest"), f"manifest.{key}", minimum=0
        ) != expected:
            _fail(f"manifest.{key} mismatch")
    all_scheduled_complete = _boolean(
        _required(manifest, "all_scheduled_pairs_complete", "manifest"),
        "manifest.all_scheduled_pairs_complete",
    )
    if all_scheduled_complete != (complete_terminal_count == EXPECTED_ROOT_PAIRS):
        _fail("manifest all-scheduled-pairs disposition mismatch")
    if _string(
        _required(manifest, "run_status", "manifest"), "manifest.run_status"
    ) != "complete":
        _fail("manifest.run_status must be complete")
    if _integer(
        _required(manifest, "worker_loop_count", "manifest"),
        "manifest.worker_loop_count",
        minimum=0,
    ) != EXPECTED_WORKERS:
        _fail(f"manifest.worker_loop_count must be {EXPECTED_WORKERS}")
    live_calls = _integer(
        _required(manifest, "live_model_calls", "manifest"),
        "manifest.live_model_calls",
        minimum=0,
    )
    if (
        live_mode
        and (live_calls != started_invocation_count or live_calls > 80)
    ) or (
        not live_mode and (live_calls != 0 or started_invocation_count != 0)
    ):
        _fail("manifest live-call count mismatch")
    if scheduler_event_count is not None:
        if _integer(
            _required(manifest, "event_record_count", "manifest"),
            "manifest.event_record_count",
            minimum=0,
        ) != scheduler_event_count:
            _fail("manifest.event_record_count mismatch")

    run_start = _finite_number(
        _required(manifest, "run_start_monotonic", "manifest"),
        "manifest.run_start_monotonic",
        minimum=0.0,
    )
    run_end = _finite_number(
        _required(manifest, "run_end_monotonic", "manifest"),
        "manifest.run_end_monotonic",
        minimum=0.0,
    )
    duration = _finite_number(
        _required(manifest, "duration_seconds", "manifest"),
        "manifest.duration_seconds",
        minimum=0.0,
    )
    if run_end < run_start or not _close(duration, run_end - run_start):
        _fail("manifest contains impossible run timestamps")

    if artifact_sizes is not None:
        sizes = _mapping(
            _required(manifest, "artifact_sizes", "manifest"),
            "manifest.artifact_sizes",
        )
        if set(sizes) != expected_artifact_names:
            _fail("manifest.artifact_sizes inventory mismatch")
        for key, filename in filename_for_key.items():
            size = sizes.get(filename)
            if _integer(size, f"manifest.artifact_sizes.{filename}", minimum=0) != _integer(
                _required(artifact_sizes, key, "_artifact_sizes"),
                f"_artifact_sizes.{key}",
                minimum=0,
            ):
                _fail(f"manifest size mismatch for {filename}")


def _attempt_exclusion_reasons(attempt: Mapping[str, Any]) -> list[str]:
    reasons: list[str] = []
    if not attempt["valid"]:
        reasons.append("invalid_scientific_attempt")
    if not attempt["evidence_preserved"]:
        reasons.append("evidence_not_preserved")
    if not attempt["checker_results_preserved"]:
        reasons.append("checker_results_not_preserved")
    if not attempt["integrity_checks_passed"]:
        reasons.append("integrity_checks_failed")
    if not attempt["normal"]:
        reasons.append("not_normal_terminal")
    if attempt["subject_timeout"]:
        reasons.append("subject_timeout")
    if not attempt["resolved"]:
        reasons.append("mechanically_unresolved")
    if not math.isfinite(attempt["wall"]) or attempt["wall"] <= 0.0:
        reasons.append("nonpositive_or_nonfinite_wall")
    return reasons


def _build_common_pair_selection(
    task_ids: Sequence[str], terminals: Mapping[str, Mapping[str, Any]]
) -> tuple[
    dict[str, list[Mapping[str, Any]]],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    selected: dict[str, list[Mapping[str, Any]]] = {
        task_id: [] for task_id in task_ids
    }
    included_rows: list[dict[str, Any]] = []
    excluded_rows: list[dict[str, Any]] = []
    ordered = sorted(
        terminals.values(), key=lambda pair: (task_ids.index(pair["task_id"]), pair["repeat_id"])
    )
    for pair in ordered:
        reasons_by_arm = {
            attempt["arm"]: _attempt_exclusion_reasons(attempt)
            for attempt in pair["attempts"]
        }
        for arm in EXPECTED_ARMS:
            if arm not in reasons_by_arm:
                reasons_by_arm[arm] = [
                    "attempt_not_launched_after_preusable_infrastructure_failure"
                ]
        if not any(reasons_by_arm.values()):
            selected[pair["task_id"]].append(pair)
            included_rows.append(
                {
                    "task_id": pair["task_id"],
                    "repeat_id": pair["repeat_id"],
                    "pair_id": pair["pair_id"],
                    "root_pair_id": pair["root_pair_id"],
                }
            )
        else:
            excluded_rows.append(
                {
                    "task_id": pair["task_id"],
                    "repeat_id": pair["repeat_id"],
                    "pair_id": pair["pair_id"],
                    "root_pair_id": pair["root_pair_id"],
                    "reasons_by_arm": reasons_by_arm,
                    "recorded_exclusion_reason": pair["exclusion_reason"],
                }
            )
    for pairs in selected.values():
        pairs.sort(key=lambda pair: pair["repeat_id"])
    return selected, included_rows, excluded_rows


def _correctness_result(
    task_ids: Sequence[str], terminals: Mapping[str, Mapping[str, Any]]
) -> dict[str, Any]:
    by_task: list[dict[str, Any]] = []
    totals = {
        arm: {
            "resolved": 0,
            "unresolved": 0,
            "timed_out": 0,
            "not_launched": 0,
            "invalid": 0,
            "total": 0,
        }
        for arm in EXPECTED_ARMS
    }
    pairs_by_task: dict[str, list[Mapping[str, Any]]] = {
        task_id: [] for task_id in task_ids
    }
    for pair in terminals.values():
        pairs_by_task[pair["task_id"]].append(pair)
    for task_id in task_ids:
        arm_rows: dict[str, dict[str, int]] = {}
        for arm in EXPECTED_ARMS:
            attempts = [
                attempt
                for pair in pairs_by_task[task_id]
                for attempt in pair["attempts"]
                if attempt["arm"] == arm
            ]
            if len(attempts) > EXPECTED_REPEATS:
                _fail(f"task {task_id} has too many terminal {arm} attempts")
            resolved = sum(attempt["resolved"] for attempt in attempts)
            timed_out = sum(attempt["subject_timeout"] for attempt in attempts)
            row = {
                "resolved": resolved,
                "unresolved": EXPECTED_REPEATS - resolved,
                "timed_out": timed_out,
                "not_launched": EXPECTED_REPEATS - len(attempts),
                "invalid": sum(not attempt["valid"] for attempt in attempts),
                "total": EXPECTED_REPEATS,
            }
            arm_rows[arm] = row
            for key in totals[arm]:
                totals[arm][key] += row[key]
        by_task.append({"task_id": task_id, "arms": arm_rows})
    for arm in EXPECTED_ARMS:
        if totals[arm]["total"] != EXPECTED_ROOT_PAIRS:
            _fail(f"correctness denominator for {arm} is not {EXPECTED_ROOT_PAIRS}")
    candidate_rate = totals["candidate"]["resolved"] / EXPECTED_ROOT_PAIRS
    control_rate = totals["control"]["resolved"] / EXPECTED_ROOT_PAIRS
    gate_passes = totals["candidate"]["resolved"] >= totals["control"]["resolved"]
    return {
        "reported_first": True,
        "denominator_per_arm": EXPECTED_ROOT_PAIRS,
        "arms": {
            arm: {
                **totals[arm],
                "resolution_rate": totals[arm]["resolved"] / EXPECTED_ROOT_PAIRS,
            }
            for arm in EXPECTED_ARMS
        },
        "resolution_rate_difference_candidate_minus_control": candidate_rate
        - control_rate,
        "absolute_resolution_rate_difference": abs(candidate_rate - control_rate),
        "observed_correctness_gate_passes": gate_passes,
        "noninferiority_tested": False,
        "by_task": by_task,
    }


def _inconclusive_endpoint(name: str, reason: str, details: Any) -> dict[str, Any]:
    return {
        "endpoint": name,
        "status": "inconclusive",
        "reason": reason,
        "details": details,
        "n_tasks": 0,
        "degrees_of_freedom": None,
        "task_results": [],
        "mean_log_ratio": None,
        "ratio": None,
        "reduction_percent": None,
        "sample_standard_deviation": None,
        "standard_error": None,
        "t_statistic": None,
        "t_statistic_nonfinite": None,
        "p_value_two_sided": None,
        "critical_value_two_sided_95": None,
        "confidence_interval_95": None,
        "significant_at_0_05": False,
        "favorable_reduction": False,
    }


def _analyze_endpoint(
    name: str,
    task_ids: Sequence[str],
    selected: Mapping[str, Sequence[Mapping[str, Any]]],
    value_key: str,
) -> dict[str, Any]:
    def arithmetic_mean(values: Sequence[float]) -> float:
        try:
            return statistics.fmean(values)
        except OverflowError:
            scale = max(values)
            return scale * statistics.fmean(value / scale for value in values)

    task_results: list[dict[str, Any]] = []
    effects: list[float] = []
    for task_id in task_ids:
        pairs = selected[task_id]
        by_arm: dict[str, list[float]] = {arm: [] for arm in EXPECTED_ARMS}
        for pair in pairs:
            for attempt in pair["attempts"]:
                value = attempt[value_key]
                if value is None or not math.isfinite(value) or value <= 0.0:
                    _fail(f"internal error: selected {name} value is unavailable")
                by_arm[attempt["arm"]].append(float(value))
        candidate_mean = arithmetic_mean(by_arm["candidate"])
        control_mean = arithmetic_mean(by_arm["control"])
        if not (
            math.isfinite(candidate_mean)
            and candidate_mean > 0.0
            and math.isfinite(control_mean)
            and control_mean > 0.0
        ):
            _fail(f"{name} task arithmetic mean is invalid")
        # Dividing first can underflow to zero even though both registered means
        # are finite and positive.  The difference of logs is algebraically
        # identical and preserves the protocol's no-minimum-floor rule.
        effect = math.log(candidate_mean) - math.log(control_mean)
        effects.append(effect)
        task_results.append(
            {
                "task_id": task_id,
                "usable_repeat_ids": [pair["repeat_id"] for pair in pairs],
                "pair_ids": [pair["pair_id"] for pair in pairs],
                "pair_count": len(pairs),
                "candidate_arithmetic_mean": candidate_mean,
                "control_arithmetic_mean": control_mean,
                "log_ratio": effect,
            }
        )
    if len(effects) != EXPECTED_TASKS or any(not math.isfinite(x) for x in effects):
        _fail("endpoint task-effect vector is malformed")
    mean_effect = statistics.fmean(effects)
    sample_sd = statistics.stdev(effects)
    standard_error = sample_sd / math.sqrt(EXPECTED_TASKS)
    if not all(
        math.isfinite(value) for value in (mean_effect, sample_sd, standard_error)
    ):
        _fail(f"{name} statistics are non-finite")
    degrees_of_freedom = EXPECTED_TASKS - 1
    t_nonfinite: str | None = None
    if standard_error == 0.0:
        if mean_effect == 0.0:
            t_statistic: float | None = 0.0
            p_value = 1.0
        else:
            t_statistic = None
            t_nonfinite = (
                "positive_infinity" if mean_effect > 0.0 else "negative_infinity"
            )
            p_value = 0.0
    else:
        t_statistic = mean_effect / standard_error
        p_value = student_t_two_sided_p(t_statistic, degrees_of_freedom)
    critical = student_t_quantile(1.0 - ALPHA / 2.0, degrees_of_freedom)
    log_lower = mean_effect - critical * standard_error
    log_upper = mean_effect + critical * standard_error
    try:
        ratio = math.exp(mean_effect)
        ratio_lower = math.exp(log_lower)
        ratio_upper = math.exp(log_upper)
    except OverflowError as error:
        raise AnalysisError(f"{name} ratio transformation overflowed") from error
    reduction = 100.0 * (1.0 - ratio)
    reduction_lower = 100.0 * (1.0 - ratio_upper)
    reduction_upper = 100.0 * (1.0 - ratio_lower)
    significant = p_value < ALPHA
    favorable = significant and mean_effect < 0.0
    return {
        "endpoint": name,
        "status": "conclusive",
        "reason": None,
        "details": None,
        "n_tasks": EXPECTED_TASKS,
        "degrees_of_freedom": degrees_of_freedom,
        "task_results": task_results,
        "mean_log_ratio": mean_effect,
        "ratio": ratio,
        "reduction_percent": reduction,
        "sample_standard_deviation": sample_sd,
        "standard_error": standard_error,
        "t_statistic": t_statistic,
        "t_statistic_nonfinite": t_nonfinite,
        "p_value_two_sided": p_value,
        "critical_value_two_sided_95": critical,
        "confidence_interval_95": {
            "log_ratio": {"lower": log_lower, "upper": log_upper},
            "ratio": {"lower": ratio_lower, "upper": ratio_upper},
            "reduction_percent": {
                "lower": reduction_lower,
                "upper": reduction_upper,
            },
        },
        "significant_at_0_05": significant,
        "favorable_reduction": favorable,
    }


def _validate_concurrency(
    attempts: Sequence[Mapping[str, Any]],
) -> tuple[int, int, int]:
    intervals = [
        attempt
        for attempt in attempts
        if attempt["subject_end"] > attempt["subject_start"]
    ]
    events: list[tuple[float, int]] = []
    for attempt in intervals:
        events.append((attempt["subject_start"], 1))
        events.append((attempt["subject_end"], -1))
    # At an exact boundary, the ending attempt is inactive before the new one
    # becomes active.
    active = 0
    peak = 0
    for _, delta in sorted(events, key=lambda row: (row[0], row[1])):
        active += delta
        if active < 0:
            _fail("attempt concurrency events are impossible")
        peak = max(peak, active)
    if active != 0:
        _fail("attempt concurrency events do not close")
    if peak > EXPECTED_WORKERS:
        _fail(f"subject concurrency exceeds {EXPECTED_WORKERS}")

    overlaps = 0
    by_task: dict[str, list[Mapping[str, Any]]] = {}
    for attempt in intervals:
        by_task.setdefault(attempt["task_id"], []).append(attempt)
    for task_attempts in by_task.values():
        for left_index, left in enumerate(task_attempts):
            for right in task_attempts[left_index + 1 :]:
                if left["root_pair_id"] == right["root_pair_id"]:
                    continue
                if (
                    left["subject_start"] < right["subject_end"]
                    and right["subject_start"] < left["subject_end"]
                ):
                    overlaps += 1
    if overlaps:
        _fail("different repeats of the same task overlap")

    executor_events: list[tuple[float, int]] = []
    for attempt in attempts:
        executor_events.append((attempt["executor_start"], 1))
        executor_events.append((attempt["executor_end"], -1))
    executor_active = 0
    executor_peak = 0
    for _, delta in sorted(executor_events, key=lambda row: (row[0], row[1])):
        executor_active += delta
        if executor_active < 0 or executor_active > EXPECTED_WORKERS:
            _fail("executor interval replay violates the frozen concurrency cap")
        executor_peak = max(executor_peak, executor_active)
    if executor_active != 0:
        _fail("executor interval replay does not terminate empty")
    return peak, overlaps, executor_peak


def _validate_scheduler_replay(
    raw_events: Sequence[Any],
    *,
    attempts_by_id: Mapping[str, Mapping[str, Any]],
    pairs_by_id: Mapping[str, Mapping[str, Any]],
    scheduled_roots: Mapping[str, Mapping[str, Any]],
    run_seal_sha256: str,
    live_mode: bool,
) -> int:
    """Replay the complete durable scheduler lifecycle from canonical events."""

    if not raw_events:
        _fail("scheduler event stream is empty")

    by_task: dict[str, list[Mapping[str, Any]]] = {}
    for pair in pairs_by_id.values():
        by_task.setdefault(pair["task_id"], []).append(pair)
    for task_pairs in by_task.values():
        ordered = sorted(task_pairs, key=lambda pair: (pair["started"], pair["completed"]))
        for previous, current in zip(ordered, ordered[1:]):
            if current["started"] < previous["completed"]:
                _fail(
                    "same-task pair intervals overlap: "
                    f"{previous['pair_id']} and {current['pair_id']}"
                )

    common_fields = {
        "active_subjects",
        "event_index",
        "event_type",
        "monotonic_time",
        "run_seal_sha256",
        "schema_version",
    }
    event_fields = {
        "worker_started": {"worker_id"},
        "worker_stopped": {"worker_id"},
        "pair_claimed": {
            "active_pair_count",
            "active_task_ids",
            "pair_id",
            "pending_pair_count",
            "root_pair_id",
            "task_id",
            "worker_id",
        },
        "pair_released": {
            "active_pair_count",
            "active_task_ids",
            "pair_id",
            "pending_pair_count",
            "replacement_pair_id",
            "root_pair_id",
            "task_id",
            "worker_id",
        },
        "subject_started": {"attempt_id", "pair_id", "task_id", "worker_id"},
        "subject_finished": {"attempt_id", "pair_id", "task_id", "worker_id"},
        "attempt_record_durable": {
            "attempt_id",
            "pair_id",
            "task_id",
            "worker_id",
        },
        "pair_record_durable": {
            "pair_id",
            "replacement_pair_id",
            "root_pair_id",
            "task_id",
            "worker_id",
        },
    }
    expected_workers = {f"worker-{index:02d}" for index in range(1, 13)}
    started_workers: set[str] = set()
    stopped_workers: set[str] = set()
    pending_pairs = set(scheduled_roots)
    active_pairs: dict[str, Mapping[str, Any]] = {}
    active_pair_by_worker: dict[str, str] = {}
    claimed_pairs: set[str] = set()
    durable_pairs: set[str] = set()
    released_pairs: set[str] = set()
    active_attempts: dict[str, Mapping[str, Any]] = {}
    active_attempt_by_worker: dict[str, str] = {}
    active_attempt_by_pair: dict[str, str] = {}
    started_attempts: set[str] = set()
    finished_attempts: set[str] = set()
    durable_attempts: set[str] = set()
    previous_time = -math.inf
    peak = 0

    def require_worker(raw: Mapping[str, Any], where: str) -> str:
        worker_id = _string(_required(raw, "worker_id", where), f"{where}.worker_id")
        if worker_id not in expected_workers:
            _fail(f"{where}.worker_id is outside the frozen worker set")
        return worker_id

    def check_pair_identity(
        raw: Mapping[str, Any], where: str, pair: Mapping[str, Any]
    ) -> str:
        worker_id = require_worker(raw, where)
        for field, expected in (
            ("pair_id", pair["pair_id"]),
            ("root_pair_id", pair["root_pair_id"]),
            ("task_id", pair["task_id"]),
        ):
            if _string(_required(raw, field, where), f"{where}.{field}") != expected:
                _fail(f"{where}.{field} disagrees with pair evidence")
        if worker_id != pair["worker_id"]:
            _fail(f"{where}.worker_id disagrees with pair evidence")
        return worker_id

    def check_attempt_identity(
        raw: Mapping[str, Any], where: str, attempt: Mapping[str, Any]
    ) -> str:
        worker_id = require_worker(raw, where)
        for field, expected in (
            ("attempt_id", attempt["attempt_id"]),
            ("pair_id", attempt["pair_id"]),
            ("task_id", attempt["task_id"]),
        ):
            if _string(_required(raw, field, where), f"{where}.{field}") != expected:
                _fail(f"{where}.{field} disagrees with attempt evidence")
        if worker_id != attempt["worker_id"]:
            _fail(f"{where}.worker_id disagrees with attempt evidence")
        return worker_id

    for index, raw_event in enumerate(raw_events, 1):
        where = f"scheduler_events[{index - 1}]"
        event = _mapping(raw_event, where)
        event_type = _string(
            _required(event, "event_type", where), f"{where}.event_type"
        )
        if event_type not in event_fields:
            _fail(f"{where}.event_type is unexpected")
        if set(event) != common_fields | event_fields[event_type]:
            _fail(f"{where} fields do not match the frozen event schema")
        if _string(
            _required(event, "schema_version", where), f"{where}.schema_version"
        ) != EVENT_SCHEMA_VERSION:
            _fail(f"unsupported {where}.schema_version")
        if _validate_hash(
            _required(event, "run_seal_sha256", where),
            f"{where}.run_seal_sha256",
        ) != run_seal_sha256:
            _fail(f"{where}.run_seal_sha256 mismatch")
        if _integer(
            _required(event, "event_index", where),
            f"{where}.event_index",
            minimum=1,
        ) != index:
            _fail(f"{where}.event_index is not contiguous")
        event_time = _finite_number(
            _required(event, "monotonic_time", where),
            f"{where}.monotonic_time",
            minimum=0.0,
        )
        if event_time < previous_time:
            _fail("scheduler event timestamps go backwards")
        previous_time = event_time

        if event_type == "worker_started":
            worker_id = require_worker(event, where)
            if worker_id in started_workers:
                _fail(f"{where} duplicates a worker start")
            started_workers.add(worker_id)
        elif event_type == "worker_stopped":
            worker_id = require_worker(event, where)
            if worker_id not in started_workers or worker_id in stopped_workers:
                _fail(f"{where} has an unmatched worker stop")
            if worker_id in active_pair_by_worker or worker_id in active_attempt_by_worker:
                _fail(f"{where} stops a worker with active work")
            if pending_pairs or active_pairs:
                _fail(f"{where} stops before the scheduler is globally drained")
            stopped_workers.add(worker_id)
        elif event_type == "pair_claimed":
            pair_id = _string(
                _required(event, "pair_id", where), f"{where}.pair_id"
            )
            if pair_id not in pairs_by_id or pair_id not in pending_pairs:
                _fail(f"{where} claims an unknown or non-pending pair")
            pair = pairs_by_id[pair_id]
            worker_id = check_pair_identity(event, where, pair)
            if worker_id not in started_workers or worker_id in stopped_workers:
                _fail(f"{where} assigns an unavailable worker")
            if worker_id in active_pair_by_worker:
                _fail(f"{where} gives one worker two active pairs")
            active_tasks = {row["task_id"] for row in active_pairs.values()}
            eligible = [
                pairs_by_id[pending_id]
                for pending_id in pending_pairs
                if pairs_by_id[pending_id]["task_id"] not in active_tasks
                and not (
                    live_mode
                    and pairs_by_id[pending_id]["replacement_generation"]
                    and not set(scheduled_roots).issubset(claimed_pairs)
                )
            ]
            if not eligible:
                _fail(f"{where} claims a pair when no task is eligible")
            expected_pair = min(eligible, key=lambda row: row["queue_position"])
            if pair_id != expected_pair["pair_id"]:
                _fail(f"{where} violates deterministic queue selection")
            if not pair["claimed"] <= event_time <= pair["started"]:
                _fail(f"{where} claim timestamp disagrees with pair bounds")
            pending_pairs.remove(pair_id)
            active_pairs[pair_id] = pair
            active_pair_by_worker[worker_id] = pair_id
            claimed_pairs.add(pair_id)
            active_tasks = sorted(row["task_id"] for row in active_pairs.values())
            if _integer(
                _required(event, "active_pair_count", where),
                f"{where}.active_pair_count",
                minimum=0,
            ) != len(active_pairs):
                _fail(f"{where}.active_pair_count fails scheduler replay")
            if _list(
                _required(event, "active_task_ids", where),
                f"{where}.active_task_ids",
            ) != active_tasks:
                _fail(f"{where}.active_task_ids fails scheduler replay")
            if _integer(
                _required(event, "pending_pair_count", where),
                f"{where}.pending_pair_count",
                minimum=0,
            ) != len(pending_pairs):
                _fail(f"{where}.pending_pair_count fails scheduler replay")
        elif event_type == "pair_released":
            pair_id = _string(
                _required(event, "pair_id", where), f"{where}.pair_id"
            )
            if pair_id not in active_pairs or pair_id in released_pairs:
                _fail(f"{where} releases a pair without one active claim")
            pair = active_pairs[pair_id]
            worker_id = check_pair_identity(event, where, pair)
            if active_pair_by_worker.get(worker_id) != pair_id:
                _fail(f"{where} releases a pair from the wrong worker")
            if pair_id not in durable_pairs or pair_id in active_attempt_by_pair:
                _fail(f"{where} releases non-durable or active pair evidence")
            if event_time < pair["completed"]:
                _fail(f"{where} predates pair completion")
            replacement_id = _required(event, "replacement_pair_id", where)
            if replacement_id != pair["replacement_pair_id"]:
                _fail(f"{where}.replacement_pair_id disagrees with pair evidence")
            del active_pairs[pair_id]
            del active_pair_by_worker[worker_id]
            released_pairs.add(pair_id)
            if replacement_id is not None:
                if (
                    replacement_id not in pairs_by_id
                    or replacement_id in pending_pairs
                    or replacement_id in claimed_pairs
                ):
                    _fail(f"{where} enqueues an invalid replacement pair")
                replacement = pairs_by_id[replacement_id]
                if replacement["replacement_for_pair_id"] != pair_id:
                    _fail(f"{where} replacement linkage is inconsistent")
                if replacement["enqueued"] > event_time:
                    _fail(f"{where} predates replacement enqueue time")
                pending_pairs.add(replacement_id)
            active_tasks = sorted(row["task_id"] for row in active_pairs.values())
            if _integer(
                _required(event, "active_pair_count", where),
                f"{where}.active_pair_count",
                minimum=0,
            ) != len(active_pairs):
                _fail(f"{where}.active_pair_count fails scheduler replay")
            if _list(
                _required(event, "active_task_ids", where),
                f"{where}.active_task_ids",
            ) != active_tasks:
                _fail(f"{where}.active_task_ids fails scheduler replay")
            if _integer(
                _required(event, "pending_pair_count", where),
                f"{where}.pending_pair_count",
                minimum=0,
            ) != len(pending_pairs):
                _fail(f"{where}.pending_pair_count fails scheduler replay")
        elif event_type in {"subject_started", "subject_finished", "attempt_record_durable"}:
            attempt_id = _string(
                _required(event, "attempt_id", where), f"{where}.attempt_id"
            )
            if attempt_id not in attempts_by_id:
                _fail(f"{where} references an unknown attempt")
            attempt = attempts_by_id[attempt_id]
            worker_id = check_attempt_identity(event, where, attempt)
            pair_id = attempt["pair_id"]
            if pair_id not in active_pairs or active_pair_by_worker.get(worker_id) != pair_id:
                _fail(f"{where} occurs outside its active worker/pair")
            if event_type == "subject_started":
                if attempt_id in started_attempts:
                    _fail(f"{where} duplicates a subject start")
                if worker_id in active_attempt_by_worker or pair_id in active_attempt_by_pair:
                    _fail(f"{where} creates overlapping work on one worker/pair")
                pair_attempt_ids = active_pairs[pair_id]["attempt_ids"]
                prior_ids = pair_attempt_ids[: attempt["arm_index"] - 1]
                if any(prior_id not in durable_attempts for prior_id in prior_ids):
                    _fail(f"{where} starts an arm before prior-arm evidence is durable")
                if event_time != attempt["subject_start"]:
                    _fail(f"{where} subject-start timestamp mismatch")
                active_attempts[attempt_id] = attempt
                active_attempt_by_worker[worker_id] = attempt_id
                active_attempt_by_pair[pair_id] = attempt_id
                started_attempts.add(attempt_id)
            elif event_type == "subject_finished":
                if attempt_id not in active_attempts or attempt_id in finished_attempts:
                    _fail(f"{where} has an unmatched subject finish")
                if not live_mode and event_time != attempt["subject_end"]:
                    _fail(f"{where} subject-finish timestamp mismatch")
                del active_attempts[attempt_id]
                del active_attempt_by_worker[worker_id]
                del active_attempt_by_pair[pair_id]
                finished_attempts.add(attempt_id)
            else:
                if attempt_id not in finished_attempts or attempt_id in durable_attempts:
                    _fail(f"{where} has early or duplicate durable attempt evidence")
                if event_time < attempt["attempt_end"]:
                    _fail(f"{where} predates completed attempt evidence")
                durable_attempts.add(attempt_id)
        else:
            pair_id = _string(
                _required(event, "pair_id", where), f"{where}.pair_id"
            )
            if pair_id not in active_pairs or pair_id in durable_pairs:
                _fail(f"{where} has unknown or duplicate durable pair evidence")
            pair = active_pairs[pair_id]
            check_pair_identity(event, where, pair)
            if _required(event, "replacement_pair_id", where) != pair["replacement_pair_id"]:
                _fail(f"{where}.replacement_pair_id disagrees with pair evidence")
            if any(
                attempt_id not in durable_attempts
                for attempt_id in pair["attempt_ids"]
            ):
                _fail(f"{where} precedes durable attempt evidence")
            if event_time < pair["completed"]:
                _fail(f"{where} predates completed pair evidence")
            durable_pairs.add(pair_id)

        reported_active = _integer(
            _required(event, "active_subjects", where),
            f"{where}.active_subjects",
            minimum=0,
            maximum=EXPECTED_WORKERS,
        )
        if reported_active != len(active_attempts):
            _fail(f"{where}.active_subjects fails scheduler replay")
        peak = max(peak, len(active_attempts))

    if started_workers != expected_workers or stopped_workers != expected_workers:
        _fail("scheduler events omit the frozen worker lifecycle")
    if pending_pairs or active_pairs or active_pair_by_worker:
        _fail("scheduler pair replay does not terminate empty")
    if active_attempts or active_attempt_by_worker or active_attempt_by_pair:
        _fail("scheduler subject replay does not terminate empty")
    expected_attempts = set(attempts_by_id)
    if not (
        started_attempts
        == finished_attempts
        == durable_attempts
        == expected_attempts
    ):
        _fail("scheduler events omit an attempt lifecycle")
    expected_pairs = set(pairs_by_id)
    if not (claimed_pairs == durable_pairs == released_pairs == expected_pairs):
        _fail("scheduler events omit a pair lifecycle")
    return peak


def analyze_records(raw_records: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and analyze a normalized run record dictionary.

    The dictionary has six public keys: ``schedule``, ``run_seal``,
    ``attempts``, ``pairs``, ``scheduler_events``, and ``manifest``.  Directory
    loading adds private exact-byte hash/size maps; callers that provide
    normalized data directly are hashed using the runner's canonical JSON/JSONL
    encoding.  Only the private dict subtype returned by the exact-byte fixture
    loader may omit scheduler events and current implementation hashes.
    """

    records = _mapping(raw_records, "records")
    schedule = _mapping(_required(records, "schedule", "records"), "schedule")
    seal = _mapping(_required(records, "run_seal", "records"), "run_seal")
    raw_attempts = _list(_required(records, "attempts", "records"), "attempts")
    raw_pairs = _list(_required(records, "pairs", "records"), "pairs")
    manifest = _mapping(_required(records, "manifest", "records"), "manifest")
    raw_scheduler_events: list[Any] | None = None
    if "scheduler_events" in records:
        raw_scheduler_events = _list(
            records["scheduler_events"], "scheduler_events"
        )
    synthetic_fixture = records.get("synthetic_fixture", False)
    if type(synthetic_fixture) is not bool:
        _fail("records.synthetic_fixture must be boolean")
    fixture_authorized = isinstance(raw_records, _TrustedSyntheticFixtureRecords)
    if fixture_authorized and not synthetic_fixture:
        _fail("trusted synthetic fixture marker is missing")
    if synthetic_fixture and not fixture_authorized:
        _fail("records.synthetic_fixture is reserved for the pinned test fixture")
    if not fixture_authorized and not isinstance(raw_records, _LoadedRunRecords):
        _fail(
            "non-fixture analysis requires directory-verified workspace evidence"
        )
    if raw_scheduler_events is None and not fixture_authorized:
        _fail("scheduler_events are required outside the frozen synthetic fixture")
    normalized = {
        "schedule": schedule,
        "run_seal": seal,
        "attempts": raw_attempts,
        "pairs": raw_pairs,
        "manifest": manifest,
    }
    if raw_scheduler_events is not None:
        normalized["scheduler_events"] = raw_scheduler_events
    if "_artifact_sha256" in records:
        normalized["_artifact_sha256"] = records["_artifact_sha256"]
    if "_artifact_sizes" in records:
        normalized["_artifact_sizes"] = records["_artifact_sizes"]
    artifact_hashes = _normalized_artifact_hashes(normalized)
    artifact_sizes = _normalized_artifact_sizes(normalized)
    task_ids, scheduled_roots, queue_positions = _validate_schedule(schedule)
    run_id, preregistration_hash, replacement_ceiling = _validate_run_seal(
        seal,
        artifact_hashes,
        task_ids,
        enforce_current_hashes=not fixture_authorized,
    )
    live_mode = seal["mode"] == "live_approved"
    run_seal_sha256 = artifact_hashes["run_seal"]

    attempts: list[dict[str, Any]] = []
    attempts_by_id: dict[str, dict[str, Any]] = {}
    workspaces: set[str] = set()
    for index, raw_attempt in enumerate(raw_attempts):
        attempt = _validate_attempt(
            raw_attempt,
            index,
            run_id=run_id,
            run_seal_sha256=run_seal_sha256,
            scheduled_roots=scheduled_roots,
            live_mode=live_mode,
            allow_legacy_invocation_marker=fixture_authorized,
        )
        if attempt["attempt_id"] in attempts_by_id:
            _fail(f"duplicate attempt record: {attempt['attempt_id']}")
        if attempt["workspace_path"] in workspaces:
            _fail(f"workspace is reused: {attempt['workspace_path']}")
        attempts_by_id[attempt["attempt_id"]] = attempt
        workspaces.add(attempt["workspace_path"])
        attempts.append(attempt)
    if isinstance(raw_records, _LoadedRunRecords):
        verified_workspace_paths = set(
            _list(
                _required(records, "_verified_workspace_paths", "records"),
                "records._verified_workspace_paths",
            )
        )
        expected_workspace_paths = {
            f"{attempt['workspace_path']}/stub-evidence.json" for attempt in attempts
        }
        if (not live_mode and verified_workspace_paths != expected_workspace_paths) or (
            live_mode and not expected_workspace_paths.issubset(verified_workspace_paths)
        ):
            _fail("attempt workspace paths disagree with verified workspace evidence")
        if live_mode and any(
            not any(path.startswith(f"{workspace}/") for workspace in workspaces)
            for path in verified_workspace_paths
        ):
            _fail("live workspace evidence is outside an attempt workspace")
        verified_workspace_evidence = _mapping(
            _required(records, "_verified_workspace_evidence", "records"),
            "records._verified_workspace_evidence",
        )
        if set(verified_workspace_evidence) != expected_workspace_paths:
            _fail("workspace evidence records disagree with attempt inventory")
        for attempt in attempts:
            relative = f"{attempt['workspace_path']}/stub-evidence.json"
            evidence = _mapping(
                verified_workspace_evidence[relative],
                f"records._verified_workspace_evidence.{relative}",
            )
            expected_fields = {"attempt_id", "mode", "outcome", "synthetic"}
            if live_mode:
                expected_fields.add("request_sha256")
            if set(evidence) != expected_fields:
                _fail(f"workspace evidence schema mismatch: {relative}")
            if (
                _string(
                    _required(evidence, "attempt_id", relative),
                    f"{relative}.attempt_id",
                )
                != attempt["attempt_id"]
                or _string(
                    _required(evidence, "mode", relative), f"{relative}.mode"
                )
                != seal["mode"]
                or _boolean(
                    _required(evidence, "synthetic", relative),
                    f"{relative}.synthetic",
                )
                is not (not live_mode)
            ):
                _fail(f"workspace evidence identity mismatch: {relative}")
            if live_mode and _validate_hash(
                _required(evidence, "request_sha256", relative),
                f"{relative}.request_sha256",
            ) != seal["request_sha256"]:
                _fail(f"workspace evidence request mismatch: {relative}")
            outcome = _string(
                _required(evidence, "outcome", relative), f"{relative}.outcome"
            )
            expected_outcome = attempt["termination_class"]
            normalized_second_arm_failure = (
                attempt["arm_index"] == 2
                and expected_outcome == "late_infrastructure_failure"
                and outcome == "replaceable_infrastructure_failure"
                and attempt["record"]["mechanical_reason_code"]
                == "infrastructure_failure_after_prior_arm"
            )
            if outcome != expected_outcome and not normalized_second_arm_failure:
                _fail(f"workspace evidence outcome mismatch: {relative}")

    pairs: list[dict[str, Any]] = []
    for index, raw_pair in enumerate(raw_pairs):
        pairs.append(
            _validate_pair(
                raw_pair,
                index,
                run_id=run_id,
                run_seal_sha256=run_seal_sha256,
                scheduled_roots=scheduled_roots,
                attempts_by_id=attempts_by_id,
            )
        )
    terminals, superseded = _resolve_replacement_chains(pairs, scheduled_roots)
    pairs_by_id = {pair["pair_id"]: pair for pair in pairs}
    if len(superseded) > replacement_ceiling:
        _fail("replacement evidence exceeds the sealed synthetic replacement limit")
    pair_queue_positions = [pair["queue_position"] for pair in pairs]
    if len(pair_queue_positions) != len(set(pair_queue_positions)):
        _fail("pair records contain duplicate queue positions")

    scheduler_replay_peak: int | None = None
    if raw_scheduler_events is not None:
        scheduler_replay_peak = _validate_scheduler_replay(
            raw_scheduler_events,
            attempts_by_id=attempts_by_id,
            pairs_by_id=pairs_by_id,
            scheduled_roots=scheduled_roots,
            run_seal_sha256=run_seal_sha256,
            live_mode=live_mode,
        )
    referenced_attempts = [attempt_id for pair in pairs for attempt_id in pair["attempt_ids"]]
    if len(referenced_attempts) != len(set(referenced_attempts)):
        _fail("an attempt is referenced by multiple pair records")
    if set(referenced_attempts) != set(attempts_by_id):
        _fail("attempt records contain an orphan or pair records omit an attempt")

    for root_pair_id, root in scheduled_roots.items():
        root_record = next(
            (pair for pair in pairs if pair["pair_id"] == root_pair_id), None
        )
        if root_record is None:
            _fail(f"missing root pair record: {root_pair_id}")
        if queue_positions[root_pair_id] != int(root["queue_position"]):
            _fail(f"internal queue-position mismatch: {root_pair_id}")
        if root_record["queue_position"] != queue_positions[root_pair_id]:
            _fail(f"root pair queue position disagrees with schedule: {root_pair_id}")
    for pair in superseded:
        child = pairs_by_id[pair["replacement_pair_id"]]
        if child["claimed"] < pair["completed"]:
            _fail(f"replacement begins before parent completes: {child['pair_id']}")
    if live_mode:
        eligible = [
            root_id
            for root_id in sorted(scheduled_roots, key=queue_positions.get)
            if pairs_by_id[root_id]["attempts"][0]["termination_class"]
            == "replaceable_infrastructure_failure"
        ]
        if {pair["root_pair_id"] for pair in superseded} != set(
            eligible[:replacement_ceiling]
        ):
            _fail("live replacements do not follow frozen base-queue priority")
        reason_codes = set(seal["replacement_policy"]["reason_codes"])
        for pair in superseded:
            if pair["attempts"][0]["record"]["mechanical_reason_code"] not in reason_codes:
                _fail("live replacement uses an unapproved reason code")
            child = pairs_by_id[pair["replacement_pair_id"]]
            if (
                child["replacement_generation"] != 1
                or child["pair_id"] != f"{pair['root_pair_id']}-replacement-1"
                or child["queue_position"] != 36 + queue_positions[pair["root_pair_id"]]
            ):
                _fail("live replacement identity or generation mismatch")

    peak_concurrency, same_task_overlaps, executor_peak = _validate_concurrency(
        attempts
    )
    if (
        scheduler_replay_peak is not None
        and not live_mode
        and scheduler_replay_peak != peak_concurrency
    ):
        _fail("scheduler replay peak disagrees with attempt intervals")
    _validate_manifest(
        manifest,
        artifact_hashes=artifact_hashes,
        artifact_sizes=artifact_sizes,
        run_id=run_id,
        run_seal_sha256=run_seal_sha256,
        attempts_count=len(attempts),
        started_invocation_count=sum(
            attempt["subject_invocation_started"] for attempt in attempts
        ),
        pair_records_count=len(pairs),
        superseded_count=len(superseded),
        complete_terminal_count=sum(
            pair["status"] == "complete" for pair in terminals.values()
        ),
        scheduler_event_count=(
            None if raw_scheduler_events is None else len(raw_scheduler_events)
        ),
        preregistration_sha256=preregistration_hash,
        live_mode=live_mode,
    )
    reported_peak = scheduler_replay_peak if live_mode else peak_concurrency
    if "peak_subject_concurrency" in manifest:
        if _integer(
            manifest["peak_subject_concurrency"],
            "manifest.peak_subject_concurrency",
            minimum=0,
        ) != reported_peak:
            _fail("manifest.peak_subject_concurrency mismatch")
    if "observed_peak_active_subjects" in manifest:
        if _integer(
            manifest["observed_peak_active_subjects"],
            "manifest.observed_peak_active_subjects",
            minimum=0,
        ) != reported_peak:
            _fail("manifest.observed_peak_active_subjects mismatch")
    if "same_task_overlap_count" in manifest:
        if _integer(
            manifest["same_task_overlap_count"],
            "manifest.same_task_overlap_count",
            minimum=0,
        ) != same_task_overlaps:
            _fail("manifest.same_task_overlap_count mismatch")
    if _integer(
        _required(manifest, "observed_peak_executor_calls", "manifest"),
        "manifest.observed_peak_executor_calls",
        minimum=0,
        maximum=EXPECTED_WORKERS,
    ) != executor_peak:
        _fail("manifest.observed_peak_executor_calls mismatch")
    run_start = float(manifest["run_start_monotonic"])
    run_end = float(manifest["run_end_monotonic"])
    if any(
        attempt["enqueued"] < run_start or attempt["attempt_end"] > run_end
        for attempt in attempts
    ):
        _fail("attempt timestamps fall outside manifest run bounds")
    if any(
        pair[timestamp] < run_start or pair[timestamp] > run_end
        for pair in pairs
        for timestamp in ("enqueued", "claimed", "started", "completed")
    ):
        _fail("pair timestamps fall outside manifest run bounds")
    if raw_scheduler_events is not None and any(
        float(event["monotonic_time"]) < run_start
        or float(event["monotonic_time"]) > run_end
        for event in raw_scheduler_events
    ):
        _fail("scheduler event timestamps fall outside manifest run bounds")

    correctness = _correctness_result(task_ids, terminals)
    selected, included_rows, excluded_rows = _build_common_pair_selection(
        task_ids, terminals
    )
    usable_counts = {task_id: len(selected[task_id]) for task_id in task_ids}
    insufficient = [
        {"task_id": task_id, "usable_pair_count": usable_counts[task_id]}
        for task_id in task_ids
        if usable_counts[task_id] < 2
    ]

    selected_token_missing: list[dict[str, Any]] = []
    unselected_token_missing: list[dict[str, Any]] = []
    superseded_token_missing: list[dict[str, Any]] = []
    selected_partial_token_fields: list[dict[str, Any]] = []
    unselected_partial_token_fields: list[dict[str, Any]] = []
    superseded_partial_token_fields: list[dict[str, Any]] = []
    selected_pair_ids = {
        pair["pair_id"] for task_pairs in selected.values() for pair in task_pairs
    }
    for pair in terminals.values():
        target = (
            selected_token_missing
            if pair["pair_id"] in selected_pair_ids
            else unselected_token_missing
        )
        for attempt in pair["attempts"]:
            missing_any = [
                key for key, value in attempt["token_fields"].items() if value is None
            ]
            if missing_any:
                (
                    selected_partial_token_fields
                    if pair["pair_id"] in selected_pair_ids
                    else unselected_partial_token_fields
                ).append(
                    {
                        "pair_id": attempt["pair_id"],
                        "attempt_id": attempt["attempt_id"],
                        "arm": attempt["arm"],
                        "missing_components": missing_any,
                    }
                )
            if attempt["token_proxy"] is None or attempt["token_proxy"] <= 0.0:
                target.append(
                    {
                        "task_id": attempt["task_id"],
                        "repeat_id": attempt["repeat_id"],
                        "pair_id": attempt["pair_id"],
                        "attempt_id": attempt["attempt_id"],
                        "arm": attempt["arm"],
                        "missing_components": [
                            key
                            for key in (
                                "input_tokens",
                                "cached_input_tokens",
                                "output_tokens",
                            )
                            if attempt["token_fields"][key] is None
                        ],
                        "nonpositive_proxy": attempt["token_proxy"] == 0.0,
                    }
                )
    for pair in superseded:
        for attempt in pair["attempts"]:
            missing_any = [
                key for key, value in attempt["token_fields"].items() if value is None
            ]
            if missing_any:
                superseded_partial_token_fields.append(
                    {
                        "pair_id": attempt["pair_id"],
                        "attempt_id": attempt["attempt_id"],
                        "arm": attempt["arm"],
                        "missing_components": missing_any,
                    }
                )
            if attempt["token_proxy"] is None or attempt["token_proxy"] <= 0.0:
                superseded_token_missing.append(
                    {
                        "pair_id": attempt["pair_id"],
                        "attempt_id": attempt["attempt_id"],
                        "arm": attempt["arm"],
                        "missing_components": [
                            key
                            for key in (
                                "input_tokens",
                                "cached_input_tokens",
                                "output_tokens",
                            )
                            if attempt["token_fields"][key] is None
                        ],
                        "nonpositive_proxy": attempt["token_proxy"] == 0.0,
                    }
                )

    if insufficient:
        wall = _inconclusive_endpoint(
            "subject_wall_clock",
            "fewer_than_two_common_usable_pairs",
            insufficient,
        )
        token = _inconclusive_endpoint(
            "uncached_input_plus_output_token_proxy",
            "fewer_than_two_common_usable_pairs",
            insufficient,
        )
    else:
        wall = _analyze_endpoint(
            "subject_wall_clock", task_ids, selected, "wall"
        )
        if selected_token_missing:
            token = _inconclusive_endpoint(
                "uncached_input_plus_output_token_proxy",
                "selected_token_telemetry_missing_or_nonpositive",
                selected_token_missing,
            )
        else:
            token = _analyze_endpoint(
                "uncached_input_plus_output_token_proxy",
                task_ids,
                selected,
                "token_proxy",
            )

    warnings: list[str] = []
    if not correctness["observed_correctness_gate_passes"]:
        for endpoint, label in (
            (wall, "wall-time"),
            (token, "token-proxy"),
        ):
            if endpoint["favorable_reduction"]:
                warnings.append(
                    "Conditional on scheduled pairs in which both arms normally "
                    "completed and mechanically resolved, the candidate's "
                    f"task-weighted {label} ratio was "
                    f"{endpoint['reduction_percent']:.6g}% lower, while resolving "
                    f"{correctness['arms']['candidate']['resolved']}/36 attempts "
                    "versus "
                    f"{correctness['arms']['control']['resolved']}/36 under no MD. "
                    "The observed correctness gate failed. Correctness "
                    "non-inferiority was not tested, and this is not an overall "
                    "better-MD result."
                )

    superseded_rows = [
        {
            "root_pair_id": pair["root_pair_id"],
            "pair_id": pair["pair_id"],
            "replacement_pair_id": pair["replacement_pair_id"],
            "replacement_generation": pair["replacement_generation"],
            "attempt_ids": pair["attempt_ids"],
        }
        for pair in sorted(
            superseded,
            key=lambda pair: (
                task_ids.index(pair["task_id"]),
                pair["repeat_id"],
                pair["replacement_generation"],
            ),
        )
    ]
    incomplete_rows = [
        {
            "root_pair_id": pair["root_pair_id"],
            "pair_id": pair["pair_id"],
            "replacement_generation": pair["replacement_generation"],
            "attempt_ids": pair["attempt_ids"],
            "missing_arms": [
                arm
                for arm in EXPECTED_ARMS
                if arm not in {attempt["arm"] for attempt in pair["attempts"]}
            ],
            "exclusion_reason": pair["exclusion_reason"],
        }
        for pair in sorted(
            terminals.values(),
            key=lambda pair: (task_ids.index(pair["task_id"]), pair["repeat_id"]),
        )
        if pair["status"] == "incomplete"
    ]
    overall_favorable = bool(
        correctness["observed_correctness_gate_passes"]
        and wall["favorable_reduction"]
        and token["favorable_reduction"]
    )
    return {
        "schema_version": ANALYSIS_SCHEMA_VERSION,
        "evidence_validation_mode": (
            "frozen_synthetic_test_fixture"
            if fixture_authorized
            else "sealed_live_run" if live_mode else "sealed_offline_run"
        ),
        "run_id": run_id,
        "preregistration_sha256": preregistration_hash,
        "run_seal_sha256": run_seal_sha256,
        "frozen_hashes": {
            **{name: seal[name] for name in HASH_NAMES},
            "schedule_sha256": artifact_hashes["schedule"],
            "run_seal_sha256": run_seal_sha256,
            "evidence_artifact_sha256": dict(manifest["artifact_sha256"]),
        },
        "design": {
            "task_count": EXPECTED_TASKS,
            "repeats_per_task": EXPECTED_REPEATS,
            "planned_calls_per_arm": EXPECTED_ROOT_PAIRS,
            "root_pair_count": EXPECTED_ROOT_PAIRS,
            "worker_count": EXPECTED_WORKERS,
            "subject_timeout_seconds": EXPECTED_TIMEOUT_SECONDS,
            "alpha_per_endpoint": ALPHA,
            "multiplicity_adjustment": None,
        },
        "correctness": correctness,
        "common_pair_selection": {
            "definition_independent_of_tokens": True,
            "same_set_for_both_endpoints": True,
            "usable_pair_counts_by_task": usable_counts,
            "included_pairs": included_rows,
            "excluded_pairs": excluded_rows,
            "minimum_two_per_task_satisfied": not insufficient,
        },
        "replacement_evidence": {
            "superseded_pair_count": len(superseded_rows),
            "superseded_pairs": superseded_rows,
            "terminal_incomplete_pair_count": len(incomplete_rows),
            "terminal_incomplete_pairs": incomplete_rows,
            "all_attempt_records_preserved": True,
        },
        "token_telemetry": {
            "missing_or_nonpositive_selected": selected_token_missing,
            "missing_or_nonpositive_outside_common_set": unselected_token_missing,
            "missing_or_nonpositive_superseded": superseded_token_missing,
            "partial_components_selected": selected_partial_token_fields,
            "partial_components_outside_common_set": unselected_partial_token_fields,
            "partial_components_superseded": superseded_partial_token_fields,
        },
        "concurrency": {
            "peak_subject_concurrency": peak_concurrency,
            "same_task_overlap_count": same_task_overlaps,
        },
        "endpoints": {
            "wall": wall,
            "token": token,
        },
        "overall_time_and_token_favorable_md_decision": overall_favorable,
        "warnings": warnings,
        "interpretation": {
            "resource_results_are_conditional": True,
            "correctness_noninferiority_tested": False,
            "family_wise_error_control_claimed": False,
        },
    }


def analyze_run_directory(run_directory: str | os.PathLike[str]) -> dict[str, Any]:
    return analyze_records(load_run_directory(run_directory))


def _load_frozen_synthetic_fixture(
    source: Path,
) -> _TrustedSyntheticFixtureRecords:
    """Load the one byte-pinned event-less fixture used by unit tests."""

    if not source.is_file():
        _fail(f"analysis input does not exist: {source}")
    try:
        fixture_bytes = source.read_bytes()
        if _sha256_bytes(fixture_bytes) != FROZEN_SYNTHETIC_FIXTURE_SHA256:
            _fail("normalized fixture bytes do not match the frozen test fixture")
        fixture = json.loads(
            fixture_bytes.decode("utf-8"),
            parse_constant=lambda token: _fail(
                f"{source} contains non-finite JSON number {token}"
            ),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AnalysisError(f"cannot load normalized fixture {source}: {error}") from error
    records = _mapping(fixture, str(source))
    if records.get("synthetic_fixture") is not True:
        _fail("frozen fixture lacks its explicit synthetic marker")
    return _TrustedSyntheticFixtureRecords(records)


def analyze_path(path: str | os.PathLike[str]) -> dict[str, Any]:
    source = Path(path)
    if source.is_dir():
        return analyze_run_directory(source)
    if not source.is_file():
        _fail(f"analysis input does not exist: {source}")
    return analyze_records(_load_frozen_synthetic_fixture(source))


def write_analysis_atomic(
    output_path: str | os.PathLike[str], analysis: Mapping[str, Any]
) -> None:
    """Atomically create an analysis file; an existing destination is fatal."""

    destination = Path(output_path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(
        analysis,
        sort_keys=True,
        indent=2,
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8") + b"\n"
    temporary_name: str | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary_name, destination)
        except FileExistsError as error:
            raise AnalysisError(f"analysis output already exists: {destination}") from error
        directory_descriptor = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate and analyze a Starlette atomic-pair run"
    )
    parser.add_argument(
        "input",
        help="validated run directory (synthetic fixture files are API-test-only)",
    )
    parser.add_argument(
        "--output",
        required=True,
        help="new analysis JSON path (existing files are never overwritten)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _build_parser().parse_args(argv)
    try:
        source = Path(arguments.input)
        if not source.is_dir():
            _fail("CLI input must be a run directory")
        analysis = analyze_run_directory(source)
        write_analysis_atomic(arguments.output, analysis)
    except AnalysisError as error:
        print(f"analysis failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
