"""12-worker atomic-pair runner for the frozen Starlette protocol.

Offline operation remains the default.  Live execution requires an injected
executor plus explicit request/approval bindings and replacement limits.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import random
import re
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Iterable, Mapping, Sequence


WORKER_COUNT = 12
REPEATS = 3
SUBJECT_TIMEOUT_SECONDS = 900
ARMS = ("candidate", "control")
SEQUENCES = ("MMN", "MNM", "NMM", "NNM", "NMN", "MNN")
DEFAULT_TASK_IDS = tuple(f"synthetic-starlette-{index:02d}" for index in range(1, 13))
DEFAULT_SEED = "starlette-atomic-pairs-offline-v1"
DEFAULT_PREREGISTRATION_SHA256 = (
    "565388658f593a14c931757bf1cfe7095c062bd9e332297b1e3225bef5fddcc1"
)
CANDIDATE_SHA256 = (
    "c0d56e29ade34c24278b976e84b29e47324c11a23399ca882239daffc9762c74"
)
CONTROL_SHA256 = (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

SCHEDULE_SCHEMA = "starlette-atomic-pair-schedule-v1"
RUN_SEAL_SCHEMA = "starlette-atomic-pair-run-seal-v1"
ATTEMPT_SCHEMA = "starlette-atomic-pair-attempt-v1"
PAIR_SCHEMA = "starlette-atomic-pair-result-v1"
EVENT_SCHEMA = "starlette-atomic-pair-scheduler-event-v1"
MANIFEST_SCHEMA = "starlette-atomic-pair-manifest-v1"
QUALIFICATION_SCHEMA = "starlette-atomic-pair-qualification-v1"

NORMAL_COMPLETION = "normal_completion"
NORMAL_INCORRECT_COMPLETION = "normal_incorrect_completion"
REFUSAL = "refusal"
SUBJECT_EARLY_STOP = "subject_early_stop"
SUBJECT_TIMEOUT = "subject_timeout"
REPLACEABLE_INFRASTRUCTURE_FAILURE = "replaceable_infrastructure_failure"
LATE_INFRASTRUCTURE_FAILURE = "late_infrastructure_failure"
UNCLASSIFIED_ABNORMAL_TERMINATION = "unclassified_abnormal_termination"
TERMINATION_CLASSES = frozenset(
    {
        NORMAL_COMPLETION,
        NORMAL_INCORRECT_COMPLETION,
        REFUSAL,
        SUBJECT_EARLY_STOP,
        SUBJECT_TIMEOUT,
        REPLACEABLE_INFRASTRUCTURE_FAILURE,
        LATE_INFRASTRUCTURE_FAILURE,
        UNCLASSIFIED_ABNORMAL_TERMINATION,
    }
)

RUN_FILES = (
    "schedule.json",
    "run-seal.json",
    "attempts.jsonl",
    "pairs.jsonl",
    "scheduler-events.jsonl",
    "manifest.json",
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class EvidenceError(ValueError):
    """Raised when frozen evidence is incomplete, inconsistent, or noncanonical."""


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_bytes(value: object) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_sha256(value: object, field: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise EvidenceError(f"{field} must be a lowercase SHA-256")
    return value


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_bytes_once(path: Path, payload: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    descriptor = os.open(path, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError(f"short write for {path}")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _write_json_once(path: Path, value: object) -> str:
    payload = canonical_bytes(value)
    _write_bytes_once(path, payload)
    return sha256_bytes(payload)


def _read_canonical_json(path: Path) -> Any:
    if path.is_symlink() or not path.is_file():
        raise EvidenceError(f"required regular file missing: {path}")
    payload = path.read_bytes()
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError(f"invalid JSON in {path}: {exc}") from exc
    try:
        is_canonical = payload == canonical_bytes(value)
    except (TypeError, ValueError) as exc:
        raise EvidenceError(f"noncanonical JSON: {path}") from exc
    if not is_canonical:
        raise EvidenceError(f"noncanonical JSON: {path}")
    return value


def _read_canonical_jsonl(path: Path) -> list[dict[str, Any]]:
    if path.is_symlink() or not path.is_file():
        raise EvidenceError(f"required regular file missing: {path}")
    records: list[dict[str, Any]] = []
    with path.open("rb") as handle:
        for line_number, payload in enumerate(handle, 1):
            try:
                value = json.loads(payload)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise EvidenceError(
                    f"invalid JSONL record {path}:{line_number}: {exc}"
                ) from exc
            try:
                is_canonical = payload == canonical_bytes(value)
            except (TypeError, ValueError) as exc:
                raise EvidenceError(
                    f"noncanonical JSONL record {path}:{line_number}"
                ) from exc
            if not isinstance(value, dict) or not is_canonical:
                raise EvidenceError(f"noncanonical JSONL record {path}:{line_number}")
            records.append(value)
    return records


class _DurableJsonl:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._handle = path.open("xb", buffering=0)
        os.fsync(self._handle.fileno())
        _fsync_directory(path.parent)
        self.records: list[dict[str, Any]] = []

    def append(self, record: Mapping[str, Any]) -> None:
        frozen = dict(record)
        payload = canonical_bytes(frozen)
        with self._lock:
            self._handle.write(payload)
            os.fsync(self._handle.fileno())
            self.records.append(frozen)

    def close(self) -> None:
        with self._lock:
            if not self._handle.closed:
                self._handle.close()


def _arm_for_symbol(symbol: str) -> str:
    if symbol == "M":
        return "candidate"
    if symbol == "N":
        return "control"
    raise EvidenceError(f"unknown arm-order symbol: {symbol!r}")


def _build_schedule_unvalidated(
    task_ids: Sequence[str] = DEFAULT_TASK_IDS,
    *,
    seed: str = DEFAULT_SEED,
) -> dict[str, Any]:
    """Build the deterministic, balanced 12-task by 3-repeat schedule."""

    tasks = list(task_ids)
    if len(tasks) != 12 or len(set(tasks)) != 12:
        raise EvidenceError("the frozen schedule requires exactly 12 unique task IDs")
    if any(not isinstance(task, str) or not task for task in tasks):
        raise EvidenceError("task IDs must be nonempty strings")
    if not isinstance(seed, str) or not seed:
        raise EvidenceError("randomization seed must be a nonempty string")

    rng = random.Random(seed)
    assignment_order = tasks.copy()
    rng.shuffle(assignment_order)
    sequence_by_task: dict[str, str] = {}
    for sequence_index, sequence in enumerate(SEQUENCES):
        for task in assignment_order[sequence_index * 2 : sequence_index * 2 + 2]:
            sequence_by_task[task] = sequence

    ordinal_by_task = {task: ordinal for ordinal, task in enumerate(tasks, 1)}
    pairs: list[dict[str, Any]] = []
    for task in tasks:
        sequence = sequence_by_task[task]
        for repeat_id, symbol in enumerate(sequence, 1):
            first_arm = _arm_for_symbol(symbol)
            second_arm = "control" if first_arm == "candidate" else "candidate"
            pair_id = f"pair-{ordinal_by_task[task]:02d}-r{repeat_id}"
            pairs.append(
                {
                    "arm_order": symbol,
                    "first_arm": first_arm,
                    "pair_id": pair_id,
                    "queue_position": 0,
                    "repeat_id": repeat_id,
                    "root_pair_id": pair_id,
                    "second_arm": second_arm,
                    "sequence": sequence,
                    "task_id": task,
                }
            )
    rng.shuffle(pairs)
    for queue_position, pair in enumerate(pairs, 1):
        pair["queue_position"] = queue_position

    schedule = {
        "pair_count": 36,
        "randomization_seed": seed,
        "repeats_per_task": REPEATS,
        "schema_version": SCHEDULE_SCHEMA,
        "sequence_assignments": [
            {"sequence": sequence_by_task[task], "task_id": task} for task in tasks
        ],
        "task_count": 12,
        "task_ids": tasks,
        "worker_count": WORKER_COUNT,
        "pairs": pairs,
    }
    return schedule


def build_schedule(
    task_ids: Sequence[str] = DEFAULT_TASK_IDS,
    *,
    seed: str = DEFAULT_SEED,
) -> dict[str, Any]:
    """Build and mechanically validate the frozen balanced schedule."""

    schedule = _build_schedule_unvalidated(task_ids, seed=seed)
    validate_schedule(schedule)
    return schedule


def validate_schedule(schedule: Mapping[str, Any]) -> None:
    if not isinstance(schedule, Mapping):
        raise EvidenceError("schedule must be an object")
    if schedule.get("schema_version") != SCHEDULE_SCHEMA:
        raise EvidenceError("unsupported schedule schema")
    if schedule.get("worker_count") != WORKER_COUNT:
        raise EvidenceError("schedule must freeze exactly 12 workers")
    if schedule.get("repeats_per_task") != REPEATS:
        raise EvidenceError("schedule must freeze exactly three repeats")
    seed = schedule.get("randomization_seed")
    if not isinstance(seed, str) or not seed:
        raise EvidenceError("schedule randomization seed must be a nonempty string")
    tasks = schedule.get("task_ids")
    pairs = schedule.get("pairs")
    assignments = schedule.get("sequence_assignments")
    if not isinstance(tasks, list) or len(tasks) != 12 or len(set(tasks)) != 12:
        raise EvidenceError("schedule must contain exactly 12 unique task IDs")
    if schedule.get("task_count") != 12:
        raise EvidenceError("task_count mismatch")
    if not isinstance(assignments, list) or len(assignments) != 12:
        raise EvidenceError("sequence assignment count mismatch")
    sequence_by_task: dict[str, str] = {}
    for assignment in assignments:
        if not isinstance(assignment, dict):
            raise EvidenceError("invalid sequence assignment")
        task_id = assignment.get("task_id")
        sequence = assignment.get("sequence")
        if task_id in sequence_by_task or task_id not in tasks or sequence not in SEQUENCES:
            raise EvidenceError("invalid or duplicate sequence assignment")
        sequence_by_task[task_id] = sequence
    if Counter(sequence_by_task.values()) != Counter({sequence: 2 for sequence in SEQUENCES}):
        raise EvidenceError("each six-sequence arm order must be assigned to two tasks")
    if not isinstance(pairs, list) or len(pairs) != 36 or schedule.get("pair_count") != 36:
        raise EvidenceError("schedule must contain 36 pairs")

    seen_ids: set[str] = set()
    seen_task_repeats: set[tuple[str, int]] = set()
    positions: set[int] = set()
    first_counts = Counter()
    twice_candidate = 0
    for pair in pairs:
        if not isinstance(pair, dict):
            raise EvidenceError("invalid schedule pair")
        pair_id = pair.get("pair_id")
        task_id = pair.get("task_id")
        repeat_id = pair.get("repeat_id")
        position = pair.get("queue_position")
        if not isinstance(pair_id, str) or pair_id in seen_ids:
            raise EvidenceError("duplicate or invalid pair ID")
        seen_ids.add(pair_id)
        if task_id not in sequence_by_task or repeat_id not in (1, 2, 3):
            raise EvidenceError("invalid task/repeat in schedule pair")
        key = (task_id, repeat_id)
        if key in seen_task_repeats:
            raise EvidenceError("duplicate task/repeat schedule pair")
        seen_task_repeats.add(key)
        if not isinstance(position, int) or position < 1 or position > 36:
            raise EvidenceError("invalid queue position")
        positions.add(position)
        sequence = sequence_by_task[task_id]
        symbol = sequence[repeat_id - 1]
        first_arm = _arm_for_symbol(symbol)
        second_arm = "control" if first_arm == "candidate" else "candidate"
        expected = {
            "arm_order": symbol,
            "first_arm": first_arm,
            "root_pair_id": pair_id,
            "second_arm": second_arm,
            "sequence": sequence,
        }
        if any(pair.get(field) != value for field, value in expected.items()):
            raise EvidenceError("schedule pair conflicts with sequence assignment")
        first_counts[(repeat_id, first_arm)] += 1
    if positions != set(range(1, 37)):
        raise EvidenceError("queue positions must be exactly 1 through 36")
    for repeat_id in (1, 2, 3):
        if first_counts[(repeat_id, "candidate")] != 6:
            raise EvidenceError("each repeat must have six candidate-first pairs")
        if first_counts[(repeat_id, "control")] != 6:
            raise EvidenceError("each repeat must have six control-first pairs")
    for sequence in sequence_by_task.values():
        if sequence.count("M") == 2:
            twice_candidate += 1
    if twice_candidate != 6:
        raise EvidenceError("exactly six tasks must be candidate-first twice")
    expected_schedule = _build_schedule_unvalidated(tasks, seed=seed)
    if canonical_bytes(dict(schedule)) != canonical_bytes(expected_schedule):
        raise EvidenceError("schedule does not match deterministic seed recomputation")


@dataclass(frozen=True)
class StubOutcome:
    termination_class: str = NORMAL_COMPLETION
    resolved: bool | None = None
    delay_seconds: float | None = None
    missing_tokens: bool = False
    usable_subject_output: bool | None = None
    subject_workspace_changed: bool | None = None
    trajectory_length: int | None = None
    retry_count: int = 0
    rate_limit_count: int = 0
    mechanical_reason_code: str | None = None


@dataclass(frozen=True)
class AttemptContext:
    attempt_id: str
    arm: str
    arm_index: int
    pair_id: str
    root_pair_id: str
    task_id: str
    repeat_id: int
    worker_id: str
    workspace: Path
    replacement_generation: int


class DeterministicStubExecutor:
    """Deterministic no-model executor with injectable mechanical outcomes."""

    def __init__(
        self,
        outcomes: Mapping[object, StubOutcome | Mapping[str, Any] | str] | None = None,
        *,
        delay_seconds: float = 0.05,
    ) -> None:
        if delay_seconds < 0:
            raise ValueError("delay_seconds must be nonnegative")
        self.outcomes = dict(outcomes or {})
        self.delay_seconds = delay_seconds

    def _outcome(self, context: AttemptContext) -> StubOutcome:
        keys = (
            context.attempt_id,
            (context.pair_id, context.arm),
            (context.root_pair_id, context.arm, context.replacement_generation),
            (context.task_id, context.repeat_id, context.arm),
        )
        raw: StubOutcome | Mapping[str, Any] | str | None = None
        for key in keys:
            if key in self.outcomes:
                raw = self.outcomes[key]
                break
        if raw is None:
            return StubOutcome()
        if isinstance(raw, StubOutcome):
            return raw
        if isinstance(raw, str):
            return StubOutcome(termination_class=raw)
        if isinstance(raw, Mapping):
            return StubOutcome(**raw)
        raise TypeError(f"unsupported stub outcome for {context.attempt_id}")

    def __call__(self, context: AttemptContext) -> dict[str, Any]:
        outcome = self._outcome(context)
        delay = self.delay_seconds if outcome.delay_seconds is None else outcome.delay_seconds
        if delay < 0:
            raise ValueError("stub delay must be nonnegative")
        fingerprint = hashlib.sha256(context.attempt_id.encode("utf-8")).digest()
        evidence = {
            "attempt_id": context.attempt_id,
            "mode": "offline_stub",
            "outcome": outcome.termination_class,
            "synthetic": True,
        }
        _write_json_once(context.workspace / "stub-evidence.json", evidence)
        if delay:
            time.sleep(delay)

        if outcome.missing_tokens:
            tokens = {
                "cached_input_tokens": None,
                "input_tokens": None,
                "output_tokens": None,
                "reasoning_tokens": None,
                "total_tokens": None,
                "uncached_input_tokens": None,
                "uncached_input_plus_output_token_proxy": None,
            }
        else:
            input_tokens = 420 + fingerprint[0]
            cached_input_tokens = 40 + fingerprint[1] % 31
            output_tokens = 120 + fingerprint[2]
            reasoning_tokens = min(output_tokens, 20 + fingerprint[3] % 51)
            uncached_input_tokens = input_tokens - cached_input_tokens
            tokens = {
                "cached_input_tokens": cached_input_tokens,
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "reasoning_tokens": reasoning_tokens,
                "total_tokens": input_tokens + output_tokens,
                "uncached_input_tokens": uncached_input_tokens,
                "uncached_input_plus_output_token_proxy": (
                    uncached_input_tokens + output_tokens
                ),
            }
        return {
            "mechanical_reason_code": outcome.mechanical_reason_code,
            "rate_limit_count": outcome.rate_limit_count,
            "resolved": outcome.resolved,
            "retry_count": outcome.retry_count,
            "subject_workspace_changed": outcome.subject_workspace_changed,
            "termination_class": outcome.termination_class,
            "token_components": tokens,
            "trajectory_length": outcome.trajectory_length,
            "usable_subject_output": outcome.usable_subject_output,
        }


def classify_termination(
    termination_class: str,
    *,
    resolved: bool | None = None,
    usable_subject_output: bool | None = None,
    subject_workspace_changed: bool | None = None,
    mechanical_reason_code: str | None = None,
) -> dict[str, Any]:
    """Apply the frozen mechanical termination taxonomy without outcome judgment."""

    if termination_class not in TERMINATION_CLASSES:
        raise EvidenceError(f"unknown termination class: {termination_class!r}")
    for field_name, value in (
        ("resolved", resolved),
        ("usable_subject_output", usable_subject_output),
        ("subject_workspace_changed", subject_workspace_changed),
    ):
        if value is not None and type(value) is not bool:
            raise EvidenceError(f"{field_name} must be a boolean or None")
    defaults: dict[str, tuple[bool, bool, bool, bool, bool, str, int]] = {
        NORMAL_COMPLETION: (True, True, False, False, True, "completed", 3),
        NORMAL_INCORRECT_COMPLETION: (
            True,
            True,
            False,
            False,
            True,
            "checker_unresolved",
            3,
        ),
        REFUSAL: (True, True, False, False, True, "subject_refusal", 1),
        SUBJECT_EARLY_STOP: (
            True,
            True,
            False,
            False,
            True,
            "subject_originated_early_stop",
            1,
        ),
        SUBJECT_TIMEOUT: (
            True,
            False,
            True,
            False,
            True,
            "subject_timeout",
            2,
        ),
        REPLACEABLE_INFRASTRUCTURE_FAILURE: (
            False,
            False,
            False,
            True,
            False,
            "preusable_infrastructure_failure",
            0,
        ),
        LATE_INFRASTRUCTURE_FAILURE: (
            False,
            False,
            False,
            True,
            False,
            "late_infrastructure_failure",
            0,
        ),
        UNCLASSIFIED_ABNORMAL_TERMINATION: (
            False,
            False,
            False,
            False,
            False,
            "unclassified_abnormal_termination",
            0,
        ),
    }
    (
        valid,
        normal_terminal_record,
        subject_timeout,
        infrastructure_failure,
        default_usable,
        default_reason,
        trajectory_length,
    ) = defaults[termination_class]
    if termination_class == NORMAL_COMPLETION:
        resolved_value = True if resolved is None else bool(resolved)
    elif termination_class in {
        REFUSAL,
        SUBJECT_EARLY_STOP,
        SUBJECT_TIMEOUT,
        LATE_INFRASTRUCTURE_FAILURE,
        UNCLASSIFIED_ABNORMAL_TERMINATION,
    }:
        resolved_value = False if resolved is None else bool(resolved)
    else:
        resolved_value = False
    usable_value = default_usable if usable_subject_output is None else bool(usable_subject_output)
    changed_value = usable_value if subject_workspace_changed is None else bool(subject_workspace_changed)
    if termination_class in {
        LATE_INFRASTRUCTURE_FAILURE,
        UNCLASSIFIED_ABNORMAL_TERMINATION,
    }:
        valid = usable_value or changed_value
        if resolved_value and not valid:
            raise EvidenceError(
                "resolved abnormal termination requires preserved usable subject work"
            )
    if termination_class == REPLACEABLE_INFRASTRUCTURE_FAILURE and (
        usable_value or changed_value
    ):
        raise EvidenceError(
            "replaceable infrastructure failure cannot contain usable subject work"
        )
    return {
        "infrastructure_failure": infrastructure_failure,
        "mechanical_reason_code": mechanical_reason_code or default_reason,
        "normal_terminal_record": normal_terminal_record,
        "resolved": resolved_value,
        "subject_timeout": subject_timeout,
        "subject_workspace_changed": changed_value,
        "termination_class": termination_class,
        "trajectory_length": trajectory_length,
        "usable_subject_output": usable_value,
        "valid": valid,
    }


@dataclass(frozen=True)
class _PairJob:
    arm_order: str
    first_arm: str
    pair_id: str
    queue_position: int
    repeat_id: int
    root_pair_id: str
    second_arm: str
    task_id: str
    sequence: str
    replacement_for_pair_id: str | None = None
    replacement_generation: int = 0
    enqueued_monotonic: float = 0.0
    claimed_monotonic: float = 0.0


class _Telemetry:
    def __init__(self, writer: _DurableJsonl, run_seal_sha256: str) -> None:
        self.writer = writer
        self.run_seal_sha256 = run_seal_sha256
        self._lock = threading.Lock()
        self._event_index = 0
        self.active_subjects = 0
        self.peak_active_subjects = 0
        self._active_attempts: set[str] = set()

    def emit(self, event_type: str, **fields: Any) -> None:
        with self._lock:
            self._event_index += 1
            record = {
                "active_subjects": self.active_subjects,
                "event_index": self._event_index,
                "event_type": event_type,
                "monotonic_time": time.monotonic(),
                "run_seal_sha256": self.run_seal_sha256,
                "schema_version": EVENT_SCHEMA,
                **fields,
            }
            self.writer.append(record)

    def subject_started(self, *, attempt_id: str, worker_id: str, pair_id: str, task_id: str) -> float:
        with self._lock:
            if attempt_id in self._active_attempts:
                raise EvidenceError(f"attempt already active: {attempt_id}")
            self._active_attempts.add(attempt_id)
            self.active_subjects += 1
            if self.active_subjects > WORKER_COUNT:
                raise EvidenceError("active subject cap exceeded")
            self.peak_active_subjects = max(
                self.peak_active_subjects, self.active_subjects
            )
            self._event_index += 1
            now = time.monotonic()
            self.writer.append(
                {
                    "active_subjects": self.active_subjects,
                    "attempt_id": attempt_id,
                    "event_index": self._event_index,
                    "event_type": "subject_started",
                    "monotonic_time": now,
                    "pair_id": pair_id,
                    "run_seal_sha256": self.run_seal_sha256,
                    "schema_version": EVENT_SCHEMA,
                    "task_id": task_id,
                    "worker_id": worker_id,
                }
            )
            return now

    def subject_finished(self, *, attempt_id: str, worker_id: str, pair_id: str, task_id: str) -> float:
        with self._lock:
            if attempt_id not in self._active_attempts:
                raise EvidenceError(f"attempt is not active: {attempt_id}")
            self._active_attempts.remove(attempt_id)
            self.active_subjects -= 1
            self._event_index += 1
            now = time.monotonic()
            self.writer.append(
                {
                    "active_subjects": self.active_subjects,
                    "attempt_id": attempt_id,
                    "event_index": self._event_index,
                    "event_type": "subject_finished",
                    "monotonic_time": now,
                    "pair_id": pair_id,
                    "run_seal_sha256": self.run_seal_sha256,
                    "schema_version": EVENT_SCHEMA,
                    "task_id": task_id,
                    "worker_id": worker_id,
                }
            )
            return now

    @property
    def event_count(self) -> int:
        return self._event_index


class _ExecutorConcurrency:
    """Independent observation of time spent inside the executor callable."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.active = 0
        self.peak = 0

    def enter(self) -> float:
        with self._lock:
            self.active += 1
            if self.active > WORKER_COUNT:
                raise EvidenceError("executor concurrency exceeded the 12-call cap")
            self.peak = max(self.peak, self.active)
        return time.monotonic()

    def exit(self) -> float:
        ended = time.monotonic()
        with self._lock:
            if self.active <= 0:
                raise EvidenceError("executor concurrency accounting underflow")
            self.active -= 1
        return ended


class _Scheduler:
    def __init__(
        self,
        jobs: Sequence[_PairJob],
        telemetry: _Telemetry,
        synthetic_replacement_limit: int | None,
        live_policy: bool = False,
    ) -> None:
        if synthetic_replacement_limit is not None and synthetic_replacement_limit < 0:
            raise ValueError("synthetic replacement limit must be nonnegative")
        self._condition = threading.Condition()
        self._pending = list(sorted(jobs, key=lambda item: item.queue_position))
        self._active_tasks: set[str] = set()
        self._active_count = 0
        self._telemetry = telemetry
        self._replacement_limit = synthetic_replacement_limit
        self._replacement_count = 0
        self._next_queue_position = len(jobs) + 1
        self._base_pair_count = len(jobs)
        self._base_claimed_count = 0
        self._first_arm_decisions: dict[int, bool] = {}
        self._live_policy = live_policy
        self._aborted = False

    def claim(self, worker_id: str) -> _PairJob | None:
        while True:
            with self._condition:
                if self._aborted:
                    return None
                eligible_index = next(
                    (
                        index
                        for index, job in enumerate(self._pending)
                        if job.task_id not in self._active_tasks
                        and not (
                            self._live_policy
                            and job.replacement_generation
                            and self._base_claimed_count < self._base_pair_count
                        )
                    ),
                    None,
                )
                if eligible_index is not None:
                    job = self._pending.pop(eligible_index)
                    claimed = replace(job, claimed_monotonic=time.monotonic())
                    self._active_tasks.add(job.task_id)
                    self._active_count += 1
                    if job.replacement_generation == 0:
                        self._base_claimed_count += 1
                    active_task_ids = sorted(self._active_tasks)
                    active_pair_count = self._active_count
                    pending_count = len(self._pending)
                    try:
                        self._telemetry.emit(
                            "pair_claimed",
                            active_pair_count=active_pair_count,
                            active_task_ids=active_task_ids,
                            pair_id=claimed.pair_id,
                            pending_pair_count=pending_count,
                            root_pair_id=claimed.root_pair_id,
                            task_id=claimed.task_id,
                            worker_id=worker_id,
                        )
                    except BaseException:
                        self._active_tasks.remove(job.task_id)
                        self._active_count -= 1
                        self._pending.append(job)
                        self._pending.sort(key=lambda item: item.queue_position)
                        self._condition.notify_all()
                        raise
                    return claimed
                if not self._pending and self._active_count == 0:
                    return None
                self._condition.wait()

    def record_first_arm(
        self, job: _PairJob, replaceable_failure: bool
    ) -> _PairJob | None:
        with self._condition:
            if self._aborted:
                return None
            if self._live_policy:
                if job.replacement_generation:
                    return None
                self._first_arm_decisions[job.queue_position] = replaceable_failure
                self._condition.notify_all()
                if not replaceable_failure:
                    return None
                while not self._aborted and any(
                    position not in self._first_arm_decisions
                    for position in range(1, job.queue_position)
                ):
                    self._condition.wait()
                if self._aborted:
                    return None
                earlier_failures = sum(
                    self._first_arm_decisions[position]
                    for position in range(1, job.queue_position)
                )
                if (
                    self._replacement_limit is None
                    or earlier_failures >= self._replacement_limit
                ):
                    return None
            elif not replaceable_failure:
                return None
            if self._replacement_limit is None:
                return None
            if self._replacement_count >= self._replacement_limit:
                return None
            self._replacement_count += 1
            generation = job.replacement_generation + 1
            replacement_job = replace(
                job,
                claimed_monotonic=0.0,
                enqueued_monotonic=time.monotonic(),
                pair_id=(
                    f"{job.root_pair_id}-replacement-{generation}"
                    if self._live_policy
                    else f"{job.root_pair_id}-replacement-{generation:02d}"
                ),
                queue_position=(
                    self._base_pair_count + job.queue_position
                    if self._live_policy
                    else self._next_queue_position
                ),
                replacement_for_pair_id=job.pair_id,
                replacement_generation=generation,
            )
            self._next_queue_position += 1
            return replacement_job

    def finish(self, job: _PairJob, worker_id: str, replacement: _PairJob | None) -> None:
        with self._condition:
            if job.task_id not in self._active_tasks:
                raise EvidenceError(f"task was not active: {job.task_id}")
            if replacement is not None and not self._aborted:
                self._pending.append(replacement)
            self._active_tasks.remove(job.task_id)
            self._active_count -= 1
            active_task_ids = sorted(self._active_tasks)
            active_pair_count = self._active_count
            pending_count = len(self._pending)
            try:
                self._telemetry.emit(
                    "pair_released",
                    active_pair_count=active_pair_count,
                    active_task_ids=active_task_ids,
                    pair_id=job.pair_id,
                    pending_pair_count=pending_count,
                    replacement_pair_id=None if replacement is None else replacement.pair_id,
                    root_pair_id=job.root_pair_id,
                    task_id=job.task_id,
                    worker_id=worker_id,
                )
            finally:
                self._condition.notify_all()

    def abort(self) -> None:
        with self._condition:
            self._aborted = True
            self._pending.clear()
            self._condition.notify_all()

    @property
    def replacement_count(self) -> int:
        with self._condition:
            return self._replacement_count


def _runtime_manifest_hash() -> str:
    runtime = {
        "live_model_calls": 0,
        "mode": "offline_stub",
        "network_access": False,
        "provider_integration": False,
        "subject_timeout_seconds": SUBJECT_TIMEOUT_SECONDS,
        "worker_count": WORKER_COUNT,
    }
    return sha256_bytes(canonical_bytes(runtime))


def _task_manifest_hash(task_ids: Sequence[str]) -> str:
    manifest = {
        "mode": "offline_synthetic",
        "tasks": [
            {
                "task_id": task_id,
                "task_sha256": sha256_bytes(
                    f"offline-synthetic-starlette-task-v1:{task_id}".encode("utf-8")
                ),
            }
            for task_id in task_ids
        ],
    }
    return sha256_bytes(canonical_bytes(manifest))


def _analyzer_path() -> Path | None:
    specification = importlib.util.find_spec("tooling.analyze_starlette_atomic_pairs")
    if specification is None or specification.origin is None:
        return None
    path = Path(specification.origin)
    return path if path.is_file() else None


def _analyzer_hash() -> str | None:
    path = _analyzer_path()
    return None if path is None else sha256_file(path)


def _attempt_id(job: _PairJob, arm_index: int, arm: str) -> str:
    suffix = "candidate" if arm == "candidate" else "control"
    return f"{job.pair_id}-a{arm_index}-{suffix}"


def _coerce_executor_result(raw: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise TypeError("offline executor must return a mapping")
    return dict(raw)


def _token_fields(raw: Mapping[str, Any]) -> dict[str, int | None]:
    components = raw.get("token_components")
    if not isinstance(components, Mapping):
        components = {}
    names = (
        "input_tokens",
        "cached_input_tokens",
        "uncached_input_tokens",
        "output_tokens",
        "reasoning_tokens",
        "total_tokens",
        "uncached_input_plus_output_token_proxy",
    )
    return {name: components.get(name) for name in names}


def _resource_eligibility(attempts: Sequence[Mapping[str, Any]]) -> tuple[bool, str | None]:
    if len(attempts) != 2:
        return False, "missing_arm"
    for attempt in attempts:
        if not attempt["valid"]:
            return False, "invalid_attempt"
        if not attempt["normal_terminal_record"]:
            return False, "non_normal_terminal_record"
        if not attempt["resolved"]:
            return False, "mechanically_unresolved"
        wall = attempt["subject_wall_seconds"]
        if not isinstance(wall, (int, float)) or not math.isfinite(wall) or wall <= 0:
            return False, "invalid_wall_duration"
    return True, None


def _validate_pair_attempts(job: _PairJob, attempts: Sequence[Mapping[str, Any]]) -> None:
    if len(attempts) != 2:
        raise EvidenceError("complete pair must have exactly two attempts")
    if any(
        attempt["termination_class"] == REPLACEABLE_INFRASTRUCTURE_FAILURE
        for attempt in attempts
    ):
        raise EvidenceError(
            "complete pair cannot contain a replaceable infrastructure attempt"
        )
    expected_arms = (job.first_arm, job.second_arm)
    if tuple(attempt["arm"] for attempt in attempts) != expected_arms:
        raise EvidenceError("attempt arm order conflicts with frozen pair order")
    if attempts[0]["worker_id"] != attempts[1]["worker_id"]:
        raise EvidenceError("both arms must execute on the same worker")
    if attempts[0]["subject_end_monotonic"] > attempts[1]["subject_start_monotonic"]:
        raise EvidenceError("pair arms overlap")
    if attempts[0]["workspace_path"] == attempts[1]["workspace_path"]:
        raise EvidenceError("pair arms must use distinct workspaces")


def _build_pair_record(
    *,
    job: _PairJob,
    attempts: Sequence[Mapping[str, Any]],
    worker_id: str,
    run_seal_sha256: str,
    replacement: _PairJob | None,
    pair_started: float,
    pair_ended: float,
) -> dict[str, Any]:
    if len(attempts) == 2:
        _validate_pair_attempts(job, attempts)
        status = "complete"
        structural_valid = True
    else:
        status = "superseded" if replacement is not None else "incomplete"
        structural_valid = len(attempts) == 1
    eligible, exclusion_reason = _resource_eligibility(attempts)
    telemetry_complete = eligible and all(
        attempt["uncached_input_plus_output_token_proxy"] is not None
        for attempt in attempts
    )
    if len(attempts) == 2:
        arm_gap = attempts[1]["subject_start_monotonic"] - attempts[0]["subject_end_monotonic"]
    else:
        arm_gap = None
    return {
        "arm_gap_seconds": arm_gap,
        "arm_order": job.arm_order,
        "attempt_ids": [attempt["attempt_id"] for attempt in attempts],
        "completed_monotonic": pair_ended,
        "enqueued_monotonic": job.enqueued_monotonic,
        "exclusion_reason": exclusion_reason,
        "first_arm": job.first_arm,
        "mechanical_reason_codes": [
            attempt["mechanical_reason_code"] for attempt in attempts
        ],
        "pair_claimed_monotonic": job.claimed_monotonic,
        "pair_completed_monotonic": pair_ended,
        "pair_duration_seconds": pair_ended - job.claimed_monotonic,
        "pair_end_monotonic": pair_ended,
        "pair_id": job.pair_id,
        "queue_delay_seconds": job.claimed_monotonic - job.enqueued_monotonic,
        "queue_position": job.queue_position,
        "replacement_for_pair_id": job.replacement_for_pair_id,
        "replacement_generation": job.replacement_generation,
        "replacement_pair_id": None if replacement is None else replacement.pair_id,
        "repeat_id": job.repeat_id,
        "resource_eligible": eligible,
        "resource_exclusion_reason": exclusion_reason,
        "root_pair_id": job.root_pair_id,
        "run_seal_sha256": run_seal_sha256,
        "schema_version": PAIR_SCHEMA,
        "second_arm": job.second_arm,
        "started_monotonic": pair_started,
        "status": status,
        "structural_valid": structural_valid,
        "task_id": job.task_id,
        "termination_classes": [attempt["termination_class"] for attempt in attempts],
        "token_telemetry_complete": telemetry_complete,
        "worker_id": worker_id,
    }


def _execute_pair(
    *,
    job: _PairJob,
    worker_id: str,
    run_dir: Path,
    run_seal_sha256: str,
    executor: Callable[[AttemptContext], Mapping[str, Any]],
    scheduler: _Scheduler,
    telemetry: _Telemetry,
    executor_concurrency: _ExecutorConcurrency,
    attempt_writer: _DurableJsonl,
    pair_writer: _DurableJsonl,
    first_wave_barrier: threading.Barrier | None,
    use_first_wave_barrier: bool,
    live_mode: bool,
) -> _PairJob | None:
    pair_started = time.monotonic()
    attempts: list[dict[str, Any]] = []
    replacement: _PairJob | None = None
    for arm_index, arm in enumerate((job.first_arm, job.second_arm), 1):
        attempt_id = _attempt_id(job, arm_index, arm)
        attempt_started = time.monotonic()
        workspace_relative = Path("workspaces") / attempt_id
        workspace = run_dir / workspace_relative
        workspace.mkdir(mode=0o700)
        context = AttemptContext(
            arm=arm,
            arm_index=arm_index,
            attempt_id=attempt_id,
            pair_id=job.pair_id,
            repeat_id=job.repeat_id,
            replacement_generation=job.replacement_generation,
            root_pair_id=job.root_pair_id,
            task_id=job.task_id,
            worker_id=worker_id,
            workspace=workspace,
        )
        if arm_index == 1 and use_first_wave_barrier and first_wave_barrier is not None:
            try:
                first_wave_barrier.wait(timeout=10)
            except threading.BrokenBarrierError as exc:
                raise EvidenceError("12-worker stub concurrency barrier failed") from exc
        subject_started = telemetry.subject_started(
            attempt_id=attempt_id,
            pair_id=job.pair_id,
            task_id=job.task_id,
            worker_id=worker_id,
        )
        executor_started = executor_concurrency.enter()
        try:
            raw = _coerce_executor_result(executor(context))
        except Exception as exc:  # preserve a fail-closed mechanical record
            raw = {
                "mechanical_reason_code": f"offline_executor_exception:{type(exc).__name__}",
                "rate_limit_count": 0,
                "resolved": False,
                "retry_count": 0,
                "subject_invocation_started": False,
                "subject_workspace_changed": False,
                "termination_class": UNCLASSIFIED_ABNORMAL_TERMINATION,
                "token_components": {},
                "trajectory_length": 0,
                "usable_subject_output": False,
            }
        finally:
            executor_ended = executor_concurrency.exit()
        observed_subject_ended = telemetry.subject_finished(
            attempt_id=attempt_id,
            pair_id=job.pair_id,
            task_id=job.task_id,
            worker_id=worker_id,
        )
        subject_invocation_started = (
            raw.get("subject_invocation_started") if live_mode else False
        )
        if type(subject_invocation_started) is not bool:
            raise EvidenceError(
                "live executor subject_invocation_started must be boolean"
            )
        termination_class = raw.get("termination_class")
        if arm_index == 2 and termination_class == REPLACEABLE_INFRASTRUCTURE_FAILURE:
            termination_class = LATE_INFRASTRUCTURE_FAILURE
            raw["mechanical_reason_code"] = "infrastructure_failure_after_prior_arm"
        classification = classify_termination(
            str(termination_class),
            mechanical_reason_code=raw.get("mechanical_reason_code"),
            resolved=raw.get("resolved"),
            subject_workspace_changed=raw.get("subject_workspace_changed"),
            usable_subject_output=raw.get("usable_subject_output"),
        )
        trajectory_length = raw.get("trajectory_length")
        if trajectory_length is None:
            trajectory_length = classification["trajectory_length"]
        if (
            not isinstance(trajectory_length, int)
            or isinstance(trajectory_length, bool)
            or trajectory_length < 0
        ):
            raise EvidenceError("trajectory_length must be a nonnegative integer")
        retry_count = raw.get("retry_count", 0)
        rate_limit_count = raw.get("rate_limit_count", 0)
        if (
            not isinstance(retry_count, int)
            or isinstance(retry_count, bool)
            or retry_count < 0
        ):
            raise EvidenceError("retry_count must be a nonnegative integer")
        if (
            not isinstance(rate_limit_count, int)
            or isinstance(rate_limit_count, bool)
            or rate_limit_count < 0
        ):
            raise EvidenceError("rate_limit_count must be a nonnegative integer")
        tokens = _token_fields(raw)
        if arm_index == 1:
            replacement = scheduler.record_first_arm(
                job, termination_class == REPLACEABLE_INFRASTRUCTURE_FAILURE
            )
        attempt_ended = time.monotonic()
        if live_mode:
            subject_wall = raw.get("duration_seconds")
            if (
                not isinstance(subject_wall, (int, float))
                or isinstance(subject_wall, bool)
                or not math.isfinite(subject_wall)
                or subject_wall < 0
            ):
                raise EvidenceError("live executor duration_seconds must be finite and nonnegative")
            subject_ended = subject_started + float(subject_wall)
            subject_wall = subject_ended - subject_started
            if subject_ended > attempt_ended:
                raise EvidenceError("live subject duration exceeds its attempt interval")
        else:
            subject_ended = observed_subject_ended
            subject_wall = subject_ended - subject_started
        event_source = "live_event_stream" if live_mode else "synthetic_offline_fixture"
        record = {
            "arm": arm,
            "arm_index": arm_index,
            "arm_order": job.arm_order,
            "attempt_duration_seconds": attempt_ended - attempt_started,
            "attempt_end_monotonic": attempt_ended,
            "attempt_id": attempt_id,
            "attempt_start_monotonic": attempt_started,
            "attempt_ended_monotonic": attempt_ended,
            "attempt_started_monotonic": attempt_started,
            "checker_results_preserved": True,
            "evidence_preserved": True,
            "first_arm": job.first_arm,
            "infrastructure_failure": classification["infrastructure_failure"],
            "integrity_checks_passed": classification["resolved"],
            "mechanical_reason_code": classification["mechanical_reason_code"],
            "normal_terminal_record": classification["normal_terminal_record"],
            "enqueued_monotonic": job.enqueued_monotonic,
            "executor_end_monotonic": executor_ended,
            "executor_start_monotonic": executor_started,
            "pair_claimed_monotonic": job.claimed_monotonic,
            "pair_enqueued_monotonic": job.enqueued_monotonic,
            "pair_id": job.pair_id,
            "queue_delay_seconds": job.claimed_monotonic - job.enqueued_monotonic,
            "queue_duration_seconds": job.claimed_monotonic - job.enqueued_monotonic,
            "queue_position": job.queue_position,
            "rate_limit_count": rate_limit_count,
            "rate_limit_events": [
                {"index": index, "source": event_source}
                for index in range(1, rate_limit_count + 1)
            ],
            "rate_limits": rate_limit_count,
            "replacement_for_pair_id": job.replacement_for_pair_id,
            "replacement_generation": job.replacement_generation,
            "replacement_pair_id": None if replacement is None else replacement.pair_id,
            "repeat_id": job.repeat_id,
            "resolved": classification["resolved"],
            "retry_count": retry_count,
            "retry_events": [
                {"index": index, "source": event_source}
                for index in range(1, retry_count + 1)
            ],
            "retries": retry_count,
            "root_pair_id": job.root_pair_id,
            "run_id": run_dir.name,
            "run_seal_sha256": run_seal_sha256,
            "schema_version": ATTEMPT_SCHEMA,
            "second_arm": job.second_arm,
            "subject_end_monotonic": subject_ended,
            "subject_invocation_started": subject_invocation_started,
            "subject_observation_end_monotonic": observed_subject_ended,
            "subject_start_monotonic": subject_started,
            "subject_timeout": classification["subject_timeout"],
            "subject_timeout_limit_seconds": SUBJECT_TIMEOUT_SECONDS,
            "synthetic_timeout_fault": (
                not live_mode
                and classification["termination_class"] == SUBJECT_TIMEOUT
            ),
            "subject_duration_seconds": subject_wall,
            "subject_wall_seconds": subject_wall,
            "subject_workspace_changed": classification["subject_workspace_changed"],
            "task_id": job.task_id,
            "termination_class": classification["termination_class"],
            "token_components": tokens,
            "token_proxy": tokens["uncached_input_plus_output_token_proxy"],
            "total_attempt_duration_seconds": attempt_ended - attempt_started,
            "trajectory_length": trajectory_length,
            "usable_subject_output": classification["usable_subject_output"],
            "valid": classification["valid"],
            "worker_id": worker_id,
            "workspace_path": workspace_relative.as_posix(),
            **tokens,
        }
        if not isinstance(record["mechanical_reason_code"], str) or not record[
            "mechanical_reason_code"
        ]:
            raise EvidenceError("mechanical_reason_code must be a nonempty string")
        _validate_token_record(record)
        attempt_writer.append(record)
        attempts.append(record)
        telemetry.emit(
            "attempt_record_durable",
            attempt_id=attempt_id,
            pair_id=job.pair_id,
            task_id=job.task_id,
            worker_id=worker_id,
        )
        if termination_class == REPLACEABLE_INFRASTRUCTURE_FAILURE:
            break

    pair_ended = time.monotonic()
    pair_record = _build_pair_record(
        attempts=attempts,
        job=job,
        pair_ended=pair_ended,
        pair_started=pair_started,
        replacement=replacement,
        run_seal_sha256=run_seal_sha256,
        worker_id=worker_id,
    )
    pair_record["run_id"] = run_dir.name
    pair_writer.append(pair_record)
    telemetry.emit(
        "pair_record_durable",
        pair_id=job.pair_id,
        replacement_pair_id=None if replacement is None else replacement.pair_id,
        root_pair_id=job.root_pair_id,
        task_id=job.task_id,
        worker_id=worker_id,
    )
    return replacement


def _exclusive_run_directory(path: Path) -> None:
    if path.exists() or path.is_symlink():
        raise FileExistsError(f"run directory already exists: {path}")
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise EvidenceError(f"run directory parent must be an existing regular directory: {path.parent}")
    path.mkdir(mode=0o700)
    (path / "workspaces").mkdir(mode=0o700)


def run_stub(
    output_dir: str | Path,
    *,
    task_ids: Sequence[str] = DEFAULT_TASK_IDS,
    seed: str = DEFAULT_SEED,
    preregistration_sha256: str = DEFAULT_PREREGISTRATION_SHA256,
    synthetic_replacement_limit: int | None = None,
    executor: Callable[[AttemptContext], Mapping[str, Any]] | None = None,
    schedule: Mapping[str, Any] | None = None,
    analyzer_sha256: str | None = None,
    synchronize_first_wave: bool = True,
    live_bindings: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute one exclusive 12-worker run and return its manifest."""

    preregistration_sha256 = _validate_sha256(
        preregistration_sha256, "preregistration_sha256"
    )
    live_mode = live_bindings is not None
    if live_mode:
        if executor is None:
            raise ValueError("live execution requires an injected executor")
        for name in (
            "approval_sha256",
            "request_sha256",
            "runtime_manifest_sha256",
            "task_manifest_sha256",
        ):
            _validate_sha256(live_bindings.get(name), name)
        if (
            live_bindings.get("planned_live_model_calls") != 72
            or live_bindings.get("max_live_model_calls") != 80
            or not isinstance(live_bindings.get("reason_codes"), list)
        ):
            raise ValueError("live call plan or replacement reason codes are invalid")
        synthetic_replacement_limit = live_bindings.get("max_replacement_pairs")
    if synthetic_replacement_limit is not None and (
        not isinstance(synthetic_replacement_limit, int)
        or isinstance(synthetic_replacement_limit, bool)
        or synthetic_replacement_limit < 0
    ):
        raise ValueError("synthetic replacement limit must be nonnegative")
    output = Path(output_dir)
    frozen_schedule = dict(schedule) if schedule is not None else build_schedule(task_ids, seed=seed)
    validate_schedule(frozen_schedule)
    scheduled_tasks = list(frozen_schedule["task_ids"])
    if schedule is not None and tuple(task_ids) != DEFAULT_TASK_IDS and list(task_ids) != scheduled_tasks:
        raise EvidenceError("supplied task IDs conflict with supplied frozen schedule")

    _exclusive_run_directory(output)
    run_started = time.monotonic()
    schedule_sha256 = _write_json_once(output / "schedule.json", frozen_schedule)
    runner_sha256 = sha256_file(Path(__file__))
    detected_analyzer_sha256 = _analyzer_hash() if analyzer_sha256 is None else analyzer_sha256
    if detected_analyzer_sha256 is not None:
        _validate_sha256(detected_analyzer_sha256, "analyzer_sha256")
    replacement_policy = (
        {
            "generation_limit": 1,
            "limit": synthetic_replacement_limit,
            "reason_codes": list(live_bindings.get("reason_codes", ())),
            "selection": "eligible_roots_by_ascending_base_queue_position",
            "source": "approved_live_request",
        }
        if live_mode
        else
        {
            "limit": synthetic_replacement_limit,
            "source": "explicit_synthetic_offline_fixture",
        }
        if synthetic_replacement_limit is not None
        else {"limit": None, "source": "deferred_no_offline_default"}
    )
    seal = {
        "analyzer_sha256": detected_analyzer_sha256,
        "candidate_sha256": CANDIDATE_SHA256,
        "control_sha256": CONTROL_SHA256,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "live_model_calls": None if live_mode else 0,
        "mode": "live_approved" if live_mode else "offline_stub",
        "preregistration_sha256": preregistration_sha256,
        "replacement_policy": replacement_policy,
        "run_id": output.name,
        "runner_sha256": runner_sha256,
        "runtime_manifest_sha256": (
            live_bindings["runtime_manifest_sha256"]
            if live_mode
            else _runtime_manifest_hash()
        ),
        "schedule_sha256": schedule_sha256,
        "schema_version": RUN_SEAL_SCHEMA,
        "subject_timeout_seconds": SUBJECT_TIMEOUT_SECONDS,
        "task_manifest_sha256": (
            live_bindings["task_manifest_sha256"]
            if live_mode
            else _task_manifest_hash(scheduled_tasks)
        ),
        "worker_count": WORKER_COUNT,
    }
    if live_mode:
        seal.update(
            {
                "approval_sha256": live_bindings["approval_sha256"],
                "max_live_model_calls": live_bindings["max_live_model_calls"],
                "planned_live_model_calls": live_bindings["planned_live_model_calls"],
                "request_sha256": live_bindings["request_sha256"],
            }
        )
    run_seal_sha256 = _write_json_once(output / "run-seal.json", seal)

    attempt_writer = _DurableJsonl(output / "attempts.jsonl")
    pair_writer = _DurableJsonl(output / "pairs.jsonl")
    event_writer = _DurableJsonl(output / "scheduler-events.jsonl")
    telemetry = _Telemetry(event_writer, run_seal_sha256)
    executor_concurrency = _ExecutorConcurrency()
    enqueued = time.monotonic()
    jobs = [
        _PairJob(
            arm_order=pair["arm_order"],
            enqueued_monotonic=enqueued,
            first_arm=pair["first_arm"],
            pair_id=pair["pair_id"],
            queue_position=pair["queue_position"],
            repeat_id=pair["repeat_id"],
            root_pair_id=pair["root_pair_id"],
            second_arm=pair["second_arm"],
            sequence=pair["sequence"],
            task_id=pair["task_id"],
        )
        for pair in frozen_schedule["pairs"]
    ]
    scheduler = _Scheduler(
        jobs, telemetry, synthetic_replacement_limit, live_policy=live_mode
    )
    offline_executor = executor or DeterministicStubExecutor()
    barrier = threading.Barrier(WORKER_COUNT) if synchronize_first_wave else None
    failures: list[BaseException] = []
    failure_lock = threading.Lock()

    def worker(worker_index: int) -> None:
        worker_id = f"worker-{worker_index:02d}"
        first_pair = True
        try:
            telemetry.emit("worker_started", worker_id=worker_id)
            while True:
                job = scheduler.claim(worker_id)
                if job is None:
                    break
                replacement_job: _PairJob | None = None
                try:
                    replacement_job = _execute_pair(
                        attempt_writer=attempt_writer,
                        executor=offline_executor,
                        executor_concurrency=executor_concurrency,
                        first_wave_barrier=barrier,
                        job=job,
                        pair_writer=pair_writer,
                        run_dir=output,
                        run_seal_sha256=run_seal_sha256,
                        scheduler=scheduler,
                        telemetry=telemetry,
                        use_first_wave_barrier=first_pair,
                        worker_id=worker_id,
                        live_mode=live_mode,
                    )
                finally:
                    scheduler.finish(job, worker_id, replacement_job)
                first_pair = False
        except BaseException as exc:
            with failure_lock:
                failures.append(exc)
            scheduler.abort()
            if barrier is not None:
                barrier.abort()
            try:
                telemetry.emit(
                    "worker_failed", error_type=type(exc).__name__, worker_id=worker_id
                )
            except BaseException:
                pass
        finally:
            try:
                telemetry.emit("worker_stopped", worker_id=worker_id)
            except BaseException:
                pass

    threads = [
        threading.Thread(target=worker, args=(index,), name=f"starlette-pair-worker-{index:02d}")
        for index in range(1, WORKER_COUNT + 1)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    attempt_writer.close()
    pair_writer.close()
    event_writer.close()
    if failures:
        raise EvidenceError(
            "worker failure(s): "
            + ", ".join(type(failure).__name__ for failure in failures)
        ) from failures[0]

    run_ended = time.monotonic()
    final_by_root: dict[str, dict[str, Any]] = {}
    for record in pair_writer.records:
        final_by_root[record["root_pair_id"]] = record
    all_roots_complete = len(final_by_root) == 36 and all(
        record["status"] == "complete" for record in final_by_root.values()
    )
    workspace_hashes = {
        path.relative_to(output).as_posix(): sha256_file(path)
        for path in sorted((output / "workspaces").rglob("*"))
        if path.is_file() and not path.is_symlink()
    }
    artifact_hashes = {
        filename: sha256_file(output / filename)
        for filename in RUN_FILES
        if filename != "manifest.json"
    }
    artifact_sizes = {
        filename: (output / filename).stat().st_size
        for filename in RUN_FILES
        if filename != "manifest.json"
    }
    completed_root_count = sum(
        record["status"] == "complete" for record in final_by_root.values()
    )
    superseded_count = sum(
        record["status"] == "superseded" for record in pair_writer.records
    )
    live_model_calls = (
        sum(record["subject_invocation_started"] for record in attempt_writer.records)
        if live_mode
        else 0
    )
    if live_model_calls > 80:
        raise EvidenceError("live model call count exceeds the approved cap")
    manifest = {
        "all_scheduled_pairs_complete": all_roots_complete,
        "artifact_sha256": artifact_hashes,
        "artifact_sizes": artifact_sizes,
        "attempt_record_count": len(attempt_writer.records),
        "completed_root_pair_count": completed_root_count,
        "duration_seconds": run_ended - run_started,
        "event_record_count": len(event_writer.records),
        "live_model_calls": live_model_calls,
        "observed_peak_active_subjects": telemetry.peak_active_subjects,
        "observed_peak_executor_calls": executor_concurrency.peak,
        "pair_record_count": len(pair_writer.records),
        "peak_subject_concurrency": telemetry.peak_active_subjects,
        "planned_attempt_count": 72,
        "planned_pair_count": 36,
        "preregistration_sha256": preregistration_sha256,
        "record_counts": {
            "attempt_records": len(attempt_writer.records),
            "pair_records": len(pair_writer.records),
            "scheduled_root_pairs": 36,
            "superseded_pairs": superseded_count,
            "terminal_pairs": completed_root_count,
        },
        "repeats": REPEATS,
        "replacement_pair_count": scheduler.replacement_count,
        "run_end_monotonic": run_ended,
        "run_id": output.name,
        "run_seal_sha256": run_seal_sha256,
        "run_start_monotonic": run_started,
        "run_status": "complete",
        "same_task_overlap_count": 0,
        "schema_version": MANIFEST_SCHEMA,
        "status": "complete",
        "task_count": 12,
        "worker_count": WORKER_COUNT,
        "worker_loop_count": WORKER_COUNT,
        "workspace_evidence_sha256": workspace_hashes,
    }
    validate_run_directory(
        output,
        expected_preregistration_sha256=preregistration_sha256,
        enforce_current_runner=True,
        _manifest_override=manifest,
    )
    _write_json_once(output / "manifest.json", manifest)
    validate_run_directory(
        output,
        expected_preregistration_sha256=preregistration_sha256,
        enforce_current_runner=True,
    )
    return manifest


def _number(value: object, field: str) -> float:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        raise EvidenceError(f"{field} must be numeric")
    converted = float(value)
    if not math.isfinite(converted):
        raise EvidenceError(f"{field} must be finite")
    return converted


def _validate_token_record(attempt: Mapping[str, Any]) -> None:
    names = (
        "input_tokens",
        "cached_input_tokens",
        "uncached_input_tokens",
        "output_tokens",
        "reasoning_tokens",
        "total_tokens",
        "uncached_input_plus_output_token_proxy",
    )
    values = [attempt.get(name) for name in names]
    components = attempt.get("token_components")
    if not isinstance(components, dict) or any(components.get(name) != attempt.get(name) for name in names):
        raise EvidenceError("flat and nested token components must match")
    if all(value is None for value in values):
        return
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in values):
        raise EvidenceError("token components must be all-null or nonnegative integers")
    input_tokens = attempt["input_tokens"]
    cached = attempt["cached_input_tokens"]
    uncached = attempt["uncached_input_tokens"]
    output = attempt["output_tokens"]
    if cached > input_tokens or uncached != input_tokens - cached:
        raise EvidenceError("invalid cached/uncached input token accounting")
    if attempt["uncached_input_plus_output_token_proxy"] != uncached + output:
        raise EvidenceError("invalid registered token proxy")
    if attempt["total_tokens"] != input_tokens + output:
        raise EvidenceError("invalid total token accounting")
    if attempt["reasoning_tokens"] > output:
        raise EvidenceError("reasoning tokens must already be included in output")


def validate_run_directory(
    run_dir: str | Path,
    *,
    expected_preregistration_sha256: str | None = None,
    enforce_current_runner: bool = False,
    _manifest_override: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Fail-closed structural and hash verification for one atomic run."""

    root = Path(run_dir)
    if root.is_symlink() or not root.is_dir():
        raise EvidenceError(f"run directory is not a regular directory: {root}")
    allowed_top = set(RUN_FILES) | {"workspaces", "analysis.json"}
    actual_top = {path.name for path in root.iterdir()}
    unexpected = actual_top - allowed_top
    required_top = set(RUN_FILES) | {"workspaces"}
    if _manifest_override is not None:
        required_top.remove("manifest.json")
        if "manifest.json" in actual_top:
            raise EvidenceError("pre-manifest validation cannot override existing evidence")
    missing = required_top - actual_top
    if unexpected or missing:
        raise EvidenceError(
            f"run directory shape mismatch; missing={sorted(missing)}, unexpected={sorted(unexpected)}"
        )
    schedule = _read_canonical_json(root / "schedule.json")
    seal = _read_canonical_json(root / "run-seal.json")
    attempts = _read_canonical_jsonl(root / "attempts.jsonl")
    pairs = _read_canonical_jsonl(root / "pairs.jsonl")
    events = _read_canonical_jsonl(root / "scheduler-events.jsonl")
    manifest = (
        dict(_manifest_override)
        if _manifest_override is not None
        else _read_canonical_json(root / "manifest.json")
    )
    validate_schedule(schedule)
    if seal.get("schema_version") != RUN_SEAL_SCHEMA:
        raise EvidenceError("unsupported run-seal schema")
    if manifest.get("schema_version") != MANIFEST_SCHEMA:
        raise EvidenceError("unsupported run-manifest schema")
    preregistration_sha256 = _validate_sha256(
        seal.get("preregistration_sha256"), "run-seal preregistration_sha256"
    )
    if expected_preregistration_sha256 is not None and preregistration_sha256 != expected_preregistration_sha256:
        raise EvidenceError("preregistration hash mismatch")
    if manifest.get("preregistration_sha256") != preregistration_sha256:
        raise EvidenceError("manifest/run-seal preregistration mismatch")
    if seal.get("schedule_sha256") != sha256_file(root / "schedule.json"):
        raise EvidenceError("run-seal schedule hash mismatch")
    if seal.get("worker_count") != WORKER_COUNT or seal.get("subject_timeout_seconds") != SUBJECT_TIMEOUT_SECONDS:
        raise EvidenceError("run-seal worker/timeout freeze mismatch")
    mode = seal.get("mode")
    if mode not in {"offline_stub", "live_approved"}:
        raise EvidenceError("unsupported run-seal mode")
    live_mode = mode == "live_approved"
    if (not live_mode and seal.get("live_model_calls") != 0) or (
        live_mode and seal.get("live_model_calls") is not None
    ):
        raise EvidenceError("run-seal live-call marker conflicts with mode")
    if seal.get("candidate_sha256") != CANDIDATE_SHA256 or seal.get("control_sha256") != CONTROL_SHA256:
        raise EvidenceError("candidate/control hash mismatch")
    if seal.get("run_id") != root.name:
        raise EvidenceError("run-seal run ID does not match its directory")
    replacement_policy = seal.get("replacement_policy")
    if not isinstance(replacement_policy, dict):
        raise EvidenceError("run-seal replacement policy is missing")
    replacement_limit = replacement_policy.get("limit")
    replacement_source = replacement_policy.get("source")
    if live_mode:
        if (
            not isinstance(replacement_limit, int)
            or isinstance(replacement_limit, bool)
            or replacement_limit < 0
            or replacement_source != "approved_live_request"
            or replacement_policy.get("generation_limit") != 1
            or replacement_policy.get("selection")
            != "eligible_roots_by_ascending_base_queue_position"
            or not isinstance(replacement_policy.get("reason_codes"), list)
        ):
            raise EvidenceError("live replacement policy is invalid")
        for field in ("approval_sha256", "request_sha256"):
            _validate_sha256(seal.get(field), f"run-seal {field}")
        if seal.get("planned_live_model_calls") != 72 or seal.get(
            "max_live_model_calls"
        ) != 80:
            raise EvidenceError("live call plan/cap mismatch")
    elif replacement_limit is None:
        if replacement_source != "deferred_no_offline_default":
            raise EvidenceError("null replacement limit must remain explicitly deferred")
    elif (
        not isinstance(replacement_limit, int)
        or isinstance(replacement_limit, bool)
        or replacement_limit < 0
        or replacement_source != "explicit_synthetic_offline_fixture"
    ):
        raise EvidenceError("replacement limit is not an explicit synthetic fixture value")
    for field in (
        "runner_sha256",
        "runtime_manifest_sha256",
        "schedule_sha256",
        "task_manifest_sha256",
    ):
        _validate_sha256(seal.get(field), f"run-seal {field}")
    if not live_mode:
        if seal.get("runtime_manifest_sha256") != _runtime_manifest_hash():
            raise EvidenceError("run-seal runtime manifest hash mismatch")
        if seal.get("task_manifest_sha256") != _task_manifest_hash(schedule["task_ids"]):
            raise EvidenceError("run-seal task manifest hash mismatch")
    if seal.get("analyzer_sha256") is not None:
        _validate_sha256(seal.get("analyzer_sha256"), "run-seal analyzer_sha256")
    if enforce_current_runner and seal.get("runner_sha256") != sha256_file(Path(__file__)):
        raise EvidenceError("run evidence was not produced by the current runner bytes")
    run_seal_sha256 = sha256_file(root / "run-seal.json")
    if manifest.get("run_seal_sha256") != run_seal_sha256:
        raise EvidenceError("manifest run-seal hash mismatch")

    expected_artifacts = {
        filename: sha256_file(root / filename)
        for filename in RUN_FILES
        if filename != "manifest.json"
    }
    if manifest.get("artifact_sha256") != expected_artifacts:
        raise EvidenceError("manifest artifact hash mismatch")
    expected_sizes = {
        filename: (root / filename).stat().st_size
        for filename in RUN_FILES
        if filename != "manifest.json"
    }
    if manifest.get("artifact_sizes") != expected_sizes:
        raise EvidenceError("manifest artifact size mismatch")
    if manifest.get("attempt_record_count") != len(attempts):
        raise EvidenceError("attempt record count mismatch")
    if manifest.get("pair_record_count") != len(pairs):
        raise EvidenceError("pair record count mismatch")
    if manifest.get("event_record_count") != len(events):
        raise EvidenceError("scheduler event count mismatch")
    if manifest.get("planned_pair_count") != 36 or manifest.get("planned_attempt_count") != 72:
        raise EvidenceError("planned inventory mismatch")
    live_calls = manifest.get("live_model_calls")
    if (
        manifest.get("worker_loop_count") != WORKER_COUNT
        or type(live_calls) is not int
        or not 0 <= live_calls <= 80
        or (not live_mode and live_calls != 0)
    ):
        raise EvidenceError("manifest worker/live-call count mismatch")
    if manifest.get("run_status") != "complete" or manifest.get("status") != "complete":
        raise EvidenceError("run did not reach a complete scheduler terminal state")
    if manifest.get("run_id") != root.name or manifest.get("worker_count") != WORKER_COUNT:
        raise EvidenceError("manifest run/worker identity mismatch")
    if manifest.get("task_count") != 12 or manifest.get("repeats") != REPEATS:
        raise EvidenceError("manifest task/repeat inventory mismatch")
    duration = _number(manifest.get("duration_seconds"), "duration_seconds")
    if duration < 0:
        raise EvidenceError("negative run duration")
    run_start = _number(manifest.get("run_start_monotonic"), "run_start_monotonic")
    run_end = _number(manifest.get("run_end_monotonic"), "run_end_monotonic")
    if run_start > run_end or not math.isclose(
        duration, run_end - run_start, rel_tol=0, abs_tol=1e-9
    ):
        raise EvidenceError("manifest run timestamps are impossible")

    attempt_by_id: dict[str, dict[str, Any]] = {}
    workspace_paths: set[str] = set()
    required_attempt_fields = {
        "arm",
        "arm_index",
        "arm_order",
        "attempt_end_monotonic",
        "attempt_id",
        "attempt_start_monotonic",
        "checker_results_preserved",
        "evidence_preserved",
        "executor_end_monotonic",
        "executor_start_monotonic",
        "infrastructure_failure",
        "integrity_checks_passed",
        "mechanical_reason_code",
        "normal_terminal_record",
        "pair_claimed_monotonic",
        "pair_enqueued_monotonic",
        "pair_id",
        "queue_delay_seconds",
        "queue_position",
        "rate_limit_count",
        "rate_limit_events",
        "replacement_for_pair_id",
        "replacement_generation",
        "replacement_pair_id",
        "repeat_id",
        "resolved",
        "retry_count",
        "retry_events",
        "root_pair_id",
        "run_seal_sha256",
        "subject_end_monotonic",
        "subject_invocation_started",
        "subject_start_monotonic",
        "subject_timeout",
        "subject_timeout_limit_seconds",
        "synthetic_timeout_fault",
        "subject_wall_seconds",
        "task_id",
        "termination_class",
        "total_attempt_duration_seconds",
        "trajectory_length",
        "valid",
        "worker_id",
        "workspace_path",
    }
    for attempt in attempts:
        missing_fields = required_attempt_fields - attempt.keys()
        if missing_fields:
            raise EvidenceError(f"attempt missing required fields: {sorted(missing_fields)}")
        if attempt.get("schema_version") != ATTEMPT_SCHEMA:
            raise EvidenceError("unsupported attempt schema")
        attempt_id = attempt["attempt_id"]
        if not isinstance(attempt_id, str) or attempt_id in attempt_by_id:
            raise EvidenceError("duplicate or invalid attempt ID")
        attempt_by_id[attempt_id] = attempt
        if attempt.get("run_seal_sha256") != run_seal_sha256:
            raise EvidenceError("mixed run seals in attempts")
        if attempt.get("run_id") != root.name:
            raise EvidenceError("attempt run ID mismatch")
        if attempt.get("arm") not in ARMS or attempt.get("arm_index") not in (1, 2):
            raise EvidenceError("invalid attempt arm")
        if attempt.get("repeat_id") not in (1, 2, 3):
            raise EvidenceError("invalid attempt repeat")
        if attempt.get("termination_class") not in TERMINATION_CLASSES:
            raise EvidenceError("invalid attempt termination class")
        if attempt.get("subject_timeout_limit_seconds") != SUBJECT_TIMEOUT_SECONDS:
            raise EvidenceError("attempt timeout freeze mismatch")
        start = _number(attempt["subject_start_monotonic"], "subject_start_monotonic")
        end = _number(attempt["subject_end_monotonic"], "subject_end_monotonic")
        executor_start = _number(
            attempt["executor_start_monotonic"], "executor_start_monotonic"
        )
        executor_end = _number(
            attempt["executor_end_monotonic"], "executor_end_monotonic"
        )
        attempt_start = _number(attempt["attempt_start_monotonic"], "attempt_start_monotonic")
        attempt_end = _number(attempt["attempt_end_monotonic"], "attempt_end_monotonic")
        enqueued = _number(attempt["pair_enqueued_monotonic"], "pair_enqueued_monotonic")
        claimed = _number(attempt["pair_claimed_monotonic"], "pair_claimed_monotonic")
        ordered = (
            enqueued <= claimed <= attempt_start <= start <= end <= attempt_end
            and executor_start <= executor_end <= attempt_end
            and (live_mode or start <= executor_start <= executor_end <= end)
        )
        if not ordered:
            raise EvidenceError("impossible attempt timestamps")
        if not math.isclose(attempt["subject_wall_seconds"], end - start, rel_tol=0, abs_tol=1e-9):
            raise EvidenceError("subject wall duration mismatch")
        if not math.isclose(attempt["queue_delay_seconds"], claimed - enqueued, rel_tol=0, abs_tol=1e-9):
            raise EvidenceError("queue delay mismatch")
        if not math.isclose(attempt["total_attempt_duration_seconds"], attempt_end - attempt_start, rel_tol=0, abs_tol=1e-9):
            raise EvidenceError("total attempt duration mismatch")
        if (
            not isinstance(attempt.get("retry_count"), int)
            or isinstance(attempt["retry_count"], bool)
            or attempt["retry_count"] < 0
        ):
            raise EvidenceError("invalid retry count")
        if (
            not isinstance(attempt.get("rate_limit_count"), int)
            or isinstance(attempt["rate_limit_count"], bool)
            or attempt["rate_limit_count"] < 0
        ):
            raise EvidenceError("invalid rate-limit count")
        if attempt.get("retries") != attempt["retry_count"] or not isinstance(
            attempt.get("retry_events"), list
        ) or len(attempt["retry_events"]) != attempt["retry_count"]:
            raise EvidenceError("retry telemetry mismatch")
        if attempt.get("rate_limits") != attempt["rate_limit_count"] or not isinstance(
            attempt.get("rate_limit_events"), list
        ) or len(attempt["rate_limit_events"]) != attempt["rate_limit_count"]:
            raise EvidenceError("rate-limit telemetry mismatch")
        if not isinstance(attempt.get("trajectory_length"), int) or attempt["trajectory_length"] < 0:
            raise EvidenceError("invalid trajectory length")
        boolean_fields = (
            "checker_results_preserved",
            "evidence_preserved",
            "infrastructure_failure",
            "integrity_checks_passed",
            "normal_terminal_record",
            "resolved",
            "subject_invocation_started",
            "subject_timeout",
            "synthetic_timeout_fault",
            "subject_workspace_changed",
            "usable_subject_output",
            "valid",
        )
        if any(type(attempt.get(field)) is not bool for field in boolean_fields):
            raise EvidenceError("attempt classification flags must be booleans")
        normal_classes = {
            NORMAL_COMPLETION,
            NORMAL_INCORRECT_COMPLETION,
            REFUSAL,
            SUBJECT_EARLY_STOP,
        }
        termination_class = attempt["termination_class"]
        if (
            termination_class == NORMAL_INCORRECT_COMPLETION
            and attempt["resolved"]
        ):
            raise EvidenceError("normal_incorrect_completion attempt must resolve false")
        if attempt["normal_terminal_record"] != (termination_class in normal_classes):
            raise EvidenceError("normal-terminal flag conflicts with termination class")
        if attempt["subject_timeout"] != (termination_class == SUBJECT_TIMEOUT):
            raise EvidenceError("subject-timeout flag conflicts with termination class")
        if attempt["synthetic_timeout_fault"] != (
            not live_mode and termination_class == SUBJECT_TIMEOUT
        ):
            raise EvidenceError("synthetic-timeout marker conflicts with termination class")
        if attempt["infrastructure_failure"] != (
            termination_class
            in {REPLACEABLE_INFRASTRUCTURE_FAILURE, LATE_INFRASTRUCTURE_FAILURE}
        ):
            raise EvidenceError("infrastructure flag conflicts with termination class")
        if termination_class in normal_classes | {SUBJECT_TIMEOUT} and not attempt["valid"]:
            raise EvidenceError("scientific termination must remain valid")
        if termination_class == REPLACEABLE_INFRASTRUCTURE_FAILURE and (
            attempt["valid"]
            or attempt["usable_subject_output"]
            or attempt["subject_workspace_changed"]
        ):
            raise EvidenceError("replaceable infrastructure attempt contains usable work")
        if termination_class in {
            LATE_INFRASTRUCTURE_FAILURE,
            UNCLASSIFIED_ABNORMAL_TERMINATION,
        } and attempt["valid"] != (
            attempt["usable_subject_output"] or attempt["subject_workspace_changed"]
        ):
            raise EvidenceError("abnormal-attempt validity conflicts with preserved usable work")
        if attempt["resolved"] and not (
            attempt["valid"]
            and attempt["evidence_preserved"]
            and attempt["checker_results_preserved"]
            and attempt["integrity_checks_passed"]
        ):
            raise EvidenceError("resolved attempt lacks preserved checker/integrity evidence")
        _validate_token_record(attempt)
        workspace_relative = attempt["workspace_path"]
        if not isinstance(workspace_relative, str) or workspace_relative in workspace_paths:
            raise EvidenceError("duplicate or invalid workspace path")
        workspace_paths.add(workspace_relative)
        relative = Path(workspace_relative)
        if (
            relative.is_absolute()
            or ".." in relative.parts
            or relative.parts[:1] != ("workspaces",)
            or len(relative.parts) != 2
        ):
            raise EvidenceError("workspace path escapes run directory")
        workspace = root / relative
        if workspace.is_symlink() or not workspace.is_dir():
            raise EvidenceError("attempt workspace is missing or unsafe")
        stub_evidence = workspace / "stub-evidence.json"
        workspace_evidence = _read_canonical_json(stub_evidence)
        normalized_second_arm_failure = (
            attempt["arm_index"] == 2
            and termination_class == LATE_INFRASTRUCTURE_FAILURE
            and workspace_evidence.get("outcome")
            == REPLACEABLE_INFRASTRUCTURE_FAILURE
            and attempt["mechanical_reason_code"]
            == "infrastructure_failure_after_prior_arm"
        )
        if (
            workspace_evidence.get("attempt_id") != attempt_id
            or workspace_evidence.get("mode") != mode
            or workspace_evidence.get("synthetic") is not (not live_mode)
            or (
                workspace_evidence.get("outcome") != termination_class
                and not normalized_second_arm_failure
            )
        ):
            raise EvidenceError("workspace evidence identity mismatch")

    started_invocations = sum(
        attempt["subject_invocation_started"] for attempt in attempts
    )
    if (live_mode and live_calls != started_invocations) or (
        not live_mode and started_invocations != 0
    ):
        raise EvidenceError("manifest live-call count mismatch")

    workspace_root = root / "workspaces"
    if workspace_root.is_symlink() or not workspace_root.is_dir():
        raise EvidenceError("workspace root is missing or unsafe")
    expected_workspace_names = {Path(path).name for path in workspace_paths}
    actual_workspace_names = {path.name for path in workspace_root.iterdir()}
    if actual_workspace_names != expected_workspace_names:
        raise EvidenceError("workspace inventory contains missing or unexpected paths")
    for workspace_name in expected_workspace_names:
        workspace = workspace_root / workspace_name
        if not live_mode and {path.name for path in workspace.iterdir()} != {
            "stub-evidence.json"
        }:
            raise EvidenceError("workspace contains missing or unexpected evidence files")
        if any(path.is_symlink() for path in workspace.rglob("*")):
            raise EvidenceError("workspace evidence contains a symlink")

    executor_transitions: list[tuple[float, int]] = []
    for attempt in attempts:
        executor_transitions.append((attempt["executor_start_monotonic"], 1))
        executor_transitions.append((attempt["executor_end_monotonic"], -1))
    executor_active = 0
    executor_peak = 0
    for _, delta in sorted(executor_transitions, key=lambda item: (item[0], item[1])):
        executor_active += delta
        if executor_active < 0 or executor_active > WORKER_COUNT:
            raise EvidenceError("executor interval replay violated concurrency bounds")
        executor_peak = max(executor_peak, executor_active)
    if executor_active != 0:
        raise EvidenceError("executor interval replay did not terminate empty")
    if manifest.get("observed_peak_executor_calls") != executor_peak:
        raise EvidenceError("manifest executor-concurrency peak mismatch")

    pair_by_id: dict[str, dict[str, Any]] = {}
    referenced_attempts: set[str] = set()
    schedule_by_root = {pair["pair_id"]: pair for pair in schedule["pairs"]}
    pair_intervals_by_task: dict[str, list[tuple[float, float, str]]] = {}
    for pair in pairs:
        if pair.get("schema_version") != PAIR_SCHEMA:
            raise EvidenceError("unsupported pair schema")
        pair_id = pair.get("pair_id")
        if not isinstance(pair_id, str) or pair_id in pair_by_id:
            raise EvidenceError("duplicate or invalid pair record ID")
        pair_by_id[pair_id] = pair
        if pair.get("run_seal_sha256") != run_seal_sha256:
            raise EvidenceError("mixed run seals in pair records")
        if pair.get("run_id") != root.name:
            raise EvidenceError("pair run ID mismatch")
        if pair.get("structural_valid") is not True:
            raise EvidenceError("pair record is not structurally valid")
        root_pair_id = pair.get("root_pair_id")
        if root_pair_id not in schedule_by_root:
            raise EvidenceError("pair record has unknown schedule root")
        scheduled = schedule_by_root[root_pair_id]
        for field in ("task_id", "repeat_id", "first_arm", "second_arm", "arm_order"):
            if pair.get(field) != scheduled[field]:
                raise EvidenceError("pair record conflicts with frozen schedule")
        attempt_ids = pair.get("attempt_ids")
        if not isinstance(attempt_ids, list) or len(attempt_ids) not in (1, 2):
            raise EvidenceError("pair must reference one or two attempts")
        if any(attempt_id in referenced_attempts for attempt_id in attempt_ids):
            raise EvidenceError("attempt referenced by multiple pair records")
        try:
            pair_attempts = [attempt_by_id[attempt_id] for attempt_id in attempt_ids]
        except KeyError as exc:
            raise EvidenceError("pair references missing attempt") from exc
        referenced_attempts.update(attempt_ids)
        if any(attempt["pair_id"] != pair_id for attempt in pair_attempts):
            raise EvidenceError("attempt/pair ID mismatch")
        for attempt in pair_attempts:
            expected_attempt_values = {
                "arm_order": pair["arm_order"],
                "first_arm": pair["first_arm"],
                "queue_position": pair["queue_position"],
                "repeat_id": pair["repeat_id"],
                "root_pair_id": root_pair_id,
                "second_arm": pair["second_arm"],
                "task_id": pair["task_id"],
                "worker_id": pair["worker_id"],
            }
            if any(
                attempt.get(field) != value
                for field, value in expected_attempt_values.items()
            ):
                raise EvidenceError("attempt record conflicts with its pair or schedule")
        if any(
            attempt["replacement_for_pair_id"] != pair.get("replacement_for_pair_id")
            or attempt["replacement_generation"] != pair.get("replacement_generation")
            or attempt["replacement_pair_id"] != pair.get("replacement_pair_id")
            for attempt in pair_attempts
        ):
            raise EvidenceError("attempt/pair replacement linkage mismatch")
        if pair.get("status") == "complete":
            _validate_pair_attempts(
                _PairJob(
                    arm_order=pair["arm_order"],
                    first_arm=pair["first_arm"],
                    pair_id=pair_id,
                    queue_position=pair["queue_position"],
                    repeat_id=pair["repeat_id"],
                    root_pair_id=root_pair_id,
                    second_arm=pair["second_arm"],
                    sequence=scheduled["sequence"],
                    task_id=pair["task_id"],
                ),
                pair_attempts,
            )
        elif pair.get("status") not in ("superseded", "incomplete"):
            raise EvidenceError("invalid pair status")
        if pair.get("status") in {"superseded", "incomplete"} and len(pair_attempts) != 1:
            raise EvidenceError("failed or superseded pair must preserve one preusable attempt")
        if pair.get("status") == "incomplete" and pair.get("replacement_pair_id") is not None:
            raise EvidenceError("incomplete pair unexpectedly links a replacement")
        if pair.get("status") == "superseded" and not pair.get("replacement_pair_id"):
            raise EvidenceError("superseded pair lacks replacement linkage")
        start = _number(pair.get("started_monotonic"), "pair started_monotonic")
        end = _number(pair.get("completed_monotonic"), "pair completed_monotonic")
        enqueued = _number(pair.get("enqueued_monotonic"), "pair enqueued_monotonic")
        claimed = _number(pair.get("pair_claimed_monotonic"), "pair claimed_monotonic")
        if not (enqueued <= claimed <= start <= end):
            raise EvidenceError("impossible pair timestamps")
        if pair.get("pair_end_monotonic") != end or pair.get("pair_completed_monotonic") != end:
            raise EvidenceError("pair completion timestamp aliases mismatch")
        pair_duration = _number(pair.get("pair_duration_seconds"), "pair duration")
        if not math.isclose(pair_duration, end - claimed, rel_tol=0, abs_tol=1e-9):
            raise EvidenceError("pair duration mismatch")
        pair_queue_delay = _number(pair.get("queue_delay_seconds"), "pair queue delay")
        if not math.isclose(pair_queue_delay, claimed - enqueued, rel_tol=0, abs_tol=1e-9):
            raise EvidenceError("pair queue delay mismatch")
        if any(
            attempt["attempt_start_monotonic"] < start
            or attempt["attempt_end_monotonic"] > end
            for attempt in pair_attempts
        ):
            raise EvidenceError("pair bounds do not contain its attempts")
        expected_arm_gap = (
            pair_attempts[1]["subject_start_monotonic"]
            - pair_attempts[0]["subject_end_monotonic"]
            if len(pair_attempts) == 2
            else None
        )
        if pair.get("arm_gap_seconds") != expected_arm_gap:
            raise EvidenceError("pair arm-gap summary mismatch")
        if pair.get("mechanical_reason_codes") != [
            attempt["mechanical_reason_code"] for attempt in pair_attempts
        ]:
            raise EvidenceError("pair mechanical-reason summary mismatch")
        if pair.get("termination_classes") != [
            attempt["termination_class"] for attempt in pair_attempts
        ]:
            raise EvidenceError("pair termination-class summary mismatch")
        eligible, exclusion_reason = _resource_eligibility(pair_attempts)
        if pair.get("resource_eligible") != eligible or pair.get("exclusion_reason") != exclusion_reason:
            raise EvidenceError("pair resource eligibility mismatch")
        if pair.get("resource_exclusion_reason") != exclusion_reason:
            raise EvidenceError("pair exclusion reason alias mismatch")
        telemetry_complete = eligible and all(
            attempt["uncached_input_plus_output_token_proxy"] is not None
            for attempt in pair_attempts
        )
        if pair.get("token_telemetry_complete") != telemetry_complete:
            raise EvidenceError("pair token-telemetry summary mismatch")
        pair_intervals_by_task.setdefault(pair["task_id"], []).append((start, end, pair_id))
    if referenced_attempts != set(attempt_by_id):
        raise EvidenceError("unreferenced attempt record")
    pair_ids_by_root: dict[str, set[str]] = {
        root_pair_id: set() for root_pair_id in schedule_by_root
    }
    for pair in pairs:
        pair_ids_by_root[pair["root_pair_id"]].add(pair["pair_id"])
    terminal_by_root: dict[str, dict[str, Any]] = {}
    superseded_count = 0
    for root_pair_id in schedule_by_root:
        current = pair_by_id.get(root_pair_id)
        if current is None:
            raise EvidenceError("missing scheduled root pair record")
        seen_chain: set[str] = set()
        expected_generation = 0
        expected_parent: str | None = None
        while True:
            current_id = current["pair_id"]
            if current_id in seen_chain:
                raise EvidenceError("replacement chain contains a cycle")
            seen_chain.add(current_id)
            if current.get("replacement_generation") != expected_generation:
                raise EvidenceError("replacement chain generation mismatch")
            if current.get("replacement_for_pair_id") != expected_parent:
                raise EvidenceError("replacement chain parent mismatch")
            child_id = current.get("replacement_pair_id")
            if child_id is None:
                if current.get("status") not in {"complete", "incomplete"}:
                    raise EvidenceError("replacement chain lacks a terminal pair")
                terminal_by_root[root_pair_id] = current
                break
            if current.get("status") != "superseded":
                raise EvidenceError("non-superseded pair links a replacement")
            failed_attempt = attempt_by_id[current["attempt_ids"][0]]
            if (
                failed_attempt["arm_index"] != 1
                or failed_attempt["termination_class"]
                != REPLACEABLE_INFRASTRUCTURE_FAILURE
                or failed_attempt["usable_subject_output"]
                or failed_attempt["subject_workspace_changed"]
            ):
                raise EvidenceError("replacement did not follow a preusable first-arm infrastructure failure")
            child = pair_by_id.get(child_id)
            if child is None or child.get("root_pair_id") != root_pair_id:
                raise EvidenceError("broken replacement chain")
            superseded_count += 1
            expected_generation += 1
            expected_parent = current_id
            current = child
        if seen_chain != pair_ids_by_root[root_pair_id]:
            raise EvidenceError("replacement chain contains an orphan or branch")
    if replacement_limit is None and superseded_count:
        raise EvidenceError("replacement occurred without an explicit synthetic limit")
    if replacement_limit is not None and superseded_count > replacement_limit:
        raise EvidenceError("synthetic replacement limit exceeded")
    if live_mode:
        eligible_roots = [
            root_pair_id
            for root_pair_id in sorted(
                schedule_by_root,
                key=lambda value: schedule_by_root[value]["queue_position"],
            )
            if attempt_by_id[pair_by_id[root_pair_id]["attempt_ids"][0]][
                "termination_class"
            ]
            == REPLACEABLE_INFRASTRUCTURE_FAILURE
        ]
        selected_roots = {
            pair["root_pair_id"] for pair in pairs if pair["status"] == "superseded"
        }
        if selected_roots != set(eligible_roots[:replacement_limit]):
            raise EvidenceError("live replacement selection is not frozen queue priority")
        reason_codes = set(replacement_policy["reason_codes"])
        if any(
            attempt_by_id[pair_by_id[root_id]["attempt_ids"][0]][
                "mechanical_reason_code"
            ]
            not in reason_codes
            for root_id in selected_roots
        ):
            raise EvidenceError("live replacement uses an unapproved reason code")
        for pair in pairs:
            if pair["replacement_generation"]:
                scheduled_root = schedule_by_root[pair["root_pair_id"]]
                if (
                    pair["replacement_generation"] != 1
                    or pair["pair_id"] != f"{pair['root_pair_id']}-replacement-1"
                    or pair["queue_position"] != 36 + scheduled_root["queue_position"]
                ):
                    raise EvidenceError("live replacement identity or generation mismatch")
        latest_base_claim = max(
            pair_by_id[root]["pair_claimed_monotonic"] for root in schedule_by_root
        )
        if any(
            pair["pair_claimed_monotonic"] < latest_base_claim
            for pair in pairs
            if pair["replacement_generation"]
        ):
            raise EvidenceError("live replacement was claimed before the base queue drained")
    if manifest.get("replacement_pair_count") != superseded_count:
        raise EvidenceError("manifest replacement count mismatch")
    completed_root_count = sum(
        pair["status"] == "complete" for pair in terminal_by_root.values()
    )
    if manifest.get("completed_root_pair_count") != completed_root_count:
        raise EvidenceError("manifest terminal-pair count mismatch")
    if manifest.get("all_scheduled_pairs_complete") != (completed_root_count == 36):
        raise EvidenceError("manifest scheduled-pair completion flag mismatch")
    expected_record_counts = {
        "attempt_records": len(attempts),
        "pair_records": len(pairs),
        "scheduled_root_pairs": 36,
        "superseded_pairs": superseded_count,
        "terminal_pairs": completed_root_count,
    }
    if manifest.get("record_counts") != expected_record_counts:
        raise EvidenceError("manifest detailed record counts mismatch")
    for intervals in pair_intervals_by_task.values():
        ordered = sorted(intervals)
        for previous, current in zip(ordered, ordered[1:]):
            if current[0] < previous[1]:
                raise EvidenceError(
                    f"same-task pair overlap: {previous[2]} and {current[2]}"
                )

    if not events:
        raise EvidenceError("scheduler event stream is empty")
    active_attempts: set[str] = set()
    active_pairs: dict[str, str] = {}
    started_attempt_ids: set[str] = set()
    finished_attempt_ids: set[str] = set()
    durable_attempt_ids: set[str] = set()
    claimed_pair_ids: set[str] = set()
    released_pair_ids: set[str] = set()
    durable_pair_ids: set[str] = set()
    peak = 0
    worker_started: Counter[str] = Counter()
    worker_stopped: Counter[str] = Counter()
    last_event_time = -math.inf
    for expected_index, event in enumerate(events, 1):
        if event.get("schema_version") != EVENT_SCHEMA:
            raise EvidenceError("unsupported scheduler event schema")
        if event.get("event_index") != expected_index:
            raise EvidenceError("scheduler event index gap or reorder")
        if event.get("run_seal_sha256") != run_seal_sha256:
            raise EvidenceError("mixed run seals in scheduler events")
        event_time = _number(event.get("monotonic_time"), "event monotonic_time")
        if event_time < last_event_time:
            raise EvidenceError("scheduler event times moved backwards")
        last_event_time = event_time
        event_type = event.get("event_type")
        if event_type == "worker_started":
            worker_started[event.get("worker_id")] += 1
        elif event_type == "worker_stopped":
            worker_stopped[event.get("worker_id")] += 1
        elif event_type == "pair_claimed":
            task_id = event.get("task_id")
            pair_id = event.get("pair_id")
            if pair_id not in pair_by_id or pair_id in claimed_pair_ids:
                raise EvidenceError("duplicate or unknown pair claim event")
            pair = pair_by_id[pair_id]
            if any(
                event.get(field) != pair[field]
                for field in ("root_pair_id", "task_id", "worker_id")
            ):
                raise EvidenceError("pair claim event conflicts with its pair")
            if task_id in active_pairs.values():
                raise EvidenceError("event replay found simultaneous same-task pairs")
            active_pairs[pair_id] = task_id
            claimed_pair_ids.add(pair_id)
        elif event_type == "pair_released":
            pair_id = event.get("pair_id")
            if pair_id not in active_pairs:
                raise EvidenceError("pair release without claim")
            if pair_id not in durable_pair_ids:
                raise EvidenceError("pair release before durable pair record")
            pair = pair_by_id[pair_id]
            if any(
                event.get(field) != pair[field]
                for field in ("root_pair_id", "task_id", "worker_id")
            ) or event.get("replacement_pair_id") != pair.get("replacement_pair_id"):
                raise EvidenceError("pair release event conflicts with its pair")
            del active_pairs[pair_id]
            released_pair_ids.add(pair_id)
        elif event_type == "subject_started":
            attempt_id = event.get("attempt_id")
            if attempt_id not in attempt_by_id or attempt_id in started_attempt_ids:
                raise EvidenceError("duplicate or unknown subject start event")
            attempt = attempt_by_id[attempt_id]
            if event.get("pair_id") not in active_pairs or (
                event.get("pair_id") != attempt["pair_id"]
                or event.get("task_id") != attempt["task_id"]
                or event.get("worker_id") != attempt["worker_id"]
            ):
                raise EvidenceError("subject start event conflicts with its attempt")
            if event_time != attempt["subject_start_monotonic"]:
                raise EvidenceError("subject start event timestamp mismatch")
            prior_attempt_ids = pair_by_id[attempt["pair_id"]]["attempt_ids"][
                : attempt["arm_index"] - 1
            ]
            if any(
                prior_attempt_id not in durable_attempt_ids
                for prior_attempt_id in prior_attempt_ids
            ):
                raise EvidenceError("later arm started before prior attempt was durable")
            active_attempts.add(attempt_id)
            started_attempt_ids.add(attempt_id)
        elif event_type == "subject_finished":
            attempt_id = event.get("attempt_id")
            if attempt_id not in active_attempts:
                raise EvidenceError("subject finish without start")
            attempt = attempt_by_id[attempt_id]
            if any(
                event.get(field) != attempt[field]
                for field in ("pair_id", "task_id", "worker_id")
            ):
                raise EvidenceError("subject finish event conflicts with its attempt")
            if not live_mode and event_time != attempt["subject_end_monotonic"]:
                raise EvidenceError("subject finish event timestamp mismatch")
            active_attempts.remove(attempt_id)
            finished_attempt_ids.add(attempt_id)
        elif event_type == "attempt_record_durable":
            attempt_id = event.get("attempt_id")
            if attempt_id not in finished_attempt_ids or attempt_id in durable_attempt_ids:
                raise EvidenceError("attempt durable event is missing, early, or duplicate")
            attempt = attempt_by_id[attempt_id]
            if any(
                event.get(field) != attempt[field]
                for field in ("pair_id", "task_id", "worker_id")
            ):
                raise EvidenceError("attempt durable event conflicts with its attempt")
            durable_attempt_ids.add(attempt_id)
        elif event_type == "pair_record_durable":
            pair_id = event.get("pair_id")
            if pair_id not in pair_by_id or pair_id in durable_pair_ids:
                raise EvidenceError("pair durable event is unknown or duplicate")
            if pair_id not in active_pairs:
                raise EvidenceError("pair became durable outside its active claim")
            pair = pair_by_id[pair_id]
            if any(
                event.get(field) != pair[field]
                for field in ("root_pair_id", "task_id", "worker_id")
            ) or event.get("replacement_pair_id") != pair.get("replacement_pair_id"):
                raise EvidenceError("pair durable event conflicts with its pair")
            if any(
                attempt_id not in durable_attempt_ids
                for attempt_id in pair_by_id[pair_id]["attempt_ids"]
            ):
                raise EvidenceError("pair became durable before all attempt records")
            durable_pair_ids.add(pair_id)
        elif event_type == "worker_failed":
            raise EvidenceError("scheduler evidence contains a worker failure")
        else:
            raise EvidenceError(f"unknown scheduler event type: {event_type!r}")
        if event_type in {"pair_claimed", "pair_released"}:
            if event.get("active_pair_count") != len(active_pairs):
                raise EvidenceError("active-pair event count mismatch")
            if event.get("active_task_ids") != sorted(active_pairs.values()):
                raise EvidenceError("active-task event inventory mismatch")
        if event.get("active_subjects") != len(active_attempts):
            raise EvidenceError("active-subject event count mismatch")
        if len(active_attempts) > WORKER_COUNT:
            raise EvidenceError("event replay exceeded subject cap")
        peak = max(peak, len(active_attempts))
    expected_workers = {f"worker-{index:02d}" for index in range(1, 13)}
    expected_worker_counts = Counter({worker_id: 1 for worker_id in expected_workers})
    if worker_started != expected_worker_counts or worker_stopped != expected_worker_counts:
        raise EvidenceError("fixed 12-worker loop evidence is incomplete")
    if active_attempts or active_pairs:
        raise EvidenceError("scheduler event replay did not terminate empty")
    expected_attempt_ids = set(attempt_by_id)
    if not (
        started_attempt_ids
        == finished_attempt_ids
        == durable_attempt_ids
        == expected_attempt_ids
    ):
        raise EvidenceError("attempt event lifecycle is incomplete")
    expected_pair_ids = set(pair_by_id)
    if not (
        claimed_pair_ids == released_pair_ids == durable_pair_ids == expected_pair_ids
    ):
        raise EvidenceError("pair event lifecycle is incomplete")
    if manifest.get("observed_peak_active_subjects") != peak:
        raise EvidenceError("manifest observed peak mismatch")
    if manifest.get("peak_subject_concurrency") != peak:
        raise EvidenceError("manifest peak-concurrency alias mismatch")
    if manifest.get("same_task_overlap_count") != 0:
        raise EvidenceError("manifest reports same-task overlap")
    observed_executor_peak = manifest.get("observed_peak_executor_calls")
    if (
        not isinstance(observed_executor_peak, int)
        or isinstance(observed_executor_peak, bool)
        or observed_executor_peak < 0
        or observed_executor_peak > WORKER_COUNT
    ):
        raise EvidenceError("manifest executor-concurrency diagnostic is invalid")

    expected_workspace_hashes = {
        path.relative_to(root).as_posix(): sha256_file(path)
        for path in sorted(workspace_root.rglob("*"))
        if path.is_file() and not path.is_symlink()
    }
    if manifest.get("workspace_evidence_sha256") != expected_workspace_hashes:
        raise EvidenceError("workspace evidence hash mismatch")
    return {
        "attempts": attempts,
        "events": events,
        "manifest": manifest,
        "pairs": pairs,
        "run_seal": seal,
        "schedule": schedule,
    }


def _write_analysis_if_available(run_dir: Path) -> str | None:
    try:
        from tooling import analyze_starlette_atomic_pairs as analyzer
    except ImportError:
        return None
    analyze = getattr(analyzer, "analyze_run_directory", None)
    if not callable(analyze):
        return None
    analysis_path = run_dir / "analysis.json"
    result = analyze(run_dir)
    if analysis_path.exists():
        return sha256_file(analysis_path)
    return _write_json_once(analysis_path, result)


def _complete_offline_preflight(
    run_dir: Path,
    *,
    analyzer_sha256: str,
    preregistration_sha256: str,
    seed: str,
) -> dict[str, Any]:
    """Child-process body for one killable complete offline preflight."""

    manifest = run_stub(
        run_dir,
        analyzer_sha256=analyzer_sha256,
        preregistration_sha256=preregistration_sha256,
        seed=seed,
    )
    analysis_sha256 = _write_analysis_if_available(run_dir)
    if analysis_sha256 is None:
        raise EvidenceError("preflight did not produce frozen analyzer output")
    validate_run_directory(
        run_dir,
        expected_preregistration_sha256=preregistration_sha256,
        enforce_current_runner=True,
    )
    return {
        "analysis_sha256": analysis_sha256,
        "manifest_sha256": sha256_file(run_dir / "manifest.json"),
        "run_seal_sha256": manifest["run_seal_sha256"],
        "runner_duration_seconds": manifest["duration_seconds"],
        "status": "complete",
    }


def qualify(
    output_root: str | Path,
    *,
    expected_runs: int = 3,
    max_seconds: float = 60.0,
    preregistration_sha256: str = DEFAULT_PREREGISTRATION_SHA256,
) -> dict[str, Any]:
    """Create exactly the requested consecutive offline preflight evidence."""

    if expected_runs <= 0:
        raise ValueError("expected_runs must be positive")
    if max_seconds <= 0:
        raise ValueError("max_seconds must be positive")
    preregistration_sha256 = _validate_sha256(
        preregistration_sha256, "preregistration_sha256"
    )
    output = Path(output_root)
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"qualification output already exists: {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.mkdir(mode=0o700)
    analyzer_sha256 = _analyzer_hash()
    if analyzer_sha256 is None:
        raise EvidenceError("frozen analyzer must exist before qualification")
    run_entries: list[dict[str, Any]] = []
    qualification_started = time.monotonic()
    for index in range(1, expected_runs + 1):
        complete_preflight_started = time.monotonic()
        run_name = f"preflight-{index:03d}"
        run_dir = output / run_name
        command = [
            sys.executable,
            "-m",
            "tooling.starlette_atomic_pairs",
            "_offline-preflight-child",
            "--output-dir",
            str(run_dir),
            "--analyzer-sha256",
            analyzer_sha256,
            "--preregistration-sha256",
            preregistration_sha256,
            "--seed",
            f"starlette-atomic-pair-qualification-v1-{index:03d}",
        ]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                check=False,
                cwd=Path(__file__).resolve().parents[1],
                timeout=max_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise EvidenceError(
                f"{run_name} exceeded the killable {max_seconds:g}-second preflight deadline; "
                "partial evidence was preserved"
            ) from exc
        if completed.returncode != 0:
            detail = completed.stderr.decode("utf-8", errors="replace").strip()
            raise EvidenceError(
                f"{run_name} child failed with exit {completed.returncode}: {detail}"
            )
        try:
            child_result = json.loads(completed.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise EvidenceError(f"{run_name} child returned malformed output") from exc
        if (
            not isinstance(child_result, dict)
            or child_result.get("status") != "complete"
            or completed.stdout != canonical_bytes(child_result)
        ):
            raise EvidenceError(f"{run_name} child returned noncanonical or incomplete output")
        manifest = _read_canonical_json(run_dir / "manifest.json")
        validate_run_directory(
            run_dir,
            expected_preregistration_sha256=preregistration_sha256,
            enforce_current_runner=True,
        )
        expected_child_values = {
            "analysis_sha256": sha256_file(run_dir / "analysis.json"),
            "manifest_sha256": sha256_file(run_dir / "manifest.json"),
            "run_seal_sha256": manifest["run_seal_sha256"],
            "runner_duration_seconds": manifest["duration_seconds"],
            "status": "complete",
        }
        if child_result != expected_child_values:
            raise EvidenceError(f"{run_name} child result does not match durable evidence")
        complete_preflight_duration = time.monotonic() - complete_preflight_started
        if complete_preflight_duration > max_seconds:
            raise EvidenceError(
                f"{run_name} complete preflight exceeded {max_seconds:g} seconds: "
                f"{complete_preflight_duration:.6f}"
            )
        run_entries.append(
            {
                "analysis_sha256": child_result["analysis_sha256"],
                "complete_preflight_duration_seconds": complete_preflight_duration,
                "duration_seconds": complete_preflight_duration,
                "manifest_sha256": child_result["manifest_sha256"],
                "run_directory": run_name,
                "run_seal_sha256": child_result["run_seal_sha256"],
                "runner_duration_seconds": child_result[
                    "runner_duration_seconds"
                ],
            }
        )
    qualification_manifest = {
        "analyzer_sha256": analyzer_sha256,
        "completed_run_count": expected_runs,
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "duration_seconds": time.monotonic() - qualification_started,
        "expected_run_count": expected_runs,
        "live_model_calls": 0,
        "max_preflight_seconds": max_seconds,
        "preregistration_sha256": preregistration_sha256,
        "runner_sha256": sha256_file(Path(__file__)),
        "runs": run_entries,
        "schema_version": QUALIFICATION_SCHEMA,
        "status": "complete",
        "worker_count": WORKER_COUNT,
    }
    _write_json_once(output / "qualification-manifest.json", qualification_manifest)
    verify_qualification(
        output,
        expected_runs=expected_runs,
        max_seconds=max_seconds,
        preregistration_sha256=preregistration_sha256,
    )
    return qualification_manifest


def verify_qualification(
    output_root: str | Path,
    *,
    expected_runs: int,
    max_seconds: float,
    preregistration_sha256: str,
) -> dict[str, Any]:
    """Read-only verification of pre-existing qualification evidence."""

    preregistration_sha256 = _validate_sha256(
        preregistration_sha256, "preregistration_sha256"
    )
    output = Path(output_root)
    if output.is_symlink() or not output.is_dir():
        raise EvidenceError("qualification output root is missing or unsafe")
    qualification_manifest = _read_canonical_json(output / "qualification-manifest.json")
    if qualification_manifest.get("schema_version") != QUALIFICATION_SCHEMA:
        raise EvidenceError("unsupported qualification schema")
    if qualification_manifest.get("status") != "complete":
        raise EvidenceError("qualification is not complete")
    if qualification_manifest.get("preregistration_sha256") != preregistration_sha256:
        raise EvidenceError("qualification preregistration hash mismatch")
    if qualification_manifest.get("expected_run_count") != expected_runs:
        raise EvidenceError("qualification expected-run count mismatch")
    if qualification_manifest.get("completed_run_count") != expected_runs:
        raise EvidenceError("qualification completed-run count mismatch")
    if qualification_manifest.get("worker_count") != WORKER_COUNT:
        raise EvidenceError("qualification worker count mismatch")
    if qualification_manifest.get("live_model_calls") != 0:
        raise EvidenceError("qualification contains live model calls")
    if qualification_manifest.get("max_preflight_seconds") != max_seconds:
        raise EvidenceError("qualification preflight bound mismatch")
    qualification_duration = _number(
        qualification_manifest.get("duration_seconds"), "qualification duration"
    )
    if qualification_duration <= 0:
        raise EvidenceError("qualification duration must be positive")
    if qualification_manifest.get("runner_sha256") != sha256_file(Path(__file__)):
        raise EvidenceError("qualification runner hash mismatch")
    analyzer_sha256 = _analyzer_hash()
    if analyzer_sha256 is None or qualification_manifest.get("analyzer_sha256") != analyzer_sha256:
        raise EvidenceError("qualification analyzer hash mismatch")
    runs = qualification_manifest.get("runs")
    if not isinstance(runs, list) or len(runs) != expected_runs:
        raise EvidenceError("qualification run inventory mismatch")
    expected_names = [f"preflight-{index:03d}" for index in range(1, expected_runs + 1)]
    actual_top = {path.name for path in output.iterdir()}
    expected_top = {"qualification-manifest.json", *expected_names}
    if actual_top != expected_top:
        raise EvidenceError("qualification directory contains missing or unexpected paths")
    verified_runs: list[dict[str, Any]] = []
    for run_index, (expected_name, entry) in enumerate(
        zip(expected_names, runs), 1
    ):
        if not isinstance(entry, dict) or entry.get("run_directory") != expected_name:
            raise EvidenceError("qualification run order/name mismatch")
        run_dir = output / expected_name
        records = validate_run_directory(
            run_dir,
            expected_preregistration_sha256=preregistration_sha256,
            enforce_current_runner=True,
        )
        manifest = records["manifest"]
        if records["run_seal"].get("replacement_policy") != {
            "limit": None,
            "source": "deferred_no_offline_default",
        }:
            raise EvidenceError(
                "official qualification replacement policy must remain deferred"
            )
        schedule = records["schedule"]
        if schedule.get("randomization_seed") != (
            f"starlette-atomic-pair-qualification-v1-{run_index:03d}"
        ):
            raise EvidenceError("official qualification seed mismatch")
        if schedule.get("task_ids") != list(DEFAULT_TASK_IDS):
            raise EvidenceError("official qualification task inventory mismatch")
        if records["run_seal"].get("analyzer_sha256") != analyzer_sha256:
            raise EvidenceError("preflight run-seal analyzer hash mismatch")
        runner_duration = _number(
            manifest.get("duration_seconds"), "preflight runner duration"
        )
        complete_duration = _number(
            entry.get("complete_preflight_duration_seconds"),
            "complete preflight duration",
        )
        if complete_duration <= 0 or complete_duration > max_seconds:
            raise EvidenceError(f"{expected_name} exceeded the preflight time bound")
        if complete_duration < runner_duration:
            raise EvidenceError(
                f"{expected_name} complete duration is shorter than its runner phase"
            )
        if entry.get("duration_seconds") != complete_duration:
            raise EvidenceError("qualification complete-duration alias mismatch")
        if entry.get("runner_duration_seconds") != runner_duration:
            raise EvidenceError("qualification/runner duration mismatch")
        if entry.get("manifest_sha256") != sha256_file(run_dir / "manifest.json"):
            raise EvidenceError("qualification run-manifest hash mismatch")
        if entry.get("run_seal_sha256") != manifest.get("run_seal_sha256"):
            raise EvidenceError("qualification run-seal hash mismatch")
        if manifest.get("attempt_record_count") != 72 or manifest.get("pair_record_count") != 36:
            raise EvidenceError("qualification preflight is not a complete 36/72 dry run")
        if not manifest.get("all_scheduled_pairs_complete"):
            raise EvidenceError("qualification has incomplete scheduled pairs")
        if manifest.get("observed_peak_active_subjects") != WORKER_COUNT:
            raise EvidenceError("qualification did not observe all 12 stub workers concurrently")
        if manifest.get("observed_peak_executor_calls") != WORKER_COUNT:
            raise EvidenceError("qualification did not observe 12 concurrent executor calls")
        analysis_path = run_dir / "analysis.json"
        if analysis_path.exists():
            if entry.get("analysis_sha256") != sha256_file(analysis_path):
                raise EvidenceError("qualification analysis hash mismatch")
            recorded_analysis = _read_canonical_json(analysis_path)
            from tooling import analyze_starlette_atomic_pairs as analyzer

            recomputed_analysis = analyzer.analyze_run_directory(run_dir)
            if recorded_analysis != recomputed_analysis or analysis_path.read_bytes() != canonical_bytes(
                recomputed_analysis
            ):
                raise EvidenceError("qualification analysis does not match sealed analyzer recomputation")
        elif entry.get("analysis_sha256") is not None:
            raise EvidenceError("qualification references missing analysis")
        else:
            raise EvidenceError("qualification preflight lacks frozen analysis")
        verified_runs.append(
            {
                "complete_preflight_duration_seconds": complete_duration,
                "runner_duration_seconds": runner_duration,
                "run_directory": expected_name,
                "run_seal_sha256": manifest["run_seal_sha256"],
            }
        )
    if qualification_duration < sum(
        run["complete_preflight_duration_seconds"] for run in verified_runs
    ):
        raise EvidenceError(
            "qualification duration is shorter than its sequential complete preflights"
        )
    return {
        "preregistration_sha256": preregistration_sha256,
        "run_count": len(verified_runs),
        "runs": verified_runs,
        "status": "verified",
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run-stub", help="run one exclusive no-model preflight")
    run_parser.add_argument("--output-dir", type=Path, required=True)
    run_parser.add_argument("--seed", default=DEFAULT_SEED)
    run_parser.add_argument(
        "--preregistration-sha256", default=DEFAULT_PREREGISTRATION_SHA256
    )
    run_parser.add_argument("--synthetic-replacement-limit", type=int)

    qualify_parser = subparsers.add_parser(
        "qualify", help="create consecutive complete offline preflights"
    )
    qualify_parser.add_argument("--output-root", type=Path, required=True)
    qualify_parser.add_argument("--expected-runs", type=int, default=3)
    qualify_parser.add_argument("--max-seconds", type=float, default=60.0)
    qualify_parser.add_argument(
        "--preregistration-sha256", default=DEFAULT_PREREGISTRATION_SHA256
    )

    verify_parser = subparsers.add_parser(
        "verify-qualification", help="read-only verification of qualification evidence"
    )
    verify_parser.add_argument("--output-root", type=Path, required=True)
    verify_parser.add_argument("--expected-runs", type=int, required=True)
    verify_parser.add_argument("--max-seconds", type=float, required=True)
    verify_parser.add_argument("--preregistration-sha256", required=True)

    child_parser = subparsers.add_parser(
        "_offline-preflight-child",
        help=argparse.SUPPRESS,
    )
    child_parser.add_argument("--output-dir", type=Path, required=True)
    child_parser.add_argument("--analyzer-sha256", required=True)
    child_parser.add_argument("--preregistration-sha256", required=True)
    child_parser.add_argument("--seed", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "run-stub":
            result = run_stub(
                arguments.output_dir,
                preregistration_sha256=arguments.preregistration_sha256,
                seed=arguments.seed,
                synthetic_replacement_limit=arguments.synthetic_replacement_limit,
            )
        elif arguments.command == "qualify":
            result = qualify(
                arguments.output_root,
                expected_runs=arguments.expected_runs,
                max_seconds=arguments.max_seconds,
                preregistration_sha256=arguments.preregistration_sha256,
            )
        elif arguments.command == "verify-qualification":
            result = verify_qualification(
                arguments.output_root,
                expected_runs=arguments.expected_runs,
                max_seconds=arguments.max_seconds,
                preregistration_sha256=arguments.preregistration_sha256,
            )
        else:
            result = _complete_offline_preflight(
                arguments.output_dir,
                analyzer_sha256=_validate_sha256(
                    arguments.analyzer_sha256, "analyzer_sha256"
                ),
                preregistration_sha256=arguments.preregistration_sha256,
                seed=arguments.seed,
            )
    except (EvidenceError, FileExistsError, OSError, ValueError) as exc:
        print(f"starlette atomic-pair error: {exc}", file=sys.stderr)
        return 2
    print(canonical_json(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
