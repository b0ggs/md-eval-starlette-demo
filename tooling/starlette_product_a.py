#!/usr/bin/env python3
"""Fresh, fixed, approval-gated Product A Starlette experiment.

The command line intentionally exposes no knobs for tasks, arms, models, or
analysis.  Tests may inject an offline preflight and executor through the
Python API; the command-line ``run`` command always uses the sealed live
backend and therefore always requires a separately created approval.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
from pathlib import Path, PurePosixPath
import statistics
import threading
import time
from typing import Any, Callable, Mapping, Sequence
import uuid

from mdseval.hashing import sha256_file
from scripts import run_batch
from scripts.contain import runtime as sealed
from tooling import analyze_starlette_atomic_pairs as statistical
from tooling import starlette_atomic_pairs as atomic
from tooling import starlette_eighteen_task_experiment as historical
from tooling import starlette_live_shakeout as live
from tooling import taskcheck
from tooling.starlette_demo import demo_task_registry


ROOT = Path(__file__).resolve().parents[1]
RUNS_ROOT = ROOT / "runs" / "product-a"

# Product A is deliberately a finite protocol, not a configurable framework.
TASK_IDS = historical.TASK_IDS
ARM_PATHS = dict(historical.ARM_PATHS)
ARM_HASHES = dict(historical.ARM_HASHES)
IMAGE_DIGESTS = dict(historical.IMAGE_DIGESTS)
INTERPRETER_PINS = dict(historical.INTERPRETER_PINS)
SPEC_PATH = historical.SPEC_PATH
SEED = historical.SEED
WORKERS = 12
REPEATS = 2
PAIR_COUNT = 36
PLANNED_CALLS = 72
REPLACEMENT_PAIR_LIMIT = 4
MAX_SUBJECT_INVOCATIONS = 80
PREFLIGHT_DEADLINE_SECONDS = 120
MODEL = "gpt-5.6-sol"
REASONING_EFFORT = "high"
RUNNER = historical.RUNNER
REPLACEMENT_REASON_CODES = tuple(historical.REPLACEMENT_REASON_CODES)

REQUEST_FILENAME = "REQUEST.json"
APPROVAL_FILENAME = "APPROVED.json"
CONSUMED_APPROVAL_FILENAME = "CONSUMED_APPROVAL.json"
EVIDENCE_DIRECTORY = "live-evidence"
REPORT_FILENAME = "REPORT.md"

ANALYSIS_FREEZE = {
    "schema_version": "starlette-product-a-complete-task-analysis-v1",
    "selection_timing": "prospectively frozen in the hash-bound request before launch",
    "top_level_correctness": (
        "for each arm, failed and passed terminal planned outcomes out of 36, failures first; "
        "all failed raw invocations are additionally enumerated"
    ),
    "analysis_unit": "task",
    "required_usable_pairs_per_task": 2,
    "lone_surviving_repeat_policy": "exclude_task",
    "minimum_eligible_tasks_for_estimation": 2,
    "telemetry_eligibility": "one common eligible task set requires both wall and token telemetry",
    "complete_task_rule": (
        "include a task only when both terminal paired repeats are complete and each repeat "
        "has jointly normal, valid, mechanically resolved MD and No-MD attempts with finite "
        "positive wall and token measurements; never use a lone surviving repeat"
    ),
    "wall_endpoint": "subject_end_monotonic - subject_start_monotonic",
    "token_endpoint": "input_tokens - cached_input_tokens + output_tokens",
    "task_effect": "log(arithmetic mean MD / arithmetic mean No-MD) across both repeats",
    "task_weighting": "equal weight over all eligible tasks",
    "test": "two-sided one-sample Student-t test of eligible task effects; alpha=0.05",
    "interval": "two-sided model-based 95% Student-t confidence interval",
    "classification": [
        "significantly favorable",
        "significantly unfavorable",
        "nonsignificant",
        "not estimable",
    ],
    "post_outcome_method_choice_forbidden": True,
}

COMPONENT_PATHS = {
    **historical.COMPONENTS,
    "standalone_task_registry": "tooling/starlette_demo.py",
    "product_a_runner_and_reporter": "tooling/starlette_product_a.py",
}


class ProductAError(RuntimeError):
    """Raised when a Product A lifecycle or evidence invariant is violated."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ProductAError(message)


def _canonical_bytes(value: object) -> bytes:
    return atomic.canonical_bytes(value)


def _digest_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def _write_json_once(path: Path, value: object) -> str:
    return atomic._write_json_once(path, value)


def _read_json(path: Path) -> dict[str, Any]:
    value = atomic._read_canonical_json(path)
    _require(isinstance(value, dict), f"JSON object required: {path}")
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return atomic._read_canonical_jsonl(path)


def _validate_run_boundary(run_dir: Path, allowed_runs_root: Path) -> Path:
    """Require a real, direct child of the explicitly allowed runs root."""

    run_dir = run_dir.absolute()
    allowed_runs_root = allowed_runs_root.absolute()
    _require(
        allowed_runs_root.is_dir()
        and not allowed_runs_root.is_symlink()
        and allowed_runs_root.resolve() == allowed_runs_root,
        "allowed Product A runs root is missing, indirect, or unsafe",
    )
    _require(
        run_dir.parent == allowed_runs_root
        and run_dir.is_dir()
        and not run_dir.is_symlink()
        and run_dir.resolve() == run_dir,
        "run directory must be a real direct child of the allowed Product A runs root",
    )
    _require(
        run_dir.name.startswith("product-a-")
        and taskcheck.TASK_ID.fullmatch(run_dir.name) is not None,
        "invalid Product A run ID",
    )
    return run_dir


def _bound_runs_root(
    run_dir: Path,
    request: Mapping[str, Any],
    allowed_runs_root: Path | None,
) -> Path:
    """Resolve the fixed CLI root or the request-bound Python test root."""

    try:
        recorded = Path(str(request["runs_root"])).absolute()
    except KeyError as exc:
        raise ProductAError("request does not bind its runs root") from exc
    expected = RUNS_ROOT.absolute() if allowed_runs_root is None else allowed_runs_root.absolute()
    # ``None`` remains convenient for API-created temporary campaigns: their
    # canonical, approved request is the authority.  The public CLI always
    # passes RUNS_ROOT explicitly.
    if allowed_runs_root is None and run_dir.absolute().parent != RUNS_ROOT.absolute():
        expected = recorded
    _require(recorded == expected, "request runs root differs from the allowed root")
    return expected


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _nonce() -> str:
    return uuid.uuid4().hex


def _fixed_schedule() -> dict[str, Any]:
    schedule = historical.build_schedule()
    historical._validate_schedule(schedule)
    return schedule


def _execution_request(repo: Path, run_id: str) -> dict[str, Any]:
    spec = repo / SPEC_PATH
    container = {
        "image_digests": dict(IMAGE_DIGESTS),
        "interpreter_pins": dict(INTERPRETER_PINS),
        "spec_sha256": sha256_file(spec),
        "web_search": "disabled",
    }
    with demo_task_registry():
        return run_batch._request(
            run_id,
            [repo / "tasks" / task_id for task_id in TASK_IDS],
            [
                ("candidate", repo / ARM_PATHS["md"]),
                ("control", repo / ARM_PATHS["no-md"]),
            ],
            task_order_seed=0,
            runner=RUNNER,
            container=container,
        )


def _build_request(
    repo: Path,
    run_dir: Path,
    *,
    request_nonce: str,
    created_utc: str,
) -> dict[str, Any]:
    _require(repo.resolve() == ROOT, "Product A must use this repository's bundled inputs")
    _require(run_dir.is_absolute(), "run directory must be absolute")
    _validate_run_boundary(run_dir, run_dir.parent)
    _require(isinstance(request_nonce, str) and len(request_nonce) == 32 and
             all(character in "0123456789abcdef" for character in request_nonce),
             "invalid request nonce")
    _require(isinstance(created_utc, str) and bool(created_utc), "invalid request creation time")
    _require((repo / SPEC_PATH).is_file(), "bundled contamination specification is missing")
    for arm, relative in ARM_PATHS.items():
        _require(sha256_file(repo / relative) == ARM_HASHES[arm], f"bundled arm changed: {arm}")

    execution = _execution_request(repo, run_dir.name)
    task_hashes = {row["id"]: row["manifest_sha256"] for row in execution["tasks"]}
    schedule = _fixed_schedule()
    request = {
        "schema_version": "starlette-product-a-request-v1",
        "product": "A",
        "purpose": "fresh fixed 18-task Starlette MD versus No-MD experiment",
        "run_id": run_dir.name,
        "run_directory": str(run_dir),
        "runs_root": str(run_dir.parent),
        "request_nonce": request_nonce,
        "created_utc": created_utc,
        "attempt_inventory": "fresh calls and fresh exclusive workspaces only",
        "tasks": [
            {"task_id": task_id, "manifest_sha256": task_hashes[task_id]}
            for task_id in TASK_IDS
        ],
        "arms": [
            {"name": arm, "path": ARM_PATHS[arm], "sha256": ARM_HASHES[arm]}
            for arm in ("md", "no-md")
        ],
        "execution_arm_mapping": {"md": "candidate", "no-md": "control"},
        "model": MODEL,
        "reasoning_effort": REASONING_EFFORT,
        "runner": execution["runner"],
        "schedule": schedule,
        "planned_atomic_pairs": PAIR_COUNT,
        "planned_scientific_calls": PLANNED_CALLS,
        "max_subject_invocations": MAX_SUBJECT_INVOCATIONS,
        "execution": {
            "worker_count": WORKERS,
            "max_active_subject_calls": WORKERS,
            "same_task_repeats_may_overlap": False,
            "pair_arms_same_worker": True,
            "pair_arms_sequential_and_back_to_back": True,
            "base_queue_must_be_fully_claimed_before_replacements": True,
            "preflight_deadline_seconds": PREFLIGHT_DEADLINE_SECONDS,
            "subject_timeout_seconds": RUNNER.timeout_seconds,
            "output_directory": f"{EVIDENCE_DIRECTORY}",
        },
        "retry_and_fallback": {
            "inline_retry_limit": 0,
            "same_arm_relaunch_limit": 0,
            "replacement_generation_limit": 1,
            "max_replacement_pairs": REPLACEMENT_PAIR_LIMIT,
            "max_contingent_replacement_calls": 2 * REPLACEMENT_PAIR_LIMIT,
            "max_subject_invocations": MAX_SUBJECT_INVOCATIONS,
            "whole_pair_replacement_only": True,
            "first_arm_preusable_infrastructure_only": True,
            "scientific_failures_never_retried": True,
            "reason_codes": list(REPLACEMENT_REASON_CODES),
        },
        "analysis_freeze": dict(ANALYSIS_FREEZE),
        "contamination_spec": {
            "path": SPEC_PATH,
            "sha256": sha256_file(repo / SPEC_PATH),
        },
        "sealed_attempt_request_sha256": _digest_bytes(_canonical_bytes(execution)),
        "component_sha256": {
            name: sha256_file(repo / relative)
            for name, relative in COMPONENT_PATHS.items()
        },
        "repository_state_sha256": {
            "task_ledger": sha256_file(repo / "verification/starlette-task-ledger.jsonl"),
            "exposure_ledger": sha256_file(repo / "tasks/exposures.jsonl"),
        },
        "approval": {
            "required": True,
            "request_sha256_exact_match": True,
            "one_use": True,
            "consumed_before_preflight_backend_or_execution_output": True,
            "approved_path": APPROVAL_FILENAME,
            "consumed_path": CONSUMED_APPROVAL_FILENAME,
        },
        "report": {
            "automatic_during_verify_report": True,
            "path": REPORT_FILENAME,
            "write_once": True,
        },
    }
    return request


def _validate_request(repo: Path, run_dir: Path, request: Mapping[str, Any]) -> None:
    try:
        nonce = request["request_nonce"]
        created = request["created_utc"]
    except KeyError as exc:
        raise ProductAError("request identity is incomplete") from exc
    expected = _build_request(
        repo,
        run_dir,
        request_nonce=str(nonce),
        created_utc=str(created),
    )
    _require(dict(request) == expected, "request differs from the fixed Product A protocol")


def prepare(
    *,
    runs_root: Path = RUNS_ROOT,
    repo: Path = ROOT,
    now: Callable[[], str] = _utc_now,
    nonce_factory: Callable[[], str] = _nonce,
) -> dict[str, Any]:
    """Create one unique, unapproved Product A request directory."""

    repo = repo.absolute()
    runs_root = runs_root.absolute()
    _require(repo.resolve() == ROOT, "Product A repository root is fixed")
    if runs_root.exists():
        _require(
            runs_root.is_dir()
            and not runs_root.is_symlink()
            and runs_root.resolve() == runs_root,
            "unsafe Product A runs root",
        )
    else:
        runs_root.mkdir(parents=True)
        _require(runs_root.resolve() == runs_root, "unsafe Product A runs root")
    for _ in range(16):
        nonce = nonce_factory()
        _require(isinstance(nonce, str), "nonce factory returned a non-string")
        run_id = f"product-a-{nonce[:30]}"
        run_dir = runs_root / run_id
        try:
            run_dir.mkdir(mode=0o700)
        except FileExistsError:
            continue
        _validate_run_boundary(run_dir, runs_root)
        request = _build_request(repo, run_dir, request_nonce=nonce, created_utc=now())
        request_path = run_dir / REQUEST_FILENAME
        request_sha = _write_json_once(request_path, request)
        return {
            "run_directory": str(run_dir),
            "request": str(request_path),
            "request_sha256": request_sha,
        }
    raise ProductAError("could not allocate a unique Product A run directory")


def approve(
    run_dir: Path,
    request_sha256: str,
    *,
    repo: Path = ROOT,
    allowed_runs_root: Path | None = None,
) -> dict[str, Any]:
    """Explicitly approve the exact canonical request, once."""

    run_dir = run_dir.absolute()
    _validate_run_boundary(run_dir, allowed_runs_root or run_dir.parent)
    request = _read_json(run_dir / REQUEST_FILENAME)
    allowed_root = _bound_runs_root(run_dir, request, allowed_runs_root)
    run_dir = _validate_run_boundary(run_dir, allowed_root)
    _validate_request(repo.absolute(), run_dir, request)
    actual_sha = sha256_file(run_dir / REQUEST_FILENAME)
    _require(request_sha256 == actual_sha, "approval request SHA-256 does not match REQUEST.json")
    _require(not (run_dir / CONSUMED_APPROVAL_FILENAME).exists(), "approval was already consumed")
    _validate_run_boundary(run_dir, allowed_root)
    approval = {"request_sha256": actual_sha}
    try:
        approval_sha = _write_json_once(run_dir / APPROVAL_FILENAME, approval)
    except FileExistsError as exc:
        raise ProductAError("request is already approved") from exc
    return {
        "approval": str(run_dir / APPROVAL_FILENAME),
        "approval_sha256": approval_sha,
        "request_sha256": actual_sha,
    }


def _consume_approval(run_dir: Path) -> tuple[dict[str, Any], str]:
    """Atomically claim an approval; the claim remains consumed after any failure."""

    approved = run_dir / APPROVAL_FILENAME
    consumed = run_dir / CONSUMED_APPROVAL_FILENAME
    try:
        approval_raw = approved.read_bytes()
        approval = json.loads(approval_raw)
    except FileNotFoundError as exc:
        raise ProductAError("an explicit approval is required") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProductAError("approval is malformed") from exc
    _require(isinstance(approval, dict) and approval_raw == _canonical_bytes(approval),
             "approval is noncanonical")
    approval_sha = _digest_bytes(approval_raw)
    request_sha = approval.get("request_sha256")
    claim = {
        "schema_version": "starlette-product-a-consumed-approval-v1",
        "approval_sha256": approval_sha,
        "request_sha256": request_sha,
    }
    try:
        _write_json_once(consumed, claim)
    except FileExistsError as exc:
        raise ProductAError("approval was already consumed") from exc
    _require(not approved.is_symlink() and approved.read_bytes() == approval_raw,
             "approval changed while it was consumed")
    return approval, approval_sha


def classify_endpoint(mean_effect: float | None, p_value: float | None) -> str:
    """Return the protocol's exact four-way endpoint interpretation."""

    if (
        isinstance(mean_effect, bool)
        or isinstance(p_value, bool)
        or not isinstance(mean_effect, (int, float))
        or not isinstance(p_value, (int, float))
        or not math.isfinite(float(mean_effect))
        or not math.isfinite(float(p_value))
        or not 0.0 <= float(p_value) <= 1.0
    ):
        return "not estimable"
    if p_value < 0.05 and mean_effect < 0.0:
        return "significantly favorable"
    if p_value < 0.05 and mean_effect > 0.0:
        return "significantly unfavorable"
    return "nonsignificant"


def _is_positive_number(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
        and float(value) > 0.0
    )


def _attempt_passes(attempt: Mapping[str, Any]) -> bool:
    return (
        attempt.get("normal_terminal_record") is True
        and attempt.get("valid") is True
        and attempt.get("resolved") is True
    )


def _finite_number(value: object, field: str) -> float:
    _require(
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value)),
        f"attempt {field} must be finite numeric telemetry",
    )
    return float(value)


def _validate_attempt_telemetry(attempts: Sequence[Mapping[str, Any]]) -> None:
    """Reject impossible timing or workspace telemetry before any analysis."""

    seen_attempt_ids: set[str] = set()
    seen_workspaces: set[str] = set()
    for attempt in attempts:
        attempt_id = attempt.get("attempt_id")
        workspace_text = attempt.get("workspace_path")
        _require(
            isinstance(attempt_id, str)
            and bool(attempt_id)
            and attempt_id not in seen_attempt_ids,
            "attempt identity is missing or duplicated",
        )
        _require(isinstance(workspace_text, str),
                 f"attempt workspace path is invalid: {attempt_id}")
        workspace = PurePosixPath(workspace_text)
        _require(
            not workspace.is_absolute()
            and workspace.as_posix() == workspace_text
            and workspace.parts == ("workspaces", attempt_id)
            and workspace_text not in seen_workspaces,
            f"attempt workspace path is unsafe or duplicated: {attempt_id}",
        )
        seen_attempt_ids.add(attempt_id)
        seen_workspaces.add(workspace_text)

        attempt_start = _finite_number(
            attempt.get("attempt_start_monotonic"), "attempt_start_monotonic"
        )
        attempt_end = _finite_number(
            attempt.get("attempt_end_monotonic"), "attempt_end_monotonic"
        )
        executor_start = _finite_number(
            attempt.get("executor_start_monotonic"), "executor_start_monotonic"
        )
        executor_end = _finite_number(
            attempt.get("executor_end_monotonic"), "executor_end_monotonic"
        )
        subject_start = _finite_number(
            attempt.get("subject_start_monotonic"), "subject_start_monotonic"
        )
        subject_end = _finite_number(
            attempt.get("subject_end_monotonic"), "subject_end_monotonic"
        )
        observed_end = _finite_number(
            attempt.get("subject_observation_end_monotonic"),
            "subject_observation_end_monotonic",
        )
        wall = _finite_number(attempt.get("subject_wall_seconds"), "subject_wall_seconds")
        duration_alias = _finite_number(
            attempt.get("subject_duration_seconds"), "subject_duration_seconds"
        )
        tolerance = 1e-9
        _require(
            attempt_start <= subject_start + tolerance
            and subject_start <= executor_start + tolerance
            and executor_start <= executor_end + tolerance
            and executor_end <= observed_end + tolerance
            and subject_start <= subject_end + tolerance
            and subject_end <= observed_end + tolerance
            and observed_end <= attempt_end + tolerance,
            f"attempt timestamps are not finitely ordered: {attempt_id}",
        )
        expected_wall = subject_end - subject_start
        _require(
            wall >= 0.0
            and math.isclose(wall, expected_wall, rel_tol=0.0, abs_tol=tolerance)
            and math.isclose(duration_alias, wall, rel_tol=0.0, abs_tol=tolerance),
            f"attempt subject wall telemetry is inconsistent: {attempt_id}",
        )
        atomic._validate_token_record(attempt)
        classified = atomic.classify_termination(
            str(attempt.get("termination_class")),
            mechanical_reason_code=attempt.get("mechanical_reason_code"),
            resolved=attempt.get("resolved"),
            usable_subject_output=attempt.get("usable_subject_output"),
            subject_workspace_changed=attempt.get("subject_workspace_changed"),
        )
        for field in (
            "mechanical_reason_code",
            "resolved",
            "valid",
            "normal_terminal_record",
            "subject_timeout",
            "infrastructure_failure",
            "usable_subject_output",
            "subject_workspace_changed",
        ):
            _require(
                attempt.get(field) == classified[field],
                f"attempt classification is inconsistent: {attempt_id}:{field}",
            )
        _require(
            attempt.get("evidence_preserved") is True
            and attempt.get("checker_results_preserved") is True
            and attempt.get("integrity_checks_passed") is classified["resolved"]
            and type(attempt.get("subject_invocation_started")) is bool,
            f"attempt preservation flags are inconsistent: {attempt_id}",
        )


def _readable_failure_reason(attempt: Mapping[str, Any]) -> str:
    termination = attempt.get("termination_class")
    if termination == atomic.NORMAL_INCORRECT_COMPLETION:
        return "mechanical checker did not resolve the task"
    if termination == atomic.REFUSAL:
        return "subject refused or did not implement the task"
    if termination == atomic.SUBJECT_EARLY_STOP:
        return "subject stopped before completing the task"
    if termination == atomic.SUBJECT_TIMEOUT:
        return "subject exceeded the fixed execution timeout"
    if termination == atomic.REPLACEABLE_INFRASTRUCTURE_FAILURE:
        return "pre-output infrastructure failure made the invocation unusable"
    if termination == atomic.LATE_INFRASTRUCTURE_FAILURE:
        return "infrastructure failed after the paired execution had begun"
    if termination == atomic.UNCLASSIFIED_ABNORMAL_TERMINATION:
        return "abnormal termination could not be classified as a usable result"
    if attempt.get("resolved") is not True:
        return "mechanical checker did not resolve the task"
    if attempt.get("valid") is not True:
        return "attempt evidence or integrity validation failed"
    return "attempt did not satisfy the fixed passing criteria"


def _terminal_pairs(pairs: Sequence[Mapping[str, Any]]) -> dict[str, Mapping[str, Any]]:
    terminal: dict[str, Mapping[str, Any]] = {}
    for pair in sorted(
        pairs,
        key=lambda row: (str(row.get("root_pair_id")), int(row.get("replacement_generation", -1))),
    ):
        root_pair_id = pair.get("root_pair_id")
        _require(isinstance(root_pair_id, str), "pair has no root identity")
        terminal[root_pair_id] = pair
    return terminal


def _pair_eligibility_reasons(
    pair: Mapping[str, Any] | None,
    by_attempt: Mapping[str, Mapping[str, Any]],
) -> tuple[list[str], list[Mapping[str, Any]]]:
    if pair is None:
        return ["missing terminal pair"], []
    attempt_ids = pair.get("attempt_ids")
    if not isinstance(attempt_ids, list):
        return ["invalid attempt inventory"], []
    try:
        attempts = [by_attempt[str(attempt_id)] for attempt_id in attempt_ids]
    except KeyError:
        return ["missing attempt record"], []
    reasons: list[str] = []
    if pair.get("status") != "complete":
        reasons.append(f"terminal pair status is {pair.get('status', 'missing')}")
    if len(attempts) != 2 or {row.get("arm") for row in attempts} != {"candidate", "control"}:
        reasons.append("paired MD/No-MD attempt inventory is incomplete")
    for attempt in attempts:
        label = "MD" if attempt.get("arm") == "candidate" else "No-MD"
        if not _attempt_passes(attempt):
            reason = attempt.get("mechanical_reason_code") or attempt.get("termination_class") or "failed"
            reasons.append(f"{label} did not pass: {reason}")
        if not _is_positive_number(attempt.get("subject_wall_seconds")):
            reasons.append(f"{label} wall telemetry is missing or invalid")
        if not _is_positive_number(attempt.get("uncached_input_plus_output_token_proxy")):
            reasons.append(f"{label} token telemetry is missing or invalid")
    return list(dict.fromkeys(reasons)), attempts


def _endpoint(
    name: str,
    eligible_task_ids: Sequence[str],
    selected: Mapping[str, Sequence[Mapping[str, Any]]],
    value: Callable[[Mapping[str, Any]], object],
) -> dict[str, Any]:
    task_results: list[dict[str, Any]] = []
    for task_id in eligible_task_ids:
        md_values: list[float] = []
        no_md_values: list[float] = []
        for pair in selected[task_id]:
            for attempt in pair["attempts"]:
                observed = value(attempt)
                _require(_is_positive_number(observed),
                         f"eligible {name} telemetry became invalid: {task_id}")
                target = md_values if attempt["arm"] == "candidate" else no_md_values
                target.append(float(observed))
        _require(len(md_values) == REPEATS and len(no_md_values) == REPEATS,
                 f"eligible {name} inventory became incomplete: {task_id}")
        md_mean = statistics.fmean(md_values)
        no_md_mean = statistics.fmean(no_md_values)
        effect = math.log(md_mean) - math.log(no_md_mean)
        task_results.append({
            "task_id": task_id,
            "md_mean": md_mean,
            "no_md_mean": no_md_mean,
            "log_ratio": effect,
            "change_percent": 100.0 * (md_mean / no_md_mean - 1.0),
        })

    if len(task_results) < 2:
        return {
            "name": name,
            "status": "not estimable",
            "classification": "not estimable",
            "reason": "fewer than two eligible complete tasks",
            "task_count": len(task_results),
            "degrees_of_freedom": None,
            "task_results": task_results,
            "mean_task_log_ratio": None,
            "geometric_mean_ratio": None,
            "change_percent": None,
            "confidence_interval_95_log_ratio": None,
            "confidence_interval_95_ratio": None,
            "confidence_interval_95_change_percent": None,
            "t_statistic": None,
            "p_value_two_sided": None,
        }

    effects = [row["log_ratio"] for row in task_results]
    mean_effect = statistics.fmean(effects)
    sample_sd = statistics.stdev(effects)
    standard_error = sample_sd / math.sqrt(len(effects))
    if standard_error == 0.0:
        t_statistic: float | None = 0.0 if mean_effect == 0.0 else None
        p_value = 1.0 if mean_effect == 0.0 else 0.0
    else:
        t_statistic = mean_effect / standard_error
        p_value = statistical.student_t_two_sided_p(t_statistic, len(effects) - 1)
    critical = statistical.student_t_quantile(0.975, len(effects) - 1)
    lower = mean_effect - critical * standard_error
    upper = mean_effect + critical * standard_error
    ratio = math.exp(mean_effect)
    ratio_ci = [math.exp(lower), math.exp(upper)]
    classification = classify_endpoint(mean_effect, p_value)
    _require(classification != "not estimable", f"estimated {name} result became nonfinite")
    return {
        "name": name,
        "status": "estimated",
        "classification": classification,
        "task_count": len(task_results),
        "degrees_of_freedom": len(task_results) - 1,
        "task_results": task_results,
        "mean_task_log_ratio": mean_effect,
        "sample_standard_deviation": sample_sd,
        "standard_error": standard_error,
        "geometric_mean_ratio": ratio,
        "change_percent": 100.0 * (ratio - 1.0),
        "confidence_interval_95_log_ratio": [lower, upper],
        "confidence_interval_95_ratio": ratio_ci,
        "confidence_interval_95_change_percent": [
            100.0 * (ratio_ci[0] - 1.0),
            100.0 * (ratio_ci[1] - 1.0),
        ],
        "t_statistic": t_statistic,
        "p_value_two_sided": p_value,
    }


def build_analysis(
    request: Mapping[str, Any],
    attempts: Sequence[Mapping[str, Any]],
    pairs: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Apply the prospectively frozen complete-task rule to terminal pairs."""

    _validate_attempt_telemetry(attempts)
    _require(request.get("analysis_freeze") == ANALYSIS_FREEZE,
             "request does not contain the fixed complete-task rule")
    by_attempt = {str(row.get("attempt_id")): row for row in attempts}
    _require(len(by_attempt) == len(attempts), "duplicate attempt identity")
    terminal = _terminal_pairs(pairs)
    expected_roots = {
        str(row["root_pair_id"]): row for row in request["schedule"]["pairs"]
    }
    _require(set(terminal) == set(expected_roots), "terminal pair inventory is incomplete")

    correctness = {
        "md": {"passed": 0, "failed": 0, "total": PAIR_COUNT},
        "no_md": {"passed": 0, "failed": 0, "total": PAIR_COUNT},
    }
    failures: list[dict[str, Any]] = []
    terminal_attempt_ids: set[str] = set()
    for attempt in attempts:
        if not _attempt_passes(attempt):
            mechanical_code = (
                attempt.get("mechanical_reason_code")
                or attempt.get("termination_class")
                or "failed"
            )
            failures.append({
                "scope": "raw invocation",
                "attempt_id": attempt.get("attempt_id"),
                "task_id": attempt.get("task_id"),
                "repeat": attempt.get("repeat_id"),
                "arm": "MD" if attempt.get("arm") == "candidate" else "No-MD",
                "mechanical_reason_code": mechanical_code,
                "reason": _readable_failure_reason(attempt),
                "termination_class": attempt.get("termination_class"),
            })

    selected: dict[str, list[dict[str, Any]]] = {task_id: [] for task_id in TASK_IDS}
    exclusion_details: dict[str, list[dict[str, Any]]] = {task_id: [] for task_id in TASK_IDS}
    for root_pair_id, scheduled in expected_roots.items():
        pair = terminal[root_pair_id]
        reasons, pair_attempts = _pair_eligibility_reasons(pair, by_attempt)
        terminal_attempt_ids.update(str(row["attempt_id"]) for row in pair_attempts)
        attempts_by_arm = {row.get("arm"): row for row in pair_attempts}
        for internal_arm, report_arm in (("candidate", "md"), ("control", "no_md")):
            attempt = attempts_by_arm.get(internal_arm)
            if attempt is not None and _attempt_passes(attempt):
                correctness[report_arm]["passed"] += 1
            else:
                correctness[report_arm]["failed"] += 1
                if attempt is None:
                    failures.append({
                        "scope": "terminal planned outcome",
                        "attempt_id": None,
                        "task_id": scheduled["task_id"],
                        "repeat": scheduled["repeat"],
                        "arm": "MD" if internal_arm == "candidate" else "No-MD",
                        "mechanical_reason_code": "missing_terminal_attempt",
                        "reason": "terminal pair has no attempt for this planned arm",
                        "termination_class": "missing_terminal_attempt",
                    })
        if reasons:
            exclusion_details[scheduled["task_id"]].append({
                "repeat": scheduled["repeat"],
                "root_pair_id": root_pair_id,
                "reasons": reasons,
            })
        else:
            selected[scheduled["task_id"]].append({**dict(pair), "attempts": pair_attempts})

    for task_pairs in selected.values():
        task_pairs.sort(key=lambda row: int(row["repeat_id"]))
    eligible_task_ids = [
        task_id for task_id in TASK_IDS
        if len(selected[task_id]) == REPEATS and not exclusion_details[task_id]
    ]
    exclusions = [
        {
            "task_id": task_id,
            "usable_pair_count": len(selected[task_id]),
        }
        for task_id in TASK_IDS
        if task_id not in eligible_task_ids
    ]
    failures.sort(key=lambda row: (
        str(row["task_id"]), int(row["repeat"] or 0), str(row["arm"]),
        str(row["attempt_id"]), str(row["scope"]),
    ))
    endpoints = {
        "wall": _endpoint(
            "wall", eligible_task_ids, selected,
            lambda row: row.get("subject_wall_seconds"),
        ),
        "token": _endpoint(
            "token", eligible_task_ids, selected,
            lambda row: row.get("uncached_input_plus_output_token_proxy"),
        ),
    }
    return {
        "schema_version": "starlette-product-a-analysis-v1",
        "analysis_freeze_sha256": _digest_bytes(_canonical_bytes(ANALYSIS_FREEZE)),
        "correctness": correctness,
        "failures": failures,
        "raw_failure_count": sum(row["scope"] == "raw invocation" for row in failures),
        "eligibility": {
            "rule": ANALYSIS_FREEZE["complete_task_rule"],
            "eligible_task_count": len(eligible_task_ids),
            "eligible_task_ids": eligible_task_ids,
            "excluded_task_count": len(exclusions),
            "exclusions": exclusions,
            "exclusion_details": [
                {"task_id": row["task_id"], "details": exclusion_details[row["task_id"]]}
                for row in exclusions
            ],
        },
        "endpoints": endpoints,
    }


def _execute(
    output: Path,
    request: Mapping[str, Any],
    executor: Callable[[atomic.AttemptContext], Mapping[str, Any]],
    preflight_result: Mapping[str, Any],
    request_sha: str,
    approval_sha: str,
    *,
    execution_mode: str,
) -> dict[str, Any]:
    """Execute the fixed queue and durably preserve every record."""

    schedule = request["schedule"]
    historical._validate_schedule(schedule)
    _require(not output.exists() and not output.is_symlink(), "execution evidence already exists")
    atomic._exclusive_run_directory(output)
    started = time.monotonic()
    schedule_sha = _write_json_once(output / "schedule.json", schedule)
    preflight_sha = _write_json_once(output / "preflight.json", dict(preflight_result))
    seal = {
        "schema_version": "starlette-product-a-run-seal-v1",
        "run_id": request["run_id"],
        "execution_mode": execution_mode,
        "request_sha256": request_sha,
        "approval_sha256": approval_sha,
        "consumed_approval_sha256": sha256_file(
            output.parent / CONSUMED_APPROVAL_FILENAME
        ),
        "schedule_sha256": schedule_sha,
        "preflight_sha256": preflight_sha,
        "runner_sha256": request["component_sha256"]["product_a_runner_and_reporter"],
        "planned_scientific_calls": PLANNED_CALLS,
        "max_subject_invocations": MAX_SUBJECT_INVOCATIONS,
        "worker_count": WORKERS,
        "replacement_pair_limit": REPLACEMENT_PAIR_LIMIT,
        "analysis_freeze_sha256": _digest_bytes(_canonical_bytes(ANALYSIS_FREEZE)),
    }
    seal_sha = _write_json_once(output / "run-seal.json", seal)
    attempts = atomic._DurableJsonl(output / "attempts.jsonl")
    pairs = atomic._DurableJsonl(output / "pairs.jsonl")
    events = atomic._DurableJsonl(output / "scheduler-events.jsonl")
    telemetry = atomic._Telemetry(events, seal_sha)
    concurrency = atomic._ExecutorConcurrency()
    scheduler = atomic._Scheduler(
        historical._jobs(schedule), telemetry, REPLACEMENT_PAIR_LIMIT, live_policy=True,
    )
    failures: list[BaseException] = []
    failure_lock = threading.Lock()

    def guarded_executor(context: atomic.AttemptContext) -> Mapping[str, Any]:
        raw = dict(executor(context))
        if raw.get("termination_class") == atomic.REPLACEABLE_INFRASTRUCTURE_FAILURE:
            classified = atomic.classify_termination(
                atomic.REPLACEABLE_INFRASTRUCTURE_FAILURE,
                mechanical_reason_code=raw.get("mechanical_reason_code"),
                resolved=raw.get("resolved"),
                usable_subject_output=raw.get("usable_subject_output"),
                subject_workspace_changed=raw.get("subject_workspace_changed"),
            )
            authorized = (
                classified["mechanical_reason_code"] in REPLACEMENT_REASON_CODES
                and classified["usable_subject_output"] is False
                and classified["subject_workspace_changed"] is False
            )
            if not authorized:
                raw.update(atomic.classify_termination(
                    atomic.UNCLASSIFIED_ABNORMAL_TERMINATION,
                    mechanical_reason_code="unauthorized_replacement_proposal",
                ))
            else:
                raw.update(classified)
        return raw

    def worker(index: int) -> None:
        worker_id = f"worker-{index:02d}"
        try:
            telemetry.emit("worker_started", worker_id=worker_id)
            while True:
                job = scheduler.claim(worker_id)
                if job is None:
                    return
                replacement_job = None
                try:
                    replacement_job = atomic._execute_pair(
                        attempt_writer=attempts,
                        executor=guarded_executor,
                        executor_concurrency=concurrency,
                        first_wave_barrier=None,
                        job=job,
                        pair_writer=pairs,
                        run_dir=output,
                        run_seal_sha256=seal_sha,
                        scheduler=scheduler,
                        telemetry=telemetry,
                        use_first_wave_barrier=False,
                        worker_id=worker_id,
                        # The injected seam emulates the exact live record path.
                        # It remains unreachable from the CLI.
                        live_mode=True,
                    )
                finally:
                    scheduler.finish(job, worker_id, replacement_job)
        except BaseException as exc:
            with failure_lock:
                failures.append(exc)
            scheduler.abort()
            try:
                telemetry.emit(
                    "worker_failed", error_type=type(exc).__name__, worker_id=worker_id,
                )
            except BaseException:
                pass
        finally:
            try:
                telemetry.emit("worker_stopped", worker_id=worker_id)
            except BaseException:
                pass

    threads = [
        threading.Thread(
            target=worker,
            args=(index,),
            name=f"starlette-product-a-worker-{index:02d}",
        )
        for index in range(1, WORKERS + 1)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    attempts.close()
    pairs.close()
    events.close()
    if failures:
        raise ProductAError(
            "worker failure(s): " + ", ".join(type(failure).__name__ for failure in failures)
        ) from failures[0]

    attempt_rows = attempts.records
    pair_rows = pairs.records
    event_rows = events.records
    base_rows = [row for row in pair_rows if row["replacement_generation"] == 0]
    replacements = [row for row in pair_rows if row["replacement_generation"] == 1]
    _require(len(base_rows) == PAIR_COUNT, "base pair execution is incomplete")
    actual_subjects = sum(row["subject_invocation_started"] is True for row in attempt_rows)
    _require(
        len(attempt_rows) <= MAX_SUBJECT_INVOCATIONS
        and actual_subjects <= MAX_SUBJECT_INVOCATIONS
        and len(replacements) <= REPLACEMENT_PAIR_LIMIT,
        "approved invocation or replacement cap exceeded",
    )
    workspace_hashes = {
        path.relative_to(output).as_posix(): sha256_file(path)
        for path in sorted((output / "workspaces").rglob("*"))
        if path.is_file() and not path.is_symlink()
    }
    analysis = build_analysis(request, attempt_rows, pair_rows)
    analysis_sha = _write_json_once(output / "analysis.json", analysis)
    manifest = {
        "schema_version": "starlette-eighteen-two-repeat-execution-v1",
        "product_a_schema_version": "starlette-product-a-execution-v1",
        "status": "complete",
        "execution_mode": execution_mode,
        "planned_pairs": PAIR_COUNT,
        "planned_scientific_calls": PLANNED_CALLS,
        "max_subject_invocations": MAX_SUBJECT_INVOCATIONS,
        "base_pair_count": len(base_rows),
        "replacement_pair_count": len(replacements),
        "pair_record_count": len(pair_rows),
        "actual_attempt_records": len(attempt_rows),
        "actual_subject_invocations": actual_subjects,
        "observed_peak_active_subjects": telemetry.peak_active_subjects,
        "observed_peak_executor_calls": concurrency.peak,
        "worker_count": WORKERS,
        "same_task_overlap_count": 0,
        "duration_seconds": time.monotonic() - started,
        "run_seal_sha256": seal_sha,
        "attempts_sha256": sha256_file(output / "attempts.jsonl"),
        "pairs_sha256": sha256_file(output / "pairs.jsonl"),
        "scheduler_events_sha256": sha256_file(output / "scheduler-events.jsonl"),
        "analysis_sha256": analysis_sha,
        "workspace_evidence_sha256": workspace_hashes,
    }
    _write_json_once(output / "execution-manifest.json", manifest)
    historical._verify_records(schedule, manifest, attempt_rows, pair_rows, event_rows)
    return manifest


def run_approved(
    run_dir: Path,
    *,
    repo: Path = ROOT,
    preflight: Callable[[Mapping[str, Any]], Mapping[str, Any]] | None = None,
    executor: Callable[[atomic.AttemptContext], Mapping[str, Any]] | None = None,
    allowed_runs_root: Path | None = None,
) -> dict[str, Any]:
    """Consume one approval, then run exactly one fresh Product A campaign.

    ``preflight`` and ``executor`` are an offline-only test seam.  They must be
    supplied together, and the CLI never exposes them.
    """

    run_dir = run_dir.absolute()
    _validate_run_boundary(run_dir, allowed_runs_root or run_dir.parent)
    boundary_request = _read_json(run_dir / REQUEST_FILENAME)
    allowed_root = _bound_runs_root(run_dir, boundary_request, allowed_runs_root)
    run_dir = _validate_run_boundary(run_dir, allowed_root)
    approval, approval_sha = _consume_approval(run_dir)  # irrevocable first boundary
    _validate_run_boundary(run_dir, allowed_root)
    repo = repo.absolute()
    request_path = run_dir / REQUEST_FILENAME
    request_raw = request_path.read_bytes()
    try:
        request = json.loads(request_raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProductAError("REQUEST.json is malformed") from exc
    _require(isinstance(request, dict) and request_raw == _canonical_bytes(request),
             "REQUEST.json is noncanonical")
    _require(request == boundary_request, "REQUEST.json changed at the approval boundary")
    _require(_bound_runs_root(run_dir, request, allowed_runs_root) == allowed_root,
             "request runs root changed at the approval boundary")
    request_sha = _digest_bytes(request_raw)
    _require(approval == {"request_sha256": request_sha}, "approval hash mismatch")
    _validate_request(repo, run_dir, request)
    _require((preflight is None) == (executor is None),
             "offline preflight and executor must be injected together")
    output = run_dir / EVIDENCE_DIRECTORY
    _require(not output.exists() and not output.is_symlink(), "execution evidence already exists")
    inner_request = _execution_request(repo, request["run_id"])
    _require(
        _digest_bytes(_canonical_bytes(inner_request)) ==
        request["sealed_attempt_request_sha256"],
        "sealed attempt request changed",
    )
    _require(request_path.read_bytes() == request_raw, "REQUEST.json changed after approval consumption")
    _validate_run_boundary(run_dir, allowed_root)

    previous_spec = sealed.SPEC
    sealed.SPEC = repo / SPEC_PATH
    try:
        if preflight is not None:
            preflight_result = dict(preflight(request))
            backend = executor
            execution_mode = "offline_fake"
        else:
            with demo_task_registry():
                preflight_result = run_batch.preflight_request(
                    inner_request, deadline_seconds=PREFLIGHT_DEADLINE_SECONDS,
                )
            backend = None
            execution_mode = "live_approved"
        _require(preflight_result.get("status") == "PASS",
                 f"launch runtime preflight failed: {preflight_result.get('failed_checks')}")
        _require(set(preflight_result.get("seals", {})) == set(TASK_IDS),
                 "launch runtime preflight seals are incomplete")
        _require(request_path.read_bytes() == request_raw,
                 "REQUEST.json changed between preflight and execution")
        _validate_run_boundary(run_dir, allowed_root)
        if backend is None:
            with demo_task_registry():
                backend = live.AtomicLiveBackend(
                    live.RunBatchBackend(repo, output, inner_request, preflight_result["seals"]),
                    request_sha,
                )
        assert backend is not None
        with demo_task_registry():
            return _execute(
                output,
                request,
                backend,
                preflight_result,
                request_sha,
                approval_sha,
                execution_mode=execution_mode,
            )
    finally:
        sealed.SPEC = previous_spec


def _verify_workspace_evidence(
    repo: Path,
    output: Path,
    request: Mapping[str, Any],
    preflight_result: Mapping[str, Any],
    attempts: Sequence[Mapping[str, Any]],
    *,
    execution_mode: str,
    request_sha: str,
) -> None:
    inner_request = _execution_request(repo, str(request["run_id"]))
    for row in attempts:
        workspace = output / str(row["workspace_path"])
        _require(workspace.is_dir() and not workspace.is_symlink(),
                 f"attempt workspace is missing: {row['attempt_id']}")
        stub = _read_json(workspace / "stub-evidence.json")
        expected_outcome = row["termination_class"]
        if (
            row["arm_index"] == 2
            and row["termination_class"] == atomic.LATE_INFRASTRUCTURE_FAILURE
            and row["mechanical_reason_code"] == "infrastructure_failure_after_prior_arm"
        ):
            expected_outcome = atomic.REPLACEABLE_INFRASTRUCTURE_FAILURE

        if execution_mode == "offline_fake":
            _require(
                stub == {
                    "attempt_id": row["attempt_id"],
                    "mode": "offline_stub",
                    "outcome": expected_outcome,
                    "synthetic": True,
                },
                f"offline fake evidence differs: {row['attempt_id']}",
            )
            _require(
                {path.name for path in workspace.iterdir()} == {"stub-evidence.json"},
                f"offline fake workspace inventory differs: {row['attempt_id']}",
            )
            continue

        _require(execution_mode == "live_approved", "unsupported execution mode")
        _require(
            stub == {
                "attempt_id": row["attempt_id"],
                "mode": "live_approved",
                "outcome": expected_outcome,
                "request_sha256": request_sha,
                "synthetic": False,
            },
            f"live adapter evidence differs: {row['attempt_id']}",
        )
        ordinal = 2 * int(row["replacement_generation"]) + int(row["arm_index"])
        attempt_dir = workspace / str(row["task_id"]) / str(row["arm"]) / f"attempt-{ordinal}"
        manifest_path = attempt_dir / "attempt-manifest.json"
        if not manifest_path.is_file():
            _require(
                row["normal_terminal_record"] is False
                and row["termination_class"] in {
                    atomic.REPLACEABLE_INFRASTRUCTURE_FAILURE,
                    atomic.LATE_INFRASTRUCTURE_FAILURE,
                    atomic.UNCLASSIFIED_ABNORMAL_TERMINATION,
                }
                and not (workspace / "evidence-ledger.jsonl").exists(),
                f"normal or unanchored attempt lacks finalized evidence: {row['attempt_id']}",
            )
            continue
        with demo_task_registry():
            run_batch._verify_attempts(workspace, allow_dispositions=False)
        adapted = live.RunBatchBackend._adapt_attempt(
            None,
            str(row["task_id"]),
            str(row["arm"]),
            ordinal,
            workspace,
            True,
            bool(row["subject_invocation_started"]),
        )
        for key, value in adapted.items():
            if key == "duration_seconds":
                _require(row["subject_duration_seconds"] == value,
                         f"subject duration differs: {row['attempt_id']}")
            elif key == "token_components":
                _require(row["token_components"] == value,
                         f"token evidence differs: {row['attempt_id']}")
            else:
                _require(row.get(key) == value,
                         f"attempt summary differs: {row['attempt_id']}:{key}")
        expected_seal = preflight_result["seals"][row["task_id"]]
        _require(
            all(
                run_batch._json(attempt_dir / name).get("container_preflight") == expected_seal
                for name in ("intent.json", "launch.json", "result.json")
            ),
            f"preflight seal echo differs: {row['attempt_id']}",
        )
        raw_result = run_batch._json(attempt_dir / "result.json")
        run_batch._verify_event_evidence(attempt_dir, raw_result, hardened=True)
        _require(run_batch._container_echo(attempt_dir, inner_request),
                 f"container evidence differs: {row['attempt_id']}")


def _verify_evidence(
    repo: Path,
    run_dir: Path,
    *,
    allowed_runs_root: Path | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    _validate_run_boundary(run_dir, allowed_runs_root or run_dir.parent)
    request_path = run_dir / REQUEST_FILENAME
    request_raw = request_path.read_bytes()
    request = _read_json(request_path)
    allowed_root = _bound_runs_root(run_dir, request, allowed_runs_root)
    run_dir = _validate_run_boundary(run_dir, allowed_root)
    _require(request_raw == _canonical_bytes(request), "REQUEST.json is noncanonical")
    request_sha = _digest_bytes(request_raw)
    _validate_request(repo, run_dir, request)
    approval = _read_json(run_dir / APPROVAL_FILENAME)
    approval_sha = sha256_file(run_dir / APPROVAL_FILENAME)
    _require(approval == {"request_sha256": request_sha}, "preserved approval hash mismatch")
    consumed = _read_json(run_dir / CONSUMED_APPROVAL_FILENAME)
    _require(consumed == {
        "schema_version": "starlette-product-a-consumed-approval-v1",
        "approval_sha256": approval_sha,
        "request_sha256": request_sha,
    }, "consumed approval binding differs")

    output = run_dir / EVIDENCE_DIRECTORY
    _require(output.is_dir() and not output.is_symlink(), "execution evidence is missing or unsafe")
    workspaces_root = output / "workspaces"
    _require(
        workspaces_root.is_dir()
        and not workspaces_root.is_symlink()
        and workspaces_root.resolve() == workspaces_root,
        "attempt workspace evidence root is missing, indirect, or unsafe",
    )
    expected_names = {
        "schedule.json",
        "preflight.json",
        "run-seal.json",
        "attempts.jsonl",
        "pairs.jsonl",
        "scheduler-events.jsonl",
        "analysis.json",
        "execution-manifest.json",
        "workspaces",
    }
    _require({path.name for path in output.iterdir()} == expected_names,
             "execution evidence inventory differs")
    for name in expected_names - {"workspaces"}:
        evidence_file = output / name
        _require(
            evidence_file.is_file()
            and not evidence_file.is_symlink()
            and evidence_file.resolve() == evidence_file,
            f"execution evidence file is missing, indirect, or unsafe: {name}",
        )
    workspace_entries = list(workspaces_root.rglob("*"))
    _require(
        all(not path.is_symlink() for path in workspace_entries),
        "attempt workspace evidence contains a symbolic link",
    )
    schedule = _read_json(output / "schedule.json")
    preflight_result = _read_json(output / "preflight.json")
    seal = _read_json(output / "run-seal.json")
    manifest = _read_json(output / "execution-manifest.json")
    analysis = _read_json(output / "analysis.json")
    attempts = _read_jsonl(output / "attempts.jsonl")
    pairs = _read_jsonl(output / "pairs.jsonl")
    events = _read_jsonl(output / "scheduler-events.jsonl")
    _validate_attempt_telemetry(attempts)
    _require(schedule == request["schedule"], "schedule differs from the approved request")
    _require(preflight_result.get("status") == "PASS" and
             set(preflight_result.get("seals", {})) == set(TASK_IDS),
             "preserved preflight is incomplete")
    execution_mode = manifest.get("execution_mode")
    _require(execution_mode in {"live_approved", "offline_fake"},
             "execution mode is invalid")
    _require(manifest.get("product_a_schema_version") == "starlette-product-a-execution-v1",
             "Product A execution manifest schema is invalid")
    expected_seal = {
        "schema_version": "starlette-product-a-run-seal-v1",
        "run_id": request["run_id"],
        "execution_mode": execution_mode,
        "request_sha256": request_sha,
        "approval_sha256": approval_sha,
        "consumed_approval_sha256": sha256_file(run_dir / CONSUMED_APPROVAL_FILENAME),
        "schedule_sha256": sha256_file(output / "schedule.json"),
        "preflight_sha256": sha256_file(output / "preflight.json"),
        "runner_sha256": request["component_sha256"]["product_a_runner_and_reporter"],
        "planned_scientific_calls": PLANNED_CALLS,
        "max_subject_invocations": MAX_SUBJECT_INVOCATIONS,
        "worker_count": WORKERS,
        "replacement_pair_limit": REPLACEMENT_PAIR_LIMIT,
        "analysis_freeze_sha256": _digest_bytes(_canonical_bytes(ANALYSIS_FREEZE)),
    }
    _require(seal == expected_seal, "run seal binding differs")
    _require(
        manifest.get("run_seal_sha256") == sha256_file(output / "run-seal.json")
        and manifest.get("attempts_sha256") == sha256_file(output / "attempts.jsonl")
        and manifest.get("pairs_sha256") == sha256_file(output / "pairs.jsonl")
        and manifest.get("scheduler_events_sha256") ==
            sha256_file(output / "scheduler-events.jsonl")
        and manifest.get("analysis_sha256") == sha256_file(output / "analysis.json"),
        "execution evidence hash changed",
    )
    workspace_hashes = {
        path.relative_to(output).as_posix(): sha256_file(path)
        for path in sorted(workspace_entries)
        if path.is_file()
    }
    _require(manifest.get("workspace_evidence_sha256") == workspace_hashes,
             "workspace evidence changed")
    historical._verify_records(schedule, manifest, attempts, pairs, events)
    recomputed = build_analysis(request, attempts, pairs)
    _require(analysis == recomputed and
             (output / "analysis.json").read_bytes() == _canonical_bytes(recomputed),
             "analysis differs from the frozen complete-task policy")
    _verify_workspace_evidence(
        repo,
        output,
        request,
        preflight_result,
        attempts,
        execution_mode=str(execution_mode),
        request_sha=request_sha,
    )
    return manifest, analysis


def _markdown_cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def render_report(analysis: Mapping[str, Any]) -> str:
    """Render a correctness-first report without ambiguous result labels."""

    correctness = analysis["correctness"]
    md = correctness["md"]
    no_md = correctness["no_md"]
    lines = [
        f"MD: **{md['failed']}/36 failed; {md['passed']}/36 passed.**",
        "",
        f"No-MD: **{no_md['failed']}/36 failed; {no_md['passed']}/36 passed.**",
        "",
        "# Product A: fresh Starlette MD versus No-MD report",
        "",
        "## Failures",
        "",
    ]
    failures = analysis["failures"]
    if failures:
        lines.extend([
            "| Scope | Attempt | Task | Repeat | Arm | Reason | Mechanical code | Termination |",
            "|---|---|---|---:|---|---|---|---|",
        ])
        for failure in failures:
            lines.append(
                f"| {_markdown_cell(failure['scope'])} | "
                f"{_markdown_cell(failure['attempt_id'] or '—')} | "
                f"{_markdown_cell(failure['task_id'])} | "
                f"{_markdown_cell(failure['repeat'])} | "
                f"{_markdown_cell(failure['arm'])} | "
                f"{_markdown_cell(failure['reason'])} | "
                f"{_markdown_cell(failure['mechanical_reason_code'])} | "
                f"{_markdown_cell(failure['termination_class'])} |"
            )
    else:
        lines.append("None.")

    eligibility = analysis["eligibility"]
    lines.extend([
        "",
        "## Eligible complete tasks",
        "",
        f"Eligible task count: **{eligibility['eligible_task_count']}/18**.",
        "",
        "A task contributes only when both paired repeats pass jointly for MD and No-MD; "
        "a lone surviving repeat is never analyzed.",
        "",
        "### Exclusions",
        "",
    ])
    if eligibility["exclusions"]:
        details_by_task = {
            row["task_id"]: row["details"]
            for row in eligibility["exclusion_details"]
        }
        lines.extend([
            "| Task | Usable paired repeats | Reasons |",
            "|---|---:|---|",
        ])
        for exclusion in eligibility["exclusions"]:
            details = details_by_task[exclusion["task_id"]]
            reason_text = "; ".join(
                f"repeat {detail['repeat']}: {', '.join(detail['reasons'])}"
                for detail in details
            )
            lines.append(
                f"| {_markdown_cell(exclusion['task_id'])} | "
                f"{exclusion['usable_pair_count']}/2 | {_markdown_cell(reason_text)} |"
            )
    else:
        lines.append("None.")

    lines.extend([
        "",
        "## Complete-task inference",
        "",
        "Negative resource change favors MD.",
        "",
        "| Endpoint | Eligible tasks | Effect (MD vs No-MD) | 95% change CI | "
        "Two-sided p | Classification |",
        "|---|---:|---:|---:|---:|---|",
    ])
    for endpoint_name in ("wall", "token"):
        endpoint = analysis["endpoints"][endpoint_name]
        if endpoint["classification"] == "not estimable":
            effect_text = "not estimable"
            ci_text = "not estimable"
            p_text = "not estimable"
        else:
            effect_text = f"{endpoint['change_percent']:+.4f}%"
            change_ci = endpoint["confidence_interval_95_change_percent"]
            ci_text = f"{change_ci[0]:+.4f}%–{change_ci[1]:+.4f}%"
            p_text = f"{endpoint['p_value_two_sided']:.8g}"
        lines.append(
            f"| {endpoint_name.title()} | {endpoint['task_count']} | {effect_text} | "
            f"{ci_text} | {p_text} | **{endpoint['classification']}** |"
        )
    return "\n".join(lines) + "\n"


def verify_and_report(
    run_dir: Path,
    *,
    repo: Path = ROOT,
    allowed_runs_root: Path | None = None,
) -> dict[str, Any]:
    """Verify all preserved evidence, recompute analysis, and write REPORT.md once."""

    run_dir = run_dir.absolute()
    repo = repo.absolute()
    manifest, analysis = _verify_evidence(
        repo, run_dir, allowed_runs_root=allowed_runs_root,
    )
    report_path = run_dir / REPORT_FILENAME
    _require(not report_path.exists() and not report_path.is_symlink(), "report already exists")
    rendered = render_report(analysis)
    try:
        atomic._write_bytes_once(report_path, rendered.encode("utf-8"))
    except FileExistsError as exc:
        raise ProductAError("report already exists") from exc
    return {
        "run_directory": str(run_dir),
        "evidence_directory": str(run_dir / EVIDENCE_DIRECTORY),
        "report": str(report_path),
        "report_sha256": _digest_bytes(rendered.encode("utf-8")),
        "eligible_task_count": analysis["eligibility"]["eligible_task_count"],
        "md_passed": analysis["correctness"]["md"]["passed"],
        "md_failed": analysis["correctness"]["md"]["failed"],
        "no_md_passed": analysis["correctness"]["no_md"]["passed"],
        "no_md_failed": analysis["correctness"]["no_md"]["failed"],
        "subject_invocations": manifest["actual_subject_invocations"],
    }


def _cli_run_directory(value: str) -> Path:
    path = Path(value).absolute()
    expected_parent = RUNS_ROOT.absolute()
    if (
        not expected_parent.is_dir()
        or expected_parent.is_symlink()
        or expected_parent.resolve() != expected_parent
        or path.parent != expected_parent
        or path.is_symlink()
        or not path.is_dir()
        or path.resolve() != path
    ):
        raise argparse.ArgumentTypeError(
            f"run directory must be an existing direct child of {expected_parent}"
        )
    return path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("prepare", help="create a unique fixed Product A request")
    approve_parser = commands.add_parser("approve", help="approve one exact request hash")
    approve_parser.add_argument("run_directory", type=_cli_run_directory)
    approve_parser.add_argument("request_sha256")
    run_parser = commands.add_parser("run", help="consume approval and run the fixed live experiment")
    run_parser.add_argument("run_directory", type=_cli_run_directory)
    verify_parser = commands.add_parser(
        "verify-report", help="verify evidence and write the fixed Markdown report once",
    )
    verify_parser.add_argument("run_directory", type=_cli_run_directory)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "prepare":
            result = prepare()
        elif args.command == "approve":
            result = approve(
                args.run_directory,
                args.request_sha256,
                allowed_runs_root=RUNS_ROOT,
            )
        elif args.command == "run":
            result = run_approved(args.run_directory, allowed_runs_root=RUNS_ROOT)
        else:
            result = verify_and_report(args.run_directory, allowed_runs_root=RUNS_ROOT)
    except (
        ProductAError,
        atomic.EvidenceError,
        live.ShakeoutError,
        run_batch.BatchError,
        taskcheck.TaskError,
        OSError,
        ValueError,
        KeyError,
        TypeError,
        json.JSONDecodeError,
    ) as exc:
        print(f"ERROR: {exc}")
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
