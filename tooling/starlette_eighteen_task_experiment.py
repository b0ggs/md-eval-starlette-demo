#!/usr/bin/env python3
"""Approval-gated 18-task, two-repeat Starlette MD/no-MD experiment."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import math
import random
from pathlib import Path
import statistics
import threading
import time
from typing import Any, Callable, Mapping, Sequence

from mdseval.config import RunnerConfig
from mdseval.hashing import sha256_file
from scripts import run_batch
from scripts.contain import runtime as sealed
from tooling import starlette_atomic_pairs as atomic
from tooling import analyze_starlette_atomic_pairs as frozen_analysis
from tooling import starlette_live_shakeout as live
from tooling import taskcheck


ROOT = Path(__file__).resolve().parents[1]
BATCH_ID = "starlette-eighteen-two-repeat-v2"
BATCH_PATH = f"runs/dev-v2/{BATCH_ID}"
OUTPUT_PATH = f"{BATCH_PATH}/live-evidence"
SPEC_PATH = "runs/dev-v2/starlette-eighteen-two-repeat-v1-contamination-spec.json"
TASK_IDS = (
    "full-starlette-websocket-denial",
    "confirm-starlette-cors-origin",
    "confirm-starlette-state-mapping",
    "confirm-starlette-cors-private-network",
    "confirm-starlette-exception-context",
    "confirm-starlette-uploadfile-rollover",
    "confirm-starlette-background-exception",
    "confirm-starlette-http-disconnect",
    "confirm-starlette-session-tracking",
    "confirm-starlette-range-crlf",
    "confirm-starlette-gzip-vary",
    "confirm-starlette-malformed-host",
    "confirm-starlette-ws-disconnected",
    "confirm-starlette-debug-extension",
    "confirm-starlette-suffix-range",
    "confirm-starlette-form-context-cleanup",
    "confirm-starlette-staticfiles-weak-etag",
    "confirm-starlette-root-path-boundary",
)
ARM_PATHS = {
    "md": "controls/coder/evidence-bounded-v1.md",
    "no-md": "controls/coder/null-m2.md",
}
ARM_HASHES = {
    "md": "c0d56e29ade34c24278b976e84b29e47324c11a23399ca882239daffc9762c74",
    "no-md": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}
_OLD_IMAGE = "sha256:391377b4628f194db028967f7c1e056edae72f89f3d68218057abcb3590a374d"
_SESSION_IMAGE = "sha256:4d8c0d0da2ec20b961fd53b8d95b33e9bbf3deb715f1f421f0e016b6616c4e02"
_NEW_IMAGE = "sha256:c07e0026afa34f3e9e2e47d60aa3653715c6f53a8fe5342a34582af1f047f9fe"
IMAGE_DIGESTS = {
    **{task: _OLD_IMAGE for task in TASK_IDS[:11]},
    **{task: _NEW_IMAGE for task in TASK_IDS[11:]},
    "confirm-starlette-session-tracking": _SESSION_IMAGE,
}
INTERPRETER_PINS = {task: "3.11.5" for task in TASK_IDS}
SEED = "starlette-eighteen-two-repeat-v1-schedule"
WORKERS = 12
REPEATS = 2
PAIR_COUNT = 36
PLANNED_CALLS = 72
REPLACEMENT_PAIR_LIMIT = 4
MAX_SUBJECT_INVOCATIONS = 80
PREFLIGHT_DEADLINE_SECONDS = 120
REPLACEMENT_REASON_CODES = tuple(live.REASON_CODES)
RUNNER = RunnerConfig(
    "codex-cli", "gpt-5.6-sol", "high", "workspace-write", "never",
    False, True, False, 900, 1,
)
COMPONENTS = {
    "experiment_runner": "tooling/starlette_eighteen_task_experiment.py",
    "sealed_attempt": "scripts/run_batch.py",
    "live_adapter": "tooling/starlette_live_shakeout.py",
    "containment": "scripts/contain/runtime.py",
    "codex_adapter": "src/mdseval/runner/codex_cli.py",
    "capture": "src/mdseval/capture.py",
    "subject_wrapper": "tooling/prompts/subject-wrapper-v1.txt",
    "termination_classifier": "tooling/starlette_atomic_pairs.py",
    "statistical_primitives": "tooling/analyze_starlette_atomic_pairs.py",
    "task_admission": "tooling/taskcheck.py",
}
ANALYSIS_FREEZE = {
    "report_correctness_first": True,
    "correctness_gate": "resolved candidate attempts >= resolved control attempts",
    "wall_endpoint": "subject_end_monotonic - subject_start_monotonic",
    "token_endpoint": "input_tokens - cached_input_tokens + output_tokens",
    "common_pair_rule": "each task requires two pairs with both arms normal and resolved; otherwise that endpoint is inconclusive",
    "task_effect": "log(arithmetic mean candidate / arithmetic mean control)",
    "task_weighting": "equal weight over 18 tasks",
    "test": "two-sided one-sample t test of task effects; df=17; alpha=0.05",
    "interval": "two-sided model-based 95% Student-t confidence interval on mean task log ratio",
    "favorable_rule": "p < 0.05 and mean task log ratio < 0",
    "claims": "wall and token are separate; no multiplicity-adjusted joint claim",
    "post_outcome_method_choice_forbidden": True,
}


class ExperimentError(RuntimeError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ExperimentError(message)


_bytes, _write, _read = live._bytes, live._write, live._read


def build_schedule() -> dict[str, Any]:
    """Return the frozen balanced 18-task by two-repeat pair schedule."""
    rng = random.Random(SEED)
    assignment = list(TASK_IDS)
    rng.shuffle(assignment)
    md_first_r1 = set(assignment[: len(TASK_IDS) // 2])
    pairs: list[dict[str, Any]] = []
    for task_index, task in enumerate(TASK_IDS, 1):
        repeat_one_first = "md" if task in md_first_r1 else "no-md"
        for repeat in range(1, REPEATS + 1):
            first = repeat_one_first if repeat == 1 else (
                "no-md" if repeat_one_first == "md" else "md"
            )
            second = "no-md" if first == "md" else "md"
            pair_id = f"pair-{task_index:02d}-r{repeat}"
            pairs.append({
                "arm_order": [first, second],
                "first_arm": first,
                "pair_id": pair_id,
                "queue_position": 0,
                "repeat": repeat,
                "root_pair_id": pair_id,
                "second_arm": second,
                "task_id": task,
            })
    rng.shuffle(pairs)
    for position, pair in enumerate(pairs, 1):
        pair["queue_position"] = position
    return {
        "schema_version": "starlette-eighteen-two-repeat-schedule-v1",
        "randomization_seed": SEED,
        "task_ids": list(TASK_IDS),
        "task_count": len(TASK_IDS),
        "repeats_per_task": REPEATS,
        "worker_count": WORKERS,
        "planned_pairs": PAIR_COUNT,
        "planned_calls": PLANNED_CALLS,
        "inline_retry_limit": 0,
        "same_arm_relaunch_limit": 0,
        "replacement_generation_limit": 1,
        "replacement_pair_limit": REPLACEMENT_PAIR_LIMIT,
        "pairs": pairs,
    }


def _validate_schedule(schedule: Mapping[str, Any]) -> None:
    _require(dict(schedule) == build_schedule(), "schedule differs from the frozen deterministic plan")
    pairs = schedule["pairs"]
    _require(len(pairs) == PAIR_COUNT and len({row["pair_id"] for row in pairs}) == PAIR_COUNT,
             "schedule pair inventory is invalid")
    _require({row["queue_position"] for row in pairs} == set(range(1, PAIR_COUNT + 1)),
             "schedule queue positions are invalid")
    for repeat in range(1, REPEATS + 1):
        rows = [row for row in pairs if row["repeat"] == repeat]
        _require(len(rows) == len(TASK_IDS) and
                 sum(row["first_arm"] == "md" for row in rows) == len(TASK_IDS) // 2,
                 f"repeat {repeat} arm order is not balanced")
    for task in TASK_IDS:
        rows = sorted((row for row in pairs if row["task_id"] == task),
                      key=lambda row: row["repeat"])
        _require(len(rows) == REPEATS and rows[0]["first_arm"] != rows[1]["first_arm"],
                 f"task crossover is invalid: {task}")


def _exact_paths(repo: Path, batch: Path, output: Path, spec: Path) -> None:
    expected = (repo / BATCH_PATH, repo / OUTPUT_PATH, repo / SPEC_PATH)
    actual = (batch, output, spec)
    _require(repo.resolve() == ROOT and all(path.absolute() == wanted and path.resolve() == wanted
             and not path.is_symlink() for path, wanted in zip(actual, expected)),
             "experiment paths differ from the fixed sibling paths")


def _execution_request(repo: Path, spec: Path) -> dict[str, Any]:
    container = {
        "image_digests": dict(IMAGE_DIGESTS),
        "interpreter_pins": dict(INTERPRETER_PINS),
        "spec_sha256": sha256_file(spec),
        "web_search": "disabled",
    }
    return run_batch._request(
        BATCH_ID,
        [repo / "tasks" / task for task in TASK_IDS],
        [("candidate", repo / ARM_PATHS["md"]),
         ("control", repo / ARM_PATHS["no-md"])],
        task_order_seed=0,
        runner=RUNNER,
        container=container,
    )


def build_request(repo: Path, batch: Path, output: Path, spec: Path) -> dict[str, Any]:
    _exact_paths(repo, batch, output, spec)
    _require(spec.is_file(), "contamination specification is missing")
    try:
        spec_value = json.loads(spec.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ExperimentError("contamination specification is malformed") from exc
    _require(isinstance(spec_value, dict) and set(spec_value) == set(TASK_IDS),
             "contamination specification does not contain exactly 18 tasks")
    for arm, relative in ARM_PATHS.items():
        _require(sha256_file(repo / relative) == ARM_HASHES[arm], f"frozen arm changed: {arm}")
    schedule = build_schedule()
    _validate_schedule(schedule)
    execution = _execution_request(repo, spec)
    task_hashes = {row["id"]: row["manifest_sha256"] for row in execution["tasks"]}
    return {
        "schema_version": "starlette-eighteen-two-repeat-request-v1",
        "batch_id": BATCH_ID,
        "purpose": "finite-known-set development replication; not the frozen v7 confirmation",
        "attempt_inventory": "fresh attempts only; prior run outcomes and evidence are not reused",
        "batch_path": BATCH_PATH,
        "output_path": OUTPUT_PATH,
        "contamination_spec": {"path": SPEC_PATH, "sha256": sha256_file(spec)},
        "tasks": [{"task_id": task, "manifest_sha256": task_hashes[task]} for task in TASK_IDS],
        "arms": [{"name": arm, "path": ARM_PATHS[arm], "sha256": ARM_HASHES[arm]}
                 for arm in ("md", "no-md")],
        "execution_arm_mapping": {"md": "candidate", "no-md": "control"},
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
            "base_queue_must_be_fully_claimed_before_fallback_claim": True,
            "preflight_deadline_seconds": PREFLIGHT_DEADLINE_SECONDS,
            "subject_timeout_seconds": RUNNER.timeout_seconds,
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
            "second_arm_infrastructure_failure_is_late_and_nonreplaceable": True,
            "scientific_failures_never_retried": True,
            "unclassified_abnormal_terminations_never_retried": True,
            "replacement_pair_selection": "eligible roots by ascending frozen base queue position; first four only",
            "reason_codes": list(REPLACEMENT_REASON_CODES),
        },
        "analysis_freeze": dict(ANALYSIS_FREEZE),
        "runner": execution["runner"],
        "sealed_attempt_request_sha256": sha256(_bytes(execution)).hexdigest(),
        "component_sha256": {name: sha256_file(repo / path) for name, path in COMPONENTS.items()},
        "repository_state_sha256": {
            "task_ledger": sha256_file(repo / "tasks/ledger.jsonl"),
            "exposure_ledger": sha256_file(repo / "tasks/exposures.jsonl"),
        },
        "approval": {"required_before_any_launch_preflight_output_or_backend": True,
                     "path": f"{BATCH_PATH}/APPROVED.json",
                     "matching_hash_only": True,
                     "schema": {"request_sha256": "sha256_of_exact_REQUEST.json_bytes"}},
    }


def _validate_request(repo: Path, batch: Path, output: Path,
                      request: Mapping[str, Any]) -> None:
    try:
        spec = repo / str(request["contamination_spec"]["path"])
    except (KeyError, TypeError) as exc:
        raise ExperimentError("request paths are invalid") from exc
    expected = build_request(repo, batch, output, spec)
    _require(dict(request) == expected, "request binding changed")


def prepare(repo: Path, batch: Path, output: Path, spec: Path) -> Path:
    request = build_request(repo, batch, output, spec)
    _require(not batch.exists() and not output.exists(), "batch or output already exists")
    batch.mkdir(parents=True)
    _write(batch / "REQUEST.json", request)
    return batch / "REQUEST.json"


def verify_prepared(repo: Path, batch: Path, output: Path, *,
                    require_unapproved: bool = True) -> dict[str, Any]:
    request_path = batch / "REQUEST.json"
    _require(request_path.is_file() and not request_path.is_symlink(), "REQUEST.json is missing or unsafe")
    raw = request_path.read_bytes()
    request = json.loads(raw)
    _require(raw == _bytes(request), "REQUEST.json is noncanonical")
    _validate_request(repo, batch, output, request)
    if require_unapproved:
        _require(not (batch / "APPROVED.json").exists(), "prepared request is already approved")
    _require(not output.exists(), "execution output already exists")
    return {"request_sha256": sha256(raw).hexdigest(), "tasks": len(TASK_IDS),
            "atomic_pairs": PAIR_COUNT, "planned_scientific_calls": PLANNED_CALLS,
            "maximum_invocations": MAX_SUBJECT_INVOCATIONS, "live_model_calls": 0}


def _approved(batch: Path) -> tuple[dict[str, Any], str, str]:
    """Read and validate approval; callers must make this their first operation."""
    request_path, approval_path = batch / "REQUEST.json", batch / "APPROVED.json"
    request_raw, approval_raw = request_path.read_bytes(), approval_path.read_bytes()
    _require(not request_path.is_symlink() and not approval_path.is_symlink(),
             "approval inputs are symlinks")
    request, approval = json.loads(request_raw), json.loads(approval_raw)
    _require(request_raw == _bytes(request) and approval_raw == _bytes(approval),
             "approval inputs are noncanonical")
    request_sha, approval_sha = sha256(request_raw).hexdigest(), sha256(approval_raw).hexdigest()
    _require(approval == {"request_sha256": request_sha}, "approval hash mismatch")
    return request, request_sha, approval_sha


def _arm(label: str) -> str:
    try:
        return {"md": "candidate", "no-md": "control"}[label]
    except KeyError as exc:
        raise ExperimentError(f"unknown schedule arm: {label}") from exc


def _jobs(schedule: Mapping[str, Any]) -> list[atomic._PairJob]:
    first_by_task = {
        task: "".join("M" if row["first_arm"] == "md" else "N"
                      for row in sorted((item for item in schedule["pairs"]
                                         if item["task_id"] == task),
                                        key=lambda item: item["repeat"]))
        for task in TASK_IDS
    }
    now = time.monotonic()
    return [
        atomic._PairJob(
            arm_order="M" if row["first_arm"] == "md" else "N",
            enqueued_monotonic=now,
            first_arm=_arm(row["first_arm"]),
            pair_id=row["pair_id"],
            queue_position=row["queue_position"],
            repeat_id=row["repeat"],
            root_pair_id=row["root_pair_id"],
            second_arm=_arm(row["second_arm"]),
            sequence=first_by_task[row["task_id"]],
            task_id=row["task_id"],
        )
        for row in schedule["pairs"]
    ]


def _endpoint(name: str, selected: Mapping[str, Sequence[Mapping[str, Any]]],
              value: Callable[[Mapping[str, Any]], float | None]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for task in TASK_IDS:
        candidate: list[float] = []
        control: list[float] = []
        for pair in selected[task]:
            for attempt in pair["attempts"]:
                observed = value(attempt)
                if observed is None or not math.isfinite(observed) or observed <= 0:
                    return {"name": name, "status": "inconclusive",
                            "reason": "selected telemetry missing or nonpositive",
                            "task_id": task, "favorable_reduction": False}
                (candidate if attempt["arm"] == "candidate" else control).append(observed)
        if len(candidate) != REPEATS or len(control) != REPEATS:
            return {"name": name, "status": "inconclusive",
                    "reason": "selected arm inventory is incomplete", "task_id": task,
                    "favorable_reduction": False}
        candidate_mean, control_mean = statistics.mean(candidate), statistics.mean(control)
        rows.append({"task_id": task, "candidate_mean": candidate_mean,
                     "control_mean": control_mean,
                     "log_ratio": math.log(candidate_mean) - math.log(control_mean)})
    effects = [row["log_ratio"] for row in rows]
    mean_effect = statistics.mean(effects)
    sample_sd = statistics.stdev(effects)
    if sample_sd == 0:
        t_statistic: float | None = 0.0 if mean_effect == 0 else None
        p_value = 1.0 if mean_effect == 0 else 0.0
    else:
        t_statistic = mean_effect / (sample_sd / math.sqrt(len(effects)))
        p_value = frozen_analysis.student_t_two_sided_p(t_statistic, len(effects) - 1)
    standard_error = sample_sd / math.sqrt(len(effects))
    critical = frozen_analysis.student_t_quantile(0.975, len(effects) - 1)
    lower, upper = (mean_effect - critical * standard_error,
                    mean_effect + critical * standard_error)
    geometric_ratio = math.exp(mean_effect)
    return {"name": name, "status": "conclusive", "task_results": rows,
            "task_count": len(rows), "degrees_of_freedom": len(rows) - 1,
            "mean_task_log_ratio": mean_effect, "sample_standard_deviation": sample_sd,
            "t_statistic": t_statistic, "p_value_two_sided": p_value, "alpha": 0.05,
            "geometric_mean_ratio": geometric_ratio,
            "reduction_percent": (1.0 - geometric_ratio) * 100.0,
            "confidence_interval_95_log_ratio": [lower, upper],
            "confidence_interval_95_ratio": [math.exp(lower), math.exp(upper)],
            "favorable_reduction": p_value < 0.05 and mean_effect < 0}


def build_analysis(request: Mapping[str, Any], attempts: Sequence[Mapping[str, Any]],
                   pairs: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    by_attempt = {row["attempt_id"]: row for row in attempts}
    terminal: dict[str, Mapping[str, Any]] = {}
    for pair in sorted(pairs, key=lambda row: row["replacement_generation"]):
        terminal[pair["root_pair_id"]] = pair
    selected: dict[str, list[dict[str, Any]]] = {task: [] for task in TASK_IDS}
    resolved = {"candidate": 0, "control": 0}
    for pair_id in sorted(terminal):
        pair = terminal[pair_id]
        pair_attempts = [by_attempt[item] for item in pair["attempt_ids"]]
        for attempt in pair_attempts:
            if attempt["arm"] in resolved and attempt["resolved"] is True:
                resolved[attempt["arm"]] += 1
        usable = (pair["status"] == "complete" and len(pair_attempts) == 2 and
                  {row["arm"] for row in pair_attempts} == {"candidate", "control"} and
                  all(row["normal_terminal_record"] is True and row["valid"] is True and
                      row["resolved"] is True for row in pair_attempts))
        if usable:
            selected[pair["task_id"]].append({**pair, "attempts": pair_attempts})
    counts = {task: len(selected[task]) for task in TASK_IDS}
    insufficient = [{"task_id": task, "usable_pair_count": count}
                    for task, count in counts.items() if count != REPEATS]
    if insufficient:
        wall = {"name": "wall", "status": "inconclusive",
                "reason": "fewer than two jointly normal and resolved pairs for at least one task",
                "details": insufficient, "favorable_reduction": False}
        token = {**wall, "name": "token"}
    else:
        wall = _endpoint(
            "wall", selected,
            lambda row: float(row["subject_end_monotonic"] - row["subject_start_monotonic"]),
        )
        token = _endpoint(
            "token", selected,
            lambda row: row.get("uncached_input_plus_output_token_proxy"),
        )
    correctness_gate = resolved["candidate"] >= resolved["control"]
    return {
        "schema_version": "starlette-eighteen-two-repeat-analysis-v1",
        "analysis_freeze_sha256": sha256(_bytes(request.get("analysis_freeze", ANALYSIS_FREEZE))).hexdigest(),
        "finite_known_set_replication": True,
        "correctness": {"resolved_attempts": resolved,
                        "candidate_at_least_control": correctness_gate},
        "common_pair_selection": {"usable_pair_counts_by_task": counts,
                                  "all_tasks_have_two": not insufficient},
        "endpoints": {"wall": wall, "token": token},
        "claims": {"wall_favorable": correctness_gate and wall["favorable_reduction"],
                   "token_favorable": correctness_gate and token["favorable_reduction"],
                   "multiplicity_adjusted_joint_claim": False},
    }


def execute(output: Path, request: Mapping[str, Any],
            executor: Callable[[atomic.AttemptContext], Mapping[str, Any]],
            preflight: Mapping[str, Any], request_sha: str, approval_sha: str) -> dict[str, Any]:
    """Execute the frozen pair queue using the qualified atomic scheduling primitives."""
    schedule = request["schedule"]
    _validate_schedule(schedule)
    _require(not output.exists() and not output.is_symlink(), "execution output already exists")
    atomic._exclusive_run_directory(output)
    started = time.monotonic()
    schedule_sha = atomic._write_json_once(output / "schedule.json", schedule)
    preflight_sha = atomic._write_json_once(output / "preflight.json", dict(preflight))
    seal = {
        "schema_version": "starlette-eighteen-two-repeat-run-seal-v1",
        "request_sha256": request_sha,
        "approval_sha256": approval_sha,
        "schedule_sha256": schedule_sha,
        "preflight_sha256": preflight_sha,
        "runner_sha256": request["component_sha256"]["experiment_runner"],
        "planned_scientific_calls": PLANNED_CALLS,
        "max_subject_invocations": MAX_SUBJECT_INVOCATIONS,
        "worker_count": WORKERS,
        "replacement_pair_limit": REPLACEMENT_PAIR_LIMIT,
    }
    seal_sha = atomic._write_json_once(output / "run-seal.json", seal)
    attempts = atomic._DurableJsonl(output / "attempts.jsonl")
    pairs = atomic._DurableJsonl(output / "pairs.jsonl")
    events = atomic._DurableJsonl(output / "scheduler-events.jsonl")
    telemetry = atomic._Telemetry(events, seal_sha)
    concurrency = atomic._ExecutorConcurrency()
    scheduler = atomic._Scheduler(
        _jobs(schedule), telemetry, REPLACEMENT_PAIR_LIMIT, live_policy=True,
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
            authorized = (classified["mechanical_reason_code"] in REPLACEMENT_REASON_CODES and
                          classified["usable_subject_output"] is False and
                          classified["subject_workspace_changed"] is False)
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
                        live_mode=True,
                    )
                finally:
                    scheduler.finish(job, worker_id, replacement_job)
        except BaseException as exc:
            with failure_lock:
                failures.append(exc)
            scheduler.abort()
            try:
                telemetry.emit("worker_failed", error_type=type(exc).__name__, worker_id=worker_id)
            except BaseException:
                pass
        finally:
            try:
                telemetry.emit("worker_stopped", worker_id=worker_id)
            except BaseException:
                pass

    threads = [threading.Thread(target=worker, args=(index,),
                                name=f"starlette-18x2-worker-{index:02d}")
               for index in range(1, WORKERS + 1)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    attempts.close(); pairs.close(); events.close()
    if failures:
        raise ExperimentError("worker failure(s): " + ", ".join(
            type(failure).__name__ for failure in failures)) from failures[0]

    attempt_rows, pair_rows = attempts.records, pairs.records
    base_rows = [row for row in pair_rows if row["replacement_generation"] == 0]
    replacements = [row for row in pair_rows if row["replacement_generation"] == 1]
    _require(len(base_rows) == PAIR_COUNT, "base pair execution is incomplete")
    _require(len(attempt_rows) <= MAX_SUBJECT_INVOCATIONS and
             len(replacements) <= REPLACEMENT_PAIR_LIMIT,
             "approved invocation or replacement cap exceeded")
    actual_subjects = sum(row["subject_invocation_started"] is True for row in attempt_rows)
    _require(actual_subjects <= MAX_SUBJECT_INVOCATIONS, "subject invocation cap exceeded")
    workspace_hashes = {
        path.relative_to(output).as_posix(): sha256_file(path)
        for path in sorted((output / "workspaces").rglob("*"))
        if path.is_file() and not path.is_symlink()
    }
    manifest = {
        "schema_version": "starlette-eighteen-two-repeat-execution-v1",
        "status": "complete",
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
        "workspace_evidence_sha256": workspace_hashes,
    }
    analysis = build_analysis(request, attempt_rows, pair_rows)
    analysis_sha = atomic._write_json_once(output / "analysis.json", analysis)
    manifest["analysis_sha256"] = analysis_sha
    atomic._write_json_once(output / "execution-manifest.json", manifest)
    _verify_records(schedule, manifest, attempt_rows, pair_rows,
                    atomic._read_canonical_jsonl(output / "scheduler-events.jsonl"))
    return manifest


def _verify_records(schedule: Mapping[str, Any], manifest: Mapping[str, Any],
                    attempts: list[dict[str, Any]], pairs: list[dict[str, Any]],
                    events: list[dict[str, Any]]) -> None:
    _validate_schedule(schedule)
    planned = {row["pair_id"]: row for row in schedule["pairs"]}
    _require(len({row.get("pair_id") for row in pairs}) == len(pairs) and
             all(row.get("replacement_generation") in {0, 1} for row in pairs),
             "pair evidence contains a duplicate or unsupported generation")
    base = {row["pair_id"]: row for row in pairs if row.get("replacement_generation") == 0}
    replacements = [row for row in pairs if row.get("replacement_generation") == 1]
    _require(set(base) == set(planned) and len(base) == PAIR_COUNT,
             "base pair records differ from the schedule")
    attempts_by_pair: dict[str, list[dict[str, Any]]] = {}
    for attempt in attempts:
        attempts_by_pair.setdefault(str(attempt.get("pair_id")), []).append(attempt)
    _require(len({row.get("attempt_id") for row in attempts}) == len(attempts) and
             set(attempts_by_pair) == {row["pair_id"] for row in pairs} and
             sum(len(rows) for rows in attempts_by_pair.values()) == len(attempts),
             "attempt evidence contains an unknown or empty pair")
    for pair_id, scheduled in planned.items():
        row = base[pair_id]
        expected_arms = [_arm(name) for name in scheduled["arm_order"]]
        observed = sorted(attempts_by_pair.get(pair_id, []), key=lambda item: item["arm_index"])
        _require(row.get("task_id") == scheduled["task_id"] and
                 row.get("repeat_id") == scheduled["repeat"] and
                 row.get("queue_position") == scheduled["queue_position"] and
                 row.get("root_pair_id") == pair_id and row.get("worker_id") and
                 row.get("first_arm") == expected_arms[0] and
                 row.get("second_arm") == expected_arms[1] and
                 row.get("arm_order") == ("M" if scheduled["first_arm"] == "md" else "N") and
                 [item["arm"] for item in observed] == expected_arms[:len(observed)] and
                 row.get("attempt_ids") == [item["attempt_id"] for item in observed] and
                 row.get("termination_classes") ==
                 [item["termination_class"] for item in observed] and
                 row.get("mechanical_reason_codes") ==
                 [item["mechanical_reason_code"] for item in observed],
                 f"base pair evidence differs from schedule: {pair_id}")
        if len(observed) == 2:
            _require(row.get("status") == "complete" and
                     observed[0]["worker_id"] == observed[1]["worker_id"] == row["worker_id"] and
                     observed[0]["subject_end_monotonic"] <= observed[1]["subject_start_monotonic"],
                     f"atomic pair ordering failed: {pair_id}")
        else:
            _require(len(observed) == 1 and observed[0]["termination_class"] ==
                     atomic.REPLACEABLE_INFRASTRUCTURE_FAILURE and
                     row.get("status") in {"superseded", "incomplete"},
                     f"nonreplaceable attempt truncated a pair: {pair_id}")
            _require(observed[0]["mechanical_reason_code"] in REPLACEMENT_REASON_CODES and
                     observed[0]["usable_subject_output"] is False and
                     observed[0]["subject_workspace_changed"] is False,
                     f"replacement eligibility is not an authorized preusable failure: {pair_id}")
    eligible = sorted((row for row in base.values()
                       if row["termination_classes"] == [atomic.REPLACEABLE_INFRASTRUCTURE_FAILURE]),
                      key=lambda row: row["queue_position"])
    selected = eligible[:REPLACEMENT_PAIR_LIMIT]
    _require(len(replacements) == len(selected) and
             {row["root_pair_id"] for row in replacements} ==
             {row["root_pair_id"] for row in selected},
             "replacement selection differs from frozen queue priority")
    selected_roots = {row["root_pair_id"] for row in selected}
    for row in eligible:
        _require(row["status"] == ("superseded" if row["root_pair_id"] in selected_roots
                                   else "incomplete") and
                 bool(row["replacement_pair_id"]) == (row["root_pair_id"] in selected_roots),
                 "base replacement disposition differs from the approved cap")
    latest_base_claim = max(row["pair_claimed_monotonic"] for row in base.values())
    for row in replacements:
        parent = base[row["root_pair_id"]]
        observed = sorted(attempts_by_pair.get(row["pair_id"], []),
                          key=lambda item: item["arm_index"])
        scheduled = planned[row["root_pair_id"]]
        expected_arms = [_arm(name) for name in scheduled["arm_order"]]
        _require(row["pair_id"] == f"{row['root_pair_id']}-replacement-1" and
                 row["replacement_for_pair_id"] == row["root_pair_id"] and
                 row["queue_position"] == PAIR_COUNT + parent["queue_position"] and
                 row["pair_claimed_monotonic"] >= latest_base_claim and
                 parent["replacement_pair_id"] == row["pair_id"] and
                 row["task_id"] == scheduled["task_id"] and
                 row["repeat_id"] == scheduled["repeat"] and
                 row["first_arm"] == expected_arms[0] and
                 row["second_arm"] == expected_arms[1] and
                 row["arm_order"] == ("M" if scheduled["first_arm"] == "md" else "N") and
                 [item["arm"] for item in observed] == expected_arms[:len(observed)] and
                 row["attempt_ids"] == [item["attempt_id"] for item in observed] and
                 row["termination_classes"] ==
                 [item["termination_class"] for item in observed] and
                 row["mechanical_reason_codes"] ==
                 [item["mechanical_reason_code"] for item in observed] and
                 1 <= len(observed) <= 2 and
                 all(item["worker_id"] == row["worker_id"] for item in observed),
                 "replacement identity, generation, or claim timing is invalid")
        if len(observed) == 2:
            _require(row["status"] == "complete" and
                     observed[0]["subject_end_monotonic"] <= observed[1]["subject_start_monotonic"],
                     "replacement arms are not atomic")
        else:
            _require(row["status"] == "incomplete" and
                     observed[0]["termination_class"] == atomic.REPLACEABLE_INFRASTRUCTURE_FAILURE,
                     "replacement truncation is not a first-arm infrastructure failure")
    intervals: dict[str, list[tuple[float, float]]] = {}
    for row in pairs:
        intervals.setdefault(row["task_id"], []).append(
            (row["pair_claimed_monotonic"], row["pair_end_monotonic"]))
    for task, spans in intervals.items():
        spans.sort()
        _require(all(left[1] <= right[0] for left, right in zip(spans, spans[1:])),
                 f"same-task pair overlap detected: {task}")
    _require(len(attempts) <= MAX_SUBJECT_INVOCATIONS and len(replacements) <= REPLACEMENT_PAIR_LIMIT
             and manifest.get("planned_pairs") == PAIR_COUNT
             and manifest.get("planned_scientific_calls") == PLANNED_CALLS
             and manifest.get("max_subject_invocations") == MAX_SUBJECT_INVOCATIONS
             and manifest.get("base_pair_count") == PAIR_COUNT
             and manifest.get("replacement_pair_count") == len(replacements)
             and manifest.get("pair_record_count") == len(pairs)
             and manifest.get("actual_attempt_records") == len(attempts)
             and manifest.get("actual_subject_invocations") ==
             sum(row.get("subject_invocation_started") is True for row in attempts)
             and manifest.get("worker_count") == WORKERS
             and 0 <= manifest.get("observed_peak_active_subjects", -1) <= WORKERS
             and 0 <= manifest.get("observed_peak_executor_calls", -1) <= WORKERS
             and manifest.get("status") == "complete"
             and manifest.get("schema_version") == "starlette-eighteen-two-repeat-execution-v1",
             "execution manifest violates the frozen caps")
    active = peak = 0
    started_attempts: list[str] = []
    finished_attempts: list[str] = []
    started_workers: set[str] = set()
    stopped_workers: set[str] = set()
    for index, event in enumerate(events, 1):
        kind = event.get("event_type")
        if kind == "subject_started":
            active += 1
            started_attempts.append(str(event.get("attempt_id")))
        elif kind == "subject_finished":
            active -= 1
            finished_attempts.append(str(event.get("attempt_id")))
        elif kind == "worker_started":
            started_workers.add(str(event.get("worker_id")))
        elif kind == "worker_stopped":
            stopped_workers.add(str(event.get("worker_id")))
        peak = max(peak, active)
        _require(event.get("event_index") == index and
                 event.get("run_seal_sha256") == manifest.get("run_seal_sha256") and
                 event.get("active_subjects") == active and 0 <= active <= WORKERS,
                 "scheduler event stream is inconsistent")
    expected_attempt_ids = [row["attempt_id"] for row in attempts]
    expected_workers = {f"worker-{index:02d}" for index in range(1, WORKERS + 1)}
    _require(active == 0 and len(events) > 0 and
             sorted(started_attempts) == sorted(expected_attempt_ids) == sorted(finished_attempts) and
             started_workers == stopped_workers == expected_workers and
             peak == manifest.get("observed_peak_active_subjects"),
             "scheduler lifecycle is incomplete")


def run_approved(repo: Path, batch: Path, output: Path) -> dict[str, Any]:
    request, request_sha, approval_sha = _approved(batch)  # must remain first
    _validate_request(repo, batch, output, request)
    request_path = batch / "REQUEST.json"
    _require(request_path.read_bytes() == _bytes(request), "REQUEST.json changed during validation")
    spec = repo / request["contamination_spec"]["path"]
    execution = _execution_request(repo, spec)
    _require(sha256(_bytes(execution)).hexdigest() == request["sealed_attempt_request_sha256"],
             "sealed attempt request changed")
    previous_spec = sealed.SPEC
    sealed.SPEC = spec
    try:
        preflight = run_batch.preflight_request(
            execution, deadline_seconds=PREFLIGHT_DEADLINE_SECONDS,
        )
        _require(preflight.get("status") == "PASS",
                 f"launch runtime preflight failed: {preflight.get('failed_checks')}")
        _require(set(preflight.get("seals", {})) == set(TASK_IDS),
                 "launch runtime preflight seals are incomplete")
        backend = live.AtomicLiveBackend(
            live.RunBatchBackend(repo, output, execution, preflight["seals"]), request_sha,
        )
        return execute(output, request, backend, preflight, request_sha, approval_sha)
    finally:
        sealed.SPEC = previous_spec


def _verify_attempt_evidence(repo: Path, output: Path, request: Mapping[str, Any],
                             preflight: Mapping[str, Any],
                             attempts: Sequence[Mapping[str, Any]]) -> None:
    execution = _execution_request(repo, repo / request["contamination_spec"]["path"])
    for row in attempts:
        workspace = output / str(row["workspace_path"])
        _require(workspace.is_dir() and not workspace.is_symlink(),
                 f"attempt workspace is missing: {row['attempt_id']}")
        stub = atomic._read_canonical_json(workspace / "stub-evidence.json")
        stub_outcome = row["termination_class"]
        normalized_second_arm_failure = (
            row["arm_index"] == 2 and
            row["termination_class"] == atomic.LATE_INFRASTRUCTURE_FAILURE and
            row["mechanical_reason_code"] == "infrastructure_failure_after_prior_arm"
        )
        if normalized_second_arm_failure:
            stub_outcome = atomic.REPLACEABLE_INFRASTRUCTURE_FAILURE
        _require(stub == {
            "attempt_id": row["attempt_id"],
            "mode": "live_approved",
            "outcome": stub_outcome,
            "request_sha256": request["_verified_request_sha256"],
            "synthetic": False,
        }, f"live adapter evidence differs: {row['attempt_id']}")
        ordinal = 2 * int(row["replacement_generation"]) + int(row["arm_index"])
        attempt = workspace / str(row["task_id"]) / str(row["arm"]) / f"attempt-{ordinal}"
        manifest = attempt / "attempt-manifest.json"
        if not manifest.is_file():
            _require(row["normal_terminal_record"] is False and
                     row["termination_class"] in {
                         atomic.REPLACEABLE_INFRASTRUCTURE_FAILURE,
                         atomic.LATE_INFRASTRUCTURE_FAILURE,
                         atomic.UNCLASSIFIED_ABNORMAL_TERMINATION,
                     } and not (workspace / "evidence-ledger.jsonl").exists(),
                     f"normal or unanchored attempt lacks finalized evidence: {row['attempt_id']}")
            continue
        run_batch._verify_attempts(workspace, allow_dispositions=False)
        adapted = live.RunBatchBackend._adapt_attempt(
            None, str(row["task_id"]), str(row["arm"]), ordinal, workspace, True,
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
        expected_seal = preflight["seals"][row["task_id"]]
        _require(all(run_batch._json(attempt / name).get("container_preflight") == expected_seal
                     for name in ("intent.json", "launch.json", "result.json")),
                 f"preflight seal echo differs: {row['attempt_id']}")
        raw = run_batch._json(attempt / "result.json")
        run_batch._verify_event_evidence(attempt, raw, hardened=True)
        _require(run_batch._container_echo(attempt, execution),
                 f"container evidence differs: {row['attempt_id']}")


def verify(repo: Path, batch: Path, output: Path) -> dict[str, Any]:
    request, request_sha, approval_sha = _approved(batch)
    _validate_request(repo, batch, output, request)
    manifest = atomic._read_canonical_json(output / "execution-manifest.json")
    analysis = atomic._read_canonical_json(output / "analysis.json")
    seal = atomic._read_canonical_json(output / "run-seal.json")
    schedule = atomic._read_canonical_json(output / "schedule.json")
    preflight = atomic._read_canonical_json(output / "preflight.json")
    attempts = atomic._read_canonical_jsonl(output / "attempts.jsonl")
    pairs = atomic._read_canonical_jsonl(output / "pairs.jsonl")
    events = atomic._read_canonical_jsonl(output / "scheduler-events.jsonl")
    _require(schedule == request["schedule"] and preflight.get("status") == "PASS" and
             set(preflight.get("seals", {})) == set(TASK_IDS),
             "schedule or preflight differs from the approved plan")
    _require(seal == {
        "schema_version": "starlette-eighteen-two-repeat-run-seal-v1",
        "request_sha256": request_sha,
        "approval_sha256": approval_sha,
        "schedule_sha256": sha256_file(output / "schedule.json"),
        "preflight_sha256": sha256_file(output / "preflight.json"),
        "runner_sha256": request["component_sha256"]["experiment_runner"],
        "planned_scientific_calls": PLANNED_CALLS,
        "max_subject_invocations": MAX_SUBJECT_INVOCATIONS,
        "worker_count": WORKERS,
        "replacement_pair_limit": REPLACEMENT_PAIR_LIMIT,
    }, "run seal binding changed")
    _require(manifest.get("run_seal_sha256") == sha256_file(output / "run-seal.json") and
             manifest.get("attempts_sha256") == sha256_file(output / "attempts.jsonl") and
             manifest.get("pairs_sha256") == sha256_file(output / "pairs.jsonl") and
             manifest.get("scheduler_events_sha256") ==
             sha256_file(output / "scheduler-events.jsonl") and
             manifest.get("analysis_sha256") == sha256_file(output / "analysis.json"),
             "execution evidence hash changed")
    current_workspace_hashes = {
        path.relative_to(output).as_posix(): sha256_file(path)
        for path in sorted((output / "workspaces").rglob("*"))
        if path.is_file() and not path.is_symlink()
    }
    _require(manifest.get("workspace_evidence_sha256") == current_workspace_hashes,
             "workspace evidence changed")
    _verify_records(schedule, manifest, attempts, pairs, events)
    recomputed_analysis = build_analysis(request, attempts, pairs)
    _require(analysis == recomputed_analysis and
             (output / "analysis.json").read_bytes() == _bytes(recomputed_analysis),
             "analysis differs from the frozen reporting policy")
    evidence_request = dict(request)
    evidence_request["_verified_request_sha256"] = request_sha
    _verify_attempt_evidence(repo, output, evidence_request, preflight, attempts)
    return {"attempt_records": len(attempts), "pair_records": len(pairs),
            "base_pairs": PAIR_COUNT,
            "replacement_pairs": manifest["replacement_pair_count"],
            "subject_invocations": manifest["actual_subject_invocations"],
            "peak": manifest["observed_peak_active_subjects"]}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "verify-prepared", "run", "verify"))
    parser.add_argument("--batch-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--spec", type=Path)
    args = parser.parse_args(argv)
    batch, output = args.batch_dir.absolute(), args.output_dir.absolute()
    try:
        if args.command == "prepare":
            _require(args.spec is not None, "--spec is required for prepare")
            result: object = {"request": str(prepare(ROOT, batch, output, args.spec.absolute()))}
        elif args.command == "verify-prepared":
            result = verify_prepared(ROOT, batch, output)
        elif args.command == "run":
            result = run_approved(ROOT, batch, output)
        else:
            result = verify(ROOT, batch, output)
    except (ExperimentError, atomic.EvidenceError, live.ShakeoutError, run_batch.BatchError,
            taskcheck.TaskError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}")
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
