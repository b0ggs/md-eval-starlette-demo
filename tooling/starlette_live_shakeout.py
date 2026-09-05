#!/usr/bin/env python3
"""Prepare and approval-gate the required one-time Starlette live shakeout.

``qualify`` and ``prepare`` are no-model operations.  Only ``run`` can reach
the existing live attempt machinery, and it reads a matching APPROVED.json
before verification, preflight, output creation, or backend construction.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import shutil
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from mdseval.capture import parse_disposition
from mdseval.config import RunnerConfig
from mdseval.hashing import sha256_file
from scripts import run_batch
from scripts.contain import runtime as sealed
from tooling import starlette_atomic_pairs, taskcheck

ROOT = Path(__file__).resolve().parents[1]
BATCH_ID = "starlette-live-concurrency-v1"
TASK_IDS = (
    "full-boltons-wraps-forwarding",
    "full-flask-automatic-options",
    "full-starlette-websocket-denial",
    "full-click-stream-lifecycle",
)
TASK_HASHES = {
    "full-boltons-wraps-forwarding": "284379193eb4270b0fb6015345813d3a5ad679082c6aaf3dd3835dc57fc9d525",
    "full-flask-automatic-options": "46886f0ec984a874989a3b5ffc43a76a221dde104cf12ba95f94df0d4938916a",
    "full-starlette-websocket-denial": "d51eea2f228c6ff906a2f6d819d285536aceb07787718c33dede09195d16b754",
    "full-click-stream-lifecycle": "89ebdca30a29f878df6df2ad623bb2610bd5af7875620ed43d2e48c2cc7403a4",
}
SEQUENCES = dict(zip(TASK_IDS, ("MMN", "MNN", "NMM", "NNM")))
IMAGES = {
    "full-boltons-wraps-forwarding": "sha256:701fb29f189e057c591d6715256934aaa7597b58c589362e7e2cb50d3c550c33",
    "full-flask-automatic-options": "sha256:6a93531a8fb34697294a0f869d074a4d75ee692a67a624ba4dee317e7e58be99",
    "full-starlette-websocket-denial": "sha256:391377b4628f194db028967f7c1e056edae72f89f3d68218057abcb3590a374d",
    "full-click-stream-lifecycle": "sha256:701fb29f189e057c591d6715256934aaa7597b58c589362e7e2cb50d3c550c33",
}
PINS = {task_id: "3.11.5" for task_id in TASK_IDS}
PREREGISTRATION = "FINAL_STARLETTE_WALL_TOKEN_PREREGISTRATION_2026-08-29 (1).md"
PREREGISTRATION_SHA256 = "34f4fd5d9b23e77271713ab71e1550e798fb1cbb335b891e15002ed54eea0456"
CANDIDATE = "controls/coder/evidence-bounded-v1.md"
CANDIDATE_SHA256 = "c0d56e29ade34c24278b976e84b29e47324c11a23399ca882239daffc9762c74"
CONTROL = "controls/coder/null-m2.md"
CONTROL_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ANALYZER = "tooling/analyze_starlette_atomic_pairs.py"
ANALYZER_SHA256 = "29d203f6bdb70a800f973f02f5a22b6d1310a771beb0e58ba4783b52c68fd91e"
OFFLINE_RUNNER = "tooling/starlette_atomic_pairs.py"
OFFLINE_RUNNER_SHA256 = "655d9281a2334355e39379844a391a3fa39c8f8a79922f4407c35b0db4b4d4ce"
PRIOR_QUALIFICATION = "qualification/starlette-atomic-pairs/qualification-manifest.json"
PRIOR_QUALIFICATION_SHA256 = "f80c310c59c280f61e561a83dbcf1d31de4b4fa995eea6e5b7837e95442151b8"
QUALIFICATION_ROOT = "qualification/starlette-live-shakeout-preparation"
BATCH_ROOT = "runs/shakeout/starlette-live-concurrency-v1"
LIVE_OUTPUT = f"{BATCH_ROOT}/live-evidence"
WORKER_COUNT = 12
PLANNED_PAIRS = 12
PLANNED_CALLS = 24
MAX_INLINE_RETRIES = 0
MAX_REPLACEMENT_PAIRS = 4
MAX_CALLS = 28
TIMEOUT_SECONDS = 900
PREFLIGHT_SECONDS = 60.0
SEED = 20260830
REASON_CODES = (
    "authentication_preusable_failure",
    "runtime_identity_preusable_failure",
    "subject_spawn_preusable_failure",
    "transport_preoutput_preusable_failure",
)
TOKEN_FIELDS = (
    "input_tokens", "cached_input_tokens", "uncached_input_tokens", "output_tokens",
    "reasoning_tokens", "total_tokens", "uncached_input_plus_output_token_proxy",
)
PACKAGE_FILES = (
    "task-manifest.json",
    "schedule.json",
    "runtime-manifest.json",
    "replacement-reason-codes.json",
    "fallback-schedule.json",
    "preflight-report.json",
    "REQUEST.json",
)
RUNNER = RunnerConfig(
    "codex-cli", "gpt-5.6-sol", "high", "workspace-write", "never",
    False, True, False, TIMEOUT_SECONDS, 1,
)

CONFIRMATION_BATCH_ID = "starlette-wall-token-v7"
CONFIRMATION_ROOT = f"evals/confirmation/{CONFIRMATION_BATCH_ID}"
CONFIRMATION_STAGING = "evals/confirmation/.starlette-wall-token-v7.prepare"
CONFIRMATION_OUTPUT = f"runs/confirmation/{CONFIRMATION_BATCH_ID}/live-evidence"
CONFIRMATION_TASK_IDS = (
    "full-starlette-websocket-denial", "confirm-starlette-cors-origin",
    "confirm-starlette-state-mapping", "confirm-starlette-cors-private-network",
    "confirm-starlette-exception-context", "confirm-starlette-uploadfile-rollover",
    "confirm-starlette-asgi-pathsend", "confirm-starlette-background-exception",
    "confirm-starlette-http-disconnect", "confirm-starlette-session-tracking",
    "confirm-starlette-range-crlf", "confirm-starlette-gzip-vary",
)
CONFIRMATION_FROZEN = {
    CANDIDATE: CANDIDATE_SHA256, CONTROL: CONTROL_SHA256,
    PREREGISTRATION: starlette_atomic_pairs.DEFAULT_PREREGISTRATION_SHA256,
    "STARLETTE_CONFIRMATION_90_90_IMPLEMENTATION.md": "03a305ae4b1a62fdb44392a6ef25d3c88512057988dea555f36a1ba466835d68",
    "tasks/ledger.jsonl": "428b3093364a683433f1ecf143206b35831335f5c3747f4f63adf00133488753",
    "tasks/exposures.jsonl": "4d98619c2b6aa8b5057827d0c8d5346345a48e6bb5328d61ff41837b0627be78",
    "runs/shakeout/starlette-live-concurrency-v1/LIVE_SHAKEOUT_EVIDENCE_MANIFEST.sha256": "8824efea218d032d019d75b5021a895913e83ab12645540d12008e67b59c345d",
    "runs/shakeout/starlette-live-concurrency-v1/LIVE_SHAKEOUT_REPORT.md": "252368c69ac2322887d3751c5b6a3bfbda1885539f9db0dade49b524c1471dae",
    "qualification/starlette-live-adapter-recovery-r1/qualification-manifest.json": "f868b793db419d4f0945b185542e935bd4bb1d6bffb3cb87aaa1bb0131ad9e7f",
    "runs/confirmation/starlette-wall-token-v5/live-evidence/attempts.jsonl": "2ab37d94fe3b8e7fde1d7b15a6a31f5bd5ca0a808927a61a61a03be63413ef74",
}
CONFIRMATION_ARTIFACTS = {
    name: f"evals/confirmation/starlette-wall-token-v1/{filename}"
    for name, filename in {
        "source_selection": "source-selection.json", "task_manifest": "task-manifest.json",
        "sequence_assignment": "sequence-assignment.json", "pair_schedule": "pair-schedule.json",
        "pair_queue": "pair-queue.json", "fallback_schedule": "fallback-schedule.json",
        "replacement_reason_codes": "replacement-reason-codes.json",
        "contamination_spec": "contamination-spec.json", "analysis_freeze": "analysis-freeze.json",
    }.items()
}
CONFIRMATION_COMPONENTS = {
    "atomic_pair_protocol": "tooling/starlette_atomic_pairs.py",
    "analyzer": "tooling/analyze_starlette_atomic_pairs.py",
    "containment": "scripts/contain/runtime.py", "sealed_attempt_implementation": "scripts/run_batch.py",
    "existing_live_backend": "tooling/starlette_live_shakeout.py",
    "codex_cli_adapter": "src/mdseval/runner/codex_cli.py",
    "capture_and_token_accounting": "src/mdseval/capture.py",
    "subject_wrapper": "tooling/prompts/subject-wrapper-v1.txt",
}


class ShakeoutError(RuntimeError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ShakeoutError(message)


def _bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _digest(value: bytes) -> str:
    return sha256(value).hexdigest()


def _write(path: Path, value: object) -> str:
    payload = _bytes(value)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise ShakeoutError(f"exclusive-create collision: {path}") from exc
    return _digest(payload)


def _read(path: Path) -> dict[str, Any]:
    _require(path.is_file() and not path.is_symlink(), f"missing or unsafe JSON: {path}")
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ShakeoutError(f"malformed JSON: {path}") from exc
    _require(isinstance(value, dict) and raw == _bytes(value), f"noncanonical JSON: {path}")
    return value


def _repo_path(repo: Path, relative: str) -> Path:
    path = repo / relative
    _require(path.resolve().is_relative_to(repo.resolve()), f"path leaves repository: {relative}")
    return path


def _assert_hashes(repo: Path) -> None:
    expected = {
        PREREGISTRATION: PREREGISTRATION_SHA256,
        CANDIDATE: CANDIDATE_SHA256,
        CONTROL: CONTROL_SHA256,
        ANALYZER: ANALYZER_SHA256,
        OFFLINE_RUNNER: OFFLINE_RUNNER_SHA256,
        PRIOR_QUALIFICATION: PRIOR_QUALIFICATION_SHA256,
    }
    for relative, digest in expected.items():
        _require(sha256_file(_repo_path(repo, relative)) == digest, f"frozen hash changed: {relative}")


def build_schedule(seed: int = SEED) -> dict[str, Any]:
    pairs = []
    for task_id in TASK_IDS:
        for repeat, symbol in enumerate(SEQUENCES[task_id], 1):
            first = "candidate" if symbol == "M" else "control"
            second = "control" if first == "candidate" else "candidate"
            pairs.append({
                "arm_order": [first, second],
                "pair_id": f"{task_id}-r{repeat}",
                "repeat": repeat,
                "root_pair_id": f"{task_id}-r{repeat}",
                "task_id": task_id,
            })
    random.Random(seed).shuffle(pairs)
    for position, pair in enumerate(pairs, 1):
        pair["queue_position"] = position
    return {
        "schema_version": "starlette-live-shakeout-schedule-v1",
        "randomization_seed": seed,
        "worker_count": WORKER_COUNT,
        "planned_pairs": PLANNED_PAIRS,
        "planned_calls": PLANNED_CALLS,
        "same_task_repeats_may_overlap": True,
        "pairs": pairs,
    }


def _validate_schedule(schedule: Mapping[str, Any]) -> None:
    _require(dict(schedule) == build_schedule(schedule.get("randomization_seed", -1)), "schedule changed")
    pairs = schedule["pairs"]
    _require(len(pairs) == 12 and sum(p["arm_order"][0] == "candidate" for p in pairs) == 6,
             "schedule balance changed")
    for repeat in range(1, 4):
        _require(sum(p["repeat"] == repeat and p["arm_order"][0] == "candidate" for p in pairs) == 2,
                 "per-repeat balance changed")


def build_task_manifest(repo: Path) -> dict[str, Any]:
    tasks = []
    exposures = taskcheck._verify_exposures(repo / "tasks" / "exposures.jsonl")
    for task_id in TASK_IDS:
        verified = taskcheck.verify(repo / "tasks" / task_id, md_filename=None)
        _require(verified["manifest_sha256"] == TASK_HASHES[task_id], f"task changed: {task_id}")
        _require(any(row["task_id"] == task_id and row["event"] == "exposed" for row in exposures),
                 f"shakeout task is not already exposed: {task_id}")
        tasks.append({"task_id": task_id, "manifest_sha256": TASK_HASHES[task_id]})
    return {"schema_version": "starlette-live-shakeout-task-manifest-v1", "tasks": tasks}


def _container() -> dict[str, Any]:
    return {
        "image_digests": dict(IMAGES),
        "interpreter_pins": dict(PINS),
        "spec_sha256": sha256_file(sealed.SPEC),
        "web_search": "disabled",
    }


def _execution_request(repo: Path) -> dict[str, Any]:
    return run_batch._request(
        BATCH_ID,
        [repo / "tasks" / task_id for task_id in TASK_IDS],
        [("candidate", repo / CANDIDATE), ("control", repo / CONTROL)],
        task_order_seed=SEED,
        runner=RUNNER,
        container=_container(),
    )


def build_runtime_manifest(repo: Path) -> dict[str, Any]:
    return {
        "schema_version": "starlette-live-shakeout-runtime-v1",
        "model": RUNNER.model,
        "reasoning_effort": RUNNER.reasoning_effort,
        "subject_timeout_seconds": TIMEOUT_SECONDS,
        "worker_count": WORKER_COUNT,
        "subject_network_access": False,
        "subagents_enabled": False,
        "container": _container(),
        "component_sha256": {
            "live_bridge": sha256_file(Path(__file__)),
            "offline_runner": sha256_file(repo / OFFLINE_RUNNER),
            "analyzer": sha256_file(repo / ANALYZER),
            "run_batch": sha256_file(repo / "scripts/run_batch.py"),
            "containment": sha256_file(repo / "scripts/contain/runtime.py"),
            "wrapper": sha256_file(repo / "tooling/prompts/subject-wrapper-v1.txt"),
        },
    }


def build_reason_codes() -> dict[str, Any]:
    return {
        "schema_version": "starlette-live-shakeout-reasons-v1",
        "replaceable_reason_codes": list(REASON_CODES),
        "eligibility": "first_arm_preusable_infrastructure_failure_only",
        "inline_retry_limit": 0,
    }


def build_fallback(schedule: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": "starlette-live-shakeout-fallback-v1",
        "base_drain_required": True,
        "replacement_generation_limit": 1,
        "max_replacement_pairs": MAX_REPLACEMENT_PAIRS,
        "max_subject_invocations": MAX_CALLS,
        "selection": "eligible_roots_by_base_queue_position_first_four",
        "root_priority": [p["root_pair_id"] for p in schedule["pairs"]],
    }


class _Jsonl:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.stream = path.open("xb")
        self.lock = threading.Lock()

    def append(self, value: object) -> None:
        with self.lock:
            self.stream.write(_bytes(value))
            self.stream.flush()
            os.fsync(self.stream.fileno())

    def close(self) -> None:
        self.stream.close()


class StubBackend:
    """No-model backend used only for qualification and unit tests."""

    def __init__(self, failures: set[str] | None = None) -> None:
        self.failures = failures or set()
        self.barrier = threading.Barrier(WORKER_COUNT)

    def __call__(self, job: Mapping[str, Any], arm: str, arm_index: int, evidence: Path) -> dict[str, Any]:
        del evidence
        if job.get("generation", 0) == 0 and arm_index == 1:
            self.barrier.wait(timeout=10)
        time.sleep(0.005)
        failed = (job.get("generation", 0) == 0 and
                  job["root_pair_id"] in self.failures and arm_index == 1)
        return {
            "termination_class": (starlette_atomic_pairs.REPLACEABLE_INFRASTRUCTURE_FAILURE
                                  if failed else starlette_atomic_pairs.NORMAL_COMPLETION),
            "mechanical_reason_code": ("transport_preoutput_preusable_failure" if failed else "completed"),
            "valid": not failed,
            "resolved": not failed,
            "normal_terminal_record": not failed,
            "subject_timeout": False,
            "infrastructure_failure": failed,
            "usable_subject_output": not failed,
            "subject_workspace_changed": not failed,
            "duration_seconds": 0.005,
            "trajectory_length": 1,
            "retry_count": 0,
            "rate_limit_count": 0,
            "token_components": {"input_tokens": 10, "cached_input_tokens": 2,
                                 "output_tokens": 3, "reasoning_tokens": 1,
                                 "total_tokens": 13,
                                 "uncached_input_plus_output_token_proxy": 11},
        }


class RunBatchBackend:
    """Thin adapter to the repository's existing sealed attempt implementation."""

    def __init__(self, repo: Path, output: Path, request: dict[str, Any], seals: dict[str, Any]) -> None:
        self.repo, self.output, self.request, self.seals = repo, output, request, seals
        self.home = os.environ.get("MDSEVAL_CODEX_HOME", str(repo / ".mdseval-codex-home"))
        _require((Path(self.home) / "auth.json").is_file(), "isolated auth source is missing")
        self.arms = {row["name"]: row for row in request["arms"]}

    @staticmethod
    def _reason(text: str) -> str:
        lowered = text.lower()
        if any(word in lowered for word in ("authentication", "unauthorized", "api key", "login")):
            return REASON_CODES[0]
        if any(word in lowered for word in ("configuration", "runtime identity", "image digest")):
            return REASON_CODES[1]
        if any(word in lowered for word in ("spawn", "executable", "permission")):
            return REASON_CODES[2]
        return REASON_CODES[3]

    def __call__(self, job: Mapping[str, Any], arm: str, arm_index: int, evidence: Path) -> dict[str, Any]:
        task_id = job["task_id"]
        task = self.repo / "tasks" / task_id
        ordinal = 2 * int(job.get("generation", 0)) + arm_index
        subject_invocation_started = False

        def observe_subject_invocation() -> None:
            nonlocal subject_invocation_started
            subject_invocation_started = True

        try:
            usable = run_batch._attempt(
                task, self.request, self.arms[arm], ordinal, evidence,
                run_batch.run_process_group, self.home, self.seals[task_id],
                subject_invocation_observer=observe_subject_invocation,
            )
        except taskcheck.TaskError:
            return self._abnormal(False, "task_integrity_failure", subject_invocation_started)
        except run_batch.BatchError as exc:
            text = str(exc)
            replaceable = text.startswith("BUILD_REJECTED") or "did not spawn" in text
            return self._abnormal(replaceable, self._reason(text), subject_invocation_started)
        except Exception as exc:
            return self._abnormal(
                False, f"live_backend_exception:{type(exc).__name__}",
                subject_invocation_started,
            )
        try:
            return self._adapt_attempt(
                task_id, arm, ordinal, evidence, usable, subject_invocation_started,
            )
        except Exception as exc:
            return self._abnormal(
                False, f"live_backend_exception:{type(exc).__name__}",
                subject_invocation_started,
            )

    def _adapt_attempt(
        self, task_id: str, arm: str, ordinal: int, evidence: Path, usable: bool,
        subject_invocation_started: bool,
    ) -> dict[str, Any]:
        attempt = evidence / task_id / arm / f"attempt-{ordinal}"
        if not usable:
            text = "\n".join(path.read_text(errors="replace") for path in attempt.glob("*.txt"))
            return self._abnormal(True, self._reason(text), subject_invocation_started)
        result = run_batch._json(attempt / "result.json")
        final = (attempt / "final.txt").read_text(errors="replace")
        changed = any(result.get("target_path_changes", {}).values())
        if result["timed_out"]:
            termination = starlette_atomic_pairs.SUBJECT_TIMEOUT
        elif result["returncode"] == 0 and result["valid"]:
            disposition = parse_disposition(final)
            termination = (starlette_atomic_pairs.REFUSAL if disposition in {"BLOCKED", "NEEDS_CLARIFICATION"}
                           else starlette_atomic_pairs.NORMAL_COMPLETION if result["resolved"]
                           else starlette_atomic_pairs.NORMAL_INCORRECT_COMPLETION)
        else:
            termination = starlette_atomic_pairs.UNCLASSIFIED_ABNORMAL_TERMINATION
        totals = result["token_totals"]
        if totals.get("usage_reported") is True:
            uncached = totals["input_tokens"] - totals["cached_input_tokens"]
            token_components = {
                **{name: totals[name] for name in (
                    "input_tokens", "cached_input_tokens", "output_tokens",
                    "reasoning_tokens", "total_tokens",
                )},
                "uncached_input_tokens": uncached,
                "uncached_input_plus_output_token_proxy": uncached + totals["output_tokens"],
            }
        else:
            token_components = {name: None for name in TOKEN_FIELDS}
        events = (attempt / "events.jsonl").read_text(errors="replace").splitlines()
        return {
            **starlette_atomic_pairs.classify_termination(
                termination, resolved=result["resolved"], usable_subject_output=bool(final or changed),
                subject_workspace_changed=changed,
            ),
            "duration_seconds": result["duration_seconds"],
            "trajectory_length": len(events),
            "retry_count": sum('"retry"' in row.lower() for row in events),
            "rate_limit_count": sum("rate_limit" in row.lower() for row in events),
            "subject_invocation_started": subject_invocation_started,
            "token_components": token_components,
        }

    @staticmethod
    def _abnormal(
        replaceable: bool, reason: str, subject_invocation_started: bool = False,
    ) -> dict[str, Any]:
        termination = (starlette_atomic_pairs.REPLACEABLE_INFRASTRUCTURE_FAILURE if replaceable
                       else starlette_atomic_pairs.UNCLASSIFIED_ABNORMAL_TERMINATION)
        return {**starlette_atomic_pairs.classify_termination(termination, mechanical_reason_code=reason),
                "duration_seconds": 0.0, "trajectory_length": 0, "retry_count": 0,
                "rate_limit_count": 0, "subject_invocation_started": subject_invocation_started,
                "token_components": {name: None for name in TOKEN_FIELDS}}


class AtomicLiveBackend:
    """Adapt the existing sealed attempt backend to atomic-runner contexts."""

    def __init__(self, backend: RunBatchBackend, request_sha256: str) -> None:
        self.backend = backend
        self.request_sha256 = request_sha256

    def __call__(self, context: starlette_atomic_pairs.AttemptContext) -> dict[str, Any]:
        job = {
            "generation": context.replacement_generation,
            "root_pair_id": context.root_pair_id,
            "task_id": context.task_id,
        }
        try:
            result = dict(
                self.backend(job, context.arm, context.arm_index, context.workspace)
            )
        except Exception as exc:
            result = RunBatchBackend._abnormal(
                False, f"live_backend_exception:{type(exc).__name__}"
            )
        starlette_atomic_pairs._write_json_once(
            context.workspace / "stub-evidence.json",
            {
                "attempt_id": context.attempt_id,
                "mode": "live_approved",
                "outcome": result["termination_class"],
                "request_sha256": self.request_sha256,
                "synthetic": False,
            },
        )
        return result


def _confirmation_cli_version() -> str:
    completed = subprocess.run(
        ["codex", "--version"], capture_output=True, check=False, text=True, timeout=10,
    )
    value = completed.stdout.strip()
    _require(completed.returncode == 0 and value.startswith("codex-cli "),
             "installed codex --version is unavailable")
    return value


def _exact_confirmation_path(path: Path, expected: Path, label: str) -> Path:
    absolute = path.absolute()
    _require(absolute == expected and path.resolve() == expected and not path.is_symlink(),
             f"{label} must use its canonical non-symlink path")
    return expected


def _confirmation_auth(repo: Path) -> Path:
    value = os.environ.get("MDSEVAL_CODEX_HOME")
    _require(bool(value), "MDSEVAL_CODEX_HOME is required")
    auth = _exact_confirmation_path(Path(value), repo / ".mdseval-codex-home", "auth source")
    auth_file = auth / "auth.json"
    _require(auth.is_dir() and not auth.is_symlink() and auth_file.is_file() and
             not auth_file.is_symlink() and auth_file.stat().st_size > 0,
             "repository-local auth.json must be a nonempty non-symlink file")
    return auth


def _confirmation_inputs(
    repo: Path, qualification: Path,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    for relative, digest in CONFIRMATION_FROZEN.items():
        _require(sha256_file(_repo_path(repo, relative)) == digest,
                 f"frozen hash changed: {relative}")
    _require(qualification.resolve() == repo / "qualification/starlette-live-adapter-recovery-r1"
             and not qualification.is_symlink(), "confirmation qualification path changed")
    starlette_atomic_pairs.verify_qualification(
        qualification, expected_runs=3, max_seconds=60,
        preregistration_sha256=starlette_atomic_pairs.DEFAULT_PREREGISTRATION_SHA256,
    )
    source_request_path = repo / "evals/confirmation/starlette-wall-token-v1/REQUEST.json"
    source_runtime_path = repo / "evals/confirmation/starlette-wall-token-v1/runtime-manifest.json"
    _require(sha256_file(source_request_path) ==
             "836d6e67b397841b2aedb8faf4d34f8eaecb052e27b576163057709b795b2699",
             "frozen v1 request changed")
    _require(sha256_file(source_runtime_path) ==
             "2f599b578e41d7c4c8fea304b5ec4e442f950966eaba55504d25075678060406",
             "frozen v1 runtime changed")
    source, runtime = _read(source_request_path), _read(source_runtime_path)
    for name, relative in CONFIRMATION_ARTIFACTS.items():
        binding = source["artifacts_sha256"][name]
        _require(binding["path"] == relative and sha256_file(repo / relative) == binding["sha256"],
                 f"frozen artifact changed: {relative}")
    task_manifest = _read(repo / CONFIRMATION_ARTIFACTS["task_manifest"])
    task_ids = tuple(row["task_id"] for row in task_manifest["tasks"])
    _require(task_ids == CONFIRMATION_TASK_IDS and task_manifest["task_count"] == 12,
             "confirmation task order changed")
    for row in task_manifest["tasks"]:
        verified = taskcheck.verify(repo / "tasks" / row["task_id"], md_filename=None)
        _require(verified["manifest_sha256"] == row["admission"]["taskcheck_manifest_sha256"],
                 f"task changed: {row['task_id']}")
        _require(sha256_file(repo / "tasks" / row["task_id"] / "image-lock.json") ==
                 runtime["container"]["image_lock_sha256"][row["task_id"]],
                 f"image lock changed: {row['task_id']}")
    schedule = _read(repo / CONFIRMATION_ARTIFACTS["pair_schedule"])
    starlette_atomic_pairs.validate_schedule(schedule)
    _require(tuple(schedule["task_ids"]) == CONFIRMATION_TASK_IDS, "confirmation schedule changed")
    rows = [json.loads(line) for line in
            (repo / "runs/confirmation/starlette-wall-token-v5/live-evidence/attempts.jsonl")
            .read_text(encoding="utf-8").splitlines()]
    _require(len(rows) == 26 and len({row["pair_id"] for row in rows}) == 13 and all(
        row["termination_class"] == starlette_atomic_pairs.UNCLASSIFIED_ABNORMAL_TERMINATION
        and row["usable_subject_output"] is False
        and row["subject_workspace_changed"] is False for row in rows
    ), "v5 abandoned-campaign facts changed")
    return source, runtime, schedule


def _confirmation_runtime(
    repo: Path, qualification_report: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    del qualification_report
    runtime = _read(repo / "evals/confirmation/starlette-wall-token-v1/runtime-manifest.json")
    runtime["schema_version"] = "starlette-confirmation-runtime-v7"
    runtime["component_sha256"] = {
        name: sha256_file(repo / relative) for name, relative in CONFIRMATION_COMPONENTS.items()
    }
    runtime["model"]["cli_version"] = _confirmation_cli_version()
    runtime["qualification"] = {
        "full_stack_runs": 3, "max_seconds_per_run": 60,
        "recovery_qualification_sha256": CONFIRMATION_FROZEN[
            "qualification/starlette-live-adapter-recovery-r1/qualification-manifest.json"],
        "live_concurrency_shakeout_evidence_manifest_sha256": CONFIRMATION_FROZEN[
            "runs/shakeout/starlette-live-concurrency-v1/LIVE_SHAKEOUT_EVIDENCE_MANIFEST.sha256"],
        "live_concurrency_shakeout_report_sha256": CONFIRMATION_FROZEN[
            "runs/shakeout/starlette-live-concurrency-v1/LIVE_SHAKEOUT_REPORT.md"],
    }
    return runtime


def _confirmation_offline_run(
    repo: Path, output: Path, request: Mapping[str, Any], runtime: Mapping[str, Any],
    schedule: Mapping[str, Any], smoke: Callable[..., dict[str, Any]] | None,
) -> dict[str, Any]:
    started = time.monotonic()
    deadline = started + PREFLIGHT_SECONDS
    output.mkdir()
    atomic = output / "atomic"
    manifest = starlette_atomic_pairs.run_stub(
        atomic, task_ids=CONFIRMATION_TASK_IDS, schedule=schedule,
        preregistration_sha256=starlette_atomic_pairs.DEFAULT_PREREGISTRATION_SHA256,
    )
    from tooling import analyze_starlette_atomic_pairs
    analysis = analyze_starlette_atomic_pairs.analyze_run_directory(atomic)
    starlette_atomic_pairs._write_json_once(atomic / "analysis.json", analysis)
    starlette_atomic_pairs.validate_run_directory(
        atomic, expected_preregistration_sha256=starlette_atomic_pairs.DEFAULT_PREREGISTRATION_SHA256,
        enforce_current_runner=True,
    )
    _require(time.monotonic() < deadline, "full-stack preflight exceeded 60 seconds")
    exposure_before = sha256_file(repo / "tasks/exposures.jsonl")
    observed: list[bool] = []
    observer_request = run_batch._request(
        CONFIRMATION_BATCH_ID, [repo / "tasks" / CONFIRMATION_TASK_IDS[0]],
        [("candidate", repo / CANDIDATE)], task_order_seed=0, runner=RUNNER,
    )
    try:
        run_batch._attempt(
            repo / "tasks" / CONFIRMATION_TASK_IDS[0], observer_request,
            observer_request["arms"][0], 1, output / "observer", lambda *args, **kwargs:
            (_ for _ in ()).throw(OSError("no-model observer boundary")),
            str(repo / ".mdseval-codex-home"),
            subject_invocation_observer=lambda: observed.append(True),
        )
    except run_batch.BatchError as exc:
        _require("did not spawn" in str(exc), "observer boundary qualification failed")
    _require(observed == [True] and sha256_file(repo / "tasks/exposures.jsonl") == exposure_before,
             "observer boundary qualification failed")
    remaining = deadline - time.monotonic()
    _require(remaining > 0, "full-stack preflight exceeded 60 seconds")
    previous_spec = sealed.SPEC
    sealed.SPEC = repo / CONFIRMATION_ARTIFACTS["contamination_spec"]
    try:
        preflight = run_batch.preflight_request(
            _confirmation_execution_request(repo, request, runtime), smoke=smoke,
            deadline_seconds=remaining,
        )
    finally:
        sealed.SPEC = previous_spec
    duration = time.monotonic() - started
    _require(preflight["status"] == "PASS" and duration <= PREFLIGHT_SECONDS,
             f"full-stack preflight failed: {preflight.get('failed_checks')}")
    return {
        "analysis_sha256": sha256_file(atomic / "analysis.json"),
        "duration_seconds": duration, "live_model_calls": 0,
        "manifest_sha256": sha256_file(atomic / "manifest.json"),
        "observed_peak_active_subjects": manifest["observed_peak_active_subjects"],
        "observer_boundary_count": len(observed),
        "observer_evidence_sha256": sha256_file(next((output / "observer").rglob("pre-spawn.json"))),
        "runtime_seals": preflight["seals"],
        "sealed_subject_called": False, "status": "PASS",
    }


def _confirmation_request(
    repo: Path, batch: Path, output: Path, runtime: Mapping[str, Any],
    report: Mapping[str, Any],
) -> dict[str, Any]:
    del batch
    request = _read(repo / "evals/confirmation/starlette-wall-token-v1/REQUEST.json")
    request["batch_id"], request["purpose"] = CONFIRMATION_BATCH_ID, "v7_prospectively_amended_confirmation"
    request["execution"]["execution_output_path"] = output.relative_to(repo).as_posix()
    request["approval"]["approval_path"] = f"{CONFIRMATION_ROOT}/APPROVED.json"
    request["artifacts_sha256"] = {
        name: {"path": relative, "sha256": sha256_file(repo / relative)}
        for name, relative in CONFIRMATION_ARTIFACTS.items()
    }
    for name, filename in (("runtime_manifest", "runtime-manifest.json"),
                           ("prelaunch_report", "prelaunch-preflight-report.json"),
                           ("confirmation_manifest", "confirmation-manifest.json"),
                           ("full_stack_qualification", "qualification/qualification-manifest.json")):
        request["artifacts_sha256"][name] = {
            "path": f"{CONFIRMATION_ROOT}/{filename}", "sha256": report[f"{name}_sha256"]}
    request["launch_components"] = {
        name: {"path": relative, "sha256": sha256_file(repo / relative)}
        for name, relative in CONFIRMATION_COMPONENTS.items()
    }
    request["frozen_inputs_sha256"].update({
        "runner": sha256_file(repo / CONFIRMATION_COMPONENTS["atomic_pair_protocol"]),
        "analyzer": sha256_file(repo / CONFIRMATION_COMPONENTS["analyzer"]),
    })
    request["runtime"] = {"model": RUNNER.model, "reasoning_effort": RUNNER.reasoning_effort,
                          "runtime_manifest_sha256": report["runtime_manifest_sha256"]}
    request["qualification_sha256"] = {
        "full_stack_requalification": {
            "path": f"{CONFIRMATION_ROOT}/qualification/qualification-manifest.json",
            "sha256": report["full_stack_qualification_sha256"],
        },
        "recovery_qualification": {
            "path": "qualification/starlette-live-adapter-recovery-r1/qualification-manifest.json",
            "sha256": CONFIRMATION_FROZEN[
                "qualification/starlette-live-adapter-recovery-r1/qualification-manifest.json"],
        },
        "live_concurrency_shakeout_evidence_manifest": {
            "path": "runs/shakeout/starlette-live-concurrency-v1/LIVE_SHAKEOUT_EVIDENCE_MANIFEST.sha256",
            "sha256": CONFIRMATION_FROZEN[
                "runs/shakeout/starlette-live-concurrency-v1/LIVE_SHAKEOUT_EVIDENCE_MANIFEST.sha256"],
        },
        "live_concurrency_shakeout_report": {
            "path": "runs/shakeout/starlette-live-concurrency-v1/LIVE_SHAKEOUT_REPORT.md",
            "sha256": CONFIRMATION_FROZEN[
                "runs/shakeout/starlette-live-concurrency-v1/LIVE_SHAKEOUT_REPORT.md"],
        },
    }
    request["prospective_addendum_sha256"] = CONFIRMATION_FROZEN[
        "STARLETTE_CONFIRMATION_90_90_IMPLEMENTATION.md"]
    request["frozen_path_sha256"] = dict(CONFIRMATION_FROZEN)
    request["v5_disposition"] = {"attempts": 26, "pairs": 13, "excluded": True,
                                 "attempts_sha256": CONFIRMATION_FROZEN[
        "runs/confirmation/starlette-wall-token-v5/live-evidence/attempts.jsonl"]}
    request.pop("source_head_before_confirmation_package", None)
    return request


def _confirmation_manifest(
    repo: Path, runtime_sha256: str, preflight_sha256: str,
    qualification_sha256: str, preflight: Mapping[str, Any],
) -> dict[str, Any]:
    analyzer = sha256_file(repo / CONFIRMATION_COMPONENTS["analyzer"])
    runner = sha256_file(repo / CONFIRMATION_COMPONENTS["atomic_pair_protocol"])
    path = repo / "evals/confirmation/starlette-wall-token-v1/confirmation-manifest.json"
    _require(sha256_file(path) == "9e444693ab8c734fad3760e60ad921df5abd9dbf14c0eb7e65b3cb8058bf9cf9",
             "frozen v1 Section 14 manifest changed")
    result = _read(path)
    result["schema_version"] = "starlette-confirmation-manifest-v7"
    result["confirmation_manifest"].update({
        "RUNNER_SHA256": runner, "ANALYZER_SHA256": analyzer,
        "ANALYSIS_SCRIPT_SHA256": analyzer, "RUNTIME_MANIFEST_SHA256": runtime_sha256,
        "PRELAUNCH_PREFLIGHT_REPORT_SHA256": preflight_sha256,
    })
    result["runner_runtime_qualification"].update({
        "RUNNER_SHA256": runner, "ANALYZER_SHA256": analyzer,
        "RUNTIME_MANIFEST_SHA256": runtime_sha256,
        "OFFLINE_12_WORKER_QUALIFICATION_REPORT_SHA256": qualification_sha256,
    })
    result["additional_bindings"].update({
        "EXPOSURES_LEDGER_SHA256": CONFIRMATION_FROZEN["tasks/exposures.jsonl"],
        "PROTOCOL_ADDENDUM_SHA256": CONFIRMATION_FROZEN[
            "STARLETTE_CONFIRMATION_90_90_IMPLEMENTATION.md"],
        "V5_ABANDONED_ATTEMPTS_SHA256": CONFIRMATION_FROZEN[
            "runs/confirmation/starlette-wall-token-v5/live-evidence/attempts.jsonl"],
        "PRELAUNCH_ANALYSIS_SHA256": preflight["analysis_sha256"],
        "PRELAUNCH_RUN_MANIFEST_SHA256": preflight["manifest_sha256"],
    })
    return result


def _validate_confirmation_run(
    repo: Path, run_dir: Path, row: Mapping[str, Any], runtime: Mapping[str, Any],
) -> None:
    atomic = run_dir / "atomic"
    records = starlette_atomic_pairs.validate_run_directory(
        atomic, expected_preregistration_sha256=starlette_atomic_pairs.DEFAULT_PREREGISTRATION_SHA256,
        enforce_current_runner=True,
    )
    from tooling import analyze_starlette_atomic_pairs
    expected_analysis = analyze_starlette_atomic_pairs.analyze_run_directory(atomic)
    _require(_read(atomic / "analysis.json") == expected_analysis and
             row.get("analysis_sha256") == sha256_file(atomic / "analysis.json") and
             row.get("manifest_sha256") == sha256_file(atomic / "manifest.json"),
             "offline analyzer evidence changed")
    manifest = records["manifest"]
    _require(manifest["planned_pair_count"] == 36 and manifest["planned_attempt_count"] == 72 and
             manifest["worker_count"] == 12 and manifest["live_model_calls"] == 0 and
             manifest["observed_peak_active_subjects"] == 12 and
             row.get("observed_peak_active_subjects") == manifest["observed_peak_active_subjects"] and
             row.get("observer_boundary_count") == 1 and
             row.get("observer_evidence_sha256") == sha256_file(next(
                 (run_dir / "observer").rglob("pre-spawn.json"))) and
             len(list((run_dir / "observer").rglob("pre-spawn.json"))) == 1,
             "full-stack run evidence changed")
    seals = row.get("runtime_seals")
    _require(isinstance(seals, dict) and set(seals) == set(CONFIRMATION_TASK_IDS),
             "full-stack runtime seals changed")
    container = runtime["container"]
    _require(all(sealed._validate_fast_seal(
        seals[task_id], container["image_digests"][task_id],
        container["interpreter_pins"][task_id],
    ) for task_id in CONFIRMATION_TASK_IDS), "full-stack runtime seal is invalid")


def verify_confirmation_prepared(
    repo: Path, batch: Path, output: Path, qualification: Path, *, require_unapproved: bool,
) -> dict[str, Any]:
    allowed_batches = (repo / CONFIRMATION_ROOT, repo / CONFIRMATION_STAGING)
    _require(any(batch.absolute() == path and batch.resolve() == path and not batch.is_symlink()
                 for path in allowed_batches), "confirmation batch path is not canonical")
    output = _exact_confirmation_path(output, repo / CONFIRMATION_OUTPUT, "output")
    _confirmation_auth(repo)
    _confirmation_inputs(repo, qualification)
    request = _read(batch / "REQUEST.json")
    schedule, runtime, report = _validate_confirmation_request(repo, batch, request)
    allowed = {"REQUEST.json", "confirmation-manifest.json", "runtime-manifest.json",
               "prelaunch-preflight-report.json", "qualification", "preflight"}
    if not require_unapproved and (batch / "APPROVED.json").is_file(): allowed.add("APPROVED.json")
    _require({path.name for path in batch.iterdir()} == allowed and
             not any(path.is_symlink() for path in batch.rglob("*")),
             "confirmation package paths changed or contain a symlink")
    _require(not require_unapproved or not (batch / "APPROVED.json").exists(),
             "prepared confirmation is already approved")
    _require(runtime == _confirmation_runtime(repo), "confirmation runtime binding changed")
    qualification_record = _read(batch / "qualification/qualification-manifest.json")
    _require(qualification_record.get("schema_version") ==
             "starlette-confirmation-full-stack-qualification-v7" and
             set(qualification_record) == {"schema_version", "status", "live_model_calls",
                 "sealed_subject_called", "expected_runs", "max_seconds", "runs",
                 "runtime_manifest_sha256"} and
             qualification_record.get("status") == "PASS" and
             qualification_record.get("runtime_manifest_sha256") == sha256_file(batch / "runtime-manifest.json") and
             qualification_record.get("live_model_calls") == 0 and
             qualification_record.get("sealed_subject_called") is False and
             qualification_record.get("expected_runs") == 3 and
             qualification_record.get("max_seconds") == 60 and
             len(qualification_record.get("runs", ())) == 3 and all(
                 set(row) == {"analysis_sha256", "duration_seconds", "live_model_calls",
                     "manifest_sha256", "observed_peak_active_subjects", "observer_boundary_count",
                     "observer_evidence_sha256", "runtime_seals", "sealed_subject_called", "status",
                     "run_index"} and row.get("status") == "PASS" and row.get("live_model_calls") == 0 and
                 row.get("sealed_subject_called") is False and
                 isinstance(row.get("duration_seconds"), (int, float)) and
                 not isinstance(row["duration_seconds"], bool) and
                 math.isfinite(row["duration_seconds"]) and 0 < row["duration_seconds"] <= 60
                 for row in qualification_record["runs"]), "full-stack qualification changed")
    _require([row.get("run_index") for row in qualification_record["runs"]] == [1, 2, 3],
             "full-stack qualification run indices changed")
    _require(report.get("status") == "PASS" and report.get("live_model_calls") == 0 and
             report.get("sealed_subject_called") is False and report.get("duration_seconds", 61) <= 60,
             "confirmation preflight changed")
    previous_spec = sealed.SPEC
    sealed.SPEC = repo / CONFIRMATION_ARTIFACTS["contamination_spec"]
    try:
        for index, row in enumerate(qualification_record["runs"], 1):
            _validate_confirmation_run(repo, batch / "qualification" / f"run-{index:03d}",
                                       row, runtime)
        _validate_confirmation_run(repo, batch / "preflight", report, runtime)
    finally:
        sealed.SPEC = previous_spec
    hashes = {"runtime_manifest_sha256": sha256_file(batch / "runtime-manifest.json"),
              "prelaunch_report_sha256": sha256_file(batch / "prelaunch-preflight-report.json"),
              "confirmation_manifest_sha256": sha256_file(batch / "confirmation-manifest.json"),
              "full_stack_qualification_sha256": sha256_file(
                  batch / "qualification/qualification-manifest.json")}
    expected_manifest = _confirmation_manifest(
        repo, hashes["runtime_manifest_sha256"], hashes["prelaunch_report_sha256"],
        hashes["full_stack_qualification_sha256"], report,
    )
    _require(_read(batch / "confirmation-manifest.json") == expected_manifest,
             "Section 14 manifest changed")
    _require(request == _confirmation_request(repo, batch, output, runtime, hashes),
             "confirmation request binding changed")
    return request


def prepare_confirmation(
    repo: Path, batch: Path, output: Path, qualification: Path, *,
    smoke: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    batch = _exact_confirmation_path(batch, repo / CONFIRMATION_ROOT, "batch")
    output = _exact_confirmation_path(output, repo / CONFIRMATION_OUTPUT, "output")
    qualification = _exact_confirmation_path(
        qualification, repo / "qualification/starlette-live-adapter-recovery-r1", "qualification")
    _confirmation_auth(repo)
    source, _, schedule = _confirmation_inputs(repo, qualification)
    stage = repo / CONFIRMATION_STAGING
    _require(not batch.exists() and not stage.exists() and not output.exists(),
             "v7 preparation or output path already exists")
    stage.mkdir()
    try:
        runtime = _confirmation_runtime(repo)
        _write(stage / "runtime-manifest.json", runtime)
        seed_request = dict(source); seed_request["batch_id"] = CONFIRMATION_BATCH_ID
        (stage / "qualification").mkdir()
        runs = []
        for index in range(1, 4):
            row = _confirmation_offline_run(repo, stage / "qualification" / f"run-{index:03d}",
                                            seed_request, runtime, schedule, smoke)
            row["run_index"] = index
            runs.append(row)
        qualification_record = {"schema_version": "starlette-confirmation-full-stack-qualification-v7",
            "status": "PASS", "live_model_calls": 0, "sealed_subject_called": False,
            "expected_runs": 3, "max_seconds": 60, "runs": runs,
            "runtime_manifest_sha256": sha256_file(stage / "runtime-manifest.json")}
        _write(stage / "qualification/qualification-manifest.json", qualification_record)
        preflight = _confirmation_offline_run(repo, stage / "preflight", seed_request,
                                               runtime, schedule, smoke)
        preflight.update({"schema_version": "starlette-confirmation-prelaunch-preflight-v7",
            "schedule_sha256": sha256_file(repo / CONFIRMATION_ARTIFACTS["pair_schedule"]),
            "runtime_manifest_sha256": sha256_file(stage / "runtime-manifest.json")})
        _write(stage / "prelaunch-preflight-report.json", preflight)
        section14 = _confirmation_manifest(
            repo, sha256_file(stage / "runtime-manifest.json"),
            sha256_file(stage / "prelaunch-preflight-report.json"),
            sha256_file(stage / "qualification/qualification-manifest.json"), preflight,
        )
        _write(stage / "confirmation-manifest.json", section14)
        hashes = {"runtime_manifest_sha256": sha256_file(stage / "runtime-manifest.json"),
                  "prelaunch_report_sha256": sha256_file(stage / "prelaunch-preflight-report.json"),
                  "confirmation_manifest_sha256": sha256_file(stage / "confirmation-manifest.json"),
                  "full_stack_qualification_sha256": sha256_file(stage / "qualification/qualification-manifest.json")}
        request = _confirmation_request(repo, stage, output, runtime, hashes)
        _write(stage / "REQUEST.json", request)
        verify_confirmation_prepared(repo, stage, output, qualification, require_unapproved=True)
        os.replace(stage, batch)
        return request
    except BaseException:
        if stage.exists() and not stage.is_symlink(): shutil.rmtree(stage)
        raise


def _confirmation_execution_request(
    repo: Path, request: Mapping[str, Any], runtime: Mapping[str, Any]
) -> dict[str, Any]:
    container = runtime["container"]
    return run_batch._request(
        request["batch_id"],
        [repo / row["path"] for row in request["tasks"]],
        [(row["name"], repo / row["path"]) for row in request["arms"]],
        task_order_seed=0,
        runner=RUNNER,
        container={
            key: container[key]
            for key in ("image_digests", "interpreter_pins", "spec_sha256", "web_search")
        },
    )


def _confirmation_bound_path(repo: Path, batch: Path, relative: str) -> Path:
    final = repo / CONFIRMATION_ROOT
    path = _repo_path(repo, relative)
    if batch.resolve() == repo / CONFIRMATION_STAGING and path.is_relative_to(final):
        return batch / path.relative_to(final)
    return path


def _validate_confirmation_request(
    repo: Path, batch: Path, request: Mapping[str, Any]
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    _require(request.get("schema_version") == "starlette-confirmation-live-request-v1",
             "unsupported confirmation request")
    _require(request.get("batch_id") == CONFIRMATION_BATCH_ID and batch.resolve() in {
        repo / CONFIRMATION_ROOT, repo / CONFIRMATION_STAGING}, "confirmation batch path changed")
    execution, fallback = request.get("execution"), request.get("retry_and_fallback")
    _require(isinstance(execution, dict) and execution.get("worker_count") == 12 and
             execution.get("max_active_subject_calls") == 12 and
             execution.get("subject_timeout_seconds") == 900 and
             execution.get("same_task_repeats_may_overlap") is False and
             execution.get("batch_early_stop_on_any_other_pair_failure") is False,
             "confirmation execution policy changed")
    _require(isinstance(fallback, dict) and fallback.get("inline_retry_limit") == 0 and
             fallback.get("same_arm_relaunch_limit") == 0 and
             fallback.get("replacement_generation_limit") == 1 and
             fallback.get("max_replacement_pairs") == 4 and
             fallback.get("max_subject_invocations") == 80 and
             fallback.get("base_queue_must_be_fully_claimed_before_fallback_claim") is True,
             "confirmation fallback policy changed")
    _require(fallback.get("reason_codes") == list(REASON_CODES),
             "confirmation replacement reason codes changed")
    _require(request.get("planned_atomic_pairs") == 36 and
             request.get("planned_scientific_calls") == 72 and
             len(request.get("planned_calls", ())) == 72,
             "confirmation call inventory changed")
    artifacts = request.get("artifacts_sha256")
    _require(isinstance(artifacts, dict), "confirmation artifact bindings missing")
    for binding in artifacts.values():
        path = _confirmation_bound_path(repo, batch, binding["path"])
        _require(sha256_file(path) == binding["sha256"], f"artifact changed: {binding['path']}")
    for binding in request.get("launch_components", {}).values():
        path = _repo_path(repo, binding["path"])
        _require(sha256_file(path) == binding["sha256"], f"launch component changed: {binding['path']}")
    frozen = request.get("frozen_inputs_sha256", {})
    expected = {
        "candidate": CANDIDATE_SHA256,
        "control": CONTROL_SHA256,
        "finalized_preregistration": starlette_atomic_pairs.DEFAULT_PREREGISTRATION_SHA256,
        "runner": sha256_file(repo / "tooling/starlette_atomic_pairs.py"),
        "analyzer": sha256_file(repo / "tooling/analyze_starlette_atomic_pairs.py"),
    }
    _require(all(frozen.get(key) == value for key, value in expected.items()),
             "frozen confirmation input hash changed")
    _require(request.get("arms") == [
        {"name": "candidate", "path": CANDIDATE, "sha256": CANDIDATE_SHA256},
        {"name": "control", "path": CONTROL, "sha256": CONTROL_SHA256},
    ], "confirmation arms changed")
    schedule = _read(_repo_path(repo, artifacts["pair_schedule"]["path"]))
    starlette_atomic_pairs.validate_schedule(schedule)
    tasks = {row["id"]: row for row in request["tasks"]}
    _require(set(tasks) == set(schedule["task_ids"]), "confirmation task set changed")
    for task_id, row in tasks.items():
        _require(row["path"] == f"tasks/{task_id}", f"task path changed: {task_id}")
        verified = taskcheck.verify(repo / row["path"], md_filename=None)
        _require(verified["manifest_sha256"] == row["manifest_sha256"],
                 f"task changed: {task_id}")
    arms = {row["name"]: row for row in request["arms"]}
    expected_calls = []
    for pair in schedule["pairs"]:
        prior = None
        for arm_position, arm in enumerate((pair["first_arm"], pair["second_arm"]), 1):
            call_id = f"{pair['pair_id']}-a{arm_position}-{arm}"
            expected_calls.append({
                "arm": arm, "arm_position": arm_position,
                "arm_sha256": arms[arm]["sha256"], "call_id": call_id,
                "depends_on_call_id": prior, "pair_id": pair["pair_id"],
                "planned_call_index": len(expected_calls) + 1,
                "queue_position": pair["queue_position"], "repeat_id": pair["repeat_id"],
                "root_pair_id": pair["root_pair_id"], "task_id": pair["task_id"],
                "task_manifest_sha256": tasks[pair["task_id"]]["manifest_sha256"],
            })
            prior = call_id
    _require(request["planned_calls"] == expected_calls,
             "confirmation planned-call schedule changed")
    runtime = _read(_confirmation_bound_path(repo, batch, artifacts["runtime_manifest"]["path"]))
    _require(runtime.get("model", {}).get("requested") == RUNNER.model and
             runtime.get("model", {}).get("reasoning_effort") == RUNNER.reasoning_effort and
             runtime.get("runner", {}).get("subject_timeout_seconds") == RUNNER.timeout_seconds and
             runtime.get("runner", {}).get("worker_count") == 12 and
             runtime.get("runner", {}).get("max_active_subject_calls") == 12,
             "confirmation runtime changed")
    spec_path = _repo_path(repo, runtime["container"]["contamination_spec_path"])
    _require(sha256_file(spec_path) == runtime["container"]["spec_sha256"],
             "confirmation contamination specification changed")
    report = _read(_confirmation_bound_path(repo, batch, artifacts["prelaunch_report"]["path"]))
    _require(report.get("status") == "PASS" and report.get("live_model_calls") == 0 and
             report.get("sealed_subject_called") is False and report.get("duration_seconds", 61) <= 60 and
             report.get("schedule_sha256") == artifacts["pair_schedule"]["sha256"] and
             report.get("runtime_manifest_sha256") == artifacts["runtime_manifest"]["sha256"],
             "confirmation preflight binding changed")
    return schedule, runtime, report


def run_confirmation_approved(repo: Path, batch: Path, output: Path) -> dict[str, Any]:
    """Launch one approved confirmation; approval is checked before all other work."""

    request_bytes = (batch / "REQUEST.json").read_bytes()
    approval_bytes = (batch / "APPROVED.json").read_bytes()
    approval = json.loads(approval_bytes)
    _require(approval_bytes == _bytes(approval) and
             approval == {"request_sha256": _digest(request_bytes)} and
             not (batch / "APPROVED.json").is_symlink(), "approval hash mismatch")
    batch = _exact_confirmation_path(batch, repo / CONFIRMATION_ROOT, "launch batch")
    output = _exact_confirmation_path(output, repo / CONFIRMATION_OUTPUT, "launch output")
    _confirmation_auth(repo)
    qualification = repo / "qualification/starlette-live-adapter-recovery-r1"
    request = verify_confirmation_prepared(
        repo, batch, output, qualification, require_unapproved=False,
    )
    _require(_bytes(request) == request_bytes, "REQUEST.json changed during approval validation")
    schedule, runtime, report = _validate_confirmation_request(repo, batch, request)
    del report
    expected_output = _repo_path(repo, request["execution"]["execution_output_path"])
    _require(output == expected_output, "confirmation output path changed")
    _require(not output.exists() and not output.is_symlink(), "confirmation output already exists")
    previous_spec = sealed.SPEC
    sealed.SPEC = _repo_path(repo, runtime["container"]["contamination_spec_path"])
    try:
        live_preflight = run_batch.preflight_request(
            _confirmation_execution_request(repo, request, runtime),
            deadline_seconds=PREFLIGHT_SECONDS,
        )
        _require(live_preflight["status"] == "PASS",
                 f"launch runtime preflight failed: {live_preflight.get('failed_checks')}")
        seals = live_preflight["seals"]
        container = runtime["container"]
        _require(set(seals) == set(schedule["task_ids"]) and all(
            sealed._validate_fast_seal(
                seals[task_id], container["image_digests"][task_id],
                container["interpreter_pins"][task_id],
            ) for task_id in schedule["task_ids"]
        ), "confirmation runtime seals changed")
        execution_request = _confirmation_execution_request(repo, request, runtime)
        backend = AtomicLiveBackend(
            RunBatchBackend(repo, output, execution_request, seals), _digest(request_bytes)
        )
        manifest = starlette_atomic_pairs.run_stub(
            output, task_ids=schedule["task_ids"], schedule=schedule, executor=backend,
            synchronize_first_wave=False, live_bindings={
                "approval_sha256": _digest(approval_bytes), "max_live_model_calls": 80,
                "max_replacement_pairs": 4, "planned_live_model_calls": 72,
                "reason_codes": request["retry_and_fallback"]["reason_codes"],
                "request_sha256": _digest(request_bytes),
                "runtime_manifest_sha256": request["artifacts_sha256"]["runtime_manifest"]["sha256"],
                "task_manifest_sha256": request["artifacts_sha256"]["task_manifest"]["sha256"],
            },
        )
        from tooling import analyze_starlette_atomic_pairs
        analysis = analyze_starlette_atomic_pairs.analyze_run_directory(output)
        starlette_atomic_pairs._write_json_once(output / "analysis.json", analysis)
    finally:
        sealed.SPEC = previous_spec
    return {"analysis": analysis, "manifest": manifest}


def execute_schedule(
    output: Path, schedule: Mapping[str, Any], backend: Callable[..., Mapping[str, Any]],
    *, mode: str, request_sha256: str | None = None,
) -> dict[str, Any]:
    _validate_schedule(schedule)
    _require(not output.exists() and not output.is_symlink(), "execution output already exists")
    output.mkdir(parents=True)
    seal = {
        "schema_version": "starlette-live-shakeout-run-seal-v1",
        "adapter_sha256": sha256_file(Path(__file__)),
        "schedule_sha256": _digest(_bytes(schedule)),
        "request_sha256": request_sha256,
        "mode": mode,
    }
    seal_sha = _write(output / "run-seal.json", seal)
    events = _Jsonl(output / "scheduler-events.jsonl")
    attempts_writer = _Jsonl(output / "attempts.jsonl")
    pairs = _Jsonl(output / "pairs.jsonl")
    state_lock = threading.Lock()
    event_lock = threading.Lock()
    active = peak = invocations = sequence = 0
    started = time.monotonic()

    def event(kind: str, active_now: int, **fields: Any) -> None:
        nonlocal sequence
        with event_lock:
            sequence += 1
            events.append({"active_subjects": active_now, "event": kind, "index": sequence,
                           "monotonic_time": time.monotonic(), "run_seal_sha256": seal_sha, **fields})

    def invoke(job: Mapping[str, Any], arm: str, arm_index: int, worker: str) -> dict[str, Any]:
        nonlocal active, peak, invocations
        with state_lock:
            _require(invocations < MAX_CALLS, "subject invocation cap exceeded")
            invocations += 1
            active += 1
            peak = max(peak, active)
            active_now = active
        event("subject_started", active_now, arm=arm, pair_id=job["pair_id"], worker_id=worker)
        begin = time.monotonic()
        try:
            result = dict(backend(job, arm, arm_index, output / "pair-evidence" / job["pair_id"]))
        finally:
            end = time.monotonic()
            with state_lock:
                active -= 1
                active_now = active
            event("subject_finished", active_now, arm=arm, pair_id=job["pair_id"], worker_id=worker)
        result.update({"arm": arm, "arm_index": arm_index, "subject_start_monotonic": begin,
                       "subject_end_monotonic": end, "worker_id": worker})
        return result

    def run_pair(job: Mapping[str, Any], worker: str) -> dict[str, Any]:
        claimed = time.monotonic()
        attempts = []
        for arm_index, arm in enumerate(job["arm_order"], 1):
            attempt = invoke(job, arm, arm_index, worker)
            if (arm_index == 2 and attempt["termination_class"] ==
                    starlette_atomic_pairs.REPLACEABLE_INFRASTRUCTURE_FAILURE):
                attempt.update(starlette_atomic_pairs.classify_termination(
                    starlette_atomic_pairs.LATE_INFRASTRUCTURE_FAILURE,
                    mechanical_reason_code="infrastructure_failure_after_prior_arm",
                ))
            attempts.append(attempt)
            attempts_writer.append({**attempt, "pair_id": job["pair_id"],
                                    "root_pair_id": job["root_pair_id"],
                                    "run_seal_sha256": seal_sha})
            if attempt["termination_class"] == starlette_atomic_pairs.REPLACEABLE_INFRASTRUCTURE_FAILURE:
                break
        eligible = (job.get("generation", 0) == 0 and len(attempts) == 1 and
                    attempts[0]["termination_class"]
                    == starlette_atomic_pairs.REPLACEABLE_INFRASTRUCTURE_FAILURE)
        record = {**job, "generation": job.get("generation", 0), "worker_id": worker,
                  "attempts": attempts, "replacement_eligible": eligible,
                  "pair_claimed_monotonic": claimed, "pair_end_monotonic": time.monotonic(),
                  "run_seal_sha256": seal_sha}
        pairs.append(record)
        return record

    base_jobs = [{**pair, "generation": 0, "replacement_of": None} for pair in schedule["pairs"]]
    with ThreadPoolExecutor(max_workers=WORKER_COUNT) as pool:
        base = list(pool.map(lambda item: run_pair(item[1], f"worker-{item[0]:02d}"),
                             enumerate(base_jobs, 1)))
    eligible = sorted((row for row in base if row["replacement_eligible"]),
                      key=lambda row: row["queue_position"])
    replacement_jobs = [{**row, "pair_id": f"{row['root_pair_id']}-replacement-1",
                         "generation": 1, "replacement_of": row["pair_id"], "attempts": None}
                        for row in eligible[:MAX_REPLACEMENT_PAIRS]]
    with ThreadPoolExecutor(max_workers=WORKER_COUNT) as pool:
        replacements = list(pool.map(
            lambda item: run_pair(item[1], f"worker-{item[0]:02d}"), enumerate(replacement_jobs, 1)
        ))
    events.close(); attempts_writer.close(); pairs.close()
    manifest = {
        "schema_version": "starlette-live-shakeout-execution-v1",
        "mode": mode,
        "live_model_calls": invocations if mode == "live_approved" else 0,
        "planned_pairs": PLANNED_PAIRS,
        "planned_calls": PLANNED_CALLS,
        "actual_subject_invocations": invocations,
        "base_pair_count": len(base),
        "replacement_pair_count": len(replacements),
        "terminal_unreplaced_eligible_count": max(0, len(eligible) - len(replacements)),
        "observed_peak_subjects": peak,
        "duration_seconds": time.monotonic() - started,
        "run_seal_sha256": seal_sha,
        "attempts_sha256": sha256_file(output / "attempts.jsonl"),
        "pairs_sha256": sha256_file(output / "pairs.jsonl"),
        "scheduler_events_sha256": sha256_file(output / "scheduler-events.jsonl"),
    }
    _write(output / "execution-manifest.json", manifest)
    return manifest


def verify_execution(output: Path, *, complete_offline: bool) -> dict[str, Any]:
    manifest = _read(output / "execution-manifest.json")
    seal = _read(output / "run-seal.json")
    _require(manifest["run_seal_sha256"] == sha256_file(output / "run-seal.json"), "run seal mismatch")
    _require(seal["adapter_sha256"] == sha256_file(Path(__file__)), "adapter binding changed")
    _require(manifest["attempts_sha256"] == sha256_file(output / "attempts.jsonl") and
             manifest["pairs_sha256"] == sha256_file(output / "pairs.jsonl") and
             manifest["scheduler_events_sha256"] == sha256_file(output / "scheduler-events.jsonl"),
             "execution evidence hash changed")
    if complete_offline:
        _require(manifest["mode"] == "offline_stub" and manifest["live_model_calls"] == 0 and
                 manifest["actual_subject_invocations"] == 24 and manifest["base_pair_count"] == 12 and
                 manifest["replacement_pair_count"] == 0 and manifest["observed_peak_subjects"] == 12,
                 "offline preflight incomplete")
    return manifest


def qualify(repo: Path, root: Path) -> dict[str, Any]:
    _assert_hashes(repo)
    _require(not root.exists() and not root.is_symlink(), "qualification root exists")
    root.mkdir(parents=True)
    runs = []
    for index in range(1, 4):
        started = time.monotonic()
        run_dir = root / f"preflight-{index:03d}"
        manifest = execute_schedule(run_dir, build_schedule(SEED + index - 1), StubBackend(), mode="offline_stub")
        verify_execution(run_dir, complete_offline=True)
        duration = time.monotonic() - started
        _require(duration <= PREFLIGHT_SECONDS, "offline preflight exceeded 60 seconds")
        runs.append({"run": run_dir.name, "duration_seconds": duration,
                     "manifest_sha256": sha256_file(run_dir / "execution-manifest.json")})
    result = {"schema_version": "starlette-live-shakeout-qualification-v1", "status": "PASS",
              "live_model_calls": 0, "expected_runs": 3, "max_seconds": PREFLIGHT_SECONDS,
              "adapter_sha256": sha256_file(Path(__file__)),
              "prior_qualification_sha256": sha256_file(repo / PRIOR_QUALIFICATION), "runs": runs}
    _write(root / "qualification-manifest.json", result)
    verify_qualification(repo, root)
    return result


def verify_qualification(repo: Path, root: Path) -> dict[str, Any]:
    result = _read(root / "qualification-manifest.json")
    _require(result.get("status") == "PASS" and result.get("live_model_calls") == 0 and
             result.get("expected_runs") == 3 and result.get("max_seconds") == PREFLIGHT_SECONDS and
             result.get("adapter_sha256") == sha256_file(Path(__file__)) and
             result.get("prior_qualification_sha256") == sha256_file(repo / PRIOR_QUALIFICATION),
             "qualification binding changed")
    _require([row["run"] for row in result["runs"]] == [f"preflight-{i:03d}" for i in range(1, 4)],
             "qualification run inventory changed")
    for row in result["runs"]:
        run_dir = root / row["run"]
        _require(0 < row["duration_seconds"] <= 60 and
                 row["manifest_sha256"] == sha256_file(run_dir / "execution-manifest.json"),
                 "qualification run record changed")
        verify_execution(run_dir, complete_offline=True)
    return result


def _preflight(repo: Path, smoke: Callable[..., dict[str, Any]] | None = None) -> dict[str, Any]:
    previous = os.environ.get("MDSEVAL_CODEX_HOME")
    if previous is None:
        os.environ["MDSEVAL_CODEX_HOME"] = str(repo / ".mdseval-codex-home")
    try:
        report = run_batch.preflight_request(_execution_request(repo), require_auth=True, smoke=smoke)
    finally:
        if previous is None:
            del os.environ["MDSEVAL_CODEX_HOME"]
    _require(report["status"] == "PASS" and report["duration_seconds"] <= PREFLIGHT_SECONDS,
             f"runtime preflight failed: {report.get('failed_checks')}")
    report.update({"schema_version": "starlette-live-shakeout-preflight-v1",
                   "live_model_calls": 0, "sealed_subject_called": False})
    return report


def _validate_preflight(report: Mapping[str, Any], repo: Path) -> None:
    _require(report.get("status") == "PASS" and report.get("live_model_calls") == 0 and
             report.get("sealed_subject_called") is False and
             isinstance(report.get("duration_seconds"), (int, float)) and
             math.isfinite(report["duration_seconds"]) and report["duration_seconds"] <= 60,
             "preflight report invalid")
    seals = report.get("seals")
    _require(isinstance(seals, dict) and set(seals) == set(TASK_IDS), "preflight seals incomplete")
    for task_id, seal in seals.items():
        _require(seal.get("seal_schema") == sealed.FAST_SEAL_SCHEMA and
                 sealed._validate_fast_seal(seal, IMAGES[task_id], PINS[task_id]) is True,
                 "preflight seal invalid")


def _request(repo: Path, batch: Path, qualification: Path) -> dict[str, Any]:
    return {
        "schema_version": "starlette-live-shakeout-request-v1",
        "batch_id": BATCH_ID,
        "purpose": "required_once_load_pairing_telemetry_only",
        "planned_pairs": 12,
        "planned_calls": 24,
        "worker_count": 12,
        "inline_retry_limit": 0,
        "same_arm_relaunch_limit": 0,
        "replacement_generation_limit": 1,
        "max_replacement_pairs": 4,
        "max_subject_invocations": 28,
        "subject_timeout_seconds": 900,
        "confirmation_inference_forbidden": True,
        "candidate_tuning_forbidden": True,
        "task_selection_forbidden": True,
        "execution_output_path": LIVE_OUTPUT,
        "artifacts_sha256": {name: sha256_file(batch / name) for name in PACKAGE_FILES if name != "REQUEST.json"},
        "inputs_sha256": {"preregistration": PREREGISTRATION_SHA256, "candidate": CANDIDATE_SHA256,
                          "control": CONTROL_SHA256, "offline_runner": OFFLINE_RUNNER_SHA256,
                          "analyzer": ANALYZER_SHA256, "live_bridge": sha256_file(Path(__file__)),
                          "offline_qualification": PRIOR_QUALIFICATION_SHA256,
                          "bridge_qualification": sha256_file(qualification / "qualification-manifest.json")},
        "approval": {"required_before_any_launch_preflight_output_or_backend": True,
                     "schema": {"request_sha256": "sha256_of_exact_REQUEST.json_bytes"}},
    }


def prepare(repo: Path, batch: Path, qualification: Path, *, smoke: Callable[..., dict[str, Any]] | None = None) -> dict[str, Any]:
    _assert_hashes(repo)
    starlette_atomic_pairs.verify_qualification(
        repo / "qualification/starlette-atomic-pairs", expected_runs=3, max_seconds=60,
        preregistration_sha256=PREREGISTRATION_SHA256,
    )
    verify_qualification(repo, qualification)
    _require(not batch.exists() and not batch.is_symlink(), "batch directory exists")
    task_manifest, schedule = build_task_manifest(repo), build_schedule()
    runtime, reasons, fallback = build_runtime_manifest(repo), build_reason_codes(), build_fallback(schedule)
    preflight = _preflight(repo, smoke)
    batch.mkdir(parents=True)
    for name, value in (("task-manifest.json", task_manifest), ("schedule.json", schedule),
                        ("runtime-manifest.json", runtime), ("replacement-reason-codes.json", reasons),
                        ("fallback-schedule.json", fallback), ("preflight-report.json", preflight)):
        _write(batch / name, value)
    _write(batch / "REQUEST.json", _request(repo, batch, qualification))
    return verify_prepared(repo, batch, qualification, require_unapproved=True)


def verify_prepared(
    repo: Path, batch: Path, qualification: Path, *, require_unapproved: bool,
) -> dict[str, Any]:
    _assert_hashes(repo)
    verify_qualification(repo, qualification)
    expected = set(PACKAGE_FILES) | ({"APPROVED.json"} if not require_unapproved and
                                    (batch / "APPROVED.json").exists() else set())
    _require(batch.is_dir() and not batch.is_symlink() and {p.name for p in batch.iterdir()} == expected,
             "prepared package file set changed")
    if require_unapproved:
        _require(not (batch / "APPROVED.json").exists(), "prepared package is already approved")
    task_manifest, schedule = _read(batch / "task-manifest.json"), _read(batch / "schedule.json")
    runtime = _read(batch / "runtime-manifest.json")
    _require(task_manifest == build_task_manifest(repo), "task manifest changed")
    _validate_schedule(schedule)
    _require(runtime == build_runtime_manifest(repo), "runtime manifest changed")
    _require(_read(batch / "replacement-reason-codes.json") == build_reason_codes(), "reason codes changed")
    _require(_read(batch / "fallback-schedule.json") == build_fallback(schedule), "fallback changed")
    _validate_preflight(_read(batch / "preflight-report.json"), repo)
    request = _read(batch / "REQUEST.json")
    _require(request == _request(repo, batch, qualification), "request binding changed")
    return request


def run_approved(repo: Path, batch: Path, output: Path) -> dict[str, Any]:
    # Security boundary: approval is the first operation.
    request_bytes = (batch / "REQUEST.json").read_bytes()
    approval = json.loads((batch / "APPROVED.json").read_bytes())
    _require(approval == {"request_sha256": _digest(request_bytes)}, "approval hash mismatch")
    _require(batch.resolve() == repo / BATCH_ROOT, "approved batch path changed")
    _require(output.resolve() == repo / LIVE_OUTPUT, "live output path changed")
    qualification = repo / QUALIFICATION_ROOT
    request = verify_prepared(repo, batch, qualification, require_unapproved=False)
    live_preflight = _preflight(repo)
    output = output.resolve()
    backend = RunBatchBackend(repo, output, _execution_request(repo), live_preflight["seals"])
    return execute_schedule(output, _read(batch / "schedule.json"), backend,
                            mode="live_approved", request_sha256=_digest(request_bytes))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=ROOT)
    commands = parser.add_subparsers(dest="command", required=True)
    qualify_parser = commands.add_parser("qualify")
    qualify_parser.add_argument("--root", type=Path, required=True)
    verify_q = commands.add_parser("verify-qualification")
    verify_q.add_argument("--root", type=Path, required=True)
    prepare_parser = commands.add_parser("prepare")
    prepare_parser.add_argument("--batch-dir", type=Path, required=True)
    prepare_parser.add_argument("--qualification-root", type=Path, required=True)
    prepare_confirmation_parser = commands.add_parser("prepare-confirmation")
    prepare_confirmation_parser.add_argument("--batch-dir", type=Path, required=True)
    prepare_confirmation_parser.add_argument("--output-dir", type=Path, required=True)
    prepare_confirmation_parser.add_argument("--qualification-root", type=Path, required=True)
    verify_p = commands.add_parser("verify-prepared")
    verify_p.add_argument("--batch-dir", type=Path, required=True)
    verify_p.add_argument("--require-unapproved", action="store_true")
    run_parser = commands.add_parser("run")
    run_parser.add_argument("--batch-dir", type=Path, required=True)
    run_parser.add_argument("--output-dir", type=Path, required=True)
    confirmation_parser = commands.add_parser("run-confirmation")
    confirmation_parser.add_argument("--batch-dir", type=Path, required=True)
    confirmation_parser.add_argument("--output-dir", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    repo = args.repo_root.resolve()
    try:
        _require(args.repo_root.absolute() == repo and not args.repo_root.is_symlink(),
                 "repo root must use its canonical non-symlink path")
        if args.command == "qualify":
            _require(args.root.resolve() == repo / QUALIFICATION_ROOT, "qualification path changed")
            result = qualify(repo, args.root)
        elif args.command == "verify-qualification":
            result = verify_qualification(repo, args.root)
        elif args.command == "prepare":
            _require(args.batch_dir.resolve() == repo / BATCH_ROOT and
                     args.qualification_root.resolve() == repo / QUALIFICATION_ROOT,
                     "prepared path changed")
            result = prepare(repo, args.batch_dir, args.qualification_root)
        elif args.command == "prepare-confirmation":
            prepare_confirmation(
                repo, args.batch_dir, args.output_dir, args.qualification_root,
            )
            qualification = _read(args.batch_dir / "qualification/qualification-manifest.json")
            preflight = _read(args.batch_dir / "prelaunch-preflight-report.json")
            result = {"request_sha256": sha256_file(args.batch_dir / "REQUEST.json"),
                      "tasks": 12, "atomic_pairs": 36, "planned_scientific_calls": 72,
                      "maximum_invocations": 80, "live_model_calls": 0,
                      "qualification_durations_seconds": [row["duration_seconds"]
                                                           for row in qualification["runs"]],
                      "preflight_duration_seconds": preflight["duration_seconds"]}
        elif args.command == "verify-prepared":
            result = verify_prepared(repo, args.batch_dir, repo / QUALIFICATION_ROOT,
                                     require_unapproved=args.require_unapproved)
        elif args.command == "run":
            result = run_approved(repo, args.batch_dir, args.output_dir)
        else:
            result = run_confirmation_approved(repo, args.batch_dir, args.output_dir)
    except (ShakeoutError, starlette_atomic_pairs.EvidenceError, taskcheck.TaskError,
            run_batch.BatchError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=os.sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
