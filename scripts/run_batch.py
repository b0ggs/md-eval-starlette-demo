#!/usr/bin/env python3
"""Queue, run, and verify one- or two-arm task-layout development batches."""
import argparse
import json
import math
import os
import re
import secrets
import shutil
import sys
import tempfile
import threading
import time
from dataclasses import asdict, fields
from pathlib import Path
from typing import Any, Callable
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from mdseval.capture import (Redactor, audit_event_evidence, capture_git,
                             is_secret_name, redact_event_stream)  # noqa: E402
from mdseval.config import RunnerConfig  # noqa: E402
from mdseval.fixtures import audit_final_subject_tree  # noqa: E402
from mdseval.gitutils import init_repository, run_git  # noqa: E402
from mdseval.hashing import sha256_file, tree_sha256  # noqa: E402
from mdseval.processutils import ProcessOutcome, run_process_group  # noqa: E402
from mdseval.runner.codex_cli import (build_codex_command, config_arguments,
                                      isolated_environment)  # noqa: E402
from mdseval.scout import classify_infrastructure_failure  # noqa: E402
from scripts.contain import runtime as sealed  # noqa: E402
from tooling import taskcheck  # noqa: E402
RUNNER = RunnerConfig("codex-cli", "gpt-5.6-sol", "high", "workspace-write", "never",
                      False, True, False, 300, 1)
WRAPPER_PATH = ROOT / "tooling" / "prompts" / "subject-wrapper-v1.txt"
V1_KEYS = {"batch_id", "tasks", "arm", "call_count", "contingent_replacement_call_cap", "runner"}
PREFLIGHT_DEADLINE_SECONDS = 60.0
_EXPOSURE_LOCK = threading.Lock()
BatchError = RuntimeError
def _ensure(condition: bool, message: str) -> None:
    if not condition:
        raise BatchError(message)
def _bytes(value: Any) -> bytes:
    return (taskcheck.canonical(value) + "\n").encode()
def _write_once(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("xb") as stream:
            stream.write(data)
    except FileExistsError as exc:
        raise BatchError(f"exclusive-create collision: {path}") from exc
    except BaseException:
        path.unlink(missing_ok=True)
        raise
def _json(path: Path, *, canonical: bool = True) -> dict[str, Any]:
    _ensure(not path.is_symlink() and path.is_file(), f"missing or unsafe JSON: {path}")
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BatchError(f"malformed JSON: {path}") from exc
    _ensure(isinstance(value, dict) and (not canonical or raw == _bytes(value)),
            f"noncanonical JSON object: {path}")
    return value
def _relative(path: Path) -> str:
    try:
        return path.resolve().relative_to(ROOT).as_posix()
    except ValueError as exc:
        raise BatchError(f"path is outside repository: {path}") from exc
def _resolve(relative: str) -> Path:
    path = (ROOT / relative).resolve()
    _ensure(_relative(path) == relative, f"unsafe repository-relative path: {relative}")
    return path
def _sha(value: Any) -> bool:
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value))
def _runner(value: Any) -> RunnerConfig:
    try:
        if not isinstance(value, dict):
            raise TypeError
        raw = dict(value); raw.pop("container", None)
        runner = RunnerConfig(**raw)
    except TypeError as exc:
        raise BatchError("runner schema is invalid") from exc
    safe = ((runner.type, runner.sandbox, runner.approval_policy)
            == ("codex-cli", "workspace-write", "never")
            and not runner.subagents_enabled and runner.ephemeral
            and not runner.network_for_agent_commands
            and isinstance(runner.timeout_seconds, int) and runner.timeout_seconds > 0
            and not isinstance(runner.timeout_seconds, bool)
            and runner.max_parallel_runs == 1 and not isinstance(runner.max_parallel_runs, bool)
            and all(isinstance(value, str) and value
                    for value in (runner.model, runner.reasoning_effort)))
    _ensure(safe, "runner weakens the development isolation contract")
    return runner
def _container(value: Any, task_ids: set[str], *, require_search_disabled: bool = False) -> dict[str, Any] | None:
    if value is None:
        return None
    images = value.get("image_digests") if isinstance(value, dict) else None; pins = value.get("interpreter_pins") if isinstance(value, dict) else None
    valid = (isinstance(value, dict) and frozenset(value) in sealed.CONTAINER_KEYSETS
             and isinstance(images, dict) and isinstance(pins, dict) and set(images) == set(pins) == task_ids
             and _sha(value.get("spec_sha256")) and all(isinstance(item, str)
             and re.fullmatch(r"sha256:[0-9a-f]{64}", item) for item in images.values())
             and all(isinstance(item, str) and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", item)
                     for item in pins.values()) and sealed.container_web_search_valid(value, require_search_disabled))
    _ensure(valid, "runner.container schema or task binding is invalid")
    return value
def _request(batch_id: str, tasks: list[Path], arms: list[tuple[str, Path]], *,
        md_filename: str = "CODER.md", task_order_seed: int | None = None,
        runner: RunnerConfig = RUNNER, container: dict[str, Any] | None = None) -> dict[str, Any]:
    _ensure(bool(taskcheck.TASK_ID.fullmatch(batch_id)) and bool(tasks) and len(arms) in {1, 2}
            and len({task.name for task in tasks}) == len(tasks) and all(taskcheck.TASK_ID.fullmatch(task.name) for task in tasks),
            "batch id, tasks, or arm count is invalid")
    _ensure(all(not task.is_symlink() and _relative(task.resolve()) == f"tasks/{task.name}"
                for task in tasks), "task paths must be canonical repository tasks")
    md_filename = taskcheck._md_filename(md_filename)
    seed = secrets.randbits(64) if task_order_seed is None else task_order_seed
    _ensure(isinstance(seed, int) and not isinstance(seed, bool) and seed >= 0,
            "task order seed must be a nonnegative integer")
    container = _container(container, {task.name for task in tasks},
                           require_search_disabled=container is not None)
    task_rows = [{"id": task.name, "manifest_sha256": taskcheck.verify(
        task, md_filename=None)["manifest_sha256"]} for task in tasks]
    arm_rows = []
    for name, source in arms:
        if source.is_symlink():
            raise BatchError("arm labels/files are invalid")
        source = source.resolve()
        if (not taskcheck.TASK_ID.fullmatch(name) or not source.is_file()
                or not _relative(source).startswith("controls/")):
            raise BatchError("arm labels/files are invalid")
        _ensure(name not in {"n", "null"} or not source.stat().st_size,
                "null arm file must be zero bytes")
        arm_rows.append({"name": name, "path": _relative(source), "sha256": sha256_file(source)})
    _ensure(len({row["name"] for row in arm_rows}) == len(arm_rows),
            "arm labels must be distinct")
    task_rows = taskcheck._batch_task_order(task_rows, seed)
    runner_row = asdict(_runner(asdict(runner)))
    if container is not None:
        runner_row["container"] = container
    nominal = 3 * len(task_rows) * len(arm_rows)
    replacement_cap = len(task_rows) * len(arm_rows)
    request = {"schema_version": 3, "batch_id": batch_id, "tasks": task_rows, "arms": arm_rows,
               "call_count": nominal, "replacement_call_cap": replacement_cap,
               "max_total_calls": nominal + replacement_cap, "md_filename": md_filename,
               "task_order_seed": seed, "runner": runner_row}
    taskcheck._validate_batch_request_v3(request, batch_id, {1, 2})
    return request

def _preflight_failure(started: float, name: str, exc: BaseException,
                       monotonic: Callable[[], float] = time.monotonic) -> dict[str, Any]:
    return {"status": "FAIL", "duration_seconds": max(0.0, monotonic() - started),
            "failed_checks": [name], "errors": {name: f"{type(exc).__name__}: {exc}"},
            "seals": {}}

def preflight_request(request: dict[str, Any], *, require_auth: bool = True,
        deadline_seconds: float = PREFLIGHT_DEADLINE_SECONDS,
        monotonic: Callable[[], float] = time.monotonic,
        smoke: Callable[..., dict[str, Any]] | None = None,
        started: float | None = None) -> dict[str, Any]:
    """Run the bounded schema-v3 mechanical preflight without writing evidence."""
    started = monotonic() if started is None else started
    deadline = started + deadline_seconds
    failed: list[str] = []
    errors: dict[str, str] = {}
    seals: dict[str, dict[str, Any]] = {}

    def fail(name: str, exc: BaseException | str) -> None:
        if name not in failed:
            failed.append(name)
        errors[name] = str(exc) if isinstance(exc, str) else f"{type(exc).__name__}: {exc}"

    def remaining(name: str) -> bool:
        if monotonic() < deadline:
            return True
        fail("deadline", f"global {deadline_seconds:g}-second preflight deadline expired during {name}")
        return False

    container: dict[str, Any] | None = None
    try:
        taskcheck._validate_batch_request_v3(request, str(request.get("batch_id", "")), {1, 2})
        runner = _runner(request.get("runner"))
        task_ids = {row["id"] for row in request["tasks"]}
        container = _container(request["runner"].get("container"), task_ids,
                               require_search_disabled=True)
        if require_auth:
            _ensure(container is not None, "schema v3 execution requires a sealed container")
    except (BatchError, taskcheck.TaskError, TypeError, KeyError) as exc:
        fail("request_shape", exc)
        runner = None

    if not failed:
        for row in request["tasks"]:
            name = f"task:{row['id']}:manifest"
            if not remaining(name):
                break
            try:
                task = _resolve(f"tasks/{row['id']}")
                verified = taskcheck.verify(task, md_filename=None)
                _ensure(verified["manifest_sha256"] == row["manifest_sha256"],
                        "request-bound task hash changed")
            except (BatchError, taskcheck.TaskError, OSError) as exc:
                fail(name, exc)
        for arm in request["arms"]:
            name = f"arm:{arm['name']}:hash"
            if not remaining(name):
                break
            try:
                path = _resolve(arm["path"])
                _ensure(not path.is_symlink() and path.is_file()
                        and sha256_file(path) == arm["sha256"],
                        "request-bound arm hash changed")
            except (BatchError, OSError) as exc:
                fail(name, exc)

    # require_auth=False is the existing offline unit-test seam. The CLI never
    # exposes it, and all static request/task/arm checks above still run.
    if not failed and not require_auth:
        duration = max(0.0, monotonic() - started)
        if duration > deadline_seconds:
            fail("deadline", f"global {deadline_seconds:g}-second preflight deadline expired")
        return {"status": "PASS" if not failed else "FAIL", "duration_seconds": duration,
                "failed_checks": failed, "errors": errors, "seals": seals}

    codex_home: Path | None = None
    spec: dict[str, Any] | None = None
    if not failed and remaining("contamination_spec"):
        try:
            _ensure(container is not None and sha256_file(sealed.SPEC) == container["spec_sha256"],
                    "contamination specification hash changed")
            raw_spec = json.loads(sealed.SPEC.read_text(encoding="utf-8"))
            _ensure(isinstance(raw_spec, dict) and set(raw_spec) == {row["id"] for row in request["tasks"]},
                    "contamination specification task set differs from request")
            _ensure(all(raw_spec[row["id"]].get("interpreter_pin")
                        == container["interpreter_pins"][row["id"]] for row in request["tasks"]),
                    "contamination specification interpreter pin differs from request")
            spec = raw_spec
        except (BatchError, OSError, UnicodeError, json.JSONDecodeError, KeyError) as exc:
            fail("contamination_spec", exc)
    if not failed and remaining("auth_source"):
        try:
            codex_home = Path(_auth_home())
            with (codex_home / "auth.json").open("rb") as stream:
                _ensure(bool(stream.read(1)), "isolated auth source is unreadable or empty")
        except (BatchError, OSError) as exc:
            fail("auth_source", exc)

    if not failed:
        groups: dict[tuple[str, str], list[str]] = {}
        assert container is not None and spec is not None and codex_home is not None
        for row in request["tasks"]:
            task_id = row["id"]
            pair = (container["image_digests"][task_id], container["interpreter_pins"][task_id])
            groups.setdefault(pair, []).append(task_id)
        smoke = smoke or sealed.fast_smoke
        for (image, pin), ids in sorted(groups.items()):
            name = f"runtime:{image}@{pin}"
            if not remaining(name):
                break
            try:
                seal = smoke(image, pin, sorted(ids), codex_home, deadline)
                _ensure(isinstance(seal, dict)
                        and seal.get("seal_schema") == sealed.FAST_SEAL_SCHEMA
                        and seal.get("image_digest") == image
                        and seal.get("interpreter_pin") == pin
                        and seal.get("task_ids") == sorted(ids)
                        and seal.get("spec_sha256") == container["spec_sha256"],
                        "runtime smoke returned an incorrectly bound compact seal")
                for task_id in ids:
                    seals[task_id] = seal
            except (BatchError, OSError, RuntimeError, TimeoutError, ValueError) as exc:
                fail(name, exc)
            if not remaining(name):
                break

    duration = max(0.0, monotonic() - started)
    if duration > deadline_seconds:
        fail("deadline", f"global {deadline_seconds:g}-second preflight deadline expired")
    return {"status": "PASS" if not failed else "FAIL", "duration_seconds": duration,
            "failed_checks": failed, "errors": errors, "seals": seals}

def queue_request(batch_id: str, tasks: list[Path], arms: list[tuple[str, Path]],
        runs_root: Path = ROOT / "runs" / "dev-v2", *, md_filename: str = "CODER.md",
        task_order_seed: int | None = None, runner: RunnerConfig = RUNNER,
        container: dict[str, Any] | None = None, require_auth: bool = True) -> Path:
    started = time.monotonic()
    request = _request(batch_id, tasks, arms, md_filename=md_filename,
                       task_order_seed=task_order_seed, runner=runner, container=container)
    preflight = preflight_request(request, require_auth=require_auth, started=started)
    _ensure(preflight["status"] == "PASS",
            "preflight failed: " + ", ".join(preflight["failed_checks"]))
    path = runs_root / batch_id / "REQUEST.json"
    data = _bytes(request)
    if path.exists():
        _ensure(path.read_bytes() == data, "existing REQUEST.json differs; evidence is immutable")
    else:
        _write_once(path, data)
    return path
def _approved(batch: Path) -> tuple[dict[str, Any], int]:
    request_path = batch / "REQUEST.json"
    request = _json(request_path)
    approval = _json(batch / "APPROVED.json", canonical=False)
    _ensure(set(approval) == {"request_sha256"}
            and approval["request_sha256"] == sha256_file(request_path),
            "APPROVED.json request hash mismatch")
    if set(request) == V1_KEYS:
        tasks, arm = request.get("tasks"), request.get("arm")
        valid = (request.get("batch_id") == batch.name and isinstance(tasks, list) and bool(tasks)
                 and isinstance(arm, dict) and set(arm) == {"name", "path", "sha256"}
                 and isinstance(arm.get("name"), str) and taskcheck.TASK_ID.fullmatch(arm["name"])
                 and isinstance(arm.get("path"), str) and arm["path"].startswith("controls/")
                 and _sha(arm.get("sha256"))
                 and all(isinstance(row, dict) and set(row) == {"task_id", "task_dir", "manifest_sha256"}
                         and isinstance(row["task_id"], str) and taskcheck.TASK_ID.fullmatch(row["task_id"])
                         and row["task_dir"] == f"tasks/{row['task_id']}" and _sha(row["manifest_sha256"])
                         for row in tasks)
                 and len({row["task_id"] for row in tasks}) == len(tasks)
                 and request.get("call_count") == 3 * len(tasks)
                 and request.get("contingent_replacement_call_cap") == len(tasks)
                 and request.get("runner") == asdict(RUNNER))
        _ensure(valid, "v1 REQUEST schema or binding is invalid")
        return request, 1
    if request.get("schema_version") == 3:
        taskcheck._validate_batch_request_v3(request, batch.name, {1, 2})
        version = 3
    else:
        taskcheck._validate_batch_request(request, batch.name, {1, 2})
        version = 2
    _runner(request.get("runner"))
    _container(request["runner"].get("container"), {row["id"] for row in request["tasks"]},
               require_search_disabled=version == 3 and request["runner"].get("container") is not None)
    return request, version
def _launch_record(batch: Path, task_id: str, container: dict[str, Any], manifest_sha256: str, section14: bool = False) -> dict[str, Any]:
    paths = [batch / "preflight" / kind / f"{task_id}.{suffix}" for kind, suffix in
             (("host", "jsonl"), ("container", "jsonl"), ("environment", "json"))]
    files = [item for path in paths for item in (path, path.with_suffix(path.suffix + ".stderr"))]
    for path in files:
        _ensure(not path.is_symlink() and path.is_file(), f"missing sealed preflight evidence: {path}")
        relative = _relative(path); run_git(ROOT, "ls-files", "--error-unmatch", "--", relative)
        run_git(ROOT, "diff", "--quiet", "HEAD", "--", relative)
    def summary(path: Path) -> dict[str, Any]:
        try: rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        except (UnicodeError, json.JSONDecodeError) as exc: raise BatchError("malformed probe event stream") from exc
        _ensure(bool(rows) and all(isinstance(row, dict) for row in rows) and rows[-1].get("check") == "summary", "invalid probe event stream")
        return rows[-1]
    host, probe, environment = summary(paths[0]), summary(paths[1]), _json(paths[2]); evidence_manifest = environment.get("task_manifest_sha256") if section14 else (environment.get("task_manifest_sha256") or json.loads(environment.get("taskcheck", {}).get("stdout", ""))["manifest_sha256"])
    common = {"task_id": task_id, "image_digest": container["image_digests"][task_id],
              "spec_sha256": container["spec_sha256"]}
    _ensure(evidence_manifest == manifest_sha256 and all(row.get(key) == value for row in (host, probe, environment)
                for key, value in common.items()), "sealed preflight binding mismatch")
    spec_ids = sorted(container["image_digests"])
    _ensure(not section14 or all(row.get("spec_task_ids") == spec_ids for row in (host, probe, environment)), "probe task-id set differs from request container task keys")
    host_na = (host.get("status") == "N/A" and isinstance(host.get("reason"), str)
               and bool(host["reason"].strip()) and isinstance(host.get("absence_evidence"), (dict, list))
               and bool(host["absence_evidence"]) and type(host.get("contamination_count")) is type(host.get("failure_count")) is int and host["contamination_count"] == host["failure_count"] == 0); host_red = (host.get("status") == "EXPECTED_RED" and (not section14 or type(host.get("contamination_count")) is type(host.get("failure_count")) is int and host["contamination_count"] > 0 and host["failure_count"] == 0))
    policy = next((row for row in map(json.loads, paths[1].read_text().splitlines())
                   if row.get("check") == "runtime_policy_identity"), {})
    _ensure((host_red or section14 and host_na)
            and probe.get("status") == "ALL_GREEN"
            and environment.get("status") == "ALL_GREEN" and policy.get("status") == "PASS"
            and environment.get("interpreter_pin") == container["interpreter_pins"][task_id]
            and environment.get("runtime_security_sha256") == probe.get("runtime_security_sha256")
            and policy.get("identity", {}).get("subject") == environment.get("identity"),
            "sealed preflight did not pass")
    return sealed.bind_web_search_evidence({"files": {_relative(path): sha256_file(path) for path in files},
            "runtime_security_sha256": probe["runtime_security_sha256"], "policy_sha256": probe["policy_sha256"], "identity": environment["identity"]}, container, policy)
def _ledger(batch: Path, *, required: bool = False) -> tuple[dict[str, str], dict[str, str]]:
    rows = taskcheck._read_chain(batch / "evidence-ledger.jsonl", "evidence ledger", required=required)
    attempts: dict[str, str] = {}
    dispositions: dict[str, str] = {}
    for number, row in enumerate(rows, 1):
        if "type" not in row:
            attempt = row.get("attempt")
            parts = attempt.split("/") if isinstance(attempt, str) else []
            valid = (set(row) == {"attempt", "manifest_sha256", "prev_sha256"}
                     and len(parts) == 3 and all(taskcheck.TASK_ID.fullmatch(part) for part in parts[:2])
                     and re.fullmatch(r"attempt-[1-9][0-9]*", parts[2])
                     and _sha(row.get("manifest_sha256")) and attempt not in attempts)
            _ensure(valid, f"invalid attempt ledger row at line {number}")
            attempts[attempt] = row["manifest_sha256"]
        else:
            key = f"{row.get('task_id')}/{row.get('arm')}"
            valid = (set(row) == {"type", "task_id", "arm", "sha256", "prev_sha256"}
                     and row.get("type") == "disposition" and taskcheck.TASK_ID.fullmatch(str(row.get("task_id", "")))
                     and taskcheck.TASK_ID.fullmatch(str(row.get("arm", "")))
                     and _sha(row.get("sha256")) and key not in dispositions)
            _ensure(valid, f"invalid disposition ledger row at line {number}")
            dispositions[key] = row["sha256"]
    return attempts, dispositions
def _auth_home() -> str:
    value = os.environ.get("MDSEVAL_CODEX_HOME")
    auth = Path(value).expanduser() / "auth.json" if value else None
    _ensure(bool(auth) and not auth.is_symlink() and auth.is_file() and bool(auth.stat().st_size),
            "MDSEVAL_CODEX_HOME must contain a nonempty non-symlink auth.json")
    return str(auth.parent)
def _auth_secret_values(codex_home: str) -> tuple[str, ...]:
    path = Path(codex_home) / "auth.json"
    if path.is_symlink() or not path.is_file():
        return ()
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        return ()
    secrets_found: set[str] = set()
    def visit(item: Any, secret_context: bool = False) -> None:
        if isinstance(item, dict):
            for key, child in item.items():
                visit(child, secret_context or isinstance(key, str) and is_secret_name(key))
        elif isinstance(item, list):
            for child in item:
                visit(child, secret_context)
        elif secret_context and isinstance(item, str) and item:
            secrets_found.add(item)
    visit(value)
    return tuple(sorted(secrets_found, key=len, reverse=True))
def _expose(task: Path, batch_id: str) -> None:
    path = task.parent / "exposures.jsonl"
    with _EXPOSURE_LOCK:
        rows = taskcheck._verify_exposures(path)
        events = [row for row in rows if row["task_id"] == task.name]
        _ensure(not any(row["event"] == "retired" for row in events),
                f"retired task cannot launch: {task.name}")
        if not events:
            taskcheck._append_chain(path, {"task_id": task.name, "event": "exposed",
                                    "batch_id": batch_id, "reason": None}, "exposures ledger")
def _workspace(task: Path, arm: bytes, parent: Path, md_filename: str) -> tuple[Path, str]:
    workspace = parent / "workspace"
    shutil.copytree(task / "public", workspace)
    (workspace / md_filename).write_bytes(arm)
    init_repository(workspace)
    for command in (("config", "user.name", "MD Eval"), ("config", "user.email", "mdseval@invalid.local"),
                    ("add", "--all"), ("commit", "-q", "-m", "baseline")):
        run_git(workspace, *command)
    return workspace, str(run_git(workspace, "rev-parse", "HEAD")).strip()
def _reserve(path: Path, intent: dict[str, Any]) -> None:
    try:
        path.mkdir(parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise BatchError(f"exclusive-create collision: {path}") from exc
    _write_once(path / "intent.json", _bytes(intent))
def _checker(task: Path, workspace: Path) -> tuple[dict[str, Any], bool, float]:
    with tempfile.TemporaryDirectory(prefix="final-tree-") as temporary:
        clean = Path(temporary) / "tree"
        shutil.copytree(workspace, clean, ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        started = time.monotonic()
        first, raw = taskcheck.run_checker(task / "check.py", clean)
        second, raw_two = taskcheck.run_checker(task / "check.py", clean)
        return first, first == second and raw == raw_two, time.monotonic() - started
def _attempt_manifest(attempt: Path, ledger: Path | None = None) -> str:
    target = attempt / "attempt-manifest.json"
    files = {path.relative_to(attempt).as_posix(): sha256_file(path)
             for path in sorted(attempt.rglob("*")) if path.is_file() and path.name != "attempt-manifest.json"}
    if ledger is None:
        manifest = _json(target)
        _ensure(set(manifest) == {"files", "created"} and manifest["files"] == files,
                f"attempt evidence differs from manifest: {attempt}")
    else:
        _write_once(target, _bytes({"files": files, "created": time.time()}))
        taskcheck._append_chain(ledger, {"attempt": attempt.relative_to(ledger.parent).as_posix(),
                                        "manifest_sha256": sha256_file(target)}, "evidence ledger")
    return sha256_file(target)
def _attempt(task: Path, request: dict[str, Any], arm: dict[str, str], ordinal: int,
        batch: Path, process_runner: Callable[..., ProcessOutcome], codex_home: str,
        preflight_seal: dict[str, Any] | None = None, *,
        subject_invocation_observer: Callable[[], None] | None = None) -> bool:
    container = request["runner"].get("container")
    verified = taskcheck.verify(task, md_filename=(
        None if request.get("schema_version") == 3 or container else request["md_filename"]))
    expected = next(row["manifest_sha256"] for row in request["tasks"] if row["id"] == task.name)
    arm_path = _resolve(arm["path"])
    _ensure(verified["manifest_sha256"] == expected and sha256_file(arm_path) == arm["sha256"],
            "approved task manifest or arm hash changed")
    md_filename = request["md_filename"]
    runner = _runner(request["runner"])
    if container and request.get("schema_version") == 3:
        _ensure(isinstance(preflight_seal, dict)
                and preflight_seal.get("seal_schema") == sealed.FAST_SEAL_SCHEMA
                and preflight_seal.get("image_digest") == container["image_digests"][task.name]
                and preflight_seal.get("interpreter_pin") == container["interpreter_pins"][task.name]
                and task.name in preflight_seal.get("task_ids", []),
                "missing or incorrectly bound run-level fast-preflight seal")
        seal = preflight_seal
    else:
        seal = (_launch_record(batch, task.name, container, expected,
                               "comparability_note" in request) if container else None)
    wrapper = WRAPPER_PATH.read_text(encoding="utf-8").replace("{md_filename}", md_filename)
    wrapper_sha = taskcheck.sha256_bytes(wrapper.encode())
    destination = batch / task.name / arm["name"] / f"attempt-{ordinal}"
    intent = {"task": task.name, "arm": arm["name"], "ordinal": ordinal,
              "task_manifest_sha256": expected, "arm_sha256": arm["sha256"],
              "md_filename": md_filename, "wrapper_sha256": wrapper_sha, "runner": request["runner"]}
    if container:
        intent.update({"container": container, "container_preflight": seal})
    redactor = Redactor(_auth_secret_values(codex_home))
    with tempfile.TemporaryDirectory(prefix="mdseval-attempt-") as temporary:
        workspace, baseline = _workspace(task, arm_path.read_bytes(), Path(temporary), md_filename)
        _reserve(destination, intent)
        _write_once(destination / "wrapper.txt", wrapper.encode())
        final_temp = Path(temporary) / "final.txt"
        command = build_codex_command(runner, workspace, final_temp)
        command[command.index("--cd"):command.index("--cd")] = config_arguments(
            sealed.SUBJECT_SHELL_CONFIGS)
        marker = 'project_doc_fallback_filenames=["CODER.md"]'
        _ensure(command.count(marker) == 1, "frozen project-document argument is missing")
        command[command.index(marker)] = (
            f"project_doc_fallback_filenames={json.dumps([md_filename], separators=(',', ':'))}")
        _write_once(destination / "launch.json", _bytes({**intent, "started": time.time(), "command": command}))
        _expose(task, request["batch_id"])
        attempt_started = time.monotonic()
        try:
            if container:
                if subject_invocation_observer is not None:
                    subject_invocation_observer()
                subject_result = sealed.subject(
                    command, workspace, final_temp, wrapper, runner.timeout_seconds,
                    Path(codex_home), container["image_digests"][task.name],
                    container["interpreter_pins"][task.name], seal)
                _ensure(isinstance(subject_result, sealed.SubjectOutcome),
                        "sealed subject returned an invalid outcome")
                outcome = subject_result.process
                duration = subject_result.duration_seconds
            else:
                if subject_invocation_observer is not None:
                    subject_invocation_observer()
                outcome = process_runner(
                    command, cwd=workspace, input_text=wrapper,
                    timeout=runner.timeout_seconds,
                    environment=isolated_environment(codex_home))
                duration = time.monotonic() - attempt_started
        except Exception as exc:
            if container: _write_once(destination / "build-rejected.json", _bytes({"error": redactor.text(f"{type(exc).__name__}: {exc}")})); raise BatchError("BUILD_REJECTED: sealed runtime prelaunch failed") from exc
            if not isinstance(exc, OSError): raise
            _write_once(destination / "pre-spawn.json", _bytes({"error": f"{type(exc).__name__}: {exc}"})); raise BatchError("subject process did not spawn; preserved as pre-spawn failure") from exc
        attempt_elapsed = time.monotonic() - attempt_started
        final = final_temp.read_text(encoding="utf-8", errors="replace") if final_temp.is_file() else ""
        raw_events = Path(temporary) / "subject-events.raw.jsonl"
        raw_events.write_text(outcome.stdout, encoding="utf-8")
        event_audit = audit_event_evidence(raw_events)
        events = destination / "events.jsonl"
        _write_once(events, redact_event_stream(outcome.stdout, redactor).encode())
        _write_once(destination / "stderr.txt", redactor.text(outcome.stderr).encode())
        _write_once(destination / "final.txt", redactor.text(final).encode())
        persisted_audit = audit_event_evidence(events)
        if persisted_audit.valid != event_audit.valid or persisted_audit.usage != event_audit.usage:
            event_audit = type(event_audit)(
                fatal_defects=(*event_audit.fatal_defects,
                               "redacted_event_evidence_mismatch"),
                observed_item_types=event_audit.observed_item_types,
                usage=event_audit.usage,
                event_count=event_audit.event_count,
            )
        usage = event_audit.usage
        infra_events = outcome.stdout
        stderr_lower = outcome.stderr.lower()
        if "401 unauthorized" in stderr_lower and "token_expired" in stderr_lower:
            infra_events += ("" if not infra_events or infra_events.endswith("\n") else "\n")
            infra_events += '{"type":"error","message":"unauthorized token_expired"}\n'
        tokens = {"input_tokens": usage["input_tokens"], "cached_input_tokens": usage["cached_input_tokens"],
                  "output_tokens": usage["output_tokens"], "reasoning_tokens": usage["reasoning_output_tokens"],
                  "total_tokens": usage["total_tokens"], "usage_reported": usage["usage_reported"]}
        requirements = _json(task / "manifest.json")["requirements"]
        blank = {"requirements": {key: False for key in requirements}, "regressions": {}, "resolved": False}
        event_reason = ("fatal event evidence defect: " + ";".join(event_audit.fatal_defects)
                        if event_audit.fatal_defects else "")
        invalid, scoreable, changes, final_hash, checker_duration = event_reason, True, (), "", 0.0
        try:
            audit_final_subject_tree(workspace)
        except Exception as exc:
            invalid, scoreable, checked = f"final tree audit failed: {type(exc).__name__}: {exc}", False, blank
            _write_once(destination / "capture.json", _bytes({"error": invalid}))
            _write_once(destination / "diff.patch", b"")
        else:
            try:
                final_hash = tree_sha256(workspace)
                capture = capture_git(workspace, baseline, redactor)
                changes = capture.changed_paths
                _write_once(destination / "capture.json", _bytes(asdict(capture)))
                _write_once(destination / "diff.patch", capture.diff.encode())
                provider_error_item_only = (
                    len(event_audit.fatal_defects) == 1
                    and re.fullmatch(r'line:\d+:unknown_item_type:"error"',
                                     event_audit.fatal_defects[0]) is not None)
                if (event_audit.valid or provider_error_item_only) and not outcome.interrupted and classify_infrastructure_failure(
                        spawn_error=None, timed_out=outcome.timed_out, returncode=outcome.returncode,
                        events_jsonl=infra_events, stderr=outcome.stderr, final_text=final,
                        changed_paths=capture.changed_paths, untracked=capture.untracked):
                    _write_once(destination / "infra-invalid.json", _bytes({"error": "runner infrastructure failure"}))
                    return False
                if not invalid and (outcome.returncode != 0 or outcome.timed_out
                                    or outcome.interrupted):
                    invalid = ("subject process did not complete cleanly: "
                               f"returncode={outcome.returncode},timed_out={outcome.timed_out},"
                               f"interrupted={outcome.interrupted}")
                md_path = workspace / md_filename
                contract = workspace / ".issue-contract.md"
                if (md_path.is_symlink() or not md_path.is_file() or sha256_file(md_path) != arm["sha256"]
                        or contract.is_symlink() or not contract.is_file()
                        or sha256_file(contract) != sha256_file(task / "public" / ".issue-contract.md")
                        or capture.unauthorized_commit):
                    invalid = "protected input changed or subject committed"
            except Exception as exc:
                invalid, scoreable, checked = f"capture failed: {type(exc).__name__}: {exc}", False, blank
            try:
                if container:
                    checked, deterministic, checker_duration, checker_evidence = sealed.checker(
                        task, workspace, container["image_digests"][task.name],
                        container["interpreter_pins"][task.name], Path(codex_home), seal["identity"])
                    _write_once(destination / "checker-runtime.json", _bytes(checker_evidence))
                else:
                    checked, deterministic, checker_duration = _checker(task, workspace)
                taskcheck.verify(task)
                if not deterministic:
                    invalid = "checker result nondeterministic"
            except Exception as exc:
                invalid, scoreable, checked = f"checker unscoreable: {type(exc).__name__}: {exc}", False, blank
        failed = [key for key, passed in checked["requirements"].items() if not passed]
        omissions = {key: taskcheck._probe_fires(workspace, requirements[key]["omission_probe"], key)
                     if scoreable else False for key in failed}
        target_changes = {key: [path for path in requirements[key]["target_paths"] if path in changes]
                          for key in failed}
        result = {"task_id": task.name, "arm": arm["name"], "ordinal": ordinal,
                  "duration_seconds": duration,
                  "attempt_elapsed_seconds": attempt_elapsed,
                  "checker_duration_seconds": checker_duration,
                  "final_tree_sha256": final_hash, "task_manifest_sha256": expected,
                  "arm_sha256": arm["sha256"], "md_filename": md_filename,
                  "wrapper_sha256": wrapper_sha, "runner": request["runner"],
                  "returncode": outcome.returncode, "timed_out": outcome.timed_out,
                  "interrupted": outcome.interrupted, "requirements": checked["requirements"],
                  "regressions": checked["regressions"], "resolved": checked["resolved"],
                  "omissions": omissions, "omission_only": bool(failed) and all(omissions.values())
                  and all(checked["regressions"].values()), "target_path_changes": target_changes,
                  "event_fatal_defects": list(event_audit.fatal_defects),
                  "observed_item_types": list(event_audit.observed_item_types),
                  "valid": not invalid, "invalid_reason": invalid}
        if container:
            result.update({"container": container, "container_preflight": seal, "token_totals": tokens})
        _write_once(destination / "checker.json", _bytes(checked))
        _write_once(destination / "result.json", _bytes(result))
        _attempt_manifest(destination, batch / "evidence-ledger.jsonl")
        return True
def _retired(task: Path) -> list[str]:
    rows = taskcheck._read_chain(task.parent / "exposures.jsonl", "exposures ledger")
    retired = {row["task_id"] for row in rows if row.get("event") == "retired"}
    result = []
    meta = _json(task / "task-meta.json", canonical=False) if (task / "task-meta.json").is_file() else {}
    parent = meta.get("parent_task_id")
    while parent in retired and parent not in result:
        result.append(parent)
        path = task.parent / parent / "task-meta.json"
        parent = _json(path, canonical=False).get("parent_task_id") if path.is_file() else None
    return result
def _state(base: Path) -> tuple[list[dict[str, Any]], int, int, int]:
    dirs = sorted(base.glob("attempt-*"), key=lambda path: int(path.name.split("-")[-1])) if base.exists() else []
    _ensure(not any(os.path.lexists(path / "build-rejected.json") for path in dirs), "BUILD_REJECTED sealed attempt cannot be retried")
    ambiguous = [path for path in dirs if (path / "launch.json").is_file()
                 and not (path / "pre-spawn.json").exists()
                 and not (path / "attempt-manifest.json").exists()
                 and not (path / "infra-invalid.json").is_file()]
    _ensure(not ambiguous, "unfinished exposed attempt cannot be classified or retried: "
            + ", ".join(path.name for path in ambiguous))
    anchored, _ = _ledger(base.parents[1])
    results = []
    for path in dirs:
        manifest = path / "attempt-manifest.json"
        if manifest.is_file():
            relative = path.relative_to(base.parents[1]).as_posix()
            digest = sha256_file(manifest)
            _ensure(relative in anchored,
                    f"finalized attempt is absent from evidence ledger: {relative}")
            _ensure(anchored[relative] == digest, f"unanchored finalized attempt: {relative}")
            results.append(_json(path / "result.json"))
    infra = sum((path / "infra-invalid.json").is_file()
                and not (path / "attempt-manifest.json").exists() for path in dirs)
    launched = sum((path / "launch.json").is_file() and not (path / "pre-spawn.json").exists()
                   for path in dirs)
    ordinal = max([int(path.name.split("-")[-1]) for path in dirs] or [0]) + 1
    return results, infra, ordinal, launched
def _container_echo(attempt: Path, request: dict[str, Any]) -> bool:
    paths=[attempt/name for name in ("intent.json","launch.json","result.json")]; expected=request["runner"].get("container"); return expected is None or paths[0].is_file() and all((not path.exists() and not path.is_symlink()) or ((row:=_json(path)).get("container")==expected and row.get("runner")==request["runner"]) for path in paths)
def _fast_seal_echo(attempt: Path, request: dict[str, Any], task_id: str) -> dict[str, Any] | None:
    container = request["runner"].get("container")
    if request.get("schema_version") != 3 or container is None:
        return None
    rows = [_json(path) for name in ("intent.json", "launch.json", "result.json")
            if (path := attempt / name).is_file() and not path.is_symlink()]
    _ensure(bool(rows), f"missing v3 attempt evidence: {attempt}")
    values = [row.get("container_preflight") for row in rows]
    _ensure(all(isinstance(value, dict) and value == values[0] for value in values),
            f"fast-preflight seal echo mismatch: {attempt}")
    seal = values[0]
    _ensure(seal.get("seal_schema") == sealed.FAST_SEAL_SCHEMA
            and seal.get("image_digest") == container["image_digests"][task_id]
            and seal.get("interpreter_pin") == container["interpreter_pins"][task_id]
            and seal.get("spec_sha256") == container["spec_sha256"]
            and task_id in seal.get("task_ids", []),
            f"fast-preflight seal binding mismatch: {attempt}")
    _ensure(
        sealed._validate_fast_seal(
            seal,
            container["image_digests"][task_id],
            container["interpreter_pins"][task_id],
        ),
        f"fast-preflight seal is not valid under the current runtime policy: {attempt}",
    )
    return seal
def _disposition(task: Path, arm: dict[str, str], results: list[dict[str, Any]], infra: int,
        request: dict[str, Any], *, legacy: bool = False) -> dict[str, Any]:
    if not legacy:
        rendered = WRAPPER_PATH.read_text(encoding="utf-8").replace("{md_filename}", request["md_filename"])
        wrapper_sha = taskcheck.sha256_bytes(rendered.encode())
        mismatch = any(row.get("runner") != request["runner"] or row.get("arm") != arm["name"]
                       or row.get("arm_sha256") != arm["sha256"]
                       or row.get("md_filename") != request["md_filename"]
                       or row.get("wrapper_sha256") != wrapper_sha
                       or (request["runner"].get("container") is not None
                           and row.get("container") != request["runner"]["container"]) for row in results)
        _ensure(not mismatch, "attempt runner/arm/wrapper evidence mismatch")
    requirement_count = len(_json(task / "manifest.json")["requirements"])
    passed = sum(sum(row["requirements"].values()) for row in results)
    q = passed / (3 * requirement_count) if requirement_count else 0.0
    s = sum(row["resolved"] for row in results)
    invalid = ("second infrastructure failure" if infra >= 2 else next(
        (row["invalid_reason"] for row in results if not row["valid"]), ""))
    wrong = any(row["valid"] and not row["resolved"] and not row["omission_only"] for row in results)
    label = ("invalid" if invalid else "wrong-failure-mode" if wrong else "promising"
             if 0.55 <= q <= 0.90 and s in {1, 2} else "ceiling"
             if s == 3 or (s in {1, 2} and q > 0.90) else "floor")
    value = {"q": q, "s": s, "label": label, "fidelity_note": invalid[:200]}
    ancestors = _retired(task)
    value.update({"task_id": task.name, "attempts": [row["ordinal"] for row in results],
                  "retired_ancestors": ancestors, "task_denominator": 1 + len(ancestors)})
    if not legacy:
        value.update({"arm": arm["name"], "runner": request["runner"]})
        if request["runner"].get("container") is not None:
            names = ("input_tokens", "cached_input_tokens", "output_tokens", "reasoning_tokens", "total_tokens")
            value.update({"attempt_metrics": [{"ordinal": row["ordinal"], "duration_seconds": row["duration_seconds"], "token_totals": row["token_totals"]} for row in results], "token_totals": {key: sum(row["token_totals"][key] for row in results) for key in names},
                          "token_evidence_complete": all(row["token_totals"]["usage_reported"] for row in results)})
    return value
def _write_disposition(
        batch: Path, task: Path, arm: dict[str, str], results: list[dict[str, Any]],
        infra: int, request: dict[str, Any]) -> None:
    path = batch / task.name / arm["name"] / "disposition.json"
    expected = _disposition(task, arm, results, infra, request)
    _, anchored = _ledger(batch)
    key = f"{task.name}/{arm['name']}"
    if key in anchored:
        _ensure(path.is_file() and _json(path) == expected and anchored[key] == sha256_file(path),
                f"disposition ledger hash mismatch: {key}")
        return
    _ensure(not path.exists() or _json(path) == expected,
            f"orphan disposition differs from recomputation: {task.name}/{arm['name']}")
    if not path.exists():
        _write_once(path, _bytes(expected))
    digest = sha256_file(path)
    taskcheck._append_chain(batch / "evidence-ledger.jsonl",
                            {"type": "disposition", "task_id": task.name, "arm": arm["name"], "sha256": digest},
                            "evidence ledger")
def _launched_calls(batch: Path) -> int:
    return sum(path.name == "launch.json" and not (path.parent / "pre-spawn.json").exists()
               for path in batch.rglob("launch.json"))
def launch(batch_id: str, runs_root: Path = ROOT / "runs" / "dev-v2",
        process_runner: Callable[..., ProcessOutcome] = run_process_group,
        require_auth: bool = True) -> None:
    batch = runs_root / batch_id
    request, version = _approved(batch)
    _ensure(version == 3, "live launch requires REQUEST schema v3")
    container = request["runner"].get("container")
    codex_home: str | None = None
    invocation_seals: dict[str, dict[str, Any]] | None = None
    for task_index, row in enumerate(request["tasks"]):
        task = _resolve(f"tasks/{row['id']}")
        verified = taskcheck.verify(task, md_filename=(
            None if version == 3 or request["runner"].get("container") else request["md_filename"]))
        _ensure(verified["manifest_sha256"] == row["manifest_sha256"],
                f"request-bound task hash changed: {task.name}")
        if version == 2 and container:
            _launch_record(batch, task.name, container, row["manifest_sha256"],
                           "comparability_note" in request)
        for round_index in range(3):
            arms = request["arms"] if (task_index + round_index) % 2 == 0 else list(reversed(request["arms"]))
            for arm in arms:
                base = batch / task.name / arm["name"]
                results, infra, ordinal, _ = _state(base)
                while len(results) <= round_index and infra < 2:
                    _ensure(_launched_calls(batch) < request["max_total_calls"],
                            "approved maximum subject-call count exhausted")
                    if version == 3 and invocation_seals is None:
                        preflight = preflight_request(request, require_auth=require_auth)
                        _ensure(preflight["status"] == "PASS",
                                "preflight failed: " + ", ".join(preflight["failed_checks"]))
                        invocation_seals = preflight["seals"]
                        codex_home = (_auth_home() if require_auth
                                      else str(Path(tempfile.gettempdir())))
                    assert codex_home is not None
                    seal = invocation_seals.get(task.name) if invocation_seals is not None else None
                    usable = _attempt(task, request, arm, ordinal, batch, process_runner,
                                      codex_home, seal)
                    attempt = base / f"attempt-{ordinal}"
                    ordinal += 1
                    if usable:
                        results.append(_json(attempt / "result.json"))
                    else:
                        infra += 1
        for arm in request["arms"]:
            results, infra, _, _ = _state(batch / task.name / arm["name"])
            _write_disposition(batch, task, arm, results, infra, request)
def _verify_attempts(batch: Path, *, allow_dispositions: bool) -> None:
    attempts, dispositions = _ledger(batch, required=True)
    _ensure(not dispositions or allow_dispositions, "v1 evidence ledger contains v2 rows")
    manifests = {path.parent.relative_to(batch).as_posix(): path for path in batch.rglob("attempt-manifest.json")}
    _ensure(set(manifests) == set(attempts), "finalized attempt set differs from evidence ledger")
    for relative, path in manifests.items():
        _ensure(sha256_file(path) == attempts[relative], f"attempt manifest hash mismatch: {relative}")
        _attempt_manifest(path.parent)
def _verify_event_evidence(attempt: Path, result: dict[str, Any], *, hardened: bool) -> None:
    audit = audit_event_evidence(attempt / "events.jsonl")
    _ensure(audit.valid or not result.get("valid"),
            f"result accepts fatal event evidence: {attempt}")
    if hardened:
        _ensure(result.get("event_fatal_defects") == list(audit.fatal_defects)
                and result.get("observed_item_types") == list(audit.observed_item_types),
                f"result/event policy evidence mismatch: {attempt}")
    totals = result.get("token_totals")
    if isinstance(totals, dict):
        expected = {"input_tokens": audit.usage["input_tokens"],
                    "cached_input_tokens": audit.usage["cached_input_tokens"],
                    "output_tokens": audit.usage["output_tokens"],
                    "reasoning_tokens": audit.usage["reasoning_output_tokens"],
                    "total_tokens": audit.usage["total_tokens"],
                    "usage_reported": audit.usage["usage_reported"]}
        _ensure(totals == expected, f"result/event token totals mismatch: {attempt}")
    if hardened and result.get("valid"):
        _ensure(result.get("returncode") == 0 and result.get("timed_out") is False
                and result.get("interrupted") is False and audit.usage["usage_reported"],
                f"valid attempt lacks a clean terminal process and usage: {attempt}")
    if hardened:
        duration = result.get("duration_seconds")
        elapsed = result.get("attempt_elapsed_seconds")
        _ensure(isinstance(duration, (int, float)) and not isinstance(duration, bool)
                and math.isfinite(float(duration)) and duration >= 0,
                f"invalid subject duration evidence: {attempt}")
        _ensure(isinstance(elapsed, (int, float)) and not isinstance(elapsed, bool)
                and math.isfinite(float(elapsed)) and elapsed >= duration,
                f"invalid attempt elapsed evidence: {attempt}")
def verify_batch(batch: Path) -> None:
    request, version = _approved(batch)
    legacy = version == 1
    _verify_attempts(batch, allow_dispositions=not legacy)
    tasks = ([{"id": row["task_id"], "manifest_sha256": row["manifest_sha256"]}
              for row in request["tasks"]] if legacy else request["tasks"])
    arms = [request["arm"]] if legacy else request["arms"]
    container = None if legacy else request["runner"].get("container")
    md_filename = None if legacy or container or version == 3 else request["md_filename"]
    for arm in arms:
        _ensure(sha256_file(_resolve(arm["path"])) == arm["sha256"],
                f"request-bound arm hash changed: {arm['name']}")
    anchored: dict[str, str] = {}
    if not legacy:
        _, anchored = _ledger(batch, required=True)
        expected_keys = {f"{row['id']}/{arm['name']}" for row in tasks for arm in arms}
        files = {path.parent.relative_to(batch).as_posix(): path
                 for path in batch.rglob("disposition.json")}
        _ensure(set(anchored) == expected_keys and set(files) == expected_keys,
                "disposition evidence set differs from request")
    for row in tasks:
        task = _resolve(f"tasks/{row['id']}")
        verified = taskcheck.verify(task, md_filename=md_filename)
        _ensure(verified["manifest_sha256"] == row["manifest_sha256"],
                f"request-bound task hash changed: {task.name}")
        seal = (_launch_record(batch, task.name, container, row["manifest_sha256"],
                               "comparability_note" in request)
                if version == 2 and container else None)
        fast_seal: dict[str, Any] | None = None
        for arm in arms:
            base = batch / task.name / arm["name"]
            results, infra, _, launched = _state(base)
            if version == 3:
                for result in results:
                    attempt = base / f"attempt-{result['ordinal']}"
                    _verify_event_evidence(attempt, result, hardened=True)
            _ensure(all(_container_echo(attempt, request) for attempt in base.glob("attempt-*")), f"container echo evidence mismatch: {task.name}")
            if version == 3 and container:
                echoed = [_fast_seal_echo(attempt, request, task.name)
                          for attempt in base.glob("attempt-*")]
                echoed = [item for item in echoed if item is not None]
                _ensure(bool(echoed) and all(item == echoed[0] for item in echoed),
                        f"fast-preflight seal differs across attempts: {task.name}")
                if fast_seal is None:
                    fast_seal = echoed[0]
                _ensure(all(item == fast_seal for item in echoed)
                        and all(item.get("container_preflight") == fast_seal for item in results),
                        f"container preflight evidence mismatch: {task.name}")
            else:
                _ensure(not container or all(item.get("container_preflight") == seal for item in results),
                        f"container preflight evidence mismatch: {task.name}")
            path = base / "disposition.json"
            expected = _disposition(task, arm, results, infra, request, legacy=legacy)
            valid = (len(results) >= 3 or infra >= 2) and path.is_file() and _json(path) == expected
            if not legacy:
                valid = valid and sha256_file(path) == anchored[f"{task.name}/{arm['name']}"]
                _ensure(launched <= 4, f"replacement call cap exceeded: {task.name}/{arm['name']}")
            _ensure(valid, f"missing or inconsistent disposition: {task.name}/{arm['name']}")
    if not legacy:
        _ensure(_launched_calls(batch) <= request["max_total_calls"],
                "approved maximum subject-call count exceeded")
def _add_request_arguments(command: argparse.ArgumentParser) -> None:
    command.add_argument("batch_id")
    command.add_argument("--task", action="append", type=Path, required=True)
    command.add_argument("--arm", action="append", nargs=2,
                         metavar=("NAME", "PATH"), required=True)
    command.add_argument("--md-filename", default="CODER.md")
    command.add_argument("--task-order-seed", type=int)
    command.add_argument("--container", type=json.loads)
    for field in fields(RunnerConfig):
        default = getattr(RUNNER, field.name)
        command.add_argument("--" + field.name.replace("_", "-"), default=default,
                             type=json.loads if isinstance(default, bool) else type(default))
    command.add_argument("--runs-root", type=Path, default=ROOT / "runs" / "dev-v2")

def _cli_request(args: argparse.Namespace) -> tuple[RunnerConfig, list[tuple[str, Path]]]:
    runner = RunnerConfig(*(getattr(args, field.name) for field in fields(RunnerConfig)))
    return runner, [(name, Path(path)) for name, path in args.arm]

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("preflight", "queue"):
        _add_request_arguments(commands.add_parser(name))
    for name in ("run", "verify"):
        command = commands.add_parser(name)
        command.add_argument("batch_id")
        command.add_argument("--runs-root", type=Path, default=ROOT / "runs" / "dev-v2")
    args = parser.parse_args(argv)
    if args.command == "preflight":
        started = time.monotonic()
        try:
            runner, arms = _cli_request(args)
            request = _request(args.batch_id, args.task, arms,
                               md_filename=args.md_filename,
                               task_order_seed=args.task_order_seed,
                               runner=runner, container=args.container)
            result = preflight_request(request, started=started)
        except (BatchError, taskcheck.TaskError, OSError, ValueError) as exc:
            result = _preflight_failure(started, "request_shape", exc)
        public = {key: result[key] for key in ("status", "duration_seconds", "failed_checks")}
        if result.get("errors"):
            public["errors"] = result["errors"]
        print(json.dumps(public, sort_keys=True, separators=(",", ":")))
        return 0 if result["status"] == "PASS" else 1
    try:
        if args.command == "queue":
            runner, arms = _cli_request(args)
            path = queue_request(args.batch_id, args.task, arms, args.runs_root, md_filename=args.md_filename,
                                 task_order_seed=args.task_order_seed, runner=runner, container=args.container)
            print(json.dumps({"request": str(path), "request_sha256": sha256_file(path)}, sort_keys=True))
        elif args.command == "run":
            launch(args.batch_id, args.runs_root)
        else:
            verify_batch(args.runs_root / args.batch_id)
        return 0
    except (BatchError, taskcheck.TaskError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
if __name__ == "__main__":
    raise SystemExit(main())
