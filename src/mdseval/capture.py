"""Run-event, Git-state, check, and secret-safe artifact capture."""

from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .config import CaseConfig, resolve_within
from .gitutils import run_git
from .processutils import run_process_group

UNTRACKED_CONTENT_LIMIT = 65_536
UNTRACKED_TOTAL_LIMIT = 524_288
CENTRAL_IGNORED_PATH_PARTS = frozenset({"__pycache__", ".pytest_cache"})
CENTRAL_IGNORED_SUFFIXES = (".pyc", ".pyo")
ENV_ASSIGNMENT = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)=(\"[^\"]*\"|'[^']*'|[^\s]+)"
)
SECRET_NAME_TOKEN = re.compile(
    r"(?i)(?:^|_)(?:TOKEN|SECRET|PASSWORD|PASS|KEY|CREDENTIAL)(?:_|$)"
)
ALLOWED_EVENT_TYPES = frozenset(
    {
        "thread.started",
        "turn.started",
        "turn.completed",
        "turn.failed",
        "error",
        "item.started",
        "item.completed",
        "item.updated",
    }
)
ALLOWED_ITEM_TYPES = frozenset(
    {"command_execution", "file_change", "agent_message", "todo_list"}
)
ITEM_EVENT_TYPES = frozenset({"item.started", "item.completed", "item.updated"})
TERMINAL_EVENT_TYPES = frozenset({"turn.completed", "turn.failed"})
USAGE_FIELDS = (
    "input_tokens",
    "cached_input_tokens",
    "cache_write_input_tokens",
    "output_tokens",
    "reasoning_output_tokens",
)


def is_secret_name(name: str) -> bool:
    return bool(SECRET_NAME_TOKEN.search(name))


class Redactor:
    def __init__(self, secret_values: Iterable[str] = ()) -> None:
        self._values = tuple(
            sorted((value for value in secret_values if value), key=len, reverse=True)
        )

    def text(self, value: str) -> str:
        for secret in self._values:
            value = value.replace(secret, "[REDACTED]")
        return ENV_ASSIGNMENT.sub(
            lambda match: (
                f"{match.group(1)}=[REDACTED]"
                if is_secret_name(match.group(1))
                else match.group(0)
            ),
            value,
        )

    def object(self, value: Any) -> Any:
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.object(item) for item in value]
        if isinstance(value, dict):
            result: dict[Any, Any] = {}
            for key, item in value.items():
                safe_key = self.text(key) if isinstance(key, str) else key
                if safe_key in result:
                    base = str(safe_key)
                    suffix = 2
                    while f"{base}#{suffix}" in result:
                        suffix += 1
                    safe_key = f"{base}#{suffix}"
                result[safe_key] = self.object(item)
            return result
        return value

    def bytes(self, value: bytes) -> bytes:
        for secret in self._values:
            value = value.replace(secret.encode("utf-8"), b"[REDACTED]")
        return value


def redact_event_stream(value: str, redactor: Redactor) -> str:
    """Redact JSONL without turning valid records into malformed evidence."""
    safe: list[str] = []
    for line in value.splitlines():
        if not line.strip():
            safe.append(line)
            continue
        try:
            event = json.loads(
                line,
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_json_constant,
            )
        except (json.JSONDecodeError, ValueError):
            safe.append("!MALFORMED! " + redactor.text(line))
        else:
            safe.append(
                json.dumps(
                    redactor.object(event),
                    ensure_ascii=False,
                    separators=(",", ":"),
                )
            )
    return "\n".join(safe) + ("\n" if value.endswith(("\n", "\r")) else "")


@dataclass(frozen=True)
class ParsedEvents:
    valid: bool
    events: tuple[dict[str, Any], ...]
    commands: tuple[dict[str, Any], ...]
    file_changes: tuple[dict[str, Any], ...]
    usage: dict[str, int]
    malformed_lines: tuple[int, ...] = ()


@dataclass(frozen=True)
class EventEvidenceAudit:
    """Fail-closed validation of the Codex JSONL evidence surface."""

    fatal_defects: tuple[str, ...]
    observed_item_types: tuple[str, ...]
    usage: dict[str, int]
    event_count: int

    @property
    def valid(self) -> bool:
        return not self.fatal_defects


@dataclass(frozen=True)
class GitCapture:
    final_head: str
    status: str
    diff: str
    changed_paths: tuple[str, ...]
    untracked: tuple[dict[str, Any], ...]
    unauthorized_commit: bool
    historical_diff: str = ""


@dataclass(frozen=True)
class CheckResult:
    command: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    passed: bool


def _run_git(repo: Path, *args: str, binary: bool = False) -> bytes | str:
    return run_git(repo, *args, binary=binary)


def is_ignored_generated_path(path: str) -> bool:
    parts = Path(path).parts
    return bool(set(parts) & CENTRAL_IGNORED_PATH_PARTS) or path.endswith(
        CENTRAL_IGNORED_SUFFIXES
    )


def _read_bounded(path: Path, remaining: int, redactor: Redactor) -> dict[str, Any]:
    if path.is_symlink():
        return {
            "encoding": "symlink",
            "content": "",
            "truncated": False,
            "raw_bytes_captured": 0,
        }
    limit = max(0, min(UNTRACKED_CONTENT_LIMIT, remaining))
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    truncated = len(data) > limit
    data = data[:limit]
    raw_bytes_captured = len(data)
    data = redactor.bytes(data)
    try:
        content = data.decode("utf-8")
        encoding = "utf-8"
    except UnicodeDecodeError:
        content = base64.b64encode(data).decode("ascii")
        encoding = "base64"
    return {
        "encoding": encoding,
        "content": content,
        "truncated": truncated,
        "raw_bytes_captured": raw_bytes_captured,
    }


def _untracked_patch(entry: dict[str, Any]) -> str:
    path = entry["path"]
    if entry["encoding"] != "utf-8":
        return f"diff --git a/{path} b/{path}\nnew file mode 100644\nBinary file {path} added\n"
    lines = entry["content"].splitlines()
    body = "\n".join(f"+{line}" for line in lines)
    if body:
        body += "\n"
    return (
        f"diff --git a/{path} b/{path}\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        f"+++ b/{path}\n"
        f"@@ -0,0 +1,{len(lines)} @@\n{body}"
    )


def capture_git(repo: Path, baseline_commit: str, redactor: Redactor) -> GitCapture:
    final_head = str(_run_git(repo, "rev-parse", "HEAD")).strip()
    status = redactor.text(
        str(
            _run_git(
                repo,
                "status",
                "--short",
                "--untracked-files=all",
                "--ignored=matching",
            )
        )
    )
    commit_history = {
        line.strip()
        for line in str(_run_git(repo, "rev-list", "--all", "--reflog")).splitlines()
        if line.strip()
    }
    fsck = str(_run_git(repo, "fsck", "--unreachable", "--no-reflogs"))
    dangling_commits = {
        line.split()[-1]
        for line in fsck.splitlines()
        if line.startswith(("unreachable commit ", "dangling commit "))
    }
    unauthorized_commits = (commit_history | dangling_commits) - {baseline_commit}
    tracked_paths_raw = str(
        _run_git(
            repo,
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--name-only",
            "-z",
            baseline_commit,
            "--",
        )
    )
    tracked_paths = [item for item in tracked_paths_raw.split("\0") if item]
    untracked_raw = _run_git(
        repo, "ls-files", "--others", "-z", binary=True
    )
    assert isinstance(untracked_raw, bytes)
    untracked_paths = [
        item.decode("utf-8", errors="surrogateescape")
        for item in untracked_raw.split(b"\0")
        if item
    ]
    historical_paths: set[str] = set()
    historical_diff = ""
    for commit in sorted(unauthorized_commits):
        names = str(
            _run_git(
                repo,
                "diff-tree",
                "--root",
                "--no-commit-id",
                "--name-only",
                "-r",
                commit,
            )
        )
        historical_paths.update(line for line in names.splitlines() if line)
        historical_diff += str(
            _run_git(
                repo,
                "show",
                "--format=",
                "--no-ext-diff",
                "--no-textconv",
                commit,
            )
        )
    entries: list[dict[str, Any]] = []
    remaining = UNTRACKED_TOTAL_LIMIT
    for relative in sorted(untracked_paths):
        safe = Path(relative)
        if safe.is_absolute() or ".." in safe.parts:
            raise ValueError(f"unsafe untracked path: {relative!r}")
        path = repo / safe
        try:
            path.parent.resolve().relative_to(repo.resolve())
        except ValueError as exc:
            raise ValueError(f"untracked parent escapes repository: {relative!r}") from exc
        bounded = _read_bounded(path, remaining, redactor)
        remaining = max(0, remaining - bounded["raw_bytes_captured"])
        if bounded["encoding"] == "utf-8":
            bounded["content"] = redactor.text(bounded["content"])
        entries.append({"path": redactor.text(relative), **bounded})
    tracked_diff = str(
        _run_git(
            repo,
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            baseline_commit,
            "--",
        )
    )
    full_diff = tracked_diff
    for entry in entries:
        full_diff += _untracked_patch(entry)
    full_diff = redactor.text(full_diff)
    changed = sorted(
        {
            redactor.text(path)
            for path in (*tracked_paths, *untracked_paths, *historical_paths)
            if not is_ignored_generated_path(path)
        }
    )
    return GitCapture(
        final_head=final_head,
        status=status,
        diff=full_diff,
        changed_paths=tuple(changed),
        untracked=tuple(entries),
        unauthorized_commit=bool(unauthorized_commits) or final_head != baseline_commit,
        historical_diff=redactor.text(historical_diff),
    )


def _event_command(event: dict[str, Any]) -> dict[str, Any] | None:
    if event.get("type") == "command":
        return {
            "sequence": event.get("_sequence"),
            "command": str(event.get("command", "")),
            "exit_code": event.get("exit_code"),
            "status": event.get("status", "completed"),
            "output": str(event.get("output", "")),
        }
    item = event.get("item")
    if isinstance(item, dict) and item.get("type") in {
        "command_execution",
        "command",
        "shell_command",
    }:
        command = item.get("command") or item.get("cmd") or ""
        if isinstance(command, list):
            command = " ".join(str(part) for part in command)
        return {
            "sequence": event.get("_sequence"),
            "command": str(command),
            "exit_code": item.get("exit_code"),
            "status": item.get("status", event.get("type", "")),
            "output": str(
                item.get("aggregated_output")
                or item.get("output")
                or item.get("stderr")
                or ""
            ),
        }
    return None


def _event_file_change(event: dict[str, Any]) -> dict[str, Any] | None:
    if event.get("type") == "file_change":
        paths = event.get("paths", [])
    else:
        item = event.get("item")
        if not isinstance(item, dict) or item.get("type") not in {
            "file_change",
            "file_changes",
        }:
            return None
        paths = item.get("paths") or item.get("changes") or []
    if isinstance(paths, str):
        paths = [paths]
    normalized: list[str] = []
    for path in paths if isinstance(paths, list) else []:
        if isinstance(path, dict):
            path = path.get("path")
        if isinstance(path, str):
            normalized.append(path)
    return {"sequence": event.get("_sequence"), "paths": normalized}


def parse_event_stream(path: Path) -> ParsedEvents:
    events: list[dict[str, Any]] = []
    malformed: list[int] = []
    for line_number, line in enumerate(
        path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
    ):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            malformed.append(line_number)
            continue
        if not isinstance(value, dict):
            malformed.append(line_number)
            continue
        value = dict(value)
        value["_sequence"] = len(events)
        events.append(value)
    commands = [command for event in events if (command := _event_command(event))]
    changes = [change for event in events if (change := _event_file_change(event))]
    usage = {
        "input_tokens": 0,
        "cached_input_tokens": 0,
        "output_tokens": 0,
        "reasoning_output_tokens": 0,
        "usage_reported": False,
    }
    usage_turns = 0
    complete_usage_turns = 0
    for event in events:
        if event.get("type") != "turn.completed":
            continue
        source = event.get("usage", {})
        if not isinstance(source, dict) or not source:
            continue
        usage_turns += 1
        primary_usage_keys: set[str] = set()
        for key in (
            "input_tokens",
            "cached_input_tokens",
            "output_tokens",
            "reasoning_output_tokens",
        ):
            value = source.get(key, 0)
            if isinstance(value, int) and not isinstance(value, bool):
                usage[key] += value
                if key in {"input_tokens", "output_tokens"} and key in source:
                    primary_usage_keys.add(key)
        if primary_usage_keys == {"input_tokens", "output_tokens"}:
            complete_usage_turns += 1
    usage["usage_reported"] = bool(
        usage_turns and usage_turns == complete_usage_turns
    )
    usage["total_tokens"] = usage["input_tokens"] + usage["output_tokens"]
    return ParsedEvents(
        valid=bool(events) and not malformed,
        events=tuple(events),
        commands=tuple(commands),
        file_changes=tuple(changes),
        usage=usage,
        malformed_lines=tuple(malformed),
    )


class _DuplicateJSONKey(ValueError):
    def __init__(self, key: str) -> None:
        super().__init__(key)
        self.key = key


def _unique_json_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJSONKey(key)
        value[key] = item
    return value


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def _empty_audit_usage() -> dict[str, int]:
    return {
        "input_tokens": 0,
        "cached_input_tokens": 0,
        "cache_write_input_tokens": 0,
        "output_tokens": 0,
        "reasoning_output_tokens": 0,
        "usage_reported": False,
        "total_tokens": 0,
    }


def audit_event_evidence(path: Path) -> EventEvidenceAudit:
    """Validate one Codex JSONL stream without accepting unknown tool surfaces.

    Evidence defects are data, not parser exceptions. The caller can therefore
    preserve a defective stream and deterministically invalidate its attempt.
    """

    defects: list[str] = []
    observed_item_types: set[str] = set()
    usage = _empty_audit_usage()
    events: list[dict[str, Any]] = []

    try:
        raw = path.read_bytes()
    except OSError:
        return EventEvidenceAudit(
            fatal_defects=("unreadable_event_stream",),
            observed_item_types=(),
            usage=usage,
            event_count=0,
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return EventEvidenceAudit(
            fatal_defects=("invalid_utf8_event_stream",),
            observed_item_types=(),
            usage=usage,
            event_count=0,
        )

    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(
                line,
                object_pairs_hook=_unique_json_object,
                parse_constant=_reject_json_constant,
            )
        except _DuplicateJSONKey as exc:
            key = json.dumps(exc.key, ensure_ascii=True)
            defects.append(f"line:{line_number}:duplicate_json_key:{key}")
            continue
        except (json.JSONDecodeError, ValueError):
            defects.append(f"line:{line_number}:malformed_json")
            continue
        if not isinstance(value, dict):
            defects.append(f"line:{line_number}:non_object_event")
            continue

        events.append(value)
        event_type = value.get("type")
        if not isinstance(event_type, str) or not event_type:
            defects.append(f"line:{line_number}:invalid_event_type")
            continue
        if event_type not in ALLOWED_EVENT_TYPES:
            encoded = json.dumps(event_type, ensure_ascii=True)
            defects.append(f"line:{line_number}:unknown_event_type:{encoded}")
            continue

        if event_type in ITEM_EVENT_TYPES:
            item = value.get("item")
            if not isinstance(item, dict):
                defects.append(f"line:{line_number}:invalid_item")
                continue
            item_type = item.get("type")
            if not isinstance(item_type, str) or not item_type:
                defects.append(f"line:{line_number}:invalid_item_type")
                continue
            observed_item_types.add(item_type)
            if item_type not in ALLOWED_ITEM_TYPES:
                encoded = json.dumps(item_type, ensure_ascii=True)
                defects.append(f"line:{line_number}:unknown_item_type:{encoded}")

        if event_type == "turn.completed":
            source = value.get("usage")
            if not isinstance(source, dict) or not source:
                defects.append(f"line:{line_number}:invalid_usage")
                continue
            primary_complete = True
            for key in ("input_tokens", "output_tokens"):
                if key not in source:
                    defects.append(f"line:{line_number}:missing_usage_field:{key}")
                    primary_complete = False
            for key in source:
                if key not in USAGE_FIELDS:
                    encoded = json.dumps(key, ensure_ascii=True)
                    defects.append(
                        f"line:{line_number}:unknown_usage_field:{encoded}"
                    )
            for key in USAGE_FIELDS:
                if key not in source:
                    continue
                amount = source[key]
                if not isinstance(amount, int) or isinstance(amount, bool):
                    defects.append(f"line:{line_number}:non_integer_usage:{key}")
                    if key in {"input_tokens", "output_tokens"}:
                        primary_complete = False
                    continue
                if amount < 0:
                    defects.append(f"line:{line_number}:negative_usage:{key}")
                    if key in {"input_tokens", "output_tokens"}:
                        primary_complete = False
                    continue
                usage[key] += amount
            if primary_complete:
                usage["usage_reported"] = True

    if not events and not defects:
        defects.append("empty_event_stream")

    event_types = [event.get("type") for event in events]
    thread_starts = [
        index for index, event_type in enumerate(event_types) if event_type == "thread.started"
    ]
    turn_starts = [
        index for index, event_type in enumerate(event_types) if event_type == "turn.started"
    ]
    terminals = [
        index for index, event_type in enumerate(event_types) if event_type in TERMINAL_EVENT_TYPES
    ]

    if not thread_starts:
        defects.append("lifecycle:missing_thread_start")
    elif len(thread_starts) != 1:
        defects.append("lifecycle:multiple_thread_starts")
    elif thread_starts[0] != 0:
        defects.append("lifecycle:thread_start_not_first")

    if not turn_starts:
        defects.append("lifecycle:missing_turn_start")
    elif len(turn_starts) != 1:
        defects.append("lifecycle:multiple_turn_starts")

    if not terminals:
        defects.append("lifecycle:missing_terminal")
    elif len(terminals) != 1:
        defects.append("lifecycle:multiple_terminals")
    elif terminals[0] != len(events) - 1:
        defects.append("lifecycle:terminal_not_last")

    if thread_starts and turn_starts and thread_starts[0] >= turn_starts[0]:
        defects.append("lifecycle:start_order")
    if turn_starts and terminals and turn_starts[0] >= terminals[-1]:
        defects.append("lifecycle:terminal_order")

    completed_turns = sum(
        event_type == "turn.completed" for event_type in event_types
    )
    if completed_turns != 1:
        usage["usage_reported"] = False
    usage["total_tokens"] = usage["input_tokens"] + usage["output_tokens"]

    return EventEvidenceAudit(
        fatal_defects=tuple(defects),
        observed_item_types=tuple(sorted(observed_item_types)),
        usage=usage,
        event_count=len(events),
    )


def parse_disposition(final_text: str) -> str | None:
    for line in final_text.splitlines():
        if line.strip():
            value = line.strip()
            return value if value in {"IMPLEMENTED", "NEEDS_CLARIFICATION", "BLOCKED"} else None
    return None


def run_hidden_checks(
    case: CaseConfig, repo: Path, redactor: Redactor
) -> tuple[CheckResult, ...]:
    results: list[CheckResult] = []
    environment = {
        name: os.environ[name]
        for name in ("PATH", "TMPDIR", "TMP", "TEMP", "LANG", "LC_ALL")
        if name in os.environ
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    for command in case.required_post_run_checks:
        arguments = [
            str(repo) if argument == "{repo}" else argument for argument in command
        ]
        process = run_process_group(
            arguments,
            cwd=case.directory,
            input_text=None,
            timeout=min(case.timeout_seconds, 60),
            environment=environment,
        )
        results.append(
            CheckResult(
                command=tuple(
                    "{repo}" if argument == str(repo) else redactor.text(argument)
                    for argument in arguments
                ),
                exit_code=process.returncode if process.returncode is not None else -1,
                stdout=redactor.text(process.stdout),
                stderr=redactor.text(process.stderr),
                passed=process.returncode == 0
                and not process.timed_out
                and not process.interrupted,
            )
        )
    return tuple(results)


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(
            value,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n",
        encoding="utf-8",
    )
