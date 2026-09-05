"""Infrastructure-failure classifier required by the frozen batch runner.

The standalone demonstration does not include the unrelated Scout experiment
engine. The frozen runner imports this pure classifier while validating saved
attempt evidence, so this compatibility module retains only that dependency.
"""

from __future__ import annotations

import errno
import json
from typing import Any


_SPAWN_INFRASTRUCTURE_ERRNOS = frozenset(
    {
        errno.EACCES,
        errno.EAGAIN,
        errno.EMFILE,
        errno.ENFILE,
        errno.ENOENT,
        errno.ENOEXEC,
        errno.ENOMEM,
    }
)

_INFRASTRUCTURE_ERROR_MARKERS = (
    "authentication failed",
    "not authenticated",
    "unauthorized",
    "invalid api key",
    "missing api key",
    "login required",
    "unknown configuration field",
    "failed to load config",
    "invalid configuration",
    "configuration error",
    "service unavailable",
    "temporarily unavailable",
    "server overloaded",
    "rate limit exceeded",
    "failed to connect",
    "connection refused",
    "connection reset",
    "transport error",
    "dns resolution failed",
)


def classify_infrastructure_failure(
    *,
    spawn_error: dict[str, Any] | None,
    timed_out: bool,
    returncode: int | None,
    events_jsonl: str,
    stderr: str,
    final_text: str,
    changed_paths: tuple[str, ...] | list[str],
    untracked: tuple[dict[str, Any], ...] | list[dict[str, Any]],
) -> bool:
    """Narrow, pure pre-output infrastructure classification for replacements."""
    if timed_out or final_text or changed_paths or untracked:
        return False
    if spawn_error is not None:
        return (
            set(spawn_error) == {"type", "message", "errno"}
            and spawn_error["type"]
            in {"FileNotFoundError", "PermissionError", "OSError"}
            and isinstance(spawn_error["message"], str)
            and spawn_error["errno"] in _SPAWN_INFRASTRUCTURE_ERRNOS
            and not events_jsonl
            and not stderr
        )
    if returncode in (0, None):
        return False
    structured_errors: list[str] = []
    saw_agent_output = False
    saw_structured_event = False
    for line in events_jsonl.splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return False
        if not isinstance(event, dict):
            return False
        saw_structured_event = True
        event_type = event.get("type")
        item = event.get("item")
        is_error = event_type in {"error", "turn.failed"} or (
            event_type == "item.completed"
            and isinstance(item, dict)
            and item.get("type") == "error"
        )
        if is_error:
            structured_errors.append(json.dumps(event, sort_keys=True).lower())
        elif event_type not in {"thread.started", "turn.started"}:
            saw_agent_output = True
    if saw_agent_output:
        return False
    error_text = " ".join(structured_errors)
    if not error_text and not saw_structured_event:
        error_text = stderr.lower()
    return any(marker in error_text for marker in _INFRASTRUCTURE_ERROR_MARKERS)
