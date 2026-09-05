"""Runner protocol and common result type."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from ..capture import Redactor
from ..fixtures import PreparedFixture


@dataclass(frozen=True)
class RunResult:
    status: str
    exit_code: int | None
    duration_seconds: float
    timed_out: bool = False
    interrupted: bool = False


class SubjectRunner(Protocol):
    def run(
        self,
        fixture: PreparedFixture,
        artifact_dir: Path,
        timeout_seconds: int,
        redactor: Redactor,
    ) -> RunResult: ...
