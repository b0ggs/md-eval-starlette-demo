"""Deterministic subject adapter used only for tests and the local demo."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..capture import Redactor
from ..config import resolve_within
from ..fixtures import PreparedFixture
from .base import RunResult


@dataclass(frozen=True)
class FakePlan:
    final_text: str = "IMPLEMENTED\nFake implementation completed.\n"
    changes: dict[str, str] = field(default_factory=dict)
    events: tuple[dict[str, Any], ...] = ()
    exit_code: int = 0
    duration_seconds: float = 0.01
    timed_out: bool = False
    interrupted: bool = False
    malformed_event_line: str | None = None


class FakeAdapter:
    def __init__(self, plans: dict[str, FakePlan] | None = None) -> None:
        self.plans = plans or {}

    def run(
        self,
        fixture: PreparedFixture,
        artifact_dir: Path,
        timeout_seconds: int,
        redactor: Redactor,
    ) -> RunResult:
        plan = self.plans.get(fixture.case.id, FakePlan())
        artifact_dir.mkdir(parents=True, exist_ok=True)
        applied = False
        lines: list[str] = []
        for event in plan.events:
            if event.get("type") == "file_change" and not applied:
                self._apply_changes(fixture.repo, plan.changes)
                applied = True
            lines.append(json.dumps(redactor.object(event), sort_keys=True))
        if not applied:
            self._apply_changes(fixture.repo, plan.changes)
        if plan.malformed_event_line is not None:
            lines.append(redactor.text(plan.malformed_event_line))
        if not any(event.get("type") == "turn.completed" for event in plan.events):
            lines.append(
                json.dumps(
                    {
                        "type": "turn.completed",
                        "usage": {
                            "input_tokens": 100,
                            "cached_input_tokens": 25,
                            "output_tokens": 20,
                            "reasoning_output_tokens": 5,
                        },
                    },
                    sort_keys=True,
                )
            )
        (artifact_dir / "events.jsonl").write_text(
            "\n".join(lines) + ("\n" if lines else ""), encoding="utf-8"
        )
        (artifact_dir / "stderr.txt").write_text("", encoding="utf-8")
        (artifact_dir / "final.txt").write_text(
            redactor.text(plan.final_text), encoding="utf-8"
        )
        status = "TIMEOUT" if plan.timed_out else "INTERRUPTED" if plan.interrupted else "COMPLETED"
        return RunResult(
            status=status,
            exit_code=None if plan.timed_out else plan.exit_code,
            duration_seconds=min(plan.duration_seconds, timeout_seconds),
            timed_out=plan.timed_out,
            interrupted=plan.interrupted,
        )

    @staticmethod
    def _apply_changes(repo: Path, changes: dict[str, str]) -> None:
        for relative, content in changes.items():
            path = resolve_within(repo, relative, "fake change")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
