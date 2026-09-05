"""Small process-group runner with timeout and interruption cleanup."""

from __future__ import annotations

import errno
import os
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ProcessOutcome:
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    interrupted: bool


def _stop_group(process: subprocess.Popen[str]) -> None:
    def send(sig: int) -> bool:
        try:
            os.killpg(process.pid, sig)
        except OSError as exc:
            if exc.errno in {errno.ESRCH, errno.EPERM}:
                return False
            raise
        return True

    # Do not use signal 0 as a liveness probe: macOS can report EPERM for it
    # while an interrupted process group is already being reaped. Always make
    # a best-effort TERM/KILL pass and make cleanup itself non-failing.
    send(signal.SIGTERM)
    time.sleep(0.05)
    try:
        send(signal.SIGKILL)
    except OSError:
        # This is a cleanup boundary. The process is still reaped below, and
        # an unusual platform-specific signalling error must not discard the
        # INTERRUPTED/TIMEOUT evidence that the caller is about to persist.
        pass


def run_process_group(
    command: list[str],
    *,
    cwd: Path,
    input_text: str | None,
    timeout: int,
    environment: dict[str, str],
) -> ProcessOutcome:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdin=subprocess.PIPE if input_text is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        env=environment,
        start_new_session=True,
    )
    timed_out = False
    interrupted = False
    try:
        stdout, stderr = process.communicate(input_text, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _stop_group(process)
        try:
            stdout, stderr = process.communicate(timeout=1)
        except BaseException:
            stdout, stderr = "", ""
    except BaseException:
        interrupted = True
        _stop_group(process)
        try:
            stdout, stderr = process.communicate(timeout=1)
        except BaseException:
            stdout, stderr = "", ""
    finally:
        # A leader may exit while background children in its group survive.
        _stop_group(process)
    return ProcessOutcome(
        returncode=None if timed_out or interrupted else process.returncode,
        stdout=stdout or "",
        stderr=stderr or "",
        timed_out=timed_out,
        interrupted=interrupted,
    )
