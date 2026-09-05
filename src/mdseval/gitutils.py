"""Hardened Git subprocess helpers for evaluator-controlled operations."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

SAFE_PROCESS_ENV_NAMES = (
    "PATH",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LC_ALL",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
)


def safe_process_environment() -> dict[str, str]:
    environment = {
        name: os.environ[name] for name in SAFE_PROCESS_ENV_NAMES if name in os.environ
    }
    environment.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def git_command(*args: str) -> list[str]:
    return [
        "git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        f"core.hooksPath={os.devnull}",
        *args,
    ]


def run_git(
    repo: Path,
    *args: str,
    binary: bool = False,
    timeout: int = 30,
) -> bytes | str:
    process = subprocess.run(
        git_command(*args),
        cwd=repo,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=safe_process_environment(),
        timeout=timeout,
    )
    if process.returncode:
        raise RuntimeError(
            f"git {' '.join(args)} failed: "
            f"{process.stderr.decode('utf-8', errors='replace').strip()}"
        )
    if binary:
        return process.stdout
    return process.stdout.decode("utf-8", errors="replace")


def init_repository(repo: Path) -> None:
    run_git(repo, "init", "-q", "--template=")
