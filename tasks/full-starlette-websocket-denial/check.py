#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


PRIVATE = Path(__file__).resolve().parent / "private"
SEALED_DEPS = Path("/sealed-deps")
HOST_WHEELS = Path(__file__).resolve().parent / "image" / "wheels"

R1_TESTS = (
    "tests/test_responses.py::test_streaming_response_runs_background_on_websocket_scope",
    "tests/test_websockets.py::test_send_denial_response_with_streaming_response",
)
R2_TESTS = (
    "tests/test_websockets.py::test_send_denial_response_with_file_response",
)


def overlay_private(workspace: Path) -> None:
    for source in sorted(PRIVATE.rglob("*")):
        if source.is_file():
            target = workspace / source.relative_to(PRIVATE)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)


def run_pytest(
    workspace: Path,
    tests: tuple[str, ...],
    *,
    extra: tuple[str, ...] = (),
    timeout: int = 12,
) -> bool:
    env = os.environ.copy()
    dependency_paths = [str(workspace)]
    if SEALED_DEPS.is_dir():
        dependency_paths.append(str(SEALED_DEPS))
    else:
        dependency_paths.extend(str(path) for path in sorted(HOST_WHEELS.glob("*.whl")))
    env["PYTHONPATH"] = os.pathsep.join(dependency_paths)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTEST_DISABLE_PLUGIN_AUTOLOAD"] = "1"
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "-o",
        "addopts=",
        "-p",
        "no:cacheprovider",
        "-p",
        "anyio.pytest_plugin",
        *extra,
        *tests,
    ]
    try:
        result = subprocess.run(
            command,
            cwd=workspace,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def score(workspace: Path) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="starlette-denial-check-") as temp_name:
        temp = Path(temp_name)
        trial = temp / "trial"
        guard = temp / "guard"
        shutil.copytree(workspace, trial)
        shutil.copytree(workspace, guard)
        overlay_private(trial)
        requirements = {
            "R1": run_pytest(trial, R1_TESTS),
            "R2": run_pytest(trial, R2_TESTS),
        }
        # The guard uses the untouched pre-fix tests. Two response tests changed
        # only to add the now-required ASGI scope type in the fix commit, so they
        # are excluded along with all private fix-introduced cases. The remaining
        # response and WebSocket modules provide broad integration coverage.
        regressions = {
            "G1": run_pytest(
                guard,
                ("tests/test_responses.py", "tests/test_websockets.py"),
                extra=(
                    "-k",
                    "not test_streaming_response_stops_if_receiving_http_disconnect "
                    "and not test_streaming_response_on_client_disconnects",
                ),
                timeout=25,
            )
        }
    return {
        "requirements": requirements,
        "regressions": regressions,
        "resolved": all((*requirements.values(), *regressions.values())),
    }


def main() -> int:
    fallback = {
        "requirements": {"R1": False, "R2": False},
        "regressions": {"G1": False},
        "resolved": False,
    }
    try:
        workspace = Path(sys.argv[1]).resolve()
        result = score(workspace) if workspace.is_dir() else fallback
    except (IndexError, OSError, UnicodeError):
        result = fallback
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
