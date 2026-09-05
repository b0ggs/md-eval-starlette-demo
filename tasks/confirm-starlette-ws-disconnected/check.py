#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parent
PRIVATE = ROOT / "private"
SEALED_DEPS = Path(os.environ.get("MDSEVAL_SEALED_DEPS", "/sealed-deps"))
HOST_WHEELS = ROOT / "image" / "wheels"
CONFIG = json.loads((ROOT / "checker-config.json").read_text())


def overlay_private(workspace: Path) -> None:
    for source in sorted(PRIVATE.rglob("*")):
        if source.is_file():
            target = workspace / source.relative_to(PRIVATE)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)


def run_pytest(workspace: Path, tests: list[str], timeout: int) -> bool:
    env = os.environ.copy()
    paths = [str(workspace)]
    if SEALED_DEPS.is_dir():
        paths.append(str(SEALED_DEPS))
    else:
        paths.extend(str(path) for path in sorted(HOST_WHEELS.glob("*.whl")))
    env["PYTHONPATH"] = os.pathsep.join(paths)
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


def run_python_probe(workspace: Path, code: str, timeout: int) -> bool:
    env = os.environ.copy()
    paths = [str(workspace)]
    if SEALED_DEPS.is_dir():
        paths.append(str(SEALED_DEPS))
    else:
        paths.extend(str(path) for path in sorted(HOST_WHEELS.glob("*.whl")))
    env["PYTHONPATH"] = os.pathsep.join(paths)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env["PYTHONNOUSERSITE"] = "1"
    try:
        result = subprocess.run(
            [sys.executable, "-c", code],
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


def requirement_passes(
    workspace: Path,
    requirement_id: str,
    tests: list[str],
) -> bool:
    if not run_pytest(workspace, tests, CONFIG["requirement_timeout_seconds"]):
        return False
    probe = CONFIG.get("requirement_probes", {}).get(requirement_id)
    return probe is None or run_python_probe(
        workspace,
        probe,
        CONFIG["requirement_timeout_seconds"],
    )


def score(workspace: Path) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix=CONFIG["task_id"] + "-check-") as temp_name:
        temp = Path(temp_name)
        trial = temp / "trial"
        guard = temp / "guard"
        shutil.copytree(workspace, trial)
        shutil.copytree(workspace, guard)
        overlay_private(trial)
        requirements = {
            key: requirement_passes(trial, key, tests)
            for key, tests in CONFIG["requirements"].items()
        }
        regressions = {
            "G1": run_pytest(
                guard,
                CONFIG["regressions"],
                CONFIG["regression_timeout_seconds"],
            )
        }
    return {
        "requirements": requirements,
        "regressions": regressions,
        "resolved": all((*requirements.values(), *regressions.values())),
    }


def inventory(root: Path) -> tuple[int, str]:
    rows = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            relative = path.relative_to(root).as_posix()
            rows.append(relative + "\0" + hashlib.sha256(path.read_bytes()).hexdigest())
    payload = ("\n".join(rows) + "\n").encode()
    return len(rows), hashlib.sha256(payload).hexdigest()


def source_lock_ok() -> bool:
    lock = json.loads((ROOT / "source-lock.json").read_text())
    failure = json.loads((ROOT / "failure-source.json").read_text())
    public = ROOT / "public"
    reference = ROOT / "reference"
    public_files = {
        path.relative_to(public).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in public.rglob("*")
        if path.is_file()
    }
    reference_files = {
        path.relative_to(reference).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in reference.rglob("*")
        if path.is_file()
    }
    private_files = {
        path.relative_to(PRIVATE).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in PRIVATE.rglob("*")
        if path.is_file()
    }
    changed = {
        path
        for path in public_files | reference_files
        if public_files.get(path) != reference_files.get(path)
    }
    return (
        list(inventory(public))
        == [lock["public_file_count"], lock["public_inventory_sha256"]]
        and list(inventory(reference))
        == [lock["reference_file_count"], lock["reference_inventory_sha256"]]
        and changed == set(lock["solution_paths"])
        and {
            path: public_files.get(path)
            for path in lock["solution_paths"]
        }
        == lock["public_solution_sha256"]
        and {
            path: reference_files.get(path)
            for path in lock["solution_paths"]
        }
        == lock["reference_solution_sha256"]
        and private_files == lock["private_test_sha256"]
        and failure["base_sha"] == lock["base_sha"]
        and failure["fix_sha"] == lock["fix_sha"]
        and not any(
            (ROOT / name).exists()
            for name in (
                "blind",
                "blind.provenance.json",
                "blind-calibration.json",
                "manifest.json",
            )
        )
        and not any(path.is_symlink() for path in ROOT.rglob("*"))
    )


def self_test() -> int:
    public = score(ROOT / "public")
    reference = score(ROOT / "reference")
    source_locked = source_lock_ok()
    valid = (
        source_locked
        and all(value is False for value in public["requirements"].values())
        and all(value is True for value in public["regressions"].values())
        and reference["resolved"] is True
    )
    print(
        json.dumps(
            {
                "public": public,
                "reference": reference,
                "source_lock": source_locked,
                "valid": valid,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0 if valid else 1


def main() -> int:
    if len(sys.argv) == 2 and sys.argv[1] == "--self-test":
        return self_test()
    fallback = {
        "requirements": {key: False for key in CONFIG["requirements"]},
        "regressions": {"G1": False},
        "resolved": False,
    }
    try:
        workspace = Path(sys.argv[1]).resolve()
        result = score(workspace) if workspace.is_dir() else fallback
    except (IndexError, OSError, UnicodeError, ValueError):
        result = fallback
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
