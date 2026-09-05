#!/usr/bin/env python3
"""Standalone task-layout-v2/v3 admission and integrity tool (stdlib only)."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

TASK_ID = re.compile(r"^[a-z0-9-]{1,40}$")
JUNK_NAMES = {".git", "__pycache__"}
MANIFEST_KEYS_V2 = {
    "task_id", "files", "salience", "parent_task_id", "gate",
    "requirements", "created",
}
MANIFEST_KEYS_V3 = MANIFEST_KEYS_V2 | {"layout_version"}
MD_FILENAME = re.compile(r"^[A-Za-z0-9._-]+$")
BATCH_REQUEST_KEYS = {
    "batch_id", "tasks", "arms", "call_count", "replacement_call_cap",
    "max_total_calls", "md_filename", "task_order_seed", "runner",
}
BATCH_REQUEST_V3_KEYS = BATCH_REQUEST_KEYS | {"schema_version"}
COMPARABILITY_NOTE = "The 600-second subject timeout creates a comparability boundary with prior 300-second batches."
MECHANISM_FACT_KEYS = {
    "fact", "public_support_path", "required_md_substrings",
    "predicted_bare_behavior", "affected_requirement",
}
DECOY_NAMES = ("wrong-layer", "wrong-verification")


class TaskError(RuntimeError):
    """A task or integrity contract was violated."""


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _paths(root: Path) -> list[Path]:
    if not root.is_dir() or root.is_symlink():
        raise TaskError(f"directory is missing or unsafe: {root}")
    result: list[Path] = []
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root)
        if path.is_symlink():
            raise TaskError(f"symlink is forbidden: {relative}")
        if any(part in JUNK_NAMES for part in relative.parts) or path.suffix == ".pyc":
            raise TaskError(f"junk path is forbidden: {relative}")
        if path.is_file():
            result.append(path)
    return result


def tree_sha256(root: Path) -> str:
    lines = [f"{p.relative_to(root).as_posix()}\t{sha256_file(p)}\n" for p in _paths(root)]
    return sha256_bytes("".join(lines).encode("utf-8"))


def _task_file_hashes(task: Path) -> dict[str, str]:
    return {
        path.relative_to(task).as_posix(): sha256_file(path)
        for path in _paths(task)
        if path.relative_to(task).as_posix() != "manifest.json"
    }


def _json_file(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TaskError(f"invalid {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise TaskError(f"{label} must be a JSON object")
    return value


def _safe_relative(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise TaskError(f"{label} must be a nonempty relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or value != path.as_posix():
        raise TaskError(f"{label} is not a safe normalized path: {value!r}")
    return value


def _normalize_section(value: Any, label: str) -> dict[str, bool]:
    if not isinstance(value, dict):
        raise TaskError(f"checker {label} must be an object")
    normalized: dict[str, bool] = {}
    for key, item in value.items():
        if not isinstance(key, str) or not key:
            raise TaskError(f"checker {label} keys must be nonempty strings")
        if isinstance(item, bool):
            normalized[key] = item
        elif isinstance(item, dict) and isinstance(item.get("passed"), bool):
            normalized[key] = item["passed"]
        else:
            raise TaskError(f"checker {label}.{key} is not a boolean result")
    return normalized


def _parse_result(raw: str) -> dict[str, Any]:
    lines = [line for line in raw.splitlines() if line.strip()]
    if not lines:
        raise TaskError("checker produced no JSON line")
    try:
        value = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        raise TaskError(f"checker last stdout line is invalid JSON: {exc}") from exc
    if not isinstance(value, dict) or not {"requirements", "regressions", "resolved"} <= set(value):
        raise TaskError("checker result lacks requirements/regressions/resolved")
    requirements = _normalize_section(value["requirements"], "requirements")
    regressions = _normalize_section(value["regressions"], "regressions")
    resolved = value["resolved"]
    if not isinstance(resolved, bool):
        raise TaskError("checker resolved must be a boolean")
    if resolved != all((*requirements.values(), *regressions.values())):
        raise TaskError("checker resolved disagrees with normalized results")
    return {"requirements": requirements, "regressions": regressions, "resolved": resolved}


def run_checker(check: Path, source: Path, *, coder_sentinel: bool = False,
                md_filename: str = "CODER.md") -> tuple[dict[str, Any], bytes]:
    with tempfile.TemporaryDirectory(prefix="taskcheck-") as temporary:
        workspace = Path(temporary) / "workspace"
        shutil.copytree(source, workspace)
        if coder_sentinel:
            (workspace / md_filename).write_bytes(b"TASKCHECK ARM SENTINEL\n")
        before = tree_sha256(workspace)
        environment = os.environ.copy()
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        try:
            process = subprocess.run(
                [sys.executable, str(check.resolve()), str(workspace)],
                cwd=check.parent, env=environment, capture_output=True,
                text=True, timeout=60, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise TaskError(f"checker invocation failed: {type(exc).__name__}: {exc}") from exc
        if process.returncode:
            detail = process.stderr.strip() or process.stdout.strip()
            raise TaskError(f"checker exited {process.returncode}: {detail[-500:]}")
        if tree_sha256(workspace) != before:
            raise TaskError("checker modified its workspace")
        return _parse_result(process.stdout), process.stdout.encode("utf-8")


def _probe_fires(root: Path, probe: dict[str, Any], label: str) -> bool:
    if not isinstance(probe, dict) or probe.get("type") not in {"path_absent", "text_absent"}:
        raise TaskError(f"{label} has an invalid omission_probe")
    path_text = _safe_relative(probe.get("path"), f"{label}.omission_probe.path")
    target = root / path_text
    if probe["type"] == "path_absent":
        if set(probe) != {"type", "path"}:
            raise TaskError(f"{label} path_absent probe has unknown keys")
        return not target.exists()
    if set(probe) != {"type", "path", "text"} or not isinstance(probe.get("text"), str) or not probe["text"]:
        raise TaskError(f"{label} text_absent probe requires nonempty text")
    if not target.is_file():
        return True
    try:
        return probe["text"] not in target.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise TaskError(f"{label} probe cannot read {path_text}: {exc}") from exc


def _validate_requirements(task: Path, supplied: dict[str, Any], keys: set[str],
                           layout: int, salience: str, max_per_file: int,
                           min_files: int) -> dict[str, Any] | None:
    if set(supplied) != keys:
        raise TaskError(f"requirements.json keys differ from checker: {sorted(set(supplied) ^ keys)}")
    statements: list[tuple[str, str]] = []
    for key, value in supplied.items():
        expected = {"target_paths", "omission_probe"} | ({"stated_in"} if layout == 3 else set())
        if not isinstance(value, dict) or set(value) != expected:
            raise TaskError(f"requirements.json {key} has invalid keys")
        targets = value["target_paths"]
        if not isinstance(targets, list) or not targets:
            raise TaskError(f"requirements.json {key}.target_paths must be nonempty")
        for index, target in enumerate(targets):
            relative = _safe_relative(target, f"{key}.target_paths[{index}]")
            if not (task / "reference" / relative).exists():
                raise TaskError(f"{key} target path is absent from reference: {relative}")
        probe = value["omission_probe"]
        if not _probe_fires(task / "public", probe, key):
            raise TaskError(f"{key} omission probe does not fire on pristine public")
        if _probe_fires(task / "reference", probe, key):
            raise TaskError(f"{key} omission probe still fires on reference")
        if layout == 3:
            stated = value["stated_in"]
            if not isinstance(stated, dict) or set(stated) != {"path", "quote"}:
                raise TaskError(f"{key}.stated_in must contain path and quote")
            path = _safe_relative(stated.get("path"), f"{key}.stated_in.path")
            quote = stated.get("quote")
            trimmed = quote.rstrip("\"')]}\u201d\u2019") if isinstance(quote, str) else ""
            if (not isinstance(quote, str) or quote != quote.strip() or len(quote.split()) < 2
                    or not trimmed.endswith((".", "!", "?"))):
                raise TaskError(f"{key}.stated_in.quote must be one or more full sentences")
            source = task / "public" / path
            if source.is_symlink() or not source.is_file() or quote.encode() not in source.read_bytes():
                raise TaskError(f"{key}.stated_in.quote is absent from public/{path}")
            statements.append((path, quote))
    if layout != 3:
        return None
    quotes = [quote.encode() for _, quote in statements]
    for source in _paths(task / "public"):
        data = source.read_bytes()
        positions = [[match.start() for match in re.finditer(re.escape(quote), data)]
                     for quote in quotes]
        for index, left in enumerate(quotes):
            for other_index, right in enumerate(quotes[index + 1:], index + 1):
                if any(a < b + len(right) and b < a + len(left)
                       for a in positions[index] for b in positions[other_index]):
                    raise TaskError("stated_in quotes must be pairwise non-overlapping")
        if sum(bool(items) for items in positions) > max_per_file:
            raise TaskError(f"public/{source.relative_to(task / 'public')} exceeds stated quote cap")
    distinct = len({path for path, _ in statements})
    if salience in {"pointer", "none"} and distinct < min_files:
        raise TaskError(f"stated requirements span only {distinct} public files")
    return {"max_stated_per_file": max_per_file, "min_statement_files": min_files,
            "statement_files": distinct}


def _validate_mechanism(task: Path, scored: set[str]) -> dict[str, Any] | None:
    path = task / "mechanism.json"
    decoys = task / "decoys"
    if not path.exists():
        if decoys.exists():
            raise TaskError("decoys require mechanism.json")
        return None
    value = _json_file(path, "mechanism.json")
    if set(value) != {"facts", "nondisclosure_note"}:
        raise TaskError("mechanism.json has invalid keys")
    facts, note = value["facts"], value["nondisclosure_note"]
    if (not isinstance(facts, list) or len(facts) != 2
            or not isinstance(note, str) or not note.strip()):
        raise TaskError("mechanism.json requires two facts and a nondisclosure note")
    names: set[str] = set()
    for index, fact in enumerate(facts):
        label = f"mechanism.json facts[{index}]"
        if not isinstance(fact, dict) or set(fact) != MECHANISM_FACT_KEYS:
            raise TaskError(f"{label} has invalid keys")
        strings = (fact["fact"], fact["predicted_bare_behavior"])
        if not all(isinstance(item, str) and item.strip() for item in strings):
            raise TaskError(f"{label} text fields must be nonempty strings")
        support = _safe_relative(fact["public_support_path"], f"{label}.public_support_path")
        source = task / "public" / support
        substrings = fact["required_md_substrings"]
        if (source.is_symlink() or not source.is_file()
                or not isinstance(substrings, list) or not substrings
                or not all(isinstance(item, str) and item for item in substrings)
                or len(set(substrings)) != len(substrings)):
            raise TaskError(f"{label} support or required_md_substrings is invalid")
        data = source.read_text(encoding="utf-8")
        if any(item not in data for item in substrings):
            raise TaskError(f"{label} required MD substring lacks public support")
        if fact["affected_requirement"] not in scored or fact["fact"] in names:
            raise TaskError(f"{label} affected requirement or fact name is invalid")
        names.add(fact["fact"])
    if (not decoys.is_dir() or decoys.is_symlink()
            or {path.name for path in decoys.iterdir()} != set(DECOY_NAMES)
            or not all((decoys / name).is_dir() for name in DECOY_NAMES)):
        raise TaskError("mechanism decoys must be exactly wrong-layer and wrong-verification")
    return value


def _read_chain(path: Path, kind: str, *, required: bool = False) -> list[dict[str, Any]]:
    if not path.is_file():
        if required:
            raise TaskError(f"missing {kind}: {path}")
        return []
    rows: list[dict[str, Any]] = []
    previous = "GENESIS"
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            raise TaskError(f"invalid {kind} line {number}: {exc}") from exc
        if not isinstance(row, dict) or line != canonical(row):
            raise TaskError(f"noncanonical {kind} line {number}")
        if row.get("prev_sha256") != previous:
            raise TaskError(f"broken {kind} chain at line {number}")
        previous = sha256_bytes(line.encode("utf-8"))
        rows.append(row)
    return rows


def _append_chain(path: Path, row: dict[str, Any], kind: str) -> None:
    rows = _read_chain(path, kind)
    previous = "GENESIS" if not rows else sha256_bytes(canonical(rows[-1]).encode("utf-8"))
    row = {**row, "prev_sha256": previous}
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(canonical(row) + "\n")


def _verify_exposures(path: Path) -> list[dict[str, Any]]:
    rows = _read_chain(path, "exposures ledger")
    expected = {"task_id", "event", "batch_id", "reason", "prev_sha256"}
    for number, row in enumerate(rows, 1):
        valid = (set(row) == expected and TASK_ID.fullmatch(str(row.get("task_id", "")))
                 and row.get("event") in {"exposed", "retired"}
                 and isinstance(row.get("batch_id"), str) and bool(row["batch_id"])
                 and (row.get("reason") is None or isinstance(row["reason"], str)))
        if not valid:
            raise TaskError(f"invalid exposures ledger schema at line {number}")
    return rows


def _git_anchor(task: Path, ledger: Path) -> None:
    probe = subprocess.run(
        ["git", "-C", str(task), "rev-parse", "--show-toplevel"],
        capture_output=True, text=True, check=False,
    )
    if probe.returncode:
        raise TaskError("task is not inside a git worktree")
    root = Path(probe.stdout.strip()).resolve()
    try:
        task_rel = task.resolve().relative_to(root)
        ledger_rel = ledger.resolve().relative_to(root)
    except ValueError as exc:
        raise TaskError("task and ledger must be inside one git worktree") from exc
    for command in (
        ["git", "-C", str(root), "add", "--", str(task_rel), str(ledger_rel)],
        ["git", "-C", str(root), "commit", "-m", f"admit: {task.name}"],
    ):
        result = subprocess.run(command, capture_output=True, text=True, check=False)
        if result.returncode:
            raise TaskError(f"git anchor failed: {(result.stderr or result.stdout).strip()}")


def _md_filename(value: str) -> str:
    if not isinstance(value, str) or not MD_FILENAME.fullmatch(value) or value in {".", ".."}:
        raise TaskError("md filename must be a safe bare basename")
    return value


def _batch_task_order(rows: list[dict[str, Any]], seed: int) -> list[dict[str, Any]]:
    return sorted(rows, key=lambda row: (sha256_bytes(f"{seed}:{row['id']}".encode()), row["id"]))


def _validate_batch_request(request: Any, batch_id: str, arm_counts: set[int]) -> None:
    tasks = request.get("tasks") if isinstance(request, dict) else None
    arms = request.get("arms") if isinstance(request, dict) else None
    seed = request.get("task_order_seed") if isinstance(request, dict) else None
    runner = request.get("runner") if isinstance(request, dict) else None
    timeout = runner.get("timeout_seconds") if isinstance(runner, dict) else None
    expected_keys = BATCH_REQUEST_KEYS | ({"comparability_note"} if timeout == 600 else set())
    pair_count = len(tasks) * len(arms) if isinstance(tasks, list) and isinstance(arms, list) else 0
    valid = (
        isinstance(request, dict) and set(request) == expected_keys
        and (timeout != 600 or request.get("comparability_note") == COMPARABILITY_NOTE)
        and request.get("batch_id") == batch_id and isinstance(tasks, list) and bool(tasks)
        and isinstance(arms, list) and len(arms) in arm_counts
        and all(isinstance(row, dict) and set(row) == {"id", "manifest_sha256"}
                and isinstance(row["id"], str) and TASK_ID.fullmatch(row["id"])
                and isinstance(row["manifest_sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", row["manifest_sha256"]) for row in tasks)
        and all(isinstance(row, dict) and set(row) == {"name", "path", "sha256"}
                and isinstance(row["name"], str) and TASK_ID.fullmatch(row["name"])
                and isinstance(row["path"], str) and row["path"].startswith("controls/")
                and PurePosixPath(row["path"]).as_posix() == row["path"]
                and ".." not in PurePosixPath(row["path"]).parts
                and isinstance(row["sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) for row in arms)
        and len({row["id"] for row in tasks}) == len(tasks)
        and len({row["name"] for row in arms}) == len(arms)
        and isinstance(seed, int) and not isinstance(seed, bool) and seed >= 0
        and tasks == _batch_task_order(tasks, seed) and isinstance(request.get("runner"), dict)
        and all(isinstance(request.get(key), int) and not isinstance(request[key], bool)
                for key in ("call_count", "replacement_call_cap", "max_total_calls"))
        and request["call_count"] == 3 * pair_count
        and request["replacement_call_cap"] == pair_count
        and request["max_total_calls"] == 4 * pair_count
    )
    if not valid:
        raise TaskError("v2 REQUEST schema or binding is invalid")
    _md_filename(request["md_filename"])


def _validate_batch_request_v3(request: Any, batch_id: str,
                               arm_counts: set[int]) -> None:
    """Validate the explicit fast-preflight request schema.

    The unversioned validator above is intentionally frozen for historical v2
    requests, including its 600-second comparability-note convention.
    """
    tasks = request.get("tasks") if isinstance(request, dict) else None
    arms = request.get("arms") if isinstance(request, dict) else None
    seed = request.get("task_order_seed") if isinstance(request, dict) else None
    pair_count = len(tasks) * len(arms) if isinstance(tasks, list) and isinstance(arms, list) else 0
    valid = (
        isinstance(request, dict) and set(request) == BATCH_REQUEST_V3_KEYS
        and request.get("schema_version") == 3
        and request.get("batch_id") == batch_id and isinstance(tasks, list) and bool(tasks)
        and isinstance(arms, list) and len(arms) in arm_counts
        and all(isinstance(row, dict) and set(row) == {"id", "manifest_sha256"}
                and isinstance(row["id"], str) and TASK_ID.fullmatch(row["id"])
                and isinstance(row["manifest_sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", row["manifest_sha256"]) for row in tasks)
        and all(isinstance(row, dict) and set(row) == {"name", "path", "sha256"}
                and isinstance(row["name"], str) and TASK_ID.fullmatch(row["name"])
                and isinstance(row["path"], str) and row["path"].startswith("controls/")
                and PurePosixPath(row["path"]).as_posix() == row["path"]
                and ".." not in PurePosixPath(row["path"]).parts
                and isinstance(row["sha256"], str)
                and re.fullmatch(r"[0-9a-f]{64}", row["sha256"]) for row in arms)
        and len({row["id"] for row in tasks}) == len(tasks)
        and len({row["name"] for row in arms}) == len(arms)
        and isinstance(seed, int) and not isinstance(seed, bool) and seed >= 0
        and tasks == _batch_task_order(tasks, seed) and isinstance(request.get("runner"), dict)
        and all(isinstance(request.get(key), int) and not isinstance(request[key], bool)
                for key in ("call_count", "replacement_call_cap", "max_total_calls"))
        and request["call_count"] == 3 * pair_count
        and request["replacement_call_cap"] == pair_count
        and request["max_total_calls"] == 4 * pair_count
    )
    if not valid:
        raise TaskError("v3 REQUEST schema or binding is invalid")
    _md_filename(request["md_filename"])


def _layout(task: Path, md_filename: str) -> None:
    if not TASK_ID.fullmatch(task.name):
        raise TaskError(f"invalid task id: {task.name}")
    for directory in ("public", "reference", "blind"):
        if not (task / directory).is_dir():
            raise TaskError(f"missing directory: {directory}")
    for filename in ("check.py", "blind.provenance.json", "requirements.json"):
        if not (task / filename).is_file():
            raise TaskError(f"missing file: {filename}")
    if not (task / "public" / ".issue-contract.md").is_file():
        raise TaskError("public/.issue-contract.md is required")
    _paths(task)
    for directory in ("public", "blind"):
        if any(path.name == md_filename for path in (task / directory).rglob("*")):
            raise TaskError(f"{md_filename} is forbidden inside {directory}/")


def _meta(task: Path) -> tuple[str, str | None, int, bool]:
    path = task / "task-meta.json"
    if not path.exists():
        return "enumerated", None, 2, False
    value = _json_file(path, "task-meta.json")
    layout = value.get("layout_version", 2)
    explicit = "layout_version" in value
    expected = {"salience", "parent_task_id"} | ({"layout_version"} if explicit else set())
    if (isinstance(layout, bool) or not isinstance(layout, int)
            or set(value) != expected or layout not in {2, 3}):
        raise TaskError("task-meta.json has an invalid v2/v3 schema")
    salience, parent = value["salience"], value["parent_task_id"]
    if salience not in {"enumerated", "pointer", "none"}:
        raise TaskError("task-meta.json salience is invalid")
    if parent is not None and (not isinstance(parent, str) or not TASK_ID.fullmatch(parent)):
        raise TaskError("task-meta.json parent_task_id is invalid")
    if parent == task.name:
        raise TaskError("task cannot be its own parent")
    return salience, parent, layout, explicit


def admit(task_dir: Path, ledger: Path | None = None, exposures: Path | None = None,
          md_filename: str = "CODER.md", max_stated_per_file: int = 3,
          min_statement_files: int = 4) -> dict[str, Any]:
    task = task_dir.resolve()
    ledger = (ledger or task.parent / "ledger.jsonl").resolve()
    exposures = (exposures or task.parent / "exposures.jsonl").resolve()
    md_filename = _md_filename(md_filename)
    if max_stated_per_file < 1 or min_statement_files < 1:
        raise TaskError("spread thresholds must be positive")
    _layout(task, md_filename)
    salience, parent, layout, explicit_layout = _meta(task)
    exposed_rows = _verify_exposures(exposures)
    if any(row.get("task_id") == task.name for row in exposed_rows):
        raise TaskError(f"task is frozen by exposures ledger: {task.name}")
    public_before = tree_sha256(task / "public")
    pristine, pristine_raw = run_checker(task / "check.py", task / "public")
    sentinel, sentinel_raw = run_checker(
        task / "check.py", task / "public", coder_sentinel=True, md_filename=md_filename)
    if pristine_raw != sentinel_raw or pristine != sentinel:
        raise TaskError("checker is not arm-neutral")
    supplied = _json_file(task / "requirements.json", "requirements.json")
    spread = _validate_requirements(task, supplied, set(pristine["requirements"]),
                                    layout, salience, max_stated_per_file, min_statement_files)
    mechanism = _validate_mechanism(
        task, set(pristine["requirements"]) | set(pristine["regressions"]))
    provenance = _json_file(task / "blind.provenance.json", "blind.provenance.json")
    provenance_keys = {"solver_agent", "timestamp", "input_tree_sha256"}
    if layout == 3:
        provenance_keys |= {"solver_command_sha256", "sandbox_flags"}
    if set(provenance) != provenance_keys:
        raise TaskError("blind provenance has invalid keys")
    string_keys = provenance_keys - {"sandbox_flags"}
    if (not all(isinstance(provenance.get(key), str) and provenance[key] for key in string_keys)
            or (layout == 3 and (not isinstance(provenance["sandbox_flags"], list)
                                or not provenance["sandbox_flags"]
                                or not all(isinstance(item, str) and item for item in provenance["sandbox_flags"])))):
        raise TaskError("blind provenance fields must be nonempty strings")
    if layout == 3 and not re.fullmatch(r"[0-9a-f]{64}", provenance["solver_command_sha256"]):
        raise TaskError("blind provenance solver command hash is invalid")
    if provenance["input_tree_sha256"] != public_before:
        raise TaskError("blind provenance input tree hash does not match public/")
    if pristine["resolved"] or not all(pristine["regressions"].values()):
        raise TaskError("pristine public must be unresolved with all regressions passing")
    reference, reference_raw = run_checker(task / "check.py", task / "reference")
    reference_two, reference_two_raw = run_checker(task / "check.py", task / "reference")
    if reference_raw != reference_two_raw or reference != reference_two:
        raise TaskError("reference checker JSON is nondeterministic")
    blind, _ = run_checker(task / "check.py", task / "blind")
    expected_keys = (set(pristine["requirements"]), set(pristine["regressions"]))
    for label, result in (("reference", reference), ("blind", blind)):
        if (set(result["requirements"]), set(result["regressions"])) != expected_keys:
            raise TaskError(f"{label} checker keys differ from pristine")
        if not result["resolved"]:
            failed = [key for section in ("requirements", "regressions") for key, passed in result[section].items() if not passed]
            raise TaskError(f"{label} does not resolve: {failed}")
    decoy_failures: dict[str, list[str]] = {}
    if mechanism:
        for name in DECOY_NAMES:
            result, _ = run_checker(task / "check.py", task / "decoys" / name)
            if (set(result["requirements"]), set(result["regressions"])) != expected_keys:
                raise TaskError(f"decoy {name} checker keys differ from pristine")
            failed = [key for section in ("requirements", "regressions")
                      for key, passed in result[section].items() if not passed]
            if result["resolved"] or not failed:
                raise TaskError(f"decoy {name} unexpectedly resolves")
            decoy_failures[name] = failed
    if tree_sha256(task / "public") != public_before:
        raise TaskError("original public/ changed during admission")
    manifest = {
        "task_id": task.name,
        "files": _task_file_hashes(task),
        "salience": salience,
        "parent_task_id": parent,
        "gate": {
            "layout": {"status": "pass", "detail": f"task-layout-v{layout}"},
            "probes": {"status": "pass", "detail": f"{len(supplied)} validated"},
            "arm_neutrality": {"status": "pass", "detail": "sentinel output identical"},
            "provenance": {"status": "pass", "detail": public_before},
            "pristine": {"status": "pass", "detail": sorted(k for k, v in pristine["requirements"].items() if not v)},
            "reference": {"status": "pass", "detail": "resolved twice deterministically"},
            "blind": {"status": "pass", "detail": "resolved"},
            "integrity": {"status": "pass", "detail": public_before},
        },
        "requirements": supplied,
        "created": dt.datetime.now(dt.timezone.utc).isoformat(),
    }
    if explicit_layout:
        manifest["layout_version"] = layout
    if layout == 3:
        manifest["gate"]["spread"] = {"status": "pass", "detail": spread}
    if mechanism:
        manifest["gate"]["mechanism"] = {"status": "pass", "detail": "2 facts validated"}
        manifest["gate"]["decoys"] = {"status": "pass", "detail": decoy_failures}
    manifest_path = task / "manifest.json"
    manifest_path.write_text(canonical(manifest) + "\n", encoding="utf-8")
    _append_chain(ledger, {
        "task_id": task.name,
        "manifest_sha256": sha256_file(manifest_path),
        "timestamp": dt.datetime.now(dt.timezone.utc).isoformat(),
    }, "task ledger")
    _git_anchor(task, ledger)
    return manifest


def _verify_ledger(ledger: Path, tasks_root: Path, *, required: bool) -> list[dict[str, Any]]:
    rows = _read_chain(ledger, "task ledger", required=required)
    expected = {"task_id", "manifest_sha256", "prev_sha256", "timestamp"}
    for number, row in enumerate(rows, 1):
        if (set(row) != expected or not TASK_ID.fullmatch(str(row.get("task_id", "")))
                or not re.fullmatch(r"[0-9a-f]{64}", str(row.get("manifest_sha256", "")))
                or not isinstance(row.get("timestamp"), str) or not row["timestamp"]):
            raise TaskError(f"invalid task ledger schema at line {number}")
    missing = sorted({row["task_id"] for row in rows if not (tasks_root / row["task_id"]).is_dir()})
    if missing:
        raise TaskError(f"ledger-known tasks missing from disk: {missing}")
    return rows


def verify(task_dir: Path, ledger: Path | None = None, exposures: Path | None = None,
           md_filename: str | None = None) -> dict[str, Any]:
    task = task_dir.resolve()
    ledger = (ledger or task.parent / "ledger.jsonl").resolve()
    exposures = (exposures or task.parent / "exposures.jsonl").resolve()
    manifest_path = task / "manifest.json"
    manifest = _json_file(manifest_path, "manifest.json")
    expected = MANIFEST_KEYS_V3 if "layout_version" in manifest else MANIFEST_KEYS_V2
    salience, parent, layout, explicit_layout = _meta(task)
    if (set(manifest) != expected or manifest.get("task_id") != task.name
            or manifest.get("salience") != salience or manifest.get("parent_task_id") != parent
            or manifest.get("layout_version", 2) != layout
            or ("layout_version" in manifest) != explicit_layout):
        raise TaskError("manifest schema or task id is invalid")
    if manifest.get("files") != _task_file_hashes(task):
        raise TaskError("task files differ from manifest")
    rows = _verify_ledger(ledger, task.parent, required=True)
    latest = next((row for row in reversed(rows) if row["task_id"] == task.name), None)
    if latest is None or latest["manifest_sha256"] != sha256_file(manifest_path):
        raise TaskError("manifest hash is not anchored by the latest task ledger entry")
    _verify_exposures(exposures)
    if md_filename is not None:
        md_filename = _md_filename(md_filename)
        _layout(task, md_filename)
        pristine, pristine_raw = run_checker(task / "check.py", task / "public")
        sentinel, sentinel_raw = run_checker(
            task / "check.py", task / "public", coder_sentinel=True, md_filename=md_filename)
        if pristine_raw != sentinel_raw or pristine != sentinel:
            raise TaskError("checker is not arm-neutral")
    return {"task_id": task.name, "verified": True, "manifest_sha256": latest["manifest_sha256"]}


def batch(mode: str, directory: Path, ledger: Path | None = None,
          exposures: Path | None = None, md_filename: str = "CODER.md",
          max_stated_per_file: int = 3, min_statement_files: int = 4) -> list[dict[str, Any]]:
    root = directory.resolve()
    ledger = (ledger or root / "ledger.jsonl").resolve()
    exposures = (exposures or root / "exposures.jsonl").resolve()
    tasks = [path for path in sorted(root.iterdir()) if path.is_dir() and (path / "check.py").is_file()]
    if not tasks:
        if mode == "verify":
            _verify_ledger(ledger, root, required=ledger.exists())
        raise TaskError(f"no child directories containing check.py under {root}")
    rows: list[dict[str, Any]] = []
    for task in tasks:
        try:
            result = (admit(task, ledger, exposures, md_filename, max_stated_per_file,
                            min_statement_files) if mode == "admit"
                      else verify(task, ledger, exposures, md_filename))
            rows.append({"task_id": task.name, "ok": True, "detail": result.get("manifest_sha256", "admitted")})
        except TaskError as exc:
            rows.append({"task_id": task.name, "ok": False, "detail": str(exc)})
    print("TASK\tSTATUS\tDETAIL")
    for row in rows:
        print(f"{row['task_id']}\t{'PASS' if row['ok'] else 'FAIL'}\t{row['detail']}")
    if not all(row["ok"] for row in rows):
        raise TaskError(f"batch {mode} failed: {sum(row['ok'] for row in rows)}/{len(rows)} pass")
    return rows


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("admit", "verify"):
        command = commands.add_parser(name)
        command.add_argument("task_dir", type=Path)
        command.add_argument("--ledger", type=Path)
        command.add_argument("--exposures", type=Path)
        command.add_argument("--md-filename", default="CODER.md")
        command.add_argument("--max-stated-per-file", type=int, default=3)
        command.add_argument("--min-statement-files", type=int, default=4)
    command = commands.add_parser("batch")
    command.add_argument("mode", choices=("admit", "verify"))
    command.add_argument("directory", type=Path)
    command.add_argument("--ledger", type=Path)
    command.add_argument("--exposures", type=Path)
    command.add_argument("--md-filename", default="CODER.md")
    command.add_argument("--max-stated-per-file", type=int, default=3)
    command.add_argument("--min-statement-files", type=int, default=4)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "admit":
            result = admit(args.task_dir, args.ledger, args.exposures, args.md_filename,
                           args.max_stated_per_file, args.min_statement_files)
        elif args.command == "verify":
            result = verify(args.task_dir, args.ledger, args.exposures, args.md_filename)
        else:
            result = batch(args.mode, args.directory, args.ledger, args.exposures,
                           args.md_filename, args.max_stated_per_file,
                           args.min_statement_files)
        if args.command != "batch":
            print(canonical(result))
        return 0
    except TaskError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
