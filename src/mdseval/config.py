"""Strict standard-library configuration loading."""

from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from .hashing import sha256_file, tree_sha256
from .variants import CHAMPION_SHA256, RESERVED_VARIANT_IDS, validate_locked_variants

DISPOSITIONS = frozenset({"IMPLEMENTED", "NEEDS_CLARIFICATION", "BLOCKED"})
QUALITATIVE_DIMENSIONS = frozenset(
    {"assumption_handling", "simplicity", "scope_discipline", "verification_quality"}
)
FORBIDDEN_FIXTURE_NAMES = frozenset(
    {"AGENTS.md", "AGENTS.override.md", ".codex", ".agents", ".git"}
)
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
CANDIDATE_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*-v[1-9][0-9]*$")
LOCKED_SUITES = {
    "smoke": (
        "ambiguity-must-clarify",
        "ambiguity-repo-resolves",
        "scope-ttl-zero",
        "bug-reproduce-mutable-default",
    ),
    "dev": (
        "ambiguity-must-clarify",
        "ambiguity-repo-resolves",
        "simplicity-username-lowercase",
        "scope-ttl-zero",
        "scope-remove-own-orphan",
        "bug-reproduce-mutable-default",
        "feature-json-output",
        "goal-status-422",
    ),
    "holdout": ("breadth-layered-settings", "goal-real-entrypoint"),
}
SCHEMA_REQUIRED_FIELDS = {
    "experiment.schema.json": {
        "schema_version",
        "experiment_id",
        "target_role",
        "runner",
        "judge",
        "variants",
        "suites",
        "run_order_seed",
        "default_repeats",
    },
    "case.schema.json": {
        "schema_version",
        "id",
        "suite",
        "expected_disposition",
        "allowed_changes",
        "forbidden_changes",
        "required_post_run_checks",
        "verification_evidence",
        "unchanged_regions",
        "qualitative_dimensions",
        "limits",
    },
    "judge-output.schema.json": {
        "schema_version",
        "winner",
        "confidence",
        "dimensions",
        "hard_concerns",
    },
}


class ConfigError(ValueError):
    """Raised when an experiment or case is invalid."""


@dataclass(frozen=True)
class RunnerConfig:
    type: str
    model: str
    reasoning_effort: str
    sandbox: str
    approval_policy: str
    subagents_enabled: bool
    ephemeral: bool
    network_for_agent_commands: bool
    timeout_seconds: int
    max_parallel_runs: int


@dataclass(frozen=True)
class JudgeConfig:
    type: str
    model: str
    reasoning_effort: str
    sandbox: str
    timeout_seconds: int


@dataclass(frozen=True)
class VerificationEvidence:
    pre_edit_failure_required: bool
    post_edit_check_required: bool
    command_patterns: tuple[str, ...]


@dataclass(frozen=True)
class CaseConfig:
    schema_version: int
    id: str
    suite: str
    expected_disposition: str
    allowed_changes: tuple[str, ...]
    forbidden_changes: tuple[str, ...]
    required_post_run_checks: tuple[tuple[str, ...], ...]
    verification_evidence: VerificationEvidence
    unchanged_regions: tuple[dict[str, str], ...]
    qualitative_dimensions: tuple[str, ...]
    timeout_seconds: int
    directory: Path
    definition_hash: str
    fixture_hash: str

    @property
    def fixture_dir(self) -> Path:
        return self.directory / "fixture"

    @property
    def contract_path(self) -> Path:
        return self.directory / "contract.md"

    @property
    def rubric_path(self) -> Path:
        return self.directory / "rubric.md"


@dataclass(frozen=True)
class ExperimentConfig:
    schema_version: int
    experiment_id: str
    target_role: str
    runner: RunnerConfig
    judge: JudgeConfig
    variants: dict[str, Path]
    candidate_ids: tuple[str, ...]
    suites: dict[str, tuple[str, ...]]
    run_order_seed: int
    default_repeats: int
    path: Path
    root: Path
    cases: dict[str, CaseConfig]
    definition_hash: str


def _object(
    value: Any, label: str, *, required: set[str], optional: set[str] | None = None
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ConfigError(f"{label} must be an object")
    optional = optional or set()
    unknown = set(value) - required - optional
    missing = required - set(value)
    if unknown:
        raise ConfigError(f"{label} has unknown keys: {sorted(unknown)}")
    if missing:
        raise ConfigError(f"{label} is missing keys: {sorted(missing)}")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{label} must be a nonempty string")
    return value


def _identifier(value: Any, label: str) -> str:
    result = _string(value, label)
    if not SAFE_ID.fullmatch(result):
        raise ConfigError(f"{label} must be one safe path component")
    return result


def _integer(value: Any, label: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{label} must be an integer")
    if positive and value <= 0:
        raise ConfigError(f"{label} must be positive")
    return value


def _boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{label} must be a boolean")
    return value


def _string_list(value: Any, label: str, *, nonempty: bool = False) -> tuple[str, ...]:
    if not isinstance(value, list) or (nonempty and not value):
        raise ConfigError(f"{label} must be a{' nonempty' if nonempty else ''} list")
    result = tuple(_string(item, f"{label} item") for item in value)
    if len(set(result)) != len(result):
        raise ConfigError(f"{label} contains duplicates")
    return result


def safe_relative_path(value: str, label: str = "path") -> PurePosixPath:
    path = PurePosixPath(_string(value, label))
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ConfigError(f"{label} must be a safe relative path: {value!r}")
    if any(part in {"", "."} for part in path.parts):
        raise ConfigError(f"{label} contains an unsafe component: {value!r}")
    return path


def resolve_within(root: Path, relative: str, label: str = "path") -> Path:
    safe_relative_path(relative, label)
    root = root.resolve()
    resolved = (root / relative).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ConfigError(f"{label} escapes root: {relative!r}") from exc
    return resolved


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConfigError(f"cannot read valid JSON from {path}: {exc}") from exc


def _find_root(experiment_path: Path) -> Path:
    current = experiment_path.resolve().parent
    for candidate in (current, *current.parents):
        if (candidate / "pyproject.toml").is_file():
            return candidate
    raise ConfigError("could not find repository root containing pyproject.toml")


def _validate_schema_documents(root: Path) -> None:
    for name, required_fields in SCHEMA_REQUIRED_FIELDS.items():
        path = root / "schemas" / name
        if path.is_symlink() or not path.is_file():
            raise ConfigError(f"required schema is missing or unsafe: {path}")
        data = _read_json(path)
        if (
            not isinstance(data, dict)
            or data.get("$schema") != "https://json-schema.org/draft/2020-12/schema"
            or data.get("type") != "object"
            or data.get("additionalProperties") is not False
            or set(data.get("required", ())) != required_fields
            or not isinstance(data.get("properties"), dict)
            or not required_fields <= set(data["properties"])
        ):
            raise ConfigError(f"schema document is incomplete or unsupported: {path}")


def _load_runner(value: Any) -> RunnerConfig:
    required = {
        "type",
        "model",
        "reasoning_effort",
        "sandbox",
        "approval_policy",
        "subagents_enabled",
        "ephemeral",
        "network_for_agent_commands",
        "timeout_seconds",
        "max_parallel_runs",
    }
    data = _object(value, "runner", required=required)
    runner = RunnerConfig(
        type=_string(data["type"], "runner.type"),
        model=_string(data["model"], "runner.model"),
        reasoning_effort=_string(data["reasoning_effort"], "runner.reasoning_effort"),
        sandbox=_string(data["sandbox"], "runner.sandbox"),
        approval_policy=_string(data["approval_policy"], "runner.approval_policy"),
        subagents_enabled=_boolean(data["subagents_enabled"], "runner.subagents_enabled"),
        ephemeral=_boolean(data["ephemeral"], "runner.ephemeral"),
        network_for_agent_commands=_boolean(
            data["network_for_agent_commands"], "runner.network_for_agent_commands"
        ),
        timeout_seconds=_integer(
            data["timeout_seconds"], "runner.timeout_seconds", positive=True
        ),
        max_parallel_runs=_integer(
            data["max_parallel_runs"], "runner.max_parallel_runs", positive=True
        ),
    )
    if runner.type != "codex_cli":
        raise ConfigError(f"unsupported runner type: {runner.type}")
    if runner.model != "gpt-5.6-sol" or runner.reasoning_effort != "high":
        raise ConfigError("runner model and reasoning effort must match the locked experiment")
    if runner.sandbox != "workspace-write" or runner.approval_policy != "never":
        raise ConfigError("runner sandbox and approval policy must match the locked experiment")
    if runner.subagents_enabled or not runner.ephemeral or runner.network_for_agent_commands:
        raise ConfigError("runner isolation settings violate the locked experiment")
    if runner.max_parallel_runs != 1:
        raise ConfigError("max_parallel_runs must be 1")
    return runner


def _load_judge(value: Any) -> JudgeConfig:
    data = _object(
        value,
        "judge",
        required={
            "type",
            "model",
            "reasoning_effort",
            "sandbox",
            "timeout_seconds",
        },
    )
    judge = JudgeConfig(
        type=_string(data["type"], "judge.type"),
        model=_string(data["model"], "judge.model"),
        reasoning_effort=_string(data["reasoning_effort"], "judge.reasoning_effort"),
        sandbox=_string(data["sandbox"], "judge.sandbox"),
        timeout_seconds=_integer(
            data["timeout_seconds"], "judge.timeout_seconds", positive=True
        ),
    )
    if (
        judge.type != "codex_cli"
        or judge.sandbox != "read-only"
        or judge.model != "gpt-5.6-sol"
        or judge.reasoning_effort != "high"
    ):
        raise ConfigError("judge settings must match the locked experiment")
    return judge


def load_case(case_dir: Path) -> CaseConfig:
    case_dir = case_dir.resolve()
    case_path = case_dir / "case.json"
    data = _object(
        _read_json(case_path),
        str(case_path),
        required={
            "schema_version",
            "id",
            "suite",
            "expected_disposition",
            "allowed_changes",
            "forbidden_changes",
            "required_post_run_checks",
            "verification_evidence",
            "unchanged_regions",
            "qualitative_dimensions",
            "limits",
        },
    )
    if _integer(data["schema_version"], "case.schema_version") != 1:
        raise ConfigError(f"{case_path}: unsupported schema_version")
    case_id = _identifier(data["id"], "case.id")
    if case_dir.name != case_id:
        raise ConfigError(f"{case_path}: id does not match directory name")
    suite = _string(data["suite"], "case.suite")
    if suite not in {"dev", "holdout"}:
        raise ConfigError(f"{case_path}: unsupported suite {suite!r}")
    disposition = _string(data["expected_disposition"], "case.expected_disposition")
    if disposition not in DISPOSITIONS:
        raise ConfigError(f"{case_path}: unsupported disposition {disposition!r}")
    allowed = _string_list(data["allowed_changes"], "case.allowed_changes")
    forbidden = _string_list(data["forbidden_changes"], "case.forbidden_changes")
    for item in (*allowed, *forbidden):
        safe_relative_path(item, f"{case_id} change path")
    if set(allowed) & set(forbidden):
        raise ConfigError(f"{case_path}: a path is both allowed and forbidden")

    checks_value = data["required_post_run_checks"]
    if not isinstance(checks_value, list) or not checks_value:
        raise ConfigError(f"{case_path}: required_post_run_checks must be nonempty")
    checks: list[tuple[str, ...]] = []
    for index, command in enumerate(checks_value):
        checks.append(
            _string_list(command, f"{case_id} check {index}", nonempty=True)
        )

    evidence_data = _object(
        data["verification_evidence"],
        f"{case_id}.verification_evidence",
        required={
            "pre_edit_failure_required",
            "post_edit_check_required",
            "command_patterns",
        },
    )
    evidence = VerificationEvidence(
        pre_edit_failure_required=_boolean(
            evidence_data["pre_edit_failure_required"],
            f"{case_id}.pre_edit_failure_required",
        ),
        post_edit_check_required=_boolean(
            evidence_data["post_edit_check_required"],
            f"{case_id}.post_edit_check_required",
        ),
        command_patterns=_string_list(
            evidence_data["command_patterns"], f"{case_id}.command_patterns"
        ),
    )

    regions_value = data["unchanged_regions"]
    if not isinstance(regions_value, list):
        raise ConfigError(f"{case_id}.unchanged_regions must be a list")
    regions: list[dict[str, str]] = []
    for index, value in enumerate(regions_value):
        region = _object(
            value,
            f"{case_id}.unchanged_regions[{index}]",
            required={"path", "content"},
        )
        region_path = _string(region["path"], "unchanged region path")
        safe_relative_path(region_path, "unchanged region path")
        regions.append(
            {"path": region_path, "content": _string(region["content"], "region content")}
        )

    dimensions = _string_list(
        data["qualitative_dimensions"], "case.qualitative_dimensions", nonempty=True
    )
    unsupported = set(dimensions) - QUALITATIVE_DIMENSIONS
    if unsupported:
        raise ConfigError(f"{case_path}: unsupported dimensions {sorted(unsupported)}")
    limits = _object(data["limits"], f"{case_id}.limits", required={"timeout_seconds"})
    timeout = _integer(
        limits["timeout_seconds"], f"{case_id}.limits.timeout_seconds", positive=True
    )

    for required_path in ("fixture", "contract.md", "rubric.md", "checks"):
        path = case_dir / required_path
        if not path.exists():
            raise ConfigError(f"{case_path}: missing {required_path}")
    if not (case_dir / "contract.md").read_text(encoding="utf-8").strip():
        raise ConfigError(f"{case_path}: empty contract")
    if not (case_dir / "rubric.md").read_text(encoding="utf-8").strip():
        raise ConfigError(f"{case_path}: empty rubric")
    for current, dirnames, filenames in os.walk(case_dir / "fixture", followlinks=False):
        for name in (*dirnames, *filenames):
            path = Path(current) / name
            if path.is_symlink():
                raise ConfigError(f"{case_path}: fixture symlink is forbidden: {path}")
            if name in FORBIDDEN_FIXTURE_NAMES:
                raise ConfigError(f"{case_path}: forbidden fixture input: {name}")
    for command in checks:
        for argument in command:
            if argument.startswith("/") or ".." in PurePosixPath(argument).parts:
                raise ConfigError(f"{case_path}: unsafe check argument {argument!r}")
        executable = command[0]
        if "/" in executable:
            executable_path = resolve_within(case_dir, executable, "check executable")
            if not executable_path.is_file() or not os.access(executable_path, os.X_OK):
                raise ConfigError(
                    f"{case_path}: check executable is unavailable: {executable}"
                )
        elif shutil.which(executable) is None:
            raise ConfigError(
                f"{case_path}: check interpreter is unavailable: {executable}"
            )
        if len(command) >= 2 and command[0] in {"python", "python3"}:
            script = resolve_within(case_dir, command[1], "check script")
            if not script.is_file():
                raise ConfigError(f"{case_path}: missing check script {command[1]}")
            try:
                compile(script.read_text(encoding="utf-8"), str(script), "exec")
            except SyntaxError as exc:
                raise ConfigError(f"{case_path}: invalid check script: {exc}") from exc

    return CaseConfig(
        schema_version=1,
        id=case_id,
        suite=suite,
        expected_disposition=disposition,
        allowed_changes=allowed,
        forbidden_changes=forbidden,
        required_post_run_checks=tuple(checks),
        verification_evidence=evidence,
        unchanged_regions=tuple(regions),
        qualitative_dimensions=dimensions,
        timeout_seconds=timeout,
        directory=case_dir,
        definition_hash=tree_sha256(case_dir),
        fixture_hash=tree_sha256(case_dir / "fixture"),
    )


def _discover_cases(root: Path) -> dict[str, CaseConfig]:
    cases: dict[str, CaseConfig] = {}
    evals_root = (root / "evals").resolve()
    for case_path in sorted((root / "evals").glob("*/*/case.json")):
        try:
            case_path.resolve().relative_to(evals_root)
        except ValueError as exc:
            raise ConfigError(f"case path escapes evals root: {case_path}") from exc
        case = load_case(case_path.parent)
        if case.id in cases:
            raise ConfigError(f"duplicate case id: {case.id}")
        cases[case.id] = case
    return cases


def load_experiment(path: str | Path) -> ExperimentConfig:
    experiment_path = Path(path).resolve()
    root = _find_root(experiment_path)
    _validate_schema_documents(root)
    data = _object(
        _read_json(experiment_path),
        str(experiment_path),
        required={
            "schema_version",
            "experiment_id",
            "target_role",
            "runner",
            "judge",
            "variants",
            "suites",
            "run_order_seed",
            "default_repeats",
        },
    )
    if _integer(data["schema_version"], "experiment.schema_version") != 1:
        raise ConfigError("unsupported experiment schema_version")
    target_role = _identifier(data["target_role"], "target_role")
    variants_data = data["variants"]
    if not isinstance(variants_data, dict) or not variants_data:
        raise ConfigError("variants must be a nonempty object")
    variants: dict[str, Path] = {}
    for variant_id, relative in variants_data.items():
        variant_id = _identifier(variant_id, "variant id")
        relative = _string(relative, "variant path")
        relative_path = safe_relative_path(relative, "variant path")
        if variant_id not in RESERVED_VARIANT_IDS:
            if not CANDIDATE_ID.fullmatch(variant_id):
                raise ConfigError(f"candidate id is not lowercase versioned kebab-case: {variant_id}")
            expected = f"candidates/{target_role}/{variant_id}.md"
            if relative != expected:
                raise ConfigError(f"candidate path must be exactly {expected}")
            if any((root.joinpath(*relative_path.parts[:index])).is_symlink() for index in range(1, len(relative_path.parts) + 1)):
                raise ConfigError(f"candidate path is symlinked: {relative}")
        variant_path = resolve_within(root, relative, "variant")
        if not variant_path.is_file():
            raise ConfigError(f"variant does not exist: {relative}")
        variants[variant_id] = variant_path
    candidate_ids = tuple(sorted(set(variants) - RESERVED_VARIANT_IDS))
    if not RESERVED_VARIANT_IDS <= set(variants) or not candidate_ids:
        raise ConfigError("champion, deliberately-bad, and at least one candidate are required")
    if sha256_file(variants["champion"]) != CHAMPION_SHA256:
        raise ConfigError("champion hash does not match the locked baseline")
    try:
        validate_locked_variants(variants)
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
    locked_bytes = {variants[item].read_bytes() for item in RESERVED_VARIANT_IDS}
    candidate_bytes: dict[bytes, str] = {}
    for candidate_id in candidate_ids:
        try:
            content = variants[candidate_id].read_bytes()
            text = content.decode("utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise ConfigError(f"candidate is not readable UTF-8: {candidate_id}") from exc
        if not text.strip():
            raise ConfigError(f"candidate is empty: {candidate_id}")
        if content in locked_bytes:
            raise ConfigError(f"candidate duplicates a locked role: {candidate_id}")
        if content in candidate_bytes:
            raise ConfigError(f"candidate duplicates {candidate_bytes[content]}: {candidate_id}")
        candidate_bytes[content] = candidate_id

    suites_data = data["suites"]
    if not isinstance(suites_data, dict) or not suites_data:
        raise ConfigError("suites must be a nonempty object")
    suites = {
        _identifier(name, "suite name"): _string_list(case_ids, f"suite {name}")
        for name, case_ids in suites_data.items()
    }
    if suites != LOCKED_SUITES:
        raise ConfigError("suite membership must match the locked MVP experiment")
    cases = _discover_cases(root)
    for suite_name, case_ids in suites.items():
        missing = set(case_ids) - set(cases)
        if missing:
            raise ConfigError(f"suite {suite_name} references missing cases: {sorted(missing)}")
        if suite_name in {"dev", "holdout"}:
            wrong = [case_id for case_id in case_ids if cases[case_id].suite != suite_name]
            if wrong:
                raise ConfigError(f"suite {suite_name} contains cases with wrong suite: {wrong}")

    repeats = _integer(data["default_repeats"], "default_repeats", positive=True)
    return ExperimentConfig(
        schema_version=1,
        experiment_id=_identifier(data["experiment_id"], "experiment_id"),
        target_role=target_role,
        runner=_load_runner(data["runner"]),
        judge=_load_judge(data["judge"]),
        variants=variants,
        candidate_ids=candidate_ids,
        suites=suites,
        run_order_seed=_integer(data["run_order_seed"], "run_order_seed"),
        default_repeats=repeats,
        path=experiment_path,
        root=root,
        cases=cases,
        definition_hash=sha256_file(experiment_path),
    )


def validate_experiment(path: str | Path) -> ExperimentConfig:
    """Load and validate all experiment inputs."""
    return load_experiment(path)
