"""Pinned, isolated Codex CLI subject adapter and non-mutating preflight."""

from __future__ import annotations

import os
import signal
import shutil
import subprocess
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from ..capture import Redactor, redact_event_stream
from ..config import ExperimentConfig, RunnerConfig
from ..fixtures import PreparedFixture
from ..wrapper import WRAPPER_PROMPT
from ..gitutils import init_repository, safe_process_environment
from ..processutils import run_process_group
from .base import RunResult

SAFE_ENVIRONMENT_NAMES = (
    "PATH",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LC_ALL",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
)
IMPOSSIBLE_SESSION_ID = "ffffffff-ffff-ffff-ffff-ffffffffffff"

# The subject is being evaluated as a local coding agent.  Account-level apps and
# other remote or delegated capabilities are outside that contract.  Keep this
# list explicit so a newly introduced capability cannot silently become part of
# an experiment merely because it is enabled in an evaluator's account.
SUBJECT_CAPABILITY_CONFIGS = (
    'web_search="disabled"',
    "agents.enabled=false",
    "apps._default.enabled=false",
    "apps._default.destructive_enabled=false",
    "apps._default.open_world_enabled=false",
    "features.apps=false",
    "features.auth_elicitation=false",
    "features.browser_use=false",
    "features.browser_use_external=false",
    "features.browser_use_full_cdp_access=false",
    "features.code_mode=false",
    "features.code_mode_host=false",
    "features.computer_use=false",
    "features.enable_mcp_apps=false",
    "features.goals=false",
    "features.guardian_approval=false",
    "features.hooks=false",
    "features.image_generation=false",
    "features.in_app_browser=false",
    "features.in_app_updates=false",
    "features.memories=false",
    "features.multi_agent=false",
    "features.multi_agent_v2=false",
    "features.plugin_sharing=false",
    "features.plugins=false",
    "features.remote_plugin=false",
    "features.request_permissions_tool=false",
    "features.skill_mcp_dependency_install=false",
    "features.skill_search=false",
    "features.tool_call_mcp_elicitation=false",
    "features.tool_suggest=false",
    "features.workspace_dependencies=false",
    "skills.bundled={enabled=false}",
    "skills.include_instructions=false",
    "skills.config=[]",
)
SUBJECT_PERMISSION_CONFIGS = (
    'default_permissions="mdseval"',
    'permissions.mdseval.description="MD Eval local coding subject"',
    'permissions.mdseval.extends=":workspace"',
    'permissions.mdseval.filesystem={"/agent-home/auth.json"="deny","/agent-home/sessions"="deny","/evaluator-output"="deny","/proc"="deny"}',
)


def config_arguments(values: tuple[str, ...]) -> list[str]:
    """Render frozen Codex configuration overrides in command-line order."""
    return [item for value in values for item in ("--config", value)]


def isolated_environment(codex_home: str) -> dict[str, str]:
    environment = safe_process_environment()
    environment["CODEX_HOME"] = codex_home
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = os.devnull
    environment["GIT_TERMINAL_PROMPT"] = "0"
    return environment


def build_codex_command(
    config: RunnerConfig,
    subject_repo: Path,
    output_last_message: Path,
) -> list[str]:
    return [
        "codex",
        "--ask-for-approval",
        config.approval_policy,
        "exec",
        "--strict-config",
        "--ephemeral",
        "--json",
        "--ignore-user-config",
        "--ignore-rules",
        "--model",
        config.model,
        "--config",
        f'model_reasoning_effort="{config.reasoning_effort}"',
        "--config",
        'project_doc_fallback_filenames=["CODER.md"]',
        "--config",
        "project_doc_max_bytes=65536",
        *config_arguments(SUBJECT_CAPABILITY_CONFIGS),
        *config_arguments(SUBJECT_PERMISSION_CONFIGS),
        "--config",
        "sandbox_workspace_write.network_access=false",
        "--cd",
        str(subject_repo),
        "--output-last-message",
        str(output_last_message),
        "-",
    ]


def build_judge_command(
    experiment: ExperimentConfig, judge_repo: Path, output_path: Path
) -> list[str]:
    judge = experiment.judge
    return [
        "codex",
        "--ask-for-approval",
        "never",
        "exec",
        "--strict-config",
        "--ephemeral",
        "--json",
        "--sandbox",
        "read-only",
        "--ignore-user-config",
        "--ignore-rules",
        "--model",
        judge.model,
        "--config",
        f'model_reasoning_effort="{judge.reasoning_effort}"',
        "--config",
        "project_doc_fallback_filenames=[]",
        "--config",
        "agents.enabled=false",
        "--cd",
        str(judge_repo),
        "--output-last-message",
        str(output_path),
        "-",
    ]


def _config_arguments(command: list[str]) -> list[str]:
    result: list[str] = []
    for index, item in enumerate(command[:-1]):
        if item == "--config":
            result.extend((item, command[index + 1]))
    return result


def _archive_result_class(process: subprocess.CompletedProcess[str]) -> str:
    output = " ".join((process.stdout + process.stderr).lower().split())
    if any(
        marker in output
        for marker in (
            "unknown configuration field",
            "failed to load config",
            "error loading config",
            "invalid value",
            "failed to parse",
        )
    ):
        return "CONFIG_ERROR"
    if "failed to archive session" in output:
        return "ARCHIVE_MISS"
    if "failed to connect to remote app server" in output:
        return "REMOTE_SOCKET_MISS"
    return "UNEXPECTED"


@dataclass(frozen=True)
class DoctorResult:
    available: bool
    code: str
    checks: dict[str, object]
    command: tuple[str, ...]


def doctor(experiment: ExperimentConfig) -> DoctorResult:
    """Check the executable and isolated profile without making a model call."""
    checks: dict[str, object] = {}
    codex = shutil.which("codex")
    git = shutil.which("git")
    checks["codex_exists"] = bool(codex)
    checks["git_exists"] = bool(git)
    codex_home_value = os.environ.get("MDSEVAL_CODEX_HOME")
    codex_home = Path(codex_home_value).expanduser() if codex_home_value else None
    checks["isolated_home_configured"] = codex_home is not None
    checks["isolated_home_exists"] = bool(codex_home and codex_home.is_dir())
    checks["isolated_home_instruction_free"] = bool(
        codex_home
        and codex_home.is_dir()
        and not (codex_home / "AGENTS.md").exists()
        and not (codex_home / "AGENTS.override.md").exists()
    )
    checks["model_pinned"] = bool(
        experiment.runner.model and experiment.runner.reasoning_effort
    )
    sample = build_codex_command(
        experiment.runner, Path("<subject-repository>"), Path("<final-message>")
    )
    checks["command_constructed"] = True
    checks["judge_command_constructed"] = bool(
        build_judge_command(
            experiment, Path("<judge-repository>"), Path("<judge-final-message>")
        )
    )
    if git:
        process = subprocess.run(
            [git, "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        checks["git_version_ok"] = process.returncode == 0
    else:
        checks["git_version_ok"] = False
    if codex:
        version = subprocess.run(
            [codex, "--version"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        checks["codex_version_ok"] = version.returncode == 0
        checks["codex_version"] = version.stdout.strip() if version.returncode == 0 else ""
        help_result = subprocess.run(
            [codex, "exec", "--help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        help_text = help_result.stdout + help_result.stderr
        required_flags = {
            "--strict-config",
            "--ephemeral",
            "--json",
            "--sandbox",
            "--ignore-user-config",
            "--ignore-rules",
            "--model",
            "--config",
            "--cd",
            "--output-last-message",
        }
        missing = sorted(flag for flag in required_flags if flag not in help_text)
        approval_help = subprocess.run(
            [codex, "--help"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if "--ask-for-approval" not in approval_help.stdout + approval_help.stderr:
            missing.append("--ask-for-approval (global)")
        checks["required_flags_compatible"] = help_result.returncode == 0 and not missing
        checks["missing_flags"] = missing
        judge_sample = build_judge_command(
            experiment, Path("<judge-repository>"), Path("<judge-final-message>")
        )
        with tempfile.TemporaryDirectory(
            prefix="mdseval-config-probe-"
        ) as probe_home:
            probe_environment = isolated_environment(probe_home)
            absent_socket = Path(probe_home) / "absent.sock"
            remote = f"unix://{absent_socket}"
            probe_commands = {
                "baseline": [
                    codex,
                    "--remote",
                    remote,
                    "--strict-config",
                    "archive",
                    IMPOSSIBLE_SESSION_ID,
                ],
                "subject": [
                    codex,
                    "--remote",
                    remote,
                    "--strict-config",
                    *_config_arguments(sample),
                    "archive",
                    IMPOSSIBLE_SESSION_ID,
                ],
                "judge": [
                    codex,
                    "--remote",
                    remote,
                    "--strict-config",
                    *_config_arguments(judge_sample),
                    "archive",
                    IMPOSSIBLE_SESSION_ID,
                ],
            }
            try:
                probe_results = {
                    label: subprocess.run(
                        command,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                        timeout=15,
                        env=probe_environment,
                    )
                    for label, command in probe_commands.items()
                }
                baseline = probe_results["baseline"]
                baseline_class = _archive_result_class(baseline)
                result_classes = {
                    label: _archive_result_class(result)
                    for label, result in probe_results.items()
                }
                failures = [
                    label
                    for label, result in probe_results.items()
                    if result.returncode != baseline.returncode
                    or result_classes[label] != baseline_class
                ]
                compatible = bool(
                    baseline.returncode != 0
                    and baseline_class == "REMOTE_SOCKET_MISS"
                    and not failures
                )
                checks["required_config_compatible"] = compatible
                checks["config_compatibility_status"] = (
                    "VERIFIED_LOCAL_PARSE_ONLY"
                    if compatible
                    else "INCOMPATIBLE_CONFIG"
                    if any(
                        result_classes[label] == "CONFIG_ERROR"
                        for label in ("subject", "judge")
                    )
                    else "UNVERIFIED"
                )
                checks["config_compatibility_error"] = (
                    "" if compatible else ", ".join(failures or ["baseline"])
                )
            except (OSError, subprocess.SubprocessError) as exc:
                checks["required_config_compatible"] = False
                checks["config_compatibility_status"] = "PROBE_FAILED"
                checks["config_compatibility_error"] = type(exc).__name__
    else:
        checks["codex_version_ok"] = False
        checks["required_flags_compatible"] = False
        checks["required_config_compatible"] = False
        checks["config_compatibility_error"] = "codex executable unavailable"
        checks["missing_flags"] = ["codex executable"]
    static_ready = all(
        bool(checks.get(key))
        for key in (
            "codex_exists",
            "git_exists",
            "isolated_home_exists",
            "isolated_home_instruction_free",
            "model_pinned",
            "command_constructed",
            "judge_command_constructed",
            "git_version_ok",
            "codex_version_ok",
            "required_flags_compatible",
        )
    )
    available = static_ready and bool(checks["required_config_compatible"])
    code = (
        "LIVE_RUNNER_AVAILABLE"
        if available
        else "LIVE_RUNNER_INCOMPATIBLE_FLAGS"
        if codex and not checks.get("required_flags_compatible")
        else "LIVE_RUNNER_INCOMPATIBLE_CONFIG"
        if checks.get("config_compatibility_status") == "INCOMPATIBLE_CONFIG"
        else "LIVE_RUNNER_CONFIG_COMPATIBILITY_UNVERIFIED"
        if codex and not checks.get("required_config_compatible")
        else "LIVE_RUNNER_UNAVAILABLE"
    )
    return DoctorResult(available, code, checks, tuple(sample))


def live_smoke(experiment: ExperimentConfig, redactor: Redactor) -> RunResult:
    result = doctor(experiment)
    if not result.available:
        raise RuntimeError(result.code)
    with tempfile.TemporaryDirectory(prefix="mdseval-live-smoke-") as temporary:
        repo = Path(temporary)
        init_repository(repo)
        output = repo / "final.txt"
        command = build_codex_command(experiment.runner, repo, output)
        environment = isolated_environment(os.environ["MDSEVAL_CODEX_HOME"])
        started = time.monotonic()
        process = run_process_group(
            command,
            cwd=repo,
            input_text="Reply with exactly READY and do not modify files.",
            timeout=min(60, experiment.runner.timeout_seconds),
            environment=environment,
        )
        return RunResult(
            status=(
                "TIMEOUT"
                if process.timed_out
                else "INTERRUPTED"
                if process.interrupted
                else "COMPLETED"
            ),
            exit_code=process.returncode,
            duration_seconds=time.monotonic() - started,
            timed_out=process.timed_out,
            interrupted=process.interrupted,
        )


class CodexCLI:
    def __init__(self, config: RunnerConfig) -> None:
        self.config = config

    def run(
        self,
        fixture: PreparedFixture,
        artifact_dir: Path,
        timeout_seconds: int,
        redactor: Redactor,
    ) -> RunResult:
        artifact_dir.mkdir(parents=True, exist_ok=True)
        isolated_home = os.environ.get("MDSEVAL_CODEX_HOME")
        if not isolated_home:
            raise RuntimeError("LIVE_RUNNER_UNAVAILABLE: MDSEVAL_CODEX_HOME is not set")
        environment = isolated_environment(isolated_home)
        started = time.monotonic()
        with tempfile.TemporaryDirectory(prefix="mdseval-raw-final-") as temporary:
            raw_output = Path(temporary) / "final.txt"
            command = build_codex_command(self.config, fixture.repo, raw_output)
            process = run_process_group(
                command,
                cwd=fixture.repo,
                input_text=WRAPPER_PROMPT,
                timeout=min(timeout_seconds, self.config.timeout_seconds),
                environment=environment,
            )
            if raw_output.exists():
                with raw_output.open("rb") as stream:
                    raw_final = stream.read(1_048_577)[:1_048_576]
                raw_final = redactor.bytes(raw_final)
                final_text = raw_final.decode("utf-8", errors="replace")
            else:
                final_text = ""
        duration = time.monotonic() - started
        (artifact_dir / "events.jsonl").write_text(
            redact_event_stream(process.stdout, redactor), encoding="utf-8"
        )
        (artifact_dir / "stderr.txt").write_text(
            redactor.text(process.stderr), encoding="utf-8"
        )
        (artifact_dir / "final.txt").write_text(
            redactor.text(final_text), encoding="utf-8"
        )
        return RunResult(
            status=(
                "TIMEOUT"
                if process.timed_out
                else "INTERRUPTED"
                if process.interrupted
                else "COMPLETED"
            ),
            exit_code=process.returncode,
            duration_seconds=duration,
            timed_out=process.timed_out,
            interrupted=process.interrupted,
        )
