"""Safe, disposable subject-repository preparation."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from .capture import is_ignored_generated_path
from .config import CaseConfig, ConfigError, resolve_within
from .hashing import tree_sha256
from .gitutils import run_git

FORBIDDEN_SUBJECT_INPUTS = (
    "AGENTS.md",
    "AGENTS.override.md",
    ".codex",
    ".agents",
    ".git",
    "case.json",
    "checks",
    "rubric.md",
)


@dataclass
class PreparedFixture:
    repo: Path
    temporary_root: Path
    baseline_commit: str
    fixture_hash: str
    case: CaseConfig
    variant_hash: str

    def cleanup(self) -> None:
        shutil.rmtree(self.temporary_root, ignore_errors=True)


def _git(repo: Path, *args: str) -> str:
    return str(run_git(repo, *args)).strip()


def _copy_fixture_contents(source: Path, destination: Path) -> None:
    source = source.resolve()
    copied_directories: list[tuple[Path, Path]] = []
    for path in sorted(source.rglob("*")):
        if path.is_symlink():
            raise ConfigError(f"fixture symlink is forbidden: {path}")
        relative = path.relative_to(source)
        if is_ignored_generated_path(relative.as_posix()):
            continue
        target = resolve_within(destination, relative.as_posix(), "fixture entry")
        if path.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            copied_directories.append((path, target))
        elif path.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
    for source_directory, target_directory in reversed(copied_directories):
        shutil.copystat(source_directory, target_directory)


def _audit_subject_inputs(repo: Path) -> None:
    for forbidden in FORBIDDEN_SUBJECT_INPUTS:
        if (repo / forbidden).exists():
            raise ConfigError(f"forbidden evaluator input reached subject repository: {forbidden}")
    required = {"CODER.md", ".issue-contract.md"}
    missing = [name for name in required if not (repo / name).is_file()]
    if missing:
        raise ConfigError(f"subject repository is missing inputs: {missing}")
    for path in repo.rglob("*"):
        if path.is_symlink():
            raise ConfigError(f"subject input symlink is forbidden: {path}")


def audit_final_subject_tree(repo: Path) -> None:
    """Reject subject-created symlinks before any unsandboxed hidden check."""
    for path in repo.rglob("*"):
        relative = path.relative_to(repo)
        if relative.parts and relative.parts[0] == ".git":
            continue
        if path.is_symlink():
            raise ConfigError(f"final subject tree contains a symlink: {relative}")


def prepare_fixture(
    case: CaseConfig,
    variant_path: Path,
    variant_hash: str,
    *,
    parent: Path | None = None,
) -> PreparedFixture:
    temporary_root = Path(
        tempfile.mkdtemp(prefix=f"mdseval-{case.id}-", dir=str(parent) if parent else None)
    ).resolve()
    repo = temporary_root / "subject"
    repo.mkdir()
    try:
        _copy_fixture_contents(case.fixture_dir, repo)
        shutil.copyfile(variant_path, repo / "CODER.md")
        shutil.copyfile(case.contract_path, repo / ".issue-contract.md")
        _audit_subject_inputs(repo)
        fixture_hash = tree_sha256(repo)
        _git(repo, "init", "-q", "--template=")
        _git(repo, "config", "user.name", "MD Eval")
        _git(repo, "config", "user.email", "mdseval@invalid.local")
        _git(repo, "add", "--all")
        _git(repo, "commit", "-q", "-m", "baseline")
        baseline = _git(repo, "rev-parse", "HEAD")
        return PreparedFixture(
            repo=repo,
            temporary_root=temporary_root,
            baseline_commit=baseline,
            fixture_hash=fixture_hash,
            case=case,
            variant_hash=variant_hash,
        )
    except Exception:
        shutil.rmtree(temporary_root, ignore_errors=True)
        raise
