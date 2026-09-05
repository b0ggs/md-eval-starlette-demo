"""Stable hashing helpers."""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path

IGNORED_TREE_DIRECTORIES = frozenset({".git", "__pycache__", ".pytest_cache"})
IGNORED_TREE_SUFFIXES = (".pyc", ".pyo")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def tree_sha256(root: Path) -> str:
    """Hash relative names, file types, and bytes without following symlinks."""
    root = root.resolve()
    digest = hashlib.sha256()
    if not root.is_dir():
        raise ValueError(f"tree root is not a directory: {root}")
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        current_path = Path(current)
        dirnames[:] = sorted(
            name for name in dirnames if name not in IGNORED_TREE_DIRECTORIES
        )
        for name in sorted(dirnames):
            path = current_path / name
            if path.is_symlink():
                raise ValueError(f"symlink is not allowed: {path}")
            relative = path.relative_to(root).as_posix()
            digest.update(b"dir\0")
            digest.update(relative.encode("utf-8"))
            digest.update(b"\0")
            digest.update(f"mode={stat.S_IMODE(path.stat().st_mode):o}".encode("ascii"))
            digest.update(b"\0")
        for name in sorted(filenames):
            if name.endswith(IGNORED_TREE_SUFFIXES):
                continue
            path = current_path / name
            if path.is_symlink():
                raise ValueError(f"symlink is not allowed: {path}")
            relative = path.relative_to(root).as_posix()
            digest.update(b"file\0")
            digest.update(relative.encode("utf-8"))
            digest.update(b"\0")
            digest.update(f"mode={stat.S_IMODE(path.stat().st_mode):o}".encode("ascii"))
            digest.update(b"\0")
            digest.update(path.read_bytes())
            digest.update(b"\0")
    return digest.hexdigest()
