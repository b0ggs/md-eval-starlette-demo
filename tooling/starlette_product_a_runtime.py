"""Acquire and activate the one fixed public runtime for Product A."""
from __future__ import annotations
from contextlib import contextmanager
from hashlib import sha256
import json, os
from pathlib import Path
import re, shutil, subprocess, tempfile
from typing import Callable, Iterator, Mapping
from scripts.contain import runtime as sealed
from tooling import starlette_product_a as product_a
ROOT = Path(__file__).resolve().parents[1]
LOCK_PATH = ROOT / "runtime" / "product-a-v2" / "runtime-lock.json"
CACHE_ROOT = Path.home() / ".cache" / "md-eval-starlette-demo" / "product-a-v2"
COMPONENTS = {
    "product_a_public_entrypoint": "run_product_a.py",
    "product_a_public_runtime": "tooling/starlette_product_a_runtime.py",
    "product_a_public_runtime_lock": "runtime/product-a-v2/runtime-lock.json",
}
SHA = re.compile(r"sha256:[0-9a-f]{64}")
class RuntimeSetupError(RuntimeError): pass
def _need(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeSetupError(message)
def _load_lock(path: Path = LOCK_PATH) -> dict:
    try:
        lock = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeSetupError(f"invalid public runtime lock: {exc}") from exc
    _need(isinstance(lock, dict) and lock.get("schema") == "product-a-public-runtime-v2",
          "unsupported public runtime lock")
    _need(lock.get("status") == "published",
          "Product A public runtime is not published yet; no request was created")
    _need(lock.get("platform") == "linux/amd64", "unsupported public runtime platform")
    profiles = lock.get("profiles")
    _need(isinstance(profiles, dict) and set(profiles) == {"standard", "session", "modern"},
          "public runtime profiles are incomplete")
    tasks, seen = {}, set()
    for profile in profiles.values():
        _need(isinstance(profile, dict) and SHA.fullmatch(str(profile.get("config_id"))),
              "public runtime image config ID is invalid")
        pull = profile.get("pull")
        _need(isinstance(pull, str) and pull.startswith(lock["repository"] + "@sha256:")
              and SHA.fullmatch(pull.rsplit("@", 1)[1]), "public runtime pull digest is invalid")
        for task in profile.get("tasks", []):
            _need(task not in seen, "public runtime task is duplicated")
            seen.add(task)
            tasks[task] = profile["config_id"]
    _need(seen == set(product_a.TASK_IDS), "public runtime does not cover the fixed 18 tasks")
    python = lock.get("python")
    _need(isinstance(python, dict) and python.get("version") == "3.11.5"
          and SHA.fullmatch(str(python.get("source_config_id"))), "Python runtime lock is invalid")
    lock["task_images"] = tasks
    return lock
def _docker(config: Path) -> list[str]:
    configured = os.environ.get("MDSEVAL_DOCKER")
    candidate = shutil.which(configured) if configured else shutil.which("docker")
    fallback = Path("/Applications/Docker.app/Contents/Resources/bin/docker")
    if candidate is None and fallback.is_file():
        candidate = str(fallback)
    _need(candidate is not None, "Docker is required; install/start Docker and try again")
    config.mkdir(mode=0o700, exist_ok=True)
    (config / "config.json").write_text("{}\n", encoding="utf-8")
    command = [candidate, "--config", str(config)]
    socket = Path.home() / ".docker" / "run" / "docker.sock"
    host = os.environ.get("MDSEVAL_DOCKER_HOST")
    command += ["--host", host or f"unix://{socket}"] if host or socket.exists() else []
    result = _call(command, "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}", check=False)
    _need(result.returncode == 0, "Docker is installed but its daemon is unavailable")
    _need(result.stdout.strip() == "linux/amd64", "Product A currently requires linux/amd64 Docker")
    return command
def _call(docker: list[str], *arguments: str, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run([*docker, *arguments], capture_output=True, text=True, timeout=600)
    if check and result.returncode:
        raise RuntimeSetupError((result.stderr or result.stdout).strip())
    return result
def _tree_sha256(root: Path) -> str:
    digest = sha256()
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            kind, value = "L", path.readlink().as_posix()
        elif path.is_file():
            kind, value = "F", sha256(path.read_bytes()).hexdigest()
        elif path.is_dir():
            kind, value = "D", ""
        else:
            raise RuntimeSetupError(f"unsupported Python runtime entry: {relative}")
        digest.update(f"{kind}\0{relative}\0{value}\n".encode())
    return digest.hexdigest()
def _python_ready(root: Path, lock: Mapping) -> bool:
    python = lock["python"]; version = root / python["version"]; executable = version / "bin" / "python3.11"
    try:
        return (root.is_dir() and not root.is_symlink() and version.is_dir() and
                not version.is_symlink() and executable.is_file() and not executable.is_symlink() and os.access(executable, os.X_OK)
                and sha256(executable.read_bytes()).hexdigest() == python["executable_sha256"]
                and _tree_sha256(root / python["version"]) == python["tree_sha256"])
    except (OSError, RuntimeSetupError):
        return False
def _images_ready(docker: list[str], lock: Mapping) -> bool:
    for profile in lock["profiles"].values():
        result = _call(docker, "image", "inspect", "--format", "{{.Id}}",
                       profile["pull"], check=False)
        if result.returncode or result.stdout.strip() != profile["config_id"]:
            return False
    return True
def _install(docker: list[str], pins: Path, lock: Mapping,
             output: Callable[[str], None]) -> None:
    for name, profile in lock["profiles"].items():
        output(f"Pulling verified {name} runtime...")
        _call(docker, "pull", "--platform", "linux/amd64", profile["pull"])
    python = lock["python"]
    output("Acquiring pinned Python 3.11.5 tree...")
    _call(docker, "pull", "--platform", "linux/amd64", python["source_image"])
    source_id = _call(docker, "image", "inspect", "--format", "{{.Id}}",
                      python["source_image"]).stdout.strip()
    _need(source_id == python["source_config_id"], "Python source image config ID mismatch")
    pins.mkdir(parents=True, exist_ok=True)
    target = pins / python["version"]
    _need(not target.exists() and not target.is_symlink(),
          f"invalid cached Python tree; remove it and retry: {target}")
    with tempfile.TemporaryDirectory(prefix="product-a-python-", dir=pins) as temporary:
        staged = Path(temporary) / python["version"]
        staged.mkdir()
        container = _call(docker, "create", "--platform", "linux/amd64",
                          python["source_image"]).stdout.strip()
        try:
            _call(docker, "cp", f"{container}:/usr/local/.", str(staged))
        finally:
            _call(docker, "rm", "-f", container, check=False)
        _need(_python_ready(Path(temporary), lock), "extracted Python tree failed verification")
        staged.replace(target)
    _need(_images_ready(docker, lock), "downloaded runtime image failed digest verification")
@contextmanager
def protocol(lock: Mapping | None = None) -> Iterator[None]:
    selected = dict(lock or _load_lock())
    previous_images, previous_components = product_a.IMAGE_DIGESTS, product_a.COMPONENT_PATHS
    product_a.IMAGE_DIGESTS = dict(selected["task_images"])
    product_a.COMPONENT_PATHS = {**previous_components, **COMPONENTS}
    try:
        yield
    finally:
        product_a.IMAGE_DIGESTS, product_a.COMPONENT_PATHS = previous_images, previous_components
@contextmanager
def activate(input_fn: Callable[[str], str] = input,
             output_fn: Callable[[str], None] = print) -> Iterator[bool]:
    lock = _load_lock()
    auth_before = os.environ.get("MDSEVAL_CODEX_HOME")
    auth_home = Path(auth_before).expanduser() if auth_before else Path.home() / ".codex"
    auth = auth_home / "auth.json"
    _need(auth.is_file() and not auth.is_symlink() and bool(auth.stat().st_size),
          "Codex file-based login is required; run `codex login` and see README")
    os.environ["MDSEVAL_CODEX_HOME"] = str(auth_home.absolute())
    try:
        with tempfile.TemporaryDirectory(prefix="product-a-docker-config-") as config_name:
            docker = _docker(Path(config_name))
            pins = CACHE_ROOT / "interpreters"
            ready = _images_ready(docker, lock) and _python_ready(pins, lock)
            if not ready:
                try:
                    answer = input_fn("Download and verify the fixed Product A runtime? [y/N] ")
                except EOFError:
                    answer = ""
                if answer.strip().lower() not in {"y", "yes"}:
                    output_fn("Cancelled before request creation; no model calls were made.")
                    yield False
                    return
                _install(docker, pins, lock, output_fn)
            output_fn("Product A runtime verified.")
            old_docker, old_pins = sealed.DOCKER, sealed.PINS
            sealed.DOCKER, sealed.PINS = docker, pins
            try:
                with protocol(lock):
                    yield True
            finally:
                sealed.DOCKER, sealed.PINS = old_docker, old_pins
    finally:
        if auth_before is None:
            os.environ.pop("MDSEVAL_CODEX_HOME", None)
        else:
            os.environ["MDSEVAL_CODEX_HOME"] = auth_before
