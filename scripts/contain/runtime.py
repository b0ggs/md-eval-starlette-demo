import argparse, errno, hashlib, json, os, re, secrets, shlex, shutil, stat, subprocess, sys, tempfile, time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SPEC = ROOT / "scripts/contain/contamination-spec.json"
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
from mdseval.capture import parse_event_stream
from mdseval.processutils import ProcessOutcome, _stop_group, run_process_group
from mdseval.runner.codex_cli import (SUBJECT_CAPABILITY_CONFIGS,
                                      SUBJECT_PERMISSION_CONFIGS,
                                      config_arguments)
from tooling import taskcheck

DEFAULT_DOCKER_HOST = f"unix://{Path.home() / '.docker/run/docker.sock'}"
DOCKER = [os.environ.get("MDSEVAL_DOCKER", "/Applications/Docker.app/Contents/Resources/bin/docker"), "--config", os.environ.get("MDSEVAL_DOCKER_CONFIG", "/private/tmp/mdseval-public-docker-config"), "--host", os.environ.get("MDSEVAL_DOCKER_HOST", DEFAULT_DOCKER_HOST)]
PINS = Path(os.environ.get("MDSEVAL_INTERPRETERS", "/private/tmp/mdseval-interpreters-sealed"))
SECURITY = ("--cap-drop", "ALL", "--security-opt", "no-new-privileges=true",
            "--security-opt", "seccomp=unconfined", "--pids-limit", "256")
FIXED_ENV = ("HOME=/agent-home", "CODEX_HOME=/agent-home", "PYTHONHOME=/python", "PYTHONPATH=/sealed-deps", "PYTHONDONTWRITEBYTECODE=1", "PYTHONNOUSERSITE=1", "LANG=C.UTF-8", "LD_LIBRARY_PATH=/python/lib", "PATH=/usr/lib/codex/bin:/usr/lib/codex/codex-path:/python/bin:/usr/bin:/bin", "GIT_OPTIONAL_LOCKS=0")
PROXY_ENV = ("HTTPS_PROXY=http://model-proxy:8888", "HTTP_PROXY=http://model-proxy:8888")
WEB_SEARCH_DISABLED_CONFIG = 'web_search="disabled"'
SHELL_PATH = "/agent-home/bin:/usr/lib/codex/codex-path:/python/bin:/usr/bin:/bin"
SHELL_PROFILE = f"export PATH={SHELL_PATH}\n".encode()
PYTEST_WRAPPER = b'#!/bin/sh\nexec /python/bin/python3 -m pytest "$@"\n'
SUBJECT_SHELL_CONFIGS = (
    'shell_environment_policy.inherit="none"',
    "shell_environment_policy.ignore_default_excludes=false",
    'shell_environment_policy.set={HOME="/agent-home",PATH="' + SHELL_PATH
    + '",PYTHONHOME="/python",PYTHONPATH="/sealed-deps",PYTHONDONTWRITEBYTECODE="1",'
      'PYTHONNOUSERSITE="1",LANG="C.UTF-8",LC_ALL="C.UTF-8",GIT_CONFIG_NOSYSTEM="1",'
      'GIT_CONFIG_GLOBAL="/dev/null",GIT_TERMINAL_PROMPT="0",GIT_OPTIONAL_LOCKS="0",'
      'LD_LIBRARY_PATH="/python/lib"}',
)
SUBJECT_REQUIRED_CONFIGS = (*SUBJECT_CAPABILITY_CONFIGS, *SUBJECT_PERMISSION_CONFIGS,
                            *SUBJECT_SHELL_CONFIGS)
DISABLED_FEATURES = tuple(value[len("features."):-len("=false")]
                          for value in SUBJECT_CAPABILITY_CONFIGS
                          if value.startswith("features.") and value.endswith("=false"))
WEB_SEARCH_DISABLED_EVIDENCE = {"mode": "disabled", "origin_type": "sessionFlags", "session_layer_modes": ["disabled"]}
LINUX_EAI_AGAIN = -3
FAST_SEAL_SCHEMA = "fast-preflight-v2"
FAST_POLICY_COMMAND_TIMEOUT_MS = 10_000
FAST_POLICY_LINGER_SECONDS = 15.0
FAST_MOUNTS = {"/agent-home": "rw", "/evaluator-output": "rw", "/python": "ro",
               "/workspace": "rw", "/workspace/.git": "ro"}
FAST_SANDBOX = {"mode": "workspace-write", "network_access": False}
CONTAINER_KEYSETS = {frozenset({"image_digests", "spec_sha256", "interpreter_pins"}),
                     frozenset({"image_digests", "spec_sha256", "interpreter_pins", "web_search"})}


@dataclass(frozen=True)
class SubjectOutcome:
    process: ProcessOutcome
    duration_seconds: float

_TARGETED_SMOKE_SCRIPT = r'''
import hashlib, inspect, json, os, pathlib, platform, pydoc, re, shutil, socket, stat, subprocess, sys, time, tokenize

def need(value, message):
    if not value:
        raise RuntimeError(message)

def digest(value):
    if isinstance(value, str):
        value = value.encode()
    return hashlib.sha256(value).hexdigest()

def normalized(value):
    return "".join(character for character in value if not character.isspace())

def unescape(value):
    return re.sub(r"\\([0-7]{3})", lambda match: chr(int(match.group(1), 8)), value)

def mounts():
    found = {}
    with open("/proc/self/mountinfo", encoding="utf-8") as stream:
        for line in stream:
            left, right = line.rstrip("\n").split(" - ", 1)
            fields = left.split()
            need(len(fields) >= 6 and len(right.split()) >= 3, "malformed mount table")
            target = unescape(fields[4])
            found.setdefault(target, []).append(set(fields[5].split(",")))
    expected = {"/workspace": "rw", "/workspace/.git": "ro", "/python": "ro",
                "/agent-home": "rw", "/evaluator-output": "rw"}
    for target, mode in expected.items():
        need(len(found.get(target, [])) == 1 and mode in found[target][0],
             "unexpected mount: " + target)
    marker = pathlib.Path("/workspace/.mdseval-runtime-smoke")
    marker.write_text("workspace-write", encoding="utf-8")
    need(marker.read_text(encoding="utf-8") == "workspace-write", "workspace is not writable")
    marker.unlink()
    return expected

def identity(image, pin):
    executable = os.path.realpath(sys.executable)
    resolution = shutil.which("python3")
    need(platform.python_version() == pin, "interpreter pin mismatch")
    need(executable.startswith("/python/") and resolution is not None
         and os.path.realpath(resolution) == executable, "interpreter path mismatch")
    return {"canonical_executable": executable, "version": sys.version,
            "executable_sha256": digest(pathlib.Path(executable).read_bytes()),
            "image_digest": image, "path_resolution": resolution}

def home():
    home = pathlib.Path("/agent-home")
    sessions = home / "sessions"
    need(sessions.is_dir() and not sessions.is_symlink(), "unsafe isolated sessions")
    profile = home / ".bash_profile"
    wrapper = home / "bin" / "pytest"
    need(profile.is_file() and not profile.is_symlink()
         and digest(profile.read_bytes()) == os.environ["MDSEVAL_SHELL_PROFILE_SHA256"]
         and stat.S_IMODE(profile.stat().st_mode) == 0o600,
         "unsafe fixed shell profile")
    need(wrapper.is_file() and not wrapper.is_symlink()
         and digest(wrapper.read_bytes()) == os.environ["MDSEVAL_PYTEST_WRAPPER_SHA256"]
         and stat.S_IMODE(wrapper.stat().st_mode) == 0o500,
         "unsafe pytest wrapper")
    entries = {path.name for path in home.iterdir()}
    bin_entries = {path.name for path in (home / "bin").iterdir()}
    need(entries == {".bash_profile", "bin", "sessions"} and bin_entries == {"pytest"},
         "unsafe isolated home topology")
    need(not (home / "auth.json").exists(), "credential reached non-model smoke")
    command = ["/usr/bin/bash", "-lc", """
set -eu
python3 - <<'PY'
import importlib.util, json, os, pathlib, shutil, sys
pytest = importlib.util.find_spec("pytest")
print(json.dumps({
    "path": os.environ.get("PATH"),
    "python": shutil.which("python"),
    "python3": shutil.which("python3"),
    "pytest": shutil.which("pytest"),
    "canonical_executable": os.path.realpath(sys.executable),
    "pytest_origin": pytest.origin if pytest else None,
}, sort_keys=True, separators=(",", ":")))
PY
pytest --version
"""]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    lines = result.stdout.splitlines()
    need(result.returncode == 0 and len(lines) >= 2, "login-shell pytest probe failed")
    row = json.loads(lines[0])
    need(row == {"path": os.environ["MDSEVAL_EXPECTED_SHELL_PATH"],
                 "python": "/python/bin/python", "python3": "/python/bin/python3",
                 "pytest": "/agent-home/bin/pytest",
                 "canonical_executable": os.path.realpath("/python/bin/python3"),
                 "pytest_origin": "/sealed-deps/pytest/__init__.py"},
         "login-shell environment or interpreter mismatch")
    return {"credential": "absent", "profile_sha256": digest(profile.read_bytes()),
            "pytest_wrapper_sha256": digest(wrapper.read_bytes()), "shell": row}

def python_source(path):
    with tokenize.open(path) as stream:
        return stream.read()

def sources(target):
    if target.startswith("filesystem:"):
        relative = target.split(":", 1)[1]
        result = []
        for entry in sys.path:
            base = os.path.abspath(entry or os.getcwd())
            candidate = os.path.normpath(os.path.join(base, relative))
            if not os.path.isfile(candidate) or os.path.islink(candidate):
                continue
            result.append((candidate, python_source(candidate)))
        return sorted(set(result))
    try:
        value = pydoc.locate(target)
        if value is None:
            return []
        source = inspect.getsource(value)
        origin = inspect.getsourcefile(value) or inspect.getfile(value)
        return [(origin, source)]
    except Exception:
        return []

def targets(spec):
    rows = []
    for task_id in sorted(spec):
        item = spec[task_id]
        signatures = [(digest(value), normalized(value))
                      for value in item["fix_signature_strings"]]
        for target in item["answer_bearing_modules"]:
            located = sources(target)
            source_hashes = sorted(digest(normalized(source)) for _, source in located)
            matches = sorted(signature_hash for signature_hash, signature in signatures
                             if any(signature in normalized(source) for _, source in located))
            need(not matches, "fix signature present in targeted source: " + target)
            rows.append({"task_id": task_id, "target": target,
                         "source_available": bool(located),
                         "source_sha256": source_hashes,
                         "checked_signature_sha256": sorted(value[0] for value in signatures)})
    return rows

def bare_connect(host, port):
    last = None
    for _ in range(30):
        try:
            connection = socket.create_connection((host, port), timeout=1)
            connection.close()
            return True
        except OSError as exc:
            last = exc
            time.sleep(0.1)
    raise RuntimeError("isolated proxy is unreachable: " + type(last).__name__)

def main():
    payload = json.load(sys.stdin)
    rows = targets(payload["tasks"])
    result = {"status": "PASS", "identity": identity(payload["image"], payload["pin"]),
              "mounts": mounts(), "home": home(), "bare_connect": bare_connect(
                  payload["proxy_host"], payload["proxy_port"]),
              "target_checks": rows}
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))

try:
    main()
except Exception as exc:
    print(json.dumps({"status": "FAIL", "error": type(exc).__name__ + ": " + str(exc)},
                     sort_keys=True, separators=(",", ":")))
    raise SystemExit(2)
'''

_POLICY_CHILD_SCRIPT = r'''
import errno, hashlib, importlib.util, json, os, pathlib, shutil, socket, sys

def identity(image):
    executable = os.path.realpath(sys.executable)
    return {"canonical_executable": executable, "version": sys.version,
            "executable_sha256": hashlib.sha256(pathlib.Path(executable).read_bytes()).hexdigest(),
            "image_digest": image, "path_resolution": shutil.which("python3")}

def main():
    row = {"identity": identity(sys.argv[3]),
           "socket_target": [sys.argv[1], int(sys.argv[2])]}
    pytest = importlib.util.find_spec("pytest")
    row["shell"] = {"path": os.environ.get("PATH"),
                    "library_path": os.environ.get("LD_LIBRARY_PATH"),
                    "python": shutil.which("python"),
                    "python3": shutil.which("python3"),
                    "pytest": shutil.which("pytest"),
                    "pytest_origin": pytest.origin if pytest else None,
                    "forbidden_environment": sorted(name for name in os.environ
                        if name == "CODEX_HOME" or name.upper().endswith(
                            ("_PROXY", "_TOKEN", "_SECRET", "_KEY")))}
    marker = pathlib.Path("/workspace/.mdseval-policy-write")
    marker.write_text("workspace-write", encoding="utf-8")
    row["workspace_write"] = marker.read_text(encoding="utf-8") == "workspace-write"
    marker.unlink()
    for name, path in (("auth_denial", "/agent-home/auth.json"),
                       ("sessions_denial", "/agent-home/sessions"),
                       ("proc_denial", "/proc/self/status")):
        try:
            pathlib.Path(path).read_bytes()
            row[name] = None
        except PermissionError as exc:
            row[name] = "PermissionError: " + str(exc)
        except Exception as exc:
            row[name] = type(exc).__name__ + ": " + str(exc)
    for name, path in (("output_denial", "/evaluator-output/model-final.txt"),
                       ("git_denial", "/workspace/.git/mdseval-write-probe"),
                       ("profile_denial", "/agent-home/.bash_profile"),
                       ("wrapper_denial", "/agent-home/bin/pytest")):
        try:
            pathlib.Path(path).write_text("forbidden", encoding="utf-8")
            row[name] = None
        except OSError as exc:
            row[name] = type(exc).__name__ + ": " + str(exc)
    try:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.sendto(b"mdseval", (sys.argv[1], int(sys.argv[2])))
        udp.close()
        row["udp_denial"] = None
    except OSError as exc:
        row["udp_denial"] = {"type": type(exc).__name__, "errno": exc.errno}
    try:
        resolved = socket.getaddrinfo("model-proxy", int(sys.argv[2]))
        row["dns_denial"] = None if resolved else {"type": "empty", "errno": None}
    except OSError as exc:
        row["dns_denial"] = {"type": type(exc).__name__, "errno": exc.errno}
    try:
        connection = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=5)
        connection.close()
        row.update({"status": "FAIL", "denial": None, "exit_status": 0})
        code = 2
    except PermissionError as exc:
        explicit = exc.errno == errno.EPERM
        row.update({"status": "DENIED" if explicit else "FAIL",
                    "denial": "PermissionError: " + str(exc), "exit_status": exc.errno})
        code = 0 if explicit else 2
    except Exception as exc:
        row.update({"status": "FAIL", "denial": type(exc).__name__ + ": " + str(exc),
                    "exit_status": getattr(exc, "errno", 2)})
        code = 2
    print(json.dumps(row, sort_keys=True, separators=(",", ":")))
    return code

try:
    raise SystemExit(main())
except Exception as exc:
    print(json.dumps({"status": "FAIL", "error": type(exc).__name__ + ": " + str(exc)},
                     sort_keys=True, separators=(",", ":")))
    raise SystemExit(2)
'''

def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()

def _remaining(deadline: float | None, check: str) -> float | None:
    if deadline is None:
        return None
    if isinstance(deadline, bool) or not isinstance(deadline, (int, float)):
        raise ValueError("preflight deadline must be an absolute monotonic time")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError(f"global preflight deadline expired during {check}")
    return remaining

def spec_ids() -> list[str]:
    return sorted(json.loads(SPEC.read_text(encoding="utf-8")))

def _docker(*args: str, check: bool = True,
            deadline: float | None = None) -> subprocess.CompletedProcess[str]:
    timeout = _remaining(deadline, "docker " + " ".join(args))
    try:
        result = subprocess.run([*DOCKER, *args], capture_output=True, text=True,
                                check=False, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise TimeoutError("global preflight deadline expired during docker "
                           + " ".join(args)) from exc
    _remaining(deadline, "docker " + " ".join(args))
    if check and result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip())
    return result

def _remove_container(name: str, *, deadline: float | None = None) -> None:
    result = _docker("rm", "-f", name, check=False, deadline=deadline)
    detail = (result.stderr or result.stdout).strip()
    if result.returncode and "No such container" not in detail:
        raise RuntimeError("sealed container cleanup failed: " + detail)

def image_id(image: str, *, deadline: float | None = None) -> str:
    value = _docker("image", "inspect", "--format", "{{.Id}}", image,
                    deadline=deadline).stdout.strip()
    if value != image or len(value) != 71 or not value.startswith("sha256:"):
        raise RuntimeError("runtime image is not the approved content-addressed digest")
    return value
def security_args(image: str, pin: str) -> list[str]:
    return ["internal-model-proxy", *SECURITY, "--user", f"{os.getuid()}:{os.getgid()}",
            "--workdir", "/workspace", *FIXED_ENV, *PROXY_ENV, "/workspace:rw",
            "/workspace/.git:ro", f"interpreter:{pin}:/python:ro",
            "fresh-agent-home:/agent-home:rw",
            "fresh-evaluator-output:/evaluator-output:rw",
            "subject-shell-profile-sha256:" + sha(SHELL_PROFILE),
            "pytest-wrapper-sha256:" + sha(PYTEST_WRAPPER),
            "subject-config-sha256:" + sha(canonical(SUBJECT_REQUIRED_CONFIGS).encode()),
            image]

def security_sha256(image: str, pin: str) -> str:
    return sha(canonical(security_args(image, pin)).encode())

def _pin_path(pin: str, *, deadline: float | None = None) -> Path:
    _remaining(deadline, "interpreter pin")
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", pin) is None:
        raise RuntimeError("unsafe interpreter pin")
    source = PINS / pin
    if (PINS.is_symlink() or not PINS.is_dir() or source.is_symlink()
            or not source.is_dir() or source.resolve() != PINS.resolve() / pin):
        raise RuntimeError("unsafe interpreter pin source")
    _remaining(deadline, "interpreter pin")
    return source.resolve()

@contextmanager
def _home(codex_home: Path, *, deadline: float | None = None,
          include_auth: bool = False, profiled_shell: bool = False):
    _remaining(deadline, "isolated agent home")
    auth = Path(codex_home) / "auth.json"
    if include_auth and (auth.is_symlink() or not auth.is_file() or not auth.stat().st_size):
        raise RuntimeError("sealed agent home source lacks safe auth.json")
    with tempfile.TemporaryDirectory(prefix="mdseval-agent-home-") as name:
        root = Path(name)
        if include_auth:
            shutil.copyfile(auth, root / "auth.json")
            os.chmod(root / "auth.json", 0o600)
        (root / "sessions").mkdir()
        expected = {"sessions"}
        if include_auth:
            expected.add("auth.json")
        if profiled_shell:
            (root / ".bash_profile").write_bytes(SHELL_PROFILE)
            os.chmod(root / ".bash_profile", 0o600)
            (root / "bin").mkdir()
            (root / "bin" / "pytest").write_bytes(PYTEST_WRAPPER)
            os.chmod(root / "bin" / "pytest", 0o500)
            expected.update({".bash_profile", "bin", "bin/pytest"})
        entries = {path.relative_to(root).as_posix() for path in root.rglob("*")}
        if entries != expected or any(path.is_symlink() for path in root.rglob("*")):
            raise RuntimeError("unsafe sealed agent home")
        _remaining(deadline, "isolated agent home")
        yield root

def _args(image: str, pin: str, workspace: Path, home: Path, network: str,
          extra_environment: tuple[str, ...] = (), *,
          evaluator_output: Path | None = None,
          protect_git: bool = False,
          container_name: str | None = None) -> list[str]:
    python = _pin_path(pin)
    workspace = workspace.resolve()
    home = home.resolve()
    checked = [python, workspace, home]
    if evaluator_output is not None:
        evaluator_output = evaluator_output.resolve()
        checked.append(evaluator_output)
    git = workspace / ".git"
    if protect_git:
        checked.append(git)
    if not all(path.is_dir() and not path.is_symlink() for path in checked):
        raise RuntimeError("unsafe container bind source")
    args = [*DOCKER, "run", "--rm", "-i"]
    if container_name is not None:
        if re.fullmatch(r"mdseval-subject-[0-9a-f]{24}", container_name) is None:
            raise RuntimeError("unsafe sealed container name")
        args.extend(("--name", container_name))
    args.extend(("--network", network, *SECURITY, "--user",
                 f"{os.getuid()}:{os.getgid()}", "--workdir", "/workspace"))
    for value in (*FIXED_ENV, *(() if network == "none" else PROXY_ENV), *extra_environment):
        args.extend(("-e", value))
    mounts = ["--mount", f"type=bind,src={workspace},dst=/workspace",
              "--mount", f"type=bind,src={python},dst=/python,readonly",
              "--mount", f"type=bind,src={home},dst=/agent-home"]
    if evaluator_output is not None:
        mounts.extend(("--mount", f"type=bind,src={evaluator_output},dst=/evaluator-output"))
    if protect_git:
        mounts.extend(("--mount", f"type=bind,src={git},dst=/workspace/.git,readonly"))
    return [*args, *mounts, image]

def _run(image: str, pin: str, workspace: Path, codex_home: Path, network: str,
         command: list[str], *, stdin: str | None = None, timeout: float = 60,
         deadline: float | None = None,
         linger_seconds: float = 0.0, include_auth: bool = False,
         profiled_shell: bool = False,
         evaluator_output: Path | None = None,
         protect_git: bool = False) -> tuple[ProcessOutcome, list[str]]:
    extra_environment = (("MDSEVAL_SHELL_PROFILE_SHA256=" + sha(SHELL_PROFILE),
                          "MDSEVAL_PYTEST_WRAPPER_SHA256=" + sha(PYTEST_WRAPPER),
                          "MDSEVAL_EXPECTED_SHELL_PATH=" + SHELL_PATH)
                         if profiled_shell else ())
    with _home(codex_home, deadline=deadline, include_auth=include_auth,
               profiled_shell=profiled_shell) as home:
        container_name = "mdseval-subject-" + secrets.token_hex(12)
        args = [*_args(image, pin, workspace, home, network, extra_environment,
                       evaluator_output=evaluator_output, protect_git=protect_git,
                       container_name=container_name),
                *command]
        remaining = _remaining(deadline, "sealed container process")
        if remaining is not None and remaining <= 1.1:
            raise TimeoutError("global preflight deadline expired before sealed process cleanup")
        process_timeout = min(timeout, remaining - 1.1) if remaining is not None else timeout
        result: ProcessOutcome | None = None
        try:
            if not linger_seconds:
                result = run_process_group(args, cwd=workspace, input_text=stdin,
                                           timeout=process_timeout,
                                           environment=os.environ.copy())
            else:
                if stdin is None or linger_seconds <= 0:
                    raise ValueError("lingering sealed process requires nonempty stdin")
                process = subprocess.Popen(
                    args, cwd=workspace, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True, encoding="utf-8",
                    env=os.environ.copy(), start_new_session=True)
                try:
                    assert process.stdin is not None
                    process.stdin.write(stdin)
                    process.stdin.flush()
                    time.sleep(min(linger_seconds, max(0.0, process_timeout - 1.0)))
                    process.stdin.close()
                    process.stdin = None
                    stdout, stderr = process.communicate(
                        timeout=max(0.1, process_timeout - linger_seconds)
                    )
                    result = ProcessOutcome(
                        process.returncode, stdout or "", stderr or "", False, False
                    )
                except subprocess.TimeoutExpired as exc:
                    _stop_group(process)
                    process.communicate(timeout=1)
                    raise TimeoutError(
                        "global preflight deadline expired during sealed container process"
                    ) from exc
                except BaseException:
                    _stop_group(process)
                    process.communicate(timeout=1)
                    raise
        finally:
            active_error = sys.exc_info()[0] is not None
            cleanup_deadline = deadline
            if cleanup_deadline is None:
                cleanup_deadline = time.monotonic() + 10.0
            try:
                _remove_container(container_name, deadline=cleanup_deadline)
            except Exception as exc:
                if result is not None and not active_error:
                    result = ProcessOutcome(
                        result.returncode if result.returncode else 125,
                        result.stdout,
                        result.stderr
                        + "\nMDSEVAL: " + type(exc).__name__ + ": " + str(exc) + "\n",
                        result.timed_out,
                        result.interrupted,
                    )
        _remaining(deadline, "sealed container process")
        assert result is not None
        if deadline is not None and result.timed_out:
            raise TimeoutError("global preflight deadline expired during sealed container process")
        return result, args

@contextmanager
def _network(image: str, *, deadline: float | None = None,
             cleanup_grace_seconds: float | None = None):
    suffix = secrets.token_hex(6)
    network = f"mdseval-{suffix}"
    proxy = f"mdseval-proxy-{suffix}"
    _docker("network", "create", "--internal", network, deadline=deadline)
    try:
        _docker("run", "-d", "--rm", "--name", proxy, "--network", network, "--network-alias", "model-proxy",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges=true", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=1m",
                "--user", "tinyproxy:tinyproxy", image, "/usr/bin/tinyproxy", "-d", "-c", "/etc/tinyproxy/mdseval.conf",
                deadline=deadline)
        _docker("network", "connect", "bridge", proxy, deadline=deadline)
        details = json.loads(_docker("inspect", proxy, deadline=deadline).stdout)[0]
        ip = details["NetworkSettings"]["Networks"][network]["IPAddress"]
        yield network, ip
    finally:
        cleanup_deadline = (
            time.monotonic() + cleanup_grace_seconds
            if cleanup_grace_seconds is not None
            else deadline
        )
        failures = []
        for arguments in (("stop", "--time", "1", proxy), ("network", "rm", network)):
            try:
                result = _docker(*arguments, check=False, deadline=cleanup_deadline)
                detail = (result.stderr or result.stdout).strip()
                if result.returncode and "No such" not in detail:
                    failures.append(" ".join(arguments) + ": " + detail)
            except (OSError, RuntimeError, TimeoutError,
                    subprocess.SubprocessError) as exc:
                failures.append(" ".join(arguments) + ": " + type(exc).__name__)
        if failures:
            raise RuntimeError("sealed network cleanup failed: " + "; ".join(failures))

def _json_line(value: str) -> dict[str, Any]:
    rows = [json.loads(line) for line in value.splitlines() if line.strip()]
    if not rows or not isinstance(rows[-1], dict):
        raise RuntimeError("missing JSON record")
    return rows[-1]
def _identity(image: str, pin: str, workspace: Path, codex_home: Path, network: str = "none") -> dict[str, Any]:
    command = ["/python/bin/python3", "/usr/lib/mdseval/probe.py", "identity", image]
    result, _ = _run(image, pin, workspace, codex_home, network, command)
    row = _json_line(result.stdout)
    if result.returncode or row.pop("check", None) != "identity" or row.pop("status", None) != "PASS":
        raise RuntimeError("interpreter identity failed")
    return row

def _resolved_web_search(reply: dict[str, Any]) -> dict[str, Any]:
    result = reply.get("result") if isinstance(reply, dict) else None
    config = result.get("config") if isinstance(result, dict) else None
    origins = result.get("origins") if isinstance(result, dict) else None
    layers = result.get("layers") if isinstance(result, dict) else None
    origin = origins.get("web_search") if isinstance(origins, dict) else None
    name = origin.get("name") if isinstance(origin, dict) else None
    session_modes = [layer.get("config", {}).get("web_search") for layer in layers
                     if isinstance(layer, dict) and layer.get("name") == {"type": "sessionFlags"}
                     and isinstance(layer.get("config"), dict)] if isinstance(layers, list) else []
    evidence = {"mode": config.get("web_search") if isinstance(config, dict) else None,
                "origin_type": name.get("type") if isinstance(name, dict) else None,
                "session_layer_modes": session_modes}
    if evidence != WEB_SEARCH_DISABLED_EVIDENCE:
        raise RuntimeError("resolved web search is not disabled by the session flag")
    return evidence

def _resolved_subject_surface(reply: dict[str, Any]) -> str:
    result = reply.get("result") if isinstance(reply, dict) else None
    config = result.get("config") if isinstance(result, dict) else None
    layers = result.get("layers") if isinstance(result, dict) else None
    if not isinstance(config, dict) or not isinstance(layers, list):
        raise RuntimeError("resolved subject configuration is absent")
    features = config.get("features")
    apps = config.get("apps")
    default_app = apps.get("_default") if isinstance(apps, dict) else None
    skills = config.get("skills")
    if (not isinstance(features, dict)
            or any(features.get(name) is not False for name in DISABLED_FEATURES)
            or not isinstance(default_app, dict)
            or any(default_app.get(name) is not False
                   for name in ("enabled", "destructive_enabled", "open_world_enabled"))
            or skills != {"bundled": {"enabled": False}, "include_instructions": False}
            or any(config.get(name) != {} for name in ("mcp_servers", "plugins", "marketplaces"))
            or config.get("agents", {}).get("enabled") is not False
            or config.get("default_permissions") != "mdseval"):
        raise RuntimeError("external subject capability surface is not disabled")
    session = [layer for layer in layers if isinstance(layer, dict)
               and layer.get("name") == {"type": "sessionFlags"}]
    if len(session) != 1 or not isinstance(session[0].get("config"), dict):
        raise RuntimeError("subject capability overrides lack a unique session layer")
    session_config = session[0]["config"]
    session_features = session_config.get("features")
    session_apps = session_config.get("apps", {}).get("_default")
    if (not isinstance(session_features, dict)
            or any(session_features.get(name) is not False for name in DISABLED_FEATURES)
            or not isinstance(session_apps, dict)
            or any(session_apps.get(name) is not False
                   for name in ("enabled", "destructive_enabled", "open_world_enabled"))
            or session_config.get("skills") != {
                "bundled": {"enabled": False}, "include_instructions": False,
                "config": []}):
        raise RuntimeError("subject capability overrides are not session-bound")
    lower = [layer for layer in layers if isinstance(layer, dict)
             and isinstance(layer.get("name"), dict)
             and layer["name"].get("type") in {"user", "system"}]
    if len(lower) != 2 or any(layer.get("config") != {} for layer in lower):
        raise RuntimeError("subject user/system configuration layers are not empty")
    evidence = {"disabled_features": sorted(DISABLED_FEATURES),
                "apps": {name: default_app[name] for name in (
                    "enabled", "destructive_enabled", "open_world_enabled")},
                "skills": skills, "mcp_servers": {}, "plugins": {}, "marketplaces": {},
                "agents_enabled": False, "default_permissions": "mdseval",
                "lower_layers_empty": True}
    return sha(canonical(evidence).encode())

def container_web_search_valid(value: dict[str, Any], required: bool) -> bool:
    return (("web_search" not in value or value["web_search"] == "disabled")
            and (not required or value.get("web_search") == "disabled"))

def bind_web_search_evidence(result: dict[str, Any], container: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    if container.get("web_search") != "disabled":
        return result
    evidence = policy.get("policy", {}).get("web_search")
    if evidence != WEB_SEARCH_DISABLED_EVIDENCE:
        raise RuntimeError("sealed preflight does not prove web search disabled")
    return {**result, "web_search": evidence}

def event_usage_and_web_search(path: Path) -> tuple[dict[str, int], bool]:
    parsed = parse_event_stream(path)
    seen = any(isinstance(item := event.get("item"), dict) and item.get("type") == "web_search"
               for event in parsed.events)
    return parsed.usage, seen

def _policy(image: str, pin: str, workspace: Path, codex_home: Path, network: str, ip: str) -> dict[str, Any]:
    child = ["/python/bin/python3", "/usr/lib/mdseval/probe.py", "policy-child", ip, "8888", image]
    retry = "import socket,sys,time\nfor i in range(30):\n try:\n  socket.create_connection((sys.argv[1],int(sys.argv[2])),3).close()\n  break\n except OSError:\n  if i==29: raise\n  time.sleep(.1)"
    bare, bare_argv = _run(image, pin, workspace, codex_home, network,
                           ["/python/bin/python3", "-c", retry, ip, "8888"])
    messages = [
        {"method": "initialize", "id": 1, "params": {"clientInfo": {"name": "mdseval_policy_probe", "title": "MD Eval policy probe", "version": "1"}, "capabilities": {"experimentalApi": True}}},
        {"method": "initialized", "params": {}},
        {"method": "config/read", "id": 2, "params": {"cwd": "/workspace", "includeLayers": True}},
        {"method": "command/exec", "id": 3, "params": {"command": child, "cwd": "/workspace", "disableOutputCap": True, "timeoutMs": 10000}}]
    with _home(codex_home) as app_home:
        app_argv = [*_args(image, pin, workspace, app_home, network), "/usr/lib/codex/bin/codex",
                    "--strict-config", "-c", WEB_SEARCH_DISABLED_CONFIG,
                    "-c", 'sandbox_mode="workspace-write"', "-c",
                    "sandbox_workspace_write.network_access=false", "app-server"]
        process = subprocess.Popen(app_argv, cwd=workspace, stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   encoding="utf-8", env=os.environ.copy(), start_new_session=True)
        process.stdin.write("".join(canonical(row) + "\n" for row in messages))
        process.stdin.flush()
        time.sleep(8)
        stdout, stderr = process.communicate(timeout=20)
        app = ProcessOutcome(process.returncode, stdout, stderr, False, False)
    rows = list(map(json.loads, app.stdout.splitlines()))
    config_replies = [row for row in rows if row.get("id") == 2]
    replies = [row for row in rows if row.get("id") == 3]
    if bare.returncode or app.returncode or len(config_replies) != 1 or len(replies) != 1 or "result" not in replies[0]:
        raise RuntimeError("policy export failed: " + canonical({"bare": [bare.returncode, bare.stderr[-1000:]], "app": [app.returncode, app.stdout[-1000:], app.stderr[-1000:]], "config_replies": config_replies, "replies": replies}))
    web_search = _resolved_web_search(config_replies[0])
    reply = replies[0]
    source = _json_line(reply["result"]["stdout"])
    profile = source.get("permission_profile")
    if not profile:
        raise RuntimeError("policy child failed: " + canonical(reply))
    state = canonical({"permissionProfile": profile, "codexLinuxSandboxExe": "/usr/lib/codex/bin/codex",
                       "sandboxCwd": "file:///workspace", "useLegacyLandlock": False})
    replay, replay_argv = _run(image, pin, workspace, codex_home, network,
                               ["/usr/lib/codex/bin/codex", "sandbox", "--sandbox-state-json",
                                state, "--", *child])
    replay_row = _json_line(replay.stdout)
    if replay.returncode or source.get("status") != "DENIED" or replay_row.get("status") != "DENIED" or source.get("policy_sha256") != replay_row.get("policy_sha256"):
        raise RuntimeError("resolved policy replay mismatch")
    return {"bare_connect": True, "socket_target": replay_row["socket_target"],
            "source_argv": source["parent_argv"], "replay_argv": replay_row["parent_argv"],
            "source_sha256": source["policy_sha256"], "replay_sha256": replay_row["policy_sha256"],
            "source_identity": source["identity"], "replay_identity": replay_row["identity"],
            "denial": replay_row["denial"], "exit_status": replay_row["exit_status"],
            "identity": source["identity"], "bare_argv": bare_argv,
            "export_container_argv": app_argv, "replay_container_argv": replay_argv,
            "process_returncode": replay.returncode, "web_search": web_search}

def _valid_smoke_item(value: Any) -> bool:
    target = r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*"
    filesystem = r"filesystem:(?!/)(?!\.\.(?:/|$))(?!.*?/\.\.(?:/|$))[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*\.py"
    return (isinstance(value, dict)
            and set(value) == {"answer_bearing_modules", "fix_signature_strings", "interpreter_pin"}
            and isinstance(value["answer_bearing_modules"], list)
            and bool(value["answer_bearing_modules"])
            and len(value["answer_bearing_modules"]) == len(set(value["answer_bearing_modules"]))
            and all(isinstance(item, str) and re.fullmatch(target + "|" + filesystem, item)
                    for item in value["answer_bearing_modules"])
            and isinstance(value["fix_signature_strings"], list)
            and bool(value["fix_signature_strings"])
            and len(value["fix_signature_strings"]) == len(set(value["fix_signature_strings"]))
            and all(isinstance(item, str)
                    and len("".join(character for character in item
                                    if not character.isspace())) >= 20
                    for item in value["fix_signature_strings"])
            and isinstance(value["interpreter_pin"], str)
            and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["interpreter_pin"]) is not None)

def _smoke_spec(task_ids: list[str], pin: str,
                deadline: float | None = None) -> tuple[dict[str, Any], str]:
    _remaining(deadline, "contamination specification")
    if (not isinstance(task_ids, list) or not task_ids
            or any(not isinstance(task_id, str) for task_id in task_ids)
            or len(task_ids) != len(set(task_ids))):
        raise RuntimeError("runtime smoke task IDs are invalid")
    raw = SPEC.read_bytes()
    try:
        full = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("contamination specification is malformed") from exc
    ids = sorted(task_ids)
    if (not isinstance(full, dict) or any(task_id not in full for task_id in ids)
            or any(not _valid_smoke_item(full[task_id]) for task_id in ids)):
        raise RuntimeError("runtime smoke tasks are absent or malformed in contamination specification")
    selected = {task_id: full[task_id] for task_id in ids}
    if any(value["interpreter_pin"] != pin for value in selected.values()):
        raise RuntimeError("runtime smoke interpreter pin differs from contamination specification")
    _remaining(deadline, "contamination specification")
    return selected, sha(raw)

def _targeted_smoke(image: str, pin: str, tasks: dict[str, Any], workspace: Path,
                    codex_home: Path, network: str, ip: str,
                    deadline: float, evaluator_output: Path) -> dict[str, Any]:
    payload = canonical({"image": image, "pin": pin, "proxy_host": ip,
                         "proxy_port": 8888, "tasks": tasks})
    command = ["/python/bin/python3", "-c", _TARGETED_SMOKE_SCRIPT]
    result, _ = _run(image, pin, workspace, codex_home, network, command,
                     stdin=payload, deadline=deadline, profiled_shell=True,
                     evaluator_output=evaluator_output, protect_git=True)
    try:
        row = _json_line(result.stdout)
    except (UnicodeError, json.JSONDecodeError, RuntimeError, TypeError) as exc:
        raise RuntimeError("targeted sealed-runtime smoke returned malformed JSON") from exc
    if result.returncode or row.get("status") != "PASS":
        raise RuntimeError("targeted sealed-runtime smoke failed: "
                           + str(row.get("error", result.stderr[-500:])))
    if (set(row) != {"status", "identity", "mounts", "home", "bare_connect", "target_checks"}
            or row["mounts"] != FAST_MOUNTS or not isinstance(row["home"], dict)
            or row["home"].get("credential") != "absent"
            or row["home"].get("profile_sha256") != sha(SHELL_PROFILE)
            or row["home"].get("pytest_wrapper_sha256") != sha(PYTEST_WRAPPER)
            or row["bare_connect"] is not True or not isinstance(row["identity"], dict)
            or not isinstance(row["target_checks"], list)):
        raise RuntimeError("targeted sealed-runtime smoke proof is incomplete")
    expected = [(task_id, target,
                 sorted(sha(signature.encode())
                        for signature in tasks[task_id]["fix_signature_strings"]))
                for task_id in sorted(tasks)
                for target in tasks[task_id]["answer_bearing_modules"]]
    checks = row["target_checks"]
    if len(checks) != len(expected):
        raise RuntimeError("targeted contamination check coverage is incomplete")
    for check, (task_id, target, signatures) in zip(checks, expected):
        good = (isinstance(check, dict)
                and set(check) == {"task_id", "target", "source_available",
                                   "source_sha256", "checked_signature_sha256"}
                and check["task_id"] == task_id and check["target"] == target
                and isinstance(check["source_available"], bool)
                and isinstance(check["source_sha256"], list)
                and all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
                        for value in check["source_sha256"])
                and check["checked_signature_sha256"] == signatures)
        if not good:
            raise RuntimeError("targeted contamination check proof is malformed")
    identity = row["identity"]
    identity_good = (set(identity) == {"canonical_executable", "version", "executable_sha256",
                                      "image_digest", "path_resolution"}
                     and identity["image_digest"] == image
                     and isinstance(identity["canonical_executable"], str)
                     and identity["canonical_executable"].startswith("/python/")
                     and isinstance(identity["path_resolution"], str)
                     and identity["path_resolution"].startswith("/python/")
                     and isinstance(identity["version"], str)
                     and identity["version"].startswith(pin)
                     and isinstance(identity["executable_sha256"], str)
                     and re.fullmatch(r"[0-9a-f]{64}", identity["executable_sha256"]) is not None)
    if not identity_good:
        raise RuntimeError("sealed interpreter identity proof is malformed")
    return row

def _fast_policy_messages(ip: str, image: str) -> list[dict[str, Any]]:
    login_child = ["/usr/bin/bash", "-lc", "exec " + shlex.join(
        ["python3", "-c", _POLICY_CHILD_SCRIPT, ip, "8888", image])]
    return [
        {"method": "initialize", "id": 1,
         "params": {"clientInfo": {"name": "mdseval_fast_preflight",
                                    "title": "MD Eval fast preflight", "version": "1"},
                    "capabilities": {"experimentalApi": True}}},
        {"method": "initialized", "params": {}},
        {"method": "config/read", "id": 2,
         "params": {"cwd": "/workspace", "includeLayers": True}},
        {"method": "permissionProfile/list", "id": 3,
         "params": {"cwd": "/workspace"}},
        {"method": "command/exec", "id": 4,
         "params": {"command": login_child, "cwd": "/workspace",
                    "disableOutputCap": True, "timeoutMs": FAST_POLICY_COMMAND_TIMEOUT_MS}},
    ]

def _fast_policy(image: str, pin: str, workspace: Path, codex_home: Path,
                 network: str, ip: str, deadline: float,
                 evaluator_output: Path) -> dict[str, Any]:
    command = ["/usr/lib/codex/bin/codex", "--strict-config",
               *config_arguments(SUBJECT_REQUIRED_CONFIGS), "app-server"]
    stdin = "".join(canonical(row) + "\n" for row in _fast_policy_messages(ip, image))
    result, _ = _run(image, pin, workspace, codex_home, network, command,
                     stdin=stdin, deadline=deadline, linger_seconds=FAST_POLICY_LINGER_SECONDS,
                     include_auth=True, profiled_shell=True,
                     evaluator_output=evaluator_output, protect_git=True)
    try:
        rows = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    except (UnicodeError, json.JSONDecodeError, TypeError) as exc:
        raise RuntimeError("fast policy smoke returned malformed JSON") from exc
    config_replies = [row for row in rows if isinstance(row, dict) and row.get("id") == 2]
    profile_replies = [row for row in rows if isinstance(row, dict) and row.get("id") == 3]
    command_replies = [row for row in rows if isinstance(row, dict) and row.get("id") == 4]
    if (result.returncode or len(config_replies) != 1 or len(profile_replies) != 1
            or len(command_replies) != 1
            or not isinstance(command_replies[0].get("result"), dict)):
        detail = {"returncode": result.returncode, "timed_out": result.timed_out,
                  "interrupted": result.interrupted,
                  "config_reply_count": len(config_replies),
                  "profile_reply_count": len(profile_replies),
                  "command_reply_count": len(command_replies),
                  "stdout_tail": result.stdout[-1000:], "stderr_tail": result.stderr[-1000:]}
        raise RuntimeError("fast policy smoke failed: " + canonical(detail))
    web_search = _resolved_web_search(config_replies[0])
    subject_surface_sha256 = _resolved_subject_surface(config_replies[0])
    profile_result = profile_replies[0].get("result")
    profiles = profile_result.get("data") if isinstance(profile_result, dict) else None
    mdseval_profiles = [row for row in profiles if isinstance(row, dict)
                        and row.get("id") == "mdseval"] if isinstance(profiles, list) else []
    expected_profile = {"id": "mdseval", "description": "MD Eval local coding subject",
                        "allowed": True}
    if len(mdseval_profiles) != 1 or mdseval_profiles[0] != expected_profile:
        raise RuntimeError("custom permission profile is not registered and allowed")
    try:
        source = _json_line(command_replies[0]["result"]["stdout"])
    except (KeyError, TypeError, UnicodeError, json.JSONDecodeError, RuntimeError) as exc:
        child = command_replies[0].get("result")
        detail = {
            "exit_code": child.get("exitCode") if isinstance(child, dict) else None,
            "stdout_tail": str(child.get("stdout", ""))[-1000:]
            if isinstance(child, dict)
            else "",
            "stderr_tail": str(child.get("stderr", ""))[-1000:]
            if isinstance(child, dict)
            else "",
        }
        raise RuntimeError(
            "fast policy child returned malformed JSON: " + canonical(detail)
        ) from exc
    denial = source.get("denial")
    shell = source.get("shell")
    expected_shell = {"path": SHELL_PATH, "library_path": "/python/lib",
                      "python": "/python/bin/python",
                      "python3": "/python/bin/python3",
                      "pytest": "/agent-home/bin/pytest",
                      "pytest_origin": "/sealed-deps/pytest/__init__.py",
                      "forbidden_environment": []}
    good = (source.get("status") == "DENIED" and source.get("exit_status") == errno.EPERM
            and isinstance(denial, str) and "PermissionError" in denial
            and source.get("workspace_write") is True
            and all(isinstance(source.get(name), str) and "PermissionError" in source[name]
                    for name in ("auth_denial", "sessions_denial", "proc_denial"))
            and all(isinstance(source.get(name), str)
                    and ("PermissionError" in source[name]
                         or "Read-only file system" in source[name])
                    for name in ("output_denial", "git_denial", "profile_denial",
                                 "wrapper_denial"))
            and source.get("udp_denial") == {
                "type": "PermissionError", "errno": errno.EPERM}
            and source.get("dns_denial") == {
                "type": "gaierror", "errno": LINUX_EAI_AGAIN}
            and shell == expected_shell
            and source.get("socket_target") == [ip, 8888]
            and isinstance(source.get("identity"), dict))
    if not good:
        raise RuntimeError(
            "workspace-write network-denied policy proof failed: "
            + canonical(source)
        )
    policy_evidence = {"profile": expected_profile,
                       "permissions": SUBJECT_PERMISSION_CONFIGS,
                       "workspace_write": True, "network_denied": True,
                       "auth_denied": True, "sessions_denied": True,
                       "output_denied": True, "git_read_only": True,
                       "profile_read_only": True, "wrapper_read_only": True,
                       "udp_denied": True, "dns_denied": True,
                       "proc_denied": True}
    return {"identity": source["identity"],
            "policy_sha256": sha(canonical(policy_evidence).encode()),
            "subject_surface_sha256": subject_surface_sha256,
            "web_search": web_search}

_FAST_SEAL_KEYS = {"seal_schema", "image_digest", "interpreter_pin", "task_ids",
                   "spec_sha256", "runtime_security_sha256", "policy_sha256", "identity",
                   "web_search", "subject_surface_sha256", "mounts", "sandbox", "home", "target_checks_sha256",
                   "seal_sha256"}

def _seal(core: dict[str, Any]) -> dict[str, Any]:
    return {**core, "seal_sha256": sha(canonical(core).encode())}

def _validate_fast_seal(seal: dict[str, Any], image: str, pin: str) -> bool:
    if seal.get("seal_schema") != FAST_SEAL_SCHEMA:
        return False
    if set(seal) != _FAST_SEAL_KEYS:
        raise RuntimeError("fast-preflight seal schema is invalid")
    core = {key: value for key, value in seal.items() if key != "seal_sha256"}
    tasks, spec_sha256 = _smoke_spec(seal.get("task_ids"), pin)
    identity = seal.get("identity")
    good = (seal.get("seal_sha256") == sha(canonical(core).encode())
            and seal.get("image_digest") == image
            and seal.get("interpreter_pin") == pin
            and seal.get("task_ids") == sorted(tasks)
            and seal.get("spec_sha256") == spec_sha256
            and seal.get("runtime_security_sha256") == security_sha256(image, pin)
            and isinstance(seal.get("policy_sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", seal["policy_sha256"]) is not None
            and isinstance(identity, dict) and identity.get("image_digest") == image
            and seal.get("web_search") == WEB_SEARCH_DISABLED_EVIDENCE
            and isinstance(seal.get("subject_surface_sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", seal["subject_surface_sha256"]) is not None
            and seal.get("mounts") == FAST_MOUNTS and seal.get("sandbox") == FAST_SANDBOX
            and isinstance(seal.get("home"), dict)
            and seal["home"].get("credential") == "absent"
            and seal["home"].get("profile_sha256") == sha(SHELL_PROFILE)
            and seal["home"].get("pytest_wrapper_sha256") == sha(PYTEST_WRAPPER)
            and isinstance(seal.get("target_checks_sha256"), str)
            and re.fullmatch(r"[0-9a-f]{64}", seal["target_checks_sha256"]) is not None)
    if not good:
        raise RuntimeError("fast-preflight seal binding is invalid")
    return True

def fast_smoke(image: str, pin: str, task_ids: list[str], codex_home: Path,
               deadline: float) -> dict[str, Any]:
    """Return one deterministic in-memory runtime seal for an image/pin task group."""
    _remaining(deadline, "fast sealed-runtime smoke")
    tasks, spec_sha256 = _smoke_spec(task_ids, pin, deadline)
    _pin_path(pin, deadline=deadline)
    image_id(image, deadline=deadline)
    # Leave time under the caller's one global deadline for Docker cleanup.
    operation_deadline = deadline - 2.0
    _remaining(operation_deadline, "fast sealed-runtime smoke")
    with tempfile.TemporaryDirectory(prefix="mdseval-fast-smoke-") as name, \
         tempfile.TemporaryDirectory(prefix="mdseval-output-") as output_name:
        workspace = Path(name)
        (workspace / ".git").mkdir()
        evaluator_output = Path(output_name)
        with _network(image, deadline=deadline) as (network, ip):
            inspection = _targeted_smoke(image, pin, tasks, workspace, codex_home,
                                         network, ip, operation_deadline,
                                         evaluator_output)
            policy = _fast_policy(image, pin, workspace, codex_home, network, ip,
                                  operation_deadline, evaluator_output)
    _remaining(deadline, "fast sealed-runtime smoke")
    if policy["identity"] != inspection["identity"]:
        raise RuntimeError("sandbox and targeted interpreter identities differ")
    checks_sha256 = sha(canonical(inspection["target_checks"]).encode())
    core = {"seal_schema": FAST_SEAL_SCHEMA, "image_digest": image,
            "interpreter_pin": pin, "task_ids": sorted(tasks),
            "spec_sha256": spec_sha256,
            "runtime_security_sha256": security_sha256(image, pin),
            "policy_sha256": policy["policy_sha256"], "identity": policy["identity"],
            "web_search": policy["web_search"],
            "subject_surface_sha256": policy["subject_surface_sha256"],
            "mounts": dict(FAST_MOUNTS),
            "sandbox": dict(FAST_SANDBOX), "home": inspection["home"],
            "target_checks_sha256": checks_sha256}
    result = _seal(core)
    _validate_fast_seal(result, image, pin)
    _remaining(deadline, "fast sealed-runtime smoke")
    return result

def probe(task_id: str, image: str, pin: str, codex_home: Path) -> tuple[str, str, int]:
    image_id(image)
    with tempfile.TemporaryDirectory(prefix="mdseval-probe-") as name, \
         _network(image) as (network, ip), _home(codex_home, include_auth=True) as home:
        workspace = Path(name)
        shutil.copyfile(SPEC, workspace / "contamination-spec.json")
        policy = _policy(image, pin, workspace, codex_home, network, ip)
        checker_identity = _identity(image, pin, workspace, codex_home)
        command = ["/python/bin/python3", "/usr/lib/mdseval/probe.py", "container", task_id,
                   image, "/workspace/contamination-spec.json", "/workspace/runtime.json"]
        args = [*_args(image, pin, workspace, home, network), *command]
        runtime = {"runtime_args": args, "runtime_security_args": security_args(image, pin),
                   "runtime_security_sha256": security_sha256(image, pin), "policy": policy,
                   "policy_sha256": policy["source_sha256"],
                   "identity": {"subject": policy["identity"], "checker": checker_identity}}
        (workspace / "runtime.json").write_text(canonical(runtime) + "\n", encoding="utf-8")
        result = run_process_group(args, cwd=workspace, input_text=None, timeout=180,
                                   environment=os.environ.copy())
        return result.stdout, result.stderr, result.returncode

def subject(command: list[str], workspace: Path, final_path: Path, stdin: str,
            timeout: int, codex_home: Path, image: str, pin: str,
            seal: dict[str, Any]) -> SubjectOutcome:
    fast = _validate_fast_seal(seal, image, pin)
    if not fast:
        raise RuntimeError("legacy container policy seals cannot authorize a subject launch")
    missing = [value for value in SUBJECT_REQUIRED_CONFIGS if command.count(value) != 1]
    if missing:
        raise RuntimeError("subject command does not contain each required capability, "
                           "permission, and shell policy exactly once: " + canonical(missing))
    if seal.get("runtime_security_sha256") != security_sha256(image, pin):
        raise RuntimeError("approved runtime security mismatch")
    rewritten = list(command)
    rewritten[0] = "/usr/lib/codex/bin/codex"
    rewritten[rewritten.index("--cd") + 1] = "/workspace"
    result: ProcessOutcome | None = None
    subject_duration: float | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="mdseval-output-") as output_name:
            evaluator_output = Path(output_name)
            temporary = evaluator_output / "final-message.txt"
            rewritten[rewritten.index("--output-last-message") + 1] = (
                "/evaluator-output/final-message.txt"
            )
            with _network(
                image,
                deadline=time.monotonic() + 15.0,
                cleanup_grace_seconds=10.0,
            ) as (network, ip):
                subject_started = time.monotonic()
                result, _ = _run(
                    image,
                    pin,
                    workspace,
                    codex_home,
                    network,
                    rewritten,
                    stdin=stdin,
                    timeout=timeout,
                    include_auth=True,
                    profiled_shell=True,
                    evaluator_output=evaluator_output,
                    protect_git=True,
                )
                subject_duration = time.monotonic() - subject_started
            if os.path.lexists(temporary):
                mode = os.lstat(temporary).st_mode
                if stat.S_ISREG(mode) and not temporary.is_symlink():
                    final_path.write_bytes(temporary.read_bytes())
                else:
                    result = ProcessOutcome(
                        result.returncode if result.returncode else 125,
                        result.stdout,
                        result.stderr
                        + "\nMDSEVAL: evaluator final-message path was not a regular file\n",
                        result.timed_out,
                        result.interrupted,
                    )
    except Exception as exc:
        if result is None:
            raise
        result = ProcessOutcome(
            result.returncode if result.returncode else 125,
            result.stdout,
            result.stderr
            + "\nMDSEVAL: " + type(exc).__name__ + ": " + str(exc) + "\n",
            result.timed_out,
            result.interrupted,
        )
    assert result is not None
    assert subject_duration is not None
    return SubjectOutcome(result, subject_duration)

def checker(task: Path, source: Path, image: str, pin: str, codex_home: Path, expected: dict[str, Any] | None = None) -> tuple[dict[str, Any], bool, float, dict[str, Any]]:
    image_id(image)
    with tempfile.TemporaryDirectory(prefix="mdseval-score-") as name:
        root = Path(name)
        shutil.copy2(task / "check.py", root / "check.py")
        shutil.copytree(task / "private", root / "private")
        config = task / "checker-config.json"
        if os.path.lexists(config):
            if config.is_symlink() or not stat.S_ISREG(os.lstat(config).st_mode):
                raise RuntimeError("unsafe task-root checker-config.json")
            shutil.copy2(config, root / config.name, follow_symlinks=False)
        shutil.copytree(source, root / "source", ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"))
        identity = _identity(image, pin, root, codex_home)
        if expected is not None and identity != expected:
            raise RuntimeError("checker identity mismatch")
        started = time.monotonic()
        runs = [_run(image, pin, root, codex_home, "none",
                     ["/python/bin/python3", "/workspace/check.py", "/workspace/source"])[0]
                for _ in range(2)]
        duration = time.monotonic() - started
        evidence = {"identity": identity, "image_digest": image, "interpreter_pin": pin,
                    "runs": [{"returncode": run.returncode, "stdout": run.stdout,
                              "stderr": run.stderr, "timed_out": run.timed_out,
                              "interrupted": run.interrupted} for run in runs]}
        failed = [{"run": number, "returncode": run.returncode,
                   "stderr_tail": run.stderr[-1000:], "timed_out": run.timed_out,
                   "interrupted": run.interrupted}
                  for number, run in enumerate(runs, 1)
                  if run.returncode or run.timed_out or run.interrupted]
        if failed:
            raise RuntimeError("container checker failed: " + canonical({"runs": failed}))
        deterministic = all((run.returncode, run.stdout, run.stderr) ==
                            (runs[0].returncode, runs[0].stdout, runs[0].stderr) for run in runs[1:])
        return taskcheck._parse_result(runs[0].stdout), deterministic, duration, evidence

def environment(task: Path, image: str, pin: str, codex_home: Path) -> dict[str, Any]:
    image_id(image)
    with tempfile.TemporaryDirectory(prefix="mdseval-verify-") as name:
        root = Path(name)
        tasks = root / "tasks"
        shutil.copytree(task.parent, tasks, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        command = ["/python/bin/python3", "/usr/lib/mdseval/taskcheck.py", "verify",
                   f"/workspace/tasks/{task.name}", "--md-filename", "CODER.md"]
        verify, _ = _run(image, pin, root, codex_home, "none", command, timeout=180)
    verify_row = _json_line(verify.stdout)
    manifest = verify_row.get("manifest_sha256")
    manifest_good = isinstance(manifest, str) and re.fullmatch(r"[0-9a-f]{64}", manifest) is not None
    verify_good = (not verify.returncode and not verify.stderr and verify.stdout == canonical(verify_row) + "\n" and set(verify_row) == {"task_id", "verified", "manifest_sha256"} and verify_row["task_id"] == task.name and verify_row["verified"] is True and manifest_good)
    public = checker(task, task / "public", image, pin, codex_home)
    reference = checker(task, task / "reference", image, pin, codex_home)
    identities = public[3]["identity"] == reference[3]["identity"]
    ok = (verify_good and not public[0]["resolved"] and all(public[0]["regressions"].values())
          and public[1] and reference[0]["resolved"] and reference[1] and identities)
    return {"task_id": task.name, "status": "ALL_GREEN" if ok else "EXCLUDED",
            "image_digest": image, "interpreter_pin": pin, "spec_sha256": sha(SPEC.read_bytes()),
            "spec_task_ids": spec_ids(), "task_manifest_sha256": manifest if manifest_good else None,
            "runtime_security_sha256": security_sha256(image, pin),
            "identity": public[3]["identity"],
            "taskcheck": {"returncode": verify.returncode, "stdout": verify.stdout, "stderr": verify.stderr},
            "public": {"result": public[0], "deterministic": public[1],
                       "duration_seconds": public[2], **public[3]},
            "reference": {"result": reference[0], "deterministic": reference[1],
                          "duration_seconds": reference[2], **reference[3]}}

def host_env(task_id: str, output: Path) -> dict[str, str]:
    path = output.resolve()
    task = (ROOT / "tasks" / task_id).resolve()
    good = (path.name == task_id + ".jsonl" and path.parent.name == "host"
            and path.parent.parent.name == "preflight" and task.is_dir() and not task.is_symlink())
    if not good:
        raise RuntimeError("host evidence or task root is not canonical")
    roots = {"task": str(task), "evidence": str(path.parents[2])}
    return {**os.environ, "MDSEVAL_WORKSPACE": str(task / "public"),
            "MDSEVAL_PROBE_EXCLUSIONS": canonical(roots)}

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("probe", "environment", "host"))
    parser.add_argument("task_id")
    parser.add_argument("image")
    parser.add_argument("pin")
    parser.add_argument("auth_home", type=Path)
    parser.add_argument("output", type=Path)
    arguments = parser.parse_args()
    stderr = arguments.output.with_suffix(arguments.output.suffix + ".stderr")
    if arguments.output.exists() or stderr.exists():
        raise RuntimeError("preflight evidence path already exists")
    try:
        if arguments.mode == "probe":
            value = probe(arguments.task_id, arguments.image, arguments.pin, arguments.auth_home)
        elif arguments.mode == "environment":
            record = environment(ROOT / "tasks" / arguments.task_id, arguments.image,
                                 arguments.pin, arguments.auth_home)
            value = canonical(record) + "\n", "", 0
        else:
            command = [sys.executable, str(ROOT / "scripts/contain/probe.py"), "host",
                       arguments.task_id, arguments.image, str(SPEC)]
            host = subprocess.run(command, capture_output=True, text=True,
                                  env=host_env(arguments.task_id, arguments.output))
            value = host.stdout, host.stderr, host.returncode
    except Exception as exc:
        status = ("EXCLUDED" if arguments.mode == "environment" else "BUILD_REJECTED" if arguments.mode == "probe" else "CONTROL_FAILED")
        record = {"task_id": arguments.task_id, "status": status,
                  "image_digest": arguments.image, "interpreter_pin": arguments.pin,
                  "spec_sha256": sha(SPEC.read_bytes()), "spec_task_ids": spec_ids(),
                  "task_manifest_sha256": None,
                  "error": f"{type(exc).__name__}: {exc}"}
        if arguments.mode != "environment":
            record.update({"check": "summary", "failure_count": 1, "contamination_count": 0})
        value = canonical(record) + "\n", record["error"] + "\n", 2
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(value[0], encoding="utf-8")
    stderr.write_text(value[1], encoding="utf-8")
    return value[2]

if __name__ == "__main__":
    raise SystemExit(main())
