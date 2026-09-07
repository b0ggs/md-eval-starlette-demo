#!/usr/bin/env python3
"""Build-time wheel verifier and runtime interpreter identity probe."""
import hashlib, json, os, shutil, sys, zipfile
from pathlib import Path, PurePosixPath

def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()

def install(lock_name, expected):
    lock_path = Path(lock_name)
    if sha(lock_path) != expected:
        raise ValueError("image lock digest mismatch")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    if (lock.get("schema"), lock.get("dependency_path"), lock.get("install_mode")) != (
            "section14-image-lock-v1", "/sealed-deps", "unpacked-wheels"):
        raise ValueError("unsupported image lock")
    for artifact in lock["artifacts"]:
        source = lock_path.parent / artifact["path"]
        if sha(source) != artifact["sha256"]:
            raise ValueError("wheel digest mismatch: " + artifact["path"])
        with zipfile.ZipFile(source) as wheel:
            for name in wheel.namelist():
                parts = PurePosixPath(name).parts
                if not parts or name.startswith("/") or ".." in parts:
                    raise ValueError("unsafe wheel path")
            wheel.extractall("/sealed-deps")
def identity(image):
    executable = Path(os.path.realpath(sys.executable))
    row = {"check": "identity", "status": "PASS", "canonical_executable": str(executable),
           "version": sys.version, "executable_sha256": sha(executable),
           "image_digest": image, "path_resolution": shutil.which("python3")}
    print(json.dumps(row, sort_keys=True, separators=(",", ":")))
if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "install":
        install(sys.argv[2], sys.argv[3])
    elif len(sys.argv) == 3 and sys.argv[1] == "identity":
        identity(sys.argv[2])
    else:
        raise SystemExit("unsupported probe command")
