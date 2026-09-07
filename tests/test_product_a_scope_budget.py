from __future__ import annotations
from pathlib import Path
import subprocess, unittest
ROOT = Path(__file__).resolve().parents[1]
CHECKPOINT = "3a198387f471ddbea128d135493d81ce1686522f"
# path: (baseline physical lines, maximum permitted growth)
PRODUCTION = {
    "tooling/starlette_product_a_runtime.py": (0, 180),
    "runtime/product-a-v2/Dockerfile": (0, 80),
    "runtime/product-a-v2/Dockerfile.dockerignore": (0, 15),
    "runtime/product-a-v2/probe.py": (0, 40),
    "runtime/product-a-v2/proxy.conf": (0, 20),
    "runtime/product-a-v2/model.filter": (0, 5),
    ".github/workflows/product-a-runtime.yml": (0, 45),
    "run_product_a.py": (242, 60),
    "tooling/starlette_product_a.py": (1577, 80),
    "tooling/starlette_product_a_results.py": (758, 20),
    ".github/workflows/offline-verification.yml": (45, 10),
}
TESTS = {
    "tests/test_product_a_scope_budget.py": (0, 70),
    "tests/test_starlette_product_a_runtime.py": (0, 120),
    "tests/test_run_product_a.py": (241, 35),
    "tests/test_starlette_product_a.py": (607, 20),
    "tests/test_starlette_product_a_results.py": (346, 5),
}
NON_CODE = {
    "PRODUCT_A_FINISH_CHECKLIST.md": 45,
    "README.md": 470,
    "runtime/product-a-v2/runtime-lock.json": 120,
    "runtime/product-a-v2/THIRD_PARTY_NOTICES.md": 30,
    "runtime/product-a-v2/LICENSE.codex": 220,
}
RUNTIME_ALLOWLIST = {path for path in (*PRODUCTION, *NON_CODE)
                     if path.startswith("runtime/product-a-v2/")}
CHANGED_ALLOWLIST = {*PRODUCTION, *TESTS, *NON_CODE}
def line_count(relative: str) -> int:
    return len((ROOT / relative).read_bytes().splitlines()) if (ROOT / relative).is_file() else 0
class ProductAScopeBudgetTests(unittest.TestCase):
    def test_first_party_growth_stays_bounded(self) -> None:
        for label, files, total_limit in (
            ("production", PRODUCTION, 500),
            ("tests", TESTS, 250),
        ):
            growth = 0
            for path, (baseline, limit) in files.items():
                added = max(0, line_count(path) - baseline)
                with self.subTest(group=label, path=path):
                    self.assertLessEqual(added, limit)
                growth += added
            self.assertLessEqual(growth, total_limit, label)
    def test_non_code_and_runtime_file_count_stay_bounded(self) -> None:
        for path, limit in NON_CODE.items():
            with self.subTest(path=path):
                self.assertLessEqual(line_count(path), limit)
        runtime_root = ROOT / "runtime" / "product-a-v2"
        actual = {
            path.relative_to(ROOT).as_posix()
            for path in runtime_root.rglob("*")
            if path.is_file()
        } if runtime_root.is_dir() else set()
        self.assertLessEqual(actual, RUNTIME_ALLOWLIST)
    def test_checkpoint_diff_stays_inside_the_allowlist(self) -> None:
        commands = (["git", "diff", "--name-only", CHECKPOINT, "--"],
                    ["git", "ls-files", "--others", "--exclude-standard"])
        changed = {path for command in commands for path in subprocess.run(
            command, cwd=ROOT, check=True, capture_output=True, text=True).stdout.splitlines()}
        self.assertLessEqual(changed, CHANGED_ALLOWLIST)
if __name__ == "__main__":
    unittest.main()
