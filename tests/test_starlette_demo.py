from __future__ import annotations

from hashlib import sha256
import math
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tooling import report_starlette_eighteen as report
from tooling import starlette_demo as demo
from tooling import starlette_eighteen_task_experiment as experiment


ROOT = Path(__file__).resolve().parents[1]


class StarletteDemoTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tasks = demo.verify_tasks()
        cls.verification = demo.verify_evidence()
        cls.request = experiment.atomic._read_canonical_json(
            demo.BATCH / "REQUEST.json"
        )
        cls.manifest = experiment.atomic._read_canonical_json(
            demo.EVIDENCE / "execution-manifest.json"
        )
        cls.primary = experiment.atomic._read_canonical_json(
            demo.EVIDENCE / "analysis.json"
        )
        cls.attempts = experiment.atomic._read_canonical_jsonl(
            demo.EVIDENCE / "attempts.jsonl"
        )
        cls.pairs = experiment.atomic._read_canonical_jsonl(
            demo.EVIDENCE / "pairs.jsonl"
        )
        cls.data = report.build_report_data(
            cls.request, cls.manifest, cls.primary, cls.attempts, cls.pairs
        )
        cls.rendered = report.render_markdown(cls.data)

    def assert_close(self, actual: float, expected: float) -> None:
        self.assertTrue(
            math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-15),
            f"{actual!r} != {expected!r}",
        )

    def test_exactly_18_fixtures_verify_individually_with_taskcheck(self) -> None:
        self.assertEqual(len(self.tasks), 18)
        self.assertEqual(
            [row["task_id"] for row in self.tasks], list(experiment.TASK_IDS)
        )
        self.assertTrue(all(row["verified"] is True for row in self.tasks))

    def test_checked_in_evidence_verifies_completely_offline(self) -> None:
        self.assertEqual(
            self.verification,
            {
                "attempt_records": 72,
                "base_pairs": 36,
                "pair_records": 36,
                "peak": 12,
                "replacement_pairs": 0,
                "subject_invocations": 72,
            },
        )

    def test_request_binds_the_authoritative_source_ledgers(self) -> None:
        bindings = self.request["repository_state_sha256"]
        self.assertEqual(
            sha256(demo.SOURCE_TASK_LEDGER.read_bytes()).hexdigest(),
            bindings["task_ledger"],
        )
        self.assertEqual(
            sha256(demo.SOURCE_EXPOSURE_LEDGER.read_bytes()).hexdigest(),
            bindings["exposure_ledger"],
        )

    def test_report_regeneration_is_byte_identical(self) -> None:
        self.assertEqual(
            sha256(demo.CANONICAL_REPORT.read_bytes()).hexdigest(),
            demo.EXPECTED_REPORT_SHA256,
        )
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "reproduced.md"
            result = demo.reproduce_report(destination)
            self.assertEqual(destination.read_bytes(), demo.CANONICAL_REPORT.read_bytes())
            self.assertEqual(result["report_sha256"], demo.EXPECTED_REPORT_SHA256)

    def test_report_destination_must_be_new_and_outside_repository(self) -> None:
        with self.assertRaises(demo.DemoError):
            demo.reproduce_report(ROOT / "not-allowed.md")
        with tempfile.TemporaryDirectory() as temporary:
            temporary_root = Path(temporary)
            existing = temporary_root / "existing.md"
            existing.write_text("owned by caller", encoding="utf-8")
            with self.assertRaises(demo.DemoError):
                demo.reproduce_report(existing)
            self.assertEqual(existing.read_text(encoding="utf-8"), "owned by caller")

            symlink = temporary_root / "symlink.md"
            symlink.symlink_to(temporary_root / "target.md")
            with self.assertRaises(demo.DemoError):
                demo.reproduce_report(symlink)

    def test_failed_report_reproduction_removes_its_new_output(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "failed.md"

            def write_bad_report(batch: Path, output: Path, report_path: Path):
                report_path.write_text("bad", encoding="utf-8")
                return {"report_sha256": "0" * 64}

            with mock.patch.object(report, "write_report", write_bad_report):
                with self.assertRaises(demo.DemoError):
                    demo.reproduce_report(destination)
            self.assertFalse(destination.exists())

    def test_registered_endpoints_are_inconclusive(self) -> None:
        self.assertFalse(self.primary["common_pair_selection"]["all_tasks_have_two"])
        incomplete = [
            {"task_id": "confirm-starlette-exception-context", "usable_pair_count": 1},
            {"task_id": "confirm-starlette-malformed-host", "usable_pair_count": 0},
        ]
        for name in ("wall", "token"):
            endpoint = self.primary["endpoints"][name]
            self.assertEqual(endpoint["status"], "inconclusive")
            self.assertEqual(endpoint["details"], incomplete)
            self.assertFalse(endpoint["favorable_reduction"])

    def test_post_hoc_complete_case_statistics_are_exact(self) -> None:
        expected = {
            "wall": (
                41.885409464422054,
                (0.49896158711989486, 0.6768668611570609),
                -7.587267997758838,
                1.6430677742632644e-06,
            ),
            "token": (
                33.092679367468705,
                (0.5710298679105758, 0.7839501584399416),
                -5.405727542628216,
                7.289433064836608e-05,
            ),
        }
        self.assertEqual(len(self.data["sensitivity"]["complete_task_ids"]), 16)
        for name, values in expected.items():
            endpoint = self.data["sensitivity"][name]
            self.assertEqual(endpoint["task_count"], 16)
            self.assertEqual(endpoint["degrees_of_freedom"], 15)
            self.assert_close(endpoint["reduction_percent"], values[0])
            self.assert_close(endpoint["t_statistic"], values[2])
            self.assert_close(endpoint["p_value_two_sided"], values[3])
            for actual, wanted in zip(endpoint["confidence_interval_95_ratio"], values[1]):
                self.assert_close(actual, wanted)

    def test_all_failed_attempts_remain_visible(self) -> None:
        expected = {
            "pair-05-r2-a1-candidate",
            "pair-12-r1-a1-candidate",
            "pair-12-r1-a2-control",
            "pair-12-r2-a1-control",
        }
        self.assertEqual({row["attempt_id"] for row in self.data["failures"]}, expected)
        for attempt_id in expected:
            self.assertIn(attempt_id, self.rendered)

    def test_readme_matches_the_verified_results(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        required = (
            "| Tasks | 18 |",
            "| Paired repeats per task | 2 |",
            "| Atomic pairs | 36 |",
            "| Subject invocations | 72 |",
            "| Peak concurrency | 12 |",
            "| Replacements | 0 |",
            "| Resolved attempts | MD 34/36; No MD 34/36 |",
            "| Wall time | **INCONCLUSIVE** |",
            "| Tokens | **INCONCLUSIVE** |",
            "41.8854%",
            "32.3133%–50.1038%",
            "1.6430678e-06",
            "33.0927%",
            "21.6050%–42.8970%",
            "7.2894331e-05",
            "finite-known-set development replication",
            "not the frozen v7 confirmation",
            "6e8e985318203f3818fefad07e3a9b43a7a9e300",
        )
        for text in required:
            self.assertIn(text, readme)

    def test_case_study_contains_the_complete_taxonomy(self) -> None:
        case_study = (ROOT / "docs/starlette-demonstration.md").read_text(
            encoding="utf-8"
        )
        task_section = case_study.split("## The 18 tasks", 1)[1].split(
            "## Preserved artifacts", 1
        )[0]
        categories = {
            "### ASGI and WebSocket lifecycle (3)": 3,
            "### Middleware policy and response semantics (4)": 4,
            "### Exceptions and resource lifetime (3)": 3,
            "### Files, byte ranges, and cache validators (4)": 4,
            "### State, routing, authority, and client integration (4)": 4,
        }
        self.assertEqual(sum(categories.values()), len(experiment.TASK_IDS))
        for heading in categories:
            self.assertEqual(task_section.count(heading), 1)
        for task_id in experiment.TASK_IDS:
            self.assertEqual(task_section.count(f"| `{task_id}` |"), 1)

    def test_all_starlette_bsd_notices_are_retained(self) -> None:
        for task_id in experiment.TASK_IDS:
            for fixture in ("blind", "public", "reference"):
                notice = ROOT / "tasks" / task_id / fixture / "LICENSE.md"
                text = notice.read_text(encoding="utf-8")
                self.assertIn("Copyright © 2018", text)
                self.assertIn("Redistribution and use", text)

    def test_ci_invokes_only_the_offline_public_entry_point(self) -> None:
        workflow = (
            ROOT / ".github/workflows/offline-verification.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("tooling.starlette_demo verify-tasks", workflow)
        self.assertIn("tooling.starlette_demo verify", workflow)
        self.assertIn("tooling.starlette_demo report", workflow)
        self.assertIn(
            'MDSEVAL_CODEX_HOME: "/tmp/md-eval-starlette-no-codex-home"',
            workflow,
        )
        self.assertIn("persist-credentials: false", workflow)
        for forbidden in (
            "starlette_eighteen_task_experiment run",
            "run_batch.py launch",
            "codex exec",
            "OPENAI_API_KEY: ${{",
        ):
            self.assertNotIn(forbidden, workflow)


if __name__ == "__main__":
    unittest.main()
