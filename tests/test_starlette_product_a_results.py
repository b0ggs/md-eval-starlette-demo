from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tooling import starlette_product_a_results as results


def _attempt(attempt_id: str, arm: str, passed: bool) -> dict[str, object]:
    return {
        "attempt_id": attempt_id,
        "arm": arm,
        "normal_terminal_record": True,
        "valid": True,
        "resolved": passed,
    }


def _verified_fixture(
    repo: Path,
    run_dir: Path,
    *,
    execution_mode: str = "live_approved",
) -> dict[str, object]:
    attempts: list[dict[str, object]] = []
    pairs: list[dict[str, object]] = []
    failures: list[dict[str, object]] = []
    # 31 both pass, 1 both fail, 3 MD-only fail, 1 No-MD-only fail.
    categories = (
        ["both_failed"]
        + ["md_only_failed"] * 3
        + ["no_md_only_failed"]
        + ["both_passed"] * 31
    )
    for index, category in enumerate(categories, 1):
        pair_id = f"pair-{index:02d}-r{1 if index % 2 else 2}"
        md_id = f"{pair_id}-a1-candidate"
        no_md_id = f"{pair_id}-a2-control"
        md_passed = category in {"both_passed", "no_md_only_failed"}
        no_md_passed = category in {"both_passed", "md_only_failed"}
        attempts.extend([
            _attempt(md_id, "candidate", md_passed),
            _attempt(no_md_id, "control", no_md_passed),
        ])
        pairs.append({
            "root_pair_id": pair_id,
            "replacement_generation": 0,
            "attempt_ids": [md_id, no_md_id],
        })
        for arm, attempt_id, passed in (
            ("MD", md_id, md_passed),
            ("No-MD", no_md_id, no_md_passed),
        ):
            if not passed:
                failures.append({
                    "attempt_id": attempt_id,
                    "task_id": f"task-{index:02d}",
                    "repeat": 1 if index % 2 else 2,
                    "arm": arm,
                    "scope": "raw invocation",
                    "reason": "mechanical checker did not resolve the task",
                    "mechanical_reason_code": "checker_unresolved",
                    "termination_class": "normal_incorrect_completion",
                })
    analysis = {
        "analysis_freeze_sha256": "a" * 64,
        "correctness": {
            "md": {"failed": 4, "passed": 32, "total": 36},
            "no_md": {"failed": 2, "passed": 34, "total": 36},
        },
        "failures": failures,
        "eligibility": {
            "eligible_task_count": 14,
            "exclusions": [{"task_id": "task-01", "usable_pair_count": 1}],
            "exclusion_details": [{
                "task_id": "task-01",
                "details": [{
                    "repeat": 1,
                    "reasons": ["MD did not pass: checker_unresolved"],
                }],
            }],
        },
        "endpoints": {
            "wall": {
                "task_count": 14,
                "change_percent": -52.1051,
                "confidence_interval_95_change_percent": [-58.4265, -44.8225],
                "p_value_two_sided": 4.5821128e-08,
                "classification": "significantly favorable",
            },
            "token": {
                "task_count": 14,
                "change_percent": -36.0641,
                "confidence_interval_95_change_percent": [-43.0229, -28.2553],
                "p_value_two_sided": 1.3304513e-06,
                "classification": "significantly favorable",
            },
        },
    }
    return {
        "request": {
            "created_utc": "2026-09-06T11:41:20+00:00",
            "component_sha256": {"product_a_runner_and_reporter": "b" * 64},
        },
        "request_sha256": "c" * 64,
        "manifest": {
            "status": "complete",
            "execution_mode": execution_mode,
            "actual_subject_invocations": 72,
        },
        "analysis": analysis,
        "attempts": attempts,
        "pairs": pairs,
        "report_path": run_dir / "REPORT.md",
    }


def _historical_fixture(repo: Path) -> dict[str, object]:
    endpoint = {
        "task_count": 16,
        "reduction_percent": 41.8854,
        "confidence_interval_95_ratio": [0.498962, 0.676867],
        "p_value_two_sided": 1.6430678e-06,
        "classification": "significantly favorable",
    }
    token = {
        "task_count": 16,
        "reduction_percent": 33.0927,
        "confidence_interval_95_ratio": [0.57103, 0.78395],
        "p_value_two_sided": 7.2894331e-05,
        "classification": "significantly favorable",
    }
    return {
        "outcome_counts": {
            "candidate": {"failed": 2, "passed": 34, "total": 36},
            "control": {"failed": 2, "passed": 34, "total": 36},
        },
        "sensitivity": {
            "complete_task_ids": [f"task-{index:02d}" for index in range(1, 17)],
            "wall": endpoint,
            "token": token,
        },
        "report_path": repo / results.HISTORICAL_REPORT_RELATIVE,
        "report_relative": results.HISTORICAL_REPORT_RELATIVE.as_posix(),
    }


class ProductAResultsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name).resolve()
        self.runs_root = self.repo / results.RUNS_RELATIVE
        self.runs_root.mkdir(parents=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _write_json(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value), encoding="utf-8")

    def _complete_surface(self, run_id: str) -> Path:
        run_dir = self.runs_root / run_id
        evidence = run_dir / "live-evidence"
        evidence.mkdir(parents=True)
        self._write_json(
            run_dir / "REQUEST.json",
            {"created_utc": "2026-09-06T11:41:20+00:00"},
        )
        for name in ("analysis.json", "execution-manifest.json"):
            self._write_json(evidence / name, {})
        (evidence / "attempts.jsonl").write_text("", encoding="utf-8")
        (evidence / "pairs.jsonl").write_text("", encoding="utf-8")
        (run_dir / "REPORT.md").write_text("fixture\n", encoding="utf-8")
        return run_dir

    def test_collects_only_verified_live_runs_and_discloses_other_requests(self) -> None:
        live = self._complete_surface("product-a-live")
        offline = self._complete_surface("product-a-offline")
        failed_preflight = self.runs_root / "product-a-preflight"
        failed_preflight.mkdir()
        self._write_json(
            failed_preflight / "REQUEST.json",
            {"created_utc": "2026-09-06T11:00:00+00:00"},
        )
        self._write_json(failed_preflight / "CONSUMED_APPROVAL.json", {})

        def verify(_repo: Path, run_dir: Path):
            return _verified_fixture(
                self.repo,
                run_dir,
                execution_mode=("offline_fake" if run_dir == offline else "live_approved"),
            )

        data = results.collect_results(
            self.repo,
            verify_run=verify,
            historical_loader=_historical_fixture,
        )

        self.assertEqual([row["run_id"] for row in data["fresh_runs"]], [live.name])
        self.assertEqual(data["totals"]["md"], {"failed": 4, "passed": 32, "total": 36})
        self.assertEqual(data["totals"]["no_md"], {"failed": 2, "passed": 34, "total": 36})
        self.assertEqual(
            data["paired_totals"],
            {
                "both_passed": 31,
                "both_failed": 1,
                "md_only_failed": 3,
                "no_md_only_failed": 1,
            },
        )
        states = {row["run_id"]: row["state"] for row in data["not_counted"]}
        self.assertIn("offline_fake execution", states[offline.name])
        self.assertIn("zero subject calls recorded", states[failed_preflight.name])

    def test_render_is_descriptive_and_keeps_historical_results_separate(self) -> None:
        live = self._complete_surface("product-a-live")
        data = results.collect_results(
            self.repo,
            verify_run=lambda _repo, run_dir: _verified_fixture(self.repo, run_dir),
            historical_loader=_historical_fixture,
        )
        rendered = results.render_results(data)

        self.assertIn("MD: **4/36 failed; 32/36 passed (11.1% failure).**", rendered)
        self.assertIn("No-MD: **2/36 failed; 34/36 passed (5.6% failure).**", rendered)
        self.assertIn("| 31 | 1 | 3 | 1 | 36 |", rendered)
        self.assertEqual(rendered.count("checker_unresolved"), 7)
        self.assertIn("## Per-run complete-task resource results", rendered)
        self.assertIn("4.5821128e-08", rendered)
        self.assertIn("1.3304513e-06", rendered)
        self.assertIn("## Bundled historical example (separate; not pooled)", rendered)
        self.assertIn("MD: **2/36 failed; 34/36 passed (5.6% failure).**", rendered)
        self.assertIn("The historical all-18 registered endpoint was unavailable", rendered)
        self.assertIn("does **not** pool p-values", rendered)
        self.assertNotIn("combined p-value", rendered.lower())
        self.assertIn(live.name, rendered)

    def test_accumulates_correctness_and_pairs_across_verified_runs(self) -> None:
        first = self._complete_surface("product-a-first")
        second = self._complete_surface("product-a-second")
        data = results.collect_results(
            self.repo,
            verify_run=lambda _repo, run_dir: _verified_fixture(self.repo, run_dir),
            historical_loader=_historical_fixture,
        )

        self.assertEqual(
            [row["run_id"] for row in data["fresh_runs"]],
            [first.name, second.name],
        )
        self.assertEqual(data["totals"]["md"], {"failed": 8, "passed": 64, "total": 72})
        self.assertEqual(data["totals"]["no_md"], {"failed": 4, "passed": 68, "total": 72})
        self.assertEqual(
            data["paired_totals"],
            {
                "both_passed": 62,
                "both_failed": 2,
                "md_only_failed": 6,
                "no_md_only_failed": 2,
            },
        )

    def test_refresh_replaces_only_the_root_dashboard(self) -> None:
        data = {
            "fresh_runs": [],
            "totals": {
                "md": {"failed": 0, "passed": 0, "total": 0},
                "no_md": {"failed": 0, "passed": 0, "total": 0},
            },
            "paired_totals": {key: 0 for key in results.PAIRED_KEYS},
            "not_counted": [],
            "historical": _historical_fixture(self.repo),
        }
        destination = self.repo / "RESULTS.md"
        destination.write_text("stale\n", encoding="utf-8")
        with mock.patch.object(results, "collect_results", return_value=data):
            returned = results.refresh_results(self.repo)
        self.assertEqual(returned, destination)
        self.assertEqual(destination.read_text(encoding="utf-8"), results.render_results(data))
        with mock.patch.object(results, "collect_results", return_value=data):
            with self.assertRaises(results.ResultsError):
                results.refresh_results(self.repo, self.repo / "nested" / "RESULTS.md")

    def test_completed_but_unverifiable_run_aborts_the_dashboard(self) -> None:
        self._complete_surface("product-a-corrupt")

        def reject(_repo: Path, _run_dir: Path):
            raise ValueError("evidence digest changed")

        with self.assertRaisesRegex(results.ResultsError, "cannot verify completed run"):
            results.collect_results(
                self.repo,
                verify_run=reject,
                historical_loader=_historical_fixture,
            )

    def test_only_the_exact_relocated_bundled_request_can_use_digest_fallback(self) -> None:
        bundled_source = (
            results.ROOT / results.RUNS_RELATIVE / results.BUNDLED_FRESH_RUN_ID
        )
        relocated = self.runs_root / results.BUNDLED_FRESH_RUN_ID
        relocated.mkdir()
        (relocated / "REQUEST.json").write_bytes(
            (bundled_source / "REQUEST.json").read_bytes()
        )
        sentinel = {"verified": "by exact digests"}
        with mock.patch(
            "tooling.starlette_product_a._verify_evidence",
            side_effect=ValueError("request contains its original absolute path"),
        ), mock.patch.object(
            results, "_verify_relocated_bundled_run", return_value=sentinel
        ) as fallback:
            self.assertIs(results._default_verify_run(self.repo, relocated), sentinel)
        fallback.assert_called_once_with(self.repo, relocated)

        arbitrary = self.runs_root / "product-a-arbitrary"
        arbitrary.mkdir()
        (arbitrary / "REQUEST.json").write_bytes(
            (bundled_source / "REQUEST.json").read_bytes()
        )
        with mock.patch(
            "tooling.starlette_product_a._verify_evidence",
            side_effect=ValueError("verification failed"),
        ), mock.patch.object(results, "_verify_relocated_bundled_run") as fallback:
            with self.assertRaisesRegex(ValueError, "verification failed"):
                results._default_verify_run(self.repo, arbitrary)
        fallback.assert_not_called()

    def test_checked_in_fresh_run_matches_every_fallback_digest(self) -> None:
        bundled = results.ROOT / results.RUNS_RELATIVE / results.BUNDLED_FRESH_RUN_ID
        for relative, expected in results.BUNDLED_FRESH_SHA256.items():
            self.assertEqual(results._sha256_file(bundled / relative), expected)
        verified = results._verify_relocated_bundled_run(results.ROOT, bundled)
        self.assertEqual(verified["manifest"]["execution_mode"], "live_approved")
        self.assertEqual(len(verified["attempts"]), 72)
        self.assertEqual(len(verified["pairs"]), 36)


if __name__ == "__main__":
    unittest.main()
