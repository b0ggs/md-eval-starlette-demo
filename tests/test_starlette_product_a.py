from __future__ import annotations

from contextlib import ExitStack, contextmanager
from hashlib import sha256
import json
from pathlib import Path
import shutil
import tempfile
import threading
import unittest
from unittest import mock

from tooling import starlette_atomic_pairs as atomic
from tooling import starlette_eighteen_task_experiment as frozen
from tooling import starlette_product_a as product_a


ROOT = Path(__file__).resolve().parents[1]


class CountingFakeExecutor:
    """Offline-only executor that also observes the implementation's call cap."""

    def __init__(self, outcomes=None, *, delay_seconds: float = 0.002) -> None:
        self.stub = atomic.DeterministicStubExecutor(
            outcomes or {}, delay_seconds=delay_seconds
        )
        self.calls = 0
        self.active = 0
        self.peak = 0
        self._lock = threading.Lock()

    def __call__(self, context: atomic.AttemptContext):
        with self._lock:
            self.calls += 1
            self.active += 1
            self.peak = max(self.peak, self.active)
        try:
            result = self.stub(context)
            # The production adapter records these fields for live executions.  Supplying
            # them here lets the same evidence path be exercised without a model call.
            result["duration_seconds"] = 0.000001
            result["subject_invocation_started"] = True
            return result
        finally:
            with self._lock:
                self.active -= 1


class StarletteProductAFreshLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        # Product A rejects paths with symlinked ancestors.  Resolve the platform
        # temp root so macOS does not hand the tests the indirect `/var/...` spelling.
        canonical_temp_root = Path(tempfile.gettempdir()).resolve()
        self.temporary = tempfile.TemporaryDirectory(dir=canonical_temp_root)
        self.runs_root = Path(self.temporary.name) / "product-a-runs"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _json(path: Path):
        return json.loads(path.read_text(encoding="utf-8"))

    def _prepare(self):
        prepared = product_a.prepare(runs_root=self.runs_root, repo=ROOT)
        run_dir = Path(prepared["run_directory"])
        request_path = Path(prepared["request"])
        request = self._json(request_path)
        self.assertEqual(
            sha256(request_path.read_bytes()).hexdigest(),
            prepared["request_sha256"],
        )
        return prepared, run_dir, request

    @staticmethod
    def _passing_preflight(request):
        return {
            "status": "PASS",
            "seals": {
                row["task_id"]: {"offline_fake": True}
                for row in request["tasks"]
            },
        }

    @contextmanager
    def _forbid_live_services(self):
        """Make a test fail if an injected run falls through to the live path."""
        with ExitStack() as stack:
            stack.enter_context(
                mock.patch.object(
                    frozen.run_batch,
                    "preflight_request",
                    side_effect=AssertionError("live preflight used by offline test"),
                )
            )
            stack.enter_context(
                mock.patch.object(
                    frozen.live,
                    "AtomicLiveBackend",
                    side_effect=AssertionError("live backend used by offline test"),
                )
            )
            yield

    def _run_fake(self, run_dir: Path, request_sha256: str, executor):
        product_a.approve(run_dir, request_sha256)
        with self._forbid_live_services():
            return product_a.run_approved(
                run_dir,
                repo=ROOT,
                preflight=self._passing_preflight,
                executor=executor,
            )

    def test_prepared_request_freezes_exact_product_a_design(self) -> None:
        prepared, run_dir, request = self._prepare()

        self.assertEqual([row["task_id"] for row in request["tasks"]], list(frozen.TASK_IDS))
        self.assertEqual(len(request["tasks"]), 18)
        self.assertEqual(
            request["arms"],
            [
                {
                    "name": "md",
                    "path": frozen.ARM_PATHS["md"],
                    "sha256": frozen.ARM_HASHES["md"],
                },
                {
                    "name": "no-md",
                    "path": frozen.ARM_PATHS["no-md"],
                    "sha256": frozen.ARM_HASHES["no-md"],
                },
            ],
        )
        self.assertEqual(request["runner"]["model"], "gpt-5.6-sol")
        self.assertEqual(request["runner"]["reasoning_effort"], "high")
        self.assertEqual(request["schedule"]["repeats_per_task"], 2)
        self.assertEqual(request["schedule"]["task_count"], 18)
        self.assertEqual(request["schedule"]["planned_pairs"], 36)
        self.assertEqual(request["schedule"]["planned_calls"], 72)
        self.assertEqual(request["planned_scientific_calls"], 72)
        self.assertEqual(request["execution"]["worker_count"], 12)
        self.assertEqual(request["execution"]["max_active_subject_calls"], 12)
        self.assertEqual(request["max_subject_invocations"], 80)
        self.assertEqual(request["analysis_freeze"], product_a.ANALYSIS_FREEZE)
        complete_rule = request["analysis_freeze"]["complete_task_rule"]
        self.assertIn("both terminal paired repeats", complete_rule)
        self.assertIn("never use a lone surviving repeat", complete_rule)
        self.assertEqual(Path(request["run_directory"]), run_dir)
        self.assertEqual(Path(request["runs_root"]), self.runs_root)
        self.assertEqual(request["run_id"], run_dir.name)
        self.assertTrue(request["request_nonce"])
        self.assertFalse((run_dir / "APPROVED.json").exists())
        self.assertFalse((run_dir / "CONSUMED_APPROVAL.json").exists())
        self.assertEqual(set(prepared), {"run_directory", "request", "request_sha256"})

    def test_every_prepare_has_a_unique_directory_nonce_request_and_hash(self) -> None:
        first, first_dir, first_request = self._prepare()
        second, second_dir, second_request = self._prepare()

        self.assertNotEqual(first_dir, second_dir)
        self.assertNotEqual(first_request["run_id"], second_request["run_id"])
        self.assertNotEqual(first_request["request_nonce"], second_request["request_nonce"])
        self.assertNotEqual(first["request_sha256"], second["request_sha256"])
        self.assertTrue(first_dir.is_dir())
        self.assertTrue(second_dir.is_dir())
        self.assertEqual(first_dir.parent, self.runs_root)
        self.assertEqual(second_dir.parent, self.runs_root)

    def test_stale_and_copied_approvals_are_refused_before_preflight_or_backend(self) -> None:
        first, first_dir, _ = self._prepare()
        second, second_dir, _ = self._prepare()
        third, third_dir, third_request = self._prepare()

        with self.assertRaises(product_a.ProductAError):
            product_a.approve(first_dir, second["request_sha256"])
        self.assertFalse((first_dir / "APPROVED.json").exists())

        product_a.approve(first_dir, first["request_sha256"])
        shutil.copyfile(first_dir / "APPROVED.json", second_dir / "APPROVED.json")
        hook_calls = {"preflight": 0, "executor": 0}

        def preflight(request):
            hook_calls["preflight"] += 1
            return self._passing_preflight(request)

        def executor(context):
            hook_calls["executor"] += 1
            raise AssertionError("copied approval reached executor")

        with self.assertRaises(product_a.ProductAError):
            product_a.run_approved(
                second_dir,
                repo=ROOT,
                preflight=preflight,
                executor=executor,
            )
        self.assertEqual(hook_calls, {"preflight": 0, "executor": 0})
        self.assertTrue((second_dir / "CONSUMED_APPROVAL.json").is_file())

        product_a.approve(third_dir, third["request_sha256"])
        third_request["created_utc"] += "-changed-after-approval"
        (third_dir / "REQUEST.json").write_bytes(atomic.canonical_bytes(third_request))
        with self.assertRaises(product_a.ProductAError):
            product_a.run_approved(
                third_dir,
                repo=ROOT,
                preflight=preflight,
                executor=executor,
            )
        self.assertEqual(hook_calls, {"preflight": 0, "executor": 0})
        self.assertTrue((third_dir / "CONSUMED_APPROVAL.json").is_file())

    def test_approval_is_consumed_before_preflight_and_failed_run_cannot_reuse_it(self) -> None:
        prepared, run_dir, _ = self._prepare()
        calls = {"preflight": 0, "executor": 0}

        def failing_preflight(request):
            calls["preflight"] += 1
            self.assertTrue((run_dir / "CONSUMED_APPROVAL.json").is_file())
            self.assertFalse((run_dir / product_a.EVIDENCE_DIRECTORY).exists())
            return {"status": "FAIL", "seals": {}, "failed_checks": ["fake"]}

        def executor(context):
            calls["executor"] += 1
            raise AssertionError("backend ran after failed preflight")

        with self.assertRaises(product_a.ProductAError):
            product_a.run_approved(
                run_dir,
                repo=ROOT,
                preflight=failing_preflight,
                executor=executor,
            )
        self.assertEqual(calls, {"preflight": 0, "executor": 0})
        self.assertFalse((run_dir / "CONSUMED_APPROVAL.json").exists())

        product_a.approve(run_dir, prepared["request_sha256"])
        with self.assertRaises(product_a.ProductAError):
            product_a.run_approved(
                run_dir,
                repo=ROOT,
                preflight=failing_preflight,
                executor=executor,
            )
        self.assertEqual(calls, {"preflight": 1, "executor": 0})

        with self.assertRaises(product_a.ProductAError):
            product_a.run_approved(
                run_dir,
                repo=ROOT,
                preflight=failing_preflight,
                executor=executor,
            )
        self.assertEqual(calls, {"preflight": 1, "executor": 0})

    def test_existing_evidence_is_never_reused_or_overwritten(self) -> None:
        prepared, run_dir, _ = self._prepare()
        product_a.approve(run_dir, prepared["request_sha256"])
        evidence = run_dir / product_a.EVIDENCE_DIRECTORY
        evidence.mkdir()
        sentinel = evidence / "caller-owned.txt"
        sentinel.write_text("preserve me", encoding="utf-8")
        executor = CountingFakeExecutor(delay_seconds=0)
        preflight_calls = 0

        def preflight(request):
            nonlocal preflight_calls
            preflight_calls += 1
            return self._passing_preflight(request)

        with self.assertRaises(product_a.ProductAError):
            product_a.run_approved(
                run_dir,
                repo=ROOT,
                preflight=preflight,
                executor=executor,
            )
        self.assertEqual(preflight_calls, 0)
        self.assertEqual(executor.calls, 0)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve me")
        self.assertTrue((run_dir / "CONSUMED_APPROVAL.json").is_file())

    def test_lifecycle_rejects_symlinked_roots_and_run_directories(self) -> None:
        real_root = Path(self.temporary.name) / "real-runs-root"
        linked_root = Path(self.temporary.name) / "linked-runs-root"
        real_root.mkdir()
        linked_root.symlink_to(real_root, target_is_directory=True)
        with self.assertRaises(product_a.ProductAError):
            product_a.prepare(runs_root=linked_root, repo=ROOT)
        self.assertEqual(list(real_root.iterdir()), [])

        prepared, run_dir, _ = self._prepare()
        relocated = Path(self.temporary.name) / "relocated-run"
        run_dir.rename(relocated)
        run_dir.symlink_to(relocated, target_is_directory=True)

        with self.assertRaises(product_a.ProductAError):
            product_a.approve(run_dir, prepared["request_sha256"])
        self.assertFalse((relocated / "APPROVED.json").exists())

        run_dir.unlink()
        relocated.rename(run_dir)
        product_a.approve(run_dir, prepared["request_sha256"])
        run_dir.rename(relocated)
        run_dir.symlink_to(relocated, target_is_directory=True)
        hook_calls = {"preflight": 0, "executor": 0}

        def preflight(request):
            hook_calls["preflight"] += 1
            return self._passing_preflight(request)

        def executor(context):
            hook_calls["executor"] += 1
            return {}

        with self.assertRaises(product_a.ProductAError):
            product_a.run_approved(
                run_dir,
                repo=ROOT,
                preflight=preflight,
                executor=executor,
            )
        with self.assertRaises(product_a.ProductAError):
            product_a.verify_and_report(run_dir, repo=ROOT)
        self.assertEqual(hook_calls, {"preflight": 0, "executor": 0})
        self.assertFalse((relocated / "CONSUMED_APPROVAL.json").exists())
        self.assertFalse((relocated / product_a.EVIDENCE_DIRECTORY).exists())

    def test_concurrent_run_claims_can_consume_an_approval_only_once(self) -> None:
        prepared, run_dir, _ = self._prepare()
        product_a.approve(run_dir, prepared["request_sha256"])
        preflight_entered = threading.Event()
        release_preflight = threading.Event()
        lock = threading.Lock()
        errors = []
        calls = {"preflight": 0, "executor": 0}

        def held_failing_preflight(request):
            with lock:
                calls["preflight"] += 1
            preflight_entered.set()
            if not release_preflight.wait(timeout=10):
                raise AssertionError("test did not release fake preflight")
            return {"status": "FAIL", "seals": {}, "failed_checks": ["held fake"]}

        def executor(context):
            with lock:
                calls["executor"] += 1
            raise AssertionError("backend ran after failed preflight")

        def invoke() -> None:
            try:
                product_a.run_approved(
                    run_dir,
                    repo=ROOT,
                    preflight=held_failing_preflight,
                    executor=executor,
                )
            except BaseException as exc:
                with lock:
                    errors.append(exc)

        first = threading.Thread(target=invoke, name="first-approval-claim")
        second = threading.Thread(target=invoke, name="second-approval-claim")
        first.start()
        try:
            self.assertTrue(preflight_entered.wait(timeout=10))
            second.start()
            second.join(timeout=10)
            self.assertFalse(second.is_alive())
        finally:
            release_preflight.set()
            first.join(timeout=10)
        self.assertFalse(first.is_alive())

        self.assertEqual(calls, {"preflight": 1, "executor": 0})
        self.assertEqual(len(errors), 2)
        self.assertTrue(all(isinstance(exc, product_a.ProductAError) for exc in errors))
        self.assertTrue((run_dir / "CONSUMED_APPROVAL.json").is_file())
        self.assertFalse((run_dir / product_a.EVIDENCE_DIRECTORY).exists())

    def test_fake_run_reports_failures_and_excludes_a_task_with_one_good_repeat(self) -> None:
        prepared, run_dir, _ = self._prepare()
        excluded_task = frozen.TASK_IDS[0]
        outcomes = {
            (excluded_task, 1, "candidate"): atomic.NORMAL_INCORRECT_COMPLETION,
            (excluded_task, 1, "control"): atomic.NORMAL_INCORRECT_COMPLETION,
        }
        executor = CountingFakeExecutor(outcomes)
        manifest = self._run_fake(run_dir, prepared["request_sha256"], executor)

        self.assertEqual(executor.calls, 72)
        self.assertLessEqual(executor.peak, 12)
        self.assertEqual(manifest["planned_scientific_calls"], 72)
        self.assertEqual(manifest["actual_attempt_records"], 72)
        self.assertEqual(manifest["actual_subject_invocations"], 72)
        self.assertLessEqual(manifest["observed_peak_active_subjects"], 12)
        self.assertLessEqual(manifest["observed_peak_executor_calls"], 12)

        result = product_a.verify_and_report(run_dir, repo=ROOT)
        analysis_path = run_dir / product_a.EVIDENCE_DIRECTORY / "analysis.json"
        report_path = run_dir / product_a.REPORT_FILENAME
        analysis = self._json(analysis_path)
        rendered = report_path.read_text(encoding="utf-8")

        self.assertEqual(analysis["correctness"]["md"], {"passed": 35, "failed": 1, "total": 36})
        self.assertEqual(analysis["correctness"]["no_md"], {"passed": 35, "failed": 1, "total": 36})
        self.assertEqual(analysis["eligibility"]["eligible_task_count"], 17)
        self.assertNotIn(excluded_task, analysis["eligibility"]["eligible_task_ids"])
        self.assertEqual(len(analysis["eligibility"]["exclusions"]), 1)
        exclusion = analysis["eligibility"]["exclusions"][0]
        self.assertEqual(exclusion["task_id"], excluded_task)
        self.assertEqual(exclusion["usable_pair_count"], 1)
        self.assertEqual(len(analysis["failures"]), 2)
        self.assertEqual({row["task_id"] for row in analysis["failures"]}, {excluded_task})
        self.assertEqual(
            {row["reason"] for row in analysis["failures"]},
            {"mechanical checker did not resolve the task"},
        )
        self.assertEqual(
            {row["mechanical_reason_code"] for row in analysis["failures"]},
            {"checker_unresolved"},
        )
        for failure in analysis["failures"]:
            self.assertIn(failure["attempt_id"], rendered)
            self.assertIn(failure["reason"], rendered)
        self.assertIn(
            "| mechanical checker did not resolve the task | checker_unresolved |",
            rendered,
        )

        # Counts are the first result data; failure detail and inference follow them.
        counts_position = min(rendered.index("MD"), rendered.index("No-MD"))
        failures_position = rendered.index("Failures")
        inference_position = rendered.index("Eligible")
        self.assertLess(counts_position, failures_position)
        self.assertLess(failures_position, inference_position)
        self.assertIn("MD: **1/36 failed; 35/36 passed.**", rendered[:failures_position])
        self.assertIn(
            "No-MD: **1/36 failed; 35/36 passed.**",
            rendered[:failures_position],
        )
        for endpoint_name in ("wall", "token"):
            endpoint = analysis["endpoints"][endpoint_name]
            self.assertEqual(endpoint["task_count"], 17)
            self.assertIn("mean_task_log_ratio", endpoint)
            self.assertIn("geometric_mean_ratio", endpoint)
            self.assertIn("change_percent", endpoint)
            self.assertIn("confidence_interval_95_ratio", endpoint)
            self.assertIn("p_value_two_sided", endpoint)
            self.assertIn(
                endpoint["classification"],
                {
                    "significantly favorable",
                    "significantly unfavorable",
                    "nonsignificant",
                    "not estimable",
                },
            )

        self.assertEqual(Path(result["report"]), report_path)
        report_bytes = report_path.read_bytes()
        with self.assertRaises(product_a.ProductAError):
            product_a.verify_and_report(run_dir, repo=ROOT)
        self.assertEqual(report_path.read_bytes(), report_bytes)

        # A successful approval is one-use too; neither lifecycle hook can run again.
        calls = {"preflight": 0, "executor": 0}

        def unused_preflight(request):
            calls["preflight"] += 1
            return self._passing_preflight(request)

        def unused_executor(context):
            calls["executor"] += 1
            return {}

        with self.assertRaises(product_a.ProductAError):
            product_a.run_approved(
                run_dir,
                repo=ROOT,
                preflight=unused_preflight,
                executor=unused_executor,
            )
        self.assertEqual(calls, {"preflight": 0, "executor": 0})

    def test_four_statistical_classifications_are_exhaustive_and_directional(self) -> None:
        self.assertEqual(
            product_a.classify_endpoint(-0.1, 0.049), "significantly favorable"
        )
        self.assertEqual(
            product_a.classify_endpoint(0.1, 0.049), "significantly unfavorable"
        )
        self.assertEqual(product_a.classify_endpoint(-0.1, 0.05), "nonsignificant")
        self.assertEqual(product_a.classify_endpoint(0.0, 1.0), "nonsignificant")
        self.assertEqual(product_a.classify_endpoint(None, 0.01), "not estimable")
        self.assertEqual(product_a.classify_endpoint(0.1, None), "not estimable")

        empty_endpoint = product_a._endpoint("wall", [], {}, lambda row: None)
        self.assertEqual(empty_endpoint["classification"], "not estimable")
        self.assertIsNone(empty_endpoint["change_percent"])
        self.assertIsNone(empty_endpoint["confidence_interval_95_change_percent"])
        self.assertIsNone(empty_endpoint["p_value_two_sided"])

    def test_verification_rejects_hash_laundered_wall_telemetry_tampering(self) -> None:
        prepared, run_dir, _ = self._prepare()
        executor = CountingFakeExecutor(delay_seconds=0)
        self._run_fake(run_dir, prepared["request_sha256"], executor)
        evidence = run_dir / product_a.EVIDENCE_DIRECTORY
        attempts_path = evidence / "attempts.jsonl"
        manifest_path = evidence / "execution-manifest.json"
        original_attempts = attempts_path.read_bytes()
        original_manifest = manifest_path.read_bytes()
        attempts = atomic._read_canonical_jsonl(attempts_path)
        attempts[0]["subject_wall_seconds"] += 1.0
        attempts_path.write_bytes(
            b"".join(atomic.canonical_bytes(row) for row in attempts)
        )
        manifest = self._json(manifest_path)
        manifest["attempts_sha256"] = sha256(attempts_path.read_bytes()).hexdigest()
        manifest_path.write_bytes(atomic.canonical_bytes(manifest))

        with self.assertRaisesRegex(
            product_a.ProductAError,
            "subject wall telemetry is inconsistent",
        ):
            product_a.verify_and_report(run_dir, repo=ROOT)
        self.assertFalse((run_dir / product_a.REPORT_FILENAME).exists())

        attempts_path.write_bytes(original_attempts)
        manifest_path.write_bytes(original_manifest)
        workspaces = evidence / "workspaces"
        escaped_workspaces = Path(self.temporary.name) / "escaped-workspaces"
        workspaces.rename(escaped_workspaces)
        workspaces.symlink_to(escaped_workspaces, target_is_directory=True)
        with self.assertRaisesRegex(
            product_a.ProductAError,
            "workspace evidence root is missing, indirect, or unsafe",
        ):
            product_a.verify_and_report(run_dir, repo=ROOT)
        self.assertFalse((run_dir / product_a.REPORT_FILENAME).exists())

    def test_replacement_and_invocation_caps_are_enforced_offline(self) -> None:
        prepared, run_dir, request = self._prepare()
        first_five = sorted(
            request["schedule"]["pairs"], key=lambda row: row["queue_position"]
        )[:5]
        outcomes = {}
        for pair in first_five:
            first_arm = "candidate" if pair["first_arm"] == "md" else "control"
            outcomes[(pair["pair_id"], first_arm)] = atomic.StubOutcome(
                termination_class=atomic.REPLACEABLE_INFRASTRUCTURE_FAILURE,
                mechanical_reason_code=frozen.REPLACEMENT_REASON_CODES[0],
                usable_subject_output=False,
                subject_workspace_changed=False,
            )
        executor = CountingFakeExecutor(outcomes)
        manifest = self._run_fake(run_dir, prepared["request_sha256"], executor)

        self.assertEqual(manifest["replacement_pair_count"], 4)
        self.assertLessEqual(manifest["actual_attempt_records"], 80)
        self.assertLessEqual(manifest["actual_subject_invocations"], 80)
        self.assertEqual(executor.calls, manifest["actual_attempt_records"])
        self.assertLessEqual(executor.calls, 80)
        self.assertLessEqual(executor.peak, 12)
        self.assertLessEqual(manifest["observed_peak_active_subjects"], 12)
        self.assertLessEqual(manifest["observed_peak_executor_calls"], 12)

        analysis = self._json(
            run_dir / product_a.EVIDENCE_DIRECTORY / "analysis.json"
        )
        self.assertEqual(
            analysis["correctness"]["md"],
            {"passed": 35, "failed": 1, "total": 36},
        )
        self.assertEqual(
            analysis["correctness"]["no_md"],
            {"passed": 35, "failed": 1, "total": 36},
        )
        self.assertEqual(analysis["raw_failure_count"], 5)
        self.assertEqual(
            sum(row["scope"] == "raw invocation" for row in analysis["failures"]),
            5,
        )
        self.assertEqual(
            sum(
                row["scope"] == "terminal planned outcome"
                for row in analysis["failures"]
            ),
            1,
        )
        self.assertEqual(analysis["eligibility"]["eligible_task_count"], 17)

        product_a.verify_and_report(run_dir, repo=ROOT)
        report = (run_dir / product_a.REPORT_FILENAME).read_text(encoding="utf-8")
        self.assertIn("MD: **1/36 failed; 35/36 passed.**", report)
        self.assertIn("No-MD: **1/36 failed; 35/36 passed.**", report)
        for failure in analysis["failures"]:
            if failure["attempt_id"] is not None:
                self.assertIn(failure["attempt_id"], report)
            self.assertIn(failure["reason"], report)


if __name__ == "__main__":
    unittest.main()
