from __future__ import annotations

from contextlib import contextmanager
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
import unittest
from unittest import mock

import run_product_a
from tooling import starlette_product_a as product_a


REQUEST_SHA = "a" * 64
RUN_DIR = Path("/tmp/product-a-test-run")


def passing_readiness() -> dict[str, object]:
    return {
        "status": "PASS",
        "failed_checks": [],
        "errors": {},
        "seals": {task_id: {"offline": True} for task_id in product_a.TASK_IDS},
    }


class ProductAInteractiveUXTests(unittest.TestCase):
    @staticmethod
    def prepared() -> dict[str, str]:
        return {
            "run_directory": str(RUN_DIR),
            "request": str(RUN_DIR / product_a.REQUEST_FILENAME),
            "request_sha256": REQUEST_SHA,
        }

    def test_default_no_stops_after_readiness_without_approval_or_calls(self) -> None:
        events: list[object] = []
        output: list[str] = []

        def forbidden(*args, **kwargs):
            raise AssertionError("approval or live work occurred after default No")

        result = run_product_a.run_interactive(
            input_fn=lambda prompt: events.append(("prompt", prompt)) or "",
            output_fn=output.append,
            prepare_fn=lambda: events.append("prepare") or self.prepared(),
            readiness_fn=lambda path: events.append(("readiness", path))
            or passing_readiness(),
            approve_fn=forbidden,
            run_fn=forbidden,
            verify_fn=forbidden,
            refresh_results_fn=forbidden,
        )

        self.assertEqual(result["status"], "cancelled")
        self.assertEqual(events[0:2], ["prepare", ("readiness", RUN_DIR)])
        self.assertEqual(len(events), 3)
        self.assertIn("Type YES to continue [NO]", events[2][1])
        rendered = "\n".join(output)
        self.assertIn("Tasks: 18 bundled Starlette tasks", rendered)
        self.assertIn("Calls: 72 planned; 80 maximum", rendered)
        self.assertIn("Request SHA-256: " + REQUEST_SHA, rendered)
        self.assertIn("request remains unapproved; no model calls were made", rendered)

    def test_readiness_failure_occurs_before_prompt_or_approval(self) -> None:
        events: list[object] = []
        output: list[str] = []

        def forbidden(*args, **kwargs):
            raise AssertionError("prompt, approval, or live work occurred after failed readiness")

        with self.assertRaisesRegex(
            run_product_a.ProductAUXError,
            "readiness check failed: auth_source",
        ):
            run_product_a.run_interactive(
                input_fn=forbidden,
                output_fn=output.append,
                prepare_fn=lambda: events.append("prepare") or self.prepared(),
                readiness_fn=lambda path: events.append(("readiness", path))
                or {
                    "status": "FAIL",
                    "failed_checks": ["auth_source"],
                    "errors": {"auth_source": "authentication is not configured"},
                    "seals": {},
                },
                approve_fn=forbidden,
                run_fn=forbidden,
                verify_fn=forbidden,
                refresh_results_fn=forbidden,
            )

        self.assertEqual(events, ["prepare", ("readiness", RUN_DIR)])
        rendered = "\n".join(output)
        self.assertIn(f"Prepared run directory: {RUN_DIR}", rendered)
        self.assertIn(f"Prepared request SHA-256: {REQUEST_SHA}", rendered)

    def test_yes_binds_displayed_hash_then_runs_verifies_and_refreshes(self) -> None:
        events: list[object] = []
        output: list[str] = []
        dashboard = RUN_DIR / "RESULTS.md"

        def approve(path: Path, request_sha256: str):
            events.append(("approve", path, request_sha256))
            return {"request_sha256": request_sha256, "approval": "APPROVED.json"}

        result = run_product_a.run_interactive(
            input_fn=lambda prompt: events.append(("prompt", prompt)) or "yes",
            output_fn=output.append,
            prepare_fn=lambda: events.append("prepare") or self.prepared(),
            readiness_fn=lambda path: events.append(("readiness", path))
            or passing_readiness(),
            approve_fn=approve,
            run_fn=lambda path: events.append(("run", path)) or {"attempts": 72},
            verify_fn=lambda path: events.append(("verify", path))
            or {"report": str(path / product_a.REPORT_FILENAME)},
            refresh_results_fn=lambda: events.append("refresh") or dashboard,
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(
            events,
            [
                "prepare",
                ("readiness", RUN_DIR),
                (
                    "prompt",
                    "Proceed with up to 80 live model calls? Type YES to continue [NO]: ",
                ),
                ("approve", RUN_DIR, REQUEST_SHA),
                ("run", RUN_DIR),
                ("verify", RUN_DIR),
                "refresh",
            ],
        )
        self.assertEqual(result["request_sha256"], REQUEST_SHA)
        self.assertEqual(result["results"], str(dashboard))
        rendered = "\n".join(output)
        self.assertIn("gpt-5.6-sol, high reasoning", rendered)
        self.assertIn("sealed runner repeats readiness", rendered)
        self.assertIn("Expected runtime: about an hour", rendered)
        self.assertIn("Verified report:", rendered)
        self.assertIn("Updated results dashboard:", rendered)

    def test_yes_rejects_an_approval_that_does_not_echo_the_hash(self) -> None:
        called = {"run": 0}

        with self.assertRaisesRegex(
            run_product_a.ProductAUXError,
            "approval did not bind the displayed request hash",
        ):
            run_product_a.run_interactive(
                input_fn=lambda prompt: "YES",
                output_fn=lambda line: None,
                prepare_fn=self.prepared,
                readiness_fn=lambda path: passing_readiness(),
                approve_fn=lambda path, request_sha256: {
                    "request_sha256": "b" * 64
                },
                run_fn=lambda path: called.__setitem__("run", called["run"] + 1),
                verify_fn=lambda path: {},
                refresh_results_fn=lambda: RUN_DIR / "RESULTS.md",
            )

        self.assertEqual(called["run"], 0)

    def test_live_readiness_reuses_existing_preflight_without_live_backend(self) -> None:
        request = {
            "run_id": "product-a-test-run",
            "sealed_attempt_request_sha256": "sealed-request",
        }
        inner_request = {"schema_version": 3}
        result = passing_readiness()
        original_spec = run_product_a.sealed.SPEC

        @contextmanager
        def registry():
            yield

        with mock.patch.object(
            run_product_a.product_a,
            "_validate_run_boundary",
            return_value=RUN_DIR,
        ), mock.patch.object(
            run_product_a.product_a,
            "_read_json",
            return_value=request,
        ), mock.patch.object(
            run_product_a.product_a,
            "_validate_request",
        ) as validate, mock.patch.object(
            run_product_a.product_a,
            "_execution_request",
            return_value=inner_request,
        ), mock.patch.object(
            run_product_a.product_a,
            "_canonical_bytes",
            return_value=b"request",
        ), mock.patch.object(
            run_product_a.product_a,
            "_digest_bytes",
            return_value="sealed-request",
        ), mock.patch.object(
            run_product_a,
            "demo_task_registry",
            registry,
        ), mock.patch.object(
            run_product_a.run_batch,
            "preflight_request",
            return_value=result,
        ) as preflight, mock.patch.object(
            run_product_a.product_a.live,
            "AtomicLiveBackend",
            side_effect=AssertionError("live model backend must not be constructed"),
        ):
            observed = run_product_a.live_readiness_check(RUN_DIR)

        self.assertEqual(observed, result)
        validate.assert_called_once_with(run_product_a.ROOT, RUN_DIR, request)
        preflight.assert_called_once_with(
            inner_request,
            deadline_seconds=product_a.PREFLIGHT_DEADLINE_SECONDS,
        )
        self.assertIs(run_product_a.sealed.SPEC, original_spec)

    def test_main_reports_keyboard_interrupt_without_assuming_approval_state(self) -> None:
        stderr = StringIO()
        with mock.patch.object(
            run_product_a,
            "run_interactive",
            side_effect=KeyboardInterrupt,
        ), redirect_stderr(stderr):
            self.assertEqual(run_product_a.main([]), 130)

        rendered = stderr.getvalue()
        self.assertIn("approval and execution state depends", rendered)
        self.assertNotIn("consumed approval", rendered)


if __name__ == "__main__":
    unittest.main()
