#!/usr/bin/env python3
"""Build the descriptive Product A results dashboard from preserved artifacts.

The dashboard deliberately does not combine effects, confidence intervals, or
p-values across runs.  It totals correctness outcomes and paired correctness
categories, then repeats each run's already-frozen resource analysis verbatim.
"""

from __future__ import annotations

import argparse
from contextlib import nullcontext
from hashlib import sha256
import json
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[1]
RUNS_RELATIVE = Path("runs") / "product-a"
RESULTS_RELATIVE = Path("RESULTS.md")
HISTORICAL_BATCH_RELATIVE = (
    Path("runs") / "dev-v2" / "starlette-eighteen-two-repeat-v2"
)
HISTORICAL_REPORT_RELATIVE = (
    Path("reports") / "STARLETTE_EIGHTEEN_TWO_REPEAT_V2_REPORT.md"
)

# This one checked-in fresh run predates relocation-safe requests.  Its request
# intentionally retains the original absolute path, so a clone cannot pass the
# current-path verifier.  The fallback below is restricted to this exact run and
# these exact sealed artifact bytes; locally created runs always use the full
# current-path verifier.
BUNDLED_FRESH_RUN_ID = "product-a-28d43ee1189e43c7a2b987689aa923"
BUNDLED_FRESH_SHA256 = {
    "REQUEST.json": "2fde00f0154c9051a692414c9a55df04f86e2b59e241d07e533ba0f9d95027eb",
    "APPROVED.json": "ec8ac788a97d3a6838f172dccd02383dfc9bbf6e63579f217d3a9de9f79d3c82",
    "CONSUMED_APPROVAL.json": "493288c64272a572a9c37926897020ee7abd1f4a4abcceb718ce92db3eef67b1",
    "REPORT.md": "4909adaf1dcb63bf908f35dce688a255d02a7441f893b33df4aa7de5aa2d9a28",
    "live-evidence/schedule.json": "01c11c4c0e454e48809ecd7bf07e5fb7714cb804eeb1d5d544d25b92bd279ddb",
    "live-evidence/preflight.json": "98348ff8770049f0e8582b9d27bec8a6d3260432e399051e7f3ec7692d8390b6",
    "live-evidence/run-seal.json": "d3dd5f6558db29d07abe0f6b3020c7f4812d41352d2e1c5af4a91a9503aaae0e",
    "live-evidence/attempts.jsonl": "ca8ebd1478fd0e42ceacbd595eaa5908b0220625f1548f19b3e92f314551901c",
    "live-evidence/pairs.jsonl": "943e6feb5f0ca902fa89a27ffbb46ab6f972b839ed30b8c8f39ac942eff75a82",
    "live-evidence/scheduler-events.jsonl": "530fe3bb00f849004ab70a75f5953d8108f5b0bf23ea2cc2da0b90acd31fd39d",
    "live-evidence/analysis.json": "19aec237417a1295d9ef33fef18c9a03a19317f4ba6d4cc8ad9aef9308010c6d",
    "live-evidence/execution-manifest.json": "e0b590e7031a34bb8de3debd294cd5f8727729de7ce15874e70c069fb11239cc",
}

PAIRED_KEYS = (
    "both_passed",
    "both_failed",
    "md_only_failed",
    "no_md_only_failed",
)


class ResultsError(RuntimeError):
    """Raised when preserved results cannot be summarized safely."""


VerifiedRun = Callable[[Path, Path], Mapping[str, Any]]
HistoricalLoader = Callable[[Path], Mapping[str, Any]]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ResultsError(message)


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    _require(isinstance(value, dict), f"JSON object required: {path}")
    return value


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        value = json.loads(line)
        _require(isinstance(value, dict), f"JSON object required: {path}:{number}")
        rows.append(value)
    return rows


def _sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _attempt_passes(attempt: Mapping[str, Any]) -> bool:
    return (
        attempt.get("normal_terminal_record") is True
        and attempt.get("valid") is True
        and attempt.get("resolved") is True
    )


def _paired_outcomes(
    attempts: Sequence[Mapping[str, Any]],
    pairs: Sequence[Mapping[str, Any]],
) -> dict[str, int]:
    """Count terminal paired correctness outcomes without making an inference."""

    by_attempt = {str(row.get("attempt_id")): row for row in attempts}
    _require(len(by_attempt) == len(attempts), "attempt IDs are missing or duplicated")
    terminal: dict[str, Mapping[str, Any]] = {}
    for pair in sorted(
        pairs,
        key=lambda row: (
            str(row.get("root_pair_id")),
            int(row.get("replacement_generation", -1)),
        ),
    ):
        root_pair_id = pair.get("root_pair_id")
        _require(isinstance(root_pair_id, str), "pair has no root identity")
        terminal[root_pair_id] = pair

    counts = {key: 0 for key in PAIRED_KEYS}
    for pair in terminal.values():
        attempt_ids = pair.get("attempt_ids")
        _require(isinstance(attempt_ids, list), "terminal pair has no attempt inventory")
        try:
            rows = [by_attempt[str(attempt_id)] for attempt_id in attempt_ids]
        except KeyError as exc:
            raise ResultsError("terminal pair references a missing attempt") from exc
        by_arm = {str(row.get("arm")): row for row in rows}
        _require(
            len(rows) == 2 and set(by_arm) == {"candidate", "control"},
            "terminal pair does not contain one MD and one No-MD attempt",
        )
        md_passed = _attempt_passes(by_arm["candidate"])
        no_md_passed = _attempt_passes(by_arm["control"])
        if md_passed and no_md_passed:
            counts["both_passed"] += 1
        elif not md_passed and not no_md_passed:
            counts["both_failed"] += 1
        elif not md_passed:
            counts["md_only_failed"] += 1
        else:
            counts["no_md_only_failed"] += 1
    return counts


def _verify_relocated_bundled_run(repo_root: Path, run_dir: Path) -> Mapping[str, Any]:
    """Verify the one legacy path-bound fresh run by its exact sealed digests."""

    _require(run_dir.name == BUNDLED_FRESH_RUN_ID, "not the bundled fresh run")
    _require(
        run_dir.parent == repo_root / RUNS_RELATIVE
        and run_dir.is_dir()
        and not run_dir.is_symlink(),
        "bundled fresh run is outside the expected repository location",
    )
    _require(
        {path.name for path in run_dir.iterdir()}
        == {"REQUEST.json", "APPROVED.json", "CONSUMED_APPROVAL.json", "REPORT.md", "live-evidence"},
        "bundled fresh run inventory differs",
    )
    for relative, expected in BUNDLED_FRESH_SHA256.items():
        path = run_dir / relative
        _require(path.is_file() and not path.is_symlink(), f"bundled artifact is missing: {relative}")
        _require(_sha256_file(path) == expected, f"bundled artifact changed: {relative}")

    evidence = run_dir / "live-evidence"
    expected_evidence_names = {
        "schedule.json",
        "preflight.json",
        "run-seal.json",
        "attempts.jsonl",
        "pairs.jsonl",
        "scheduler-events.jsonl",
        "analysis.json",
        "execution-manifest.json",
        "workspaces",
    }
    _require(
        evidence.is_dir()
        and not evidence.is_symlink()
        and {path.name for path in evidence.iterdir()} == expected_evidence_names,
        "bundled evidence inventory differs",
    )
    manifest = _read_json(evidence / "execution-manifest.json")
    _require(
        manifest.get("status") == "complete"
        and manifest.get("execution_mode") == "live_approved",
        "bundled fresh execution is not a completed live run",
    )
    workspace_root = evidence / "workspaces"
    _require(workspace_root.is_dir() and not workspace_root.is_symlink(), "workspace evidence is missing")
    workspace_entries = list(workspace_root.rglob("*"))
    _require(
        all(not path.is_symlink() for path in workspace_entries),
        "bundled workspace evidence contains a symbolic link",
    )
    workspace_hashes = {
        path.relative_to(evidence).as_posix(): _sha256_file(path)
        for path in sorted(workspace_entries)
        if path.is_file()
    }
    _require(
        workspace_hashes == manifest.get("workspace_evidence_sha256"),
        "bundled workspace evidence changed",
    )
    request = _read_json(run_dir / "REQUEST.json")
    _require(request.get("run_id") == BUNDLED_FRESH_RUN_ID, "bundled request identity differs")
    return {
        "request": request,
        "request_sha256": BUNDLED_FRESH_SHA256["REQUEST.json"],
        "manifest": manifest,
        "analysis": _read_json(evidence / "analysis.json"),
        "attempts": _read_jsonl(evidence / "attempts.jsonl"),
        "pairs": _read_jsonl(evidence / "pairs.jsonl"),
        "report_path": run_dir / "REPORT.md",
    }


def _default_verify_run(repo_root: Path, run_dir: Path) -> Mapping[str, Any]:
    """Use the full verifier, with an exact-digest relocation exception."""

    from tooling import starlette_product_a as product_a

    runs_root = repo_root / RUNS_RELATIVE
    components = _read_json(run_dir / "REQUEST.json").get("component_sha256", {})
    runtime_context = nullcontext()
    if isinstance(components, dict) and "product_a_public_runtime" in components:
        from tooling import starlette_product_a_runtime as public_runtime
        runtime_context = public_runtime.protocol()
    try:
        with runtime_context:
            manifest, analysis = product_a._verify_evidence(  # noqa: SLF001
                repo_root, run_dir, allowed_runs_root=runs_root,
            )
    except Exception:
        request_path = run_dir / "REQUEST.json"
        request = _read_json(request_path)
        recorded_directory = Path(str(request.get("run_directory", ""))).absolute()
        relocated_exact_bundle = (
            run_dir.name == BUNDLED_FRESH_RUN_ID
            and recorded_directory != run_dir.absolute()
            and _sha256_file(request_path) == BUNDLED_FRESH_SHA256["REQUEST.json"]
        )
        if relocated_exact_bundle:
            return _verify_relocated_bundled_run(repo_root, run_dir)
        raise
    report_path = run_dir / product_a.REPORT_FILENAME
    _require(report_path.is_file() and not report_path.is_symlink(), "REPORT.md is missing")
    _require(
        report_path.read_text(encoding="utf-8") == product_a.render_report(analysis),
        "REPORT.md differs from the verified analysis",
    )
    return {
        "request": _read_json(run_dir / product_a.REQUEST_FILENAME),
        "request_sha256": sha256(
            (run_dir / product_a.REQUEST_FILENAME).read_bytes()
        ).hexdigest(),
        "manifest": manifest,
        "analysis": analysis,
        "attempts": _read_jsonl(
            run_dir / product_a.EVIDENCE_DIRECTORY / "attempts.jsonl"
        ),
        "pairs": _read_jsonl(run_dir / product_a.EVIDENCE_DIRECTORY / "pairs.jsonl"),
        "report_path": report_path,
    }


def _default_historical_loader(repo_root: Path) -> Mapping[str, Any]:
    """Fully verify the bundled history and confirm its report still regenerates."""

    from tooling import report_starlette_eighteen as report
    from tooling import starlette_demo

    _require(repo_root == starlette_demo.ROOT, "historical verifier repository differs")
    starlette_demo.verify_evidence()

    batch = repo_root / HISTORICAL_BATCH_RELATIVE
    evidence = batch / "live-evidence"
    request = _read_json(batch / "REQUEST.json")
    manifest = _read_json(evidence / "execution-manifest.json")
    primary = _read_json(evidence / "analysis.json")
    attempts = _read_jsonl(evidence / "attempts.jsonl")
    pairs = _read_jsonl(evidence / "pairs.jsonl")
    data = report.build_report_data(request, manifest, primary, attempts, pairs)
    report_path = repo_root / HISTORICAL_REPORT_RELATIVE
    _require(
        report_path.read_text(encoding="utf-8") == report.render_markdown(data),
        "the bundled historical report does not match its preserved evidence",
    )
    return {
        **data,
        "report_path": report_path,
        "report_relative": HISTORICAL_REPORT_RELATIVE.as_posix(),
    }


def _incomplete_state(run_dir: Path) -> str:
    evidence = run_dir / "live-evidence"
    if (run_dir / "CONSUMED_APPROVAL.json").is_file() and not evidence.exists():
        return "approval consumed during preflight; zero subject calls recorded"
    if evidence.exists():
        return "execution or verification is incomplete"
    if (run_dir / "APPROVED.json").is_file():
        return "approved but not launched"
    return "prepared but not approved"


def _normalize_run(
    run_dir: Path,
    verified: Mapping[str, Any],
    repo_root: Path,
) -> dict[str, Any]:
    request = verified["request"]
    manifest = verified["manifest"]
    analysis = verified["analysis"]
    attempts = verified["attempts"]
    pairs = verified["pairs"]
    _require(isinstance(request, Mapping), "verified request is missing")
    _require(isinstance(manifest, Mapping), "verified manifest is missing")
    _require(isinstance(analysis, Mapping), "verified analysis is missing")
    _require(isinstance(attempts, Sequence), "verified attempts are missing")
    _require(isinstance(pairs, Sequence), "verified pairs are missing")

    correctness = analysis.get("correctness")
    _require(isinstance(correctness, Mapping), "verified correctness summary is missing")
    md = correctness.get("md")
    no_md = correctness.get("no_md")
    _require(isinstance(md, Mapping) and isinstance(no_md, Mapping), "arm counts are missing")
    paired = _paired_outcomes(attempts, pairs)
    pair_total = sum(paired.values())
    _require(pair_total == int(md["total"]) == int(no_md["total"]), "paired totals differ")
    _require(
        paired["both_passed"] + paired["no_md_only_failed"] == int(md["passed"])
        and paired["both_failed"] + paired["md_only_failed"] == int(md["failed"])
        and paired["both_passed"] + paired["md_only_failed"] == int(no_md["passed"])
        and paired["both_failed"] + paired["no_md_only_failed"] == int(no_md["failed"]),
        "paired categories differ from verified correctness totals",
    )

    report_path = Path(verified["report_path"])
    try:
        report_relative = report_path.relative_to(repo_root).as_posix()
    except ValueError as exc:
        raise ResultsError("verified report is outside the repository") from exc
    component_hashes = request.get("component_sha256", {})
    _require(isinstance(component_hashes, Mapping), "request component binding is missing")
    return {
        "run_id": run_dir.name,
        "created_utc": str(request.get("created_utc") or "unknown"),
        "request_sha256": str(verified["request_sha256"]),
        "analysis_freeze_sha256": str(analysis.get("analysis_freeze_sha256") or "unknown"),
        "runner_sha256": str(
            component_hashes.get("product_a_runner_and_reporter") or "unknown"
        ),
        "report_relative": report_relative,
        "correctness": {
            "md": {key: int(md[key]) for key in ("failed", "passed", "total")},
            "no_md": {
                key: int(no_md[key]) for key in ("failed", "passed", "total")
            },
        },
        "paired": paired,
        "failures": list(analysis.get("failures", [])),
        "eligibility": analysis["eligibility"],
        "endpoints": analysis["endpoints"],
        "subject_invocations": int(manifest.get("actual_subject_invocations", 0)),
    }


def collect_results(
    repo_root: Path,
    *,
    verify_run: VerifiedRun | None = None,
    historical_loader: HistoricalLoader | None = None,
) -> dict[str, Any]:
    """Collect verified live runs plus disclosed, uncounted lifecycle remnants."""

    repo_root = repo_root.absolute()
    runs_root = repo_root / RUNS_RELATIVE
    verifier = verify_run or _default_verify_run
    load_historical = historical_loader or _default_historical_loader
    fresh_runs: list[dict[str, Any]] = []
    not_counted: list[dict[str, str]] = []

    if runs_root.exists():
        _require(runs_root.is_dir() and not runs_root.is_symlink(), "unsafe Product A runs root")
        for run_dir in sorted(runs_root.iterdir(), key=lambda path: path.name):
            if not run_dir.is_dir() or run_dir.is_symlink() or not run_dir.name.startswith("product-a-"):
                continue
            request_path = run_dir / "REQUEST.json"
            if not request_path.is_file():
                not_counted.append({
                    "run_id": run_dir.name,
                    "created_utc": "unknown",
                    "request_relative": "—",
                    "state": "run directory has no request",
                })
                continue
            try:
                request = _read_json(request_path)
            except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
                raise ResultsError(f"cannot read Product A request {run_dir.name}: {exc}") from exc
            request_relative = request_path.relative_to(repo_root).as_posix()
            complete_surface = all(
                path.is_file()
                for path in (
                    run_dir / "REPORT.md",
                    run_dir / "live-evidence" / "analysis.json",
                    run_dir / "live-evidence" / "execution-manifest.json",
                    run_dir / "live-evidence" / "attempts.jsonl",
                    run_dir / "live-evidence" / "pairs.jsonl",
                )
            )
            if not complete_surface:
                not_counted.append({
                    "run_id": run_dir.name,
                    "created_utc": str(request.get("created_utc") or "unknown"),
                    "request_relative": request_relative,
                    "state": _incomplete_state(run_dir),
                })
                continue
            try:
                verified = verifier(repo_root, run_dir)
                normalized = _normalize_run(run_dir, verified, repo_root)
            except Exception as exc:
                if isinstance(exc, (KeyboardInterrupt, SystemExit)):
                    raise
                raise ResultsError(f"cannot verify completed run {run_dir.name}: {exc}") from exc
            execution_mode = verified["manifest"].get("execution_mode")
            if execution_mode != "live_approved":
                not_counted.append({
                    "run_id": run_dir.name,
                    "created_utc": normalized["created_utc"],
                    "request_relative": request_relative,
                    "state": f"{execution_mode or 'unknown'} execution; not a live replication",
                })
                continue
            _require(
                verified["manifest"].get("status") == "complete",
                f"verified live run is not complete: {run_dir.name}",
            )
            fresh_runs.append(normalized)

    fresh_runs.sort(key=lambda row: (row["created_utc"], row["run_id"]))
    totals = {
        arm: {
            key: sum(run["correctness"][arm][key] for run in fresh_runs)
            for key in ("failed", "passed", "total")
        }
        for arm in ("md", "no_md")
    }
    paired_totals = {
        key: sum(run["paired"][key] for run in fresh_runs) for key in PAIRED_KEYS
    }
    return {
        "fresh_runs": fresh_runs,
        "totals": totals,
        "paired_totals": paired_totals,
        "not_counted": sorted(
            not_counted, key=lambda row: (row["created_utc"], row["run_id"])
        ),
        "historical": dict(load_historical(repo_root)),
    }


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _link(label: str, relative: str) -> str:
    return f"[{label}]({relative})"


def _count_text(counts: Mapping[str, int]) -> str:
    total = int(counts["total"])
    failed = int(counts["failed"])
    rate = 100.0 * failed / total if total else 0.0
    return (
        f"**{failed}/{total} failed; {int(counts['passed'])}/{total} passed "
        f"({rate:.1f}% failure).**"
    )


def _endpoint_cells(endpoint: Mapping[str, Any]) -> tuple[str, str, str, str]:
    classification = str(endpoint.get("classification") or "not estimable")
    if classification == "not estimable":
        return "not estimable", "not estimable", "not estimable", classification
    effect = endpoint.get("change_percent")
    interval = endpoint.get("confidence_interval_95_change_percent")
    p_value = endpoint.get("p_value_two_sided")
    _require(
        isinstance(effect, (int, float))
        and isinstance(interval, list)
        and len(interval) == 2
        and isinstance(p_value, (int, float)),
        "estimated endpoint fields are incomplete",
    )
    return (
        f"{float(effect):+.4f}%",
        f"{float(interval[0]):+.4f}% to {float(interval[1]):+.4f}%",
        f"{float(p_value):.8g}",
        classification,
    )


def _historical_endpoint_cells(endpoint: Mapping[str, Any]) -> tuple[str, str, str, str]:
    classification = str(endpoint.get("classification") or "not estimable")
    if classification == "not estimable":
        return "not estimable", "not estimable", "not estimable", classification
    ratio_ci = endpoint.get("confidence_interval_95_ratio")
    _require(isinstance(ratio_ci, list) and len(ratio_ci) == 2, "historical CI is missing")
    reduction_low = 100.0 * (1.0 - float(ratio_ci[1]))
    reduction_high = 100.0 * (1.0 - float(ratio_ci[0]))
    return (
        f"{float(endpoint['reduction_percent']):.4f}% reduction",
        f"{reduction_low:.4f}% to {reduction_high:.4f}% reduction",
        f"{float(endpoint['p_value_two_sided']):.8g}",
        classification,
    )


def render_results(data: Mapping[str, Any]) -> str:
    """Render a deterministic, descriptive dashboard with no cross-run test."""

    runs = list(data["fresh_runs"])
    totals = data["totals"]
    paired = data["paired_totals"]
    lines = [
        "# Product A results",
        "",
        "## Verified fresh runs: correctness tally",
        "",
        f"MD: {_count_text(totals['md'])}",
        "",
        f"No-MD: {_count_text(totals['no_md'])}",
        "",
        f"Counted replications: **{len(runs)}**.",
        "",
        "These totals are descriptive. Resource effects, confidence intervals, and p-values "
        "are shown per run only; they are not pooled into a cross-run significance claim.",
        "",
        "### Paired correctness outcomes",
        "",
        "| Both passed | Both failed | MD-only failed | No-MD-only failed | Total pairs |",
        "|---:|---:|---:|---:|---:|",
        f"| {paired['both_passed']} | {paired['both_failed']} | "
        f"{paired['md_only_failed']} | {paired['no_md_only_failed']} | "
        f"{sum(paired.values())} |",
        "",
        "`MD-only failed` means No-MD passed that pair; `No-MD-only failed` means MD passed.",
        "",
        "### Run ledger",
        "",
    ]
    if runs:
        lines.extend([
            "| Run | Created (UTC) | MD | No-MD | Both pass / both fail / MD-only fail / No-MD-only fail | Report |",
            "|---:|---|---:|---:|---:|---|",
        ])
        for index, run in enumerate(runs, 1):
            md = run["correctness"]["md"]
            no_md = run["correctness"]["no_md"]
            outcome = run["paired"]
            lines.append(
                f"| {index} (`{_cell(run['run_id'])}`) | {_cell(run['created_utc'])} | "
                f"{md['failed']}/{md['total']} failed | {no_md['failed']}/{no_md['total']} failed | "
                f"{outcome['both_passed']} / {outcome['both_failed']} / "
                f"{outcome['md_only_failed']} / {outcome['no_md_only_failed']} | "
                f"{_link('REPORT.md', run['report_relative'])} |"
            )
    else:
        lines.append("No verified fresh live runs are present.")

    lines.extend(["", "## Every fresh-run failure", ""])
    failures = [
        (index, run, failure)
        for index, run in enumerate(runs, 1)
        for failure in run["failures"]
    ]
    if failures:
        lines.extend([
            "| Run | Scope | Attempt | Task | Repeat | Arm | Reason | Mechanical code | Termination |",
            "|---:|---|---|---|---:|---|---|---|---|",
        ])
        for index, _run, failure in failures:
            lines.append(
                f"| {index} | {_cell(failure.get('scope') or '—')} | "
                f"{_cell(failure.get('attempt_id') or '—')} | "
                f"{_cell(failure.get('task_id') or '—')} | "
                f"{_cell(failure.get('repeat') or '—')} | "
                f"{_cell(failure.get('arm') or '—')} | "
                f"{_cell(failure.get('reason') or '—')} | "
                f"{_cell(failure.get('mechanical_reason_code') or '—')} | "
                f"{_cell(failure.get('termination_class') or '—')} |"
            )
    else:
        lines.append("None.")

    lines.extend([
        "",
        "## Per-run complete-task resource results",
        "",
        "Negative change favors MD. Each row is the run's existing frozen analysis; no "
        "cross-run effect or p-value is calculated here.",
        "",
        "| Run | Endpoint | Eligible tasks | Effect (MD vs No-MD) | 95% change CI | Two-sided p | Classification |",
        "|---:|---|---:|---:|---:|---:|---|",
    ])
    for index, run in enumerate(runs, 1):
        for name, label in (("wall", "Wall"), ("token", "Token")):
            endpoint = run["endpoints"][name]
            effect, interval, p_value, classification = _endpoint_cells(endpoint)
            lines.append(
                f"| {index} | {label} | {endpoint['task_count']} | {effect} | "
                f"{interval} | {p_value} | **{_cell(classification)}** |"
            )
    if not runs:
        lines.append("| — | — | 0 | not estimable | not estimable | not estimable | **not estimable** |")

    lines.extend(["", "### Fresh-run exclusions", ""])
    exclusions = [
        (index, exclusion, details)
        for index, run in enumerate(runs, 1)
        for exclusion in run["eligibility"]["exclusions"]
        for details in [[
            row for row in run["eligibility"]["exclusion_details"]
            if row["task_id"] == exclusion["task_id"]
        ]]
    ]
    if exclusions:
        lines.extend([
            "| Run | Task | Usable paired repeats | Reasons |",
            "|---:|---|---:|---|",
        ])
        for index, exclusion, matching in exclusions:
            reason_text = "; ".join(
                f"repeat {detail['repeat']}: {', '.join(detail['reasons'])}"
                for row in matching
                for detail in row["details"]
            )
            lines.append(
                f"| {index} | {_cell(exclusion['task_id'])} | "
                f"{exclusion['usable_pair_count']}/2 | {_cell(reason_text)} |"
            )
    else:
        lines.append("None.")

    lines.extend(["", "### Reproducibility fingerprints", ""])
    if runs:
        lines.extend([
            "| Run | Request SHA-256 | Analysis-rule SHA-256 | Runner SHA-256 | Subject invocations |",
            "|---:|---|---|---|---:|",
        ])
        for index, run in enumerate(runs, 1):
            lines.append(
                f"| {index} | `{run['request_sha256']}` | "
                f"`{run['analysis_freeze_sha256']}` | `{run['runner_sha256']}` | "
                f"{run['subject_invocations']} |"
            )
    else:
        lines.append("No fresh-run fingerprints.")

    lines.extend(["", "## Prepared or uncounted Product A requests", ""])
    not_counted = list(data["not_counted"])
    if not_counted:
        lines.extend([
            "| Run | Created (UTC) | State | Request |",
            "|---|---|---|---|",
        ])
        for row in not_counted:
            request_link = (
                _link("REQUEST.json", row["request_relative"])
                if row["request_relative"] != "—"
                else "—"
            )
            lines.append(
                f"| `{_cell(row['run_id'])}` | {_cell(row['created_utc'])} | "
                f"{_cell(row['state'])}; **not counted** | {request_link} |"
            )
    else:
        lines.append("None.")

    historical = data["historical"]
    historical_counts = historical["outcome_counts"]
    sensitivity = historical["sensitivity"]
    historical_report_relative = str(
        historical.get("report_relative") or historical["report_path"]
    )
    lines.extend([
        "",
        "## Bundled historical example (separate; not pooled)",
        "",
        f"MD: {_count_text(historical_counts['candidate'])}",
        "",
        f"No-MD: {_count_text(historical_counts['control'])}",
        "",
        f"Eligible complete tasks: **{len(sensitivity['complete_task_ids'])}/18**.",
        "",
        "| Endpoint | Eligible tasks | Effect (MD vs No-MD) | 95% CI | Two-sided p | Classification |",
        "|---|---:|---:|---:|---:|---|",
    ])
    for name, label in (("wall", "Wall"), ("token", "Token")):
        endpoint = sensitivity[name]
        effect, interval, p_value, classification = _historical_endpoint_cells(endpoint)
        lines.append(
            f"| {label} | {endpoint.get('task_count', 0)} | {effect} | {interval} | "
            f"{p_value} | **{_cell(classification)}** |"
        )
    lines.extend([
        "",
        "The historical all-18 registered endpoint was unavailable. Its n=16 complete-task "
        "analysis was not historically preregistered, so it remains a labeled post-hoc example.",
        "",
        f"See the {_link('full historical report', historical_report_relative)} for its "
        "failures, exclusions, and per-task results.",
        "",
        "## Statistical guardrail",
        "",
        "This dashboard totals correctness outcomes only. It does **not** pool p-values, "
        "combine confidence intervals, count significant runs as proof, or introduce a new "
        "cross-run hypothesis test. A formal cross-run method can be selected separately "
        "before using future runs for confirmatory inference.",
    ])
    return "\n".join(lines) + "\n"


def refresh_results(repo_root: Path, output_path: Path | None = None) -> Path:
    """Verify available artifacts and atomically refresh the Markdown dashboard."""

    repo_root = repo_root.absolute()
    destination = (output_path or (repo_root / RESULTS_RELATIVE)).absolute()
    _require(destination.parent == repo_root, "RESULTS.md must be written at repository root")
    rendered = render_results(collect_results(repo_root))
    temporary = destination.with_name(f".{destination.name}.tmp")
    _require(not temporary.exists() and not temporary.is_symlink(), "temporary results file exists")
    try:
        temporary.write_text(rendered, encoding="utf-8")
        temporary.replace(destination)
    finally:
        if temporary.exists() and not temporary.is_symlink():
            temporary.unlink()
    return destination


def _parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(description=__doc__)


def main(argv: Sequence[str] | None = None) -> int:
    _parser().parse_args(argv)
    try:
        path = refresh_results(ROOT)
    except (ResultsError, OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}")
        return 1
    print(json.dumps({"results": str(path)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
