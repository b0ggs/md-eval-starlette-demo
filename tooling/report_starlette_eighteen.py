#!/usr/bin/env python3
"""Offline Markdown report for a verified 18-task Starlette experiment."""

from __future__ import annotations

import argparse
from hashlib import sha256
import json
import math
from pathlib import Path
import statistics
from typing import Any, Callable, Mapping, Sequence

from tooling import starlette_eighteen_task_experiment as experiment


class ReportError(RuntimeError):
    pass


def _classification(mean_effect: Any, p_value: Any) -> str:
    """Return the required four-way interpretation for an endpoint."""
    if (
        isinstance(mean_effect, bool)
        or not isinstance(mean_effect, (int, float))
        or not math.isfinite(float(mean_effect))
        or isinstance(p_value, bool)
        or not isinstance(p_value, (int, float))
        or not math.isfinite(float(p_value))
        or not 0.0 <= float(p_value) <= 1.0
    ):
        return "not estimable"
    if float(p_value) >= 0.05 or float(mean_effect) == 0.0:
        return "nonsignificant"
    if float(mean_effect) < 0.0:
        return "significantly favorable"
    return "significantly unfavorable"


def _attempt_passed(row: Mapping[str, Any]) -> bool:
    return (
        row.get("normal_terminal_record") is True
        and row.get("valid") is True
        and row.get("resolved") is True
        and row.get("subject_timeout") is not True
        and row.get("infrastructure_failure") is not True
    )


def _failure_reason(row: Mapping[str, Any]) -> str:
    mechanical = row.get("mechanical_reason_code")
    if mechanical not in (None, "", "completed"):
        return str(mechanical)
    if row.get("infrastructure_failure") is True:
        return "infrastructure_failure"
    if row.get("subject_timeout") is True:
        return "subject_timeout"
    if row.get("valid") is not True:
        return "invalid_attempt_record"
    if row.get("normal_terminal_record") is not True:
        return str(row.get("termination_class") or "abnormal_termination")
    if row.get("resolved") is not True:
        return "checker_unresolved"
    return str(mechanical or "unknown_failure")


def _has_both_repeats(pairs: Sequence[Mapping[str, Any]]) -> bool:
    return (
        len(pairs) == experiment.REPEATS
        and {row.get("repeat_id") for row in pairs}
        == set(range(1, experiment.REPEATS + 1))
    )


def _terminal_pairs(pairs: Sequence[Mapping[str, Any]]) -> list[Mapping[str, Any]]:
    terminal: dict[str, Mapping[str, Any]] = {}
    for pair in sorted(pairs, key=lambda row: row["replacement_generation"]):
        terminal[pair["root_pair_id"]] = pair
    return list(terminal.values())


def _report_inputs(
    attempts: Sequence[Mapping[str, Any]], pairs: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, dict[str, int]], dict[str, list[dict[str, Any]]], list[Mapping[str, Any]]]:
    by_attempt = {row["attempt_id"]: row for row in attempts}
    resolved = {
        task: {"candidate": 0, "control": 0} for task in experiment.TASK_IDS
    }
    selected: dict[str, list[dict[str, Any]]] = {
        task: [] for task in experiment.TASK_IDS
    }
    for pair in _terminal_pairs(pairs):
        rows = [by_attempt[item] for item in pair["attempt_ids"]]
        for row in rows:
            if row["arm"] in resolved[pair["task_id"]] and _attempt_passed(row):
                resolved[pair["task_id"]][row["arm"]] += 1
        usable = (
            pair["status"] == "complete"
            and len(rows) == 2
            and {row["arm"] for row in rows} == {"candidate", "control"}
            and all(_attempt_passed(row) for row in rows)
        )
        if usable:
            selected[pair["task_id"]].append({**pair, "attempts": rows})
    for rows in selected.values():
        rows.sort(key=lambda row: row["repeat_id"])
    failures = [
        row for row in attempts
        if not _attempt_passed(row)
    ]
    failures.sort(key=lambda row: row["attempt_id"])
    return resolved, selected, failures


def _task_endpoint(
    pairs: Sequence[Mapping[str, Any]], value: Callable[[Mapping[str, Any]], Any],
) -> dict[str, float] | None:
    values = {"candidate": [], "control": []}
    for pair in pairs:
        for attempt in pair["attempts"]:
            observed = value(attempt)
            if (
                isinstance(observed, bool)
                or not isinstance(observed, (int, float))
                or not math.isfinite(float(observed))
                or float(observed) <= 0.0
            ):
                return None
            values[attempt["arm"]].append(float(observed))
    if not values["candidate"] or len(values["candidate"]) != len(values["control"]):
        return None
    candidate = statistics.fmean(values["candidate"])
    control = statistics.fmean(values["control"])
    return {
        "candidate_mean": candidate,
        "control_mean": control,
        "log_ratio": math.log(candidate) - math.log(control),
        "change_percent": 100.0 * (candidate / control - 1.0),
    }


def _sensitivity_endpoint(
    name: str,
    task_ids: Sequence[str],
    selected: Mapping[str, Sequence[Mapping[str, Any]]],
    value: Callable[[Mapping[str, Any]], Any],
) -> dict[str, Any]:
    task_results: list[dict[str, Any]] = []
    for task in task_ids:
        result = _task_endpoint(selected[task], value)
        if result is None:
            return {
                "name": name,
                "status": "not_estimable",
                "classification": "not estimable",
                "reason": f"missing or invalid {name} telemetry for {task}",
            }
        task_results.append({"task_id": task, **result})
    if len(task_results) < 2:
        return {
            "name": name,
            "status": "not_estimable",
            "classification": "not estimable",
            "reason": "fewer than two complete tasks",
        }
    effects = [row["log_ratio"] for row in task_results]
    mean_effect = statistics.fmean(effects)
    sample_sd = statistics.stdev(effects)
    standard_error = sample_sd / math.sqrt(len(effects))
    if standard_error == 0.0:
        t_statistic = 0.0 if mean_effect == 0.0 else None
        p_value = 1.0 if mean_effect == 0.0 else 0.0
    else:
        t_statistic = mean_effect / standard_error
        p_value = experiment.frozen_analysis.student_t_two_sided_p(
            t_statistic, len(effects) - 1,
        )
    critical = experiment.frozen_analysis.student_t_quantile(
        0.975, len(effects) - 1,
    )
    lower = mean_effect - critical * standard_error
    upper = mean_effect + critical * standard_error
    ratio = math.exp(mean_effect)
    return {
        "name": name,
        "status": "conclusive",
        "task_count": len(task_results),
        "degrees_of_freedom": len(task_results) - 1,
        "task_results": task_results,
        "mean_task_log_ratio": mean_effect,
        "sample_standard_deviation": sample_sd,
        "standard_error": standard_error,
        "t_statistic": t_statistic,
        "p_value_two_sided": p_value,
        "geometric_mean_ratio": ratio,
        "reduction_percent": 100.0 * (1.0 - ratio),
        "confidence_interval_95_ratio": [math.exp(lower), math.exp(upper)],
        "favorable_reduction": p_value < 0.05 and mean_effect < 0.0,
        "classification": _classification(mean_effect, p_value),
    }


def build_report_data(
    request: Mapping[str, Any],
    manifest: Mapping[str, Any],
    primary: Mapping[str, Any],
    attempts: Sequence[Mapping[str, Any]],
    pairs: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    resolved, selected, failures = _report_inputs(attempts, pairs)
    complete_tasks = [
        task for task in experiment.TASK_IDS
        if _has_both_repeats(selected[task])
    ]
    excluded_tasks = []
    failures_by_task: dict[str, list[Mapping[str, Any]]] = {
        task: [] for task in experiment.TASK_IDS
    }
    terminal_attempt_ids = {
        attempt_id
        for pair in _terminal_pairs(pairs)
        for attempt_id in pair["attempt_ids"]
    }
    for failure in failures:
        if failure["attempt_id"] in terminal_attempt_ids:
            failures_by_task[failure["task_id"]].append(failure)
    for task in experiment.TASK_IDS:
        usable_pair_count = len(selected[task])
        if _has_both_repeats(selected[task]):
            continue
        excluded_tasks.append({
            "task_id": task,
            "usable_pair_count": usable_pair_count,
            "failures": failures_by_task[task],
        })
    task_rows = []
    for task in experiment.TASK_IDS:
        analysis_pairs = (
            selected[task]
            if _has_both_repeats(selected[task])
            else []
        )
        task_rows.append({
            "task_id": task,
            "md_resolved": resolved[task]["candidate"],
            "no_md_resolved": resolved[task]["control"],
            "usable_pairs": len(selected[task]),
            "wall": _task_endpoint(
                analysis_pairs, lambda row: row.get("subject_wall_seconds"),
            ),
            "token": _task_endpoint(
                analysis_pairs,
                lambda row: row.get("uncached_input_plus_output_token_proxy"),
            ),
        })
    sensitivity = {
        "label": "post-hoc exploratory complete-case sensitivity",
        "complete_task_ids": complete_tasks,
        "eligible_pair_count": len(complete_tasks) * experiment.REPEATS,
        "excluded_tasks": excluded_tasks,
        "wall": _sensitivity_endpoint(
            "wall", complete_tasks, selected,
            lambda row: row.get("subject_wall_seconds"),
        ),
        "token": _sensitivity_endpoint(
            "token", complete_tasks, selected,
            lambda row: row.get("uncached_input_plus_output_token_proxy"),
        ),
    }
    return {
        "purpose": request.get("purpose"),
        "outcome_counts": {
            arm: {
                "passed": sum(resolved[task][arm] for task in experiment.TASK_IDS),
                "failed": (
                    len(experiment.TASK_IDS) * experiment.REPEATS
                    - sum(resolved[task][arm] for task in experiment.TASK_IDS)
                ),
                "total": len(experiment.TASK_IDS) * experiment.REPEATS,
            }
            for arm in ("candidate", "control")
        },
        "manifest": {
            key: manifest.get(key) for key in (
                "actual_attempt_records", "pair_record_count",
                "actual_subject_invocations", "replacement_pair_count",
                "observed_peak_active_subjects", "duration_seconds",
            )
        },
        "primary": primary,
        "task_rows": task_rows,
        "failures": failures,
        "sensitivity": sensitivity,
    }


def _means(result: Mapping[str, Any] | None, unit: str) -> tuple[str, str]:
    if result is None:
        return "—", "—"
    candidate = result["candidate_mean"]
    control = result["control_mean"]
    if unit == "s":
        means = f"{candidate:.1f} / {control:.1f}s"
    else:
        means = f"{candidate:,.0f} / {control:,.0f}"
    return means, f"{result['change_percent']:+.1f}%"


def render_markdown(data: Mapping[str, Any]) -> str:
    manifest = data["manifest"]
    primary = data["primary"]
    correctness = primary["correctness"]
    counts = data["outcome_counts"]
    sensitivity = data["sensitivity"]
    eligible_task_count = len(sensitivity["complete_task_ids"])
    has_significant_result = any(
        sensitivity[name]["classification"].startswith("significantly ")
        for name in ("wall", "token")
    )
    analysis_heading = (
        f"Complete-task analysis: significant n={eligible_task_count} results"
        if has_significant_result
        else f"Complete-task analysis (n={eligible_task_count} eligible tasks)"
    )
    lines = [
        "# Starlette 18-task MD/no-MD outcome report",
        "",
        "## Pass/fail",
        "",
        f"- **MD: {counts['candidate']['failed']}/{counts['candidate']['total']} "
        f"failed; {counts['candidate']['passed']}/{counts['candidate']['total']} passed.**",
        f"- **No-MD: {counts['control']['failed']}/{counts['control']['total']} "
        f"failed; {counts['control']['passed']}/{counts['control']['total']} passed.**",
        "",
        "## Every failure and reason",
        "",
    ]
    if data["failures"]:
        lines += [
            "| Attempt | Task | Arm | Reason | Termination |",
            "|---|---|---|---|---|",
        ]
        for row in data["failures"]:
            arm = "MD" if row["arm"] == "candidate" else "No-MD"
            lines.append(
                f"| {row['attempt_id']} | {row['task_id']} | {arm} | "
                f"{_failure_reason(row)} | {row['termination_class']} |"
            )
    else:
        lines.append("None.")
    lines += [
        "",
        f"## {analysis_heading}",
        "",
        "A task is eligible only when both paired repeats are usable, meaning "
        "both arms finished normally, were valid, and passed. Both repeats from "
        "every eligible task are analyzed; a lone surviving repeat is neither "
        "used nor displayed as a resource estimate.",
        "",
        "| Endpoint | Eligible tasks | Effect (MD vs No-MD) | 95% CI | "
        "Two-sided p | Classification |",
        "|---|---:|---:|---:|---:|---|",
    ]
    for name, label in (("wall", "Wall time"), ("token", "Tokens")):
        endpoint = sensitivity[name]
        if endpoint["classification"] == "not estimable":
            lines.append(
                f"| {label} | {eligible_task_count} | — | — | — | "
                f"**not estimable** — {endpoint['reason']} |"
            )
            continue
        ratio_ci = endpoint["confidence_interval_95_ratio"]
        reduction_ci = (
            100.0 * (1.0 - ratio_ci[1]),
            100.0 * (1.0 - ratio_ci[0]),
        )
        lines.append(
            f"| {label} | {endpoint['task_count']} | "
            f"{endpoint['reduction_percent']:.4f}% reduction | "
            f"{reduction_ci[0]:.4f}%–{reduction_ci[1]:.4f}% reduction | "
            f"{endpoint['p_value_two_sided']:.8g} | "
            f"**{endpoint['classification']}** |"
        )
    lines += [
        "",
        "The effect is the geometric mean of task-level MD/No-MD ratios, shown "
        "as a percent reduction. Each task-level ratio compares arithmetic means "
        "across its two usable paired repeats. The confidence interval and "
        "two-sided p-value use the existing one-sample t procedure on task log ratios.",
        "",
        "### Eligibility and exclusions",
        "",
        f"- Eligible: **{len(sensitivity['complete_task_ids'])}/"
        f"{len(experiment.TASK_IDS)} tasks**, comprising "
        f"{sensitivity['eligible_pair_count']} usable paired repeats.",
    ]
    if sensitivity["excluded_tasks"]:
        for exclusion in sensitivity["excluded_tasks"]:
            reasons = []
            for row in exclusion["failures"]:
                arm = "MD" if row["arm"] == "candidate" else "No-MD"
                reasons.append(
                    f"repeat {row['repeat_id']} {arm}: "
                    f"{_failure_reason(row)} "
                    f"({row['termination_class']})"
                )
            reason_text = "; ".join(reasons) or "fewer than two usable repeats"
            lines.append(
                f"- Excluded `{exclusion['task_id']}`: "
                f"{exclusion['usable_pair_count']}/{experiment.REPEATS} paired "
                f"repeats usable — {reason_text}."
            )
    else:
        lines.append("- Excluded: none.")
    registered_reason = primary["endpoints"]["wall"].get(
        "reason", "not every task had two usable paired repeats"
    )
    lines += [
        "",
        "### Historical registration disclosure",
        "",
        "The stricter historically registered all-18 endpoint was unavailable "
        f"and **not estimable** because {registered_reason}. The complete-task "
        f"n={len(sensitivity['complete_task_ids'])} rule and the results above "
        "were not historically preregistered; they are a post-hoc complete-task "
        "analysis.",
        "",
        "## Execution context",
        "",
        f"Purpose: {data['purpose']}",
        "",
        f"- Correctness gate passes: {str(correctness['candidate_at_least_control']).lower()}",
        f"- Attempts / pairs / invocations: {manifest['actual_attempt_records']} / "
        f"{manifest['pair_record_count']} / {manifest['actual_subject_invocations']}",
        f"- Replacements / peak concurrency: {manifest['replacement_pair_count']} / "
        f"{manifest['observed_peak_active_subjects']}",
        "",
        "## Per-task outcomes",
        "",
        "Negative change means MD used less of the resource. Resource estimates "
        "are shown only for tasks with both usable paired repeats.",
        "",
        "| Task | MD pass | No-MD pass | Usable pairs | Wall MD / No-MD | "
        "Wall change | Token MD / No-MD | Token change |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in data["task_rows"]:
        wall, wall_change = _means(row["wall"], "s")
        token, token_change = _means(row["token"], "token")
        lines.append(
            f"| {row['task_id']} | {row['md_resolved']}/2 | "
            f"{row['no_md_resolved']}/2 | {row['usable_pairs']}/2 | {wall} | "
            f"{wall_change} | {token} | {token_change} |"
        )
    return "\n".join(lines) + "\n"


def write_report(batch: Path, output: Path, report_path: Path) -> dict[str, Any]:
    batch, output, report_path = batch.absolute(), output.absolute(), report_path.absolute()
    if report_path == output or output in report_path.parents:
        raise ReportError("report path must be outside immutable live evidence")
    verified = experiment.verify(experiment.ROOT, batch, output)
    request = experiment.atomic._read_canonical_json(batch / "REQUEST.json")
    manifest = experiment.atomic._read_canonical_json(output / "execution-manifest.json")
    primary = experiment.atomic._read_canonical_json(output / "analysis.json")
    attempts = experiment.atomic._read_canonical_jsonl(output / "attempts.jsonl")
    pairs = experiment.atomic._read_canonical_jsonl(output / "pairs.jsonl")
    rendered = render_markdown(build_report_data(request, manifest, primary, attempts, pairs))
    with report_path.open("xb") as stream:
        stream.write(rendered.encode("utf-8"))
    return {
        "report": str(report_path),
        "report_sha256": sha256(rendered.encode("utf-8")).hexdigest(),
        "verified": verified,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--batch-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--report-path", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = write_report(args.batch_dir, args.output_dir, args.report_path)
    except (
        ReportError, experiment.ExperimentError, experiment.atomic.EvidenceError,
        experiment.live.ShakeoutError, experiment.run_batch.BatchError,
        experiment.taskcheck.TaskError, OSError, ValueError, KeyError,
        json.JSONDecodeError,
    ) as exc:
        print(f"ERROR: {exc}")
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
