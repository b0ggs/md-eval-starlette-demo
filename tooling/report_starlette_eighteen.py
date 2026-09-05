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
            if row["arm"] in resolved[pair["task_id"]] and row["resolved"] is True:
                resolved[pair["task_id"]][row["arm"]] += 1
        usable = (
            pair["status"] == "complete"
            and len(rows) == 2
            and {row["arm"] for row in rows} == {"candidate", "control"}
            and all(
                row["normal_terminal_record"] is True
                and row["valid"] is True
                and row["resolved"] is True
                for row in rows
            )
        )
        if usable:
            selected[pair["task_id"]].append({**pair, "attempts": rows})
    for rows in selected.values():
        rows.sort(key=lambda row: row["repeat_id"])
    failures = [
        row for row in attempts
        if row["resolved"] is not True
        or row["normal_terminal_record"] is not True
        or row["valid"] is not True
        or row.get("subject_timeout") is True
        or row.get("infrastructure_failure") is True
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
                "status": "inconclusive",
                "reason": f"missing or invalid {name} telemetry for {task}",
            }
        task_results.append({"task_id": task, **result})
    if len(task_results) < 2:
        return {
            "name": name,
            "status": "inconclusive",
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
        if len(selected[task]) == experiment.REPEATS
    ]
    task_rows = []
    for task in experiment.TASK_IDS:
        task_rows.append({
            "task_id": task,
            "md_resolved": resolved[task]["candidate"],
            "no_md_resolved": resolved[task]["control"],
            "usable_pairs": len(selected[task]),
            "wall": _task_endpoint(
                selected[task], lambda row: row.get("subject_wall_seconds"),
            ),
            "token": _task_endpoint(
                selected[task],
                lambda row: row.get("uncached_input_plus_output_token_proxy"),
            ),
        })
    sensitivity = {
        "label": "post-hoc exploratory complete-case sensitivity",
        "complete_task_ids": complete_tasks,
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
    lines = [
        "# Starlette 18-task MD/no-MD outcome report",
        "",
        f"Purpose: {data['purpose']}",
        "",
        "## Correctness and execution",
        "",
        f"- MD resolved: {correctness['resolved_attempts']['candidate']}/36",
        f"- No MD resolved: {correctness['resolved_attempts']['control']}/36",
        f"- Correctness gate passes: {str(correctness['candidate_at_least_control']).lower()}",
        f"- Attempts / pairs / invocations: {manifest['actual_attempt_records']} / "
        f"{manifest['pair_record_count']} / {manifest['actual_subject_invocations']}",
        f"- Replacements / peak concurrency: {manifest['replacement_pair_count']} / "
        f"{manifest['observed_peak_active_subjects']}",
        "",
        "## Per-task outcomes",
        "",
        "Negative change means MD used less of the resource.",
        "",
        "| Task | MD | No MD | Usable pairs | Wall MD / No MD | Wall change | "
        "Token MD / No MD | Token change |",
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
    lines += [
        "",
        "Resource means for tasks with fewer than two usable pairs are descriptive only.",
        "",
        "## Failures and timeouts",
        "",
    ]
    if data["failures"]:
        lines += [
            "| Attempt | Task | Arm | Reason | Termination |",
            "|---|---|---|---|---|",
        ]
        for row in data["failures"]:
            arm = "MD" if row["arm"] == "candidate" else "No MD"
            lines.append(
                f"| {row['attempt_id']} | {row['task_id']} | {arm} | "
                f"{row['mechanical_reason_code']} | {row['termination_class']} |"
            )
    else:
        lines.append("None.")
    lines += ["", "## Registered primary analysis", ""]
    for name in ("wall", "token"):
        endpoint = primary["endpoints"][name]
        if endpoint["status"] == "inconclusive":
            lines.append(f"- {name.title()}: **inconclusive** — {endpoint['reason']}")
        else:
            lines.append(
                f"- {name.title()}: {endpoint['reduction_percent']:.4f}% reduction; "
                f"p={endpoint['p_value_two_sided']:.8g}"
            )
    lines += [
        "",
        "## Post-hoc exploratory complete-case sensitivity",
        "",
        "This does not replace the registered primary analysis.",
        "",
        "| Endpoint | Tasks | Reduction | 95% reduction CI | t (df) | Two-sided p | Result |",
        "|---|---:|---:|---:|---:|---:|---|",
    ]
    for name in ("wall", "token"):
        endpoint = data["sensitivity"][name]
        if endpoint["status"] != "conclusive":
            lines.append(
                f"| {name.title()} | — | — | — | — | — | "
                f"Inconclusive: {endpoint['reason']} |"
            )
            continue
        ratio_ci = endpoint["confidence_interval_95_ratio"]
        reduction_ci = (
            100.0 * (1.0 - ratio_ci[1]),
            100.0 * (1.0 - ratio_ci[0]),
        )
        result = "Significant" if endpoint["favorable_reduction"] else "Not favorable"
        t_value = endpoint["t_statistic"]
        t_text = (
            f"{t_value:.6f}" if t_value is not None else
            "-infinity" if endpoint["mean_task_log_ratio"] < 0 else "+infinity"
        )
        lines.append(
            f"| {name.title()} | {endpoint['task_count']} | "
            f"{endpoint['reduction_percent']:.4f}% | "
            f"{reduction_ci[0]:.4f}%–{reduction_ci[1]:.4f}% | "
            f"{t_text} ({endpoint['degrees_of_freedom']}) | "
            f"{endpoint['p_value_two_sided']:.8g} | {result} |"
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
