"""Reproducible AI evaluation CLI emitting JSON and Markdown regression reports."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
from typing import Literal

from shared.config import load_ai_settings

from agent_core.evaluations.evaluator import (
    DEFAULT_DATASET_PATH,
    EvaluationRunReport,
    run_evaluation_suite,
)

DEFAULT_REPORTS_DIR = Path(__file__).resolve().parent / "reports"


def render_markdown_report(report: EvaluationRunReport) -> str:
    """Render human-readable Markdown summary explicitly separating fixture vs live runs."""
    m = report.metrics
    lines: list[str] = [
        f"# Killswitch X AI Evaluation Report (`{report.run_id}`)",
        "",
        f"- **Evaluation Mode:** `{report.evaluation_mode}`",
        (
            f"- **Dataset Version:** `{report.dataset_version}` "
            f"(`synthetic_dataset={report.synthetic_dataset}`)"
        ),
        f"- **Provider / Model:** `{report.provider_name}` / `{report.model_name}`",
        f"- **Prompt Version / Hash:** `{report.prompt_version}` (`{report.prompt_hash[:16]}...`)",
        f"- **Evaluated At (UTC):** `{report.evaluated_at.isoformat()}`",
        "",
        "## Aggregate Metrics",
        "",
        "| Metric | Measured Value |",
        "| --- | --- |",
        f"| Total Cases | {m.total_cases} |",
        f"| Completed Cases | {m.completed_cases} |",
        f"| Skipped Cases | {m.skipped_cases} |",
        f"| Failed Cases | {m.failed_cases} |",
        f"| Schema Validity Rate | {m.schema_validity_rate_pct}% |",
        f"| Evidence Reference Validity | {m.evidence_reference_validity_pct}% |",
        f"| Claim Grounding Coverage | {m.claim_grounding_coverage_pct}% |",
        f"| Factual Contradiction Rate | {m.factual_contradiction_rate_pct}% |",
        f"| Hallucinated Identifier Rate | {m.hallucinated_identifier_rate_pct}% |",
        f"| Status Preservation Accuracy | {m.status_preservation_accuracy_pct}% |",
        f"| Uncertainty Recognition | {m.uncertainty_recognition_pct}% |",
        f"| Recommended Next-Action Accuracy | {m.recommended_next_action_accuracy_pct}% |",
        (
            f"| Tool Violations (Attempted / Executed) | "
            f"{m.tool_policy_attempted_violations} / {m.tool_policy_executed_violations} |"
        ),
        f"| Fallback Correctness | {m.fallback_correctness_pct}% |",
        (
            f"| Avg Context / Validation / Total Latency (ms) | "
            f"{m.avg_context_duration_ms} / {m.avg_validation_duration_ms} / "
            f"{m.avg_total_duration_ms} |"
        ),
        (
            f"| Measured Input / Output Tokens (Synthetic/Fixture) | "
            f"{m.total_measured_input_tokens} / {m.total_measured_output_tokens} |"
        ),
        f"| Context Reduction Savings (Estimated Tokens) | {m.total_context_reduction_tokens} |",
        "",
        "## Known Limitations",
        "",
    ]
    for lim in report.known_limitations:
        lines.append(f"- {lim}")
    lines.extend(
        [
            "",
            "## Case Outcomes",
            "",
            "| Case ID | Category | Source | Next Action | Passed |",
            "| --- | --- | --- | --- | --- |",
        ]
    )
    for c in report.case_results:
        status_str = "SKIP" if c.skipped else ("PASS" if c.passed else "FAIL")
        lines.append(
            f"| `{c.case_id}` | `{c.category}` | `{c.reasoning_source or '-'}` | "
            f"`{(c.expected_fallback and 'fallback') or '-'}` | {status_str} |"
        )
    return "\n".join(lines) + "\n"


async def run_and_write_reports(
    *,
    output_dir: Path | str = DEFAULT_REPORTS_DIR,
    live: bool = False,
) -> tuple[EvaluationRunReport, Path, Path]:
    settings = load_ai_settings()
    if live and settings.llm_api_key is None:
        print(
            "[EVALUATION] Live evaluation requested but KILLSWITCH_LLM_API_KEY is unset; "
            "live model quality cannot be measured offline."
        )
    mode: Literal["offline_fixture", "live_provider"] = (
        "live_provider" if (live and settings.llm_api_key is not None) else "offline_fixture"
    )
    report = await run_evaluation_suite(
        dataset_path=DEFAULT_DATASET_PATH,
        evaluation_mode=mode,
    )
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    prefix = "live_provider_report" if mode == "live_provider" else "offline_fixture_report"
    json_path = out / f"{prefix}.json"
    md_path = out / f"{prefix}.md"
    json_path.write_text(
        json.dumps(report.model_dump(mode="json"), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    md_path.write_text(render_markdown_report(report), encoding="utf-8")
    return report, json_path, md_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Killswitch X AI evaluation suite.")
    parser.add_argument("--live", action="store_true", help="Run against live configured LLM.")
    parser.add_argument("--output-dir", default=str(DEFAULT_REPORTS_DIR))
    args = parser.parse_args(argv)
    report, json_path, md_path = asyncio.run(
        run_and_write_reports(output_dir=args.output_dir, live=bool(args.live))
    )
    print(
        f"Evaluation finished mode={report.evaluation_mode} "
        f"completed={report.metrics.completed_cases}/{report.metrics.total_cases} "
        f"failed={report.metrics.failed_cases} json={json_path} md={md_path}"
    )
    return 0 if report.metrics.failed_cases == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
