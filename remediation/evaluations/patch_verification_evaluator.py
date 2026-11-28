"""Deterministic evaluator for Phase 08 isolated patch verification."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from remediation.adapters.fixture_runner import FixturePatchTestRunner
from remediation.patch_tests import IsolatedPatchVerificationOrchestrator
from remediation.verification_demos import _base_context

DATASET_PATH = Path(__file__).parent / "datasets" / "patch_verification_cases.json"
REPORT_JSON_PATH = Path(__file__).parent / "patch_verification_report.json"
REPORT_MD_PATH = Path(__file__).parent / "patch_verification_report.md"


async def evaluate_patch_verification_cases(
    dataset_path: Path = DATASET_PATH,
) -> dict[str, Any]:
    """Run all deterministic Phase 08 evaluation cases and enforce 0 unsafe false passes."""
    raw = json.loads(dataset_path.read_text(encoding="utf-8"))
    cases: list[dict[str, Any]] = raw["cases"]

    results: list[dict[str, Any]] = []
    passed = 0
    unsafe_false_pass_count = 0

    for case in cases:
        ctx = _base_context(
            source_target=case["source_target"],
            missing_smoke=case["missing_smoke"],
            override_hash="e" * 64 if case["tamper_hash"] else None,
        )
        orch = IsolatedPatchVerificationOrchestrator(
            runner=FixturePatchTestRunner(
                scenario=case["scenario"],
                source_target=case["source_target"],
            )
        )
        report = await orch.verify_candidate(ctx)
        actual_accepted = report.decision.accepted
        actual_status = report.decision.overall_status.value
        actual_reasons = [c.value for c in report.decision.reason_codes]

        if actual_accepted and not case["expected_accepted"]:
            unsafe_false_pass_count += 1

        ok = (
            actual_accepted == case["expected_accepted"]
            and actual_status == case["expected_status"]
            and case["expected_reason"] in actual_reasons
        )
        if ok:
            passed += 1

        results.append(
            {
                "case_id": case["case_id"],
                "passed": ok,
                "expected_accepted": case["expected_accepted"],
                "actual_accepted": actual_accepted,
                "expected_status": case["expected_status"],
                "actual_status": actual_status,
                "expected_reason": case["expected_reason"],
                "actual_reasons": actual_reasons,
            }
        )

    return {
        "total_cases": len(cases),
        "passed_cases": passed,
        "unsafe_false_pass_count": unsafe_false_pass_count,
        "all_passed": passed == len(cases) and unsafe_false_pass_count == 0,
        "cases": results,
    }


def write_evaluation_reports(summary: dict[str, Any]) -> None:
    """Persist JSON and Markdown evaluation reports."""
    REPORT_JSON_PATH.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# Phase 08 Isolated Patch Verification Evaluation Report",
        "",
        f"- **Total Cases:** {summary['total_cases']}",
        f"- **Passed Cases:** {summary['passed_cases']}",
        f"- **Unsafe False Passes:** {summary['unsafe_false_pass_count']}",
        f"- **All Passed:** {summary['all_passed']}",
        "",
        "| Case ID | Passed | Expected Accepted | Actual Accepted | Status | Reasons |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in summary["cases"]:
        lines.append(
            f"| `{item['case_id']}` | `{item['passed']}` | "
            f"`{item['expected_accepted']}` | `{item['actual_accepted']}` | "
            f"`{item['actual_status']}` | `{', '.join(item['actual_reasons'])}` |"
        )
    REPORT_MD_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> None:
    summary = asyncio.run(evaluate_patch_verification_cases())
    write_evaluation_reports(summary)
    print(
        f"Phase 08 evaluation: {summary['passed_cases']}/{summary['total_cases']} passed, "
        f"unsafe_false_pass_count={summary['unsafe_false_pass_count']}"
    )
    if not summary["all_passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
