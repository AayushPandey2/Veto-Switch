"""Offline evaluation harness for Phase 06 Feature Flag Coverage Auditing."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from shared.enums import CoverageStatus

from agent_core.context import FixedClock
from agent_core.coverage.models import CoverageAuditContext
from agent_core.coverage.source_snapshot import build_in_memory_snapshot
from agent_core.flag_auditor import DeterministicFlagCoverageAuditor

DATASET_PATH = Path(__file__).parent / "datasets" / "coverage_cases.json"
REPORT_JSON_PATH = Path(__file__).parent / "reports" / "coverage_report.json"


async def evaluate_coverage_dataset(dataset_path: Path = DATASET_PATH) -> dict[str, Any]:
    """Run deterministic evaluation over labeled synthetic coverage cases."""
    raw = json.loads(dataset_path.read_text(encoding="utf-8"))
    cases = raw["cases"]
    auditor = DeterministicFlagCoverageAuditor(
        clock=FixedClock(datetime(2026, 11, 28, 12, 0, 0, tzinfo=UTC))
    )

    passed = 0
    false_protected = 0
    route_hits = 0
    bypass_tp = 0
    bypass_fp = 0
    bypass_fn = 0
    details: list[dict[str, Any]] = []

    for case in cases:
        snap = build_in_memory_snapshot(
            application_id="platform_demo_app",
            environment="demo-staging",
            source_revision="eval-rev-0001",
            files={"app.py": case["source"]},
            is_complete=case.get("is_complete", True),
        )
        ctx = CoverageAuditContext(
            application_id="platform_demo_app",
            environment="demo-staging",
            snapshot=snap,
            is_fixture=True,
        )
        res = await auditor.audit(ctx)
        # Deterministic repeatability check
        res2 = await auditor.audit(ctx)
        if res.audit_id != res2.audit_id:
            raise RuntimeError(
                f"Non-deterministic audit_id for {case['case_id']}: "
                f"{res.audit_id} != {res2.audit_id}"
            )

        matching = [
            a
            for a in res.route_assessments
            if a.route_identity.route == case["expected_route"]
            and a.route_identity.method == case["expected_method"]
        ]
        if matching:
            route_hits += 1
        actual = matching[0] if matching else None
        actual_status = actual.status.value if actual else "missing"
        actual_app = actual.applicability.value if actual else "missing"

        has_bypass = any(bool(impl.alternate_entrypoints) for impl in res.sensitive_implementations)
        if case["expect_bypass"] and has_bypass:
            bypass_tp += 1
        elif case["expect_bypass"] and not has_bypass:
            bypass_fn += 1
        elif not case["expect_bypass"] and has_bypass:
            bypass_fp += 1

        if (
            actual_status == CoverageStatus.PROTECTED.value
            and case["expected_status"] != "protected"
        ):
            false_protected += 1

        ok = (
            actual_status == case["expected_status"]
            and actual_app == case["expected_applicability"]
            and has_bypass == case["expect_bypass"]
        )
        if ok:
            passed += 1
        details.append(
            {
                "case_id": case["case_id"],
                "passed": ok,
                "expected_status": case["expected_status"],
                "actual_status": actual_status,
                "expected_applicability": case["expected_applicability"],
                "actual_applicability": actual_app,
            }
        )

    total = len(cases)
    bypass_prec = bypass_tp / (bypass_tp + bypass_fp) if (bypass_tp + bypass_fp) > 0 else 1.0
    bypass_rec = bypass_tp / (bypass_tp + bypass_fn) if (bypass_tp + bypass_fn) > 0 else 1.0
    report: dict[str, Any] = {
        "phase": "Phase 06 Feature Flag Coverage Auditing (Synthetic Offline Evaluation)",
        "dataset_version": raw["dataset_version"],
        "total_cases": total,
        "passed_cases": passed,
        "accuracy": round(passed / total, 4) if total else 0.0,
        "route_discovery_recall": round(route_hits / total, 4) if total else 0.0,
        "bypass_precision": round(bypass_prec, 4),
        "bypass_recall": round(bypass_rec, 4),
        "false_protected_count": false_protected,
        "caveat": (
            "Synthetic offline evaluation; does not constitute live production security proof."
        ),
        "cases": details,
    }
    REPORT_JSON_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_JSON_PATH.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> None:
    report = asyncio.run(evaluate_coverage_dataset())
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
