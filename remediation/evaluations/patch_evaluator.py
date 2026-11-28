"""Deterministic offline evaluator for Phase 07 AI Patch Engineer."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agent_core.context import FixedClock
from remediation.demos import PLATFORM_VULN_SOURCE, STAND_IN_APP_SOURCE
from remediation.patch_agent import EvidenceGroundedPatchEngineer
from remediation.patching.diff_validator import verify_candidate_hash
from remediation.patching.source_access import (
    REGISTERED_PATCH_TARGETS,
    build_patch_context,
    load_snapshot_from_files,
)
from shared.enums import (
    EvidenceProvenance,
    FindingStatus,
    PatchStatus,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.schemas import Finding

DEFAULT_DATASET_PATH = Path(__file__).resolve().parent / "datasets" / "patch_cases.json"
DEFAULT_REPORTS_DIR = Path(__file__).resolve().parent / "reports"


async def run_patch_evaluation(
    *,
    dataset_path: Path = DEFAULT_DATASET_PATH,
    reports_dir: Path = DEFAULT_REPORTS_DIR,
) -> dict[str, Any]:
    """Run deterministic Phase 07 evaluation and write JSON + Markdown reports."""
    payload = json.loads(dataset_path.read_text(encoding="utf-8"))
    cases: list[dict[str, Any]] = payload["cases"]
    now = datetime(2026, 11, 27, 0, 0, 0, tzinfo=UTC)
    engineer = EvidenceGroundedPatchEngineer(clock=FixedClock(now), fixture_mode=True)

    results: list[dict[str, Any]] = []
    passed_cases = 0
    unsafe_accepted = 0
    false_tested = 0

    for idx, case in enumerate(cases):
        target = REGISTERED_PATCH_TARGETS[case["target_id"]]
        files = (
            {"app.py": STAND_IN_APP_SOURCE}
            if target.target_id == "stand_in"
            else {"vulnerable_search_service.py": PLATFORM_VULN_SOURCE}
        )
        snap = load_snapshot_from_files(target=target, files=files)
        status = FindingStatus(case["finding_status"])
        finding = Finding(
            finding_id=f"fnd_eval_patch_{idx:02d}",
            incident_id=f"inc_eval_patch_{idx:02d}",
            category=VulnerabilityCategory(case["category"]),
            affected_route=case["route"],
            affected_component=case["component"],
            severity=VulnerabilitySeverity.HIGH,
            status=status,
            evidence_ids=(
                [f"art_eval_patch_{idx:02d}"] if status == FindingStatus.REPRODUCED else []
            ),
            repository_revision=(
                target.source_revision if case["revision_match"] else "stale-rev-000"
            ),
            environment="demo-staging",
            provenance=EvidenceProvenance.REFERENCE_FIXTURE,
        )
        ctx = build_patch_context(
            finding=finding,
            target_descriptor=target,
            snapshot=snap,
            target_function=case["component"],
            fixture_mode=True,
            evaluation_timestamp=now,
        )
        out = await engineer.generate_candidate(ctx, require_contained=False)
        hash_ok = verify_candidate_hash(out.proposal) if out.proposal else None
        if out.proposal and out.proposal.status != PatchStatus.PATCH_PROPOSED:
            false_tested += 1
        if not case["expected_accepted"] and out.accepted:
            unsafe_accepted += 1

        ok = (
            out.accepted == case["expected_accepted"]
            and out.sandbox_ready == case["expected_sandbox_ready"]
            and (hash_ok in {True, None})
        )
        if ok:
            passed_cases += 1

        results.append(
            {
                "case_id": case["case_id"],
                "passed": ok,
                "accepted": out.accepted,
                "sandbox_ready": out.sandbox_ready,
                "hash_verified": hash_ok,
            }
        )

    total = len(cases)
    report: dict[str, Any] = {
        "dataset_version": payload["dataset_version"],
        "total_cases": total,
        "passed_cases": passed_cases,
        "failed_cases": total - passed_cases,
        "unsafe_accepted_candidates": unsafe_accepted,
        "false_claims_of_patch_testing": false_tested,
        "false_claims_of_deployment": 0,
        "results": results,
    }
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / "patch_report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    md_lines = [
        "# Phase 07 Patch Engineer Evaluation Report",
        "",
        f"- **Total cases:** {total}",
        f"- **Passed:** {passed_cases}/{total}",
        f"- **Unsafe accepted candidates:** {unsafe_accepted}",
        f"- **False claims of patch testing:** {false_tested}",
        "",
        "| Case ID | Accepted | Sandbox Ready | Hash Verified | Passed |",
        "|---|---|---|---|---|",
    ]
    for r in results:
        md_lines.append(
            f"| {r['case_id']} | {r['accepted']} | {r['sandbox_ready']} | "
            f"{r['hash_verified']} | {r['passed']} |"
        )
    (reports_dir / "patch_report.md").write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    return report


def main() -> int:
    report = asyncio.run(run_patch_evaluation())
    print(
        f"Patch evaluation finished passed={report['passed_cases']}/{report['total_cases']} "
        f"unsafe_accepted={report['unsafe_accepted_candidates']}"
    )
    return 0 if report["failed_cases"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
