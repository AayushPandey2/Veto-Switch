"""Dashboard JSON serialization and Markdown summary rendering for Phase 08."""

from __future__ import annotations

from typing import Any

from remediation.verification.models import PatchVerificationReport


def serialize_verification_dashboard(report: PatchVerificationReport) -> dict[str, Any]:
    """Serialize PatchVerificationReport into a dashboard-friendly JSON dict."""
    decision = report.decision
    result = report.patch_test_result
    return {
        "patch_id": report.patch_id,
        "incident_id": report.incident_id,
        "source_target": report.source_target,
        "candidate_tested": report.candidate_tested,
        "accepted": decision.accepted,
        "overall_status": decision.overall_status.value,
        "target_state_recommendation": decision.target_state_recommendation,
        "reason_codes": [code.value for code in decision.reason_codes],
        "isolation_valid": decision.isolation_valid,
        "evidence_valid": decision.evidence_valid,
        "evidence_provenance": decision.evidence_provenance.value,
        "test_plan": {
            "complete": decision.test_plan.complete,
            "required_test_ids": list(decision.test_plan.required_test_ids),
            "executed_test_ids": list(decision.test_plan.executed_test_ids),
            "missing_test_ids": list(decision.test_plan.missing_test_ids),
            "missing_categories": list(decision.test_plan.missing_categories),
        },
        "revisions": {
            "consistent": decision.revision_check.consistent,
            "base_source_revision": decision.revision_check.base_source_revision,
            "candidate_content_hash": decision.revision_check.candidate_content_hash,
            "expected_patched_revision": decision.revision_check.expected_patched_revision,
            "runner_computed_patched_revision": (
                decision.revision_check.runner_computed_patched_revision
            ),
            "runtime_observed_revision": decision.revision_check.runtime_observed_revision,
            "mismatches": list(decision.revision_check.mismatches),
        },
        "individual_outcomes": (
            [
                {
                    "test_name": o.test_name,
                    "category": o.category,
                    "status": o.status.value,
                    "duration_seconds": o.duration_seconds,
                    "message": o.message,
                }
                for o in result.individual_outcomes
            ]
            if result is not None
            else []
        ),
        "recovery_handoff": (
            decision.recovery_handoff.model_dump(mode="json")
            if decision.recovery_handoff is not None
            else None
        ),
        "failure_feedback": (
            decision.failure_feedback.model_dump(mode="json")
            if decision.failure_feedback is not None
            else None
        ),
        "artifact_ids": [a.artifact_id for a in report.artifacts],
        "limitations": list(decision.limitations),
        "generated_at": report.generated_at.isoformat(),
    }


def render_verification_markdown(report: PatchVerificationReport) -> str:
    """Render a concise Markdown verification summary suitable for operators and PRs."""
    d = report.decision
    lines = [
        f"# Isolated Patch Verification Summary: `{report.patch_id}`",
        "",
        f"- **Incident:** `{report.incident_id}`",
        f"- **Source Target:** `{report.source_target}`",
        f"- **Candidate Tested:** `{report.candidate_tested}`",
        f"- **Accepted:** `{d.accepted}`",
        f"- **Overall Status:** `{d.overall_status.value}`",
        f"- **Reason Codes:** {', '.join(f'`{c.value}`' for c in d.reason_codes)}",
        f"- **Isolation Valid:** `{d.isolation_valid}`",
        f"- **Evidence Valid:** `{d.evidence_valid}` (`{d.evidence_provenance.value}`)",
        "",
        "## Revision Identity",
        f"- Base Source Revision: `{d.revision_check.base_source_revision}`",
        f"- Candidate Hash: `{d.revision_check.candidate_content_hash}`",
        f"- Expected Patched Revision: `{d.revision_check.expected_patched_revision}`",
        f"- Runner Patched Revision: `{d.revision_check.runner_computed_patched_revision}`",
        f"- Runtime Observed Revision: `{d.revision_check.runtime_observed_revision}`",
        "",
        "## Test Plan Completeness",
        f"- Complete: `{d.test_plan.complete}`",
        f"- Required Tests: {', '.join(f'`{t}`' for t in d.test_plan.required_test_ids) or 'none'}",
        f"- Executed Tests: {', '.join(f'`{t}`' for t in d.test_plan.executed_test_ids) or 'none'}",
    ]
    if d.test_plan.missing_test_ids:
        lines.append(
            "- Missing Tests: " + ", ".join(f"`{t}`" for t in d.test_plan.missing_test_ids)
        )
    if d.recovery_handoff is not None:
        lines.extend(
            [
                "",
                "## Phase 09 Recovery Handoff",
                f"- `candidate_tested`: `{d.recovery_handoff.candidate_tested}`",
                "- `ready_for_deployment_verification`: "
                f"`{d.recovery_handoff.ready_for_deployment_verification}`",
                f"- `deployment_verified`: `{d.recovery_handoff.deployment_verified}`",
                f"- `rollout_authorized`: `{d.recovery_handoff.rollout_authorized}`",
            ]
        )
    if d.limitations:
        lines.extend(["", "## Limitations"])
        lines.extend(f"- {lim}" for lim in d.limitations)
    return "\n".join(lines) + "\n"
