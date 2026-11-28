"""Deterministic review-only engineering recommendations for coverage gaps."""

from __future__ import annotations

from shared.enums import CoverageApplicability, CoverageStatus
from shared.serialization import sha256_text

from agent_core.coverage.models import CoverageRecommendation, ExecutionPathAssessment


def generate_coverage_recommendations(
    assessments: list[ExecutionPathAssessment],
) -> list[CoverageRecommendation]:
    """Generate review-only recommendations for unprotected or partially protected routes.

    Never auto-applies diffs and never guesses patches for ``unknown`` coverage.
    """
    recommendations: list[CoverageRecommendation] = []
    for item in assessments:
        if item.applicability == CoverageApplicability.EXEMPT:
            continue
        if item.status not in {CoverageStatus.UNPROTECTED, CoverageStatus.PARTIALLY_PROTECTED}:
            continue

        expected_ctrl = (
            ", ".join(item.expected_flags)
            if item.expected_flags
            else "explicit_containment_flag"
        )
        src_loc = (
            f"{item.source_ref.relative_path}:{item.source_ref.start_line}-{item.source_ref.end_line}"
            if item.source_ref
            else None
        )
        rec_id = "crec_" + sha256_text(
            f"{item.route_identity.method}:{item.route_identity.route}:{item.status.value}"
        )[:16]
        recommendations.append(
            CoverageRecommendation(
                recommendation_id=rec_id,
                route=item.route_identity.route,
                method=item.route_identity.method,
                component=item.sensitive_implementation or "application_handler",
                implementation_id=item.route_identity.implementation_id,
                expected_control=expected_ctrl,
                current_problem="; ".join(item.notes) or f"Coverage gap: {item.status.value}",
                source_location=src_loc,
                proposed_change=(
                    f"Ensure {item.route_identity.handler_name} enforces a dominating guard on "
                    f"{expected_ctrl} with fail-closed fallback before invoking "
                    f"{item.sensitive_implementation or 'sensitive operation'}."
                ),
                review_only=True,
                required_tests=[
                    f"test_{item.route_identity.handler_name}_blocked_when_flag_disabled",
                    f"test_{item.route_identity.handler_name}_safe_fallback_contract",
                ],
                assumptions=[
                    "Manual engineering review and registered security verification required."
                ],
                limitations=["Review-only recommendation; never auto-merged or auto-applied."],
            )
        )
    return recommendations
