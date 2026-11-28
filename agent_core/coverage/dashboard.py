"""Deterministic dashboard and GET /flags/coverage-compatible serializers."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from shared.schemas import FeatureState

from agent_core.coverage.models import CoverageAuditResult


def serialize_coverage_dashboard(result: CoverageAuditResult) -> dict[str, Any]:
    """Serialize a ``CoverageAuditResult`` into the Section 25 dashboard JSON structure."""
    routes_payload: list[dict[str, Any]] = []
    for item in result.route_assessments:
        src_loc = (
            f"{item.source_ref.relative_path}:{item.source_ref.start_line}-{item.source_ref.end_line}"
            if item.source_ref
            else None
        )
        routes_payload.append(
            {
                "application_id": item.route_identity.application_id,
                "method": item.route_identity.method,
                "route": item.route_identity.route,
                "handler_name": item.route_identity.handler_name,
                "implementation_id": item.route_identity.implementation_id,
                "applicability": item.applicability.value,
                "coverage_status": item.status.value,
                "expected_flags": list(item.expected_flags),
                "observed_flags": list(item.observed_flags),
                "reason_codes": [r.value for r in item.reason_codes],
                "source_location": src_loc,
            }
        )

    return {
        "audit_id": result.audit_id,
        "application_id": result.application_id,
        "environment": result.environment,
        "source_revision": result.source_revision,
        "revision_namespace": result.revision_namespace,
        "source_tree_fingerprint": result.source_tree_fingerprint,
        "registry_version": result.registry_version,
        "registry_fingerprint": result.registry_fingerprint,
        "policy_version": result.policy_version,
        "analysis_scope": "bounded_flask_static_analysis",
        "evidence_support": result.evidence_support.value,
        "is_fixture": result.is_fixture,
        "summary": result.summary.model_dump(mode="json"),
        "routes": routes_payload,
        "discrepancies": [d.model_dump(mode="json") for d in result.discrepancies],
        "recommendations": [r.model_dump(mode="json") for r in result.recommendations],
        "limitations": list(result.limitations),
    }


def serialize_flags_coverage_endpoint(
    result: CoverageAuditResult,
    *,
    observed_features: Sequence[FeatureState] = (),
) -> dict[str, Any]:
    """Produce a ``GET /flags/coverage``-compatible payload preserving legacy fields.

    Preserves ``covered``, ``missing``, and ``status`` (flag availability) while adding
    distinct ``coverage_status``, ``applicability``, ``flag_availability``, ``source_location``,
    ``alternate_execution_paths``, ``evidence_ids``, ``evidence_support``, ``reason_codes``,
    ``recommended_action``, and ``analysis_limitations``.
    """
    available_flags = {f.feature_name for f in observed_features}
    finding_by_route = {f.route: f for f in result.findings}
    route_entries: list[dict[str, Any]] = []
    any_missing_flags = False

    for assessment in result.route_assessments:
        route = assessment.route_identity.route
        assoc_flags = sorted(set(assessment.expected_flags) | set(assessment.observed_flags))
        missing_flags = [fl for fl in assoc_flags if available_flags and fl not in available_flags]
        if missing_flags:
            any_missing_flags = True
        finding = finding_by_route.get(route)
        src_loc = (
            f"{assessment.source_ref.relative_path}:{assessment.source_ref.start_line}-{assessment.source_ref.end_line}"
            if assessment.source_ref
            else None
        )
        route_entries.append(
            {
                "route": route,
                "method": assessment.route_identity.method,
                "flags": assoc_flags,
                "missing": missing_flags,
                "covered": not missing_flags,
                "flag_availability": "available" if not missing_flags else "missing",
                "applicability": assessment.applicability.value,
                "coverage_status": assessment.status.value,
                "associated_flags": assoc_flags,
                "source_location": src_loc,
                "alternate_execution_paths": (
                    list(finding.alternate_execution_paths) if finding else []
                ),
                "evidence_ids": list(finding.evidence_ids) if finding else [],
                "evidence_support": result.evidence_support.value,
                "reason_codes": [r.value for r in assessment.reason_codes],
                "recommended_action": (
                    finding.recommended_action
                    if finding
                    else "Intentional exemption; no flag guard required."
                ),
                "analysis_limitations": (
                    list(finding.analysis_limitations)
                    if finding
                    else list(result.limitations)
                ),
            }
        )

    return {
        "status": "incomplete" if any_missing_flags else "complete",
        "application_id": result.application_id,
        "source_revision": result.source_revision,
        "source_tree_fingerprint": result.source_tree_fingerprint,
        "registry_fingerprint": result.registry_fingerprint,
        "summary": result.summary.model_dump(mode="json"),
        "routes": route_entries,
        "limitations": list(result.limitations),
    }
