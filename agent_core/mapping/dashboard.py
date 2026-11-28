"""Deterministic JSON serializer for dashboard-compatible mapping output."""

from __future__ import annotations

from typing import Any

from shared.enums import MappingActionEligibility, MappingReasonCode

from agent_core.mapping.models import MappingOutcome


def serialize_mapping_dashboard(outcome: MappingOutcome) -> dict[str, Any]:
    """Serialize a ``MappingOutcome`` into a deterministic dashboard-ready payload."""
    res = outcome.mapping_result
    diag = outcome.diagnostics
    codes = set(diag.reason_codes)

    return {
        "mapping": {
            "finding_id": res.finding_id,
            "status": res.mapping_status.value,
            "canonical_route": diag.canonical_route,
            "matched_alias": diag.matched_alias,
            "component": res.matched_component,
            "implementation": diag.matched_implementation,
            "selected_flag": res.selected_flag,
            "candidate_flags": list(res.candidate_flags),
            "mapping_method": diag.mapping_method.value,
            "manual_review_required": res.manual_review_required,
            "registry_version": res.registry_version,
            "registry_fingerprint": diag.registry_fingerprint,
        },
        "validation": {
            "registry_valid": MappingReasonCode.INVALID_REGISTRY not in codes,
            "environment_consistent": MappingReasonCode.ENVIRONMENT_MISMATCH not in codes,
            "revision_consistent": (
                MappingReasonCode.REGISTRY_REVISION_MISMATCH not in codes
                and MappingReasonCode.EVIDENCE_REVISION_MISMATCH not in codes
            ),
            "semantic_match_valid": (
                res.selected_flag is not None
                and MappingReasonCode.ROUTE_COMPONENT_CONFLICT not in codes
            ),
        },
        "feature_observation": {
            "status": diag.observation_status.value,
            "enabled": diag.observed_feature_state,
            "state_version": diag.feature_state_version,
        },
        "operational_readiness": {
            "action_eligibility": diag.action_eligibility.value,
            "eligible_for_containment_planning": (
                diag.action_eligibility == MappingActionEligibility.ELIGIBLE
            ),
            "requires_verification": diag.requires_verification,
            "requires_human_approval_for_mutation": True,
        },
        "phase_05_context": {
            "affected_routes": list(diag.affected_routes),
            "shared_feature_dependencies": list(diag.shared_feature_dependencies),
            "potential_replacements": list(diag.potential_replacements),
            "fallback_behavior": diag.fallback_behavior,
        },
        "provenance": [p.value for p in diag.provenance],
        "is_fixture_only": diag.is_fixture_only,
        "missing_evidence": list(diag.missing_evidence),
        "limitations": list(diag.limitations),
        "reason_codes": [c.value for c in diag.reason_codes],
        "evaluation_timestamp": diag.evaluation_timestamp.isoformat(),
    }
