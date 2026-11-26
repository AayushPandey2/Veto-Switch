"""Dashboard-compatible JSON serializer for ContainmentAnalysisResult."""

from __future__ import annotations

from typing import Any

from shared.schemas import DependencyGraph

from agent_core.containment.models import ContainmentAnalysisResult
from agent_core.graph_intelligence.serializer import serialize_blast_radius_dashboard


def serialize_containment_dashboard(
    analysis: ContainmentAnalysisResult,
    graph: DependencyGraph,
) -> dict[str, Any]:
    """Serialize blast radius, strategy comparison, and proposal into dashboard JSON."""
    rec = analysis.recommended_option
    return {
        "incident_id": analysis.incident_id,
        "finding_id": analysis.finding_id,
        "policy_version": analysis.policy_version,
        "is_fixture_only": analysis.is_fixture_only,
        "blast_radius": serialize_blast_radius_dashboard(analysis.blast_radius, graph),
        "recommended_strategy": (
            {
                "option_id": rec.option_id,
                "type": rec.strategy_type.value,
                "target": rec.proposed_target,
                "desired_enabled": (
                    analysis.proposal.desired_enabled if analysis.proposal else None
                ),
                "requires_human_approval": True,
                "relative_policy_score": rec.relative_policy_score,
            }
            if rec is not None
            else None
        ),
        "strategy_comparison": [
            {
                "option_id": s.option.option_id,
                "strategy_type": s.option.strategy_type.value,
                "title": s.option.title,
                "feasibility_status": s.action_eligibility,
                "execution_supported": s.execution_supported,
                "prerequisites": list(s.option.prerequisites),
                "estimated_disruption": s.option.estimated_disruption,
                "estimated_residual_risk": s.option.estimated_residual_risk,
                "dependency_reach": s.option.dependency_reach,
                "uncertainty": s.option.uncertainty,
                "relative_policy_score": s.option.relative_policy_score,
                "affected_nodes": list(s.option.affected_nodes),
                "preserved_nodes": list(s.option.protected_nodes),
                "reason_codes": [c.value for c in s.reason_codes],
                "evidence_ids": list(s.option.evidence_ids),
                "limitations": list(s.option.limitations),
            }
            for s in analysis.evaluated_strategies
        ],
        "sensitivity": analysis.sensitivity.model_dump(mode="json"),
        "proposal_id": analysis.proposal.proposal_id if analysis.proposal else None,
        "proposal_hash": analysis.proposal.proposal_hash if analysis.proposal else None,
        "manual_review_required": analysis.manual_review_required,
        "verification_checklist": list(analysis.verification_checklist),
        "verification_required": True,
        "containment_verified": False,
        "reason_codes": [c.value for c in analysis.reason_codes],
        "limitations": list(analysis.limitations),
    }
