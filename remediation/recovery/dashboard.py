"""Dashboard-compatible rollback serializer and Phase 11 evidence-reporting handoff."""

from __future__ import annotations

from typing import Any

from shared.enums import IncidentState
from shared.schemas import (
    ApprovalDecision,
    OperationReceipt,
    VerifiedSafeState,
)

from remediation.recovery.models import (
    Phase11RollbackHandoff,
    PostRollbackVerificationResult,
    ReadbackReconciliationResult,
    RollbackAnalysisResult,
    RollbackContext,
    RollbackReceiptValidationResult,
)


def serialize_rollback_dashboard(
    *,
    ctx: RollbackContext,
    analysis: RollbackAnalysisResult,
    approval: ApprovalDecision | None = None,
    receipt_result: RollbackReceiptValidationResult | None = None,
    readback_result: ReadbackReconciliationResult | None = None,
    verification_result: PostRollbackVerificationResult | None = None,
    final_incident_state: IncidentState = IncidentState.ROLLBACK_PROPOSED,
) -> dict[str, Any]:
    """Produce a stable, deterministic JSON-serializable dashboard payload."""
    cp = analysis.safe_state_resolution.selected_checkpoint
    last_safe_exposure = (
        cp.configured_exposure_percentage if isinstance(cp, VerifiedSafeState) else None
    )
    proposal = analysis.proposal
    selected = analysis.selected_strategy

    return {
        "incident_id": ctx.incident_id,
        "plan_id": ctx.plan_id,
        "target_feature": ctx.target_feature,
        "rollback_proposal_id": proposal.proposal_id if proposal else None,
        "proposal_hash": proposal.proposal_hash if proposal else None,
        "trigger": {
            "category": (
                analysis.trigger_validation.trigger_category.value
                if analysis.trigger_validation.trigger_category
                else None
            ),
            "valid": analysis.trigger_validation.valid,
            "is_security_regression": analysis.trigger_validation.is_security_regression,
            "rationale": analysis.trigger_validation.rationale,
        },
        "failed_guardrails": list(analysis.trigger_validation.failed_guardrails),
        "current_observed_exposure": ctx.current_observed_exposure,
        "last_verified_safe_exposure": last_safe_exposure,
        "safe_state_status": "known" if analysis.safe_state_resolution.known else "unknown",
        "candidate_strategies": [c.model_dump(mode="json") for c in analysis.candidate_strategies],
        "selected_strategy": selected.model_dump(mode="json") if selected else None,
        "proposed_target_configuration": (
            proposal.proposed_targeting_configuration
            if proposal and proposal.proposed_targeting_configuration is not None
            else ({"enabled": proposal.proposed_state} if proposal else None)
        ),
        "expected_operational_effect": (
            selected.expected_operational_effect if selected else None
        ),
        "predicted_security_effect": selected.expected_security_effect if selected else None,
        "approval_status": approval.decision.value if approval else "pending",
        "execution_status": receipt_result.status if receipt_result else "not_executed",
        "readback_status": (
            "matched"
            if (readback_result and readback_result.matched)
            else ("mismatch" if readback_result else "not_run")
        ),
        "post_rollback_verification": (
            verification_result.outcome.value if verification_result else "not_run"
        ),
        "actual_observed_configuration": (
            {
                "enabled": (
                    ctx.current_observed_feature_state.enabled
                    if ctx.current_observed_feature_state
                    else None
                ),
                "exposure": (
                    readback_result.observed_exposure
                    if readback_result
                    else ctx.current_observed_exposure
                ),
            }
        ),
        "final_incident_state": final_incident_state.value,
        "reason_codes": [r.value for r in analysis.reason_codes],
        "evidence_ids": list(analysis.trigger_validation.triggering_evidence_ids),
        "limitations": list(analysis.limitations),
        "explanation_summary": analysis.explanation_summary,
    }


def build_phase11_rollback_handoff(
    *,
    ctx: RollbackContext,
    analysis: RollbackAnalysisResult,
    history: list[VerifiedSafeState],
    approval: ApprovalDecision | None = None,
    receipt: OperationReceipt | None = None,
    readback: ReadbackReconciliationResult | None = None,
    verification: PostRollbackVerificationResult | None = None,
    final_incident_state: IncidentState = IncidentState.ROLLBACK_PROPOSED,
    artifact_hashes: dict[str, str] | None = None,
) -> Phase11RollbackHandoff:
    """Build deterministic Phase 11 Incident Evidence Reporting handoff."""
    proposal = analysis.proposal
    evidence_ids = list(analysis.trigger_validation.triggering_evidence_ids)
    if verification:
        evidence_ids.extend(verification.evidence_ids)
    if receipt:
        evidence_ids.extend(receipt.evidence_ids)

    return Phase11RollbackHandoff(
        incident_id=ctx.incident_id,
        rollout_plan_id=ctx.plan_id,
        active_candidate_identity=ctx.active_candidate_identity,
        deployment_identity=ctx.deployment_identity
        or (ctx.deployment_evidence.source_revision if ctx.deployment_evidence else None),
        stage_history=list(ctx.verified_stage_history),
        verified_safe_state_history=[cp.model_dump(mode="json") for cp in history],
        triggering_decision=(
            ctx.rollout_decision.model_dump(mode="json") if ctx.rollout_decision else None
        ),
        triggering_metrics=(
            ctx.triggering_telemetry.model_dump(mode="json") if ctx.triggering_telemetry else None
        ),
        failed_guardrails=list(analysis.trigger_validation.failed_guardrails),
        considered_rollback_strategies=[
            c.model_dump(mode="json") for c in analysis.candidate_strategies
        ],
        selected_rollback_proposal=proposal.model_dump(mode="json") if proposal else None,
        proposal_hash=proposal.proposal_hash if proposal else None,
        approval_decision=approval,
        operation_receipt=receipt,
        configuration_before={
            "enabled": (
                ctx.current_observed_feature_state.enabled
                if ctx.current_observed_feature_state
                else None
            ),
            "exposure": ctx.current_observed_exposure,
            "targeting_version": ctx.current_targeting_version,
        },
        requested_configuration=(
            proposal.proposed_targeting_configuration
            if proposal and proposal.proposed_targeting_configuration is not None
            else ({"enabled": proposal.proposed_state} if proposal else {})
        ),
        observed_configuration_after={
            "readback_matched": readback.matched if readback else False,
            "observed_exposure": readback.observed_exposure if readback else None,
        },
        post_rollback_security_results=(
            [ctx.security_regression_result.model_dump(mode="json")]
            if ctx.security_regression_result
            else []
        ),
        post_rollback_functional_results=[],
        final_rollback_status=(
            verification.outcome.value if verification else "rollback_proposed"
        ),
        final_incident_state=final_incident_state,
        evidence_ids=list(dict.fromkeys(evidence_ids)),
        artifact_hashes=dict(artifact_hashes or {}),
        policy_versions={"rollback_policy": ctx.policy_version},
        limitations=list(analysis.limitations),
    )
