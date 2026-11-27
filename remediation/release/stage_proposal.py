"""Immutable stage-specific action proposals and exact-action approval binding."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from agent_core.context import GuardResult, ProducerContext
from shared.enums import ActorType, ApprovalStatus
from shared.identifiers import ensure_utc, generate_prefixed_id, utc_now
from shared.schemas import ApprovalDecision, RolloutPlan, RolloutStage
from shared.serialization import sha256_canonical

from remediation.release.models import StageActionProposal


def build_stage_action_proposal(
    *,
    plan: RolloutPlan,
    stage: RolloutStage,
    previous_stage_id: str | None = None,
    expected_current_exposure: int = 0,
    expected_targeting_version: str | None = None,
    deployment_evidence_identity: str = "dep_unverified",
    candidate_identity: str | None = None,
    verification_evidence: list[str] | None = None,
    decision_identity: str | None = None,
    provider_feature_id: str | None = None,
    created_at: datetime | None = None,
    ttl_seconds: int = 900,
) -> StageActionProposal:
    """Create an immutable, canonically hashed StageActionProposal."""
    now = ensure_utc(created_at) if created_at is not None else utc_now()
    proposal_id = generate_prefixed_id("proposal")
    targeting_cfg: dict[str, Any] = {
        "feature_name": plan.target_feature,
        "exposure_percentage": stage.exposure_percentage,
        "cohort_strategy": stage.segment_configuration.get(
            "cohort_strategy", "deterministic_sha256_bucket"
        ),
        "stage_id": stage.stage_id,
    }
    idem_token = sha256_canonical(
        {
            "incident_id": plan.incident_id,
            "plan_id": plan.plan_id,
            "stage_id": stage.stage_id,
            "requested_exposure": stage.exposure_percentage,
            "deployment_evidence_identity": deployment_evidence_identity,
        }
    )[:32]

    return StageActionProposal(
        proposal_id=proposal_id,
        incident_id=plan.incident_id,
        plan_id=plan.plan_id,
        stage_id=stage.stage_id,
        previous_stage_id=previous_stage_id,
        target_environment=plan.environment,
        target_feature=plan.target_feature,
        provider_feature_id=provider_feature_id,
        target_implementation_revision=plan.target_implementation_revision,
        expected_current_exposure=expected_current_exposure,
        requested_exposure=stage.exposure_percentage,
        expected_targeting_version=expected_targeting_version,
        exact_requested_targeting_configuration=targeting_cfg,
        deployment_evidence_identity=deployment_evidence_identity,
        candidate_identity=candidate_identity,
        verification_evidence=list(verification_evidence or []),
        decision_identity=decision_identity,
        policy_version=plan.policy_version,
        created_at=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
        idempotency_token=idem_token,
        approval_required=True,
        execution_authorized=False,
    )


def validate_stage_proposal_approval(
    *,
    proposal: StageActionProposal,
    approval: ApprovalDecision | None,
    producer: ProducerContext,
    consumed_approval_ids: set[str] | None = None,
    reference_time: datetime | None = None,
) -> GuardResult:
    """Bind fresh human approval to exact StageActionProposal identity and hash."""
    now = ensure_utc(reference_time) if reference_time is not None else utc_now()
    if not producer.authenticated or producer.actor_type != ActorType.HUMAN_OPERATOR:
        return GuardResult(
            allowed=False,
            guard="approval_validity",
            reason_code="UNAUTHENTICATED_OR_NON_HUMAN_APPROVER",
            message="Stage approval requires authenticated HUMAN_OPERATOR.",
            missing_requirements=["authenticated_human_operator"],
        )
    if approval is None:
        return GuardResult(
            allowed=False,
            guard="approval_validity",
            reason_code="MISSING_STAGE_APPROVAL",
            message="Fresh ApprovalDecision is required for rollout stage.",
            missing_requirements=["stage_approval_decision"],
        )
    if approval.incident_id != proposal.incident_id:
        return GuardResult(
            allowed=False,
            guard="approval_validity",
            reason_code="APPROVAL_INCIDENT_MISMATCH",
            message="Approval incident_id does not match StageActionProposal.",
            missing_requirements=["matching_incident_approval"],
        )
    if approval.proposal_id not in (proposal.proposal_id, proposal.stage_id):
        return GuardResult(
            allowed=False,
            guard="approval_validity",
            reason_code="STAGE_APPROVAL_TARGET_MISMATCH",
            message="Approval proposal_id does not match StageActionProposal or stage_id.",
            missing_requirements=["matching_stage_approval"],
        )
    expected_hash = proposal.compute_canonical_hash()
    if proposal.proposal_hash != expected_hash or approval.proposal_hash != expected_hash:
        return GuardResult(
            allowed=False,
            guard="approval_validity",
            reason_code="STAGE_PROPOSAL_HASH_MISMATCH",
            message="Approval proposal_hash does not match canonical StageActionProposal hash.",
            missing_requirements=["matching_stage_proposal_hash"],
        )
    if approval.decision != ApprovalStatus.APPROVED:
        return GuardResult(
            allowed=False,
            guard="approval_validity",
            reason_code="APPROVAL_NOT_APPROVED",
            message=f"Approval decision is {approval.decision.value!r}, not 'approved'.",
            missing_requirements=["approved_decision"],
        )
    if approval.expires_at <= now or proposal.expires_at <= now:
        return GuardResult(
            allowed=False,
            guard="approval_freshness",
            reason_code="APPROVAL_EXPIRED",
            message="Stage approval or proposal has expired.",
            missing_requirements=["fresh_stage_approval"],
        )
    if consumed_approval_ids and approval.approval_id in consumed_approval_ids:
        return GuardResult(
            allowed=False,
            guard="approval_validity",
            reason_code="APPROVAL_ALREADY_CONSUMED",
            message="Stage approval has already been consumed.",
            missing_requirements=["fresh_unconsumed_approval"],
        )
    return GuardResult(
        allowed=True,
        guard="approval_validity",
        reason_code="STAGE_APPROVAL_VERIFIED",
        message=f"Stage approval {approval.approval_id!r} verified against canonical hash.",
    )
