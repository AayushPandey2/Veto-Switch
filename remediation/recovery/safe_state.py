"""Last Verified-Safe State recording, resolution, and explicit invalidation."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field, StrictBool, StrictInt
from shared.constants import POLICY_VERSION
from shared.enums import (
    DeploymentStatus,
    EvidenceProvenance,
    FeatureObservationStatus,
    OperationOutcome,
    RollbackReasonCode,
    RolloutDecisionType,
    TestExecutionStatus,
)
from shared.identifiers import generate_prefixed_id, utc_now
from shared.schemas import (
    ApprovalDecision,
    DeploymentEvidence,
    FeatureState,
    KillswitchModel,
    MetricSnapshot,
    OperationReceipt,
    RollbackPolicyConfig,
    RolloutDecision,
    VerificationResult,
    VerifiedSafeState,
)
from shared.serialization import sha256_canonical

from remediation.recovery.models import (
    CheckpointInvalidation,
    RollbackContext,
    SafeStateResolutionResult,
)


class SafeStateCheckpointInput(KillswitchModel):
    """Trusted evidence bundle required to record a VerifiedSafeState checkpoint."""

    incident_id: str = Field(min_length=1)
    plan_id: str = Field(min_length=1)
    stage_id: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    feature_name: str = Field(min_length=1)
    provider_feature_id: str | None = None
    implementation_id: str = Field(min_length=1)
    configured_exposure_percentage: StrictInt = Field(ge=0, le=100)
    targeting_configuration: dict[str, Any] = Field(default_factory=dict)
    global_feature_state: StrictBool
    approval: ApprovalDecision
    receipt: OperationReceipt
    readback_state: FeatureState
    application_observed_exposure: StrictInt | None = Field(default=None, ge=0, le=100)
    deployment_evidence: DeploymentEvidence
    security_verification: VerificationResult
    functional_verification: VerificationResult
    telemetry_snapshot: MetricSnapshot
    rollout_decision: RolloutDecision
    legacy_feature_states: dict[str, FeatureState] = Field(default_factory=dict)
    known_vulnerable_implementations: list[str] = Field(default_factory=lambda: ["search_v1"])
    policy_version: str = Field(default=POLICY_VERSION, min_length=1)
    verified_at: datetime = Field(default_factory=utc_now)


def record_verified_safe_state(bundle: SafeStateCheckpointInput) -> VerifiedSafeState:
    """Enforce the 11-point safe-state recording policy before creating a checkpoint."""
    if bundle.approval.incident_id != bundle.incident_id:
        raise ValueError("Approval incident_id mismatch.")
    if bundle.receipt.incident_id != bundle.incident_id:
        raise ValueError("OperationReceipt incident_id mismatch.")
    if bundle.receipt.outcome != OperationOutcome.SUCCEEDED:
        raise ValueError("OperationReceipt must have outcome='succeeded'.")
    if bundle.receipt.approval_id != bundle.approval.approval_id:
        raise ValueError("OperationReceipt approval_id mismatch.")
    if bundle.readback_state.observation_status != FeatureObservationStatus.OBSERVED:
        raise ValueError("FeatureState readback must be OBSERVED.")
    if (
        bundle.readback_state.environment != bundle.environment
        or bundle.readback_state.feature_name != bundle.feature_name
    ):
        raise ValueError("FeatureState readback environment/feature mismatch.")
    if bundle.readback_state.enabled != bundle.global_feature_state:
        raise ValueError("Actual readback configuration does not match approved global state.")
    if (
        bundle.application_observed_exposure is not None
        and bundle.application_observed_exposure != bundle.configured_exposure_percentage
    ):
        raise ValueError("Application-side observed exposure disagrees with readback.")
    if bundle.deployment_evidence.deployment_status != DeploymentStatus.OBSERVED:
        raise ValueError("DeploymentEvidence must be OBSERVED.")
    if (
        bundle.deployment_evidence.environment != bundle.environment
        or bundle.deployment_evidence.feature_name != bundle.feature_name
    ):
        raise ValueError("DeploymentEvidence environment/feature mismatch.")
    if (
        bundle.security_verification.execution_status != TestExecutionStatus.TEST_PASSED
        or bundle.security_verification.passed is not True
        or bundle.security_verification.vulnerability_reproduced is True
    ):
        raise ValueError("Required security verification did not pass.")
    if (
        bundle.functional_verification.execution_status != TestExecutionStatus.TEST_PASSED
        or bundle.functional_verification.passed is not True
    ):
        raise ValueError("Mandatory functional verification did not pass.")
    if (
        bundle.rollout_decision.decision_type != RolloutDecisionType.ADVANCE
        and bundle.rollout_decision.failed_guardrails
    ):
        raise ValueError("Rollout guardrails failed; cannot record verified-safe checkpoint.")
    if bundle.telemetry_snapshot.security_regression_passed is not True:
        raise ValueError("Telemetry snapshot must confirm security_regression_passed=True.")

    legacy_states: dict[str, bool] = {}
    for vuln_impl in bundle.known_vulnerable_implementations:
        fs = bundle.legacy_feature_states.get(vuln_impl)
        if fs is None or fs.observation_status != FeatureObservationStatus.OBSERVED:
            raise ValueError(
                f"Legacy implementation {vuln_impl!r} state must be OBSERVED to verify containment."
            )
        if fs.enabled:
            raise ValueError(
                f"Known vulnerable legacy implementation {vuln_impl!r} is enabled; not safe."
            )
        legacy_states[vuln_impl] = bool(fs.enabled)

    targeting_fp = sha256_canonical(
        {
            "feature_name": bundle.feature_name,
            "exposure": bundle.configured_exposure_percentage,
            "targeting": bundle.targeting_configuration,
            "global_enabled": bundle.global_feature_state,
        }
    )

    return VerifiedSafeState(
        safe_state_id=generate_prefixed_id("safe_state"),
        incident_id=bundle.incident_id,
        plan_id=bundle.plan_id,
        stage_id=bundle.stage_id,
        environment=bundle.environment,
        feature_name=bundle.feature_name,
        provider_feature_id=bundle.provider_feature_id,
        implementation_id=bundle.implementation_id,
        deployment_id=bundle.deployment_evidence.deployment_id,
        implementation_revision=bundle.deployment_evidence.source_revision,
        implementation_artifact_hash=bundle.deployment_evidence.implementation_hash,
        configured_exposure_percentage=bundle.configured_exposure_percentage,
        targeting_configuration=dict(bundle.targeting_configuration),
        targeting_fingerprint=targeting_fp,
        global_feature_state=bundle.global_feature_state,
        relevant_legacy_feature_states=legacy_states,
        operation_receipt_id=bundle.receipt.operation_id,
        approval_id=bundle.approval.approval_id,
        readback_evidence_ids=[
            *(bundle.readback_state.evidence_ids or bundle.receipt.evidence_ids),
        ],
        security_verification_ids=[bundle.security_verification.verification_id],
        functional_verification_ids=[bundle.functional_verification.verification_id],
        telemetry_snapshot_ids=[bundle.telemetry_snapshot.snapshot_id],
        evaluated_guardrails=list(bundle.rollout_decision.evaluated_guardrails),
        verified_at=bundle.verified_at,
        policy_version=bundle.policy_version,
        provenance=EvidenceProvenance.DETERMINISTIC_REASONING,
    )


def _validate_checkpoint_eligibility(
    checkpoint: VerifiedSafeState,
    ctx: RollbackContext,
    policy: RollbackPolicyConfig,
) -> CheckpointInvalidation | None:
    if checkpoint.incident_id != ctx.incident_id:
        return CheckpointInvalidation(
            safe_state_id=checkpoint.safe_state_id,
            reason_code=RollbackReasonCode.SAFE_STATE_REVISION_MISMATCH,
            explanation="Checkpoint belongs to a different incident.",
        )
    if checkpoint.environment != ctx.environment or checkpoint.feature_name != ctx.target_feature:
        return CheckpointInvalidation(
            safe_state_id=checkpoint.safe_state_id,
            reason_code=RollbackReasonCode.SAFE_STATE_REVISION_MISMATCH,
            explanation=(
                "Checkpoint environment or feature identity does not match current context."
            ),
        )
    if (
        ctx.verified_patch_revision is not None
        and checkpoint.implementation_revision != ctx.verified_patch_revision
    ):
        return CheckpointInvalidation(
            safe_state_id=checkpoint.safe_state_id,
            reason_code=RollbackReasonCode.SAFE_STATE_REVISION_MISMATCH,
            explanation=(
                f"Checkpoint revision {checkpoint.implementation_revision!r} differs from "
                f"current revision {ctx.verified_patch_revision!r}."
            ),
        )
    if (
        ctx.deployment_evidence is not None
        and checkpoint.implementation_revision != ctx.deployment_evidence.source_revision
    ):
        return CheckpointInvalidation(
            safe_state_id=checkpoint.safe_state_id,
            reason_code=RollbackReasonCode.SAFE_STATE_REVISION_MISMATCH,
            explanation="Deployment revision changed since checkpoint verification.",
        )
    if (
        ctx.routing_changed
        or ctx.dependency_graph_changed
        or ctx.manual_external_modification_detected
    ):
        return CheckpointInvalidation(
            safe_state_id=checkpoint.safe_state_id,
            reason_code=RollbackReasonCode.CURRENT_TARGETING_CONFLICT,
            explanation="Routing, dependency graph, or external state changed since checkpoint.",
        )
    if (
        ctx.security_regression_result is not None
        and ctx.security_regression_result.vulnerability_reproduced is True
    ):
        return CheckpointInvalidation(
            safe_state_id=checkpoint.safe_state_id,
            reason_code=RollbackReasonCode.SECURITY_REGRESSION_CONFIRMED,
            explanation=(
                "Confirmed security regression invalidates partial-exposure checkpoint safety."
            ),
        )
    if (
        ctx.triggering_telemetry is not None
        and ctx.triggering_telemetry.security_regression_passed is False
    ):
        return CheckpointInvalidation(
            safe_state_id=checkpoint.safe_state_id,
            reason_code=RollbackReasonCode.SECURITY_REGRESSION_CONFIRMED,
            explanation="Telemetry security regression failure invalidates prior checkpoint.",
        )
    age_seconds = (ctx.evaluation_timestamp - checkpoint.verified_at).total_seconds()
    if age_seconds > policy.safe_state_max_age_seconds:
        return CheckpointInvalidation(
            safe_state_id=checkpoint.safe_state_id,
            reason_code=RollbackReasonCode.SAFE_STATE_STALE,
            explanation=(
                f"Checkpoint age ({int(age_seconds)}s) exceeds max age "
                f"({policy.safe_state_max_age_seconds}s)."
            ),
        )
    for vuln_impl in ctx.known_vulnerable_implementations:
        if checkpoint.relevant_legacy_feature_states.get(vuln_impl) is True:
            return CheckpointInvalidation(
                safe_state_id=checkpoint.safe_state_id,
                reason_code=RollbackReasonCode.LEGACY_VULNERABLE_PATH_EXPOSED,
                explanation=f"Checkpoint had vulnerable legacy {vuln_impl!r} enabled.",
            )
    if not (
        checkpoint.readback_evidence_ids
        and checkpoint.security_verification_ids
        and checkpoint.functional_verification_ids
        and checkpoint.telemetry_snapshot_ids
    ):
        return CheckpointInvalidation(
            safe_state_id=checkpoint.safe_state_id,
            reason_code=RollbackReasonCode.POST_ROLLBACK_EVIDENCE_MISSING,
            explanation="Checkpoint is missing mandatory verification or readback evidence.",
        )
    return None


def resolve_last_verified_safe_state(
    history: list[VerifiedSafeState],
    current_context: RollbackContext,
    *,
    policy: RollbackPolicyConfig | None = None,
) -> SafeStateResolutionResult:
    """Resolve the latest eligible VerifiedSafeState checkpoint deterministically."""
    active_policy = policy or RollbackPolicyConfig()
    candidates: list[VerifiedSafeState] = list(history)
    if isinstance(current_context.last_verified_safe_state, VerifiedSafeState) and all(
        c.safe_state_id != current_context.last_verified_safe_state.safe_state_id
        for c in candidates
    ):
        candidates.append(current_context.last_verified_safe_state)

    if not candidates:
        return SafeStateResolutionResult(
            known=False,
            selected_checkpoint=None,
            reason_codes=[RollbackReasonCode.NO_VERIFIED_SAFE_STATE],
            limitations=["No historical VerifiedSafeState checkpoints are available."],
        )

    ordered = sorted(candidates, key=lambda c: (c.verified_at, c.safe_state_id), reverse=True)
    invalidations: list[CheckpointInvalidation] = []
    reason_codes: list[RollbackReasonCode] = []

    for cp in ordered:
        inv = _validate_checkpoint_eligibility(cp, current_context, active_policy)
        if inv is None:
            return SafeStateResolutionResult(
                known=True,
                selected_checkpoint=cp,
                invalidated_checkpoints=invalidations,
                reason_codes=[],
                limitations=[],
            )
        invalidations.append(inv)
        if inv.reason_code not in reason_codes:
            reason_codes.append(inv.reason_code)

    if RollbackReasonCode.NO_VERIFIED_SAFE_STATE not in reason_codes:
        reason_codes.append(RollbackReasonCode.NO_VERIFIED_SAFE_STATE)
    return SafeStateResolutionResult(
        known=False,
        selected_checkpoint=None,
        invalidated_checkpoints=invalidations,
        reason_codes=reason_codes,
        limitations=[
            "All historical checkpoints were invalidated or incompatible with current context."
        ],
    )
