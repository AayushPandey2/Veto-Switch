"""Post-rollback readback reconciliation and security/functional verification."""

from __future__ import annotations

from typing import Any

from shared.enums import (
    FeatureObservationStatus,
    IncidentState,
    RollbackActionType,
    RollbackReasonCode,
    RollbackVerificationOutcome,
    TestExecutionStatus,
)
from shared.schemas import (
    FeatureState,
    OperationReceipt,
    RollbackProposal,
    TargetingRollbackAction,
    VerificationResult,
)

from remediation.recovery.models import (
    PostRollbackVerificationResult,
    ReadbackReconciliationResult,
)


def reconcile_post_rollback_readback(
    *,
    proposal: RollbackProposal,
    management_readback: FeatureState | None,
    application_observed_enabled: bool | None = None,
    application_observed_exposure: int | None = None,
    legacy_feature_state: FeatureState | None = None,
    observed_targeting_configuration: dict[str, Any] | None = None,
) -> ReadbackReconciliationResult:
    """Verify management-plane readback and application-side observation agree with proposal."""
    if (
        management_readback is None
        or management_readback.observation_status != FeatureObservationStatus.OBSERVED
    ):
        return ReadbackReconciliationResult(
            matched=False,
            management_state_matched=False,
            application_behavior_matched=False,
            legacy_contained=False,
            reason_codes=[RollbackReasonCode.READBACK_MISMATCH],
            message="Management readback is missing or not OBSERVED.",
        )

    if (
        management_readback.environment != proposal.target_environment
        or management_readback.feature_name != proposal.target_feature
    ):
        return ReadbackReconciliationResult(
            matched=False,
            management_state_matched=False,
            application_behavior_matched=False,
            legacy_contained=False,
            reason_codes=[RollbackReasonCode.READBACK_MISMATCH],
            message="Management readback environment or feature does not match proposal.",
        )

    mgmt_matched = management_readback.enabled == proposal.proposed_state
    app_matched = True
    observed_exp: int | None = application_observed_exposure

    if isinstance(proposal.targeting_action, TargetingRollbackAction):
        desired_exp = proposal.targeting_action.desired_exposure
        if application_observed_exposure is None or application_observed_exposure != desired_exp:
            app_matched = False
        if (
            observed_targeting_configuration is not None
            and proposal.proposed_targeting_configuration is not None
            and observed_targeting_configuration != proposal.proposed_targeting_configuration
        ):
            mgmt_matched = False
    if (
        application_observed_enabled is not None
        and application_observed_enabled != proposal.proposed_state
        and not isinstance(proposal.targeting_action, TargetingRollbackAction)
    ):
        app_matched = False

    legacy_contained = True
    if legacy_feature_state is not None and (
        legacy_feature_state.observation_status != FeatureObservationStatus.OBSERVED
        or legacy_feature_state.enabled
    ):
        legacy_contained = False

    if not mgmt_matched or not app_matched or not legacy_contained:
        reasons: list[RollbackReasonCode] = []
        if not mgmt_matched or not app_matched:
            reasons.append(RollbackReasonCode.READBACK_MISMATCH)
        if not legacy_contained:
            reasons.append(RollbackReasonCode.LEGACY_VULNERABLE_PATH_EXPOSED)
        return ReadbackReconciliationResult(
            matched=False,
            management_state_matched=mgmt_matched,
            application_behavior_matched=app_matched,
            legacy_contained=legacy_contained,
            observed_exposure=observed_exp,
            reason_codes=reasons,
            message=(
                "Post-rollback readback or application observation does not match intended state."
            ),
        )

    return ReadbackReconciliationResult(
        matched=True,
        management_state_matched=True,
        application_behavior_matched=True,
        legacy_contained=True,
        observed_exposure=observed_exp,
        message=(
            "Management readback and application behavior match intended rollback configuration."
        ),
    )


def verify_post_rollback(
    *,
    proposal: RollbackProposal,
    receipt: OperationReceipt | None,
    readback: ReadbackReconciliationResult,
    security_verification: VerificationResult | None,
    functional_verification: VerificationResult | None = None,
    expected_revision: str | None = None,
) -> PostRollbackVerificationResult:
    """Evaluate complete post-rollback verification and determine accurate incident state."""
    if receipt is None:
        return PostRollbackVerificationResult(
            outcome=RollbackVerificationOutcome.ROLLBACK_OUTCOME_UNKNOWN,
            recommended_incident_state=IncidentState.ROLLBACK_PROPOSED,
            reason_codes=[RollbackReasonCode.EXECUTION_OUTCOME_UNKNOWN],
            message="Cannot verify rollback without a trusted OperationReceipt.",
        )

    if not readback.matched:
        return PostRollbackVerificationResult(
            outcome=RollbackVerificationOutcome.ROLLBACK_VERIFICATION_FAILED,
            recommended_incident_state=IncidentState.ROLLBACK_PROPOSED,
            reason_codes=readback.reason_codes or [RollbackReasonCode.READBACK_MISMATCH],
            message=readback.message,
        )

    if security_verification is None:
        return PostRollbackVerificationResult(
            outcome=RollbackVerificationOutcome.ROLLBACK_VERIFICATION_INCOMPLETE,
            recommended_incident_state=IncidentState.ROLLBACK_PROPOSED,
            reason_codes=[RollbackReasonCode.POST_ROLLBACK_EVIDENCE_MISSING],
            message="Post-rollback security regression VerificationResult is missing.",
        )

    if security_verification.incident_id != proposal.incident_id:
        return PostRollbackVerificationResult(
            outcome=RollbackVerificationOutcome.ROLLBACK_VERIFICATION_FAILED,
            recommended_incident_state=IncidentState.ROLLBACK_PROPOSED,
            reason_codes=[RollbackReasonCode.POST_ROLLBACK_SECURITY_FAILED],
            message=("Security verification incident_id does not match RollbackProposal."),
        )

    if (
        expected_revision is not None
        and security_verification.tested_revision != expected_revision
    ):
        return PostRollbackVerificationResult(
            outcome=RollbackVerificationOutcome.ROLLBACK_VERIFICATION_FAILED,
            recommended_incident_state=IncidentState.ROLLBACK_PROPOSED,
            reason_codes=[RollbackReasonCode.SAFE_STATE_REVISION_MISMATCH],
            message="Post-rollback security verification tested a different revision.",
        )

    if (
        security_verification.execution_status != TestExecutionStatus.TEST_PASSED
        or security_verification.passed is not True
        or security_verification.vulnerability_reproduced is True
    ):
        return PostRollbackVerificationResult(
            outcome=RollbackVerificationOutcome.ROLLBACK_VERIFICATION_FAILED,
            recommended_incident_state=IncidentState.ROLLBACK_PROPOSED,
            reason_codes=[RollbackReasonCode.POST_ROLLBACK_SECURITY_FAILED],
            evidence_ids=list(security_verification.artifact_ids),
            message="Post-rollback security regression verification failed.",
        )

    if functional_verification is not None and (
        functional_verification.execution_status != TestExecutionStatus.TEST_PASSED
        or functional_verification.passed is not True
    ):
        return PostRollbackVerificationResult(
            outcome=RollbackVerificationOutcome.ROLLBACK_VERIFICATION_FAILED,
            recommended_incident_state=IncidentState.ROLLBACK_PROPOSED,
            reason_codes=[RollbackReasonCode.POST_ROLLBACK_FUNCTIONAL_FAILED],
            evidence_ids=[
                *security_verification.artifact_ids,
                *functional_verification.artifact_ids,
            ],
            message="Post-rollback functional/smoke verification failed.",
        )

    evidence_ids = [*security_verification.artifact_ids, *receipt.evidence_ids]
    if functional_verification is not None:
        evidence_ids.extend(functional_verification.artifact_ids)

    # Partial exposure reduction (e.g., 25% -> 5%) must NOT be reported as CONTAINED or RECOVERED.
    if (
        proposal.action_type == RollbackActionType.TARGETING_CONFIGURATION
        and isinstance(proposal.targeting_action, TargetingRollbackAction)
        and proposal.targeting_action.desired_exposure > 0
    ):
        remaining = proposal.targeting_action.desired_exposure
        return PostRollbackVerificationResult(
            outcome=RollbackVerificationOutcome.ROLLBACK_VERIFIED,
            recommended_incident_state=IncidentState.ROLLOUT_PAUSED,
            full_containment_restored=False,
            partial_exposure_remaining=remaining,
            evidence_ids=list(dict.fromkeys(evidence_ids)),
            message=(
                f"Earlier rollout stage ({remaining}%) restored and verified; "
                "rollout remains paused with partial exposure."
            ),
            limitations=[
                f"Partial exposure ({remaining}%) remains active; "
                "not classified as full containment or RECOVERED."
            ],
        )

    return PostRollbackVerificationResult(
        outcome=RollbackVerificationOutcome.ROLLBACK_VERIFIED,
        recommended_incident_state=IncidentState.CONTAINED,
        full_containment_restored=True,
        partial_exposure_remaining=0,
        evidence_ids=list(dict.fromkeys(evidence_ids)),
        message="Full containment restored and verified via readback and post-rollback checks.",
    )
