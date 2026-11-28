"""Typed models for Phase 09 Progressive Rollout Intelligence."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator
from shared.constants import POLICY_VERSION
from shared.enums import EvidenceProvenance, RollbackReasonCode
from shared.identifiers import utc_now
from shared.schemas import (
    DeploymentEvidence,
    FeatureState,
    KillswitchModel,
    MetricSnapshot,
    PatchTestResult,
    RolloutDecision,
    RolloutPlan,
    VerificationResult,
)
from shared.serialization import sha256_canonical
from shared.validation import validate_sha256_hex


class RecoveryEligibilityStatus(StrEnum):
    """Explicit separation between diagnostic drafts, review, proposal, and execution."""

    DRAFT_PLAN_AVAILABLE = "draft_plan_available"
    ELIGIBLE_FOR_REVIEW = "eligible_for_review"
    ELIGIBLE_FOR_STAGE_PROPOSAL = "eligible_for_stage_proposal"
    AUTHORIZED_FOR_EXECUTION = "authorized_for_execution"
    INELIGIBLE = "ineligible"


class StageLifecycleState(StrEnum):
    """Granular lifecycle states for an individual progressive rollout stage."""

    NOT_STARTED = "not_started"
    PROPOSED = "proposed"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    EXECUTION_PENDING = "execution_pending"
    READBACK_PENDING = "readback_pending"
    OBSERVING = "observing"
    EVALUATION_PENDING = "evaluation_pending"
    PASSED = "passed"
    HELD = "held"
    FAILED = "failed"
    ROLLBACK_RECOMMENDED = "rollback_recommended"


class RecoveryEligibilityContext(KillswitchModel):
    """Trusted context for validating Phase 09 recovery eligibility."""

    incident_id: str = Field(min_length=1)
    finding_id: str | None = None
    active_patch_id: str | None = None
    candidate_diff_hash: str | None = None
    candidate_manifest_fingerprint: str | None = None
    verified_test_run_id: str | None = None
    verified_patched_revision: str | None = None
    patch_test_result: PatchTestResult | None = None
    deployment_evidence: DeploymentEvidence | None = None
    target_implementation: str = Field(default="search_service_v2", min_length=1)
    target_feature: str = Field(default="search_v2", min_length=1)
    provider_feature_id: str | None = None
    environment: str = Field(default="demo-staging", min_length=1)
    registry_version: str | None = None
    registry_fingerprint: str | None = None
    current_feature_state: FeatureState | None = None
    legacy_feature_state: FeatureState | None = None
    current_targeting_configuration: dict[str, Any] = Field(default_factory=dict)
    supports_segment_targeting: StrictBool = True
    application_observed_state: dict[str, Any] = Field(default_factory=dict)
    reference_security_verification: VerificationResult | None = None
    baseline_telemetry: MetricSnapshot | None = None
    rollout_policy_version: str = Field(default=POLICY_VERSION, min_length=1)
    evidence_references: list[str] = Field(default_factory=list)
    evaluation_timestamp: datetime = Field(default_factory=utc_now)
    fixture_mode: StrictBool = False


class EligibilityGateResult(KillswitchModel):
    """Outcome of the 15-point deterministic recovery eligibility gate."""

    eligible: StrictBool
    status: RecoveryEligibilityStatus
    missing_prerequisites: list[str] = Field(default_factory=list)
    blocking_reasons: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    deployment_chain_verified: StrictBool = False


class CohortAssignment(KillswitchModel):
    """Deterministic cohort bucket assignment for an identity."""

    cohort_namespace: str = Field(min_length=1)
    identity: str | None = None
    bucket: StrictInt | None = Field(default=None, ge=0, le=9999)
    exposure_percentage: StrictInt = Field(ge=0, le=100)
    included: StrictBool
    reason: str = Field(min_length=1)


class StageActionProposal(KillswitchModel):
    """Immutable, canonically hashed proposal for a single rollout stage change."""

    proposal_id: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    plan_id: str = Field(min_length=1)
    stage_id: str = Field(min_length=1)
    previous_stage_id: str | None = None
    target_environment: str = Field(min_length=1)
    target_feature: str = Field(min_length=1)
    provider_feature_id: str | None = None
    target_implementation_revision: str = Field(min_length=1)
    expected_current_exposure: StrictInt = Field(ge=0, le=100)
    requested_exposure: StrictInt = Field(ge=0, le=100)
    expected_targeting_version: str | None = None
    exact_requested_targeting_configuration: dict[str, Any] = Field(default_factory=dict)
    deployment_evidence_identity: str = Field(min_length=1)
    candidate_identity: str | None = None
    verification_evidence: list[str] = Field(default_factory=list)
    decision_identity: str | None = None
    policy_version: str = Field(default=POLICY_VERSION, min_length=1)
    created_at: datetime = Field(default_factory=utc_now)
    expires_at: datetime
    idempotency_token: str = Field(min_length=1)
    approval_required: StrictBool = True
    execution_authorized: StrictBool = False
    proposal_hash: str | None = None

    @field_validator("proposal_hash")
    @classmethod
    def _validate_hash(cls, v: str | None) -> str | None:
        return validate_sha256_hex(v) if v is not None else None

    def compute_canonical_hash(self) -> str:
        """Compute canonical SHA-256 hash over review-relevant stage action fields."""
        return sha256_canonical(
            {
                "proposal_id": self.proposal_id,
                "incident_id": self.incident_id,
                "plan_id": self.plan_id,
                "stage_id": self.stage_id,
                "previous_stage_id": self.previous_stage_id,
                "target_environment": self.target_environment,
                "target_feature": self.target_feature,
                "target_implementation_revision": self.target_implementation_revision,
                "expected_current_exposure": self.expected_current_exposure,
                "requested_exposure": self.requested_exposure,
                "expected_targeting_version": self.expected_targeting_version,
                "exact_requested_targeting_configuration": (
                    self.exact_requested_targeting_configuration
                ),
                "deployment_evidence_identity": self.deployment_evidence_identity,
                "policy_version": self.policy_version,
                "idempotency_token": self.idempotency_token,
            }
        )

    @model_validator(mode="after")
    def _bind_hash(self) -> StageActionProposal:
        if not self.approval_required:
            raise ValueError("StageActionProposal must require approval_required=True.")
        expected = self.compute_canonical_hash()
        if self.proposal_hash is None:
            object.__setattr__(self, "proposal_hash", expected)
        elif self.proposal_hash != expected:
            raise ValueError("StageActionProposal.proposal_hash mismatch.")
        return self


class FinalRecoveryAssessment(KillswitchModel):
    """Final 100% stage assessment distinguishing completion from advancement."""

    incident_id: str = Field(min_length=1)
    plan_id: str = Field(min_length=1)
    ready_for_recovered: StrictBool
    all_stages_completed: StrictBool
    final_security_passed: StrictBool
    final_functional_passed: StrictBool
    legacy_contained: StrictBool
    missing_requirements: list[str] = Field(default_factory=list)
    reason: str = Field(min_length=1)


class RollbackHandoffContext(KillswitchModel):
    """Typed Phase 09 -> Phase 10 rollback recommendation handoff."""

    incident_id: str = Field(min_length=1)
    plan_id: str = Field(min_length=1)
    current_stage_id: str = Field(min_length=1)
    current_observed_exposure: StrictInt | None = Field(default=None, ge=0, le=100)
    target_feature: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    current_targeting_configuration: dict[str, Any] = Field(default_factory=dict)
    targeting_version: str | None = None
    failed_guardrails: list[str] = Field(default_factory=list)
    security_regression_result: VerificationResult | None = None
    deployment_revision: str | None = None
    candidate_identity: str | None = None
    triggering_evidence_ids: list[str] = Field(default_factory=list)
    last_verified_successful_stage: str | None = None
    last_verified_safe_state_reference: str | None = None
    known_vulnerable_legacy_feature: str = "search_v1"
    reason_codes: list[RollbackReasonCode] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class RolloutEvaluationBundle(KillswitchModel):
    """Complete deterministic output from evaluating a rollout stage."""

    plan: RolloutPlan
    decision: RolloutDecision
    guardrail_checks: list[Any] = Field(default_factory=list)
    next_stage_proposal: StageActionProposal | None = None
    final_assessment: FinalRecoveryAssessment | None = None
    rollback_handoff: RollbackHandoffContext | None = None
    provenance: EvidenceProvenance = EvidenceProvenance.DETERMINISTIC_REASONING
