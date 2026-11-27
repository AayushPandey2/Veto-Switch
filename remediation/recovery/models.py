"""Typed domain models for Phase 10 Rollback Intelligence."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field, StrictBool, StrictInt
from shared.constants import POLICY_VERSION
from shared.enums import (
    EvidenceProvenance,
    IncidentState,
    RollbackActionType,
    RollbackFeasibilityStatus,
    RollbackReasonCode,
    RollbackStrategyType,
    RollbackTriggerCategory,
    RollbackVerificationOutcome,
)
from shared.identifiers import utc_now
from shared.schemas import (
    ApprovalDecision,
    ArtifactReference,
    CoverageFinding,
    DeploymentEvidence,
    FeatureState,
    KillswitchModel,
    MetricSnapshot,
    OperationReceipt,
    RollbackProposal,
    RolloutDecision,
    VerificationResult,
)


class ExecutorCapabilities(KillswitchModel):
    """Explicit capability contract for the external platform executor."""

    supports_boolean: StrictBool = True
    supports_targeting: StrictBool = False
    supports_compare_and_set: StrictBool = False
    app_target: str = Field(default="stand_in", min_length=1)
    declared_fallback_behavior: str | None = None
    fallback_verified: StrictBool = False
    fallback_verification_id: str | None = None


class RollbackContext(KillswitchModel):
    """Typed, provenance-aware context for deterministic rollback intelligence."""

    incident_id: str = Field(min_length=1)
    finding_id: str | None = None
    plan_id: str | None = None
    current_stage_id: str | None = None
    current_observed_exposure: StrictInt | None = Field(default=None, ge=0, le=100)
    current_targeting_configuration: dict[str, Any] | None = None
    current_targeting_version: str | None = None
    current_observed_feature_state: FeatureState | None = None
    target_feature: str = Field(min_length=1)
    provider_feature_id: str | None = None
    environment: str = Field(min_length=1)
    active_candidate_identity: str | None = None
    verified_patch_revision: str | None = None
    deployment_identity: str | None = None
    deployment_evidence: DeploymentEvidence | None = None
    rollout_decision: RolloutDecision | None = None
    failed_guardrails: list[str] = Field(default_factory=list)
    triggering_telemetry: MetricSnapshot | None = None
    security_regression_result: VerificationResult | None = None
    last_verified_safe_state: Any | None = None
    verified_stage_history: list[Any] = Field(default_factory=list)
    known_vulnerable_implementations: list[str] = Field(default_factory=lambda: ["search_v1"])
    current_legacy_feature_state: FeatureState | None = None
    legacy_segment_overrides: dict[str, Any] = Field(default_factory=dict)
    coverage_findings: list[CoverageFinding] = Field(default_factory=list)
    fallback_evidence: list[ArtifactReference] = Field(default_factory=list)
    executor_capabilities: ExecutorCapabilities = Field(default_factory=ExecutorCapabilities)
    policy_version: str = Field(default=POLICY_VERSION, min_length=1)
    evidence_references: list[str] = Field(default_factory=list)
    evaluation_timestamp: datetime = Field(default_factory=utc_now)
    fixture_mode: StrictBool = False
    manual_operator_request: StrictBool = False
    manual_request_reason: str | None = None
    routing_changed: StrictBool = False
    dependency_graph_changed: StrictBool = False
    manual_external_modification_detected: StrictBool = False


class CheckpointInvalidation(KillswitchModel):
    """Explicit reason why a historical VerifiedSafeState was invalidated."""

    safe_state_id: str = Field(min_length=1)
    reason_code: RollbackReasonCode
    explanation: str = Field(min_length=1)


class SafeStateResolutionResult(KillswitchModel):
    """Result of resolving the latest eligible VerifiedSafeState checkpoint."""

    known: StrictBool
    selected_checkpoint: Any | None = None
    invalidated_checkpoints: list[CheckpointInvalidation] = Field(default_factory=list)
    reason_codes: list[RollbackReasonCode] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class TriggerValidationResult(KillswitchModel):
    """Validated rollback trigger classification distinguishing failure vs missing data."""

    valid: StrictBool
    trigger_category: RollbackTriggerCategory | None = None
    is_security_regression: StrictBool = False
    is_operational_degradation: StrictBool = False
    is_missing_evidence_hold: StrictBool = False
    triggering_evidence_ids: list[str] = Field(default_factory=list)
    failed_guardrails: list[str] = Field(default_factory=list)
    reason_codes: list[RollbackReasonCode] = Field(default_factory=list)
    rationale: str = Field(min_length=1)
    limitations: list[str] = Field(default_factory=list)


class RollbackCandidateStrategy(KillswitchModel):
    """Bounded rollback candidate strategy with explicit feasibility and prerequisites."""

    strategy_id: str = Field(min_length=1)
    strategy_type: RollbackStrategyType
    action_type: RollbackActionType
    intended_state_change: dict[str, Any] = Field(default_factory=dict)
    current_state_precondition: dict[str, Any] = Field(default_factory=dict)
    expected_security_effect: str = Field(min_length=1)
    expected_operational_effect: str = Field(min_length=1)
    fallback_requirements: list[str] = Field(default_factory=list)
    supporting_evidence: list[str] = Field(default_factory=list)
    feasibility_status: RollbackFeasibilityStatus
    missing_prerequisites: list[str] = Field(default_factory=list)
    required_verification: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    reason_codes: list[RollbackReasonCode] = Field(default_factory=list)
    preserves_legacy_containment: StrictBool = True
    eliminates_vulnerable_exposure: StrictBool = True


class RollbackAnalysisResult(KillswitchModel):
    """Complete deterministic Rollback Intelligence Engine output."""

    incident_id: str = Field(min_length=1)
    trigger_validation: TriggerValidationResult
    safe_state_resolution: SafeStateResolutionResult
    candidate_strategies: list[RollbackCandidateStrategy] = Field(default_factory=list)
    selected_strategy: RollbackCandidateStrategy | None = None
    proposal: RollbackProposal | None = None
    executable_proposal: StrictBool = False
    manual_review_required: StrictBool = True
    reason_codes: list[RollbackReasonCode] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    explanation_summary: str = Field(min_length=1)
    explanation_provenance: EvidenceProvenance = EvidenceProvenance.DETERMINISTIC_REASONING


class RollbackReceiptValidationResult(KillswitchModel):
    """Deterministic validation of an external rollback OperationReceipt."""

    valid: StrictBool
    # execution_succeeded | execution_failed | execution_outcome_unknown | readback_pending
    status: str = Field(min_length=1)
    duplicate: StrictBool = False
    reason_codes: list[RollbackReasonCode] = Field(default_factory=list)
    message: str = Field(min_length=1)


class ReadbackReconciliationResult(KillswitchModel):
    """Reconciliation of management-plane and application-side readback."""

    matched: StrictBool
    management_state_matched: StrictBool
    application_behavior_matched: StrictBool
    legacy_contained: StrictBool
    observed_exposure: StrictInt | None = Field(default=None, ge=0, le=100)
    reason_codes: list[RollbackReasonCode] = Field(default_factory=list)
    message: str = Field(min_length=1)


class PostRollbackVerificationResult(KillswitchModel):
    """Final post-rollback security and functional verification outcome."""

    outcome: RollbackVerificationOutcome
    recommended_incident_state: IncidentState
    full_containment_restored: StrictBool = False
    partial_exposure_remaining: StrictInt | None = Field(default=None, ge=0, le=100)
    reason_codes: list[RollbackReasonCode] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    message: str = Field(min_length=1)
    limitations: list[str] = Field(default_factory=list)


class Phase11RollbackHandoff(KillswitchModel):
    """Deterministic Phase 11 Incident Evidence Reporting handoff contract."""

    incident_id: str = Field(min_length=1)
    rollout_plan_id: str | None = None
    active_candidate_identity: str | None = None
    deployment_identity: str | None = None
    stage_history: list[dict[str, Any]] = Field(default_factory=list)
    verified_safe_state_history: list[dict[str, Any]] = Field(default_factory=list)
    triggering_decision: dict[str, Any] | None = None
    triggering_metrics: dict[str, Any] | None = None
    failed_guardrails: list[str] = Field(default_factory=list)
    considered_rollback_strategies: list[dict[str, Any]] = Field(default_factory=list)
    selected_rollback_proposal: dict[str, Any] | None = None
    proposal_hash: str | None = None
    approval_decision: ApprovalDecision | None = None
    operation_receipt: OperationReceipt | None = None
    configuration_before: dict[str, Any] = Field(default_factory=dict)
    requested_configuration: dict[str, Any] = Field(default_factory=dict)
    observed_configuration_after: dict[str, Any] = Field(default_factory=dict)
    post_rollback_security_results: list[dict[str, Any]] = Field(default_factory=list)
    post_rollback_functional_results: list[dict[str, Any]] = Field(default_factory=list)
    final_rollback_status: str = Field(min_length=1)
    final_incident_state: IncidentState
    evidence_ids: list[str] = Field(default_factory=list)
    artifact_hashes: dict[str, str] = Field(default_factory=dict)
    policy_versions: dict[str, str] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
