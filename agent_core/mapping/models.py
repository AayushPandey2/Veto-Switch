"""Typed models for deterministic vulnerability-to-feature-flag mapping."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field, StrictBool, StrictInt
from shared.enums import (
    EvidenceProvenance,
    FeatureObservationStatus,
    FeatureRole,
    MappingActionEligibility,
    MappingMethod,
    MappingReasonCode,
)
from shared.identifiers import utc_now
from shared.schemas import (
    ArtifactReference,
    DependencyGraph,
    FeatureState,
    Finding,
    InvestigationSummary,
    KillswitchModel,
    MappingResult,
    RouteFlagEntry,
    UtcDatetime,
    VerificationResult,
)


class MappingContext(KillswitchModel):
    """Typed context carrying all inputs for deterministic flag mapping."""

    finding: Finding
    investigation_summary: InvestigationSummary | None = None
    artifact_references: list[ArtifactReference] = Field(default_factory=list)
    verification_results: list[VerificationResult] = Field(default_factory=list)
    registered_test_id: str | None = None
    observed_implementation: str | None = None
    http_method: str | None = None
    application_revision: str | None = None
    environment: str | None = None
    registry_revision: str | None = None
    feature_states: list[FeatureState] = Field(default_factory=list)
    dependency_graph: DependencyGraph | None = None
    fixture_mode: StrictBool = False
    evaluation_timestamp: UtcDatetime = Field(default_factory=utc_now)


class CandidateDetail(KillswitchModel):
    """Structured explanation of a candidate feature flag considered during mapping."""

    flag_name: str = Field(min_length=1)
    role: FeatureRole = FeatureRole.UNKNOWN
    implementation_id: str | None = None
    route: str | None = None
    component: str | None = None
    is_replacement: StrictBool = False
    observation_status: FeatureObservationStatus = FeatureObservationStatus.UNAVAILABLE
    observed_enabled: StrictBool | None = None
    state_version: str | None = None
    reason_codes: list[MappingReasonCode] = Field(default_factory=list)


class RejectedCandidate(KillswitchModel):
    """Candidate flag excluded during deterministic filtering or validation."""

    flag_name: str = Field(min_length=1)
    reason_code: MappingReasonCode
    reason: str = Field(min_length=1)


class RegistryValidationReport(KillswitchModel):
    """Outcome of validating a ``RouteFlagRegistry`` for integrity and consistency."""

    valid: StrictBool
    registry_version: str = Field(min_length=1)
    registry_fingerprint: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    application_revision: str | None = None
    reason_codes: list[MappingReasonCode] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class RouteResolutionResult(KillswitchModel):
    """Deterministic route and alias resolution result."""

    matched: StrictBool
    input_route: str | None = None
    canonical_route: str | None = None
    matched_alias: str | None = None
    matched_variant: str | None = None
    match_kind: Literal["canonical", "alias", "variant", "none"] = "none"
    http_method_matched: StrictBool = True
    entry: RouteFlagEntry | None = None
    reason_codes: list[MappingReasonCode] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class ComponentResolutionResult(KillswitchModel):
    """Deterministic component and component-alias resolution result."""

    matched: StrictBool
    input_component: str | None = None
    canonical_component: str | None = None
    matched_alias: str | None = None
    conflict_with_route: StrictBool = False
    entries: list[RouteFlagEntry] = Field(default_factory=list)
    reason_codes: list[MappingReasonCode] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class ImplementationResolutionResult(KillswitchModel):
    """Deterministic implementation/variant resolution from trusted signals."""

    resolved: StrictBool
    implementation_id: str | None = None
    controlling_flag: str | None = None
    source: Literal[
        "observed_implementation",
        "verification_result",
        "registered_test",
        "single_binding",
        "component_alias",
        "none",
    ] = "none"
    evidence_ids: list[str] = Field(default_factory=list)
    reason_codes: list[MappingReasonCode] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class StateValidationResult(KillswitchModel):
    """Outcome of validating runtime ``FeatureState`` observations for a flag."""

    feature_name: str = Field(min_length=1)
    observation_status: FeatureObservationStatus = FeatureObservationStatus.UNAVAILABLE
    observed_enabled: StrictBool | None = None
    state_version: str | None = None
    fresh: StrictBool = False
    consistent: StrictBool = True
    already_disabled: StrictBool = False
    segment_targeting_uncertain: StrictBool = False
    action_eligible: StrictBool = False
    requires_verification: StrictBool = True
    reason_codes: list[MappingReasonCode] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    observed_at: datetime | None = None
    provenance: EvidenceProvenance | None = None


class EvidenceValidationOutcome(KillswitchModel):
    """Outcome of validating finding and artifact evidence for mapping."""

    actionable: StrictBool
    reproduced: StrictBool
    is_suspected: StrictBool = False
    is_fixture_only: StrictBool = False
    verified_evidence_ids: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    reason_codes: list[MappingReasonCode] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class FreshnessPolicy(KillswitchModel):
    """Configurable engineering policy for feature-state observation freshness.

    Note:
        Default thresholds are configurable engineering policies, not empirically
        measured security guarantees.
    """

    max_age_seconds: StrictInt = Field(default=300, ge=1)
    max_future_skew_seconds: StrictInt = Field(default=30, ge=0)
    require_observed_in_live: StrictBool = True


class MappingDiagnostics(KillswitchModel):
    """Rich diagnostic payload supporting orchestration, Phase 05, Phase 06, and UI."""

    canonical_route: str | None = None
    matched_alias: str | None = None
    matched_implementation: str | None = None
    mapping_method: MappingMethod = MappingMethod.UNMAPPED
    reason_codes: list[MappingReasonCode] = Field(default_factory=list)
    candidate_details: list[CandidateDetail] = Field(default_factory=list)
    rejected_candidates: list[RejectedCandidate] = Field(default_factory=list)
    affected_routes: list[str] = Field(default_factory=list)
    shared_feature_dependencies: list[str] = Field(default_factory=list)
    potential_replacements: list[str] = Field(default_factory=list)
    fallback_behavior: str | None = None
    observation_status: FeatureObservationStatus = FeatureObservationStatus.UNAVAILABLE
    registry_fingerprint: str = ""
    application_revision: str | None = None
    observed_feature_state: StrictBool | None = None
    feature_state_version: str | None = None
    action_eligibility: MappingActionEligibility = MappingActionEligibility.BLOCKED
    requires_verification: StrictBool = True
    missing_evidence: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    provenance: list[EvidenceProvenance] = Field(default_factory=list)
    is_fixture_only: StrictBool = False
    evaluation_timestamp: UtcDatetime = Field(default_factory=utc_now)


class MappingOutcome(KillswitchModel):
    """Combined canonical ``MappingResult`` and structured ``MappingDiagnostics``."""

    mapping_result: MappingResult
    diagnostics: MappingDiagnostics
