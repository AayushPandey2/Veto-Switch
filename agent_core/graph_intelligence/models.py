"""Typed models for Dependency Graph Intelligence, Blast Radius, and Counterfactuals."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, StrictBool
from shared.enums import ContainmentReasonCode, EvidenceProvenance
from shared.identifiers import utc_now
from shared.schemas import (
    DependencyGraph,
    DeploymentEvidence,
    FeatureState,
    Finding,
    KillswitchModel,
    MappingResult,
    RouteFlagRegistry,
    UtcDatetime,
    VerificationResult,
)


class GraphValidationReport(KillswitchModel):
    """Outcome of validating a ``DependencyGraph`` against integrity and context rules."""

    valid: StrictBool
    graph_version: str = Field(min_length=1)
    graph_fingerprint: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    reason_codes: list[ContainmentReasonCode] = Field(default_factory=list)


class BlastRadiusContext(KillswitchModel):
    """Typed context carrying all inputs for deterministic blast-radius analysis."""

    finding: Finding
    mapping: MappingResult
    graph: DependencyGraph
    registry: RouteFlagRegistry | None = None
    observed_features: list[FeatureState] = Field(default_factory=list)
    deployment_evidence: list[DeploymentEvidence] = Field(default_factory=list)
    verification_results: list[VerificationResult] = Field(default_factory=list)
    application_revision: str | None = None
    environment: str | None = None
    fixture_mode: StrictBool = False
    evaluation_timestamp: UtcDatetime = Field(default_factory=utc_now)


class BlastRadiusResult(KillswitchModel):
    """Structured deterministic blast-radius analysis distinguishing exposure vs disruption."""

    graph_valid: StrictBool
    graph_version: str = Field(min_length=1)
    graph_fingerprint: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    application_revision: str | None = None
    root_vulnerable_nodes: list[str] = Field(default_factory=list)
    affected_implementation_nodes: list[str] = Field(default_factory=list)
    affected_route_nodes: list[str] = Field(default_factory=list)
    feature_control_nodes: list[str] = Field(default_factory=list)
    upstream_dependents: list[str] = Field(default_factory=list)
    downstream_dependencies: list[str] = Field(default_factory=list)
    shared_resources: list[str] = Field(default_factory=list)
    potentially_exposed_resources: list[str] = Field(default_factory=list)
    unrelated_nodes: list[str] = Field(default_factory=list)
    potential_replacements: list[str] = Field(default_factory=list)
    known_security_entry_points: list[str] = Field(default_factory=list)
    affected_capabilities: list[str] = Field(default_factory=list)
    preserved_capabilities: list[str] = Field(default_factory=list)
    missing_relationships: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    reason_codes: list[ContainmentReasonCode] = Field(default_factory=list)
    is_fixture_only: StrictBool = False
    provenance: list[EvidenceProvenance] = Field(default_factory=list)


class CounterfactualOutcome(KillswitchModel):
    """Non-mutating hypothetical evaluation of a candidate containment action."""

    strategy_id: str = Field(min_length=1)
    qualifier: Literal[
        "predicted", "declared", "observed", "unknown", "requires_verification"
    ] = "predicted"
    state_before: dict[str, bool | None] = Field(default_factory=dict)
    hypothetical_state_after: dict[str, bool | None] = Field(default_factory=dict)
    affected_routes: list[str] = Field(default_factory=list)
    affected_capabilities: list[str] = Field(default_factory=list)
    affected_services: list[str] = Field(default_factory=list)
    preserved_capabilities: list[str] = Field(default_factory=list)
    potentially_blocked_vulnerable_paths: list[str] = Field(default_factory=list)
    remaining_exposure_paths: list[str] = Field(default_factory=list)
    fallback_behavior: str | None = None
    missing_prerequisites: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
