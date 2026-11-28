"""Typed domain models for Phase 06 Feature Flag Coverage Auditing."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import Field, StrictBool, StrictInt
from shared.enums import (
    CoverageApplicability,
    CoverageEvidenceSupport,
    CoverageReasonCode,
    CoverageStatus,
    EvidenceProvenance,
)
from shared.identifiers import utc_now
from shared.schemas import (
    ArtifactReference,
    CoverageFinding,
    DependencyGraph,
    FeatureState,
    KillswitchModel,
    RouteFlagRegistry,
    UtcDatetime,
    VerificationResult,
)


class SourceReference(KillswitchModel):
    """Exact bounded reference into an audited source file."""

    relative_path: str = Field(min_length=1)
    start_line: StrictInt = Field(ge=1)
    end_line: StrictInt = Field(ge=1)
    file_hash: str = Field(min_length=64, max_length=64)
    source_revision: str = Field(min_length=1)
    snippet_summary: str = ""


class SourceFileEntry(KillswitchModel):
    """In-memory representation of an authorized read-only source file."""

    relative_path: str = Field(min_length=1)
    content: str
    sha256_hash: str = Field(min_length=64, max_length=64)
    size_bytes: StrictInt = Field(ge=0)


class SnapshotLimits(KillswitchModel):
    """Bounded resource limits enforced during static snapshot loading and AST analysis."""

    max_files: StrictInt = Field(default=32, ge=1)
    max_total_bytes: StrictInt = Field(default=512_000, ge=1)
    max_file_bytes: StrictInt = Field(default=128_000, ge=1)
    max_ast_nodes: StrictInt = Field(default=20_000, ge=1)
    max_call_depth: StrictInt = Field(default=6, ge=1)
    max_worklist_iterations: StrictInt = Field(default=256, ge=1)


class SourceSnapshot(KillswitchModel):
    """Authorized, bounded read-only source snapshot for a target application."""

    application_id: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    source_root_descriptor: str = Field(min_length=1)
    source_revision: str = Field(min_length=1)
    revision_namespace: str = Field(default="git_commit", min_length=1)
    source_tree_fingerprint: str = Field(min_length=64, max_length=64)
    provenance: EvidenceProvenance = EvidenceProvenance.ACTUAL_OBSERVED
    captured_at: UtcDatetime = Field(default_factory=utc_now)
    files: list[SourceFileEntry] = Field(default_factory=list)
    diagnostics: list[str] = Field(default_factory=list)
    is_complete: StrictBool = True
    limits: SnapshotLimits = Field(default_factory=SnapshotLimits)


class RouteIdentity(KillswitchModel):
    """Canonical identity of a discovered route or entry point."""

    application_id: str = Field(min_length=1)
    method: str = Field(min_length=1)
    route: str = Field(min_length=1)
    handler_name: str = Field(min_length=1)
    implementation_id: str | None = None
    aliases: list[str] = Field(default_factory=list)
    source_ref: SourceReference | None = None
    is_dynamic: StrictBool = False
    is_exempt: StrictBool = False
    applicability: CoverageApplicability = CoverageApplicability.APPLICABLE


class GuardCondition(KillswitchModel):
    """Typed representation of a static feature-flag guard condition."""

    expression_summary: str = Field(min_length=1)
    referenced_flags: list[str] = Field(default_factory=list)
    operator: Literal[
        "direct",
        "negated",
        "and",
        "or",
        "enum_is",
        "enum_is_not",
        "precedence",
        "logging_only",
        "post_sink",
        "unknown",
    ] = "unknown"
    blocks_when_disabled: StrictBool = False
    dominates_sink: StrictBool = False
    source_ref: SourceReference | None = None


class ExecutionPathAssessment(KillswitchModel):
    """Path-level control-flow and guard assessment for a sensitive implementation."""

    path_id: str = Field(min_length=1)
    route_identity: RouteIdentity
    sensitive_implementation: str | None = None
    call_chain: list[str] = Field(default_factory=list)
    guard_conditions: list[GuardCondition] = Field(default_factory=list)
    dominates_sink: StrictBool = False
    effective_when_disabled: StrictBool = False
    status: CoverageStatus = CoverageStatus.UNKNOWN
    applicability: CoverageApplicability = CoverageApplicability.APPLICABLE
    expected_flags: list[str] = Field(default_factory=list)
    observed_flags: list[str] = Field(default_factory=list)
    reason_codes: list[CoverageReasonCode] = Field(default_factory=list)
    source_ref: SourceReference | None = None
    notes: list[str] = Field(default_factory=list)


class SensitiveImplementation(KillswitchModel):
    """Implementation-wide aggregation of all entry points reaching a sensitive sink."""

    implementation_id: str = Field(min_length=1)
    symbol_name: str = Field(min_length=1)
    component: str = Field(min_length=1)
    expected_flags: list[str] = Field(default_factory=list)
    source_ref: SourceReference | None = None
    paths: list[ExecutionPathAssessment] = Field(default_factory=list)
    implementation_coverage_status: CoverageStatus = CoverageStatus.UNKNOWN
    alternate_entrypoints: list[str] = Field(default_factory=list)
    reason_codes: list[CoverageReasonCode] = Field(default_factory=list)


class ReconciliationDiscrepancy(KillswitchModel):
    """Mismatch across source routes, registry, dependency graph, and app manifest."""

    discrepancy_type: Literal[
        "source_route_missing_from_registry",
        "registry_route_missing_from_source",
        "undeclared_flag",
        "revision_mismatch",
        "component_or_implementation_mismatch",
        "graph_edge_conflict",
        "manifest_mismatch",
        "target_identity_mismatch",
    ]
    route: str | None = None
    method: str | None = None
    flag_name: str | None = None
    component: str | None = None
    details: str = Field(min_length=1)
    proposed_registry_update: dict[str, Any] | None = None


class RuntimeCorroborationSummary(KillswitchModel):
    """Bounded corroboration against trusted feature state & verification evidence."""

    evidence_support: CoverageEvidenceSupport = CoverageEvidenceSupport.UNAVAILABLE
    observed_flags: list[str] = Field(default_factory=list)
    identity_scopes: list[str] = Field(default_factory=list)
    contradicted: StrictBool = False
    contradiction_details: list[str] = Field(default_factory=list)
    missing_runtime_evidence: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class CoverageRecommendation(KillswitchModel):
    """Review-only engineering recommendation for a concrete coverage gap."""

    recommendation_id: str = Field(min_length=1)
    route: str = Field(min_length=1)
    method: str = Field(min_length=1)
    component: str = Field(min_length=1)
    implementation_id: str | None = None
    expected_control: str = Field(min_length=1)
    current_problem: str = Field(min_length=1)
    source_location: str | None = None
    proposed_change: str = Field(min_length=1)
    unified_diff: str | None = None
    review_only: StrictBool = True
    required_tests: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class CoverageAuditContext(KillswitchModel):
    """Inputs for running a deterministic, read-only Phase 06 coverage audit."""

    application_id: str = Field(default="platform_demo_app", min_length=1)
    environment: str = Field(default="demo-staging", min_length=1)
    snapshot: SourceSnapshot
    registry: RouteFlagRegistry | None = None
    dependency_graph: DependencyGraph | None = None
    manifest_routes: list[str] = Field(default_factory=list)
    observed_features: list[FeatureState] = Field(default_factory=list)
    verification_results: list[VerificationResult] = Field(default_factory=list)
    target_route: str | None = None
    target_component: str | None = None
    incident_id: str | None = None
    finding_id: str | None = None
    proposed_flag_action: str | None = None
    is_fixture: StrictBool = False


class CoverageAuditSummary(KillswitchModel):
    """Denominator-explicit route coverage counts (exempt routes excluded from denominator)."""

    sensitive_routes: StrictInt = Field(ge=0)
    protected: StrictInt = Field(ge=0)
    partially_protected: StrictInt = Field(ge=0)
    unprotected: StrictInt = Field(ge=0)
    unknown: StrictInt = Field(ge=0)
    exempt_routes: StrictInt = Field(ge=0)
    inventory_complete: StrictBool = True


class CoverageAuditResult(KillswitchModel):
    """Complete deterministic, source-grounded Phase 06 coverage audit output."""

    audit_id: str = Field(min_length=1)
    application_id: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    source_revision: str = Field(min_length=1)
    revision_namespace: str = Field(min_length=1)
    source_tree_fingerprint: str = Field(min_length=64, max_length=64)
    registry_version: str | None = None
    registry_fingerprint: str | None = None
    graph_version: str | None = None
    policy_version: str = Field(default="1.0.0-coverage", min_length=1)
    observed_at: datetime = Field(default_factory=utc_now)
    provenance: EvidenceProvenance = EvidenceProvenance.DETERMINISTIC_REASONING
    evidence_support: CoverageEvidenceSupport = CoverageEvidenceSupport.SOURCE_ONLY
    is_fixture: StrictBool = False
    summary: CoverageAuditSummary
    findings: list[CoverageFinding] = Field(default_factory=list)
    route_assessments: list[ExecutionPathAssessment] = Field(default_factory=list)
    sensitive_implementations: list[SensitiveImplementation] = Field(default_factory=list)
    discrepancies: list[ReconciliationDiscrepancy] = Field(default_factory=list)
    recommendations: list[CoverageRecommendation] = Field(default_factory=list)
    runtime_corroboration: RuntimeCorroborationSummary = Field(
        default_factory=RuntimeCorroborationSummary
    )
    reason_codes: list[CoverageReasonCode] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    artifact_reference: ArtifactReference | None = None
