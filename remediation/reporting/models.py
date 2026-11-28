"""Typed models for Phase 11 Incident Evidence Intelligence."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import Field, StrictBool, StrictInt
from shared.constants import POLICY_VERSION, SCHEMA_VERSION
from shared.enums import EvidenceProvenance, IncidentState
from shared.identifiers import utc_now
from shared.schemas import (
    ApprovalDecision,
    ArtifactReference,
    CoverageFinding,
    DeploymentEvidence,
    FeatureState,
    Finding,
    IncidentEvent,
    InvestigationSummary,
    KillswitchModel,
    MetricSnapshot,
    OperationReceipt,
    PatchProposal,
    PatchTestResult,
    RollbackProposal,
    RolloutDecision,
    RolloutPlan,
    VerificationResult,
    VerifiedSafeState,
)


class ArtifactIntegrityStatus(StrEnum):
    """Machine-readable classification of stored artifact integrity."""

    VERIFIED = "verified"
    MISSING = "missing"
    METADATA_ONLY = "metadata_only"
    CONTENT_UNAVAILABLE = "content_unavailable"
    HASH_MISMATCH = "hash_mismatch"
    SIZE_MISMATCH = "size_mismatch"
    INCIDENT_MISMATCH = "incident_mismatch"
    PROVENANCE_UNTRUSTED = "provenance_untrusted"
    ACCESS_DENIED = "access_denied"


class ArtifactIntegrityResult(KillswitchModel):
    """Integrity verification outcome for a single ArtifactReference."""

    artifact_id: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    artifact_type: str = Field(min_length=1)
    status: ArtifactIntegrityStatus
    expected_hash: str
    actual_hash: str | None = None
    expected_size_bytes: StrictInt | None = None
    actual_size_bytes: StrictInt | None = None
    provenance: EvidenceProvenance
    mandatory: StrictBool = True
    message: str = Field(min_length=1)


class ClaimEvidenceLink(KillswitchModel):
    """Structured association between a consequential claim and its supporting evidence."""

    claim_id: str = Field(min_length=1)
    claim_type: str = Field(min_length=1)
    claim_description: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    related_record_ids: list[str] = Field(default_factory=list)
    supporting_artifact_ids: list[str] = Field(default_factory=list)
    supporting_event_ids: list[str] = Field(default_factory=list)
    evidence_provenance: EvidenceProvenance = EvidenceProvenance.DETERMINISTIC_REASONING
    verification_status: str = Field(min_length=1)  # verified | unverified | contradicted | fixture
    derivation_method: str = Field(default="deterministic_rule", min_length=1)
    policy_version: str = Field(default=POLICY_VERSION, min_length=1)
    limitations: list[str] = Field(default_factory=list)


class MissingEvidenceItem(KillswitchModel):
    """Structured entry for the UNVERIFIED / INCOMPLETE EVIDENCE section."""

    missing_evidence_type: str = Field(min_length=1)
    affected_claim: str = Field(min_length=1)
    required_record: str = Field(min_length=1)
    reason: str = Field(min_length=1)
    impact: str = Field(min_length=1)
    recommended_follow_up: str = Field(min_length=1)


class SnapshotBoundary(KillswitchModel):
    """Consistent snapshot boundary for deterministic report reconstruction."""

    incident_version: StrictInt = Field(ge=1)
    maximum_event_sequence: StrictInt = Field(ge=0)
    latest_event_id: str | None = None
    artifact_manifest_version: StrictInt = Field(default=1, ge=1)
    snapshot_captured_at: datetime = Field(default_factory=utc_now)


class EvidenceReportContext(KillswitchModel):
    """Complete typed input context for IncidentEvidenceReporter."""

    incident_id: str = Field(min_length=1)
    environment: str = Field(default="unknown", min_length=1)
    incident_status: IncidentState = IncidentState.RECEIVED
    requested_report_scope: str = Field(default="full_incident_audit", min_length=1)
    accepted_events: list[IncidentEvent] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    investigation_summaries: list[InvestigationSummary] = Field(default_factory=list)
    mapping_results: list[dict[str, Any]] = Field(default_factory=list)
    blast_radius_analysis: list[dict[str, Any]] = Field(default_factory=list)
    containment_decisions: list[Any] = Field(default_factory=list)
    coverage_findings: list[CoverageFinding] = Field(default_factory=list)
    approvals: list[ApprovalDecision] = Field(default_factory=list)
    operation_receipts: list[OperationReceipt] = Field(default_factory=list)
    feature_state_observations: list[FeatureState] = Field(default_factory=list)
    verification_results: list[VerificationResult] = Field(default_factory=list)
    patch_proposals: list[PatchProposal] = Field(default_factory=list)
    patch_test_results: list[PatchTestResult] = Field(default_factory=list)
    deployment_evidence: list[DeploymentEvidence] = Field(default_factory=list)
    rollout_plans: list[RolloutPlan] = Field(default_factory=list)
    rollout_decisions: list[RolloutDecision] = Field(default_factory=list)
    metric_snapshots: list[MetricSnapshot] = Field(default_factory=list)
    verified_safe_states: list[VerifiedSafeState] = Field(default_factory=list)
    rollback_proposals: list[RollbackProposal] = Field(default_factory=list)
    rollback_results: list[dict[str, Any]] = Field(default_factory=list)
    cve_context: list[dict[str, Any]] = Field(default_factory=list)
    artifact_references: list[ArtifactReference] = Field(default_factory=list)
    artifact_contents: dict[str, bytes] = Field(default_factory=dict)
    reporting_policy_version: str = Field(default=POLICY_VERSION, min_length=1)
    schema_version: str = Field(default=SCHEMA_VERSION, min_length=1)
    snapshot_boundary: SnapshotBoundary | None = None
    generation_timestamp: datetime = Field(default_factory=utc_now)
    fixture_mode: StrictBool = False
    redaction_policy_version: str = Field(default="1.0.0", min_length=1)


class BundleFileEntry(KillswitchModel):
    """File entry in an exported evidence bundle manifest."""

    relative_path: str = Field(min_length=1)
    content_type: str = Field(min_length=1)
    size_bytes: StrictInt = Field(ge=0)
    sha256: str = Field(min_length=64, max_length=64)


class ExportManifest(KillswitchModel):
    """Deterministic manifest for an exported Markdown/JSON evidence bundle."""

    bundle_id: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    report_id: str = Field(min_length=1)
    report_schema_version: str = Field(default=SCHEMA_VERSION, min_length=1)
    reporting_policy_version: str = Field(default=POLICY_VERSION, min_length=1)
    snapshot_fingerprint: str = Field(min_length=64, max_length=64)
    maximum_event_sequence: StrictInt = Field(ge=0)
    files: list[BundleFileEntry] = Field(default_factory=list)
    source_artifact_references: list[str] = Field(default_factory=list)
    redaction_policy_version: str = Field(default="1.0.0", min_length=1)
    limitations: list[str] = Field(default_factory=list)


class BundleVerificationResult(KillswitchModel):
    """Result of verifying an exported incident evidence bundle on disk."""

    valid: StrictBool
    bundle_path: str = Field(min_length=1)
    incident_id: str | None = None
    report_id: str | None = None
    failures: list[str] = Field(default_factory=list)
    verified_files: list[str] = Field(default_factory=list)
