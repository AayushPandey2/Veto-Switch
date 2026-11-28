"""Strongly typed InvestigationContext and raw input bundle models (Section 12)."""

from __future__ import annotations

import uuid
from typing import Any, Literal

from pydantic import Field, StrictBool, StrictInt
from shared.constants import SCHEMA_VERSION
from shared.enums import EvidenceProvenance, FindingStatus, RedactionStatus, VerificationPhase
from shared.schemas import (
    ArtifactReference,
    FeatureState,
    Finding,
    KillswitchModel,
    RouteFlagRegistry,
    VerificationResult,
)
from shared.validation import validate_relative_safe_path


def _new_context_id() -> str:
    return f"ctx_{uuid.uuid4().hex[:16]}"


class SourceExcerpt(KillswitchModel):
    """Authorized bounded code excerpt supplied to investigation context."""

    file_id: str = Field(min_length=1, max_length=128)
    file_path: str = Field(min_length=1, max_length=256)
    source_revision: str | None = None
    start_line: StrictInt = Field(ge=1)
    end_line: StrictInt = Field(ge=1)
    code_excerpt: str = Field(min_length=1)
    content_hash: str = Field(min_length=16, max_length=128)
    reason_for_inclusion: str = Field(min_length=1)
    authorized: StrictBool = True

    def model_post_init(self, __context: Any) -> None:
        validate_relative_safe_path(self.file_path, field_name="file_path")


class DependencyMetadataItem(KillswitchModel):
    """Verified or supplied package dependency metadata."""

    dependency_name: str = Field(min_length=1)
    installed_version: str = Field(min_length=1)
    relevant_component: str = Field(min_length=1)
    relationship: str = Field(default="direct")
    advisory_references: list[str] = Field(default_factory=list)
    potential_applicability: str = Field(default="unknown")
    verification_limitations: list[str] = Field(default_factory=list)


class AdvisoryContextItem(KillswitchModel):
    """Normalized advisory metadata supplied by security tooling (never implies exploited)."""

    advisory_id: str = Field(min_length=1)
    cve_ids: list[str] = Field(default_factory=list)
    package_name: str = Field(min_length=1)
    affected_version_range: str = Field(default="unknown")
    summary: str = Field(min_length=1)
    reachability_confirmed: StrictBool = False
    verification_limitations: list[str] = Field(
        default_factory=lambda: [
            "Advisory version match does not establish runtime reachability or reproduction."
        ]
    )


class VerificationContextSummary(KillswitchModel):
    """Summary of authorized verification outcomes distinguishing not_run vs reproduced."""

    security_test_id: str | None = None
    test_run_id: str | None = None
    reproduction_outcome: Literal[
        "reproduced", "not_confirmed", "inconclusive", "not_run", "infrastructure_error"
    ] = "not_run"
    test_phase: VerificationPhase = VerificationPhase.BEFORE_CONTAINMENT
    environment: str | None = None
    tested_revision: str | None = None
    verification_timestamp: str | None = None
    artifact_references: list[str] = Field(default_factory=list)
    known_limitations: list[str] = Field(default_factory=list)
    conflicting_outcomes: StrictBool = False
    observed_outcomes: list[str] = Field(default_factory=list)


class ExcludedContextItem(KillswitchModel):
    """Explicit record of an input rejected during Stage 2 validation or budget reduction."""

    item_id: str = Field(min_length=1)
    item_kind: str = Field(min_length=1)
    reason_code: str = Field(min_length=1)
    reason: str = Field(min_length=1)


class ContextAuditMetadata(KillswitchModel):
    """Stage 10 audit trail capturing hashing, exclusion, redaction, and token budgeting."""

    context_version: str = SCHEMA_VERSION
    context_hash: str = Field(min_length=64, max_length=64)
    included_evidence_ids: list[str] = Field(default_factory=list)
    excluded_items: list[ExcludedContextItem] = Field(default_factory=list)
    redaction_status: RedactionStatus = RedactionStatus.NOT_REQUIRED
    redacted_fields_count: StrictInt = Field(default=0, ge=0)
    truncated: StrictBool = False
    truncation_reasons: list[str] = Field(default_factory=list)
    estimated_tokens: StrictInt = Field(default=0, ge=0)
    measured_tokens: StrictInt | None = Field(default=None, ge=0)
    token_count_source: Literal["measured", "estimated"] = "estimated"
    pre_reduction_tokens: StrictInt = Field(default=0, ge=0)
    post_reduction_tokens: StrictInt = Field(default=0, ge=0)


class InvestigationInputBundle(KillswitchModel):
    """Normalized raw inputs collected prior to the 10-stage ContextBuilder pipeline."""

    finding: Finding
    verification_results: list[VerificationResult] = Field(default_factory=list)
    verification_environments: dict[str, str] = Field(default_factory=dict)
    evidence_artifacts: list[ArtifactReference] = Field(default_factory=list)
    artifact_environments: dict[str, str] = Field(default_factory=dict)
    evidence_summaries: dict[str, str] = Field(default_factory=dict)
    source_excerpts: list[SourceExcerpt] = Field(default_factory=list)
    dependencies: list[DependencyMetadataItem] = Field(default_factory=list)
    advisories: list[AdvisoryContextItem] = Field(default_factory=list)
    declared_features: list[FeatureState] = Field(default_factory=list)
    route_registry: RouteFlagRegistry | None = None
    application_manifest_summary: dict[str, Any] = Field(default_factory=dict)
    optional_notes: list[str] = Field(default_factory=list)
    authorized_source_paths: set[str] | None = None
    has_deployment_evidence: StrictBool = False
    has_containment_evidence: StrictBool = False


class InvestigationContext(KillswitchModel):
    """Bounded, sanitized, incident-scoped investigation context ready for model + grounding."""

    context_id: str = Field(default_factory=_new_context_id)
    incident_id: str
    finding: Finding
    affected_route: str | None = None
    affected_component: str
    repository_revision: str | None = None
    environment: str | None = None
    verification_summary: VerificationContextSummary
    evidence_references: list[ArtifactReference] = Field(default_factory=list)
    evidence_summaries: dict[str, str] = Field(default_factory=dict)
    bounded_source_excerpts: list[SourceExcerpt] = Field(default_factory=list)
    dependency_metadata: list[DependencyMetadataItem] = Field(default_factory=list)
    advisory_context: list[AdvisoryContextItem] = Field(default_factory=list)
    declared_feature_registry_summary: list[str] = Field(default_factory=list)
    application_manifest_summary: dict[str, Any] = Field(default_factory=dict)
    known_limitations: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    excluded_items: list[ExcludedContextItem] = Field(default_factory=list)
    context_version: str = SCHEMA_VERSION
    context_hash: str = Field(default="", max_length=64)
    data_provenance: list[EvidenceProvenance] = Field(default_factory=list)
    has_deployment_evidence: StrictBool = False
    has_containment_evidence: StrictBool = False
    audit: ContextAuditMetadata | None = None

    def allowed_evidence_ids(self) -> set[str]:
        """Return exact set of verified incident-scoped evidence IDs supplied to investigation."""
        ids = {art.artifact_id for art in self.evidence_references}
        ids.update(self.verification_summary.artifact_references)
        if self.finding.status == FindingStatus.REPRODUCED or self.finding.evidence_ids:
            # Only IDs that survived Stage 2 filtering (exclude explicitly rejected IDs).
            rejected = {ex.item_id for ex in self.excluded_items}
            for eid in self.finding.evidence_ids:
                if eid not in rejected:
                    ids.add(eid)
        return ids

    def excluded_ids_by_reason(self) -> dict[str, str]:
        return {ex.item_id: ex.reason_code for ex in self.excluded_items}

    def allowed_file_paths(self) -> set[str]:
        return {ex.file_path for ex in self.bounded_source_excerpts}

    def allowed_source_excerpt_ids(self) -> set[str]:
        return {ex.file_id for ex in self.bounded_source_excerpts}

    def allowed_cves(self) -> set[str]:
        cves = {c.upper() for c in self.finding.cve_ids}
        for adv in self.advisory_context:
            cves.update(c.upper() for c in adv.cve_ids)
        return cves

    def to_prompt_payload(self) -> dict[str, Any]:
        """Serialize context deterministically for bounded LLM consumption."""
        return {
            "context_id": self.context_id,
            "incident_id": self.incident_id,
            "environment": self.environment,
            "repository_revision": self.repository_revision,
            "finding": {
                "finding_id": self.finding.finding_id,
                "category": self.finding.category.value,
                "status": self.finding.status.value,
                "severity": self.finding.severity.value,
                "affected_component": self.finding.affected_component,
                "affected_route": self.finding.affected_route,
                "cve_ids": self.finding.cve_ids,
                "observed_impact": self.finding.observed_impact,
                "evidence_ids": self.finding.evidence_ids,
            },
            "verification_summary": self.verification_summary.model_dump(mode="json"),
            "evidence_references": [
                {
                    "artifact_id": art.artifact_id,
                    "artifact_type": art.artifact_type.value,
                    "provenance": art.provenance.value,
                    "content_hash": art.content_hash,
                    "source_revision": art.source_revision,
                    "summary": self.evidence_summaries.get(art.artifact_id, ""),
                }
                for art in self.evidence_references
            ],
            "bounded_source_excerpts": [
                ex.model_dump(mode="json") for ex in self.bounded_source_excerpts
            ],
            "dependency_metadata": [d.model_dump(mode="json") for d in self.dependency_metadata],
            "advisory_context": [a.model_dump(mode="json") for a in self.advisory_context],
            "declared_feature_registry_summary": list(self.declared_feature_registry_summary),
            "application_manifest_summary": dict(self.application_manifest_summary),
            "known_limitations": list(self.known_limitations),
            "missing_information": list(self.missing_information),
            "has_deployment_evidence": self.has_deployment_evidence,
            "has_containment_evidence": self.has_containment_evidence,
        }
