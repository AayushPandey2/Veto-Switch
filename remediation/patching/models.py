"""Typed models for Phase 07 Evidence-Grounded AI Patch Engineer."""

from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict, Field, StrictBool, StrictInt
from shared.enums import (
    EvidenceProvenance,
    PatchRejectionReason,
    VulnerabilityCategory,
)
from shared.identifiers import utc_now
from shared.schemas import (
    ArtifactReference,
    Finding,
    KillswitchModel,
    PatchProposal,
    UtcDatetime,
    VerificationResult,
)


class PatchLimitsConfig(KillswitchModel):
    """Configurable bounds preventing oversized context or runaway patches."""

    maximum_source_files: StrictInt = Field(default=5, ge=1, le=50)
    maximum_source_bytes: StrictInt = Field(default=64_000, ge=256, le=500_000)
    maximum_excerpt_lines: StrictInt = Field(default=120, ge=10, le=1000)
    maximum_input_tokens: StrictInt = Field(default=6000, ge=256, le=200_000)
    maximum_output_tokens: StrictInt = Field(default=1500, ge=64, le=32_000)
    maximum_generation_attempts: StrictInt = Field(default=2, ge=1, le=5)
    maximum_repair_attempts: StrictInt = Field(default=2, ge=0, le=5)
    maximum_patch_bytes: StrictInt = Field(default=16_384, ge=128, le=200_000)
    maximum_changed_files: StrictInt = Field(default=3, ge=1, le=20)
    maximum_changed_lines: StrictInt = Field(default=80, ge=1, le=1000)
    maximum_hunks: StrictInt = Field(default=10, ge=1, le=100)
    provider_timeout_seconds: float = Field(default=30.0, gt=0.0, le=300.0)


class PatchTargetDescriptor(KillswitchModel):
    """Authoritative descriptor distinguishing registered demonstration applications."""

    target_id: str = Field(min_length=1)
    application_id: str = Field(min_length=1)
    source_root: str = Field(min_length=1)
    source_revision: str = Field(min_length=1)
    revision_namespace: Literal["tree_sha256", "git_commit", "fixture_revision"] = "tree_sha256"
    allowed_files: list[str] = Field(min_length=1)
    contract_version: str = Field(min_length=1)
    supported_categories: list[VulnerabilityCategory] = Field(default_factory=list)
    registered_test_ids: list[str] = Field(default_factory=list)
    sandbox_supported: StrictBool = False
    environment: str = Field(default="demo-staging", min_length=1)


class SourceSnapshot(KillswitchModel):
    """Immutable, revision-bound read-only snapshot of authorized source files."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=False)

    target_id: str = Field(min_length=1)
    source_revision: str = Field(min_length=1)
    revision_namespace: str = Field(min_length=1)
    snapshot_fingerprint: str = Field(min_length=1)
    files: dict[str, str] = Field(default_factory=dict)
    file_hashes: dict[str, str] = Field(default_factory=dict)


class SourceExcerpt(KillswitchModel):
    """Bounded source excerpt with deterministic provenance and inclusion rationale."""

    file_path: str = Field(min_length=1)
    start_line: StrictInt = Field(ge=1)
    end_line: StrictInt = Field(ge=1)
    symbol_name: str | None = None
    content: str = Field(min_length=1)
    inclusion_reason: str = Field(min_length=1)


class LocalizationResult(KillswitchModel):
    """Outcome of bounded static AST source localization."""

    outcome: Literal[
        "exact_function_match",
        "verified_source_location",
        "component_source_match",
        "multiple_candidate_locations",
        "source_unavailable",
        "source_revision_mismatch",
        "manual_review_required",
    ]
    file_path: str | None = None
    function_name: str | None = None
    candidate_locations: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class PatchGenerationContext(KillswitchModel):
    """Typed context separating trusted metadata from untrusted source/finding text."""

    finding: Finding
    incident_id: str = Field(min_length=1)
    containment_verification: VerificationResult | None = None
    reproduction_evidence: list[ArtifactReference] = Field(default_factory=list)
    registered_test_id: str | None = None
    target_descriptor: PatchTargetDescriptor
    source_snapshot: SourceSnapshot
    relevant_source_excerpts: list[SourceExcerpt] = Field(default_factory=list)
    localization: LocalizationResult
    affected_component: str = Field(min_length=1)
    affected_implementation: str | None = None
    required_test_ids: list[str] = Field(default_factory=list)
    remediation_constraints: list[str] = Field(default_factory=list)
    fixture_mode: StrictBool = False
    provenance: EvidenceProvenance = EvidenceProvenance.DETERMINISTIC_REASONING
    evaluation_timestamp: UtcDatetime = Field(default_factory=utc_now)


class LLMGeneratedPatchCandidate(KillswitchModel):
    """Strictly validated intermediate structured response from LLM (never authoritative)."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=False)

    unified_diff: str = Field(min_length=1)
    technical_rationale: str = Field(min_length=1)
    claimed_touched_files: list[str] = Field(default_factory=list)
    expected_behavior_changes: list[str] = Field(default_factory=list)
    potential_regressions: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    suggested_test_ids: list[str] = Field(default_factory=list)
    source_references: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class ParsedHunk(KillswitchModel):
    """Single parsed unified-diff hunk."""

    model_config = ConfigDict(extra="forbid", frozen=True, str_strip_whitespace=False)

    old_start: StrictInt = Field(ge=0)
    old_count: StrictInt = Field(ge=0)
    new_start: StrictInt = Field(ge=0)
    new_count: StrictInt = Field(ge=0)
    lines: list[str] = Field(default_factory=list)


class ParsedFileDiff(KillswitchModel):
    """Parsed unified diff for a single relative file."""

    old_path: str = Field(min_length=1)
    new_path: str = Field(min_length=1)
    hunks: list[ParsedHunk] = Field(min_length=1)


class ParsedUnifiedDiff(KillswitchModel):
    """Complete parsed unified diff with derived touched files."""

    files: list[ParsedFileDiff] = Field(min_length=1)
    actual_touched_files: list[str] = Field(min_length=1)
    added_lines: StrictInt = Field(ge=0)
    removed_lines: StrictInt = Field(ge=0)
    total_hunks: StrictInt = Field(ge=1)


class MinimalityMetrics(KillswitchModel):
    """Explainable minimality metrics for a validated candidate patch."""

    modified_file_count: StrictInt = Field(ge=1)
    added_line_count: StrictInt = Field(ge=0)
    removed_line_count: StrictInt = Field(ge=0)
    modified_line_count: StrictInt = Field(ge=0)
    hunk_count: StrictInt = Field(ge=1)
    affected_function_count: StrictInt = Field(ge=0)


class TestPlan(KillswitchModel):
    """Required Phase 08 verification plan derived from trusted test registry."""

    mandatory_registered_tests: list[str] = Field(default_factory=list)
    optional_registered_tests: list[str] = Field(default_factory=list)
    suggested_unimplemented_tests: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class ReviewerChecklist(KillswitchModel):
    """Structured human-review checklist for every accepted candidate patch."""

    security_review: list[str] = Field(default_factory=list)
    functional_review: list[str] = Field(default_factory=list)
    source_review: list[str] = Field(default_factory=list)
    verification_review: list[str] = Field(default_factory=list)
    recovery_review: list[str] = Field(default_factory=list)


class PatchGenerationOutcome(KillswitchModel):
    """Complete deterministic outcome of Phase 07 candidate patch generation."""

    accepted: StrictBool
    proposal: PatchProposal | None = None
    artifact_reference: ArtifactReference | None = None
    candidate_manifest_fingerprint: str | None = None
    test_plan: TestPlan = Field(default_factory=TestPlan)
    checklist: ReviewerChecklist | None = None
    pr_summary_markdown: str | None = None
    minimality: MinimalityMetrics | None = None
    rejection_reasons: list[PatchRejectionReason] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    sandbox_ready: StrictBool = False
    manual_review_required: StrictBool = True
