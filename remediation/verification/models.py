"""Typed data models for Phase 08 isolated patch verification."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import ConfigDict, Field
from shared.enums import (
    EvidenceProvenance,
    PatchVerificationReasonCode,
    TestExecutionStatus,
)
from shared.identifiers import utc_now
from shared.schemas import (
    ArtifactReference,
    Finding,
    IdentifierStr,
    KillswitchModel,
    PatchProposal,
    PatchTestResult,
    UtcDatetime,
    VerificationResult,
)

from remediation.patching.source_access import STAND_IN_TARGET


class IsolationPolicy(KillswitchModel):
    """Mandatory sandbox isolation policy enforced during patch verification."""

    require_ephemeral_sandbox: bool = True
    require_network_disabled: bool = True
    allow_local_sandbox_fallback: bool = False
    require_runtime_revision_match: bool = True
    allowed_runner_modes: tuple[str, ...] = ("docker", "ephemeral_sandbox", "fixture")
    max_run_seconds: int = Field(default=120, ge=1, le=900)


class ObservedIsolationMetadata(KillswitchModel):
    """Sandbox isolation details reported by the verification runner."""

    mode: str = Field(min_length=1)
    ephemeral: bool = False
    network_disabled: bool = False
    read_only_root: bool = False
    healthy: bool = False
    container_id: str | None = None
    allow_local_fallback: bool = False
    require_runtime_revision_match: bool | None = None


class PatchVerificationContext(KillswitchModel):
    """Authoritative inputs for verifying a candidate patch in isolation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    incident_id: IdentifierStr
    finding: Finding
    proposal: PatchProposal
    source_target: str = Field(default=STAND_IN_TARGET.target_id, min_length=1)
    authoritative_base_revision: str = Field(min_length=1)
    expected_patched_revision: str | None = None
    required_security_tests: list[str] = Field(default_factory=list)
    required_functional_tests: list[str] = Field(default_factory=list)
    required_negative_input_tests: list[str] = Field(default_factory=list)
    required_smoke_tests: list[str] = Field(default_factory=list)
    known_test_ids: set[str] | None = None
    isolation_policy: IsolationPolicy = Field(default_factory=IsolationPolicy)
    fixture_mode: bool = False
    allowed_files: list[str] = Field(default_factory=list)
    candidate_artifact: ArtifactReference | None = None
    candidate_diff_bytes: bytes | None = None
    sandbox_target: str | None = None


class TestPlanCompleteness(KillswitchModel):
    """Deterministic assessment of mandatory verification test coverage."""

    complete: bool
    required_test_ids: list[str] = Field(default_factory=list)
    executed_test_ids: list[str] = Field(default_factory=list)
    missing_test_ids: list[str] = Field(default_factory=list)
    unknown_test_ids: list[str] = Field(default_factory=list)
    missing_categories: list[str] = Field(default_factory=list)
    reason_codes: list[PatchVerificationReasonCode] = Field(default_factory=list)


class RevisionVerification(KillswitchModel):
    """Explicit 5-point revision identity verification result."""

    consistent: bool
    base_source_revision: str
    candidate_content_hash: str
    expected_patched_revision: str | None = None
    runner_computed_patched_revision: str | None = None
    runtime_observed_revision: str | None = None
    mismatches: list[str] = Field(default_factory=list)
    reason_codes: list[PatchVerificationReasonCode] = Field(default_factory=list)


class FailureFeedback(KillswitchModel):
    """Structured failure feedback returned to Phase 07 Patch Engineer on rejection."""

    patch_id: IdentifierStr
    incident_id: IdentifierStr
    retry_eligible: bool
    reason_codes: list[PatchVerificationReasonCode] = Field(default_factory=list)
    failed_tests: list[str] = Field(default_factory=list)
    missing_tests: list[str] = Field(default_factory=list)
    revision_notes: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    summary: str = Field(min_length=1)


class RecoveryHandoff(KillswitchModel):
    """Structured handoff to Phase 09 recovery orchestration.

    Explicitly separates candidate patch verification from deployment and rollout.
    """

    incident_id: IdentifierStr
    patch_id: IdentifierStr
    test_run_id: IdentifierStr
    candidate_tested: bool
    ready_for_deployment_verification: bool
    deployment_verified: Literal[False] = False
    rollout_authorized: Literal[False] = False
    tested_candidate_hash: str
    tested_source_revision: str
    patched_revision: str | None = None
    artifact_ids: list[IdentifierStr] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class VerificationAcceptanceDecision(KillswitchModel):
    """Deterministic acceptance decision over candidate, isolation, tests, and evidence."""

    accepted: bool
    overall_status: TestExecutionStatus
    target_state_recommendation: str
    reason_codes: list[PatchVerificationReasonCode] = Field(default_factory=list)
    test_plan: TestPlanCompleteness
    revision_check: RevisionVerification
    isolation_valid: bool
    evidence_valid: bool
    evidence_provenance: EvidenceProvenance
    limitations: list[str] = Field(default_factory=list)
    recovery_handoff: RecoveryHandoff | None = None
    failure_feedback: FailureFeedback | None = None


class PatchVerificationReport(KillswitchModel):
    """Complete output bundle returned by IsolatedPatchVerificationOrchestrator."""

    patch_id: IdentifierStr
    incident_id: IdentifierStr
    source_target: str
    candidate_tested: bool
    decision: VerificationAcceptanceDecision
    patch_test_result: PatchTestResult | None = None
    verification_result: VerificationResult | None = None
    artifacts: list[ArtifactReference] = Field(default_factory=list)
    generated_at: UtcDatetime


def compute_expected_patched_revision(base_revision: str, candidate_hash: str) -> str:
    """Compute a deterministic expected patched revision tag from base + candidate hash."""
    return f"{base_revision}@{candidate_hash[:12]}"


def now_utc() -> datetime:
    """Return timezone-aware UTC timestamp helper."""
    return utc_now()
