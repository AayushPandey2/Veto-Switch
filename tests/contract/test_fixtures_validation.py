"""Contract tests validating every positive and negative JSON fixture in shared/fixtures/."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError
from shared.exceptions import (
    ContractValidationError,
    ExpiredApprovalError,
    InvalidApprovalError,
    KillswitchError,
)
from shared.fixtures.loader import load_fixture_file
from shared.schemas import (
    ApprovalDecision,
    ArtifactReference,
    ContainmentOption,
    ContainmentProposal,
    DeploymentEvidence,
    EvidenceReport,
    FeatureState,
    Finding,
    IncidentEvent,
    MappingResult,
    MetricSnapshot,
    OperationReceipt,
    PatchProposal,
    PatchTestResult,
    RollbackProposal,
    VerificationResult,
)
from shared.validation import validate_approval_for_proposal, validate_unique_ids


@pytest.mark.contract
def test_findings_fixtures() -> None:
    """Scenarios 21 & 22: Valid findings validate; missing evidence fails."""
    data = load_fixture_file("findings.json")
    for payload in data["valid"].values():
        Finding.model_validate(payload)
    for payload in data["invalid"].values():
        with pytest.raises(ValidationError):
            Finding.model_validate(payload)


@pytest.mark.contract
def test_mapping_fixtures() -> None:
    data = load_fixture_file("mapping.json")
    for payload in data["valid"].values():
        if "feature_name" in payload:
            FeatureState.model_validate(payload)
        else:
            MappingResult.model_validate(payload)
    for payload in data["invalid"].values():
        cls = FeatureState if "feature_name" in payload else MappingResult
        with pytest.raises(ValidationError):
            cls.model_validate(payload)


@pytest.mark.contract
def test_containment_and_approval_fixtures() -> None:
    containment = load_fixture_file("containment.json")
    proposal = ContainmentProposal.model_validate(
        containment["valid"]["valid_containment_proposal"]
    )
    assert proposal.verify_hash() is True

    ContainmentOption.model_validate(containment["valid"]["infeasible_replacement_option"])
    for opt in containment["valid"]["multiple_containment_options"]:
        ContainmentOption.model_validate(opt)
    OperationReceipt.model_validate(containment["valid"]["rejected_operation_receipt"])

    for bad_proposal in containment["invalid"].values():
        with pytest.raises(ValidationError):
            ContainmentProposal.model_validate(bad_proposal)

    approvals = load_fixture_file("approvals.json")
    ref_time = datetime.fromisoformat(
        approvals["_meta"]["evaluation_reference_time"].replace("Z", "+00:00")
    ).astimezone(UTC)

    valid_appr = ApprovalDecision.model_validate(approvals["valid"]["valid_approval"])
    validate_approval_for_proposal(proposal, valid_appr, reference_time=ref_time)

    rejected_appr = ApprovalDecision.model_validate(approvals["valid"]["rejected_approval"])
    with pytest.raises(InvalidApprovalError):
        validate_approval_for_proposal(proposal, rejected_appr, reference_time=ref_time)

    expired_appr = ApprovalDecision.model_validate(
        approvals["negative_cross_checks"]["expired_approval"]
    )
    with pytest.raises(ExpiredApprovalError):
        validate_approval_for_proposal(proposal, expired_appr, reference_time=ref_time)

    mismatch_appr = ApprovalDecision.model_validate(
        approvals["negative_cross_checks"]["mismatched_proposal_hash"]
    )
    with pytest.raises(InvalidApprovalError):
        validate_approval_for_proposal(proposal, mismatch_appr, reference_time=ref_time)

    dup_apprs = [
        ApprovalDecision.model_validate(item)
        for item in approvals["negative_cross_checks"]["duplicate_approval_request"]
    ]
    with pytest.raises(ContractValidationError):
        validate_unique_ids([a.approval_id for a in dup_apprs], field_name="approval_id")


@pytest.mark.contract
def test_verification_patch_recovery_and_evidence_fixtures() -> None:
    verification = load_fixture_file("verification.json")
    for payload in verification["valid"].values():
        VerificationResult.model_validate(payload)
    for payload in verification["invalid"].values():
        with pytest.raises(ValidationError):
            VerificationResult.model_validate(payload)

    patches = load_fixture_file("patches.json")
    PatchProposal.model_validate(patches["valid"]["reference_candidate_patch"])
    for key in (
        "valid_patch_test_result",
        "failed_functional_test_result",
        "failed_security_test_result",
        "revision_mismatch_result",
        "infrastructure_timeout_result",
    ):
        res = PatchTestResult.model_validate(patches["valid"][key])
        if key == "revision_mismatch_result":
            assert res.has_revision_mismatch is True
            assert res.is_trusted_pass is False

    with pytest.raises((ValidationError, KillswitchError)):
        PatchProposal.model_validate(patches["invalid"]["path_outside_allowlist"])
    with pytest.raises(ValidationError):
        PatchTestResult.model_validate(
            patches["invalid"]["security_pass_overriding_functional_fail"]
        )

    recovery = load_fixture_file("recovery.json")
    for key in ("verified_deployment", "missing_deployment"):
        DeploymentEvidence.model_validate(recovery["valid"][key])
    for key in (
        "healthy_synthetic_telemetry",
        "unhealthy_synthetic_telemetry",
        "insufficient_request_sample",
        "missing_baseline_telemetry",
    ):
        MetricSnapshot.model_validate(recovery["valid"][key])
    for key in ("rollback_proposal", "unknown_last_safe_state_rollback"):
        RollbackProposal.model_validate(recovery["valid"][key])
    for bad_recovery in recovery["invalid"].values():
        cls = MetricSnapshot if "snapshot_id" in bad_recovery else RollbackProposal
        with pytest.raises(ValidationError):
            cls.model_validate(bad_recovery)

    evidence = load_fixture_file("evidence.json")
    for event_payload in evidence["valid"]["complete_synthetic_timeline"]:
        IncidentEvent.model_validate(event_payload)
    EvidenceReport.model_validate(evidence["valid"]["incomplete_timeline_report"])
    ArtifactReference.model_validate(evidence["valid"]["redacted_artifact_metadata"])

    with pytest.raises((ValidationError, KillswitchError)):
        ArtifactReference.model_validate(evidence["invalid"]["invalid_artifact_hash"])
    with pytest.raises(ValidationError):
        EvidenceReport.model_validate(
            evidence["invalid"]["complete_report_with_missing_evidence"]
        )
