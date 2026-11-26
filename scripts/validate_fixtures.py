"""CLI script validating configuration fixtures and shared/fixtures JSON contracts."""

from __future__ import annotations

import sys
from datetime import UTC, datetime

from pydantic import ValidationError
from shared.config import load_dependency_graph, load_rollout_policy, load_route_registry
from shared.exceptions import ExpiredApprovalError, InvalidApprovalError, KillswitchError
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


def main() -> int:
    """Validate all configuration files, positive fixtures, and negative fixtures."""
    # 1. Config files
    registry = load_route_registry()
    graph = load_dependency_graph()
    policy = load_rollout_policy()
    print(
        f"[OK] Config loaded: registry={registry.registry_version}, "
        f"graph_nodes={len(graph.nodes)}, policy_stages={policy.stages_percent}"
    )

    # 2. Findings
    findings = load_fixture_file("findings.json")
    for name, payload in findings["valid"].items():
        Finding.model_validate(payload)
        print(f"[OK] findings.valid.{name}")
    for name, payload in findings["invalid"].items():
        try:
            Finding.model_validate(payload)
        except ValidationError:
            print(f"[OK] findings.invalid.{name} rejected as expected")
        else:
            raise AssertionError(f"Expected findings.invalid.{name} to fail validation")

    # 3. Mapping
    mapping = load_fixture_file("mapping.json")
    for name, payload in mapping["valid"].items():
        if "feature_name" in payload:
            FeatureState.model_validate(payload)
        else:
            MappingResult.model_validate(payload)
        print(f"[OK] mapping.valid.{name}")
    for name, payload in mapping["invalid"].items():
        model_cls = FeatureState if "feature_name" in payload else MappingResult
        try:
            model_cls.model_validate(payload)
        except ValidationError:
            print(f"[OK] mapping.invalid.{name} rejected as expected")
        else:
            raise AssertionError(f"Expected mapping.invalid.{name} to fail validation")

    # 4. Containment
    containment = load_fixture_file("containment.json")
    proposal = ContainmentProposal.model_validate(
        containment["valid"]["valid_containment_proposal"]
    )
    assert proposal.verify_hash(), "valid_containment_proposal hash mismatch"
    ContainmentOption.model_validate(containment["valid"]["infeasible_replacement_option"])
    for opt in containment["valid"]["multiple_containment_options"]:
        ContainmentOption.model_validate(opt)
    OperationReceipt.model_validate(containment["valid"]["rejected_operation_receipt"])
    for name, payload in containment["invalid"].items():
        try:
            ContainmentProposal.model_validate(payload)
        except ValidationError:
            print(f"[OK] containment.invalid.{name} rejected as expected")
        else:
            raise AssertionError(f"Expected containment.invalid.{name} to fail validation")

    # 5. Approvals & cross-checks
    approvals = load_fixture_file("approvals.json")
    ref_time = datetime.fromisoformat(
        approvals["_meta"]["evaluation_reference_time"].replace("Z", "+00:00")
    ).astimezone(UTC)
    valid_appr = ApprovalDecision.model_validate(approvals["valid"]["valid_approval"])
    validate_approval_for_proposal(proposal, valid_appr, reference_time=ref_time)
    ApprovalDecision.model_validate(approvals["valid"]["rejected_approval"])

    expired_appr = ApprovalDecision.model_validate(
        approvals["negative_cross_checks"]["expired_approval"]
    )
    try:
        validate_approval_for_proposal(proposal, expired_appr, reference_time=ref_time)
    except ExpiredApprovalError:
        print("[OK] approvals.negative_cross_checks.expired_approval rejected as expected")
    else:
        raise AssertionError("Expected expired_approval to raise ExpiredApprovalError")

    mismatch_appr = ApprovalDecision.model_validate(
        approvals["negative_cross_checks"]["mismatched_proposal_hash"]
    )
    try:
        validate_approval_for_proposal(proposal, mismatch_appr, reference_time=ref_time)
    except InvalidApprovalError:
        print("[OK] approvals.negative_cross_checks.mismatched_proposal_hash rejected as expected")
    else:
        raise AssertionError("Expected mismatched_proposal_hash to raise InvalidApprovalError")

    dup_apprs = [
        ApprovalDecision.model_validate(item)
        for item in approvals["negative_cross_checks"]["duplicate_approval_request"]
    ]
    try:
        validate_unique_ids([a.approval_id for a in dup_apprs], field_name="approval_id")
    except KillswitchError:
        print(
            "[OK] approvals.negative_cross_checks.duplicate_approval_request rejected as expected"
        )
    else:
        raise AssertionError("Expected duplicate approval IDs to fail uniqueness check")

    # 6. Verification
    verification = load_fixture_file("verification.json")
    for name, payload in verification["valid"].items():
        VerificationResult.model_validate(payload)
        print(f"[OK] verification.valid.{name}")
    for name, payload in verification["invalid"].items():
        try:
            VerificationResult.model_validate(payload)
        except ValidationError:
            print(f"[OK] verification.invalid.{name} rejected as expected")
        else:
            raise AssertionError(f"Expected verification.invalid.{name} to fail validation")

    # 7. Patches
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
            assert res.has_revision_mismatch and not res.is_trusted_pass
        print(f"[OK] patches.valid.{key}")
    try:
        PatchProposal.model_validate(patches["invalid"]["path_outside_allowlist"])
    except (ValidationError, KillswitchError):
        print("[OK] patches.invalid.path_outside_allowlist rejected as expected")
    else:
        raise AssertionError("Expected path_outside_allowlist to fail")
    try:
        PatchTestResult.model_validate(patches["invalid"]["security_pass_overriding_functional_fail"])
    except ValidationError:
        print("[OK] patches.invalid.security_pass_overriding_functional_fail rejected as expected")
    else:
        raise AssertionError("Expected security_pass_overriding_functional_fail to fail")

    # 8. Recovery
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
    try:
        MetricSnapshot.model_validate(recovery["invalid"]["failed_exceeds_total_requests"])
    except ValidationError:
        print("[OK] recovery.invalid.failed_exceeds_total_requests rejected as expected")
    else:
        raise AssertionError("Expected failed_exceeds_total_requests to fail")
    try:
        RollbackProposal.model_validate(recovery["invalid"]["unknown_safe_state_without_manual_review"])
    except ValidationError:
        print("[OK] recovery.invalid.unknown_safe_state_without_manual_review rejected as expected")
    else:
        raise AssertionError("Expected unknown_safe_state_without_manual_review to fail")

    # 9. Evidence
    evidence = load_fixture_file("evidence.json")
    for event_payload in evidence["valid"]["complete_synthetic_timeline"]:
        IncidentEvent.model_validate(event_payload)
    EvidenceReport.model_validate(evidence["valid"]["incomplete_timeline_report"])
    ArtifactReference.model_validate(evidence["valid"]["redacted_artifact_metadata"])
    try:
        ArtifactReference.model_validate(evidence["invalid"]["invalid_artifact_hash"])
    except (ValidationError, KillswitchError):
        print("[OK] evidence.invalid.invalid_artifact_hash rejected as expected")
    else:
        raise AssertionError("Expected invalid_artifact_hash to fail")
    try:
        EvidenceReport.model_validate(evidence["invalid"]["complete_report_with_missing_evidence"])
    except ValidationError:
        print("[OK] evidence.invalid.complete_report_with_missing_evidence rejected as expected")
    else:
        raise AssertionError("Expected complete_report_with_missing_evidence to fail")

    print("All configuration and fixture validations passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
