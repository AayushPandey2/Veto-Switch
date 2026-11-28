"""Unit tests for core incident, mapping, graph, containment, approval, and verification schemas."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError
from shared.enums import (
    ActorType,
    ContainmentStrategyType,
    EventType,
    EvidenceProvenance,
    FeatureObservationStatus,
    FindingStatus,
    GraphEdgeType,
    GraphNodeType,
    MappingStatus,
    OperationOutcome,
    TestExecutionStatus,
    VerificationPhase,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.exceptions import ExpiredApprovalError, InvalidApprovalError
from shared.schemas import (
    ContainmentOption,
    ContainmentProposal,
    DependencyGraph,
    FeatureState,
    Finding,
    GraphEdge,
    GraphNode,
    IncidentEvent,
    InvestigationSummary,
    MappingResult,
    OperationReceipt,
    VerificationResult,
)
from shared.serialization import from_json, to_json
from shared.validation import validate_approval_for_proposal


@pytest.mark.unit
def test_valid_finding_and_reproduced_evidence_requirement() -> None:
    """Scenarios 2 & 4: Valid Finding accepted; reproduced without evidence rejected."""
    valid = Finding(
        finding_id="fnd_0001",
        incident_id="inc_0001",
        category=VulnerabilityCategory.SQL_INJECTION,
        affected_route="/search",
        affected_component="search_service",
        severity=VulnerabilitySeverity.CRITICAL,
        status=FindingStatus.REPRODUCED,
        evidence_ids=["art_0001"],
    )
    assert valid.status == FindingStatus.REPRODUCED

    unknown_route_suspected = Finding(
        finding_id="fnd_0002",
        incident_id="inc_0001",
        category=VulnerabilityCategory.OTHER,
        affected_route=None,
        affected_component="worker",
        severity=VulnerabilitySeverity.UNKNOWN,
        status=FindingStatus.SUSPECTED,
    )
    assert unknown_route_suspected.affected_route is None

    with pytest.raises(ValidationError):
        Finding(
            finding_id="fnd_0003",
            incident_id="inc_0001",
            category=VulnerabilityCategory.SQL_INJECTION,
            affected_route="/search",
            affected_component="search_service",
            severity=VulnerabilitySeverity.HIGH,
            status=FindingStatus.REPRODUCED,
            evidence_ids=[],
        )


@pytest.mark.unit
def test_mutable_defaults_not_shared_between_instances() -> None:
    """Scenario 6: List/dict defaults must be isolated per model instance."""
    inv1 = InvestigationSummary(
        investigation_id="inv_0001",
        finding_id="fnd_0001",
        incident_id="inc_0001",
        executive_summary="Summary 1",
        technical_explanation="Details 1",
        recommended_next_action="Map flag",
    )
    inv2 = InvestigationSummary(
        investigation_id="inv_0002",
        finding_id="fnd_0002",
        incident_id="inc_0002",
        executive_summary="Summary 2",
        technical_explanation="Details 2",
        recommended_next_action="Map flag",
    )
    inv1.verified_facts.append("Only in inv1")
    inv1.evidence_ids.append("art_only_1")
    assert inv2.verified_facts == []
    assert inv2.evidence_ids == []


@pytest.mark.unit
def test_mapping_result_prevents_ambiguous_or_unmapped_masquerading() -> None:
    matched = MappingResult(
        finding_id="fnd_0001",
        mapping_status=MappingStatus.MATCHED,
        affected_route="/search",
        matched_component="search_service",
        candidate_flags=["search_v1"],
        selected_flag="search_v1",
        registry_version="1.0.0",
        mapping_rationale="Exact route match.",
    )
    assert matched.selected_flag == "search_v1"

    with pytest.raises(ValidationError):
        MappingResult(
            finding_id="fnd_0001",
            mapping_status=MappingStatus.AMBIGUOUS,
            candidate_flags=["search_v1", "search_v2"],
            selected_flag="search_v1",
            registry_version="1.0.0",
            mapping_rationale="Should fail because ambiguous cannot set selected_flag.",
            manual_review_required=True,
        )

    with pytest.raises(ValidationError):
        MappingResult(
            finding_id="fnd_0001",
            mapping_status=MappingStatus.UNMAPPED,
            candidate_flags=[],
            selected_flag=None,
            registry_version="1.0.0",
            mapping_rationale="Should fail when manual_review_required is False.",
            manual_review_required=False,
        )


@pytest.mark.unit
def test_feature_state_distinguishes_unknown_from_disabled() -> None:
    unknown_state = FeatureState(
        environment="demo-staging",
        feature_id="fs_001",
        feature_name="search_v1",
        observation_status=FeatureObservationStatus.UNKNOWN,
        enabled=None,
    )
    assert unknown_state.enabled is None

    with pytest.raises(ValidationError):
        FeatureState(
            environment="demo-staging",
            feature_id="fs_001",
            feature_name="search_v1",
            observation_status=FeatureObservationStatus.UNAVAILABLE,
            enabled=False,
        )


@pytest.mark.unit
def test_operation_receipt_rejects_llm_provenance_and_unconfirmed_success() -> None:
    with pytest.raises(ValidationError):
        OperationReceipt(
            operation_id="op_0001",
            incident_id="inc_0001",
            proposal_id="prop_0001",
            approval_id="appr_0001",
            environment="demo-staging",
            target_feature="search_v1",
            requested_state=False,
            observed_state=False,
            outcome=OperationOutcome.SUCCEEDED,
            idempotency_key="idem_0001",
            provenance=EvidenceProvenance.LLM_INTERPRETATION,
        )

    with pytest.raises(ValidationError):
        OperationReceipt(
            operation_id="op_0002",
            incident_id="inc_0001",
            proposal_id="prop_0001",
            approval_id="appr_0001",
            environment="demo-staging",
            target_feature="search_v1",
            requested_state=False,
            observed_state=True,
            outcome=OperationOutcome.SUCCEEDED,
            idempotency_key="idem_0002",
            provenance=EvidenceProvenance.EXTERNAL_OPERATION_RECEIPT,
        )


@pytest.mark.unit
def test_approval_validation_detects_mismatched_hash_and_expiration(
    sample_containment_proposal: ContainmentProposal,
    sample_approval_factory,
) -> None:
    """Scenario 16: Invalid approval relationships fail deterministically."""
    eval_time = sample_containment_proposal.created_at + timedelta(minutes=2)
    good_approval = sample_approval_factory(sample_containment_proposal)
    validate_approval_for_proposal(
        sample_containment_proposal, good_approval, reference_time=eval_time
    )

    bad_hash_approval = sample_approval_factory(
        sample_containment_proposal,
        proposal_hash="a" * 64,
    )
    with pytest.raises(InvalidApprovalError):
        validate_approval_for_proposal(
            sample_containment_proposal, bad_hash_approval, reference_time=eval_time
        )

    expired_approval = sample_approval_factory(
        sample_containment_proposal,
        expires_at=sample_containment_proposal.created_at + timedelta(seconds=90),
    )
    with pytest.raises(ExpiredApprovalError):
        validate_approval_for_proposal(
            sample_containment_proposal, expired_approval, reference_time=eval_time
        )


@pytest.mark.unit
def test_verification_result_distinguishes_reproduction_from_containment() -> None:
    before = VerificationResult(
        verification_id="ver_0001",
        incident_id="inc_0001",
        test_id="sqli_search",
        phase=VerificationPhase.BEFORE_CONTAINMENT,
        execution_status=TestExecutionStatus.TEST_PASSED,
        passed=True,
        vulnerability_reproduced=True,
    )
    assert before.vulnerability_reproduced is True

    with pytest.raises(ValidationError):
        VerificationResult(
            verification_id="ver_0002",
            incident_id="inc_0001",
            test_id="sqli_search",
            phase=VerificationPhase.AFTER_CONTAINMENT,
            execution_status=TestExecutionStatus.TEST_PASSED,
            passed=True,
            vulnerability_reproduced=True,
        )

    with pytest.raises(ValidationError):
        VerificationResult(
            verification_id="ver_0003",
            incident_id="inc_0001",
            test_id="sqli_search",
            phase=VerificationPhase.AFTER_CONTAINMENT,
            execution_status=TestExecutionStatus.NOT_RUN,
            passed=True,
        )


@pytest.mark.unit
def test_dependency_graph_rejects_dangling_edges_and_infeasible_option_requires_reason() -> None:
    with pytest.raises(ValidationError):
        DependencyGraph(
            graph_version="1.0.0",
            environment="demo-staging",
            nodes=[
                GraphNode(node_id="node_a", node_type=GraphNodeType.ROUTE, label="/search")
            ],
            edges=[
                GraphEdge(
                    source_id="node_a",
                    target_id="node_missing",
                    relationship=GraphEdgeType.CALLS,
                )
            ],
        )

    with pytest.raises(ValidationError):
        ContainmentOption(
            option_id="opt_0001",
            incident_id="inc_0001",
            strategy_type=ContainmentStrategyType.SWITCH_TO_REPLACEMENT_FLAG,
            title="Switch to search_v2",
            feasible=False,
            infeasibility_reasons=[],
            estimated_disruption=0.1,
            estimated_residual_risk=0.2,
            dependency_reach=1,
            uncertainty=0.5,
            relative_policy_score=0.2,
        )


@pytest.mark.unit
def test_incident_event_typed_payload_and_roundtrip() -> None:
    event = IncidentEvent(
        event_id="evt_0001",
        incident_id="inc_0001",
        event_type=EventType.FINDING_RECEIVED,
        actor="scanner_adapter",
        actor_type=ActorType.SECURITY_SCANNER,
        timestamp_utc=datetime(2026, 11, 26, 0, 0, 0, tzinfo=UTC),
        correlation_id="corr_0001",
        sequence_number=1,
        idempotency_token="idem_0001",
        payload={
            "finding_id": "fnd_0001",
            "category": "sql_injection",
            "severity": "critical",
            "status": "reproduced",
        },
    )
    restored = from_json(IncidentEvent, to_json(event))
    assert restored == event
