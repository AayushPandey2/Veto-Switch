"""Tests for IncidentOrchestrator rollback lifecycle, guards, demos, and evaluator."""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest
from agent_core.context import EventProcessingResult, ProducerContext, TransitionContext
from agent_core.events import build_incident_event
from agent_core.incident import IncidentAggregate
from agent_core.orchestrator import IncidentOrchestrator
from agent_core.repositories.memory import InMemoryOrchestrationRepository
from remediation.evaluations.rollback_evaluator import run_rollback_evaluation
from remediation.recovery import ExecutorCapabilities, RollbackContext
from remediation.rollback_demos import (
    _NOW,
    _REV,
    _base_deployment,
    _degraded_25pct_decision,
    _feature_state,
    _safe_checkpoint_5pct,
    run_all_rollback_demos,
)
from shared.enums import (
    ActorType,
    ApprovalStatus,
    ArtifactType,
    EventType,
    EvidenceProvenance,
    IncidentState,
    OperationOutcome,
    TestExecutionStatus,
    VerificationPhase,
)
from shared.identifiers import generate_correlation_id, generate_event_id
from shared.schemas import (
    ApprovalDecision,
    ArtifactReference,
    IncidentEvent,
    OperationReceipt,
    VerificationResult,
)
from shared.serialization import sha256_text


def _seed_incident_in_rollout_pending() -> IncidentAggregate:
    return IncidentAggregate(
        incident_id="inc_demo_10",
        finding_id="fnd_demo_10",
        environment="demo-staging",
        current_state=IncidentState.ROLLOUT_PENDING,
        incident_version=5,
        mapped_flag_name="search_v2",
        source_revision=_REV,
        correlation_id=generate_correlation_id(),
        latest_event_id=generate_event_id(),
        latest_event_sequence=5,
        created_at=_NOW - timedelta(hours=1),
        updated_at=_NOW - timedelta(minutes=10),
        is_synthetic_fixture=True,
    )


class _FixedClock:
    def __init__(self, now: datetime) -> None:
        self._now = now

    def now(self) -> datetime:
        return self._now


@pytest.mark.asyncio
async def test_orchestrator_rollback_lifecycle_full_containment_and_partial() -> None:
    repo = InMemoryOrchestrationRepository()
    agg = _seed_incident_in_rollout_pending()
    init_ev = build_incident_event(
        incident_id=agg.incident_id,
        event_type=EventType.ROLLOUT_PLAN_CREATED,
        actor="release_manager",
        actor_type=ActorType.DETERMINISTIC_ENGINE,
        sequence_number=5,
        correlation_id=agg.correlation_id,
        timestamp_utc=_NOW - timedelta(minutes=10),
    )
    await repo.create_incident(
        agg,
        initial_event=init_ev,
        initial_result=EventProcessingResult(
            accepted=True,
            incident_id=agg.incident_id,
            event_id=init_ev.event_id,
            previous_state=IncidentState.PATCH_TESTED,
            current_state=IncidentState.ROLLOUT_PENDING,
            incident_version=5,
            reason_code="ROLLOUT_ELIGIBLE",
        ),
    )
    for art_id in ["art_met_25pct", "art_sec_fail", "art_post", "art_op"]:
        await repo.store_artifact(
            ArtifactReference(
                artifact_id=art_id,
                artifact_type=ArtifactType.TELEMETRY_SNAPSHOT,
                incident_id="inc_demo_10",
                content_hash=sha256_text("{}"),
                size_bytes=2,
                storage_ref=f"mem://{art_id}",
                producer="fixture_runner",
                content_type="application/json",
                provenance=EvidenceProvenance.REFERENCE_FIXTURE,
            ),
            content=b"{}",
        )

    orch = IncidentOrchestrator(
        repository=repo,
        evidence_repository=repo,
        clock=_FixedClock(_NOW),
        fixture_mode=True,
    )

    cp5 = _safe_checkpoint_5pct()
    dec25, met25 = _degraded_25pct_decision()
    sec_fail = VerificationResult(
        verification_id="ver_sec_fail",
        incident_id="inc_demo_10",
        test_id="test_demo_10",
        phase=VerificationPhase.AFTER_PATCH,
        execution_status=TestExecutionStatus.TEST_FAILED,
        passed=False,
        vulnerability_reproduced=True,
        tested_revision=_REV,
        artifact_ids=["art_sec_fail"],
        completed_at=_NOW,
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    ctx = RollbackContext(
        incident_id="inc_demo_10",
        current_observed_exposure=25,
        current_observed_feature_state=_feature_state("search_v2", True),
        target_feature="search_v2",
        environment="demo-staging",
        verified_patch_revision=_REV,
        deployment_evidence=_base_deployment(),
        rollout_decision=dec25,
        triggering_telemetry=met25,
        security_regression_result=sec_fail,
        current_legacy_feature_state=_feature_state("search_v1", False),
        executor_capabilities=ExecutorCapabilities(
            supports_boolean=True,
            supports_targeting=True,
            fallback_verified=True,
            declared_fallback_behavior="disabled_search_response",
        ),
        evaluation_timestamp=_NOW,
        fixture_mode=True,
    )

    analysis, res_prop = await orch.execute_rollback_analysis(
        incident_id="inc_demo_10",
        rollback_context=ctx,
        history=[cp5],
    )
    assert res_prop.accepted is True
    assert res_prop.current_state == IncidentState.ROLLBACK_PROPOSED
    assert analysis.proposal is not None

    # Cannot bypass approval + receipt to reach CONTAINED
    sec_pass = VerificationResult(
        verification_id="ver_post",
        incident_id="inc_demo_10",
        test_id="test_post",
        phase=VerificationPhase.AFTER_CONTAINMENT,
        execution_status=TestExecutionStatus.TEST_PASSED,
        passed=True,
        vulnerability_reproduced=False,
        tested_revision=_REV,
        artifact_ids=["art_post"],
        completed_at=_NOW,
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    bypass_res = await orch.process_event(
        IncidentEvent(
            event_id=generate_event_id(),
            incident_id="inc_demo_10",
            event_type=EventType.ROLLBACK_VERIFICATION_PASSED,
            actor="sec_verifier",
            actor_type=ActorType.SECURITY_VERIFIER,
            sequence_number=7,
            correlation_id=res_prop.incident_id,
            idempotency_token="idem_bypass",
            timestamp_utc=_NOW,
        ),
        producer_context=ProducerContext(
            producer_id="sec_verifier",
            actor_type=ActorType.SECURITY_VERIFIER,
            authenticated=True,
        ),
        transition_context=TransitionContext(
            producer_context=ProducerContext(
                producer_id="sec_verifier",
                actor_type=ActorType.SECURITY_VERIFIER,
                authenticated=True,
            ),
            rollback_proposal=analysis.proposal,
            feature_state=_feature_state("search_v2", False),
            verification_result=sec_pass,
            existing_evidence_ids={"art_post"},
        ),
    )
    assert bypass_res.accepted is False

    # Now approve with exact proposal_hash
    human = ProducerContext(
        producer_id="op_alice",
        actor_type=ActorType.HUMAN_OPERATOR,
        authenticated=True,
        provenance_mode="fixture",
    )
    appr = ApprovalDecision(
        approval_id="appr_rb_orch",
        proposal_id=analysis.proposal.proposal_id,
        proposal_hash=analysis.proposal.proposal_hash or "",
        incident_id="inc_demo_10",
        decision=ApprovalStatus.APPROVED,
        actor_id="op_alice",
        nonce="nonce_orch",
        decided_at=_NOW - timedelta(minutes=1),
        expires_at=_NOW + timedelta(minutes=15),
        authorization_context_ref="auth_orch",
    )
    inc_after_prop = await repo.get_incident("inc_demo_10")
    assert inc_after_prop is not None
    res_appr = await orch.process_event(
        IncidentEvent(
            event_id=generate_event_id(),
            incident_id="inc_demo_10",
            event_type=EventType.ROLLBACK_APPROVED,
            actor="op_alice",
            actor_type=ActorType.HUMAN_OPERATOR,
            sequence_number=inc_after_prop.latest_event_sequence + 1,
            correlation_id=inc_after_prop.correlation_id,
            idempotency_token="idem_appr_orch",
            timestamp_utc=_NOW,
        ),
        producer_context=human,
        transition_context=TransitionContext(
            producer_context=human,
            clock=_FixedClock(_NOW),
            rollback_proposal=analysis.proposal,
            approval_decision=appr,
            feature_state=_feature_state("search_v2", True),
        ),
    )
    assert res_appr.accepted is True
    assert len(res_appr.pending_requests) == 1
    assert res_appr.pending_requests[0].metadata["proposal_hash"] == analysis.proposal.proposal_hash

    rcpt = OperationReceipt(
        operation_id="op_rb_orch",
        incident_id="inc_demo_10",
        proposal_id=analysis.proposal.proposal_id,
        approval_id=appr.approval_id,
        environment="demo-staging",
        target_feature="search_v2",
        requested_state=False,
        observed_state=False,
        outcome=OperationOutcome.SUCCEEDED,
        idempotency_key="idem_op_rb_orch",
        executed_at=_NOW,
        evidence_ids=["art_op"],
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    rcpt_res, res_applied = await orch.validate_rollback_receipt(
        incident_id="inc_demo_10",
        proposal=analysis.proposal,
        approval=appr,
        receipt=rcpt,
    )
    assert rcpt_res.valid is True
    assert res_applied.accepted is True

    ver_res, res_final = await orch.complete_rollback_verification(
        incident_id="inc_demo_10",
        proposal=analysis.proposal,
        receipt=rcpt,
        management_readback=_feature_state("search_v2", False),
        security_verification=sec_pass,
        application_observed_enabled=False,
        legacy_feature_state=_feature_state("search_v1", False),
        expected_revision=_REV,
    )
    assert ver_res.full_containment_restored is True
    assert res_final.accepted is True
    assert res_final.current_state == IncidentState.CONTAINED


def test_rollback_demos_and_evaluator_pass() -> None:
    demos = run_all_rollback_demos()
    assert demos["demo_f_approval_tampering"]["allowed"] is False
    assert demos["demo_j_verified_containment_restored"]["recommended_state"] == "CONTAINED"

    report = run_rollback_evaluation(write_reports=False)
    assert report["passed_cases"] == report["total_cases"]
    assert report["unsafe_rollback_recommendations"] == 0
    assert report["unauthorized_execution_requests"] == 0
    assert report["false_rollback_success_claims"] == 0
    assert report["vulnerable_legacy_reactivations"] == 0
    assert report["deterministic_repeatability"] is True
