"""Orchestration & guard integration tests for Phase 08 patch verification."""

from __future__ import annotations

import pytest
from agent_core.context import (
    EventProcessingResult,
    ProducerContext,
    SystemClock,
    TransitionContext,
)
from agent_core.events import build_incident_event
from agent_core.guards import guard_patch_verification
from agent_core.incident import IncidentAggregate
from agent_core.orchestrator import IncidentOrchestrator
from agent_core.repositories.memory import InMemoryOrchestrationRepository
from remediation.adapters.fixture_runner import FixturePatchTestRunner
from remediation.patching.source_access import STAND_IN_TARGET
from remediation.verification_demos import _base_context
from shared.enums import (
    ActorType,
    EventType,
    EvidenceProvenance,
    IncidentState,
    TestExecutionStatus,
)
from shared.identifiers import utc_now
from shared.schemas import IndividualTestOutcome, PatchTestResult


async def _seed_patch_pending_orchestrator() -> tuple[
    IncidentOrchestrator,
    str,
    ProducerContext,
]:
    repo = InMemoryOrchestrationRepository()
    clock = SystemClock()
    orch = IncidentOrchestrator(
        repository=repo,
        evidence_repository=repo,
        clock=clock,
        fixture_mode=True,
    )
    ctx = _base_context()
    inc_id = ctx.incident_id
    corr_id = "cor_00000000000000000000000000000801"
    init_ev = build_incident_event(
        incident_id=inc_id,
        event_type=EventType.PATCH_PROPOSED,
        actor="remediation_patch_engineer",
        actor_type=ActorType.AI_AGENT,
        sequence_number=5,
        correlation_id=corr_id,
        timestamp_utc=utc_now(),
    )
    agg = IncidentAggregate(
        incident_id=inc_id,
        finding_id=ctx.finding.finding_id,
        environment="demo-staging",
        source_revision=ctx.authoritative_base_revision,
        current_state=IncidentState.PATCH_PENDING,
        active_patch_id=ctx.proposal.patch_id,
        active_patch_hash=ctx.proposal.candidate_content_hash,
        correlation_id=corr_id,
        latest_event_id=init_ev.event_id,
        latest_event_sequence=5,
        created_at=utc_now(),
        updated_at=utc_now(),
    )
    await repo.create_incident(
        agg,
        init_ev,
        EventProcessingResult(
            event_id=init_ev.event_id,
            incident_id=inc_id,
            accepted=True,
            previous_state=IncidentState.PATCH_PENDING,
            current_state=IncidentState.PATCH_PENDING,
            incident_version=1,
            reason_code="SEEDED",
        ),
    )
    producer = ProducerContext(
        producer_id="operator_patch_runner",
        actor_type=ActorType.SECURITY_VERIFIER,
        authenticated=True,
        trusted_channel="internal_trusted",
        provenance_mode="fixture",
    )
    return orch, inc_id, producer


@pytest.mark.asyncio
async def test_orchestrator_transitions_patch_pending_to_patch_tested_on_pass() -> None:
    orch, inc_id, producer = await _seed_patch_pending_orchestrator()
    vctx = _base_context()

    report, final_res = await orch.execute_patch_verification(
        inc_id,
        verification_context=vctx,
        producer_context=producer,
        patch_runner=FixturePatchTestRunner(
            scenario="pass", source_target=STAND_IN_TARGET.target_id
        ),
    )

    assert report.decision.accepted is True
    assert final_res.accepted is True
    assert final_res.current_state == IncidentState.PATCH_TESTED


@pytest.mark.asyncio
async def test_orchestrator_keeps_patch_pending_on_functional_failure() -> None:
    orch, inc_id, producer = await _seed_patch_pending_orchestrator()
    vctx = _base_context()

    report, final_res = await orch.execute_patch_verification(
        inc_id,
        verification_context=vctx,
        producer_context=producer,
        patch_runner=FixturePatchTestRunner(
            scenario="functional_fail", source_target=STAND_IN_TARGET.target_id
        ),
    )

    assert report.decision.accepted is False
    assert final_res.accepted is True
    assert final_res.current_state == IncidentState.PATCH_FAILED


@pytest.mark.asyncio
async def test_orchestrator_records_infra_error_without_advancing_state() -> None:
    orch, inc_id, producer = await _seed_patch_pending_orchestrator()
    vctx = _base_context()

    report, final_res = await orch.execute_patch_verification(
        inc_id,
        verification_context=vctx,
        producer_context=producer,
        patch_runner=FixturePatchTestRunner(
            scenario="timeout_outcome_unknown", source_target=STAND_IN_TARGET.target_id
        ),
    )

    assert report.decision.accepted is False
    assert report.decision.overall_status == TestExecutionStatus.INFRASTRUCTURE_ERROR
    assert final_res.accepted is True
    assert final_res.current_state == IncidentState.PATCH_FAILED


def test_guard_patch_verification_blocks_host_mode_and_missing_required_tests() -> None:
    vctx = _base_context()
    corr_id = "cor_00000000000000000000000000000802"
    ev = build_incident_event(
        incident_id=vctx.incident_id,
        event_type=EventType.PATCH_TEST_PASSED,
        actor="isolated_patch_verifier",
        actor_type=ActorType.SECURITY_VERIFIER,
        sequence_number=6,
        correlation_id=corr_id,
        timestamp_utc=utc_now(),
    )
    agg = IncidentAggregate(
        incident_id=vctx.incident_id,
        finding_id=vctx.finding.finding_id,
        environment="demo-staging",
        source_revision=vctx.authoritative_base_revision,
        current_state=IncidentState.PATCH_PENDING,
        active_patch_id=vctx.proposal.patch_id,
        active_patch_hash=vctx.proposal.candidate_content_hash,
        correlation_id=corr_id,
        latest_event_id=ev.event_id,
        latest_event_sequence=5,
        created_at=utc_now(),
        updated_at=utc_now(),
    )
    producer = ProducerContext(
        producer_id="isolated_patch_verifier",
        actor_type=ActorType.SECURITY_VERIFIER,
        authenticated=True,
        trusted_channel="internal_trusted",
        provenance_mode="fixture",
    )

    host_ptr = PatchTestResult(
        test_run_id="trun_00000000000000000000000000000802",
        patch_id=vctx.proposal.patch_id,
        incident_id=vctx.incident_id,
        expected_source_revision=vctx.authoritative_base_revision,
        tested_source_revision=vctx.authoritative_base_revision,
        tested_candidate_hash=vctx.proposal.candidate_content_hash,
        individual_outcomes=[
            IndividualTestOutcome(
                test_name="sqli_search_exploit",
                category="security",
                status=TestExecutionStatus.TEST_PASSED,
                duration_seconds=0.1,
                message="ok",
            )
        ],
        overall_status=TestExecutionStatus.TEST_PASSED,
        artifact_ids=["art_00000000000000000000000000000802"],
        sanitized_logs="1 passed",
        started_at=utc_now(),
        completed_at=utc_now(),
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
        isolation_metadata={"mode": "host"},
    )
    res_host = guard_patch_verification(
        agg,
        ev,
        TransitionContext(
            producer_context=producer,
            patch_proposal=vctx.proposal,
            patch_test_result=host_ptr,
        ),
    )
    assert res_host.allowed is False
    assert res_host.reason_code == "INSUFFICIENT_ISOLATION"

    incomplete_ptr = host_ptr.model_copy(update={"isolation_metadata": {"mode": "docker"}})
    res_missing = guard_patch_verification(
        agg,
        ev,
        TransitionContext(
            producer_context=producer,
            patch_proposal=vctx.proposal,
            patch_test_result=incomplete_ptr,
            required_patch_tests=["sqli_search_exploit", "smoke_health"],
        ),
    )
    assert res_missing.allowed is False
    assert res_missing.reason_code == "MISSING_REQUIRED_PATCH_TESTS"
