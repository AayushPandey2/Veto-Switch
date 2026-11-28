"""Tests for EvidenceGroundedPatchEngineer, LLM generation/fallback, orchestration, and eval."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from agent_core.context import EventProcessingResult, FixedClock, ProducerContext
from agent_core.events import build_incident_event
from agent_core.orchestrator import IncidentOrchestrator
from agent_core.repositories.memory import InMemoryOrchestrationRepository
from remediation.demos import STAND_IN_APP_SOURCE, run_patch_demos
from remediation.evaluations.patch_evaluator import run_patch_evaluation
from remediation.patch_agent import EvidenceGroundedPatchEngineer
from remediation.patching.diff_validator import validate_patch_proposal
from remediation.patching.source_access import (
    STAND_IN_TARGET,
    build_patch_context,
    load_snapshot_from_files,
)
from shared.config import load_route_registry
from shared.enums import (
    ActorType,
    ArtifactType,
    EventType,
    EvidenceProvenance,
    FindingStatus,
    IncidentState,
    PatchOrigin,
    PatchRejectionReason,
    PatchStatus,
    TestExecutionStatus,
    VerificationPhase,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.identifiers import generate_incident_id
from shared.schemas import ArtifactReference, Finding, VerificationResult
from shared.serialization import sha256_text

NOW = datetime(2026, 11, 27, 0, 0, 0, tzinfo=UTC)


@pytest.mark.asyncio
async def test_patch_engineer_sqli_and_traversal_reference_fallback() -> None:
    repo = InMemoryOrchestrationRepository()
    engineer = EvidenceGroundedPatchEngineer(
        evidence_repository=repo,
        clock=FixedClock(NOW),
        fixture_mode=True,
    )
    snap = load_snapshot_from_files(target=STAND_IN_TARGET, files={"app.py": STAND_IN_APP_SOURCE})

    f_sqli = Finding(
        finding_id="fnd_pe_01",
        incident_id="inc_pe_01",
        category=VulnerabilityCategory.SQL_INJECTION,
        affected_route="/search",
        affected_component="search_v1",
        severity=VulnerabilitySeverity.HIGH,
        status=FindingStatus.REPRODUCED,
        evidence_ids=["art_pe_01"],
        repository_revision=STAND_IN_TARGET.source_revision,
        environment="demo-staging",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    ctx_sqli = build_patch_context(
        finding=f_sqli,
        target_descriptor=STAND_IN_TARGET,
        snapshot=snap,
        fixture_mode=True,
        evaluation_timestamp=NOW,
    )
    out_sqli = await engineer.generate_candidate(ctx_sqli, require_contained=False)
    assert out_sqli.accepted is True
    assert out_sqli.proposal is not None
    assert out_sqli.proposal.patch_origin == PatchOrigin.REFERENCE_FIXTURE
    assert out_sqli.proposal.status == PatchStatus.PATCH_PROPOSED
    assert out_sqli.proposal.touched_files == ["app.py"]
    assert "sqli_search" in out_sqli.proposal.required_tests
    assert out_sqli.checklist is not None
    assert out_sqli.pr_summary_markdown is not None
    assert "Isolated verification pending." in out_sqli.pr_summary_markdown
    assert validate_patch_proposal(out_sqli.proposal, ctx_sqli) == out_sqli.proposal

    # Stale revision rejected
    f_stale = f_sqli.model_copy(update={"repository_revision": "wrong-rev"})
    ctx_stale = build_patch_context(
        finding=f_stale,
        target_descriptor=STAND_IN_TARGET,
        snapshot=snap,
        fixture_mode=True,
        evaluation_timestamp=NOW,
    )
    out_stale = await engineer.generate_candidate(ctx_stale, require_contained=False)
    assert out_stale.accepted is False
    assert PatchRejectionReason.SOURCE_REVISION_MISMATCH in out_stale.rejection_reasons


@pytest.mark.asyncio
async def test_orchestrator_execute_patch_generation_remains_patch_pending() -> None:
    repo = InMemoryOrchestrationRepository()
    clock = FixedClock(NOW)
    reg = load_route_registry()
    engineer = EvidenceGroundedPatchEngineer(
        evidence_repository=repo,
        clock=clock,
        fixture_mode=True,
    )
    orch = IncidentOrchestrator(
        repository=repo,
        evidence_repository=repo,
        route_registry=reg,
        clock=clock,
        fixture_mode=True,
        patch_engineer=engineer,
    )
    inc_id = generate_incident_id()
    raw = b"reproduction proof"
    art = ArtifactReference(
        artifact_id="art_pe_orch",
        incident_id=inc_id,
        artifact_type=ArtifactType.REPRODUCTION_LOG,
        content_hash=sha256_text(raw.decode("utf-8")),
        storage_ref="repro/pe_orch.log",
        created_at=NOW,
        producer="authorized_verifier",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
        content_type="text/plain",
        size_bytes=len(raw),
        source_revision=STAND_IN_TARGET.source_revision,
    )
    await repo.store_artifact(art, raw)
    finding = Finding(
        finding_id="fnd_pe_orch",
        incident_id=inc_id,
        category=VulnerabilityCategory.SQL_INJECTION,
        affected_route="/search",
        affected_component="search_v1",
        severity=VulnerabilitySeverity.HIGH,
        status=FindingStatus.REPRODUCED,
        evidence_ids=[art.artifact_id],
        repository_revision=STAND_IN_TARGET.source_revision,
        environment="demo-staging",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    sys_prod = ProducerContext(
        producer_id="platform_api",
        actor_type=ActorType.SYSTEM,
        authenticated=True,
        trusted_channel="fixture_sim",
        provenance_mode="fixture",
    )
    eng_prod = ProducerContext(
        producer_id="deterministic_engine",
        actor_type=ActorType.DETERMINISTIC_ENGINE,
        authenticated=True,
        trusted_channel="fixture_sim",
        provenance_mode="fixture",
    )
    inc = await orch.create_incident(finding, sys_prod)
    stored = await repo.get_incident(inc.incident_id)
    assert stored is not None
    seed_evt = build_incident_event(
        incident_id=inc.incident_id,
        event_type=EventType.CONTAINMENT_VERIFIED,
        actor="authorized_verifier",
        actor_type=ActorType.SECURITY_VERIFIER,
        sequence_number=2,
        correlation_id=inc.correlation_id,
        evidence_ids=[art.artifact_id],
        timestamp_utc=NOW,
        payload={
            "verification_id": "ver_pe_orch",
            "phase": "after_containment",
            "execution_status": "test_passed",
        },
    )
    await repo.commit_transition(
        expected_version=stored.incident_version,
        updated_incident=stored.model_copy(
            update={
                "current_state": IncidentState.CONTAINED,
                "incident_version": stored.incident_version + 1,
                "latest_event_sequence": 2,
                "latest_event_id": seed_evt.event_id,
            }
        ),
        event=seed_evt,
        result=EventProcessingResult(
            accepted=True,
            incident_id=inc.incident_id,
            event_id=seed_evt.event_id,
            previous_state=stored.current_state,
            current_state=IncidentState.CONTAINED,
            incident_version=stored.incident_version + 1,
            reason_code="CONTAINMENT_VERIFIED",
        ),
    )
    cont_ver = VerificationResult(
        verification_id="ver_pe_orch",
        incident_id=inc.incident_id,
        test_id="sqli_search",
        phase=VerificationPhase.AFTER_CONTAINMENT,
        execution_status=TestExecutionStatus.TEST_PASSED,
        passed=True,
        vulnerability_reproduced=False,
        tested_revision=STAND_IN_TARGET.source_revision,
    )
    snap = load_snapshot_from_files(target=STAND_IN_TARGET, files={"app.py": STAND_IN_APP_SOURCE})
    ctx = build_patch_context(
        finding=finding,
        target_descriptor=STAND_IN_TARGET,
        snapshot=snap,
        containment_verification=cont_ver,
        fixture_mode=True,
        evaluation_timestamp=NOW,
    )
    prop, res = await orch.execute_patch_generation(
        finding=finding,
        containment_verification=cont_ver,
        producer_context=eng_prod,
        patch_context=ctx,
    )
    assert prop is not None
    assert res.accepted is True
    assert res.current_state == IncidentState.PATCH_PENDING
    assert await repo.artifact_exists(prop.candidate_artifact_id, incident_id=inc.incident_id)


@pytest.mark.asyncio
async def test_patch_demos_and_evaluation(tmp_path: Path) -> None:
    demos = await run_patch_demos()
    assert len(demos) == 7
    report = await run_patch_evaluation(reports_dir=tmp_path)
    assert report["failed_cases"] == 0
    assert report["unsafe_accepted_candidates"] == 0
    assert report["false_claims_of_patch_testing"] == 0
