"""Shared fixtures for agent_core orchestration, state machine, guard, and replay tests."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from agent_core.context import FixedClock, ProducerContext
from agent_core.incident import IncidentAggregate
from agent_core.orchestrator import IncidentOrchestrator
from agent_core.repositories.memory import InMemoryOrchestrationRepository
from shared.artifacts import build_artifact_reference
from shared.config import load_route_registry
from shared.enums import (
    ActorType,
    ApprovalStatus,
    ArtifactType,
    EvidenceProvenance,
    FeatureObservationStatus,
    FindingStatus,
    IncidentState,
    ProposalType,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.identifiers import (
    generate_approval_id,
    generate_artifact_id,
    generate_correlation_id,
    generate_event_id,
    generate_finding_id,
    generate_idempotency_token,
    generate_incident_id,
    generate_proposal_id,
)
from shared.schemas import (
    ApprovalDecision,
    ContainmentProposal,
    FeatureState,
    Finding,
    RouteFlagRegistry,
)


@pytest.fixture()
def fixed_clock() -> FixedClock:
    return FixedClock(datetime(2026, 11, 26, 4, 0, 0, tzinfo=UTC))


@pytest.fixture()
def memory_repo() -> InMemoryOrchestrationRepository:
    return InMemoryOrchestrationRepository()


@pytest.fixture()
def route_registry() -> RouteFlagRegistry:
    return load_route_registry()


@pytest.fixture()
def live_orchestrator(
    memory_repo: InMemoryOrchestrationRepository,
    fixed_clock: FixedClock,
    route_registry: RouteFlagRegistry,
) -> IncidentOrchestrator:
    return IncidentOrchestrator(
        repository=memory_repo,
        evidence_repository=memory_repo,
        route_registry=route_registry,
        clock=fixed_clock,
        fixture_mode=False,
    )


@pytest.fixture()
def fixture_orchestrator(
    memory_repo: InMemoryOrchestrationRepository,
    fixed_clock: FixedClock,
    route_registry: RouteFlagRegistry,
) -> IncidentOrchestrator:
    return IncidentOrchestrator(
        repository=memory_repo,
        evidence_repository=memory_repo,
        route_registry=route_registry,
        clock=fixed_clock,
        fixture_mode=True,
    )


def make_producer(
    actor_type: ActorType,
    producer_id: str = "test_producer",
    *,
    authenticated: bool = True,
    provenance_mode: str = "live",
) -> ProducerContext:
    return ProducerContext(
        producer_id=producer_id,
        actor_type=actor_type,
        authenticated=authenticated,
        trusted_channel="test_channel" if authenticated else "untrusted",
        provenance_mode=provenance_mode,  # type: ignore[arg-type]
    )


def make_incident(
    *,
    state: IncidentState = IncidentState.RECEIVED,
    incident_id: str | None = None,
    finding_id: str | None = None,
    environment: str = "demo-staging",
    source_revision: str = "rev_abc123",
    mapped_flag_name: str | None = "search_v1",
    proposal: ContainmentProposal | None = None,
    last_op_ts: datetime | None = None,
    functional_smoke_test_passed: bool | None = None,
) -> IncidentAggregate:
    inc_id = incident_id or generate_incident_id()
    fnd_id = finding_id or generate_finding_id()
    now = datetime(2026, 11, 26, 4, 0, 0, tzinfo=UTC)
    return IncidentAggregate(
        incident_id=inc_id,
        finding_id=fnd_id,
        environment=environment,
        source_revision=source_revision,
        current_state=state,
        incident_version=1,
        created_at=now,
        updated_at=now,
        mapped_flag_name=mapped_flag_name,
        current_proposal_id=proposal.proposal_id if proposal else None,
        current_proposal_hash=proposal.proposal_hash if proposal else None,
        last_operation_timestamp=last_op_ts,
        functional_smoke_test_passed=functional_smoke_test_passed,
        correlation_id=generate_correlation_id(),
        latest_event_id=generate_event_id(),
        latest_event_sequence=1,
    )


def make_finding(
    *,
    incident_id: str,
    finding_id: str | None = None,
    environment: str = "demo-staging",
    revision: str = "rev_abc123",
    provenance: EvidenceProvenance = EvidenceProvenance.SECURITY_TEST_OUTPUT,
    status: FindingStatus = FindingStatus.SUSPECTED,
    evidence_ids: list[str] | None = None,
) -> Finding:
    return Finding(
        finding_id=finding_id or generate_finding_id(),
        incident_id=incident_id,
        category=VulnerabilityCategory.SQL_INJECTION,
        affected_route="/search",
        affected_component="search_service",
        severity=VulnerabilitySeverity.CRITICAL,
        status=status,
        evidence_ids=evidence_ids or [],
        repository_revision=revision,
        environment=environment,
        provenance=provenance,
    )


def make_proposal(
    *,
    incident_id: str,
    created_at: datetime,
    flag_name: str = "search_v1",
    environment: str = "demo-staging",
    desired_enabled: bool = False,
    expected_current_enabled: bool | None = True,
    evidence_ids: list[str] | None = None,
    registry_version: str = "1.0.0-demo",
) -> ContainmentProposal:
    return ContainmentProposal.with_computed_hash(
        proposal_id=generate_proposal_id(),
        incident_id=incident_id,
        proposal_type=ProposalType.CONTAINMENT_FLAG_DISABLE,
        environment=environment,
        flag_name=flag_name,
        desired_enabled=desired_enabled,
        expected_current_enabled=expected_current_enabled,
        reason="Disable vulnerable search_v1 endpoint.",
        expected_disruption="/search routes to /health fallback.",
        evidence_ids=evidence_ids or [generate_artifact_id()],
        approval_required=True,
        registry_version=registry_version,
        created_at=created_at,
        expires_at=created_at + timedelta(minutes=15),
        idempotency_token=generate_idempotency_token(),
    )


def make_approval(
    proposal: ContainmentProposal,
    *,
    decided_at: datetime | None = None,
    expires_at: datetime | None = None,
    decision: ApprovalStatus = ApprovalStatus.APPROVED,
    proposal_hash: str | None = None,
    proposal_id: str | None = None,
    incident_id: str | None = None,
    rejection_reason: str | None = None,
) -> ApprovalDecision:
    decided = decided_at or proposal.created_at + timedelta(seconds=10)
    return ApprovalDecision(
        approval_id=generate_approval_id(),
        proposal_id=proposal_id or proposal.proposal_id,
        proposal_hash=proposal_hash or proposal.proposal_hash,
        incident_id=incident_id or proposal.incident_id,
        actor_id="secops_operator",
        decision=decision,
        decided_at=decided,
        expires_at=expires_at or proposal.expires_at,
        rejection_reason=rejection_reason,
        authorization_context_ref="authctx_test_01",
        nonce=f"nonce_{generate_idempotency_token()}",
    )


def make_feature_state(
    *,
    environment: str = "demo-staging",
    feature_name: str = "search_v1",
    enabled: bool | None = True,
    observation_status: FeatureObservationStatus = FeatureObservationStatus.OBSERVED,
    observed_at: datetime | None = None,
    provenance: EvidenceProvenance = EvidenceProvenance.ACTUAL_OBSERVED,
) -> FeatureState:
    return FeatureState(
        environment=environment,
        feature_id=f"fs_{feature_name}",
        feature_name=feature_name,
        observation_status=observation_status,
        enabled=enabled,
        observed_at=observed_at or datetime(2026, 11, 26, 4, 0, 0, tzinfo=UTC),
        observation_source=provenance,
    )


async def store_evidence_artifact(
    repo: InMemoryOrchestrationRepository,
    *,
    incident_id: str,
    artifact_type: ArtifactType = ArtifactType.REPRODUCTION_LOG,
    provenance: EvidenceProvenance = EvidenceProvenance.SECURITY_TEST_OUTPUT,
    revision: str = "rev_abc123",
    content: bytes = b'{"verified": true}',
) -> str:
    art_id = generate_artifact_id()
    ref = build_artifact_reference(
        artifact_id=art_id,
        incident_id=incident_id,
        artifact_type=artifact_type,
        content=content,
        storage_ref=f"artifacts/test/{incident_id}/{art_id}.json",
        producer="test_verifier",
        provenance=provenance,
        source_revision=revision,
    )
    await repo.store_artifact(ref, content)
    return art_id
