"""Orchestration context models, clocks, structured results, and future AI protocols.

Provides:
- Deterministic injected clocks (``Clock``, ``SystemClock``, ``FixedClock``).
- Trusted producer verification context (``ProducerContext``).
- Structured guard, event-processing, and downstream request records.
- Protocol boundaries for future AI agents and orchestration persistence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any, Literal, Protocol, runtime_checkable

from pydantic import Field, StrictBool, StrictInt, model_validator
from shared.enums import ActorType, IncidentState
from shared.identifiers import ensure_utc, utc_now
from shared.schemas import (
    ApprovalDecision,
    ArtifactReference,
    ContainmentProposal,
    DependencyGraph,
    DeploymentEvidence,
    EvidenceReport,
    FeatureState,
    Finding,
    IncidentEvent,
    InvestigationSummary,
    KillswitchModel,
    MappingResult,
    MetricSnapshot,
    OperationReceipt,
    PatchProposal,
    PatchTestResult,
    RollbackProposal,
    RolloutDecision,
    RolloutPlan,
    RouteFlagRegistry,
    UtcDatetime,
    VerificationResult,
)

if TYPE_CHECKING:
    from agent_core.approval_validator import ApprovalValidator
    from agent_core.evidence_validator import EvidenceValidator
    from agent_core.incident import IncidentAggregate


@runtime_checkable
class Clock(Protocol):
    """Injected UTC clock abstraction enabling deterministic testing without sleeping."""

    def now(self) -> datetime:
        """Return current timezone-aware UTC datetime."""
        ...


class SystemClock:
    """Production wall-clock provider returning timezone-aware UTC timestamps."""

    def now(self) -> datetime:
        return utc_now()


class FixedClock:
    """Deterministic controllable clock for unit tests, replay, and simulations."""

    def __init__(self, current: datetime) -> None:
        self._current = ensure_utc(current)

    def now(self) -> datetime:
        return self._current

    def set(self, new_time: datetime) -> None:
        self._current = ensure_utc(new_time)

    def advance(self, seconds: float) -> datetime:
        self._current = self._current + timedelta(seconds=seconds)
        return self._current


class ProducerContext(KillswitchModel):
    """Trusted integration identity describing who submitted an incoming event.

    Security boundary:
        An arbitrary ``actor`` string inside an event payload MUST NEVER be used
        as authentication. Only an authenticated ``ProducerContext`` injected by
        the platform service or explicit test adapter establishes producer authority.
    """

    producer_id: str = Field(min_length=1, description="Authenticated subsystem/operator ID.")
    actor_type: ActorType = Field(description="Originating actor category.")
    authenticated: StrictBool = Field(
        default=False,
        description="Whether producer identity was verified by a trusted channel.",
    )
    trusted_channel: str = Field(
        default="untrusted",
        min_length=1,
        description="Transport or adapter channel name (e.g. 'platform_api', 'fixture_sim').",
    )
    provenance_mode: Literal["live", "fixture"] = Field(
        default="live",
        description="Explicitly differentiates live operational runs from fixture simulations.",
    )
    authorization_ref: str | None = Field(
        default=None,
        description="Optional platform session or mTLS identity reference.",
    )


class DownstreamRequest(KillswitchModel):
    """Non-executing request emitted by the orchestrator for an external subsystem.

    Invariant:
        Requests originating from synthetic/fixture runs MUST set
        ``is_synthetic_fixture=True`` and ``executable_live=False`` so fixture
        simulations can never trigger real external Flagsmith mutations.
    """

    request_id: str = Field(min_length=1)
    request_type: str = Field(min_length=1)
    incident_id: str = Field(min_length=1)
    proposal_id: str | None = None
    approval_id: str | None = None
    operation_id: str | None = None
    idempotency_key: str | None = None
    environment: str | None = None
    target_feature: str | None = None
    desired_enabled: StrictBool | None = None
    executable_live: StrictBool = False
    is_synthetic_fixture: StrictBool = False
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _prevent_live_execution_from_fixture(self) -> DownstreamRequest:
        if self.is_synthetic_fixture and self.executable_live:
            raise ValueError("Synthetic fixture requests cannot be marked executable_live=True.")
        return self


class GuardResult(KillswitchModel):
    """Structured outcome from evaluating a deterministic transition guard."""

    allowed: StrictBool
    guard: str = Field(min_length=1)
    reason_code: str = Field(min_length=1)
    message: str = Field(min_length=1)
    missing_requirements: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    retryable: StrictBool = False


class EventProcessingResult(KillswitchModel):
    """Structured deterministic outcome returned by ``IncidentOrchestrator.process_event``."""

    accepted: StrictBool
    duplicate: StrictBool = False
    incident_id: str = Field(min_length=1)
    event_id: str = Field(min_length=1)
    previous_state: IncidentState | None = None
    current_state: IncidentState | None = None
    incident_version: StrictInt = Field(ge=0)
    generated_events: list[IncidentEvent] = Field(default_factory=list)
    pending_requests: list[DownstreamRequest] = Field(default_factory=list)
    guard_failures: list[GuardResult] = Field(default_factory=list)
    reason_code: str = Field(min_length=1)
    retryable: StrictBool = False


class RolloutStageRecord(KillswitchModel):
    """Subordinate workflow state tracking a single progressive rollout stage."""

    stage_id: str = Field(min_length=1)
    exposure_percentage: StrictInt = Field(ge=0, le=100)
    target_revision: str = Field(min_length=1)
    approved_exposure: StrictInt | None = Field(default=None, ge=0, le=100)
    observed_exposure: StrictInt | None = Field(default=None, ge=0, le=100)
    targeting_configuration: dict[str, Any] = Field(default_factory=dict)
    approval_id: str | None = None
    operation_receipt_id: str | None = None
    health_passed: StrictBool | None = None
    security_verified: StrictBool | None = None
    status: Literal[
        "proposed", "approved", "applied", "observed", "completed", "held", "failed"
    ] = "proposed"


# ------------------------------------------------------------------------------
# Future Subsystem Integration Protocols (Prepared in Phase 02)
# ------------------------------------------------------------------------------
@runtime_checkable
class InvestigatorAgent(Protocol):
    """Future AI/ML Engineer 1 interface producing InvestigationSummary."""

    async def investigate(
        self,
        finding: Finding,
        evidence_artifacts: list[ArtifactReference],
    ) -> InvestigationSummary: ...


@runtime_checkable
class FeatureMapperAgent(Protocol):
    """Future AI/ML Engineer 1 interface mapping a Finding to a feature flag."""

    async def map_finding_to_flag(
        self,
        finding: Finding,
        registry: RouteFlagRegistry,
        observed_features: list[FeatureState],
    ) -> MappingResult: ...


@runtime_checkable
class ContainmentStrategistAgent(Protocol):
    """Future AI/ML Engineer 1 interface proposing least-disruptive containment."""

    async def propose_containment(
        self,
        finding: Finding,
        mapping: MappingResult,
        dependency_graph: DependencyGraph,
        observed_features: list[FeatureState],
    ) -> ContainmentProposal: ...


@runtime_checkable
class PatchEngineerAgent(Protocol):
    """Future AI/ML Engineer 2 interface proposing bounded source patches."""

    async def propose_patch(
        self,
        finding: Finding,
        containment_verification: VerificationResult,
    ) -> PatchProposal: ...


@runtime_checkable
class ReleaseManagerAgent(Protocol):
    """Future AI/ML Engineer 2 interface evaluating progressive release health."""

    async def evaluate_rollout_stage(
        self,
        plan: RolloutPlan,
        telemetry: MetricSnapshot,
        baseline: MetricSnapshot | None,
    ) -> RolloutDecision: ...


@runtime_checkable
class EvidenceReporterAgent(Protocol):
    """Future AI/ML Engineer 2 interface assembling an exportable EvidenceReport."""

    async def build_report(
        self,
        incident_id: str,
        events: list[IncidentEvent],
        artifacts: list[ArtifactReference],
    ) -> EvidenceReport: ...


@runtime_checkable
class OrchestrationRepository(Protocol):
    """Atomic persistence contract decoupling orchestrator from concrete databases."""

    async def create_incident(
        self,
        incident: IncidentAggregate,
        initial_event: IncidentEvent,
        initial_result: EventProcessingResult,
    ) -> IncidentAggregate: ...

    async def get_incident(self, incident_id: str) -> IncidentAggregate | None: ...

    async def get_incident_version(self, incident_id: str) -> int | None: ...

    async def append_incident_event(self, event: IncidentEvent) -> IncidentEvent: ...

    async def list_incident_events(self, incident_id: str) -> list[IncidentEvent]: ...

    async def get_event_by_id(self, event_id: str) -> IncidentEvent | None: ...

    async def get_processed_result(self, event_id: str) -> EventProcessingResult | None: ...

    async def save_proposal(self, proposal: ContainmentProposal) -> None: ...

    async def get_active_proposal(self, incident_id: str) -> ContainmentProposal | None: ...

    async def get_operation_by_idempotency_key(
        self, idempotency_key: str
    ) -> DownstreamRequest | None: ...

    async def commit_transition(
        self,
        *,
        expected_version: int,
        updated_incident: IncidentAggregate,
        event: IncidentEvent,
        result: EventProcessingResult,
        proposal: ContainmentProposal | None = None,
        reserved_request: DownstreamRequest | None = None,
    ) -> IncidentAggregate: ...


@dataclass
class TransitionContext:
    """In-flight evidence, approvals, and configuration supplied to transition guards."""

    producer_context: ProducerContext
    clock: Clock = field(default_factory=SystemClock)
    fixture_mode: bool = False
    route_registry: RouteFlagRegistry | None = None
    finding: Finding | None = None
    verification_result: VerificationResult | None = None
    functional_smoke_passed: bool | None = None
    mapping_result: MappingResult | None = None
    investigation_summary: InvestigationSummary | None = None
    containment_proposal: ContainmentProposal | None = None
    active_proposal: ContainmentProposal | None = None
    approval_decision: ApprovalDecision | None = None
    feature_state: FeatureState | None = None
    operation_receipt: OperationReceipt | None = None
    patch_proposal: PatchProposal | None = None
    patch_test_result: PatchTestResult | None = None
    deployment_evidence: DeploymentEvidence | None = None
    rollout_plan: RolloutPlan | None = None
    metric_snapshot: MetricSnapshot | None = None
    baseline_snapshot: MetricSnapshot | None = None
    rollout_decision: RolloutDecision | None = None
    rollback_proposal: RollbackProposal | None = None
    evidence_artifacts: list[ArtifactReference] = field(default_factory=list)
    existing_evidence_ids: set[str] | None = None
    consumed_approval_ids: set[str] = field(default_factory=set)
    stage_approval_decision: ApprovalDecision | None = None
    reopened_evidence_verified: bool = False
    current_time_override: UtcDatetime | None = None
    approval_validator: ApprovalValidator | None = None
    evidence_validator: EvidenceValidator | None = None

    @property
    def evaluation_time(self) -> datetime:
        if self.current_time_override is not None:
            return ensure_utc(self.current_time_override)
        return ensure_utc(self.clock.now().astimezone(UTC))
