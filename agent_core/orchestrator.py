"""Central deterministic IncidentOrchestrator coordinating Killswitch X workflows.

Coordinates state-machine validation, transition guards, idempotency, optimistic
concurrency, atomic persistence, event handlers, and future AI agent interfaces
without ever executing privileged Flagsmith mutations or LLM transitions directly.
"""

from __future__ import annotations

from typing import Any

from shared.contracts import EvidenceRepository
from shared.enums import (
    ActorType,
    ArtifactType,
    EventType,
    EvidenceProvenance,
    IncidentState,
    RedactionStatus,
)
from shared.exceptions import (
    ConcurrencyConflictError,
    ConfigurationError,
    ContractValidationError,
    InvalidTransitionError,
    LLMProviderError,
    LLMResponseValidationError,
    UnauthorizedOperationError,
)
from shared.identifiers import generate_artifact_id, generate_correlation_id
from shared.logging_config import get_logger, log_structured
from shared.schemas import (
    ArtifactReference,
    ContainmentProposal,
    DependencyGraph,
    FeatureState,
    Finding,
    IncidentEvent,
    InvestigationSummary,
    MappingResult,
    RouteFlagRegistry,
)
from shared.serialization import canonical_json, sha256_text

from agent_core.approval_validator import ApprovalValidator
from agent_core.context import (
    Clock,
    ContainmentStrategistAgent,
    EventProcessingResult,
    EvidenceReporterAgent,
    FeatureMapperAgent,
    GuardResult,
    InvestigatorAgent,
    OrchestrationRepository,
    PatchEngineerAgent,
    ProducerContext,
    ReleaseManagerAgent,
    SystemClock,
    TransitionContext,
)
from agent_core.event_dispatcher import EventDispatcher
from agent_core.events import (
    build_incident_event,
    enrich_replay_payload,
    validate_event_ordering_and_causality,
)
from agent_core.evidence_validator import (
    EvidenceValidator,
    collect_event_evidence_ids,
    validate_producer_for_evidence,
    validate_provenance_for_mode,
)
from agent_core.idempotency import check_event_idempotency
from agent_core.incident import IncidentAggregate
from agent_core.intelligence.investigation_context import InvestigationInputBundle
from agent_core.investigator import InvestigationExecutionResult, Investigator
from agent_core.policies import (
    validate_containment_proposal_output,
    validate_investigation_output,
    validate_mapping_output,
)
from agent_core.replay import replay_incident as replay_from_events
from agent_core.repositories.memory import InMemoryOrchestrationRepository
from agent_core.state_machine import apply_transition, validate_transition


class IncidentOrchestrator:
    """Deterministic workflow controller for Killswitch X security incidents."""

    def __init__(
        self,
        *,
        repository: OrchestrationRepository | None = None,
        evidence_repository: EvidenceRepository | None = None,
        route_registry: RouteFlagRegistry | None = None,
        clock: Clock | None = None,
        fixture_mode: bool = False,
        dispatcher: EventDispatcher | None = None,
        investigator: InvestigatorAgent | None = None,
        feature_mapper: FeatureMapperAgent | None = None,
        containment_strategist: ContainmentStrategistAgent | None = None,
        patch_engineer: PatchEngineerAgent | None = None,
        release_manager: ReleaseManagerAgent | None = None,
        evidence_reporter: EvidenceReporterAgent | None = None,
    ) -> None:
        self._repo: OrchestrationRepository = repository or InMemoryOrchestrationRepository()
        if evidence_repository is not None:
            self._evidence_repo: EvidenceRepository | None = evidence_repository
        elif isinstance(self._repo, EvidenceRepository):
            self._evidence_repo = self._repo
        else:
            self._evidence_repo = None

        self._route_registry = route_registry
        self._clock: Clock = clock or SystemClock()
        self._fixture_mode = fixture_mode
        self._dispatcher = dispatcher or EventDispatcher()
        self._evidence_validator = EvidenceValidator(
            self._evidence_repo, clock=self._clock, fixture_mode=fixture_mode
        )
        self._approval_validator = ApprovalValidator(
            clock=self._clock, route_registry=route_registry
        )
        self._investigator = investigator
        self._feature_mapper = feature_mapper
        self._containment_strategist = containment_strategist
        self._patch_engineer = patch_engineer
        self._release_manager = release_manager
        self._evidence_reporter = evidence_reporter
        self._logger = get_logger("agent_core.orchestrator")

    @property
    def repository(self) -> OrchestrationRepository:
        return self._repo

    async def create_incident(
        self,
        finding: Finding,
        context: ProducerContext | TransitionContext,
    ) -> IncidentAggregate:
        """Create a new incident in ``RECEIVED`` state from a normalized Finding."""
        producer = context.producer_context if isinstance(context, TransitionContext) else context
        tctx = (
            context
            if isinstance(context, TransitionContext)
            else TransitionContext(
                producer_context=producer,
                clock=self._clock,
                fixture_mode=self._fixture_mode,
                route_registry=self._route_registry,
            )
        )

        auth_check = validate_producer_for_evidence(
            producer,
            allowed_actor_types=frozenset(
                {
                    ActorType.SECURITY_SCANNER,
                    ActorType.SECURITY_VERIFIER,
                    ActorType.SYSTEM,
                    ActorType.HUMAN_OPERATOR,
                    ActorType.DETERMINISTIC_ENGINE,
                }
            ),
        )
        if not auth_check.allowed:
            raise UnauthorizedOperationError(
                auth_check.message,
                context={"producer_id": producer.producer_id},
            )

        prov_check = validate_provenance_for_mode(
            finding.provenance,
            fixture_mode=tctx.fixture_mode or self._fixture_mode,
            producer_mode=producer.provenance_mode,
            require_observed_in_live=True,
        )
        if not prov_check.allowed:
            raise ContractValidationError(
                prov_check.message,
                context={"finding_id": finding.finding_id, "provenance": finding.provenance.value},
            )

        now = tctx.evaluation_time
        is_fixture = bool(
            tctx.fixture_mode
            or self._fixture_mode
            or finding.provenance == EvidenceProvenance.REFERENCE_FIXTURE
            or producer.provenance_mode == "fixture"
        )
        environment = finding.environment or (
            self._route_registry.environment if self._route_registry else "demo-staging"
        )
        correlation_id = generate_correlation_id()
        initial_event = build_incident_event(
            incident_id=finding.incident_id,
            event_type=EventType.FINDING_RECEIVED,
            actor=producer.producer_id,
            actor_type=producer.actor_type,
            sequence_number=1,
            correlation_id=correlation_id,
            evidence_ids=list(finding.evidence_ids),
            timestamp_utc=now,
            payload={
                "finding_id": finding.finding_id,
                "category": finding.category.value,
                "severity": finding.severity.value,
                "status": finding.status.value,
                "environment": environment,
                "source_revision": finding.repository_revision,
                "is_synthetic_fixture": is_fixture,
                "provenance": finding.provenance.value,
            },
        )
        aggregate = IncidentAggregate(
            incident_id=finding.incident_id,
            finding_id=finding.finding_id,
            environment=environment,
            source_revision=finding.repository_revision,
            current_state=IncidentState.RECEIVED,
            incident_version=1,
            created_at=now,
            updated_at=now,
            correlation_id=correlation_id,
            latest_event_id=initial_event.event_id,
            latest_event_sequence=1,
            pending_action="request_vulnerability_verification",
            is_synthetic_fixture=is_fixture,
            provenance=finding.provenance,
        )
        initial_result = EventProcessingResult(
            accepted=True,
            duplicate=False,
            incident_id=aggregate.incident_id,
            event_id=initial_event.event_id,
            previous_state=None,
            current_state=IncidentState.RECEIVED,
            incident_version=1,
            generated_events=[initial_event],
            pending_requests=[],
            guard_failures=[],
            reason_code="INCIDENT_CREATED",
            retryable=False,
        )
        created = await self._repo.create_incident(aggregate, initial_event, initial_result)
        log_structured(
            self._logger,
            20,
            "Incident created in RECEIVED state.",
            incident_id=created.incident_id,
            correlation_id=created.correlation_id,
            event_type=EventType.FINDING_RECEIVED.value,
            operation_status="accepted",
        )
        return created

    async def process_event(
        self,
        event: IncidentEvent,
        producer_context: ProducerContext,
        transition_context: TransitionContext | None = None,
    ) -> EventProcessingResult:
        """Process an incoming event through ordering, guards, atomic commit, and dispatch."""
        # 1. Idempotency check (identical duplicate returns prior result; mismatch raises).
        existing_event = await self._repo.get_event_by_id(event.event_id)
        if existing_event is not None:
            existing_result = await self._repo.get_processed_result(event.event_id)
            dup_result = check_event_idempotency(
                incoming_event=event,
                existing_event=existing_event,
                existing_result=existing_result,
            )
            if dup_result is not None:
                return dup_result

        # 2. Load current incident aggregate.
        incident = await self._repo.get_incident(event.incident_id)
        if incident is None:
            return EventProcessingResult(
                accepted=False,
                incident_id=event.incident_id,
                event_id=event.event_id,
                previous_state=None,
                current_state=None,
                incident_version=0,
                guard_failures=[
                    GuardResult(
                        allowed=False,
                        guard="incident_identity",
                        reason_code="INCIDENT_NOT_FOUND",
                        message=f"Incident {event.incident_id!r} does not exist.",
                        missing_requirements=["existing_incident"],
                    )
                ],
                reason_code="INCIDENT_NOT_FOUND",
                retryable=False,
            )

        # 3. Build TransitionContext inheriting orchestrator policies and repository state.
        ctx = transition_context or TransitionContext(
            producer_context=producer_context,
            clock=self._clock,
            fixture_mode=self._fixture_mode,
            route_registry=self._route_registry,
        )
        if ctx.route_registry is None:
            ctx.route_registry = self._route_registry
        if ctx.clock is None:
            ctx.clock = self._clock
        ctx.fixture_mode = bool(ctx.fixture_mode or self._fixture_mode)
        if ctx.approval_validator is None:
            ctx.approval_validator = ApprovalValidator(
                clock=ctx.clock, route_registry=ctx.route_registry
            )
        if ctx.active_proposal is None and incident.current_proposal_id is not None:
            ctx.active_proposal = await self._repo.get_active_proposal(incident.incident_id)

        # 4. Validate sequence ordering & causality.
        try:
            validate_event_ordering_and_causality(incident, event)
        except (InvalidTransitionError, ContractValidationError) as exc:
            return EventProcessingResult(
                accepted=False,
                incident_id=incident.incident_id,
                event_id=event.event_id,
                previous_state=incident.current_state,
                current_state=incident.current_state,
                incident_version=incident.incident_version,
                guard_failures=[
                    GuardResult(
                        allowed=False,
                        guard="event_ordering",
                        reason_code=exc.error_code,
                        message=exc.message,
                    )
                ],
                reason_code=exc.error_code,
                retryable=False,
            )

        # 5. Pre-verify referenced evidence IDs asynchronously against EvidenceRepository.
        if self._evidence_repo is not None and ctx.existing_evidence_ids is None:
            referenced_ids = collect_event_evidence_ids(event, ctx)
            verified_ids: set[str] = set()
            for eid in referenced_ids:
                if await self._evidence_repo.artifact_exists(eid, incident_id=incident.incident_id):
                    verified_ids.add(eid)
            ctx.existing_evidence_ids = verified_ids

        # 6. Evaluate state-machine transition eligibility & guards.
        try:
            target_state, guard_results = validate_transition(incident, event, ctx)
        except InvalidTransitionError as exc:
            return EventProcessingResult(
                accepted=False,
                incident_id=incident.incident_id,
                event_id=event.event_id,
                previous_state=incident.current_state,
                current_state=incident.current_state,
                incident_version=incident.incident_version,
                guard_failures=[
                    GuardResult(
                        allowed=False,
                        guard="state_machine",
                        reason_code=exc.error_code,
                        message=exc.message,
                    )
                ],
                reason_code=exc.error_code,
                retryable=False,
            )

        guard_failures = [g for g in guard_results if not g.allowed]
        if guard_failures:
            return EventProcessingResult(
                accepted=False,
                incident_id=incident.incident_id,
                event_id=event.event_id,
                previous_state=incident.current_state,
                current_state=incident.current_state,
                incident_version=incident.incident_version,
                guard_failures=guard_failures,
                reason_code=guard_failures[0].reason_code,
                retryable=any(g.retryable for g in guard_failures),
            )

        # 7. Apply deterministic state update & enrich replay metadata.
        updated_incident = apply_transition(incident, event, target_state, ctx, guard_results)
        pending_requests = self._dispatcher.dispatch(
            previous_incident=incident,
            updated_incident=updated_incident,
            event=event,
            context=ctx,
        )

        replay_extra: dict[str, Any] = {}
        if ctx.investigation_summary is not None:
            replay_extra["investigation_id"] = ctx.investigation_summary.investigation_id
        if ctx.verification_result is not None:
            replay_extra["verification_id"] = ctx.verification_result.verification_id
            replay_extra["tested_revision"] = ctx.verification_result.tested_revision
        if ctx.mapping_result is not None:
            replay_extra["finding_id"] = ctx.mapping_result.finding_id
            replay_extra["selected_flag"] = ctx.mapping_result.selected_flag
            replay_extra["registry_version"] = ctx.mapping_result.registry_version
        if ctx.containment_proposal is not None:
            replay_extra["proposal_id"] = ctx.containment_proposal.proposal_id
            replay_extra["proposal_hash"] = ctx.containment_proposal.proposal_hash
        if ctx.approval_decision is not None:
            replay_extra["approval_id"] = ctx.approval_decision.approval_id
            replay_extra["rejection_reason"] = ctx.approval_decision.rejection_reason
        if ctx.operation_receipt is not None:
            replay_extra["operation_id"] = ctx.operation_receipt.operation_id
            replay_extra["idempotency_key"] = ctx.operation_receipt.idempotency_key
            replay_extra["observed_state"] = ctx.operation_receipt.observed_state
        if ctx.feature_state is not None:
            replay_extra["enabled"] = ctx.feature_state.enabled
            replay_extra["observed_feature_state"] = ctx.feature_state.enabled
        if ctx.patch_proposal is not None:
            replay_extra["patch_id"] = ctx.patch_proposal.patch_id
            replay_extra["candidate_content_hash"] = ctx.patch_proposal.candidate_content_hash
        if ctx.patch_test_result is not None:
            replay_extra["patch_id"] = ctx.patch_test_result.patch_id
            replay_extra["test_run_id"] = ctx.patch_test_result.test_run_id
            replay_extra["tested_candidate_hash"] = ctx.patch_test_result.tested_candidate_hash
        if ctx.deployment_evidence is not None:
            replay_extra["deployment_id"] = ctx.deployment_evidence.deployment_id
            replay_extra["deployment_revision"] = ctx.deployment_evidence.source_revision
        if ctx.rollout_plan is not None:
            replay_extra["plan_id"] = ctx.rollout_plan.plan_id
            replay_extra["target_revision"] = ctx.rollout_plan.target_implementation_revision
            replay_extra["stages"] = [
                {
                    "stage_id": s.stage_id,
                    "exposure_percentage": s.exposure_percentage,
                }
                for s in ctx.rollout_plan.stages
            ]
        if ctx.stage_approval_decision is not None:
            replay_extra["approval_id"] = ctx.stage_approval_decision.approval_id
            replay_extra["stage_id"] = (
                incident.current_rollout_stage or ctx.stage_approval_decision.proposal_id
            )
        if ctx.rollout_decision is not None:
            replay_extra["stage_id"] = ctx.rollout_decision.current_stage_id
            replay_extra["next_stage_id"] = ctx.rollout_decision.proposed_next_stage_id
        if ctx.metric_snapshot is not None:
            replay_extra["observed_exposure"] = (
                ctx.metric_snapshot.observed_rollout_stage_percentage
            )
            replay_extra["security_verified"] = ctx.metric_snapshot.security_regression_passed
        if ctx.rollback_proposal is not None:
            replay_extra["rollback_rationale"] = ctx.rollback_proposal.rollback_rationale

        persisted_event = enrich_replay_payload(event, extra=replay_extra)

        result = EventProcessingResult(
            accepted=True,
            duplicate=False,
            incident_id=updated_incident.incident_id,
            event_id=persisted_event.event_id,
            previous_state=incident.current_state,
            current_state=updated_incident.current_state,
            incident_version=updated_incident.incident_version,
            generated_events=[persisted_event],
            pending_requests=pending_requests,
            guard_failures=[],
            reason_code="TRANSITION_APPLIED"
            if updated_incident.current_state != incident.current_state
            else "CONTEXT_EVENT_APPLIED",
            retryable=False,
        )

        # 8. Atomic persistence commit with optimistic version check.
        reserved_req = (
            pending_requests[0]
            if pending_requests and pending_requests[0].idempotency_key
            else None
        )
        try:
            await self._repo.commit_transition(
                expected_version=incident.incident_version,
                updated_incident=updated_incident,
                event=persisted_event,
                result=result,
                proposal=ctx.containment_proposal,
                reserved_request=reserved_req,
            )
        except ConcurrencyConflictError as exc:
            return EventProcessingResult(
                accepted=False,
                incident_id=incident.incident_id,
                event_id=event.event_id,
                previous_state=incident.current_state,
                current_state=incident.current_state,
                incident_version=incident.incident_version,
                guard_failures=[
                    GuardResult(
                        allowed=False,
                        guard="optimistic_concurrency",
                        reason_code=exc.error_code,
                        message=exc.message,
                        retryable=True,
                    )
                ],
                reason_code=exc.error_code,
                retryable=True,
            )

        return result

    async def get_incident(self, incident_id: str) -> IncidentAggregate | None:
        return await self._repo.get_incident(incident_id)

    async def get_pending_action(self, incident_id: str) -> str | None:
        inc = await self._repo.get_incident(incident_id)
        return inc.pending_action if inc is not None else None

    async def get_incident_events(self, incident_id: str) -> list[IncidentEvent]:
        return await self._repo.list_incident_events(incident_id)

    async def replay_incident(self, incident_id: str) -> IncidentAggregate:
        """Reconstruct incident state strictly from persisted event history."""
        events = await self._repo.list_incident_events(incident_id)
        return replay_from_events(events)

    # --- Composition Points for Future Subsystems (Phase 03+) ---
    async def run_investigation(
        self,
        finding: Finding,
        evidence_artifacts: list[ArtifactReference],
    ) -> InvestigationSummary:
        if self._investigator is None:
            raise ConfigurationError("No InvestigatorAgent is configured on IncidentOrchestrator.")
        summary = await self._investigator.investigate(finding, evidence_artifacts)
        return validate_investigation_output(summary, finding=finding)

    async def execute_investigation(
        self,
        *,
        finding: Finding,
        producer_context: ProducerContext,
        bundle: InvestigationInputBundle | None = None,
        evidence_artifacts: list[ArtifactReference] | None = None,
        prompt_version: str | None = None,
        allowed_tools: list[str] | None = None,
    ) -> tuple[InvestigationSummary, InvestigationExecutionResult | None, EventProcessingResult]:
        """Run end-to-end investigation integrated with IncidentOrchestrator event trail.

        Records ``INVESTIGATION_REQUESTED`` and either ``INVESTIGATION_COMPLETED``
        (with optional ``MANUAL_REVIEW_REQUESTED``) or ``INVESTIGATION_FAILED`` without
        ever bypassing deterministic state-transition guards.
        """
        if self._investigator is None:
            raise ConfigurationError("No InvestigatorAgent is configured on IncidentOrchestrator.")
        incident = await self._repo.get_incident(finding.incident_id)
        if incident is None:
            raise ContractValidationError(
                f"Cannot investigate unknown incident {finding.incident_id!r}."
            )

        now = self._clock.now()
        next_seq = incident.latest_event_sequence + 1
        req_event = build_incident_event(
            incident_id=incident.incident_id,
            event_type=EventType.INVESTIGATION_REQUESTED,
            actor=producer_context.producer_id,
            actor_type=producer_context.actor_type,
            sequence_number=next_seq,
            correlation_id=incident.correlation_id,
            timestamp_utc=now,
            payload={"finding_id": finding.finding_id},
        )
        req_res = await self.process_event(req_event, producer_context=producer_context)
        if not req_res.accepted:
            raise InvalidTransitionError(
                f"Investigation request rejected by orchestrator: {req_res.reason_code}",
                context={"incident_id": incident.incident_id, "reason_code": req_res.reason_code},
            )
        next_seq += 1

        exec_result: InvestigationExecutionResult | None = None
        try:
            if isinstance(self._investigator, Investigator):
                target_bundle = bundle or InvestigationInputBundle(
                    finding=finding,
                    evidence_artifacts=list(evidence_artifacts or []),
                )
                exec_result = await self._investigator.investigate_bundle(
                    target_bundle,
                    correlation_id=incident.correlation_id,
                    prompt_version=prompt_version,
                    allowed_tools=allowed_tools,
                )
                summary = exec_result.summary
            else:
                summary = await self._investigator.investigate(
                    finding, list(evidence_artifacts or [])
                )
            summary = validate_investigation_output(summary, finding=finding)
        except (
            LLMProviderError,
            LLMResponseValidationError,
            ConfigurationError,
            ContractValidationError,
        ) as exc:
            fail_event = build_incident_event(
                incident_id=incident.incident_id,
                event_type=EventType.INVESTIGATION_FAILED,
                actor="agent_core_investigator",
                actor_type=ActorType.AI_AGENT,
                sequence_number=next_seq,
                correlation_id=incident.correlation_id,
                timestamp_utc=self._clock.now(),
                payload={
                    "finding_id": finding.finding_id,
                    "error_code": getattr(exc, "error_code", "INVESTIGATION_FAILED"),
                },
            )
            ai_producer = ProducerContext(
                producer_id="agent_core_investigator",
                actor_type=ActorType.AI_AGENT,
                authenticated=producer_context.authenticated,
                trusted_channel=producer_context.trusted_channel,
                provenance_mode=producer_context.provenance_mode,
            )
            await self.process_event(fail_event, producer_context=ai_producer)
            raise

        artifact_ref_id: str | None = None
        if self._evidence_repo is not None:
            serialized = canonical_json(summary.model_dump(mode="json"))
            artifact_ref_id = generate_artifact_id()
            art_ref = ArtifactReference(
                artifact_id=artifact_ref_id,
                incident_id=incident.incident_id,
                artifact_type=ArtifactType.INCIDENT_EVIDENCE_BUNDLE,
                content_hash=sha256_text(serialized),
                storage_ref=f"investigations/{incident.incident_id}/{summary.investigation_id}.json",
                created_at=self._clock.now(),
                producer="agent_core_investigator",
                provenance=summary.reasoning_source,
                content_type="application/json",
                size_bytes=len(serialized.encode("utf-8")),
                source_revision=incident.source_revision,
                redaction_status=RedactionStatus.REDACTED,
            )
            await self._evidence_repo.store_artifact(art_ref, serialized.encode("utf-8"))

        ai_producer = ProducerContext(
            producer_id="agent_core_investigator",
            actor_type=ActorType.AI_AGENT,
            authenticated=producer_context.authenticated,
            trusted_channel=producer_context.trusted_channel,
            provenance_mode=producer_context.provenance_mode,
        )
        completed_payload: dict[str, Any] = {
            "finding_id": finding.finding_id,
            "investigation_id": summary.investigation_id,
            "investigation_status": summary.investigation_status.value,
            "recommended_next_action": summary.recommended_next_action,
            "fallback_used": summary.fallback_used,
            "context_hash": summary.context_hash,
            "investigation_artifact_id": artifact_ref_id,
        }
        comp_event = build_incident_event(
            incident_id=incident.incident_id,
            event_type=EventType.INVESTIGATION_COMPLETED,
            actor="agent_core_investigator",
            actor_type=ActorType.AI_AGENT,
            sequence_number=next_seq,
            correlation_id=incident.correlation_id,
            evidence_ids=list(summary.evidence_ids),
            timestamp_utc=self._clock.now(),
            payload=completed_payload,
        )
        tctx = TransitionContext(
            producer_context=ai_producer,
            clock=self._clock,
            fixture_mode=self._fixture_mode,
            route_registry=self._route_registry,
            finding=finding,
            investigation_summary=summary,
        )
        comp_res = await self.process_event(
            comp_event, producer_context=ai_producer, transition_context=tctx
        )

        if comp_res.accepted and summary.requires_manual_review:
            review_event = build_incident_event(
                incident_id=incident.incident_id,
                event_type=EventType.MANUAL_REVIEW_REQUESTED,
                actor="agent_core_investigator",
                actor_type=ActorType.AI_AGENT,
                sequence_number=next_seq + 1,
                correlation_id=incident.correlation_id,
                evidence_ids=list(summary.evidence_ids),
                timestamp_utc=self._clock.now(),
                payload={
                    "investigation_id": summary.investigation_id,
                    "reason": "manual_review_required_by_investigation_policy",
                },
            )
            await self.process_event(review_event, producer_context=ai_producer)

        return summary, exec_result, comp_res

    async def run_mapping(
        self,
        finding: Finding,
        observed_features: list[FeatureState],
    ) -> MappingResult:
        if self._feature_mapper is None or self._route_registry is None:
            raise ConfigurationError(
                "FeatureMapperAgent and RouteFlagRegistry are required for mapping."
            )
        result = await self._feature_mapper.map_finding_to_flag(
            finding, self._route_registry, observed_features
        )
        return validate_mapping_output(result, finding=finding, registry=self._route_registry)

    async def run_containment_strategy(
        self,
        finding: Finding,
        mapping: MappingResult,
        dependency_graph: DependencyGraph,
        observed_features: list[FeatureState],
    ) -> ContainmentProposal:
        if self._containment_strategist is None or self._route_registry is None:
            raise ConfigurationError(
                "ContainmentStrategistAgent and RouteFlagRegistry are required."
            )
        proposal = await self._containment_strategist.propose_containment(
            finding, mapping, dependency_graph, observed_features
        )
        return validate_containment_proposal_output(
            proposal, finding=finding, mapping=mapping, registry=self._route_registry
        )


async def on_incident_event(
    event: IncidentEvent,
    *,
    orchestrator: IncidentOrchestrator,
    producer_context: ProducerContext,
    transition_context: TransitionContext | None = None,
) -> list[IncidentEvent]:
    """Preserved public orchestration wrapper requiring explicit trusted ProducerContext.

    Raises:
        InvalidTransitionError: If the event is rejected by the state machine or guards.
    """
    result = await orchestrator.process_event(
        event,
        producer_context=producer_context,
        transition_context=transition_context,
    )
    if not result.accepted:
        raise InvalidTransitionError(
            f"Incident event {event.event_id!r} rejected ({result.reason_code}).",
            context={
                "incident_id": event.incident_id,
                "reason_code": result.reason_code,
                "failures": [f.reason_code for f in result.guard_failures],
            },
        )
    return result.generated_events


async def analyze_incident(
    finding: Finding,
    context: dict[str, Any],
    *,
    orchestrator: IncidentOrchestrator | None = None,
) -> ContainmentProposal:
    """Preserved future analysis entry point composing mapper and containment strategist.

    Requires an injected ``IncidentOrchestrator`` configured with
    ``feature_mapper``, ``containment_strategist``, and ``route_registry``
    (including explicitly labeled fixture adapters during offline simulation).
    """
    if orchestrator is None:
        raise ConfigurationError(
            "analyze_incident requires a configured IncidentOrchestrator instance."
        )
    observed_features = context.get("observed_features", [])
    dependency_graph = context.get("dependency_graph")
    if not isinstance(dependency_graph, DependencyGraph):
        raise ContractValidationError(
            "context['dependency_graph'] must be a validated DependencyGraph instance."
        )
    mapping = await orchestrator.run_mapping(finding, observed_features)
    return await orchestrator.run_containment_strategy(
        finding, mapping, dependency_graph, observed_features
    )
