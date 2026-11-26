"""Killswitch X — Agent Core package (Phase 02 Orchestration & State Machine).

Owned by AI/ML Engineer 1 (Agent Intelligence and Orchestration).

Exposes the deterministic incident state machine, centralized transition registry,
transition guards, incident aggregate, event processing pipeline, approval and
evidence validators, idempotency, bounded retry policies, replay engine, in-memory
reference repository, and ``IncidentOrchestrator``.

Security boundary:
    ``agent_core`` has zero direct Flagsmith mutation capability, zero privileged
    platform credentials, and zero arbitrary shell execution.
"""

from __future__ import annotations

from agent_core.approval_validator import ApprovalValidator
from agent_core.context import (
    Clock,
    ContainmentStrategistAgent,
    DownstreamRequest,
    EventProcessingResult,
    EvidenceReporterAgent,
    FeatureMapperAgent,
    FixedClock,
    GuardResult,
    InvestigatorAgent,
    OrchestrationRepository,
    PatchEngineerAgent,
    ProducerContext,
    ReleaseManagerAgent,
    RolloutStageRecord,
    SystemClock,
    TransitionContext,
)
from agent_core.event_dispatcher import EventDispatcher
from agent_core.events import EventClassification, build_incident_event, classify_event
from agent_core.evidence_validator import EvidenceValidator
from agent_core.guards import GUARD_REGISTRY, evaluate_guards
from agent_core.idempotency import (
    build_operation_idempotency_key,
    check_event_idempotency,
    compute_event_payload_hash,
)
from agent_core.incident import IncidentAggregate
from agent_core.orchestrator import IncidentOrchestrator, analyze_incident, on_incident_event
from agent_core.replay import replay_incident, verify_event_history_integrity
from agent_core.repositories.memory import InMemoryOrchestrationRepository
from agent_core.retry_policy import (
    RetryClassification,
    RetryExecutionResult,
    RetryPolicyConfig,
    classify_error,
    execute_with_retry,
)
from agent_core.state_machine import (
    apply_transition,
    can_transition,
    get_allowed_events,
    get_target_state,
    is_non_transition_event,
    validate_transition,
)
from agent_core.transitions import (
    EVIDENCE_REQUIREMENTS,
    NON_TRANSITION_RULES,
    TRANSITION_INDEX,
    TRANSITION_RULES,
    generate_mermaid_state_diagram,
)

__all__ = [
    "EVIDENCE_REQUIREMENTS",
    "GUARD_REGISTRY",
    "NON_TRANSITION_RULES",
    "TRANSITION_INDEX",
    "TRANSITION_RULES",
    "ApprovalValidator",
    "Clock",
    "ContainmentStrategistAgent",
    "DownstreamRequest",
    "EventClassification",
    "EventDispatcher",
    "EventProcessingResult",
    "EvidenceReporterAgent",
    "EvidenceValidator",
    "FeatureMapperAgent",
    "FixedClock",
    "GuardResult",
    "InMemoryOrchestrationRepository",
    "IncidentAggregate",
    "IncidentOrchestrator",
    "InvestigatorAgent",
    "OrchestrationRepository",
    "PatchEngineerAgent",
    "ProducerContext",
    "ReleaseManagerAgent",
    "RetryClassification",
    "RetryExecutionResult",
    "RetryPolicyConfig",
    "RolloutStageRecord",
    "SystemClock",
    "TransitionContext",
    "analyze_incident",
    "apply_transition",
    "build_incident_event",
    "build_operation_idempotency_key",
    "can_transition",
    "check_event_idempotency",
    "classify_error",
    "classify_event",
    "compute_event_payload_hash",
    "evaluate_guards",
    "execute_with_retry",
    "generate_mermaid_state_diagram",
    "get_allowed_events",
    "get_target_state",
    "is_non_transition_event",
    "on_incident_event",
    "replay_incident",
    "validate_transition",
    "verify_event_history_integrity",
]
