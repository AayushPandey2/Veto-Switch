"""Deterministic vulnerability-to-feature-flag mapping subsystem."""

from agent_core.mapping.dashboard import serialize_mapping_dashboard
from agent_core.mapping.decision_policy import evaluate_mapping_decision
from agent_core.mapping.evidence_validator import validate_mapping_evidence
from agent_core.mapping.models import (
    CandidateDetail,
    ComponentResolutionResult,
    EvidenceValidationOutcome,
    FreshnessPolicy,
    ImplementationResolutionResult,
    MappingContext,
    MappingDiagnostics,
    MappingOutcome,
    RegistryValidationReport,
    RejectedCandidate,
    RouteResolutionResult,
    StateValidationResult,
)
from agent_core.mapping.registry import (
    IndexedRouteRegistry,
    compute_registry_fingerprint,
    validate_registry,
)
from agent_core.mapping.resolvers import (
    compute_authoritative_candidates,
    resolve_component,
    resolve_implementation,
    resolve_route,
)
from agent_core.mapping.state_validator import validate_feature_states

__all__ = [
    "CandidateDetail",
    "ComponentResolutionResult",
    "EvidenceValidationOutcome",
    "FreshnessPolicy",
    "ImplementationResolutionResult",
    "IndexedRouteRegistry",
    "MappingContext",
    "MappingDiagnostics",
    "MappingOutcome",
    "RegistryValidationReport",
    "RejectedCandidate",
    "RouteResolutionResult",
    "StateValidationResult",
    "compute_authoritative_candidates",
    "compute_registry_fingerprint",
    "evaluate_mapping_decision",
    "resolve_component",
    "resolve_implementation",
    "resolve_route",
    "serialize_mapping_dashboard",
    "validate_feature_states",
    "validate_mapping_evidence",
    "validate_registry",
]
