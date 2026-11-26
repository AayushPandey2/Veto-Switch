"""Deterministic transition guard evaluators enforcing fail-closed evidence & auth rules."""

from __future__ import annotations

from collections.abc import Callable, Sequence

from shared.enums import (
    ActorType,
    DeploymentStatus,
    EventType,
    EvidenceProvenance,
    FeatureObservationStatus,
    MappingStatus,
    OperationOutcome,
    RolloutDecisionType,
    TestExecutionStatus,
    VerificationPhase,
)
from shared.schemas import IncidentEvent

from agent_core.approval_validator import ApprovalValidator
from agent_core.context import GuardResult, TransitionContext
from agent_core.evidence_validator import (
    collect_event_evidence_ids,
    validate_producer_for_evidence,
    validate_provenance_for_mode,
)
from agent_core.incident import IncidentAggregate
from agent_core.mapping.registry import IndexedRouteRegistry
from agent_core.mapping.resolvers import compute_authoritative_candidates

GuardFn = Callable[[IncidentAggregate, IncidentEvent, TransitionContext], GuardResult]

_TRUSTED_PRODUCERS_BY_EVENT: dict[EventType, frozenset[ActorType]] = {
    EventType.FINDING_RECEIVED: frozenset(
        {ActorType.SECURITY_SCANNER, ActorType.SECURITY_VERIFIER, ActorType.SYSTEM}
    ),
    EventType.VERIFICATION_REQUESTED: frozenset(
        {ActorType.DETERMINISTIC_ENGINE, ActorType.SYSTEM, ActorType.HUMAN_OPERATOR}
    ),
    EventType.VALIDATION_REQUESTED: frozenset(
        {ActorType.DETERMINISTIC_ENGINE, ActorType.SYSTEM, ActorType.HUMAN_OPERATOR}
    ),
    EventType.REPRODUCTION_CONFIRMED: frozenset({ActorType.SECURITY_VERIFIER}),
    EventType.VULNERABILITY_REPRODUCED: frozenset({ActorType.SECURITY_VERIFIER}),
    EventType.REPRODUCTION_NOT_CONFIRMED: frozenset({ActorType.SECURITY_VERIFIER}),
    EventType.VERIFICATION_INCONCLUSIVE: frozenset({ActorType.SECURITY_VERIFIER}),
    EventType.VERIFICATION_FAILED: frozenset({ActorType.SECURITY_VERIFIER}),
    EventType.VERIFICATION_TIMEOUT: frozenset({ActorType.SECURITY_VERIFIER, ActorType.SYSTEM}),
    EventType.VULNERABILITY_UNVERIFIED: frozenset({ActorType.SECURITY_VERIFIER}),
    EventType.MAPPING_MATCHED: frozenset(
        {ActorType.DETERMINISTIC_ENGINE, ActorType.AI_AGENT, ActorType.HUMAN_OPERATOR}
    ),
    EventType.FLAG_MAPPED: frozenset(
        {ActorType.DETERMINISTIC_ENGINE, ActorType.AI_AGENT, ActorType.HUMAN_OPERATOR}
    ),
    EventType.CONTAINMENT_PROPOSED: frozenset(
        {ActorType.DETERMINISTIC_ENGINE, ActorType.AI_AGENT, ActorType.HUMAN_OPERATOR}
    ),
    EventType.APPROVAL_GRANTED: frozenset({ActorType.HUMAN_OPERATOR}),
    EventType.APPROVAL_REJECTED: frozenset({ActorType.HUMAN_OPERATOR}),
    EventType.ROLLOUT_STAGE_APPROVED: frozenset({ActorType.HUMAN_OPERATOR}),
    EventType.ROLLBACK_APPROVED: frozenset({ActorType.HUMAN_OPERATOR}),
    EventType.ROLLBACK_REJECTED: frozenset({ActorType.HUMAN_OPERATOR}),
    EventType.FLAG_UPDATE_SUCCESS: frozenset({ActorType.PLATFORM_EXECUTOR}),
    EventType.FLAG_CHANGE_EXECUTED: frozenset({ActorType.PLATFORM_EXECUTOR}),
    EventType.FLAG_UPDATE_FAILED: frozenset({ActorType.PLATFORM_EXECUTOR}),
    EventType.FLAG_CHANGE_FAILED: frozenset({ActorType.PLATFORM_EXECUTOR}),
    EventType.FLAG_UPDATE_OUTCOME_UNKNOWN: frozenset(
        {ActorType.PLATFORM_EXECUTOR, ActorType.SYSTEM}
    ),
    EventType.FLAG_STATE_OBSERVED: frozenset(
        {ActorType.PLATFORM_EXECUTOR, ActorType.SECURITY_VERIFIER, ActorType.SYSTEM}
    ),
    EventType.CONTAINMENT_VERIFICATION_PASSED: frozenset({ActorType.SECURITY_VERIFIER}),
    EventType.CONTAINMENT_VERIFICATION_FAILED: frozenset({ActorType.SECURITY_VERIFIER}),
    EventType.CONTAINMENT_CONFIRMED: frozenset(
        {ActorType.SECURITY_VERIFIER, ActorType.DETERMINISTIC_ENGINE}
    ),
    EventType.CONTAINMENT_VERIFIED: frozenset(
        {ActorType.SECURITY_VERIFIER, ActorType.DETERMINISTIC_ENGINE}
    ),
    EventType.CONTAINMENT_FAILED: frozenset({ActorType.SECURITY_VERIFIER}),
    EventType.FUNCTIONAL_SMOKE_TEST_PASSED: frozenset(
        {ActorType.SECURITY_VERIFIER, ActorType.PLATFORM_EXECUTOR, ActorType.SYSTEM}
    ),
    EventType.FUNCTIONAL_SMOKE_TEST_FAILED: frozenset(
        {ActorType.SECURITY_VERIFIER, ActorType.PLATFORM_EXECUTOR, ActorType.SYSTEM}
    ),
    EventType.PATCH_TEST_PASSED: frozenset({ActorType.SECURITY_VERIFIER}),
    EventType.PATCH_TEST_FAILED: frozenset({ActorType.SECURITY_VERIFIER}),
    EventType.PATCH_TEST_INFRASTRUCTURE_ERROR: frozenset(
        {ActorType.SECURITY_VERIFIER, ActorType.SYSTEM}
    ),
    EventType.DEPLOYMENT_OBSERVED: frozenset({ActorType.PLATFORM_EXECUTOR, ActorType.SYSTEM}),
    EventType.PATCH_DEPLOYMENT_OBSERVED: frozenset({ActorType.PLATFORM_EXECUTOR, ActorType.SYSTEM}),
    EventType.ROLLOUT_STAGE_APPLIED: frozenset({ActorType.PLATFORM_EXECUTOR}),
    EventType.ROLLOUT_STAGE_OBSERVED: frozenset({ActorType.PLATFORM_EXECUTOR, ActorType.SYSTEM}),
    EventType.ROLLBACK_APPLIED: frozenset({ActorType.PLATFORM_EXECUTOR}),
    EventType.ROLLBACK_VERIFICATION_PASSED: frozenset({ActorType.SECURITY_VERIFIER}),
    EventType.ROLLBACK_VERIFICATION_FAILED: frozenset({ActorType.SECURITY_VERIFIER}),
    EventType.INCIDENT_REOPENED: frozenset({ActorType.HUMAN_OPERATOR, ActorType.SECURITY_VERIFIER}),
}


def _ok(
    guard: str, reason_code: str, message: str, evidence_ids: list[str] | None = None
) -> GuardResult:
    return GuardResult(
        allowed=True,
        guard=guard,
        reason_code=reason_code,
        message=message,
        evidence_ids=evidence_ids or [],
    )


def _fail(
    guard: str,
    reason_code: str,
    message: str,
    missing: list[str] | None = None,
    evidence_ids: list[str] | None = None,
    retryable: bool = False,
) -> GuardResult:
    return GuardResult(
        allowed=False,
        guard=guard,
        reason_code=reason_code,
        message=message,
        missing_requirements=missing or [],
        evidence_ids=evidence_ids or [],
        retryable=retryable,
    )


def guard_producer_authenticity(
    incident: IncidentAggregate, event: IncidentEvent, context: TransitionContext
) -> GuardResult:
    """1. Verify event producer is authenticated and authorized for this event type."""
    allowed = _TRUSTED_PRODUCERS_BY_EVENT.get(
        event.event_type,
        frozenset(
            {
                ActorType.DETERMINISTIC_ENGINE,
                ActorType.HUMAN_OPERATOR,
                ActorType.PLATFORM_EXECUTOR,
                ActorType.SECURITY_VERIFIER,
                ActorType.SECURITY_SCANNER,
                ActorType.AI_AGENT,
                ActorType.SYSTEM,
            }
        ),
    )
    if context.producer_context.actor_type != event.actor_type:
        return _fail(
            "producer_authenticity",
            "ACTOR_TYPE_MISMATCH",
            "Event actor_type does not match authenticated ProducerContext.",
            missing=["matching_producer_actor_type"],
        )
    return validate_producer_for_evidence(context.producer_context, allowed_actor_types=allowed)


def guard_incident_identity(
    incident: IncidentAggregate, event: IncidentEvent, context: TransitionContext
) -> GuardResult:
    """2. Verify event belongs to the target incident."""
    if event.incident_id != incident.incident_id:
        return _fail(
            "incident_identity",
            "INCIDENT_ID_MISMATCH",
            f"Event incident_id {event.incident_id!r} != {incident.incident_id!r}.",
            missing=["matching_incident_id"],
        )
    return _ok("incident_identity", "INCIDENT_IDENTITY_VERIFIED", "Incident identity matched.")


def guard_finding_identity(
    incident: IncidentAggregate, event: IncidentEvent, context: TransitionContext
) -> GuardResult:
    """3. Verify referenced Finding or InvestigationSummary matches incident & finding."""
    if context.finding is not None:
        if context.finding.incident_id != incident.incident_id:
            return _fail(
                "finding_identity",
                "FINDING_INCIDENT_MISMATCH",
                "Finding belongs to a different incident.",
                missing=["matching_finding_incident_id"],
            )
        if context.finding.finding_id != incident.finding_id:
            return _fail(
                "finding_identity",
                "FINDING_ID_MISMATCH",
                "Finding ID does not match primary incident finding.",
                missing=["matching_finding_id"],
            )
    if (
        context.verification_result is not None
        and context.verification_result.incident_id != incident.incident_id
    ):
        return _fail(
            "finding_identity",
            "VERIFICATION_INCIDENT_MISMATCH",
            "VerificationResult belongs to a different incident.",
            missing=["matching_verification_incident_id"],
        )
    if (
        context.mapping_result is not None
        and context.mapping_result.finding_id != incident.finding_id
    ):
        return _fail(
            "finding_identity",
            "MAPPING_FINDING_MISMATCH",
            "MappingResult finding_id does not match incident finding_id.",
            missing=["matching_mapping_finding_id"],
        )
    if (
        context.investigation_summary is not None
        and (
            context.investigation_summary.incident_id != incident.incident_id
            or context.investigation_summary.finding_id != incident.finding_id
        )
    ):
        return _fail(
            "finding_identity",
            "INVESTIGATION_IDENTITY_MISMATCH",
            "InvestigationSummary incident_id or finding_id does not match incident.",
            missing=["matching_investigation_identity"],
        )
    return _ok("finding_identity", "FINDING_IDENTITY_VERIFIED", "Finding identity verified.")


def guard_evidence_existence(
    incident: IncidentAggregate, event: IncidentEvent, context: TransitionContext
) -> GuardResult:
    """4. Verify non-empty evidence references and existence in verified evidence set."""
    evidence_ids = collect_event_evidence_ids(event, context)
    if not evidence_ids:
        return _fail(
            "evidence_existence",
            "MISSING_EVIDENCE",
            "Critical transition requires non-empty verified evidence references.",
            missing=["evidence_ids"],
        )
    if context.existing_evidence_ids is not None:
        missing = [eid for eid in evidence_ids if eid not in context.existing_evidence_ids]
        if missing:
            return _fail(
                "evidence_existence",
                "UNKNOWN_OR_CROSS_INCIDENT_EVIDENCE",
                f"Evidence IDs missing or not bound to incident: {missing}",
                missing=missing,
                evidence_ids=evidence_ids,
            )
    return _ok(
        "evidence_existence",
        "EVIDENCE_EXISTS",
        "All required evidence references are present and verified.",
        evidence_ids=evidence_ids,
    )


def guard_evidence_provenance(
    incident: IncidentAggregate, event: IncidentEvent, context: TransitionContext
) -> GuardResult:
    """5. Ensure fixture/synthetic evidence cannot satisfy live operational gates."""
    provenance = EvidenceProvenance.ACTUAL_OBSERVED
    if context.verification_result is not None:
        provenance = context.verification_result.provenance
    elif context.operation_receipt is not None:
        provenance = context.operation_receipt.provenance
    elif context.patch_test_result is not None:
        provenance = context.patch_test_result.provenance
    elif context.deployment_evidence is not None:
        provenance = context.deployment_evidence.provenance
    elif context.metric_snapshot is not None:
        provenance = context.metric_snapshot.provenance
    elif context.evidence_artifacts:
        provenance = context.evidence_artifacts[0].provenance
    elif incident.is_synthetic_fixture:
        provenance = EvidenceProvenance.REFERENCE_FIXTURE

    return validate_provenance_for_mode(
        provenance,
        fixture_mode=context.fixture_mode,
        producer_mode=context.producer_context.provenance_mode,
        require_observed_in_live=True,
    )


def guard_environment_consistency(
    incident: IncidentAggregate, event: IncidentEvent, context: TransitionContext
) -> GuardResult:
    """6. Verify target environment matches across incident, registry, and evidence."""
    expected_env = incident.environment
    if (
        context.finding is not None
        and context.finding.environment is not None
        and context.finding.environment != expected_env
    ):
        return _fail(
            "environment_consistency",
            "FINDING_ENVIRONMENT_MISMATCH",
            "Finding environment does not match incident environment.",
            missing=["matching_environment"],
        )
    if (
        context.containment_proposal is not None
        and context.containment_proposal.environment != expected_env
    ):
        return _fail(
            "environment_consistency",
            "PROPOSAL_ENVIRONMENT_MISMATCH",
            "ContainmentProposal environment does not match incident environment.",
            missing=["matching_environment"],
        )
    if (
        context.operation_receipt is not None
        and context.operation_receipt.environment != expected_env
    ):
        return _fail(
            "environment_consistency",
            "RECEIPT_ENVIRONMENT_MISMATCH",
            "OperationReceipt environment does not match incident environment.",
            missing=["matching_environment"],
        )
    if context.feature_state is not None and context.feature_state.environment != expected_env:
        return _fail(
            "environment_consistency",
            "FEATURE_STATE_ENVIRONMENT_MISMATCH",
            "FeatureState environment does not match incident environment.",
            missing=["matching_environment"],
        )
    if (
        context.deployment_evidence is not None
        and context.deployment_evidence.environment != expected_env
    ):
        return _fail(
            "environment_consistency",
            "DEPLOYMENT_ENVIRONMENT_MISMATCH",
            "DeploymentEvidence environment does not match incident environment.",
            missing=["matching_environment"],
        )
    return _ok(
        "environment_consistency",
        "ENVIRONMENT_CONSISTENT",
        f"Environment {expected_env!r} consistent across artifacts.",
    )


def guard_revision_consistency(
    incident: IncidentAggregate, event: IncidentEvent, context: TransitionContext
) -> GuardResult:
    """7. Verify source revision consistency across verification, patches, and deployments."""
    if context.verification_result is not None:
        vr = context.verification_result
        expected_rev = (
            incident.verified_deployment_revision or incident.source_revision
            if vr.phase == VerificationPhase.AFTER_PATCH
            else incident.source_revision
        )
        if (
            vr.expected_revision
            and vr.tested_revision
            and vr.expected_revision != vr.tested_revision
        ):
            return _fail(
                "revision_consistency",
                "VERIFICATION_REVISION_MISMATCH",
                f"Tested revision {vr.tested_revision!r} != expected {vr.expected_revision!r}.",
                missing=["matching_tested_revision"],
            )
        if expected_rev and vr.tested_revision and vr.tested_revision != expected_rev:
            return _fail(
                "revision_consistency",
                "INCIDENT_REVISION_MISMATCH",
                f"Verification revision {vr.tested_revision!r} != incident {expected_rev!r}.",
                missing=["matching_incident_revision"],
            )
    if context.patch_test_result is not None and context.patch_test_result.has_revision_mismatch:
        return _fail(
            "revision_consistency",
            "PATCH_REVISION_MISMATCH",
            "PatchTestResult tested_source_revision differs from expected_source_revision.",
            missing=["matching_patch_revision"],
        )
    if (
        context.deployment_evidence is not None
        and incident.verified_deployment_revision is not None
        and context.deployment_evidence.source_revision != incident.verified_deployment_revision
    ):
        return _fail(
            "revision_consistency",
            "DEPLOYMENT_REVISION_MISMATCH",
            "Deployment revision differs from verified deployment revision.",
            missing=["matching_deployment_revision"],
        )
    return _ok("revision_consistency", "REVISION_CONSISTENT", "Source revisions consistent.")


def guard_registry_validity(
    incident: IncidentAggregate, event: IncidentEvent, context: TransitionContext
) -> GuardResult:
    """8. Verify route registry availability, version, and declared feature membership."""
    reg = context.route_registry
    if reg is None:
        return _fail(
            "registry_validity",
            "MISSING_ROUTE_REGISTRY",
            "Authoritative RouteFlagRegistry is required to validate feature targets.",
            missing=["route_registry"],
        )
    if reg.environment != incident.environment:
        return _fail(
            "registry_validity",
            "REGISTRY_ENVIRONMENT_MISMATCH",
            f"Registry environment {reg.environment!r} != incident {incident.environment!r}.",
            missing=["matching_registry_environment"],
        )
    if context.mapping_result is not None:
        if context.mapping_result.registry_version != reg.registry_version:
            return _fail(
                "registry_validity",
                "STALE_REGISTRY_VERSION",
                "MappingResult used a stale or mismatched registry version.",
                missing=["current_registry_version"],
            )
        if (
            context.mapping_result.selected_flag
            and context.mapping_result.selected_flag not in reg.declared_features
        ):
            return _fail(
                "registry_validity",
                "UNKNOWN_FEATURE_FLAG",
                f"Selected flag {context.mapping_result.selected_flag!r} is not declared.",
                missing=["declared_feature_flag"],
            )
        if context.mapping_result.selected_flag:
            indexed = IndexedRouteRegistry(reg)
            auth_candidates = compute_authoritative_candidates(
                indexed,
                route=context.mapping_result.affected_route,
                component=context.mapping_result.matched_component,
            )
            if context.mapping_result.selected_flag not in auth_candidates:
                return _fail(
                    "registry_validity",
                    "SEMANTIC_MAPPING_MISMATCH",
                    f"Selected flag {context.mapping_result.selected_flag!r} does not control "
                    f"route={context.mapping_result.affected_route!r} / "
                    f"component={context.mapping_result.matched_component!r}.",
                    missing=["semantically_valid_feature_flag"],
                )
    prop = context.containment_proposal or context.active_proposal
    if prop is not None:
        if prop.registry_version != reg.registry_version:
            return _fail(
                "registry_validity",
                "STALE_REGISTRY_VERSION",
                "ContainmentProposal references stale registry version.",
                missing=["current_registry_version"],
            )
        if prop.flag_name not in reg.declared_features:
            return _fail(
                "registry_validity",
                "UNKNOWN_FEATURE_FLAG",
                f"Proposal flag {prop.flag_name!r} is not declared in active registry.",
                missing=["declared_feature_flag"],
            )
    return _ok("registry_validity", "REGISTRY_VALID", "Feature registry and flag verified.")


def guard_mapping_validity(
    incident: IncidentAggregate, event: IncidentEvent, context: TransitionContext
) -> GuardResult:
    """9. Verify unambiguous, non-manual-review MappingResult."""
    mapping = context.mapping_result
    if mapping is None:
        return _fail(
            "mapping_validity",
            "MISSING_MAPPING_RESULT",
            "MappingResult is required before entering FLAG_MAPPED.",
            missing=["mapping_result"],
        )
    if mapping.mapping_status != MappingStatus.MATCHED or not mapping.selected_flag:
        return _fail(
            "mapping_validity",
            "UNMATCHED_OR_AMBIGUOUS_MAPPING",
            f"Mapping status is {mapping.mapping_status.value!r}; unambiguous match required.",
            missing=["unambiguous_flag_match"],
        )
    if mapping.manual_review_required:
        return _fail(
            "mapping_validity",
            "MANUAL_REVIEW_REQUIRED",
            "Mapping requires manual review before automatic flag progression.",
            missing=["human_mapping_disambiguation"],
        )
    if mapping.diagnostics is not None:
        eligibility = mapping.diagnostics.get("action_eligibility")
        if eligibility in {"hold", "blocked"}:
            return _fail(
                "mapping_validity",
                "MAPPING_NOT_OPERATIONALLY_ELIGIBLE",
                f"Mapping action_eligibility={eligibility!r} prevents progression to FLAG_MAPPED.",
                missing=["operationally_eligible_mapping"],
            )
    return _ok(
        "mapping_validity",
        "MAPPING_VALID",
        f"Validated mapping to flag {mapping.selected_flag!r}.",
        evidence_ids=list(mapping.evidence_ids),
    )


def guard_proposal_integrity(
    incident: IncidentAggregate, event: IncidentEvent, context: TransitionContext
) -> GuardResult:
    """10. Verify active ContainmentProposal hash integrity, expiration, and approval flag."""
    proposal = context.containment_proposal or context.active_proposal
    if proposal is None:
        return _fail(
            "proposal_integrity",
            "MISSING_CONTAINMENT_PROPOSAL",
            "Valid ContainmentProposal is required.",
            missing=["containment_proposal"],
        )
    if proposal.incident_id != incident.incident_id:
        return _fail(
            "proposal_integrity",
            "PROPOSAL_INCIDENT_MISMATCH",
            "Proposal incident_id does not match current incident.",
            missing=["matching_incident_proposal"],
        )
    if not proposal.verify_hash():
        return _fail(
            "proposal_integrity",
            "PROPOSAL_HASH_INVALID",
            "ContainmentProposal canonical SHA-256 hash verification failed.",
            missing=["valid_proposal_hash"],
        )
    if not proposal.approval_required:
        return _fail(
            "proposal_integrity",
            "APPROVAL_FLAG_MISSING",
            "ContainmentProposal must enforce approval_required=True.",
            missing=["mandatory_human_approval"],
        )
    if incident.mapped_flag_name and proposal.flag_name != incident.mapped_flag_name:
        return _fail(
            "proposal_integrity",
            "PROPOSAL_FLAG_MISMATCH",
            f"Proposal flag {proposal.flag_name!r} != mapped flag {incident.mapped_flag_name!r}.",
            missing=["mapped_flag_consistency"],
        )
    if proposal.expires_at <= context.evaluation_time and event.event_type not in (
        EventType.APPROVAL_REJECTED,
        EventType.APPROVAL_EXPIRED,
    ):
        return _fail(
            "proposal_integrity",
            "PROPOSAL_EXPIRED",
            "ContainmentProposal has passed its expiration timestamp.",
            missing=["unexpired_containment_proposal"],
        )
    return _ok(
        "proposal_integrity",
        "PROPOSAL_INTEGRITY_VERIFIED",
        "Proposal hash, identity, and policy requirements verified.",
        evidence_ids=list(proposal.evidence_ids),
    )


def _run_approval_checks(
    incident: IncidentAggregate, event: IncidentEvent, context: TransitionContext
) -> list[GuardResult]:
    validator = context.approval_validator or ApprovalValidator(
        clock=context.clock, route_registry=context.route_registry
    )
    if event.event_type in (EventType.ROLLOUT_STAGE_APPROVED, EventType.ROLLBACK_APPROVED):
        approval = context.stage_approval_decision or context.approval_decision
        stage_id = incident.current_rollout_stage or (
            approval.proposal_id if approval is not None else ""
        )
        return [
            validator.validate_stage_approval(
                incident=incident,
                approval=approval,
                producer=context.producer_context,
                stage_id=stage_id,
                consumed_approval_ids=context.consumed_approval_ids,
            )
        ]

    return validator.validate_containment_approval(
        incident=incident,
        proposal=context.active_proposal or context.containment_proposal,
        approval=context.approval_decision,
        producer=context.producer_context,
        feature_state=context.feature_state,
        consumed_approval_ids=context.consumed_approval_ids,
        route_registry=context.route_registry,
    )


def guard_approval_validity(
    incident: IncidentAggregate, event: IncidentEvent, context: TransitionContext
) -> GuardResult:
    """11. Verify authenticated human approval binds to exact active proposal."""
    results = _run_approval_checks(incident, event, context)
    for res in results:
        if (
            not res.allowed
            and res.guard != "approval_freshness"
            and res.guard != "feature_state_freshness"
        ):
            return res
    for res in results:
        if res.allowed:
            return res
    return results[0]


def guard_approval_freshness(
    incident: IncidentAggregate, event: IncidentEvent, context: TransitionContext
) -> GuardResult:
    """12. Verify approval and proposal are unexpired against injected Clock."""
    results = _run_approval_checks(incident, event, context)
    for res in results:
        if not res.allowed and res.guard == "approval_freshness":
            return res
    return _ok("approval_freshness", "APPROVAL_FRESH", "Approval freshness verified.")


def guard_feature_state_freshness(
    incident: IncidentAggregate, event: IncidentEvent, context: TransitionContext
) -> GuardResult:
    """13. Verify FeatureState is explicitly OBSERVED (unknown != disabled)."""
    fs = context.feature_state
    if fs is None:
        return _fail(
            "feature_state_freshness",
            "MISSING_FEATURE_STATE",
            "Observed FeatureState is required; missing state cannot be assumed safe/disabled.",
            missing=["observed_feature_state"],
        )
    if fs.observation_status != FeatureObservationStatus.OBSERVED or fs.enabled is None:
        return _fail(
            "feature_state_freshness",
            "UNKNOWN_FEATURE_STATE",
            "FeatureState is unknown or unavailable; never treated as disabled.",
            missing=["observed_feature_state"],
        )
    if incident.mapped_flag_name and fs.feature_name != incident.mapped_flag_name:
        return _fail(
            "feature_state_freshness",
            "FEATURE_NAME_MISMATCH",
            f"Observed feature {fs.feature_name!r} != mapped flag {incident.mapped_flag_name!r}.",
            missing=["matching_feature_name"],
        )
    if event.event_type == EventType.APPROVAL_GRANTED:
        results = _run_approval_checks(incident, event, context)
        for res in results:
            if not res.allowed and res.guard == "feature_state_freshness":
                return res
    if (
        incident.last_operation_timestamp is not None
        and fs.observed_at < incident.last_operation_timestamp
        and event.event_type in (EventType.CONTAINMENT_CONFIRMED, EventType.CONTAINMENT_VERIFIED)
    ):
        return _fail(
            "feature_state_freshness",
            "STALE_FEATURE_STATE_READBACK",
            "FeatureState readback predates the containment Flagsmith operation.",
            missing=["post_operation_feature_state_readback"],
        )
    return _ok(
        "feature_state_freshness",
        "FEATURE_STATE_FRESH",
        f"FeatureState {fs.feature_name!r}={fs.enabled} verified.",
        evidence_ids=list(fs.evidence_ids),
    )


def guard_operation_receipt_validity(
    incident: IncidentAggregate, event: IncidentEvent, context: TransitionContext
) -> GuardResult:
    """14. Verify trusted OperationReceipt matches proposal, approval, and observed state."""
    receipt = context.operation_receipt
    if receipt is None:
        return _fail(
            "operation_receipt_validity",
            "MISSING_OPERATION_RECEIPT",
            "Trusted external OperationReceipt is required.",
            missing=["operation_receipt"],
        )
    if receipt.provenance == EvidenceProvenance.LLM_INTERPRETATION:
        return _fail(
            "operation_receipt_validity",
            "LLM_RECEIPT_FORBIDDEN",
            "LLM output can never act as an external OperationReceipt.",
            missing=["external_operation_receipt"],
        )
    if receipt.incident_id != incident.incident_id:
        return _fail(
            "operation_receipt_validity",
            "RECEIPT_INCIDENT_MISMATCH",
            "OperationReceipt belongs to another incident.",
            missing=["matching_incident_receipt"],
        )
    if incident.current_proposal_id and receipt.proposal_id != incident.current_proposal_id:
        return _fail(
            "operation_receipt_validity",
            "RECEIPT_PROPOSAL_MISMATCH",
            "OperationReceipt proposal_id does not match active proposal.",
            missing=["matching_proposal_receipt"],
        )
    if incident.current_approval_id and receipt.approval_id != incident.current_approval_id:
        return _fail(
            "operation_receipt_validity",
            "RECEIPT_APPROVAL_MISMATCH",
            "OperationReceipt approval_id does not match authorizing approval.",
            missing=["matching_approval_receipt"],
        )
    if receipt.outcome != OperationOutcome.SUCCEEDED:
        return _fail(
            "operation_receipt_validity",
            "OPERATION_NOT_SUCCEEDED",
            f"OperationReceipt outcome is {receipt.outcome.value!r}.",
            missing=["successful_operation_receipt"],
        )
    return _ok(
        "operation_receipt_validity",
        "OPERATION_RECEIPT_VALID",
        "External operation receipt verified.",
        evidence_ids=list(receipt.evidence_ids),
    )


def guard_containment_verification(
    incident: IncidentAggregate, event: IncidentEvent, context: TransitionContext
) -> GuardResult:
    """15. Verify post-containment security regression + functional smoke + state readback."""
    vr = context.verification_result
    if vr is None:
        return _fail(
            "containment_verification",
            "MISSING_CONTAINMENT_VERIFICATION",
            "Post-containment VerificationResult is required.",
            missing=["post_containment_verification"],
        )
    expected_phase = VerificationPhase.AFTER_CONTAINMENT
    if vr.phase != expected_phase:
        return _fail(
            "containment_verification",
            "WRONG_VERIFICATION_PHASE",
            f"Expected phase={expected_phase.value!r}, got {vr.phase.value!r}.",
            missing=["after_containment_verification"],
        )
    if vr.execution_status != TestExecutionStatus.TEST_PASSED or vr.passed is not True:
        return _fail(
            "containment_verification",
            "CONTAINMENT_TEST_NOT_PASSED",
            f"Security regression did not pass (status={vr.execution_status.value!r}).",
            missing=["passing_security_regression"],
        )
    if vr.vulnerability_reproduced is True:
        return _fail(
            "containment_verification",
            "VULNERABILITY_STILL_REPRODUCED",
            "Vulnerability was still reproduced after containment.",
            missing=["blocked_exploit_verification"],
        )
    if (
        incident.last_operation_timestamp is not None
        and vr.completed_at is not None
        and vr.completed_at < incident.last_operation_timestamp
    ):
        return _fail(
            "containment_verification",
            "STALE_VERIFICATION_TIMESTAMP",
            "Security verification completed before the containment flag operation.",
            missing=["post_operation_verification"],
        )
    smoke_ok = (
        context.functional_smoke_passed
        if context.functional_smoke_passed is not None
        else incident.functional_smoke_test_passed
    )
    if smoke_ok is not True:
        return _fail(
            "containment_verification",
            "MISSING_OR_FAILED_SMOKE_TEST",
            "Passing functional smoke test is required alongside security regression.",
            missing=["functional_smoke_test_passed"],
        )
    return _ok(
        "containment_verification",
        "CONTAINMENT_VERIFIED",
        "Post-containment security regression, smoke test, and readback passed.",
        evidence_ids=list(vr.artifact_ids),
    )


def guard_patch_verification(
    incident: IncidentAggregate, event: IncidentEvent, context: TransitionContext
) -> GuardResult:
    """16. Verify isolated PatchTestResult (hash, revision, security + functional tests)."""
    ptr = context.patch_test_result
    if ptr is None:
        return _fail(
            "patch_verification",
            "MISSING_PATCH_TEST_RESULT",
            "Isolated PatchTestResult is required.",
            missing=["patch_test_result"],
        )
    if ptr.incident_id != incident.incident_id:
        return _fail(
            "patch_verification",
            "PATCH_INCIDENT_MISMATCH",
            "PatchTestResult belongs to a different incident.",
            missing=["matching_patch_incident"],
        )
    if context.patch_proposal is not None:
        if ptr.patch_id != context.patch_proposal.patch_id:
            return _fail(
                "patch_verification",
                "PATCH_ID_MISMATCH",
                "PatchTestResult patch_id does not match PatchProposal.",
                missing=["matching_patch_id"],
            )
        if ptr.tested_candidate_hash != context.patch_proposal.candidate_content_hash:
            return _fail(
                "patch_verification",
                "PATCH_HASH_MISMATCH",
                "Tested candidate hash does not match PatchProposal hash.",
                missing=["matching_candidate_hash"],
            )
    elif incident.active_patch_hash and ptr.tested_candidate_hash != incident.active_patch_hash:
        return _fail(
            "patch_verification",
            "PATCH_HASH_MISMATCH",
            "Tested candidate hash does not match active patch hash.",
            missing=["matching_candidate_hash"],
        )
    if ptr.isolation_metadata.get("mode") == "host":
        return _fail(
            "patch_verification",
            "INSUFFICIENT_ISOLATION",
            "Host execution is prohibited for isolated patch verification.",
            missing=["isolated_sandbox"],
        )
    if context.required_patch_tests:
        outcomes_by_name = {
            item.test_name: item.status for item in ptr.individual_outcomes
        }
        missing_req = [
            tid
            for tid in context.required_patch_tests
            if outcomes_by_name.get(tid) != TestExecutionStatus.TEST_PASSED
        ]
        if missing_req:
            return _fail(
                "patch_verification",
                "MISSING_REQUIRED_PATCH_TESTS",
                "PatchTestResult did not pass all required tests.",
                missing=missing_req,
            )
    if not ptr.is_trusted_pass:
        return _fail(
            "patch_verification",
            "UNTRUSTED_OR_FAILED_PATCH_TESTS",
            "PatchTestResult failed, had revision mismatch, or omitted required test outcomes.",
            missing=["trusted_passing_patch_tests"],
        )
    return _ok(
        "patch_verification",
        "PATCH_VERIFIED",
        "Isolated patch security and functional tests passed.",
        evidence_ids=list(ptr.artifact_ids),
    )


def guard_deployment_verification(
    incident: IncidentAggregate, event: IncidentEvent, context: TransitionContext
) -> GuardResult:
    """17. Verify observed DeploymentEvidence and implementation addressability."""
    dep = context.deployment_evidence
    if dep is None:
        return _fail(
            "deployment_verification",
            "MISSING_DEPLOYMENT_EVIDENCE",
            "DeploymentEvidence is required; patch testing alone does not prove deployment.",
            missing=["deployment_evidence"],
        )
    if dep.deployment_status != DeploymentStatus.OBSERVED or not dep.addressable:
        return _fail(
            "deployment_verification",
            "DEPLOYMENT_NOT_OBSERVED_OR_UNADDRESSABLE",
            f"Deployment status={dep.deployment_status.value!r}, addressable={dep.addressable}.",
            missing=["observed_addressable_deployment"],
        )
    if incident.active_patch_hash and dep.implementation_hash != incident.active_patch_hash:
        return _fail(
            "deployment_verification",
            "DEPLOYMENT_IMPLEMENTATION_MISMATCH",
            "Deployed implementation hash does not match tested patch candidate hash.",
            missing=["matching_deployed_implementation"],
        )
    return _ok(
        "deployment_verification",
        "DEPLOYMENT_VERIFIED",
        f"Deployment {dep.deployment_id!r} observed and addressable.",
        evidence_ids=list(dep.evidence_ids),
    )


def guard_rollout_eligibility(
    incident: IncidentAggregate, event: IncidentEvent, context: TransitionContext
) -> GuardResult:
    """18. Verify valid RolloutPlan, prerequisites, and observed feature targeting."""
    plan = context.rollout_plan
    if plan is None:
        return _fail(
            "rollout_eligibility",
            "MISSING_ROLLOUT_PLAN",
            "Valid RolloutPlan is required before entering ROLLOUT_PENDING.",
            missing=["rollout_plan"],
        )
    if plan.incident_id != incident.incident_id:
        return _fail(
            "rollout_eligibility",
            "ROLLOUT_PLAN_INCIDENT_MISMATCH",
            "RolloutPlan belongs to another incident.",
            missing=["matching_rollout_plan"],
        )
    if not plan.approval_required:
        return _fail(
            "rollout_eligibility",
            "ROLLOUT_APPROVAL_REQUIRED_FALSE",
            "RolloutPlan must enforce human approval for progressive stages.",
            missing=["approval_required_policy"],
        )
    if (
        context.deployment_evidence is not None
        and plan.target_implementation_revision != context.deployment_evidence.source_revision
    ):
        return _fail(
            "rollout_eligibility",
            "ROLLOUT_REVISION_MISMATCH",
            "RolloutPlan target revision differs from observed deployment revision.",
            missing=["matching_deployment_revision"],
        )
    return _ok(
        "rollout_eligibility",
        "ROLLOUT_ELIGIBLE",
        "Rollout plan and prerequisites verified.",
        evidence_ids=list(plan.evidence_ids),
    )


def guard_recovery_completion(
    incident: IncidentAggregate, event: IncidentEvent, context: TransitionContext
) -> GuardResult:
    """19. Verify all rollout stages completed, observed at 100%, and final checks passed."""
    if not incident.rollout_stages:
        return _fail(
            "recovery_completion",
            "NO_ROLLOUT_STAGES_EXECUTED",
            "Cannot mark incident RECOVERED without completed progressive rollout stages.",
            missing=["completed_rollout_stages"],
        )
    final_stage = incident.rollout_stages[-1]
    if final_stage.exposure_percentage < 100 or final_stage.status not in (
        "observed",
        "completed",
    ):
        return _fail(
            "recovery_completion",
            "INCOMPLETE_ROLLOUT_STAGES",
            (
                f"Final rollout stage is {final_stage.exposure_percentage}% "
                f"with status={final_stage.status!r}; 100% observed/completed required."
            ),
            missing=["100_percent_completed_stage"],
        )
    if (
        context.rollout_decision is not None
        and context.rollout_decision.decision_type != RolloutDecisionType.ADVANCE
    ):
        return _fail(
            "recovery_completion",
            "FINAL_DECISION_NOT_ADVANCE",
            "Final rollout decision did not pass all health guardrails.",
            missing=["healthy_rollout_decision"],
        )
    if (
        context.metric_snapshot is not None
        and context.metric_snapshot.security_regression_passed is not True
    ):
        return _fail(
            "recovery_completion",
            "FINAL_SECURITY_CHECK_NOT_PASSED",
            "Final security regression check during recovery has not passed.",
            missing=["final_security_regression_passed"],
        )
    if context.verification_result is None or context.verification_result.passed is not True:
        return _fail(
            "recovery_completion",
            "MISSING_FINAL_VERIFICATION",
            "Final post-patch/recovery verification result is required.",
            missing=["final_verification_result"],
        )
    return _ok(
        "recovery_completion",
        "RECOVERY_VERIFIED",
        "All progressive rollout stages, health checks, and final verifications passed.",
        evidence_ids=list(context.verification_result.artifact_ids),
    )


def guard_rollback_safety(
    incident: IncidentAggregate, event: IncidentEvent, context: TransitionContext
) -> GuardResult:
    """20. Verify RollbackProposal never blindly assumes legacy vulnerable state is safe."""
    rb = context.rollback_proposal
    if rb is None:
        return _fail(
            "rollback_safety",
            "MISSING_ROLLBACK_PROPOSAL",
            "RollbackProposal is required.",
            missing=["rollback_proposal"],
        )
    if not rb.approval_required:
        return _fail(
            "rollback_safety",
            "ROLLBACK_APPROVAL_REQUIRED",
            "RollbackProposal must require human approval.",
            missing=["human_approval_requirement"],
        )
    if not rb.last_verified_safe_state_known and not rb.manual_review_required:
        return _fail(
            "rollback_safety",
            "UNSAFE_UNKNOWN_ROLLBACK_TARGET",
            "Unknown prior safe state mandates manual_review_required=True.",
            missing=["manual_review_required"],
        )
    return _ok(
        "rollback_safety",
        "ROLLBACK_PROPOSAL_VALID",
        "Rollback proposal safety and review boundaries verified.",
        evidence_ids=list(rb.triggering_evidence_ids),
    )


GUARD_REGISTRY: dict[str, GuardFn] = {
    "producer_authenticity": guard_producer_authenticity,
    "incident_identity": guard_incident_identity,
    "finding_identity": guard_finding_identity,
    "evidence_existence": guard_evidence_existence,
    "evidence_provenance": guard_evidence_provenance,
    "environment_consistency": guard_environment_consistency,
    "revision_consistency": guard_revision_consistency,
    "registry_validity": guard_registry_validity,
    "mapping_validity": guard_mapping_validity,
    "proposal_integrity": guard_proposal_integrity,
    "approval_validity": guard_approval_validity,
    "approval_freshness": guard_approval_freshness,
    "feature_state_freshness": guard_feature_state_freshness,
    "operation_receipt_validity": guard_operation_receipt_validity,
    "containment_verification": guard_containment_verification,
    "patch_verification": guard_patch_verification,
    "deployment_verification": guard_deployment_verification,
    "rollout_eligibility": guard_rollout_eligibility,
    "recovery_completion": guard_recovery_completion,
    "rollback_safety": guard_rollback_safety,
}


def evaluate_guards(
    guard_names: Sequence[str],
    incident: IncidentAggregate,
    event: IncidentEvent,
    context: TransitionContext,
) -> list[GuardResult]:
    """Evaluate all named guards in order without short-circuiting so callers see all failures."""
    results: list[GuardResult] = []
    for name in guard_names:
        fn = GUARD_REGISTRY.get(name)
        if fn is None:
            results.append(
                _fail(
                    name,
                    "UNKNOWN_GUARD",
                    f"Transition references unregistered guard {name!r}; failing closed.",
                    missing=[name],
                )
            )
            continue
        results.append(fn(incident, event, context))
    return results
