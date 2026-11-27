"""Centralized deterministic state-transition registry and evidence requirements.

All structurally valid incident state transitions, non-transition context events,
recovery paths, and critical-state mandatory evidence definitions live here.
No LLM output or external module may define ad-hoc state transitions outside
this registry.
"""

from __future__ import annotations

from dataclasses import dataclass

from shared.enums import EventType, IncidentState


@dataclass(frozen=True)
class TransitionRule:
    """Immutable specification of a single permitted state transition."""

    from_state: IncidentState
    event_type: EventType
    to_state: IncidentState
    required_guards: tuple[str, ...]
    is_recovery: bool = False
    description: str = ""


@dataclass(frozen=True)
class NonTransitionRule:
    """Specification for events that update incident context without changing state."""

    event_type: EventType
    allowed_states: frozenset[IncidentState]
    required_guards: tuple[str, ...]
    description: str = ""


# Common baseline guards applied to every incoming event transition.
_BASE_GUARDS: tuple[str, ...] = ("producer_authenticity", "incident_identity")

# ------------------------------------------------------------------------------
# Centralized Primary + Failure + Recovery Transition Registry
# ------------------------------------------------------------------------------
TRANSITION_RULES: tuple[TransitionRule, ...] = (
    # --- Finding Intake & Verification ---
    TransitionRule(
        from_state=IncidentState.RECEIVED,
        event_type=EventType.VERIFICATION_REQUESTED,
        to_state=IncidentState.VALIDATION_REQUESTED,
        required_guards=(*_BASE_GUARDS, "finding_identity"),
        description="Request authorized vulnerability reproduction.",
    ),
    TransitionRule(
        from_state=IncidentState.RECEIVED,
        event_type=EventType.VALIDATION_REQUESTED,
        to_state=IncidentState.VALIDATION_REQUESTED,
        required_guards=(*_BASE_GUARDS, "finding_identity"),
        description="Alias for requesting authorized vulnerability reproduction.",
    ),
    TransitionRule(
        from_state=IncidentState.VALIDATION_REQUESTED,
        event_type=EventType.REPRODUCTION_CONFIRMED,
        to_state=IncidentState.REPRODUCED,
        required_guards=(
            *_BASE_GUARDS,
            "finding_identity",
            "evidence_existence",
            "evidence_provenance",
            "environment_consistency",
            "revision_consistency",
        ),
        description="Trusted reproduction evidence confirmed vulnerability.",
    ),
    TransitionRule(
        from_state=IncidentState.VALIDATION_REQUESTED,
        event_type=EventType.VULNERABILITY_REPRODUCED,
        to_state=IncidentState.REPRODUCED,
        required_guards=(
            *_BASE_GUARDS,
            "finding_identity",
            "evidence_existence",
            "evidence_provenance",
            "environment_consistency",
            "revision_consistency",
        ),
        description="Prompt 01 alias for confirmed vulnerability reproduction.",
    ),
    TransitionRule(
        from_state=IncidentState.VALIDATION_REQUESTED,
        event_type=EventType.REPRODUCTION_NOT_CONFIRMED,
        to_state=IncidentState.UNVERIFIED,
        required_guards=(*_BASE_GUARDS, "finding_identity"),
        description="Vulnerability could not be reproduced; hold in UNVERIFIED.",
    ),
    TransitionRule(
        from_state=IncidentState.VALIDATION_REQUESTED,
        event_type=EventType.VERIFICATION_INCONCLUSIVE,
        to_state=IncidentState.UNVERIFIED,
        required_guards=(*_BASE_GUARDS, "finding_identity"),
        description="Verification returned inconclusive evidence.",
    ),
    TransitionRule(
        from_state=IncidentState.VALIDATION_REQUESTED,
        event_type=EventType.VERIFICATION_FAILED,
        to_state=IncidentState.UNVERIFIED,
        required_guards=(*_BASE_GUARDS, "finding_identity"),
        description="Verification service reported failure.",
    ),
    TransitionRule(
        from_state=IncidentState.VALIDATION_REQUESTED,
        event_type=EventType.VERIFICATION_TIMEOUT,
        to_state=IncidentState.UNVERIFIED,
        required_guards=(*_BASE_GUARDS, "finding_identity"),
        description="Verification timed out without reproduction evidence.",
    ),
    TransitionRule(
        from_state=IncidentState.VALIDATION_REQUESTED,
        event_type=EventType.VULNERABILITY_UNVERIFIED,
        to_state=IncidentState.UNVERIFIED,
        required_guards=(*_BASE_GUARDS, "finding_identity"),
        description="Prompt 01 alias for unverified vulnerability.",
    ),
    # --- Investigation & Mapping ---
    TransitionRule(
        from_state=IncidentState.REPRODUCED,
        event_type=EventType.MAPPING_MATCHED,
        to_state=IncidentState.FLAG_MAPPED,
        required_guards=(
            *_BASE_GUARDS,
            "finding_identity",
            "evidence_existence",
            "environment_consistency",
            "registry_validity",
            "mapping_validity",
        ),
        description="Finding mapped unambiguously to declared feature flag.",
    ),
    TransitionRule(
        from_state=IncidentState.REPRODUCED,
        event_type=EventType.FLAG_MAPPED,
        to_state=IncidentState.FLAG_MAPPED,
        required_guards=(
            *_BASE_GUARDS,
            "finding_identity",
            "evidence_existence",
            "environment_consistency",
            "registry_validity",
            "mapping_validity",
        ),
        description="Prompt 01 alias for validated feature flag mapping.",
    ),
    TransitionRule(
        from_state=IncidentState.REPRODUCED,
        event_type=EventType.MAPPING_UNMAPPED,
        to_state=IncidentState.UNMAPPED,
        required_guards=(*_BASE_GUARDS, "finding_identity"),
        description="No feature flag covers affected route/component.",
    ),
    TransitionRule(
        from_state=IncidentState.REPRODUCED,
        event_type=EventType.MAPPING_AMBIGUOUS,
        to_state=IncidentState.UNMAPPED,
        required_guards=(*_BASE_GUARDS, "finding_identity"),
        description="Multiple candidate flags; human disambiguation required.",
    ),
    TransitionRule(
        from_state=IncidentState.REPRODUCED,
        event_type=EventType.MAPPING_FAILED,
        to_state=IncidentState.UNMAPPED,
        required_guards=(*_BASE_GUARDS, "finding_identity"),
        description="Feature flag mapping failed or registry invalid.",
    ),
    TransitionRule(
        from_state=IncidentState.REPRODUCED,
        event_type=EventType.FLAG_MAPPING_FAILED,
        to_state=IncidentState.UNMAPPED,
        required_guards=(*_BASE_GUARDS, "finding_identity"),
        description="Prompt 01 alias for feature flag mapping failure.",
    ),
    # --- Containment Proposal & Human Approval ---
    TransitionRule(
        from_state=IncidentState.FLAG_MAPPED,
        event_type=EventType.CONTAINMENT_PROPOSED,
        to_state=IncidentState.CONTAINMENT_PROPOSED,
        required_guards=(
            *_BASE_GUARDS,
            "evidence_existence",
            "evidence_provenance",
            "environment_consistency",
            "registry_validity",
            "proposal_integrity",
        ),
        description="Schema-valid containment proposal generated with evidence.",
    ),
    TransitionRule(
        from_state=IncidentState.CONTAINMENT_PROPOSED,
        event_type=EventType.APPROVAL_REQUESTED,
        to_state=IncidentState.AWAITING_APPROVAL,
        required_guards=(*_BASE_GUARDS, "proposal_integrity"),
        description="Submit containment proposal for authenticated human approval.",
    ),
    TransitionRule(
        from_state=IncidentState.AWAITING_APPROVAL,
        event_type=EventType.APPROVAL_GRANTED,
        to_state=IncidentState.APPLYING,
        required_guards=(
            *_BASE_GUARDS,
            "evidence_existence",
            "environment_consistency",
            "registry_validity",
            "proposal_integrity",
            "approval_validity",
            "approval_freshness",
            "feature_state_freshness",
        ),
        description="Human approval validated; authorize external Flagsmith execution.",
    ),
    TransitionRule(
        from_state=IncidentState.AWAITING_APPROVAL,
        event_type=EventType.APPROVAL_REJECTED,
        to_state=IncidentState.REJECTED,
        required_guards=(*_BASE_GUARDS, "proposal_integrity"),
        description="Human operator rejected pending containment proposal.",
    ),
    TransitionRule(
        from_state=IncidentState.AWAITING_APPROVAL,
        event_type=EventType.APPROVAL_EXPIRED,
        to_state=IncidentState.REJECTED,
        required_guards=(*_BASE_GUARDS,),
        description="Pending approval window expired without authorization.",
    ),
    TransitionRule(
        from_state=IncidentState.AWAITING_APPROVAL,
        event_type=EventType.CONTAINMENT_PROPOSAL_INVALIDATED,
        to_state=IncidentState.REJECTED,
        required_guards=(*_BASE_GUARDS,),
        description="Proposal invalidated prior to execution.",
    ),
    # --- External Execution & Post-Containment Verification ---
    TransitionRule(
        from_state=IncidentState.APPLYING,
        event_type=EventType.FLAG_UPDATE_SUCCESS,
        to_state=IncidentState.CONTAINMENT_TEST_PENDING,
        required_guards=(
            *_BASE_GUARDS,
            "environment_consistency",
            "operation_receipt_validity",
        ),
        description="External executor confirmed flag change; await readback & tests.",
    ),
    TransitionRule(
        from_state=IncidentState.APPLYING,
        event_type=EventType.FLAG_CHANGE_EXECUTED,
        to_state=IncidentState.CONTAINMENT_TEST_PENDING,
        required_guards=(
            *_BASE_GUARDS,
            "environment_consistency",
            "operation_receipt_validity",
        ),
        description="Prompt 01 alias for external flag update receipt.",
    ),
    TransitionRule(
        from_state=IncidentState.APPLYING,
        event_type=EventType.FLAG_UPDATE_FAILED,
        to_state=IncidentState.CHANGE_FAILED,
        required_guards=(*_BASE_GUARDS, "environment_consistency"),
        description="External Flagsmith operation failed or was rejected.",
    ),
    TransitionRule(
        from_state=IncidentState.APPLYING,
        event_type=EventType.FLAG_CHANGE_FAILED,
        to_state=IncidentState.CHANGE_FAILED,
        required_guards=(*_BASE_GUARDS, "environment_consistency"),
        description="Prompt 01 alias for failed flag update.",
    ),
    TransitionRule(
        from_state=IncidentState.APPLYING,
        event_type=EventType.FLAG_UPDATE_OUTCOME_UNKNOWN,
        to_state=IncidentState.CHANGE_FAILED,
        required_guards=(*_BASE_GUARDS,),
        description="Timeout/unknown write outcome routed to CHANGE_FAILED for reconciliation.",
    ),
    TransitionRule(
        from_state=IncidentState.CONTAINMENT_TEST_PENDING,
        event_type=EventType.CONTAINMENT_CONFIRMED,
        to_state=IncidentState.CONTAINED,
        required_guards=(
            *_BASE_GUARDS,
            "evidence_existence",
            "evidence_provenance",
            "environment_consistency",
            "revision_consistency",
            "feature_state_freshness",
            "containment_verification",
        ),
        description="Flag readback + post-change security & smoke tests confirm containment.",
    ),
    TransitionRule(
        from_state=IncidentState.CONTAINMENT_TEST_PENDING,
        event_type=EventType.CONTAINMENT_VERIFIED,
        to_state=IncidentState.CONTAINED,
        required_guards=(
            *_BASE_GUARDS,
            "evidence_existence",
            "evidence_provenance",
            "environment_consistency",
            "revision_consistency",
            "feature_state_freshness",
            "containment_verification",
        ),
        description="Prompt 01 alias for confirmed post-containment verification.",
    ),
    TransitionRule(
        from_state=IncidentState.CONTAINMENT_TEST_PENDING,
        event_type=EventType.CONTAINMENT_VERIFICATION_FAILED,
        to_state=IncidentState.CONTAINMENT_FAILED,
        required_guards=(*_BASE_GUARDS, "environment_consistency"),
        description="Post-containment verification or smoke test failed.",
    ),
    TransitionRule(
        from_state=IncidentState.CONTAINMENT_TEST_PENDING,
        event_type=EventType.CONTAINMENT_FAILED,
        to_state=IncidentState.CONTAINMENT_FAILED,
        required_guards=(*_BASE_GUARDS, "environment_consistency"),
        description="Prompt 01 alias for containment verification failure.",
    ),
    # --- Remediation / Patching ---
    TransitionRule(
        from_state=IncidentState.CONTAINED,
        event_type=EventType.PATCH_REQUESTED,
        to_state=IncidentState.PATCH_PENDING,
        required_guards=(*_BASE_GUARDS,),
        description="Initiate candidate patch generation/testing for contained incident.",
    ),
    TransitionRule(
        from_state=IncidentState.PATCH_PENDING,
        event_type=EventType.PATCH_TEST_PASSED,
        to_state=IncidentState.PATCH_TESTED,
        required_guards=(
            *_BASE_GUARDS,
            "evidence_existence",
            "evidence_provenance",
            "revision_consistency",
            "patch_verification",
        ),
        description="Candidate patch passed all required isolated security and functional tests.",
    ),
    TransitionRule(
        from_state=IncidentState.PATCH_PENDING,
        event_type=EventType.PATCH_TEST_FAILED,
        to_state=IncidentState.PATCH_FAILED,
        required_guards=(*_BASE_GUARDS,),
        description="Candidate patch failed security or functional tests.",
    ),
    TransitionRule(
        from_state=IncidentState.PATCH_PENDING,
        event_type=EventType.PATCH_VALIDATION_FAILED,
        to_state=IncidentState.PATCH_FAILED,
        required_guards=(*_BASE_GUARDS,),
        description="Candidate patch failed path allowlist or safety validation.",
    ),
    TransitionRule(
        from_state=IncidentState.PATCH_PENDING,
        event_type=EventType.PATCH_TEST_INFRASTRUCTURE_ERROR,
        to_state=IncidentState.PATCH_FAILED,
        required_guards=(*_BASE_GUARDS,),
        description="Isolated patch runner encountered an infrastructure error.",
    ),
    # --- Progressive Recovery & Rollback ---
    TransitionRule(
        from_state=IncidentState.PATCH_TESTED,
        event_type=EventType.ROLLOUT_PLAN_CREATED,
        to_state=IncidentState.ROLLOUT_PENDING,
        required_guards=(
            *_BASE_GUARDS,
            "evidence_existence",
            "environment_consistency",
            "revision_consistency",
            "patch_verification",
            "deployment_verification",
            "rollout_eligibility",
        ),
        description="Verified deployment and rollout plan ready; start staged recovery.",
    ),
    TransitionRule(
        from_state=IncidentState.ROLLOUT_PENDING,
        event_type=EventType.ROLLOUT_HOLD,
        to_state=IncidentState.ROLLOUT_PAUSED,
        required_guards=(*_BASE_GUARDS,),
        description="Pause progressive rollout due to missing telemetry or hold decision.",
    ),
    TransitionRule(
        from_state=IncidentState.ROLLOUT_PENDING,
        event_type=EventType.ROLLOUT_FAILED,
        to_state=IncidentState.ROLLOUT_PAUSED,
        required_guards=(*_BASE_GUARDS,),
        description="Pause progressive rollout on non-rollback execution failure.",
    ),
    TransitionRule(
        from_state=IncidentState.ROLLOUT_PENDING,
        event_type=EventType.ROLLBACK_PROPOSED,
        to_state=IncidentState.ROLLBACK_PROPOSED,
        required_guards=(
            *_BASE_GUARDS,
            "evidence_existence",
            "rollback_safety",
        ),
        description="Guardrail breach triggered human-reviewed rollback proposal.",
    ),
    TransitionRule(
        from_state=IncidentState.ROLLOUT_PENDING,
        event_type=EventType.ROLLOUT_COMPLETED,
        to_state=IncidentState.RECOVERED,
        required_guards=(
            *_BASE_GUARDS,
            "evidence_existence",
            "evidence_provenance",
            "environment_consistency",
            "revision_consistency",
            "deployment_verification",
            "recovery_completion",
        ),
        description="All rollout stages, readbacks, and verification checks passed.",
    ),
    # --- Explicit Audited Recovery Paths Out of Failure/Review States ---
    TransitionRule(
        from_state=IncidentState.UNVERIFIED,
        event_type=EventType.VERIFICATION_REQUESTED,
        to_state=IncidentState.VALIDATION_REQUESTED,
        required_guards=(*_BASE_GUARDS, "finding_identity"),
        is_recovery=True,
        description="Controlled re-verification requested after inconclusive result.",
    ),
    TransitionRule(
        from_state=IncidentState.UNMAPPED,
        event_type=EventType.MAPPING_MATCHED,
        to_state=IncidentState.FLAG_MAPPED,
        required_guards=(
            *_BASE_GUARDS,
            "finding_identity",
            "evidence_existence",
            "environment_consistency",
            "registry_validity",
            "mapping_validity",
        ),
        is_recovery=True,
        description="Re-mapping succeeded following route registry update or review.",
    ),
    TransitionRule(
        from_state=IncidentState.REJECTED,
        event_type=EventType.CONTAINMENT_PROPOSED,
        to_state=IncidentState.CONTAINMENT_PROPOSED,
        required_guards=(
            *_BASE_GUARDS,
            "evidence_existence",
            "evidence_provenance",
            "environment_consistency",
            "registry_validity",
            "proposal_integrity",
        ),
        is_recovery=True,
        description="New containment proposal generated after rejection or expiration.",
    ),
    TransitionRule(
        from_state=IncidentState.CHANGE_FAILED,
        event_type=EventType.CONTAINMENT_PROPOSED,
        to_state=IncidentState.CONTAINMENT_PROPOSED,
        required_guards=(
            *_BASE_GUARDS,
            "evidence_existence",
            "evidence_provenance",
            "environment_consistency",
            "registry_validity",
            "proposal_integrity",
        ),
        is_recovery=True,
        description="Regenerate containment proposal after external execution failure.",
    ),
    TransitionRule(
        from_state=IncidentState.CHANGE_FAILED,
        event_type=EventType.FLAG_UPDATE_SUCCESS,
        to_state=IncidentState.CONTAINMENT_TEST_PENDING,
        required_guards=(
            *_BASE_GUARDS,
            "environment_consistency",
            "operation_receipt_validity",
        ),
        is_recovery=True,
        description="Reconciliation confirmed external flag update succeeded.",
    ),
    TransitionRule(
        from_state=IncidentState.CONTAINMENT_FAILED,
        event_type=EventType.CONTAINMENT_PROPOSED,
        to_state=IncidentState.CONTAINMENT_PROPOSED,
        required_guards=(
            *_BASE_GUARDS,
            "evidence_existence",
            "evidence_provenance",
            "environment_consistency",
            "registry_validity",
            "proposal_integrity",
        ),
        is_recovery=True,
        description="Propose stronger containment after post-containment verification failed.",
    ),
    TransitionRule(
        from_state=IncidentState.PATCH_FAILED,
        event_type=EventType.PATCH_REQUESTED,
        to_state=IncidentState.PATCH_PENDING,
        required_guards=(*_BASE_GUARDS,),
        is_recovery=True,
        description="Request new candidate patch after prior patch failed.",
    ),
    TransitionRule(
        from_state=IncidentState.ROLLOUT_PAUSED,
        event_type=EventType.ROLLOUT_PLAN_CREATED,
        to_state=IncidentState.ROLLOUT_PENDING,
        required_guards=(
            *_BASE_GUARDS,
            "evidence_existence",
            "environment_consistency",
            "revision_consistency",
            "patch_verification",
            "deployment_verification",
            "rollout_eligibility",
        ),
        is_recovery=True,
        description="Resume progressive rollout with updated plan from paused state.",
    ),
    TransitionRule(
        from_state=IncidentState.ROLLOUT_PAUSED,
        event_type=EventType.ROLLOUT_STAGE_APPROVED,
        to_state=IncidentState.ROLLOUT_PENDING,
        required_guards=(*_BASE_GUARDS, "approval_validity", "approval_freshness"),
        is_recovery=True,
        description="Resume paused rollout after fresh human approval.",
    ),
    TransitionRule(
        from_state=IncidentState.ROLLOUT_PAUSED,
        event_type=EventType.ROLLBACK_PROPOSED,
        to_state=IncidentState.ROLLBACK_PROPOSED,
        required_guards=(*_BASE_GUARDS, "evidence_existence", "rollback_safety"),
        is_recovery=True,
        description="Escalate paused rollout to human-reviewed rollback proposal.",
    ),
    TransitionRule(
        from_state=IncidentState.ROLLBACK_PROPOSED,
        event_type=EventType.ROLLBACK_VERIFICATION_PASSED,
        to_state=IncidentState.CONTAINED,
        required_guards=(
            *_BASE_GUARDS,
            "evidence_existence",
            "environment_consistency",
            "feature_state_freshness",
            "containment_verification",
        ),
        is_recovery=True,
        description="Verified rollback returns safely to CONTAINED (never RECOVERED).",
    ),
    TransitionRule(
        from_state=IncidentState.ROLLBACK_PROPOSED,
        event_type=EventType.ROLLOUT_HOLD,
        to_state=IncidentState.ROLLOUT_PAUSED,
        required_guards=(
            *_BASE_GUARDS,
            "evidence_existence",
            "environment_consistency",
            "feature_state_freshness",
        ),
        is_recovery=True,
        description="Verified partial-exposure rollback pauses rollout without claiming CONTAINED.",
    ),
    TransitionRule(
        from_state=IncidentState.RECOVERED,
        event_type=EventType.INCIDENT_REOPENED,
        to_state=IncidentState.VALIDATION_REQUESTED,
        required_guards=(*_BASE_GUARDS, "evidence_existence"),
        is_recovery=True,
        description="Manual reopening when newly verified evidence invalidates recovery.",
    ),
)


# Lookup index: (from_state, event_type) -> TransitionRule
TRANSITION_INDEX: dict[tuple[IncidentState, EventType], TransitionRule] = {
    (rule.from_state, rule.event_type): rule for rule in TRANSITION_RULES
}


# ------------------------------------------------------------------------------
# Non-Transition Events (Context Updates Without Changing Top-Level State)
# ------------------------------------------------------------------------------
_ALL_ACTIVE_STATES: frozenset[IncidentState] = frozenset(IncidentState)

NON_TRANSITION_RULES: dict[EventType, NonTransitionRule] = {
    EventType.INVESTIGATION_REQUESTED: NonTransitionRule(
        event_type=EventType.INVESTIGATION_REQUESTED,
        allowed_states=frozenset(
            {
                IncidentState.RECEIVED,
                IncidentState.VALIDATION_REQUESTED,
                IncidentState.UNVERIFIED,
                IncidentState.REPRODUCED,
                IncidentState.FLAG_MAPPED,
            }
        ),
        required_guards=(*_BASE_GUARDS,),
        description="Record investigation request.",
    ),
    EventType.INVESTIGATION_COMPLETED: NonTransitionRule(
        event_type=EventType.INVESTIGATION_COMPLETED,
        allowed_states=frozenset(
            {
                IncidentState.RECEIVED,
                IncidentState.VALIDATION_REQUESTED,
                IncidentState.UNVERIFIED,
                IncidentState.REPRODUCED,
                IncidentState.FLAG_MAPPED,
                IncidentState.CONTAINMENT_PROPOSED,
            }
        ),
        required_guards=(*_BASE_GUARDS, "finding_identity"),
        description="Attach AI/deterministic investigation summary without changing state.",
    ),
    EventType.INVESTIGATION_FAILED: NonTransitionRule(
        event_type=EventType.INVESTIGATION_FAILED,
        allowed_states=frozenset(
            {
                IncidentState.RECEIVED,
                IncidentState.VALIDATION_REQUESTED,
                IncidentState.UNVERIFIED,
                IncidentState.REPRODUCED,
                IncidentState.FLAG_MAPPED,
            }
        ),
        required_guards=(*_BASE_GUARDS,),
        description="Record investigation diagnostic limitation.",
    ),
    EventType.MAPPING_REQUESTED: NonTransitionRule(
        event_type=EventType.MAPPING_REQUESTED,
        allowed_states=frozenset({IncidentState.REPRODUCED}),
        required_guards=(*_BASE_GUARDS,),
        description="Record feature mapping request.",
    ),
    EventType.EXECUTION_REQUESTED: NonTransitionRule(
        event_type=EventType.EXECUTION_REQUESTED,
        allowed_states=frozenset({IncidentState.APPLYING}),
        required_guards=(*_BASE_GUARDS,),
        description="Record external executor dispatch request.",
    ),
    EventType.EXECUTION_ACCEPTED: NonTransitionRule(
        event_type=EventType.EXECUTION_ACCEPTED,
        allowed_states=frozenset({IncidentState.APPLYING}),
        required_guards=(*_BASE_GUARDS,),
        description="Record external executor job acceptance.",
    ),
    EventType.FLAG_STATE_OBSERVED: NonTransitionRule(
        event_type=EventType.FLAG_STATE_OBSERVED,
        allowed_states=frozenset(
            {
                IncidentState.AWAITING_APPROVAL,
                IncidentState.APPLYING,
                IncidentState.CONTAINMENT_TEST_PENDING,
                IncidentState.CONTAINED,
                IncidentState.ROLLOUT_PENDING,
                IncidentState.ROLLBACK_PROPOSED,
                IncidentState.CHANGE_FAILED,
            }
        ),
        required_guards=(*_BASE_GUARDS, "environment_consistency", "feature_state_freshness"),
        description="Record observed Flagsmith readback state.",
    ),
    EventType.CONTAINMENT_VERIFICATION_REQUESTED: NonTransitionRule(
        event_type=EventType.CONTAINMENT_VERIFICATION_REQUESTED,
        allowed_states=frozenset({IncidentState.CONTAINMENT_TEST_PENDING}),
        required_guards=(*_BASE_GUARDS,),
        description="Record post-containment verification request.",
    ),
    EventType.CONTAINMENT_VERIFICATION_PASSED: NonTransitionRule(
        event_type=EventType.CONTAINMENT_VERIFICATION_PASSED,
        allowed_states=frozenset({IncidentState.CONTAINMENT_TEST_PENDING}),
        required_guards=(
            *_BASE_GUARDS,
            "evidence_existence",
            "evidence_provenance",
            "environment_consistency",
            "revision_consistency",
        ),
        description="Record passing post-containment security regression result.",
    ),
    EventType.FUNCTIONAL_SMOKE_TEST_PASSED: NonTransitionRule(
        event_type=EventType.FUNCTIONAL_SMOKE_TEST_PASSED,
        allowed_states=frozenset({IncidentState.CONTAINMENT_TEST_PENDING}),
        required_guards=(*_BASE_GUARDS, "environment_consistency"),
        description="Record passing functional smoke test during containment verification.",
    ),
    EventType.FUNCTIONAL_SMOKE_TEST_FAILED: NonTransitionRule(
        event_type=EventType.FUNCTIONAL_SMOKE_TEST_FAILED,
        allowed_states=frozenset({IncidentState.CONTAINMENT_TEST_PENDING}),
        required_guards=(*_BASE_GUARDS,),
        description="Record failing functional smoke test.",
    ),
    EventType.PATCH_PROPOSED: NonTransitionRule(
        event_type=EventType.PATCH_PROPOSED,
        allowed_states=frozenset({IncidentState.PATCH_PENDING}),
        required_guards=(*_BASE_GUARDS, "evidence_existence", "revision_consistency"),
        description="Record candidate patch proposal without claiming test completion.",
    ),
    EventType.PATCH_TEST_REQUESTED: NonTransitionRule(
        event_type=EventType.PATCH_TEST_REQUESTED,
        allowed_states=frozenset({IncidentState.PATCH_PENDING}),
        required_guards=(*_BASE_GUARDS,),
        description="Record isolated patch test run submission.",
    ),
    EventType.PATCH_TEST_COMPLETED: NonTransitionRule(
        event_type=EventType.PATCH_TEST_COMPLETED,
        allowed_states=frozenset({IncidentState.PATCH_PENDING, IncidentState.PATCH_TESTED}),
        required_guards=(*_BASE_GUARDS, "evidence_existence", "revision_consistency"),
        description="Attach intermediate patch test details.",
    ),
    EventType.DEPLOYMENT_OBSERVED: NonTransitionRule(
        event_type=EventType.DEPLOYMENT_OBSERVED,
        allowed_states=frozenset({IncidentState.PATCH_TESTED, IncidentState.ROLLOUT_PENDING}),
        required_guards=(
            *_BASE_GUARDS,
            "evidence_existence",
            "environment_consistency",
            "deployment_verification",
        ),
        description="Record verified deployment observation before or during rollout.",
    ),
    EventType.PATCH_DEPLOYMENT_OBSERVED: NonTransitionRule(
        event_type=EventType.PATCH_DEPLOYMENT_OBSERVED,
        allowed_states=frozenset({IncidentState.PATCH_TESTED, IncidentState.ROLLOUT_PENDING}),
        required_guards=(
            *_BASE_GUARDS,
            "evidence_existence",
            "environment_consistency",
            "deployment_verification",
        ),
        description="Alias for verified patch deployment observation.",
    ),
    EventType.ROLLOUT_STAGE_PROPOSED: NonTransitionRule(
        event_type=EventType.ROLLOUT_STAGE_PROPOSED,
        allowed_states=frozenset({IncidentState.ROLLOUT_PENDING}),
        required_guards=(*_BASE_GUARDS, "environment_consistency"),
        description="Propose entering a progressive exposure stage.",
    ),
    EventType.ROLLOUT_STAGE_APPROVED: NonTransitionRule(
        event_type=EventType.ROLLOUT_STAGE_APPROVED,
        allowed_states=frozenset({IncidentState.ROLLOUT_PENDING}),
        required_guards=(
            *_BASE_GUARDS,
            "environment_consistency",
            "approval_validity",
            "approval_freshness",
        ),
        description="Record stage-specific human approval inside ROLLOUT_PENDING.",
    ),
    EventType.ROLLOUT_STAGE_APPLIED: NonTransitionRule(
        event_type=EventType.ROLLOUT_STAGE_APPLIED,
        allowed_states=frozenset({IncidentState.ROLLOUT_PENDING}),
        required_guards=(
            *_BASE_GUARDS,
            "environment_consistency",
            "operation_receipt_validity",
        ),
        description="Record external rollout stage execution receipt.",
    ),
    EventType.ROLLOUT_STAGE_OBSERVED: NonTransitionRule(
        event_type=EventType.ROLLOUT_STAGE_OBSERVED,
        allowed_states=frozenset({IncidentState.ROLLOUT_PENDING}),
        required_guards=(*_BASE_GUARDS, "environment_consistency", "feature_state_freshness"),
        description="Record Flagsmith targeting readback for active rollout stage.",
    ),
    EventType.ROLLOUT_METRICS_RECEIVED: NonTransitionRule(
        event_type=EventType.ROLLOUT_METRICS_RECEIVED,
        allowed_states=frozenset({IncidentState.ROLLOUT_PENDING, IncidentState.ROLLOUT_PAUSED}),
        required_guards=(*_BASE_GUARDS, "environment_consistency"),
        description="Record telemetry snapshot (synthetic or observed) for rollout stage.",
    ),
    EventType.ROLLOUT_ADVANCE_PROPOSED: NonTransitionRule(
        event_type=EventType.ROLLOUT_ADVANCE_PROPOSED,
        allowed_states=frozenset({IncidentState.ROLLOUT_PENDING}),
        required_guards=(*_BASE_GUARDS, "environment_consistency"),
        description="Record release manager advance recommendation requiring fresh approval.",
    ),
    EventType.ROLLOUT_DECISION_RECORDED: NonTransitionRule(
        event_type=EventType.ROLLOUT_DECISION_RECORDED,
        allowed_states=frozenset({IncidentState.ROLLOUT_PENDING, IncidentState.ROLLOUT_PAUSED}),
        required_guards=(*_BASE_GUARDS,),
        description="Prompt 01 alias recording deterministic rollout decision.",
    ),
    EventType.ROLLBACK_APPROVED: NonTransitionRule(
        event_type=EventType.ROLLBACK_APPROVED,
        allowed_states=frozenset({IncidentState.ROLLBACK_PROPOSED}),
        required_guards=(*_BASE_GUARDS, "approval_validity", "approval_freshness"),
        description="Record authenticated human approval for proposed rollback.",
    ),
    EventType.ROLLBACK_REJECTED: NonTransitionRule(
        event_type=EventType.ROLLBACK_REJECTED,
        allowed_states=frozenset({IncidentState.ROLLBACK_PROPOSED}),
        required_guards=(*_BASE_GUARDS,),
        description="Record human rejection of rollback proposal.",
    ),
    EventType.ROLLBACK_APPLIED: NonTransitionRule(
        event_type=EventType.ROLLBACK_APPLIED,
        allowed_states=frozenset({IncidentState.ROLLBACK_PROPOSED}),
        required_guards=(
            *_BASE_GUARDS,
            "environment_consistency",
            "operation_receipt_validity",
        ),
        description="Record external rollback operation receipt.",
    ),
    EventType.ROLLBACK_VERIFICATION_FAILED: NonTransitionRule(
        event_type=EventType.ROLLBACK_VERIFICATION_FAILED,
        allowed_states=frozenset({IncidentState.ROLLBACK_PROPOSED}),
        required_guards=(*_BASE_GUARDS,),
        description="Rollback verification failed; remain in ROLLBACK_PROPOSED for manual review.",
    ),
    EventType.OPERATION_RETRY_REQUESTED: NonTransitionRule(
        event_type=EventType.OPERATION_RETRY_REQUESTED,
        allowed_states=_ALL_ACTIVE_STATES,
        required_guards=(*_BASE_GUARDS,),
        description="Record bounded retry attempt diagnostic.",
    ),
    EventType.OPERATION_RETRY_EXHAUSTED: NonTransitionRule(
        event_type=EventType.OPERATION_RETRY_EXHAUSTED,
        allowed_states=_ALL_ACTIVE_STATES,
        required_guards=(*_BASE_GUARDS,),
        description="Record retry exhaustion diagnostic.",
    ),
    EventType.INTEGRATION_UNAVAILABLE: NonTransitionRule(
        event_type=EventType.INTEGRATION_UNAVAILABLE,
        allowed_states=_ALL_ACTIVE_STATES,
        required_guards=(*_BASE_GUARDS,),
        description="Record temporary external integration unavailability.",
    ),
    EventType.MANUAL_REVIEW_REQUESTED: NonTransitionRule(
        event_type=EventType.MANUAL_REVIEW_REQUESTED,
        allowed_states=_ALL_ACTIVE_STATES,
        required_guards=(*_BASE_GUARDS,),
        description="Record explicit request for human operator review.",
    ),
    EventType.APPROVAL_INVALIDATED: NonTransitionRule(
        event_type=EventType.APPROVAL_INVALIDATED,
        allowed_states=_ALL_ACTIVE_STATES,
        required_guards=(*_BASE_GUARDS,),
        description="Record invalidation of an active approval.",
    ),
    EventType.EVIDENCE_EXPORTED: NonTransitionRule(
        event_type=EventType.EVIDENCE_EXPORTED,
        allowed_states=_ALL_ACTIVE_STATES,
        required_guards=(*_BASE_GUARDS,),
        description="Record export of an incident EvidenceReport bundle.",
    ),
}


# ------------------------------------------------------------------------------
# Mandatory Evidence Requirements per Critical State (Step 9)
# ------------------------------------------------------------------------------
EVIDENCE_REQUIREMENTS: dict[IncidentState, tuple[str, ...]] = {
    IncidentState.REPRODUCED: (
        "trusted_security_verification_result",
        "explicit_reproduction_outcome",
        "matching_incident_and_finding_id",
        "authorized_environment",
        "matching_source_revision",
        "artifact_references",
        "verification_timestamp",
    ),
    IncidentState.FLAG_MAPPED: (
        "valid_mapping_result",
        "declared_registry_version",
        "valid_target_feature",
        "matching_environment",
        "supporting_evidence_references",
    ),
    IncidentState.CONTAINMENT_PROPOSED: (
        "verified_finding",
        "valid_mapping_result",
        "schema_valid_containment_proposal",
        "exact_target_feature_and_desired_state",
        "expected_disruption_summary",
        "supporting_evidence_references",
        "mandatory_human_approval_flag",
    ),
    IncidentState.APPLYING: (
        "active_proposal",
        "matching_canonical_proposal_hash",
        "authenticated_human_approval",
        "matching_approval_target",
        "unexpired_approval_and_proposal",
        "fresh_feature_state_observation",
        "unconsumed_authorization",
        "valid_idempotency_token",
    ),
    IncidentState.CONTAINMENT_TEST_PENDING: (
        "trusted_external_operation_receipt",
        "matching_operation_and_proposal_identity",
        "matching_environment_and_target_feature",
        "successful_reported_operation_outcome",
    ),
    IncidentState.CONTAINED: (
        "successful_external_operation_receipt",
        "observed_actual_feature_state",
        "post_change_security_regression_passed",
        "functional_smoke_test_passed",
        "post_operation_evidence_timestamps",
        "matching_target_and_revision",
    ),
    IncidentState.PATCH_TESTED: (
        "candidate_patch_identity_and_hash",
        "expected_and_matching_tested_revision",
        "completed_security_regression",
        "completed_functional_tests",
        "zero_failed_or_unexecuted_required_tests",
        "trusted_isolated_patch_test_result",
    ),
    IncidentState.ROLLOUT_PENDING: (
        "tested_candidate_patch_evidence",
        "verified_deployed_implementation_evidence",
        "targeting_configuration_readback",
        "valid_rollout_plan",
        "stage_specific_human_approval_boundaries",
    ),
    IncidentState.RECOVERED: (
        "all_required_rollout_stages_completed",
        "actual_observed_target_state",
        "passing_required_security_checks",
        "passing_final_functional_checks",
        "release_health_requirements_satisfied",
        "zero_unresolved_critical_failures",
    ),
}


def generate_mermaid_state_diagram() -> str:
    """Generate a Mermaid ``stateDiagram-v2`` directly from ``TRANSITION_RULES``."""
    lines: list[str] = ["stateDiagram-v2", "    [*] --> RECEIVED : finding_received"]
    seen_edges: set[tuple[str, str, str]] = set()
    for rule in TRANSITION_RULES:
        edge = (rule.from_state.value, rule.to_state.value, rule.event_type.value)
        if edge in seen_edges:
            continue
        seen_edges.add(edge)
        lines.append(
            f"    {rule.from_state.value} --> {rule.to_state.value} : {rule.event_type.value}"
        )
    lines.append("    RECOVERED --> [*]")
    return "\n".join(lines)
