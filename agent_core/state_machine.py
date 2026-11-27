"""Pure deterministic incident state machine.

Separates structural transition eligibility (``can_transition``, ``get_target_state``)
from evidence/authorization guard evaluation (``validate_transition``) and pure
aggregate state application (``apply_transition``). Never performs network calls
or touches LLMs / Flagsmith / databases.
"""

from __future__ import annotations

from typing import Any

from shared.enums import EventType, IncidentState
from shared.exceptions import InvalidTransitionError
from shared.schemas import IncidentEvent

from agent_core.context import GuardResult, RolloutStageRecord, TransitionContext
from agent_core.guards import evaluate_guards
from agent_core.incident import IncidentAggregate
from agent_core.transitions import (
    NON_TRANSITION_RULES,
    TRANSITION_INDEX,
    TRANSITION_RULES,
)


def can_transition(from_state: IncidentState, event_type: EventType) -> bool:
    """Return True iff ``(from_state, event_type)`` exists in the transition registry."""
    return (from_state, event_type) in TRANSITION_INDEX


def is_non_transition_event(from_state: IncidentState, event_type: EventType) -> bool:
    """Return True iff ``event_type`` is a valid context-updating event in ``from_state``."""
    rule = NON_TRANSITION_RULES.get(event_type)
    if rule is None:
        return False
    return from_state in rule.allowed_states


def get_target_state(from_state: IncidentState, event_type: EventType) -> IncidentState:
    """Return the target state for a structural transition or non-transition event.

    Raises:
        InvalidTransitionError: If the event is neither a registered transition nor a
            permitted non-transition event in ``from_state``.
    """
    rule = TRANSITION_INDEX.get((from_state, event_type))
    if rule is not None:
        return rule.to_state
    if is_non_transition_event(from_state, event_type):
        return from_state
    raise InvalidTransitionError(
        f"Event {event_type.value!r} is not structurally permitted "
        f"from state {from_state.value!r}.",
        context={"from_state": from_state.value, "event_type": event_type.value},
    )


def get_allowed_events(state: IncidentState) -> list[EventType]:
    """Return all transition and non-transition events structurally valid in ``state``."""
    events: list[EventType] = [
        rule.event_type for rule in TRANSITION_RULES if rule.from_state == state
    ]
    for event_type, non_rule in NON_TRANSITION_RULES.items():
        if state in non_rule.allowed_states and event_type not in events:
            events.append(event_type)
    return events


def validate_transition(
    incident: IncidentAggregate,
    event: IncidentEvent,
    context: TransitionContext,
) -> tuple[IncidentState, list[GuardResult]]:
    """Validate structural eligibility AND all mandatory evidence/auth guards.

    Raises:
        InvalidTransitionError: If the event is not allowed in ``incident.current_state``.
    """
    from_state = incident.current_state
    rule = TRANSITION_INDEX.get((from_state, event.event_type))
    if rule is not None:
        guard_results = evaluate_guards(rule.required_guards, incident, event, context)
        return rule.to_state, guard_results

    non_rule = NON_TRANSITION_RULES.get(event.event_type)
    if non_rule is not None and from_state in non_rule.allowed_states:
        guard_results = evaluate_guards(non_rule.required_guards, incident, event, context)
        return from_state, guard_results

    raise InvalidTransitionError(
        f"Event {event.event_type.value!r} is not allowed from state {from_state.value!r}.",
        context={
            "incident_id": incident.incident_id,
            "from_state": from_state.value,
            "event_type": event.event_type.value,
        },
    )


def _derive_pending_action(state: IncidentState) -> str | None:
    mapping: dict[IncidentState, str] = {
        IncidentState.RECEIVED: "request_vulnerability_verification",
        IncidentState.VALIDATION_REQUESTED: "await_verification_evidence",
        IncidentState.REPRODUCED: "map_vulnerability_to_feature_flag",
        IncidentState.FLAG_MAPPED: "generate_containment_proposal",
        IncidentState.CONTAINMENT_PROPOSED: "request_human_approval",
        IncidentState.AWAITING_APPROVAL: "await_human_approval_decision",
        IncidentState.APPLYING: "execute_approved_flag_change_in_platform",
        IncidentState.CONTAINMENT_TEST_PENDING: "verify_flag_readback_and_security_regression",
        IncidentState.CONTAINED: "request_candidate_patch",
        IncidentState.PATCH_PENDING: "run_isolated_patch_tests",
        IncidentState.PATCH_TESTED: "verify_deployment_and_create_rollout_plan",
        IncidentState.ROLLOUT_PENDING: "progress_or_monitor_rollout_stage",
        IncidentState.UNVERIFIED: "review_or_retry_verification",
        IncidentState.UNMAPPED: "manual_flag_mapping_review",
        IncidentState.REJECTED: "propose_revised_containment_or_close",
        IncidentState.CHANGE_FAILED: "reconcile_external_operation_outcome",
        IncidentState.CONTAINMENT_FAILED: "propose_stronger_containment_strategy",
        IncidentState.PATCH_FAILED: "generate_revised_candidate_patch",
        IncidentState.ROLLOUT_PAUSED: "review_metrics_or_escalate_rollback",
        IncidentState.ROLLBACK_PROPOSED: "await_human_rollback_approval_and_verify",
    }
    return mapping.get(state)


def _update_rollout_stages(
    existing: tuple[RolloutStageRecord, ...],
    stage_id: str,
    *,
    exposure: int | None = None,
    revision: str = "",
    status: str | None = None,
    approval_id: str | None = None,
    receipt_id: str | None = None,
    observed_exposure: int | None = None,
    health_passed: bool | None = None,
    security_verified: bool | None = None,
) -> tuple[RolloutStageRecord, ...]:
    items = list(existing)
    found_idx: int | None = None
    for idx, rec in enumerate(items):
        if rec.stage_id == stage_id:
            found_idx = idx
            break
    if found_idx is None:
        new_rec = RolloutStageRecord(
            stage_id=stage_id,
            exposure_percentage=exposure if exposure is not None else 0,
            target_revision=revision or "unknown",
            approved_exposure=exposure if status == "approved" else None,
            observed_exposure=observed_exposure,
            approval_id=approval_id,
            operation_receipt_id=receipt_id,
            health_passed=health_passed,
            security_verified=security_verified,
            status=(status or "proposed"),  # type: ignore[arg-type]
        )
        items.append(new_rec)
        return tuple(items)

    current = items[found_idx]
    patch: dict[str, Any] = {}
    if status is not None:
        patch["status"] = status
    if approval_id is not None:
        patch["approval_id"] = approval_id
        patch["approved_exposure"] = current.exposure_percentage
    if receipt_id is not None:
        patch["operation_receipt_id"] = receipt_id
    if observed_exposure is not None:
        patch["observed_exposure"] = observed_exposure
    if health_passed is not None:
        patch["health_passed"] = health_passed
    if security_verified is not None:
        patch["security_verified"] = security_verified
    items[found_idx] = current.model_copy(update=patch)
    return tuple(items)


def apply_transition(
    incident: IncidentAggregate,
    event: IncidentEvent,
    target_state: IncidentState,
    context: TransitionContext,
    guard_results: list[GuardResult],
) -> IncidentAggregate:
    """Apply an already-validated transition deterministically to produce a new aggregate.

    Raises:
        InvalidTransitionError: If any evaluated guard failed.
    """
    failed = [g for g in guard_results if not g.allowed]
    if failed:
        raise InvalidTransitionError(
            f"Transition to {target_state.value!r} denied by guards: "
            f"{[g.reason_code for g in failed]}",
            context={
                "incident_id": incident.incident_id,
                "target_state": target_state.value,
                "failed_guards": [g.guard for g in failed],
            },
        )

    updates: dict[str, Any] = {
        "pending_action": _derive_pending_action(target_state),
    }

    # Clear prior failure reason when recovering or completing successfully.
    if target_state not in (
        IncidentState.REJECTED,
        IncidentState.UNVERIFIED,
        IncidentState.UNMAPPED,
        IncidentState.CHANGE_FAILED,
        IncidentState.CONTAINMENT_FAILED,
        IncidentState.PATCH_FAILED,
        IncidentState.ROLLOUT_PAUSED,
        IncidentState.ROLLBACK_PROPOSED,
    ):
        updates["failure_reason"] = None
        updates["failure_reason_code"] = None

    if context.investigation_summary is not None:
        updates["investigation_id"] = context.investigation_summary.investigation_id

    if context.verification_result is not None:
        vr = context.verification_result
        if vr.verification_id not in incident.verification_references:
            updates["verification_references"] = (
                *incident.verification_references,
                vr.verification_id,
            )
        if vr.tested_revision and incident.source_revision is None:
            updates["source_revision"] = vr.tested_revision
        if event.event_type in (
            EventType.CONTAINMENT_VERIFICATION_PASSED,
            EventType.CONTAINMENT_CONFIRMED,
            EventType.CONTAINMENT_VERIFIED,
        ):
            updates["post_containment_verification_passed"] = vr.passed

    if event.event_type == EventType.FUNCTIONAL_SMOKE_TEST_PASSED:
        updates["functional_smoke_test_passed"] = True
    elif event.event_type == EventType.FUNCTIONAL_SMOKE_TEST_FAILED:
        updates["functional_smoke_test_passed"] = False

    if context.mapping_result is not None and event.event_type in (
        EventType.MAPPING_MATCHED,
        EventType.FLAG_MAPPED,
    ):
        updates["mapping_result_id"] = context.mapping_result.finding_id
        updates["mapped_flag_name"] = context.mapping_result.selected_flag
        updates["registry_version"] = context.mapping_result.registry_version

    if (
        context.containment_proposal is not None
        and event.event_type == EventType.CONTAINMENT_PROPOSED
    ):
        prop = context.containment_proposal
        if (
            incident.current_proposal_id is not None
            and incident.current_proposal_id != prop.proposal_id
            and incident.current_proposal_id not in incident.superseded_proposal_ids
        ):
            updates["superseded_proposal_ids"] = (
                *incident.superseded_proposal_ids,
                incident.current_proposal_id,
            )
        updates["current_proposal_id"] = prop.proposal_id
        updates["current_proposal_hash"] = prop.proposal_hash
        updates["current_approval_id"] = None

    if event.event_type == EventType.APPROVAL_GRANTED and context.approval_decision is not None:
        appr = context.approval_decision
        updates["current_approval_id"] = appr.approval_id
        if appr.approval_id not in incident.consumed_approval_ids:
            updates["consumed_approval_ids"] = (*incident.consumed_approval_ids, appr.approval_id)
        if context.active_proposal is not None:
            updates["active_operation_id"] = (
                f"op_{context.active_proposal.proposal_id}_{appr.approval_id}"[:64]
            )

    if event.event_type in (
        EventType.APPROVAL_REJECTED,
        EventType.APPROVAL_EXPIRED,
        EventType.CONTAINMENT_PROPOSAL_INVALIDATED,
    ):
        if incident.current_proposal_id and (
            incident.current_proposal_id not in incident.superseded_proposal_ids
        ):
            updates["superseded_proposal_ids"] = (
                *incident.superseded_proposal_ids,
                incident.current_proposal_id,
            )
        updates["failure_reason_code"] = event.event_type.value.upper()
        if context.approval_decision and context.approval_decision.rejection_reason:
            updates["failure_reason"] = context.approval_decision.rejection_reason
        else:
            updates["failure_reason"] = f"Proposal halted due to {event.event_type.value}."

    if event.event_type in (
        EventType.FLAG_UPDATE_SUCCESS,
        EventType.FLAG_CHANGE_EXECUTED,
        EventType.FLAG_UPDATE_FAILED,
        EventType.FLAG_CHANGE_FAILED,
        EventType.ROLLBACK_APPLIED,
    ) and context.operation_receipt is not None:
        rec = context.operation_receipt
        updates["active_operation_id"] = rec.operation_id
        updates["last_operation_timestamp"] = rec.executed_at
        if rec.idempotency_key not in incident.operation_idempotency_keys:
            updates["operation_idempotency_keys"] = (
                *incident.operation_idempotency_keys,
                rec.idempotency_key,
            )
        if rec.observed_state is not None:
            updates["observed_feature_state"] = rec.observed_state

    if event.event_type == EventType.ROLLBACK_PROPOSED and context.rollback_proposal is not None:
        rb = context.rollback_proposal
        if (
            incident.current_proposal_id is not None
            and incident.current_proposal_id != rb.proposal_id
            and incident.current_proposal_id not in incident.superseded_proposal_ids
        ):
            updates["superseded_proposal_ids"] = (
                *incident.superseded_proposal_ids,
                incident.current_proposal_id,
            )
        updates["current_proposal_id"] = rb.proposal_id
        updates["current_proposal_hash"] = rb.proposal_hash
        updates["current_approval_id"] = None
        updates["active_operation_id"] = None

    if event.event_type == EventType.ROLLBACK_APPROVED:
        rb_appr = context.stage_approval_decision or context.approval_decision
        if rb_appr is not None:
            updates["current_approval_id"] = rb_appr.approval_id
            if rb_appr.approval_id not in incident.consumed_approval_ids:
                updates["consumed_approval_ids"] = (
                    *incident.consumed_approval_ids,
                    rb_appr.approval_id,
                )
            if context.rollback_proposal is not None:
                updates["active_operation_id"] = (
                    f"op_{context.rollback_proposal.proposal_id}_{rb_appr.approval_id}"[:64]
                )

    if context.feature_state is not None and context.feature_state.enabled is not None:
        updates["observed_feature_state"] = context.feature_state.enabled
        if target_state == IncidentState.CONTAINED:
            updates["last_verified_safe_state"] = context.feature_state.enabled
            updates["last_verified_safe_state_known"] = True

    if event.event_type in (EventType.CONTAINMENT_CONFIRMED, EventType.CONTAINMENT_VERIFIED):
        if context.functional_smoke_passed is True:
            updates["functional_smoke_test_passed"] = True
        if context.verification_result is not None:
            updates["post_containment_verification_passed"] = context.verification_result.passed

    if context.patch_proposal is not None and event.event_type == EventType.PATCH_PROPOSED:
        patch = context.patch_proposal
        updates["active_patch_id"] = patch.patch_id
        updates["active_patch_hash"] = patch.candidate_content_hash
        if patch.patch_id not in incident.patch_references:
            updates["patch_references"] = (*incident.patch_references, patch.patch_id)

    if context.patch_test_result is not None and event.event_type in (
        EventType.PATCH_TEST_PASSED,
        EventType.PATCH_TEST_FAILED,
        EventType.PATCH_TEST_COMPLETED,
    ):
        ptr = context.patch_test_result
        updates["active_patch_id"] = ptr.patch_id
        updates["active_patch_hash"] = ptr.tested_candidate_hash
        if ptr.test_run_id not in incident.patch_references:
            updates["patch_references"] = (*incident.patch_references, ptr.test_run_id)

    if context.deployment_evidence is not None and event.event_type in (
        EventType.DEPLOYMENT_OBSERVED,
        EventType.PATCH_DEPLOYMENT_OBSERVED,
        EventType.ROLLOUT_PLAN_CREATED,
    ):
        dep = context.deployment_evidence
        updates["verified_deployment_revision"] = dep.source_revision
        if dep.deployment_id not in incident.deployment_references:
            updates["deployment_references"] = (*incident.deployment_references, dep.deployment_id)

    if context.rollout_plan is not None and event.event_type == EventType.ROLLOUT_PLAN_CREATED:
        plan = context.rollout_plan
        updates["active_rollout_plan_id"] = plan.plan_id
        updates["current_rollout_stage"] = plan.stages[0].stage_id
        updates["rollout_stages"] = tuple(
            RolloutStageRecord(
                stage_id=s.stage_id,
                exposure_percentage=s.exposure_percentage,
                target_revision=plan.target_implementation_revision,
                status="proposed",
            )
            for s in plan.stages
        )

    if event.event_type in (
        EventType.ROLLOUT_STAGE_PROPOSED,
        EventType.ROLLOUT_STAGE_APPROVED,
        EventType.ROLLOUT_STAGE_APPLIED,
        EventType.ROLLOUT_STAGE_OBSERVED,
        EventType.ROLLOUT_METRICS_RECEIVED,
        EventType.ROLLOUT_ADVANCE_PROPOSED,
        EventType.ROLLOUT_COMPLETED,
    ):
        stage_id = incident.current_rollout_stage
        if context.rollout_decision is not None:
            stage_id = context.rollout_decision.current_stage_id
        elif context.stage_approval_decision is not None:
            stage_id = context.stage_approval_decision.proposal_id
        elif isinstance(event.payload, dict) and isinstance(event.payload.get("stage_id"), str):
            stage_id = event.payload["stage_id"]

        if stage_id:
            status_map = {
                EventType.ROLLOUT_STAGE_PROPOSED: "proposed",
                EventType.ROLLOUT_STAGE_APPROVED: "approved",
                EventType.ROLLOUT_STAGE_APPLIED: "applied",
                EventType.ROLLOUT_STAGE_OBSERVED: "observed",
                EventType.ROLLOUT_COMPLETED: "completed",
            }
            new_stage_status = status_map.get(event.event_type)
            if (
                event.event_type == EventType.ROLLOUT_ADVANCE_PROPOSED
                and context.rollout_decision is not None
            ):
                new_stage_status = "completed"
                if context.rollout_decision.proposed_next_stage_id:
                    updates["current_rollout_stage"] = (
                        context.rollout_decision.proposed_next_stage_id
                    )
            else:
                updates["current_rollout_stage"] = stage_id

            if (
                event.event_type == EventType.ROLLOUT_STAGE_APPROVED
                and context.stage_approval_decision is not None
            ):
                appr_id = context.stage_approval_decision.approval_id
                if appr_id not in incident.consumed_approval_ids:
                    updates["consumed_approval_ids"] = (
                        *incident.consumed_approval_ids,
                        appr_id,
                    )

            obs_pct = (
                context.metric_snapshot.observed_rollout_stage_percentage
                if context.metric_snapshot is not None
                else None
            )
            sec_ok = (
                context.metric_snapshot.security_regression_passed
                if context.metric_snapshot is not None
                else None
            )
            updates["rollout_stages"] = _update_rollout_stages(
                incident.rollout_stages,
                stage_id,
                status=new_stage_status,
                approval_id=(
                    context.stage_approval_decision.approval_id
                    if context.stage_approval_decision is not None
                    else None
                ),
                receipt_id=(
                    context.operation_receipt.operation_id
                    if context.operation_receipt is not None
                    else None
                ),
                observed_exposure=obs_pct,
                health_passed=(
                    True
                    if event.event_type
                    in (EventType.ROLLOUT_ADVANCE_PROPOSED, EventType.ROLLOUT_COMPLETED)
                    else None
                ),
                security_verified=sec_ok,
            )

    if target_state in (
        IncidentState.UNVERIFIED,
        IncidentState.UNMAPPED,
        IncidentState.CHANGE_FAILED,
        IncidentState.CONTAINMENT_FAILED,
        IncidentState.PATCH_FAILED,
        IncidentState.ROLLOUT_PAUSED,
        IncidentState.ROLLBACK_PROPOSED,
    ):
        updates["failure_reason_code"] = event.event_type.value.upper()
        if context.rollback_proposal is not None:
            updates["failure_reason"] = context.rollback_proposal.rollback_rationale
        elif isinstance(event.payload, dict) and isinstance(event.payload.get("reason"), str):
            updates["failure_reason"] = event.payload["reason"]
        elif updates.get("failure_reason") is None:
            updates["failure_reason"] = (
                f"Incident routed to {target_state.value} on {event.event_type.value}."
            )

    return incident.with_transition(
        new_state=target_state,
        event_id=event.event_id,
        event_sequence=event.sequence_number,
        updated_at=event.timestamp_utc,
        updates=updates,
    )
