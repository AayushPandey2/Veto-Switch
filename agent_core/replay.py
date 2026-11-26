"""Deterministic, side-effect-free incident replay engine.

Reconstructs an ``IncidentAggregate`` solely from recorded accepted ``IncidentEvent``
history without contacting LLMs, mutating Flagsmith flags, executing security tests,
or re-evaluating historical approvals against the current wall clock.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from shared.enums import ActorType, EventType, EvidenceProvenance, IncidentState
from shared.exceptions import InvalidTransitionError, ReplayIntegrityError
from shared.schemas import IncidentEvent

from agent_core.context import (
    FixedClock,
    GuardResult,
    ProducerContext,
    RolloutStageRecord,
    TransitionContext,
)
from agent_core.incident import IncidentAggregate
from agent_core.state_machine import apply_transition, get_target_state


def verify_event_history_integrity(events: Sequence[IncidentEvent]) -> list[IncidentEvent]:
    """Validate event stream consistency, uniqueness, and sequence ordering.

    Raises:
        ReplayIntegrityError: On empty streams, mixed incident IDs, duplicate
            event IDs, or non-monotonic sequence numbers.
    """
    if not events:
        raise ReplayIntegrityError(
            "Cannot replay an empty incident event history.",
            context={"event_count": 0},
        )

    ordered = sorted(events, key=lambda evt: evt.sequence_number)
    target_incident_id = ordered[0].incident_id
    seen_event_ids: set[str] = set()
    expected_seq = 1

    for evt in ordered:
        if evt.incident_id != target_incident_id:
            raise ReplayIntegrityError(
                "Event stream contains mixed incident_id values.",
                context={
                    "expected_incident_id": target_incident_id,
                    "conflicting_incident_id": evt.incident_id,
                    "event_id": evt.event_id,
                },
            )
        if evt.event_id in seen_event_ids:
            raise ReplayIntegrityError(
                f"Duplicate event_id {evt.event_id!r} detected during replay.",
                context={"incident_id": target_incident_id, "event_id": evt.event_id},
            )
        seen_event_ids.add(evt.event_id)
        if evt.sequence_number != expected_seq:
            raise ReplayIntegrityError(
                f"Inconsistent sequence number: expected {expected_seq}, "
                f"got {evt.sequence_number}.",
                context={
                    "incident_id": target_incident_id,
                    "expected_sequence": expected_seq,
                    "actual_sequence": evt.sequence_number,
                },
            )
        expected_seq += 1

    if ordered[0].event_type != EventType.FINDING_RECEIVED:
        raise ReplayIntegrityError(
            "Incident event history must begin with FINDING_RECEIVED.",
            context={
                "incident_id": target_incident_id,
                "first_event_type": ordered[0].event_type.value,
            },
        )
    return ordered


def _payload_dict(event: IncidentEvent) -> dict[str, Any]:
    if hasattr(event.payload, "model_dump"):
        return event.payload.model_dump(mode="python")
    if isinstance(event.payload, dict):
        merged = dict(event.payload)
        meta = merged.pop("_replay_meta", None)
        if isinstance(meta, dict):
            for k, v in meta.items():
                if k not in merged:
                    merged[k] = v
        return merged
    return {}


def replay_incident(events: Sequence[IncidentEvent]) -> IncidentAggregate:
    """Reconstruct an ``IncidentAggregate`` deterministically from accepted events.

    Historical approvals and decisions are reconstructed from recorded event facts
    using each event's own recorded timestamp (never re-evaluated against current
    wall-clock time). Zero external calls or notifications are performed.
    """
    ordered = verify_event_history_integrity(events)
    first = ordered[0]
    first_payload = _payload_dict(first)

    finding_id = str(first_payload.get("finding_id") or "fnd_replayed_unknown")
    environment = str(first_payload.get("environment") or "demo-staging")
    source_revision = first_payload.get("source_revision")
    is_fixture = bool(first_payload.get("is_synthetic_fixture", False))
    raw_prov = first_payload.get("provenance")
    provenance = (
        EvidenceProvenance(raw_prov)
        if isinstance(raw_prov, str) and raw_prov in {p.value for p in EvidenceProvenance}
        else (
            EvidenceProvenance.REFERENCE_FIXTURE
            if is_fixture
            else EvidenceProvenance.ACTUAL_OBSERVED
        )
    )

    aggregate = IncidentAggregate(
        incident_id=first.incident_id,
        finding_id=finding_id,
        environment=environment,
        source_revision=str(source_revision) if source_revision is not None else None,
        current_state=IncidentState.RECEIVED,
        incident_version=1,
        created_at=first.timestamp_utc,
        updated_at=first.timestamp_utc,
        correlation_id=first.correlation_id,
        latest_event_id=first.event_id,
        latest_event_sequence=first.sequence_number,
        pending_action="request_vulnerability_verification",
        is_synthetic_fixture=is_fixture,
        provenance=provenance,
    )

    for evt in ordered[1:]:
        try:
            target_state = get_target_state(aggregate.current_state, evt.event_type)
        except InvalidTransitionError as exc:
            raise ReplayIntegrityError(
                f"Invalid recorded transition at sequence {evt.sequence_number}: {exc.message}",
                context={"incident_id": aggregate.incident_id, "event_id": evt.event_id},
            ) from exc

        payload = _payload_dict(evt)
        ctx = TransitionContext(
            producer_context=ProducerContext(
                producer_id=evt.actor,
                actor_type=evt.actor_type,
                authenticated=True,
                trusted_channel="historical_replay",
                provenance_mode="fixture" if is_fixture else "live",
            ),
            clock=FixedClock(evt.timestamp_utc),
            fixture_mode=is_fixture,
        )
        # Apply structural replay via pure state_machine using synthetic pass guard
        # because replay trusts previously accepted persisted events, NOT wall clock.
        accepted_guard = [
            GuardResult(
                allowed=True,
                guard="historical_replay",
                reason_code="ACCEPTED_HISTORICAL_EVENT",
                message="Historical accepted event replayed.",
                evidence_ids=list(evt.evidence_ids),
            )
        ]
        next_agg = apply_transition(aggregate, evt, target_state, ctx, accepted_guard)

        # Hydrate replay-recorded snapshot attributes from event payload so aggregate
        # matches live orchestrator state identically.
        patch: dict[str, Any] = {}
        if isinstance(payload.get("investigation_id"), str):
            patch["investigation_id"] = payload["investigation_id"]
        if isinstance(payload.get("verification_id"), str):
            vid = payload["verification_id"]
            if vid not in next_agg.verification_references:
                patch["verification_references"] = (*next_agg.verification_references, vid)
        if isinstance(payload.get("tested_revision"), str) and next_agg.source_revision is None:
            patch["source_revision"] = payload["tested_revision"]
        if evt.event_type in (
            EventType.CONTAINMENT_VERIFICATION_PASSED,
            EventType.CONTAINMENT_CONFIRMED,
            EventType.CONTAINMENT_VERIFIED,
        ):
            patch["post_containment_verification_passed"] = True
        if evt.event_type == EventType.FUNCTIONAL_SMOKE_TEST_PASSED:
            patch["functional_smoke_test_passed"] = True
        elif evt.event_type == EventType.FUNCTIONAL_SMOKE_TEST_FAILED:
            patch["functional_smoke_test_passed"] = False

        if evt.event_type in (EventType.MAPPING_MATCHED, EventType.FLAG_MAPPED):
            if isinstance(payload.get("finding_id"), str):
                patch["mapping_result_id"] = payload["finding_id"]
            if isinstance(payload.get("selected_flag"), str):
                patch["mapped_flag_name"] = payload["selected_flag"]
            if isinstance(payload.get("registry_version"), str):
                patch["registry_version"] = payload["registry_version"]

        if evt.event_type == EventType.CONTAINMENT_PROPOSED:
            prop_id = payload.get("proposal_id")
            prop_hash = payload.get("proposal_hash")
            if isinstance(prop_id, str):
                if (
                    next_agg.current_proposal_id is not None
                    and next_agg.current_proposal_id != prop_id
                    and next_agg.current_proposal_id not in next_agg.superseded_proposal_ids
                ):
                    patch["superseded_proposal_ids"] = (
                        *next_agg.superseded_proposal_ids,
                        next_agg.current_proposal_id,
                    )
                patch["current_proposal_id"] = prop_id
                patch["current_approval_id"] = None
            if isinstance(prop_hash, str):
                patch["current_proposal_hash"] = prop_hash

        if evt.event_type == EventType.APPROVAL_GRANTED:
            appr_id = payload.get("approval_id")
            if isinstance(appr_id, str):
                patch["current_approval_id"] = appr_id
                if appr_id not in next_agg.consumed_approval_ids:
                    patch["consumed_approval_ids"] = (*next_agg.consumed_approval_ids, appr_id)
                if next_agg.current_proposal_id:
                    patch["active_operation_id"] = f"op_{next_agg.current_proposal_id}_{appr_id}"[
                        :64
                    ]

        if evt.event_type in (
            EventType.APPROVAL_REJECTED,
            EventType.APPROVAL_EXPIRED,
            EventType.CONTAINMENT_PROPOSAL_INVALIDATED,
        ):
            if (
                next_agg.current_proposal_id
                and next_agg.current_proposal_id not in next_agg.superseded_proposal_ids
            ):
                patch["superseded_proposal_ids"] = (
                    *next_agg.superseded_proposal_ids,
                    next_agg.current_proposal_id,
                )
            if isinstance(payload.get("rejection_reason"), str):
                patch["failure_reason"] = payload["rejection_reason"]

        if evt.event_type in (
            EventType.FLAG_UPDATE_SUCCESS,
            EventType.FLAG_CHANGE_EXECUTED,
            EventType.FLAG_UPDATE_FAILED,
            EventType.FLAG_CHANGE_FAILED,
        ):
            if isinstance(payload.get("operation_id"), str):
                patch["active_operation_id"] = payload["operation_id"]
            patch["last_operation_timestamp"] = evt.timestamp_utc
            if isinstance(payload.get("idempotency_key"), str):
                ik = payload["idempotency_key"]
                if ik not in next_agg.operation_idempotency_keys:
                    patch["operation_idempotency_keys"] = (
                        *next_agg.operation_idempotency_keys,
                        ik,
                    )
            if isinstance(payload.get("observed_state"), bool):
                patch["observed_feature_state"] = payload["observed_state"]

        if evt.event_type == EventType.FLAG_STATE_OBSERVED and isinstance(
            payload.get("enabled"), bool
        ):
            patch["observed_feature_state"] = payload["enabled"]

        if target_state == IncidentState.CONTAINED:
            if isinstance(payload.get("observed_feature_state"), bool):
                patch["observed_feature_state"] = payload["observed_feature_state"]
                patch["last_verified_safe_state"] = payload["observed_feature_state"]
                patch["last_verified_safe_state_known"] = True
            elif next_agg.observed_feature_state is not None:
                patch["last_verified_safe_state"] = next_agg.observed_feature_state
                patch["last_verified_safe_state_known"] = True

        if evt.event_type == EventType.PATCH_PROPOSED and isinstance(payload.get("patch_id"), str):
            pid = payload["patch_id"]
            patch["active_patch_id"] = pid
            if isinstance(payload.get("candidate_content_hash"), str):
                patch["active_patch_hash"] = payload["candidate_content_hash"]
            if pid not in next_agg.patch_references:
                patch["patch_references"] = (*next_agg.patch_references, pid)

        if evt.event_type in (
            EventType.PATCH_TEST_PASSED,
            EventType.PATCH_TEST_FAILED,
            EventType.PATCH_TEST_COMPLETED,
        ):
            if isinstance(payload.get("patch_id"), str):
                patch["active_patch_id"] = payload["patch_id"]
            if isinstance(payload.get("tested_candidate_hash"), str):
                patch["active_patch_hash"] = payload["tested_candidate_hash"]
            if isinstance(payload.get("test_run_id"), str):
                trid = payload["test_run_id"]
                if trid not in next_agg.patch_references:
                    patch["patch_references"] = (*next_agg.patch_references, trid)

        if evt.event_type in (
            EventType.DEPLOYMENT_OBSERVED,
            EventType.PATCH_DEPLOYMENT_OBSERVED,
            EventType.ROLLOUT_PLAN_CREATED,
        ):
            if isinstance(payload.get("deployment_id"), str):
                did = payload["deployment_id"]
                if did not in next_agg.deployment_references:
                    patch["deployment_references"] = (*next_agg.deployment_references, did)
            if isinstance(payload.get("deployment_revision"), str):
                patch["verified_deployment_revision"] = payload["deployment_revision"]

        if evt.event_type == EventType.ROLLOUT_PLAN_CREATED and isinstance(
            payload.get("plan_id"), str
        ):
            patch["active_rollout_plan_id"] = payload["plan_id"]
            stages_raw = payload.get("stages")
            if isinstance(stages_raw, list) and stages_raw:
                rebuilt_stages = tuple(
                    RolloutStageRecord(
                        stage_id=str(s["stage_id"]),
                        exposure_percentage=int(s["exposure_percentage"]),
                        target_revision=str(payload.get("target_revision") or "unknown"),
                        status="proposed",
                    )
                    for s in stages_raw
                )
                patch["rollout_stages"] = rebuilt_stages
                patch["current_rollout_stage"] = rebuilt_stages[0].stage_id

        if evt.event_type in (
            EventType.ROLLOUT_STAGE_PROPOSED,
            EventType.ROLLOUT_STAGE_APPROVED,
            EventType.ROLLOUT_STAGE_APPLIED,
            EventType.ROLLOUT_STAGE_OBSERVED,
            EventType.ROLLOUT_METRICS_RECEIVED,
            EventType.ROLLOUT_ADVANCE_PROPOSED,
            EventType.ROLLOUT_COMPLETED,
        ):
            stage_id = payload.get("stage_id") or next_agg.current_rollout_stage
            if isinstance(stage_id, str):
                stages_list = list(next_agg.rollout_stages)
                for idx, st in enumerate(stages_list):
                    if st.stage_id == stage_id:
                        st_patch: dict[str, Any] = {}
                        if evt.event_type == EventType.ROLLOUT_STAGE_APPROVED:
                            st_patch["status"] = "approved"
                            if isinstance(payload.get("approval_id"), str):
                                st_patch["approval_id"] = payload["approval_id"]
                                st_patch["approved_exposure"] = st.exposure_percentage
                                if payload["approval_id"] not in next_agg.consumed_approval_ids:
                                    patch["consumed_approval_ids"] = (
                                        *next_agg.consumed_approval_ids,
                                        payload["approval_id"],
                                    )
                        elif evt.event_type == EventType.ROLLOUT_STAGE_APPLIED:
                            st_patch["status"] = "applied"
                            if isinstance(payload.get("operation_id"), str):
                                st_patch["operation_receipt_id"] = payload["operation_id"]
                        elif evt.event_type == EventType.ROLLOUT_STAGE_OBSERVED:
                            st_patch["status"] = "observed"
                        elif evt.event_type == EventType.ROLLOUT_ADVANCE_PROPOSED:
                            st_patch["status"] = "completed"
                            st_patch["health_passed"] = True
                            if isinstance(payload.get("next_stage_id"), str):
                                patch["current_rollout_stage"] = payload["next_stage_id"]
                        elif evt.event_type == EventType.ROLLOUT_COMPLETED:
                            st_patch["status"] = "completed"
                            st_patch["health_passed"] = True

                        if isinstance(payload.get("observed_exposure"), int):
                            st_patch["observed_exposure"] = payload["observed_exposure"]
                        if isinstance(payload.get("security_verified"), bool):
                            st_patch["security_verified"] = payload["security_verified"]

                        stages_list[idx] = st.model_copy(update=st_patch)
                        patch["rollout_stages"] = tuple(stages_list)
                        break

        if isinstance(payload.get("rollback_rationale"), str):
            patch["failure_reason"] = payload["rollback_rationale"]

        aggregate = next_agg.model_copy(update=patch) if patch else next_agg

    # Silence unused import check for ActorType if referenced in doc/type context
    _ = ActorType
    return aggregate
