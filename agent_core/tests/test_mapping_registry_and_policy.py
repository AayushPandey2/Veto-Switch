"""Tests for registry validation, independent mapping policy, and transition guards."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from agent_core.context import FixedClock, ProducerContext, TransitionContext
from agent_core.events import build_incident_event
from agent_core.guards import guard_mapping_validity, guard_registry_validity
from agent_core.incident import IncidentAggregate
from agent_core.mapping.registry import validate_registry
from agent_core.policies import validate_mapping_output
from shared.config import load_route_registry
from shared.enums import (
    ActorType,
    CoverageStatus,
    EventType,
    FeatureRole,
    FindingStatus,
    IncidentState,
    MappingStatus,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.exceptions import AmbiguousMappingError, ContractValidationError, UnknownFeatureError
from shared.schemas import Finding, ImplementationBinding, MappingResult, RouteFlagEntry

NOW = datetime(2026, 11, 27, 0, 0, 0, tzinfo=UTC)


def test_registry_validation_rejects_conflicts_and_undeclared_features() -> None:
    reg = load_route_registry()
    valid_report = validate_registry(reg)
    assert valid_report.valid is True

    # Duplicate canonical route
    dup_route_reg = reg.model_copy(update={"routes": [reg.routes[0], reg.routes[0]]})
    assert validate_registry(dup_route_reg).valid is False

    # Conflicting alias across routes
    bad_alias_entry = reg.routes[1].model_copy(update={"route_aliases": ["/legacy/search"]})
    conflict_reg = reg.model_copy(
        update={"routes": [reg.routes[0], bad_alias_entry, *reg.routes[2:]]}
    )
    assert validate_registry(conflict_reg).valid is False

    # Undeclared feature reference
    undecl_entry = RouteFlagEntry(
        route="/new-endpoint",
        component="new_svc",
        flags=["ghost_flag"],
        coverage_status=CoverageStatus.PROTECTED,
    )
    undecl_reg = reg.model_copy(update={"routes": [*reg.routes, undecl_entry]})
    assert validate_registry(undecl_reg).valid is False

    # Conflicting feature roles
    conflict_role_entry = RouteFlagEntry(
        route="/role-test",
        component="role_svc",
        flags=["search_v1"],
        feature_roles={"search_v1": FeatureRole.REPLACEMENT_GUARD},
        implementation_bindings=[
            ImplementationBinding(
                implementation_id="search_v1",
                flag_name="search_v1",
                role=FeatureRole.IMPLEMENTATION_GUARD,
            )
        ],
        coverage_status=CoverageStatus.PROTECTED,
    )
    conflict_role_reg = reg.model_copy(update={"routes": [*reg.routes, conflict_role_entry]})
    assert validate_registry(conflict_role_reg).valid is False


def test_independent_policy_rejects_wrong_globally_declared_flag() -> None:
    reg = load_route_registry()
    finding = Finding(
        finding_id="fnd_policy_01",
        incident_id="inc_policy_01",
        category=VulnerabilityCategory.SQL_INJECTION,
        affected_route="/search",
        affected_component="search_service",
        severity=VulnerabilitySeverity.HIGH,
        status=FindingStatus.REPRODUCED,
        evidence_ids=["art_policy_01"],
    )
    # files_v1 is globally declared in reg.declared_features, but does NOT control /search!
    wrong_mapping = MappingResult(
        finding_id=finding.finding_id,
        mapping_status=MappingStatus.MATCHED,
        affected_route="/search",
        matched_component="search_service",
        candidate_flags=["files_v1"],
        selected_flag="files_v1",
        registry_version=reg.registry_version,
        mapping_rationale="Injected wrong flag.",
        evidence_ids=["art_policy_01"],
        manual_review_required=False,
    )
    with pytest.raises(ContractValidationError):
        validate_mapping_output(wrong_mapping, finding=finding, registry=reg)

    # Undeclared flag rejected
    undecl_mapping = wrong_mapping.model_copy(
        update={"candidate_flags": ["nonexistent"], "selected_flag": "nonexistent"}
    )
    with pytest.raises(UnknownFeatureError):
        validate_mapping_output(undecl_mapping, finding=finding, registry=reg)

    # Diagnostic mode allows AMBIGUOUS / UNMAPPED without raising
    amb_mapping = MappingResult(
        finding_id=finding.finding_id,
        mapping_status=MappingStatus.AMBIGUOUS,
        affected_route="/search",
        matched_component="search_service",
        candidate_flags=["search_v1", "search_v2"],
        selected_flag=None,
        registry_version=reg.registry_version,
        mapping_rationale="Ambiguous.",
        evidence_ids=["art_policy_01"],
        manual_review_required=True,
    )
    assert (
        validate_mapping_output(
            amb_mapping, finding=finding, registry=reg, require_actionable=False
        )
        == amb_mapping
    )
    with pytest.raises(AmbiguousMappingError):
        validate_mapping_output(amb_mapping, finding=finding, registry=reg, require_actionable=True)


def test_guards_reject_semantically_wrong_or_ineligible_mapping() -> None:
    reg = load_route_registry()
    incident = IncidentAggregate(
        incident_id="inc_guard_01",
        finding_id="fnd_guard_01",
        correlation_id="corr_guard_01",
        environment="demo-staging",
        current_state=IncidentState.REPRODUCED,
        source_revision="demo-rev-0000demo",
        latest_event_id="evt_guard_01",
        created_at=NOW,
        updated_at=NOW,
    )
    event = build_incident_event(
        incident_id="inc_guard_01",
        event_type=EventType.MAPPING_MATCHED,
        actor="agent_core_flag_mapper",
        actor_type=ActorType.AI_AGENT,
        sequence_number=2,
        correlation_id="corr_guard_01",
        evidence_ids=["art_guard_01"],
        timestamp_utc=NOW,
    )
    prod = ProducerContext(
        producer_id="agent_core_flag_mapper",
        actor_type=ActorType.AI_AGENT,
        authenticated=True,
        trusted_channel="fixture_sim",
        provenance_mode="fixture",
    )
    wrong_mapping = MappingResult(
        finding_id="fnd_guard_01",
        mapping_status=MappingStatus.MATCHED,
        affected_route="/search",
        matched_component="search_service",
        candidate_flags=["files_v1"],
        selected_flag="files_v1",
        registry_version=reg.registry_version,
        mapping_rationale="Wrong flag",
        evidence_ids=["art_guard_01"],
        manual_review_required=False,
    )
    tctx = TransitionContext(
        producer_context=prod,
        clock=FixedClock(NOW),
        fixture_mode=True,
        route_registry=reg,
        mapping_result=wrong_mapping,
    )
    reg_guard = guard_registry_validity(incident, event, tctx)
    assert reg_guard.allowed is False
    assert reg_guard.reason_code == "SEMANTIC_MAPPING_MISMATCH"

    hold_mapping = MappingResult(
        finding_id="fnd_guard_01",
        mapping_status=MappingStatus.MATCHED,
        affected_route="/files",
        matched_component="file_service",
        candidate_flags=["files_v1"],
        selected_flag="files_v1",
        registry_version=reg.registry_version,
        mapping_rationale="Stale state hold",
        evidence_ids=["art_guard_01"],
        manual_review_required=False,
        diagnostics={"action_eligibility": "hold"},
    )
    tctx_hold = TransitionContext(
        producer_context=prod,
        clock=FixedClock(NOW),
        fixture_mode=True,
        route_registry=reg,
        mapping_result=hold_mapping,
    )
    map_guard = guard_mapping_validity(incident, event, tctx_hold)
    assert map_guard.allowed is False
    assert map_guard.reason_code == "MAPPING_NOT_OPERATIONALLY_ELIGIBLE"
