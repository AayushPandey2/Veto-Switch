"""Comprehensive tests for DeterministicFlagMapper, state validation, and evidence safety."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from agent_core.context import FixedClock
from agent_core.flag_mapper import DeterministicFlagMapper, map_finding_to_flags
from agent_core.mapping.models import FreshnessPolicy, MappingContext
from agent_core.repositories.memory import InMemoryOrchestrationRepository
from shared.config import load_route_registry
from shared.enums import (
    ArtifactType,
    EvidenceProvenance,
    FeatureObservationStatus,
    FindingStatus,
    MappingActionEligibility,
    MappingReasonCode,
    MappingStatus,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.schemas import ArtifactReference, FeatureState, Finding
from shared.serialization import sha256_text

NOW = datetime(2026, 11, 27, 0, 0, 0, tzinfo=UTC)


def _finding(
    *,
    finding_id: str = "fnd_test_01",
    incident_id: str = "inc_test_01",
    route: str | None = "/search",
    component: str = "search_service",
    category: VulnerabilityCategory = VulnerabilityCategory.SQL_INJECTION,
    status: FindingStatus = FindingStatus.REPRODUCED,
    evidence_ids: list[str] | None = None,
    provenance: EvidenceProvenance = EvidenceProvenance.REFERENCE_FIXTURE,
    revision: str | None = "demo-rev-0000demo",
    environment: str | None = "demo-staging",
) -> Finding:
    return Finding(
        finding_id=finding_id,
        incident_id=incident_id,
        category=category,
        affected_route=route,
        affected_component=component,
        severity=VulnerabilitySeverity.HIGH,
        status=status,
        evidence_ids=evidence_ids if evidence_ids is not None else ["art_test_01"],
        repository_revision=revision,
        environment=environment,
        provenance=provenance,
    )


def _obs(
    flag: str,
    *,
    enabled: bool | None = True,
    status: FeatureObservationStatus = FeatureObservationStatus.OBSERVED,
    observed_at: datetime = NOW,
    environment: str = "demo-staging",
    provenance: EvidenceProvenance = EvidenceProvenance.REFERENCE_FIXTURE,
    segment_targeting: dict[str, object] | None = None,
) -> FeatureState:
    return FeatureState(
        environment=environment,
        feature_id=f"fs_{flag}",
        feature_name=flag,
        observation_status=status,
        enabled=enabled,
        observed_at=observed_at,
        state_version="v1",
        observation_source=provenance,
        segment_targeting=segment_targeting or {},
    )


@pytest.mark.asyncio
async def test_positive_mapping_cases() -> None:
    registry = load_route_registry()
    mapper = DeterministicFlagMapper(clock=FixedClock(NOW), fixture_mode=True)

    # 1. Verified legacy search finding maps to search_v1
    f_sqli = _finding(route="/search", component="search_service")
    out_sqli = await mapper.map_with_diagnostics(
        f_sqli,
        registry,
        [_obs("search_v1", enabled=True), _obs("search_v2", enabled=False)],
        context=MappingContext(
            finding=f_sqli,
            observed_implementation="search_v1",
            application_revision=registry.application_revision,
            environment="demo-staging",
            fixture_mode=True,
            evaluation_timestamp=NOW,
        ),
    )
    assert out_sqli.mapping_result.mapping_status == MappingStatus.MATCHED
    assert out_sqli.mapping_result.selected_flag == "search_v1"
    assert out_sqli.diagnostics.action_eligibility == MappingActionEligibility.ELIGIBLE

    # 2. Verified file traversal finding maps to files_v1
    f_files = _finding(
        route="/files",
        component="file_service",
        category=VulnerabilityCategory.PATH_TRAVERSAL,
    )
    out_files = await mapper.map_with_diagnostics(f_files, registry, [_obs("files_v1")])
    assert out_files.mapping_result.selected_flag == "files_v1"

    # 3. Declared search alias resolves correctly
    f_alias = _finding(route="/legacy/search", component="search_service")
    out_alias = await mapper.map_with_diagnostics(
        f_alias,
        registry,
        [_obs("search_v1")],
        context=MappingContext(
            finding=f_alias,
            observed_implementation="search_v1",
            fixture_mode=True,
            evaluation_timestamp=NOW,
        ),
    )
    assert out_alias.diagnostics.canonical_route == "/search"
    assert out_alias.diagnostics.matched_alias == "/legacy/search"
    assert out_alias.mapping_result.selected_flag == "search_v1"

    # 4. Declared route variant resolves correctly
    f_var = _finding(route="/files/", component="file_service")
    out_var = await mapper.map_with_diagnostics(f_var, registry, [_obs("files_v1")])
    assert out_var.diagnostics.canonical_route == "/files"
    assert out_var.mapping_result.selected_flag == "files_v1"

    # 5. Explicit component alias resolves correctly
    f_comp_alias = _finding(route="/files", component="files_v1")
    out_comp_alias = await mapper.map_with_diagnostics(f_comp_alias, registry, [_obs("files_v1")])
    assert out_comp_alias.mapping_result.selected_flag == "files_v1"
    assert out_comp_alias.mapping_result.matched_component == "file_service"

    # 6. Component-only finding resolves when genuinely unambiguous
    f_comp_only = _finding(route=None, component="file_service")
    out_comp_only = await mapper.map_with_diagnostics(f_comp_only, registry, [_obs("files_v1")])
    assert out_comp_only.mapping_result.selected_flag == "files_v1"


@pytest.mark.asyncio
async def test_ambiguity_and_negative_cases() -> None:
    registry = load_route_registry()
    mapper = DeterministicFlagMapper(clock=FixedClock(NOW), fixture_mode=True)

    # Unknown route returns unmapped and is not overridden by component
    for bad_route in ("/unknown", "/searching", "/search-admin", "/search/../files"):
        f_bad = _finding(route=bad_route, component="search_service")
        out_bad = await mapper.map_with_diagnostics(f_bad, registry, [_obs("search_v1")])
        assert out_bad.mapping_result.mapping_status == MappingStatus.UNMAPPED
        assert out_bad.mapping_result.selected_flag is None
        assert out_bad.mapping_result.manual_review_required is True

    # Unknown component returns unmapped
    f_unk_comp = _finding(route=None, component="nonexistent_service")
    out_unk_comp = await mapper.map_with_diagnostics(f_unk_comp, registry, [])
    assert out_unk_comp.mapping_result.mapping_status == MappingStatus.UNMAPPED

    # Multiple plausible flags without implementation evidence -> ambiguous
    f_amb = _finding(route="/search", component="search_service")
    out_amb = await mapper.map_with_diagnostics(
        f_amb, registry, [_obs("search_v1"), _obs("search_v2")]
    )
    assert out_amb.mapping_result.mapping_status == MappingStatus.AMBIGUOUS
    assert out_amb.mapping_result.selected_flag is None
    assert out_amb.mapping_result.manual_review_required is True
    assert sorted(out_amb.mapping_result.candidate_flags) == ["search_v1", "search_v2"]

    # Route/component conflict requires review
    f_conflict = _finding(route="/search", component="file_service")
    out_conflict = await mapper.map_with_diagnostics(f_conflict, registry, [_obs("search_v1")])
    assert out_conflict.mapping_result.mapping_status == MappingStatus.UNMAPPED
    assert MappingReasonCode.ROUTE_COMPONENT_CONFLICT in out_conflict.diagnostics.reason_codes


@pytest.mark.asyncio
async def test_state_consistency_cases() -> None:
    registry = load_route_registry()
    mapper = DeterministicFlagMapper(
        clock=FixedClock(NOW),
        freshness_policy=FreshnessPolicy(max_age_seconds=300, max_future_skew_seconds=30),
        fixture_mode=True,
    )
    f_files = _finding(route="/files", component="file_service")

    # Already-disabled feature preserves structural mapping, holds action, requires verification
    out_disabled = await mapper.map_with_diagnostics(
        f_files, registry, [_obs("files_v1", enabled=False)]
    )
    assert out_disabled.mapping_result.mapping_status == MappingStatus.MATCHED
    assert out_disabled.mapping_result.selected_flag == "files_v1"
    assert out_disabled.diagnostics.action_eligibility == MappingActionEligibility.HOLD
    assert out_disabled.diagnostics.requires_verification is True
    assert MappingReasonCode.FEATURE_ALREADY_DISABLED in out_disabled.diagnostics.reason_codes

    # Unknown / unavailable state is NOT treated as disabled
    out_unk = await mapper.map_with_diagnostics(
        f_files,
        registry,
        [_obs("files_v1", enabled=None, status=FeatureObservationStatus.UNKNOWN)],
    )
    assert out_unk.diagnostics.observed_feature_state is None
    assert out_unk.diagnostics.action_eligibility == MappingActionEligibility.HOLD
    assert MappingReasonCode.FEATURE_ALREADY_DISABLED not in out_unk.diagnostics.reason_codes

    # Stale feature observation prevents unsafe progression
    out_stale = await mapper.map_with_diagnostics(
        f_files, registry, [_obs("files_v1", observed_at=NOW - timedelta(seconds=600))]
    )
    assert out_stale.diagnostics.action_eligibility == MappingActionEligibility.HOLD
    assert MappingReasonCode.FEATURE_STATE_STALE in out_stale.diagnostics.reason_codes

    # Future timestamp beyond skew tolerance is rejected
    out_future = await mapper.map_with_diagnostics(
        f_files, registry, [_obs("files_v1", observed_at=NOW + timedelta(seconds=120))]
    )
    assert out_future.diagnostics.action_eligibility == MappingActionEligibility.HOLD
    assert MappingReasonCode.FEATURE_STATE_FUTURE_TIMESTAMP in out_future.diagnostics.reason_codes

    # Conflicting observations require review
    out_conf = await mapper.map_with_diagnostics(
        f_files,
        registry,
        [_obs("files_v1", enabled=True), _obs("files_v1", enabled=False)],
    )
    assert out_conf.diagnostics.action_eligibility == MappingActionEligibility.HOLD
    assert MappingReasonCode.FEATURE_STATE_CONFLICT in out_conf.diagnostics.reason_codes

    # Segment-targeting uncertainty is preserved
    out_seg = await mapper.map_with_diagnostics(
        f_files,
        registry,
        [_obs("files_v1", enabled=True, segment_targeting={"percentage": 50})],
    )
    assert MappingReasonCode.SEGMENT_TARGETING_UNCERTAINTY in out_seg.diagnostics.reason_codes


@pytest.mark.asyncio
async def test_evidence_safety_and_live_mode() -> None:
    registry = load_route_registry()
    repo = InMemoryOrchestrationRepository()
    mapper = DeterministicFlagMapper(
        evidence_repository=repo,
        clock=FixedClock(NOW),
        fixture_mode=False,
    )

    # Nonexistent evidence IDs cannot authorize live mapping
    f_live_missing = _finding(
        route="/files",
        component="file_service",
        provenance=EvidenceProvenance.SECURITY_TEST_OUTPUT,
        evidence_ids=["art_missing_999"],
    )
    out_missing = await mapper.map_with_diagnostics(
        f_live_missing,
        registry,
        [_obs("files_v1", provenance=EvidenceProvenance.ACTUAL_OBSERVED)],
    )
    assert out_missing.diagnostics.action_eligibility == MappingActionEligibility.BLOCKED
    assert MappingReasonCode.EVIDENCE_NOT_FOUND in out_missing.diagnostics.reason_codes

    # Cross-incident evidence is rejected
    other_bytes = b"other incident proof"
    other_art = ArtifactReference(
        artifact_id="art_other_inc",
        incident_id="inc_other",
        artifact_type=ArtifactType.REPRODUCTION_LOG,
        content_hash=sha256_text(other_bytes.decode("utf-8")),
        storage_ref="repro/other.log",
        created_at=NOW,
        producer="authorized_verifier",
        provenance=EvidenceProvenance.SECURITY_TEST_OUTPUT,
        content_type="text/plain",
        size_bytes=len(other_bytes),
    )
    await repo.store_artifact(other_art, other_bytes)
    f_cross = _finding(
        route="/files",
        component="file_service",
        provenance=EvidenceProvenance.SECURITY_TEST_OUTPUT,
        evidence_ids=["art_other_inc"],
    )
    out_cross = await mapper.map_with_diagnostics(
        f_cross,
        registry,
        [_obs("files_v1", provenance=EvidenceProvenance.ACTUAL_OBSERVED)],
    )
    assert out_cross.diagnostics.action_eligibility == MappingActionEligibility.BLOCKED

    # Suspected dependency CVE remains suspected and blocked
    f_cve = _finding(
        route="/files",
        component="file_service",
        category=VulnerabilityCategory.DEPENDENCY_CVE,
        status=FindingStatus.SUSPECTED,
        evidence_ids=[],
        provenance=EvidenceProvenance.SECURITY_TEST_OUTPUT,
    )
    out_cve = await mapper.map_with_diagnostics(
        f_cve,
        registry,
        [_obs("files_v1", provenance=EvidenceProvenance.ACTUAL_OBSERVED)],
    )
    assert out_cve.diagnostics.action_eligibility == MappingActionEligibility.BLOCKED
    assert MappingReasonCode.UNVERIFIED_FINDING in out_cve.diagnostics.reason_codes


def test_determinism_order_invariance_and_immutability() -> None:
    registry = load_route_registry()
    reversed_registry = registry.model_copy(
        update={
            "declared_features": list(reversed(registry.declared_features)),
            "routes": [
                e.model_copy(
                    update={
                        "flags": list(reversed(e.flags)),
                        "implementation_bindings": list(reversed(e.implementation_bindings)),
                    }
                )
                for e in reversed(registry.routes)
            ],
        }
    )
    f = _finding(route="/search", component="search_service")
    states = [_obs("search_v1"), _obs("search_v2")]
    ctx = MappingContext(
        finding=f,
        observed_implementation="search_v1",
        fixture_mode=True,
        evaluation_timestamp=NOW,
    )
    res1 = map_finding_to_flags(f, registry, states, context=ctx)
    res2 = map_finding_to_flags(f, reversed_registry, list(reversed(states)), context=ctx)
    assert res1.selected_flag == res2.selected_flag == "search_v1"
    assert res1.candidate_flags == res2.candidate_flags
    assert res1.mapping_status == res2.mapping_status == MappingStatus.MATCHED
