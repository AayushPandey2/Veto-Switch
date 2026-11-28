"""Deterministic 6-tier candidate discovery and mapping decision engine."""

from __future__ import annotations

from collections.abc import Sequence

from shared.enums import (
    EvidenceProvenance,
    FeatureRole,
    MappingActionEligibility,
    MappingMethod,
    MappingReasonCode,
    MappingStatus,
)
from shared.schemas import FeatureState, MappingResult, RouteFlagEntry, RouteFlagRegistry

from agent_core.mapping.models import (
    CandidateDetail,
    EvidenceValidationOutcome,
    FreshnessPolicy,
    ImplementationResolutionResult,
    MappingContext,
    MappingDiagnostics,
    MappingOutcome,
    RejectedCandidate,
    StateValidationResult,
)
from agent_core.mapping.registry import IndexedRouteRegistry, validate_registry
from agent_core.mapping.resolvers import (
    resolve_component,
    resolve_implementation,
    resolve_route,
)
from agent_core.mapping.state_validator import validate_feature_states


def _build_candidate_details(
    entry: RouteFlagEntry,
    *,
    observed_features: Sequence[FeatureState],
    environment: str,
    evaluation_time: MappingContext,
    fixture_mode: bool,
    freshness_policy: FreshnessPolicy | None,
) -> tuple[list[CandidateDetail], dict[str, StateValidationResult]]:
    bindings_by_flag = {b.flag_name: b for b in entry.implementation_bindings}
    details: list[CandidateDetail] = []
    state_by_flag: dict[str, StateValidationResult] = {}

    for flag in sorted(set(entry.flags)):
        state_res = validate_feature_states(
            flag,
            observed_features,
            environment=environment,
            evaluation_time=evaluation_time.evaluation_timestamp,
            fixture_mode=fixture_mode,
            policy=freshness_policy,
        )
        state_by_flag[flag] = state_res
        binding = bindings_by_flag.get(flag)
        role = (
            entry.feature_roles.get(flag)
            or (binding.role if binding is not None else FeatureRole.UNKNOWN)
        )
        details.append(
            CandidateDetail(
                flag_name=flag,
                role=role,
                implementation_id=binding.implementation_id if binding else None,
                route=entry.route,
                component=entry.component,
                is_replacement=binding.is_replacement if binding else False,
                observation_status=state_res.observation_status,
                observed_enabled=state_res.observed_enabled,
                state_version=state_res.state_version,
                reason_codes=state_res.reason_codes,
            )
        )
    return details, state_by_flag


def evaluate_mapping_decision(
    context: MappingContext,
    registry: RouteFlagRegistry,
    evidence_outcome: EvidenceValidationOutcome,
    *,
    freshness_policy: FreshnessPolicy | None = None,
) -> MappingOutcome:
    """Execute pure deterministic 6-tier mapping resolution and produce ``MappingOutcome``."""
    finding = context.finding
    target_env = context.environment or finding.environment or registry.environment
    expected_rev = context.application_revision or finding.repository_revision

    reg_report = validate_registry(
        registry,
        expected_environment=target_env,
        expected_revision=expected_rev,
    )
    indexed = IndexedRouteRegistry(registry)

    reason_codes: list[MappingReasonCode] = list(reg_report.reason_codes)
    reason_codes.extend(evidence_outcome.reason_codes)
    limitations: list[str] = list(reg_report.errors) + list(evidence_outcome.limitations)
    provenance: list[EvidenceProvenance] = [finding.provenance, registry.provenance]

    if not reg_report.valid:
        reason_codes.append(MappingReasonCode.MANUAL_REVIEW_REQUIRED)
        dedup_codes = sorted(set(reason_codes), key=lambda c: c.value)
        diag = MappingDiagnostics(
            mapping_method=MappingMethod.UNMAPPED,
            reason_codes=dedup_codes,
            registry_fingerprint=indexed.fingerprint,
            application_revision=expected_rev or registry.application_revision,
            action_eligibility=MappingActionEligibility.BLOCKED,
            requires_verification=True,
            missing_evidence=evidence_outcome.missing_evidence,
            limitations=limitations,
            provenance=sorted(set(provenance), key=lambda p: p.value),
            is_fixture_only=evidence_outcome.is_fixture_only or registry.is_fixture_assumption,
            evaluation_timestamp=context.evaluation_timestamp,
        )
        res = MappingResult(
            finding_id=finding.finding_id,
            mapping_status=MappingStatus.UNMAPPED,
            affected_route=finding.affected_route,
            matched_component=None,
            candidate_flags=[],
            selected_flag=None,
            registry_version=registry.registry_version,
            mapping_rationale=(
                "Registry validation failed; cannot establish trustworthy feature mapping: "
                + "; ".join(reg_report.errors)
            ),
            evidence_ids=list(evidence_outcome.verified_evidence_ids or finding.evidence_ids),
            manual_review_required=True,
            diagnostics=diag.model_dump(mode="json"),
        )
        return MappingOutcome(mapping_result=res, diagnostics=diag)

    route_res = resolve_route(
        indexed,
        route=finding.affected_route,
        http_method=context.http_method,
    )
    reason_codes.extend(route_res.reason_codes)
    limitations.extend(route_res.limitations)

    comp_res = resolve_component(
        indexed,
        component=finding.affected_component,
        route_entry=route_res.entry,
    )
    reason_codes.extend(comp_res.reason_codes)
    limitations.extend(comp_res.limitations)

    # Conflict between route and component -> unmapped + manual review
    if comp_res.conflict_with_route:
        reason_codes.append(MappingReasonCode.MANUAL_REVIEW_REQUIRED)
        dedup_codes = sorted(set(reason_codes), key=lambda c: c.value)
        diag = MappingDiagnostics(
            canonical_route=route_res.canonical_route,
            matched_alias=route_res.matched_alias or route_res.matched_variant,
            mapping_method=MappingMethod.UNMAPPED,
            reason_codes=dedup_codes,
            registry_fingerprint=indexed.fingerprint,
            application_revision=expected_rev or registry.application_revision,
            action_eligibility=MappingActionEligibility.BLOCKED,
            requires_verification=True,
            missing_evidence=evidence_outcome.missing_evidence,
            limitations=limitations,
            provenance=sorted(set(provenance), key=lambda p: p.value),
            is_fixture_only=evidence_outcome.is_fixture_only or registry.is_fixture_assumption,
            evaluation_timestamp=context.evaluation_timestamp,
        )
        res = MappingResult(
            finding_id=finding.finding_id,
            mapping_status=MappingStatus.UNMAPPED,
            affected_route=finding.affected_route,
            matched_component=route_res.entry.component if route_res.entry else None,
            candidate_flags=[],
            selected_flag=None,
            registry_version=registry.registry_version,
            mapping_rationale=(
                f"Route {finding.affected_route!r} and component {finding.affected_component!r} "
                "conflict in active registry; manual review required."
            ),
            evidence_ids=list(evidence_outcome.verified_evidence_ids or finding.evidence_ids),
            manual_review_required=True,
            diagnostics=diag.model_dump(mode="json"),
        )
        return MappingOutcome(mapping_result=res, diagnostics=diag)

    # Determine target entries (either from route or component-only when route is absent)
    target_entry: RouteFlagEntry | None = None
    mapping_method = MappingMethod.UNMAPPED

    if finding.affected_route is not None:
        # Tier 6: Unknown or mismatched route must NOT be overridden by component
        target_entry = (
            None if not route_res.matched or route_res.entry is None else route_res.entry
        )
    elif comp_res.matched and len(comp_res.entries) == 1:
        # Tier 4: Route genuinely absent, component has single entry
        target_entry = comp_res.entries[0]
        mapping_method = MappingMethod.COMPONENT_ONLY
    elif comp_res.matched and len(comp_res.entries) > 1:
        # Component maps to multiple routes -> check if all share a single flag
        all_flags = sorted({f for e in comp_res.entries for f in e.flags})
        if len(all_flags) == 1:
            target_entry = comp_res.entries[0]
            mapping_method = MappingMethod.COMPONENT_ONLY
        else:
            reason_codes.append(MappingReasonCode.MULTIPLE_VALID_CANDIDATES)
            reason_codes.append(MappingReasonCode.MANUAL_REVIEW_REQUIRED)
            limitations.append(
                f"Component {comp_res.canonical_component!r} spans multiple routes with "
                f"distinct flags {all_flags}; route is required to disambiguate."
            )
            dedup_codes = sorted(set(reason_codes), key=lambda c: c.value)
            diag = MappingDiagnostics(
                mapping_method=MappingMethod.AMBIGUOUS_CANDIDATES,
                reason_codes=dedup_codes,
                affected_routes=sorted(e.route for e in comp_res.entries),
                registry_fingerprint=indexed.fingerprint,
                application_revision=expected_rev or registry.application_revision,
                action_eligibility=MappingActionEligibility.BLOCKED,
                requires_verification=True,
                missing_evidence=evidence_outcome.missing_evidence,
                limitations=limitations,
                provenance=sorted(set(provenance), key=lambda p: p.value),
                is_fixture_only=evidence_outcome.is_fixture_only or registry.is_fixture_assumption,
                evaluation_timestamp=context.evaluation_timestamp,
            )
            res = MappingResult(
                finding_id=finding.finding_id,
                mapping_status=MappingStatus.AMBIGUOUS,
                affected_route=None,
                matched_component=comp_res.canonical_component,
                candidate_flags=all_flags,
                selected_flag=None,
                registry_version=registry.registry_version,
                mapping_rationale=(
                    f"Component {comp_res.canonical_component!r} has multiple candidate flags "
                    f"{all_flags} and no affected_route; manual disambiguation required."
                ),
                evidence_ids=list(evidence_outcome.verified_evidence_ids or finding.evidence_ids),
                manual_review_required=True,
                diagnostics=diag.model_dump(mode="json"),
            )
            return MappingOutcome(mapping_result=res, diagnostics=diag)

    if target_entry is None or not target_entry.flags:
        reason_codes.append(MappingReasonCode.MANUAL_REVIEW_REQUIRED)
        dedup_codes = sorted(set(reason_codes), key=lambda c: c.value)
        diag = MappingDiagnostics(
            canonical_route=route_res.canonical_route,
            matched_alias=route_res.matched_alias or route_res.matched_variant,
            mapping_method=MappingMethod.UNMAPPED,
            reason_codes=dedup_codes,
            registry_fingerprint=indexed.fingerprint,
            application_revision=expected_rev or registry.application_revision,
            action_eligibility=MappingActionEligibility.BLOCKED,
            requires_verification=True,
            missing_evidence=evidence_outcome.missing_evidence,
            limitations=limitations,
            provenance=sorted(set(provenance), key=lambda p: p.value),
            is_fixture_only=evidence_outcome.is_fixture_only or registry.is_fixture_assumption,
            evaluation_timestamp=context.evaluation_timestamp,
        )
        res = MappingResult(
            finding_id=finding.finding_id,
            mapping_status=MappingStatus.UNMAPPED,
            affected_route=finding.affected_route,
            matched_component=target_entry.component if target_entry else None,
            candidate_flags=[],
            selected_flag=None,
            registry_version=registry.registry_version,
            mapping_rationale=(
                f"No declared feature flag controls route {finding.affected_route!r} "
                f"(component={finding.affected_component!r})."
            ),
            evidence_ids=list(evidence_outcome.verified_evidence_ids or finding.evidence_ids),
            manual_review_required=True,
            diagnostics=diag.model_dump(mode="json"),
        )
        return MappingOutcome(mapping_result=res, diagnostics=diag)

    # Candidate discovery on target_entry
    candidate_flags = sorted(set(target_entry.flags))
    candidate_details, state_by_flag = _build_candidate_details(
        target_entry,
        observed_features=context.feature_states,
        environment=target_env,
        evaluation_time=context,
        fixture_mode=context.fixture_mode,
        freshness_policy=freshness_policy,
    )

    impl_res: ImplementationResolutionResult = resolve_implementation(
        target_entry,
        context=context,
        verification_results=context.verification_results,
    )
    reason_codes.extend(impl_res.reason_codes)
    limitations.extend(impl_res.limitations)

    selected_flag: str | None = None
    rejected_candidates: list[RejectedCandidate] = []

    if len(candidate_flags) == 1:
        selected_flag = candidate_flags[0]
        if mapping_method == MappingMethod.UNMAPPED:
            if route_res.match_kind in {"alias", "variant"}:
                mapping_method = MappingMethod.DECLARED_ALIAS_AND_IMPLEMENTATION
            else:
                mapping_method = MappingMethod.EXACT_ROUTE_AND_COMPONENT
        reason_codes.append(MappingReasonCode.SINGLE_VALID_CANDIDATE)
    elif impl_res.resolved and impl_res.controlling_flag in candidate_flags:
        selected_flag = impl_res.controlling_flag
        if route_res.match_kind in {"alias", "variant"}:
            mapping_method = MappingMethod.DECLARED_ALIAS_AND_IMPLEMENTATION
        else:
            mapping_method = MappingMethod.VERIFIED_IMPLEMENTATION_BINDING
        for flag in candidate_flags:
            if flag != selected_flag:
                rejected_candidates.append(
                    RejectedCandidate(
                        flag_name=flag,
                        reason_code=MappingReasonCode.VERIFIED_IMPLEMENTATION_MATCH,
                        reason=(
                            f"Excluded because trusted implementation "
                            f"{impl_res.implementation_id!r} is bound to {selected_flag!r}."
                        ),
                    )
                )
    else:
        # Tier 5: Multiple plausible candidates -> ambiguous
        mapping_method = MappingMethod.AMBIGUOUS_CANDIDATES
        reason_codes.append(MappingReasonCode.MULTIPLE_VALID_CANDIDATES)
        reason_codes.append(MappingReasonCode.MANUAL_REVIEW_REQUIRED)
        dedup_codes = sorted(set(reason_codes), key=lambda c: c.value)
        diag = MappingDiagnostics(
            canonical_route=target_entry.route,
            matched_alias=route_res.matched_alias or route_res.matched_variant,
            matched_implementation=impl_res.implementation_id,
            mapping_method=mapping_method,
            reason_codes=dedup_codes,
            candidate_details=candidate_details,
            rejected_candidates=rejected_candidates,
            affected_routes=[target_entry.route],
            shared_feature_dependencies=sorted(target_entry.shared_dependencies),
            potential_replacements=sorted(
                b.implementation_id
                for b in target_entry.implementation_bindings
                if b.is_replacement
            ),
            fallback_behavior=target_entry.fallback_route,
            registry_fingerprint=indexed.fingerprint,
            application_revision=expected_rev or registry.application_revision,
            action_eligibility=MappingActionEligibility.BLOCKED,
            requires_verification=True,
            missing_evidence=evidence_outcome.missing_evidence,
            limitations=limitations,
            provenance=sorted(set(provenance), key=lambda p: p.value),
            is_fixture_only=evidence_outcome.is_fixture_only or registry.is_fixture_assumption,
            evaluation_timestamp=context.evaluation_timestamp,
        )
        res = MappingResult(
            finding_id=finding.finding_id,
            mapping_status=MappingStatus.AMBIGUOUS,
            affected_route=target_entry.route,
            matched_component=target_entry.component,
            candidate_flags=candidate_flags,
            selected_flag=None,
            registry_version=registry.registry_version,
            mapping_rationale=(
                f"Route {target_entry.route!r} has multiple candidate flags {candidate_flags} "
                "and lacks deterministic implementation evidence; manual disambiguation required."
            ),
            evidence_ids=list(evidence_outcome.verified_evidence_ids or finding.evidence_ids),
            manual_review_required=True,
            diagnostics=diag.model_dump(mode="json"),
        )
        return MappingOutcome(mapping_result=res, diagnostics=diag)

    # Structural match succeeded for `selected_flag`; now evaluate operational eligibility
    state_res = state_by_flag[selected_flag]
    reason_codes.extend(state_res.reason_codes)
    limitations.extend(state_res.limitations)
    if state_res.provenance is not None:
        provenance.append(state_res.provenance)

    if not evidence_outcome.actionable:
        eligibility = MappingActionEligibility.BLOCKED
    elif not state_res.action_eligible:
        eligibility = MappingActionEligibility.HOLD
    else:
        eligibility = MappingActionEligibility.ELIGIBLE

    manual_review_needed = eligibility != MappingActionEligibility.ELIGIBLE
    if manual_review_needed:
        reason_codes.append(MappingReasonCode.MANUAL_REVIEW_REQUIRED)

    dedup_codes = sorted(set(reason_codes), key=lambda c: c.value)
    shared_routes = indexed.routes_sharing_flag(selected_flag)
    replacements = sorted(
        b.implementation_id
        for b in target_entry.implementation_bindings
        if b.is_replacement and b.flag_name != selected_flag
    )
    matched_impl = impl_res.implementation_id
    if matched_impl is None:
        for b in target_entry.implementation_bindings:
            if b.flag_name == selected_flag:
                matched_impl = b.implementation_id
                break

    diag = MappingDiagnostics(
        canonical_route=target_entry.route,
        matched_alias=route_res.matched_alias or route_res.matched_variant,
        matched_implementation=matched_impl,
        mapping_method=mapping_method,
        reason_codes=dedup_codes,
        candidate_details=candidate_details,
        rejected_candidates=rejected_candidates,
        affected_routes=shared_routes or [target_entry.route],
        shared_feature_dependencies=sorted(target_entry.shared_dependencies),
        potential_replacements=replacements,
        fallback_behavior=target_entry.fallback_route,
        observation_status=state_res.observation_status,
        registry_fingerprint=indexed.fingerprint,
        application_revision=expected_rev or registry.application_revision,
        observed_feature_state=state_res.observed_enabled,
        feature_state_version=state_res.state_version,
        action_eligibility=eligibility,
        requires_verification=state_res.requires_verification,
        missing_evidence=evidence_outcome.missing_evidence,
        limitations=limitations,
        provenance=sorted(set(provenance), key=lambda p: p.value),
        is_fixture_only=evidence_outcome.is_fixture_only or registry.is_fixture_assumption,
        evaluation_timestamp=context.evaluation_timestamp,
    )
    rationale = (
        f"Resolved {target_entry.route!r} (component={target_entry.component!r}, "
        f"implementation={matched_impl or 'unspecified'}) to flag {selected_flag!r} "
        f"via {mapping_method.value}; action_eligibility={eligibility.value}."
    )
    res = MappingResult(
        finding_id=finding.finding_id,
        mapping_status=MappingStatus.MATCHED,
        affected_route=target_entry.route,
        matched_component=target_entry.component,
        candidate_flags=candidate_flags,
        selected_flag=selected_flag,
        registry_version=registry.registry_version,
        mapping_rationale=rationale,
        evidence_ids=list(evidence_outcome.verified_evidence_ids or finding.evidence_ids),
        manual_review_required=manual_review_needed,
        diagnostics=diag.model_dump(mode="json"),
    )
    return MappingOutcome(mapping_result=res, diagnostics=diag)
