"""Deterministic route, alias, component, and implementation resolution."""

from __future__ import annotations

from collections.abc import Sequence

from shared.enums import MappingReasonCode, TestExecutionStatus, VerificationPhase
from shared.schemas import RouteFlagEntry, VerificationResult

from agent_core.mapping.models import (
    ComponentResolutionResult,
    ImplementationResolutionResult,
    MappingContext,
    RouteResolutionResult,
)
from agent_core.mapping.registry import IndexedRouteRegistry

# Explicit security-lane test ID -> implementation binding contract (from security/registry.py).
SECURITY_TEST_IMPLEMENTATION_MAP: dict[str, str] = {
    "sqli_search": "search_v1",
    "traversal_files": "files_v1",
}


def resolve_route(
    indexed: IndexedRouteRegistry,
    *,
    route: str | None,
    http_method: str | None = None,
) -> RouteResolutionResult:
    """Resolve an input route strictly via canonical match, explicit alias, or declared variant.

    Never uses fuzzy similarity, substring matching, prefix matching, or uncontrolled
    URL normalization.
    """
    if route is None or not route.strip():
        return RouteResolutionResult(
            matched=False,
            input_route=route,
            reason_codes=[MappingReasonCode.UNKNOWN_ROUTE],
            limitations=["Finding does not specify an affected HTTP route."],
        )

    entry: RouteFlagEntry | None = None
    match_kind: str = "none"
    matched_alias: str | None = None
    matched_variant: str | None = None
    reason_codes: list[MappingReasonCode] = []

    if route in indexed.by_route:
        entry = indexed.by_route[route]
        match_kind = "canonical"
        reason_codes.append(MappingReasonCode.EXACT_ROUTE_MATCH)
    elif route in indexed.by_alias:
        entry = indexed.by_alias[route]
        match_kind = "alias"
        matched_alias = route
        reason_codes.append(MappingReasonCode.DECLARED_ALIAS_MATCH)
    elif route in indexed.by_variant:
        entry = indexed.by_variant[route]
        match_kind = "variant"
        matched_variant = route
        reason_codes.append(MappingReasonCode.DECLARED_VARIANT_MATCH)

    if entry is None:
        return RouteResolutionResult(
            matched=False,
            input_route=route,
            reason_codes=[MappingReasonCode.UNKNOWN_ROUTE],
            limitations=[f"Route {route!r} is not declared in active route registry."],
        )

    method_ok = True
    limitations: list[str] = []
    if http_method and entry.http_methods:
        allowed_methods = {m.upper() for m in entry.http_methods}
        if http_method.upper() not in allowed_methods:
            method_ok = False
            reason_codes.append(MappingReasonCode.HTTP_METHOD_MISMATCH)
            limitations.append(
                f"HTTP method {http_method.upper()!r} is not declared for {entry.route!r} "
                f"(allowed: {sorted(allowed_methods)})."
            )

    return RouteResolutionResult(
        matched=method_ok,
        input_route=route,
        canonical_route=entry.route,
        matched_alias=matched_alias,
        matched_variant=matched_variant,
        match_kind=match_kind,  # type: ignore[arg-type]
        http_method_matched=method_ok,
        entry=entry,
        reason_codes=reason_codes,
        limitations=limitations,
    )


def resolve_component(
    indexed: IndexedRouteRegistry,
    *,
    component: str | None,
    route_entry: RouteFlagEntry | None = None,
) -> ComponentResolutionResult:
    """Resolve logical component or explicit component alias and cross-check route entry."""
    if component is None or not component.strip():
        return ComponentResolutionResult(
            matched=False,
            input_component=component,
            reason_codes=[MappingReasonCode.UNKNOWN_COMPONENT],
            limitations=["Finding does not specify an affected component."],
        )

    canonical_component: str | None = None
    matched_alias: str | None = None
    reason_codes: list[MappingReasonCode] = []

    if component in indexed.by_component:
        canonical_component = component
        reason_codes.append(MappingReasonCode.COMPONENT_MATCH)
    else:
        mapped_components = sorted(indexed.component_alias_to_canonical.get(component, ()))
        if len(mapped_components) == 1:
            canonical_component = mapped_components[0]
            matched_alias = component
            reason_codes.append(MappingReasonCode.COMPONENT_ALIAS_MATCH)
        elif len(mapped_components) > 1:
            return ComponentResolutionResult(
                matched=False,
                input_component=component,
                reason_codes=[MappingReasonCode.UNKNOWN_COMPONENT],
                limitations=[
                    f"Component alias {component!r} maps to multiple components: "
                    f"{mapped_components}."
                ],
            )

    if canonical_component is None:
        return ComponentResolutionResult(
            matched=False,
            input_component=component,
            reason_codes=[MappingReasonCode.UNKNOWN_COMPONENT],
            limitations=[f"Component {component!r} is not declared in active route registry."],
        )

    entries = list(indexed.by_component.get(canonical_component, ()))
    conflict = False
    limitations: list[str] = []
    if route_entry is not None and route_entry.component != canonical_component:
        conflict = True
        reason_codes.append(MappingReasonCode.ROUTE_COMPONENT_CONFLICT)
        limitations.append(
            f"Route {route_entry.route!r} belongs to component {route_entry.component!r}, "
            f"which conflicts with finding component {canonical_component!r}."
        )

    return ComponentResolutionResult(
        matched=not conflict,
        input_component=component,
        canonical_component=canonical_component,
        matched_alias=matched_alias,
        conflict_with_route=conflict,
        entries=entries,
        reason_codes=reason_codes,
        limitations=limitations,
    )


def resolve_implementation(
    entry: RouteFlagEntry,
    *,
    context: MappingContext,
    verification_results: Sequence[VerificationResult] = (),
) -> ImplementationResolutionResult:
    """Resolve affected implementation from trusted runtime/verification bindings only.

    AI ``InvestigationSummary`` text is never used to override implementation bindings.
    """
    bindings_by_impl = {b.implementation_id: b for b in entry.implementation_bindings}
    if not bindings_by_impl:
        return ImplementationResolutionResult(
            resolved=False,
            reason_codes=[MappingReasonCode.NO_IMPLEMENTATION_BINDING],
            limitations=[f"Route {entry.route!r} declares no implementation bindings."],
        )

    # 1. Explicit trusted observed implementation (e.g., X-KSX-Variant header from verifier).
    if context.observed_implementation:
        obs_impl = context.observed_implementation
        binding = bindings_by_impl.get(obs_impl)
        if binding is not None:
            return ImplementationResolutionResult(
                resolved=True,
                implementation_id=binding.implementation_id,
                controlling_flag=binding.flag_name,
                source="observed_implementation",
                evidence_ids=list(context.finding.evidence_ids),
                reason_codes=[MappingReasonCode.VERIFIED_IMPLEMENTATION_MATCH],
            )
        return ImplementationResolutionResult(
            resolved=False,
            reason_codes=[MappingReasonCode.NO_IMPLEMENTATION_BINDING],
            limitations=[
                f"Observed implementation {obs_impl!r} is not bound on route {entry.route!r}."
            ],
        )

    # 2. Verified reproduction VerificationResult matching incident.
    for vr in verification_results:
        if (
            vr.incident_id == context.finding.incident_id
            and vr.phase == VerificationPhase.BEFORE_CONTAINMENT
            and vr.execution_status == TestExecutionStatus.TEST_PASSED
            and vr.passed is True
        ):
            mapped_impl = SECURITY_TEST_IMPLEMENTATION_MAP.get(vr.test_id)
            if mapped_impl and mapped_impl in bindings_by_impl:
                binding = bindings_by_impl[mapped_impl]
                return ImplementationResolutionResult(
                    resolved=True,
                    implementation_id=binding.implementation_id,
                    controlling_flag=binding.flag_name,
                    source="verification_result",
                    evidence_ids=list(vr.artifact_ids),
                    reason_codes=[MappingReasonCode.VERIFIED_IMPLEMENTATION_MATCH],
                )

    # 3. Registered security test ID on context.
    if context.registered_test_id:
        mapped_impl = SECURITY_TEST_IMPLEMENTATION_MAP.get(context.registered_test_id)
        if mapped_impl and mapped_impl in bindings_by_impl:
            binding = bindings_by_impl[mapped_impl]
            return ImplementationResolutionResult(
                resolved=True,
                implementation_id=binding.implementation_id,
                controlling_flag=binding.flag_name,
                source="registered_test",
                evidence_ids=list(context.finding.evidence_ids),
                reason_codes=[MappingReasonCode.VERIFIED_IMPLEMENTATION_MATCH],
            )

    # 4. Explicit component alias matching an implementation ID (e.g., search_v1 or files_v1).
    comp = context.finding.affected_component
    if comp in bindings_by_impl:
        binding = bindings_by_impl[comp]
        return ImplementationResolutionResult(
            resolved=True,
            implementation_id=binding.implementation_id,
            controlling_flag=binding.flag_name,
            source="component_alias",
            evidence_ids=list(context.finding.evidence_ids),
            reason_codes=[MappingReasonCode.VERIFIED_IMPLEMENTATION_MATCH],
        )

    # 5. Single non-replacement implementation binding on the route.
    non_replacement = [b for b in entry.implementation_bindings if not b.is_replacement]
    if len(entry.implementation_bindings) == 1:
        binding = entry.implementation_bindings[0]
        return ImplementationResolutionResult(
            resolved=True,
            implementation_id=binding.implementation_id,
            controlling_flag=binding.flag_name,
            source="single_binding",
            evidence_ids=list(context.finding.evidence_ids),
            reason_codes=[MappingReasonCode.SINGLE_VALID_CANDIDATE],
        )

    if len(non_replacement) == 1 and len(entry.implementation_bindings) > 1:
        # Still require explicit evidence when multiple flags exist on the route,
        # so do NOT guess unless evidence established it.
        return ImplementationResolutionResult(
            resolved=False,
            reason_codes=[MappingReasonCode.MULTIPLE_VALID_CANDIDATES],
            limitations=[
                f"Route {entry.route!r} declares multiple implementation bindings "
                f"({sorted(bindings_by_impl)}) and lacks trusted implementation evidence."
            ],
        )

    return ImplementationResolutionResult(
        resolved=False,
        reason_codes=[MappingReasonCode.NO_IMPLEMENTATION_BINDING],
        limitations=[
            f"Could not deterministically resolve implementation on route {entry.route!r}."
        ],
    )


def compute_authoritative_candidates(
    indexed: IndexedRouteRegistry,
    *,
    route: str | None,
    component: str | None,
    http_method: str | None = None,
) -> list[str]:
    """Pure shared helper returning sorted valid candidate flags for route/component."""
    if route:
        route_res = resolve_route(indexed, route=route, http_method=http_method)
        if not route_res.matched or route_res.entry is None:
            return []
        if component:
            comp_res = resolve_component(indexed, component=component, route_entry=route_res.entry)
            if not comp_res.matched:
                return []
        return sorted(set(route_res.entry.flags))

    if component:
        comp_res = resolve_component(indexed, component=component, route_entry=None)
        if not comp_res.matched:
            return []
        flags: set[str] = set()
        for entry in comp_res.entries:
            flags.update(entry.flags)
        return sorted(flags)

    return []
