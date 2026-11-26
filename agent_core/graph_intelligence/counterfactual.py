"""Non-mutating counterfactual containment simulation over the dependency graph."""

from __future__ import annotations

from collections.abc import Sequence

from shared.enums import ContainmentStrategyType
from shared.schemas import FeatureState, RouteFlagRegistry

from agent_core.graph_intelligence.models import BlastRadiusResult, CounterfactualOutcome


def simulate_counterfactual(
    *,
    strategy_id: str,
    strategy_type: ContainmentStrategyType,
    target_flag: str | None,
    desired_enabled: bool | None,
    blast_radius: BlastRadiusResult,
    observed_features: Sequence[FeatureState],
    registry: RouteFlagRegistry | None = None,
    replacement_flag: str | None = None,
    broad_shutdown: bool = False,
) -> CounterfactualOutcome:
    """Simulate hypothetical post-action state without mutating any input or live system."""
    state_before: dict[str, bool | None] = {
        fs.feature_name: fs.enabled
        for fs in sorted(observed_features, key=lambda f: f.feature_name)
    }
    state_after = dict(state_before)

    if target_flag and desired_enabled is not None:
        state_after[target_flag] = desired_enabled
    if replacement_flag and strategy_type == ContainmentStrategyType.SWITCH_TO_REPLACEMENT_FLAG:
        state_after[replacement_flag] = True

    if broad_shutdown:
        affected_routes = sorted(
            set(blast_radius.affected_route_nodes) | set(blast_radius.unrelated_nodes)
        )
        affected_caps = ["all_application_routes"]
        preserved_caps: list[str] = []
        blocked_paths = list(blast_radius.known_security_entry_points)
        remaining_paths: list[str] = []
        fallback_behavior = "Full application maintenance / outage."
        assumptions = ["Broad shutdown disables all application endpoints."]
        limitations = [
            "Predicted disruption is application-wide; no single-flag control exists "
            "for full shutdown."
        ]
        return CounterfactualOutcome(
            strategy_id=strategy_id,
            qualifier="predicted",
            state_before=state_before,
            hypothetical_state_after=state_after,
            affected_routes=affected_routes,
            affected_capabilities=affected_caps,
            affected_services=list(blast_radius.affected_implementation_nodes),
            preserved_capabilities=preserved_caps,
            potentially_blocked_vulnerable_paths=blocked_paths,
            remaining_exposure_paths=remaining_paths,
            fallback_behavior=fallback_behavior,
            assumptions=assumptions,
            limitations=limitations,
        )

    if strategy_type == ContainmentStrategyType.DISABLE_FEATURE_FLAG and target_flag:
        blocked_paths = list(blast_radius.known_security_entry_points)
        remaining_paths = []
        if not blocked_paths:
            remaining_paths = ["unknown_entry_points"]
        disable_fallback: str | None = None
        if registry is not None:
            for entry in registry.routes:
                if target_flag in entry.flags:
                    for b in entry.implementation_bindings:
                        if b.flag_name == target_flag and b.fallback_behavior:
                            disable_fallback = b.fallback_behavior
                            break
                    if not disable_fallback and entry.fallback_route:
                        disable_fallback = f"Fallback declared: {entry.fallback_route}"
                    break
        return CounterfactualOutcome(
            strategy_id=strategy_id,
            qualifier="requires_verification",
            state_before=state_before,
            hypothetical_state_after=state_after,
            affected_routes=list(blast_radius.affected_route_nodes),
            affected_capabilities=list(blast_radius.affected_capabilities),
            affected_services=list(blast_radius.affected_implementation_nodes),
            preserved_capabilities=list(blast_radius.preserved_capabilities),
            potentially_blocked_vulnerable_paths=blocked_paths,
            remaining_exposure_paths=remaining_paths,
            fallback_behavior=disable_fallback,
            assumptions=[
                f"Assumes all declared entry points {blocked_paths} respect flag {target_flag!r}."
            ],
            limitations=[
                "Hypothetical containment prediction; actual containment requires "
                "post-change security verification."
            ],
        )

    if strategy_type == ContainmentStrategyType.SWITCH_TO_REPLACEMENT_FLAG:
        return CounterfactualOutcome(
            strategy_id=strategy_id,
            qualifier="predicted",
            state_before=state_before,
            hypothetical_state_after=state_after,
            affected_routes=list(blast_radius.affected_route_nodes),
            affected_capabilities=[],
            affected_services=list(blast_radius.affected_implementation_nodes),
            preserved_capabilities=sorted(
                set(blast_radius.affected_capabilities) | set(blast_radius.preserved_capabilities)
            ),
            potentially_blocked_vulnerable_paths=list(blast_radius.known_security_entry_points),
            remaining_exposure_paths=[],
            fallback_behavior=f"Routes served by replacement {replacement_flag or 'unknown'}.",
            missing_prerequisites=[
                "Verified replacement deployment and security regression pass."
            ],
            assumptions=["Assumes replacement implementation is deployed, addressable, and safe."],
            limitations=[
                "Multi-flag transition cannot be executed as a single-flag atomic mutation."
            ],
        )

    if strategy_type == ContainmentStrategyType.RESTRICT_TARGETING:
        return CounterfactualOutcome(
            strategy_id=strategy_id,
            qualifier="predicted",
            state_before=state_before,
            hypothetical_state_after=state_after,
            affected_routes=list(blast_radius.affected_route_nodes),
            affected_capabilities=list(blast_radius.affected_capabilities),
            affected_services=list(blast_radius.affected_implementation_nodes),
            preserved_capabilities=list(blast_radius.preserved_capabilities),
            potentially_blocked_vulnerable_paths=[],
            remaining_exposure_paths=list(blast_radius.known_security_entry_points),
            fallback_behavior="Partial cohort restriction.",
            limitations=[
                "Restricting targeting reduces exposure scope but leaves targeted "
                "cohorts vulnerable."
            ],
        )

    return CounterfactualOutcome(
        strategy_id=strategy_id,
        qualifier="unknown",
        state_before=state_before,
        hypothetical_state_after=state_after,
        affected_routes=list(blast_radius.affected_route_nodes),
        affected_capabilities=list(blast_radius.affected_capabilities),
        affected_services=list(blast_radius.affected_implementation_nodes),
        preserved_capabilities=list(blast_radius.preserved_capabilities),
        potentially_blocked_vulnerable_paths=[],
        remaining_exposure_paths=list(blast_radius.known_security_entry_points),
        limitations=["Manual mitigation or verification required."],
    )
