"""Authoritative RouteFlagRegistry validation, fingerprinting, and indexing."""

from __future__ import annotations

from collections import defaultdict

from shared.enums import CoverageStatus, FeatureRole, MappingReasonCode
from shared.schemas import RouteFlagEntry, RouteFlagRegistry
from shared.serialization import canonical_json, sha256_text

from agent_core.mapping.models import RegistryValidationReport

SUPPORTED_REGISTRY_SCHEMA_VERSIONS: frozenset[str] = frozenset({"1.0", "1.1"})


def compute_registry_fingerprint(registry: RouteFlagRegistry) -> str:
    """Compute a deterministic SHA-256 content fingerprint of a ``RouteFlagRegistry``."""
    payload = {
        "schema_version": registry.schema_version,
        "registry_version": registry.registry_version,
        "environment": registry.environment,
        "application_revision": registry.application_revision,
        "git_commit_sha": registry.git_commit_sha,
        "declared_features": sorted(registry.declared_features),
        "routes": [
            {
                "route": entry.route,
                "route_aliases": sorted(entry.route_aliases),
                "route_variants": sorted(entry.route_variants),
                "http_methods": sorted(m.upper() for m in entry.http_methods),
                "component": entry.component,
                "component_aliases": sorted(entry.component_aliases),
                "flags": sorted(entry.flags),
                "implementation_bindings": sorted(
                    (b.implementation_id, b.flag_name, b.role.value, b.is_replacement)
                    for b in entry.implementation_bindings
                ),
                "coverage_status": entry.coverage_status.value,
            }
            for entry in sorted(registry.routes, key=lambda r: r.route)
        ],
    }
    return sha256_text(canonical_json(payload))


def validate_registry(
    registry: RouteFlagRegistry,
    *,
    expected_environment: str | None = None,
    expected_revision: str | None = None,
    supported_schema_versions: frozenset[str] = SUPPORTED_REGISTRY_SCHEMA_VERSIONS,
) -> RegistryValidationReport:
    """Validate registry declarations, uniqueness, feature references, and bindings."""
    fingerprint = compute_registry_fingerprint(registry)
    errors: list[str] = []
    warnings: list[str] = []
    reason_codes: list[MappingReasonCode] = []

    if registry.schema_version not in supported_schema_versions:
        errors.append(f"Unsupported registry schema_version {registry.schema_version!r}.")
        reason_codes.append(MappingReasonCode.INVALID_REGISTRY)

    if registry.registry_fingerprint and registry.registry_fingerprint != fingerprint:
        errors.append("Registry content fingerprint does not match computed SHA-256.")
        reason_codes.append(MappingReasonCode.INVALID_REGISTRY)

    if expected_environment and registry.environment != expected_environment:
        errors.append(
            f"Registry environment {registry.environment!r} != expected {expected_environment!r}."
        )
        reason_codes.append(MappingReasonCode.ENVIRONMENT_MISMATCH)

    if (
        expected_revision
        and registry.application_revision
        and registry.application_revision != expected_revision
    ):
        errors.append(
            f"Registry application_revision {registry.application_revision!r} != "
            f"expected {expected_revision!r}."
        )
        reason_codes.append(MappingReasonCode.REGISTRY_REVISION_MISMATCH)

    seen_features: set[str] = set()
    for feat in registry.declared_features:
        if feat in seen_features:
            errors.append(f"Duplicate declared feature {feat!r}.")
            reason_codes.append(MappingReasonCode.INVALID_REGISTRY)
        seen_features.add(feat)

    seen_routes: set[str] = set()
    alias_owners: dict[str, str] = {}

    for entry in registry.routes:
        if entry.route in seen_routes:
            errors.append(f"Duplicate canonical route {entry.route!r}.")
            reason_codes.append(MappingReasonCode.INVALID_REGISTRY)
        seen_routes.add(entry.route)

        if not entry.component.strip():
            errors.append(f"Route {entry.route!r} is missing a component identifier.")
            reason_codes.append(MappingReasonCode.INVALID_REGISTRY)

        for alias in [*entry.route_aliases, *entry.route_variants]:
            if alias == entry.route:
                errors.append(f"Route {entry.route!r} lists itself as an alias or variant.")
                reason_codes.append(MappingReasonCode.INVALID_REGISTRY)
            elif alias in alias_owners and alias_owners[alias] != entry.route:
                errors.append(
                    f"Conflicting alias/variant {alias!r} claimed by both "
                    f"{alias_owners[alias]!r} and {entry.route!r}."
                )
                reason_codes.append(MappingReasonCode.INVALID_REGISTRY)
            else:
                alias_owners[alias] = entry.route

        for flag in entry.flags:
            if flag not in seen_features:
                errors.append(f"Route {entry.route!r} references undeclared feature {flag!r}.")
                reason_codes.append(MappingReasonCode.UNDECLARED_FEATURE)

        for dep in entry.shared_dependencies:
            if dep not in seen_features:
                errors.append(f"Route {entry.route!r} references undeclared dependency {dep!r}.")
                reason_codes.append(MappingReasonCode.UNDECLARED_FEATURE)

        seen_impls: set[str] = set()
        for binding in entry.implementation_bindings:
            if binding.implementation_id in seen_impls:
                errors.append(
                    f"Duplicate implementation binding {binding.implementation_id!r} "
                    f"on route {entry.route!r}."
                )
                reason_codes.append(MappingReasonCode.INVALID_REGISTRY)
            seen_impls.add(binding.implementation_id)
            if binding.flag_name not in seen_features:
                errors.append(
                    f"Implementation {binding.implementation_id!r} on {entry.route!r} "
                    f"references undeclared feature {binding.flag_name!r}."
                )
                reason_codes.append(MappingReasonCode.UNDECLARED_FEATURE)
            if entry.flags and binding.flag_name not in entry.flags:
                errors.append(
                    f"Implementation {binding.implementation_id!r} flag {binding.flag_name!r} "
                    f"is not listed in route {entry.route!r} flags."
                )
                reason_codes.append(MappingReasonCode.INVALID_REGISTRY)
            declared_role = entry.feature_roles.get(binding.flag_name)
            if (
                declared_role is not None
                and declared_role != FeatureRole.UNKNOWN
                and binding.role != FeatureRole.UNKNOWN
                and declared_role != binding.role
            ):
                errors.append(
                    f"Conflicting roles for flag {binding.flag_name!r} on {entry.route!r}: "
                    f"{declared_role.value} vs {binding.role.value}."
                )
                reason_codes.append(MappingReasonCode.INVALID_REGISTRY)

        if entry.coverage_status == CoverageStatus.PROTECTED and not entry.flags:
            warnings.append(
                f"Route {entry.route!r} is marked protected but declares no feature flags."
            )

    # Ensure aliases do not collide with another route's canonical path
    for alias, owner in alias_owners.items():
        if alias in seen_routes and alias != owner:
            errors.append(
                f"Alias {alias!r} on {owner!r} conflicts with canonical route {alias!r}."
            )
            reason_codes.append(MappingReasonCode.INVALID_REGISTRY)

    dedup_codes = sorted(set(reason_codes), key=lambda c: c.value)
    return RegistryValidationReport(
        valid=len(errors) == 0,
        registry_version=registry.registry_version,
        registry_fingerprint=fingerprint,
        environment=registry.environment,
        application_revision=registry.application_revision,
        reason_codes=dedup_codes,
        errors=errors,
        warnings=warnings,
    )


class IndexedRouteRegistry:
    """Immutable indexed lookup view over a validated ``RouteFlagRegistry``."""

    def __init__(self, registry: RouteFlagRegistry) -> None:
        self.registry = registry
        self.fingerprint = compute_registry_fingerprint(registry)
        self.declared_features: frozenset[str] = frozenset(registry.declared_features)
        self.by_route: dict[str, RouteFlagEntry] = {}
        self.by_alias: dict[str, RouteFlagEntry] = {}
        self.by_variant: dict[str, RouteFlagEntry] = {}
        self.by_component: dict[str, list[RouteFlagEntry]] = defaultdict(list)
        self.component_alias_to_canonical: dict[str, set[str]] = defaultdict(set)
        self.routes_by_flag: dict[str, list[str]] = defaultdict(list)

        for entry in sorted(registry.routes, key=lambda r: r.route):
            self.by_route[entry.route] = entry
            for alias in entry.route_aliases:
                self.by_alias[alias] = entry
            for variant in entry.route_variants:
                self.by_variant[variant] = entry
            self.by_component[entry.component].append(entry)
            for comp_alias in entry.component_aliases:
                self.component_alias_to_canonical[comp_alias].add(entry.component)
            for flag in sorted(set(entry.flags)):
                self.routes_by_flag[flag].append(entry.route)

    def routes_sharing_flag(self, flag_name: str) -> list[str]:
        """Return sorted canonical routes sharing ``flag_name``."""
        return sorted(set(self.routes_by_flag.get(flag_name, ())))
