"""Reconciliation across static source routes, RouteFlagRegistry, DependencyGraph, and manifest."""

from __future__ import annotations

from shared.enums import CoverageApplicability
from shared.schemas import DependencyGraph, RouteFlagRegistry

from agent_core.coverage.models import ExecutionPathAssessment, ReconciliationDiscrepancy


def reconcile_coverage_sources(
    *,
    assessments: list[ExecutionPathAssessment],
    source_revision: str,
    registry: RouteFlagRegistry | None,
    dependency_graph: DependencyGraph | None,
    manifest_routes: list[str],
) -> list[ReconciliationDiscrepancy]:
    """Compare discovered source routes/flags against registry, graph, and manifest."""
    discrepancies: list[ReconciliationDiscrepancy] = []
    discovered_paths = {a.route_identity.route for a in assessments}

    if registry is not None:
        if registry.application_revision and registry.application_revision != source_revision:
            discrepancies.append(
                ReconciliationDiscrepancy(
                    discrepancy_type="revision_mismatch",
                    details=(
                        f"Registry application_revision ({registry.application_revision}) "
                        f"differs from audited source_revision ({source_revision})."
                    ),
                )
            )

        reg_routes = {entry.route: entry for entry in registry.routes}
        declared_flags = set(registry.declared_features)

        for assessment in assessments:
            route = assessment.route_identity.route
            if assessment.applicability == CoverageApplicability.EXEMPT:
                continue
            if route not in reg_routes and not assessment.route_identity.is_dynamic:
                discrepancies.append(
                    ReconciliationDiscrepancy(
                        discrepancy_type="source_route_missing_from_registry",
                        route=route,
                        method=assessment.route_identity.method,
                        details=(
                            f"Route {route} discovered in source is absent "
                            "from RouteFlagRegistry."
                        ),
                        proposed_registry_update={
                            "action": "review_add_route",
                            "route": route,
                            "observed_flags": assessment.observed_flags,
                        },
                    )
                )
            for flag in assessment.observed_flags:
                if flag not in declared_flags:
                    discrepancies.append(
                        ReconciliationDiscrepancy(
                            discrepancy_type="undeclared_flag",
                            route=route,
                            flag_name=flag,
                            details=(
                                f"Flag {flag!r} used in source route {route} "
                                "is not declared in registry."
                            ),
                            proposed_registry_update={
                                "action": "review_declare_feature",
                                "flag_name": flag,
                            },
                        )
                    )

        for reg_route in reg_routes:
            if reg_route not in discovered_paths:
                discrepancies.append(
                    ReconciliationDiscrepancy(
                        discrepancy_type="registry_route_missing_from_source",
                        route=reg_route,
                        details=(
                            f"Registry route {reg_route} was not discovered "
                            "in the audited source snapshot."
                        ),
                    )
                )

    for manifest_route in manifest_routes:
        if manifest_route not in discovered_paths:
            discrepancies.append(
                ReconciliationDiscrepancy(
                    discrepancy_type="manifest_mismatch",
                    route=manifest_route,
                    details=(
                        f"Manifest route {manifest_route} not found in audited source snapshot."
                    ),
                )
            )

    if dependency_graph is not None:
        graph_routes: set[str] = {
            path_val
            for n in dependency_graph.nodes
            if n.node_type == "route"
            and isinstance((path_val := n.metadata.get("path")), str)
        }
        for gr in sorted(graph_routes):
            if gr and gr not in discovered_paths:
                discrepancies.append(
                    ReconciliationDiscrepancy(
                        discrepancy_type="graph_edge_conflict",
                        route=gr,
                        details=(
                            f"Dependency graph route node {gr} is absent "
                            "from audited source snapshot."
                        ),
                    )
                )

    return discrepancies
