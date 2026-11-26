"""Blast Radius Intelligence Engine analyzing vulnerability exposure vs containment impact."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime

from shared.enums import (
    GraphEdgeType,
    GraphNodeType,
)
from shared.schemas import (
    DependencyGraph,
    DeploymentEvidence,
    FeatureState,
    Finding,
    MappingResult,
    RouteFlagRegistry,
    VerificationResult,
)

from agent_core.graph_intelligence.engine import DirectedMultiGraphIndex, validate_graph
from agent_core.graph_intelligence.models import BlastRadiusResult


def analyze_blast_radius(
    finding: Finding,
    mapping: MappingResult,
    graph: DependencyGraph,
    *,
    registry: RouteFlagRegistry | None = None,
    observed_features: Sequence[FeatureState] = (),
    deployment_evidence: Sequence[DeploymentEvidence] = (),
    verification_results: Sequence[VerificationResult] = (),
    application_revision: str | None = None,
    environment: str | None = None,
    fixture_mode: bool = True,
    evaluation_timestamp: datetime | None = None,
) -> BlastRadiusResult:
    """Analyze vulnerability blast radius, containment disruption, and preserved capabilities."""
    _ = observed_features, deployment_evidence, verification_results, evaluation_timestamp
    target_env = environment or finding.environment or graph.environment
    report = validate_graph(graph, registry=registry, expected_environment=target_env)
    index = DirectedMultiGraphIndex(graph)

    is_fixture = fixture_mode or graph.is_fixture_assumption or (
        registry.is_fixture_assumption if registry is not None else False
    )
    provenance = sorted(
        {finding.provenance, graph.provenance}
        | ({registry.provenance} if registry is not None else set()),
        key=lambda p: p.value,
    )

    if not report.valid:
        return BlastRadiusResult(
            graph_valid=False,
            graph_version=graph.graph_version,
            graph_fingerprint=report.graph_fingerprint,
            environment=graph.environment,
            application_revision=application_revision or finding.repository_revision,
            evidence_ids=list(mapping.evidence_ids or finding.evidence_ids),
            limitations=list(report.errors),
            reason_codes=list(report.reason_codes),
            is_fixture_only=is_fixture,
            provenance=provenance,
        )

    # Identify root vulnerable nodes from mapping route, component, and selected flag
    root_nodes: set[str] = set()
    target_route = mapping.affected_route or finding.affected_route
    if target_route and target_route in index.by_route_path:
        root_nodes.add(index.by_route_path[target_route].node_id)

    target_comp = mapping.matched_component or finding.affected_component
    for n in index.by_component.get(target_comp, ()):
        root_nodes.add(n.node_id)

    feature_control_nodes: list[str] = []
    if mapping.selected_flag:
        for fn in index.by_flag_key.get(mapping.selected_flag, ()):
            feature_control_nodes.append(fn.node_id)
            # Also include nodes controlled_by this flag
            for edge in index.incoming.get(fn.node_id, ()):
                if edge.relationship == GraphEdgeType.CONTROLLED_BY:
                    root_nodes.add(edge.source_id)

    # 1. Affected routes & services via CALLS / DEPENDS_ON (excluding databases/storage)
    reachable_exec = index.bfs_outgoing(
        sorted(root_nodes),
        allowed_relationships=frozenset({GraphEdgeType.CALLS, GraphEdgeType.DEPENDS_ON}),
    )
    affected_routes: set[str] = set()
    affected_services: set[str] = set()
    for nid in reachable_exec:
        node = index.nodes[nid]
        if node.node_type == GraphNodeType.ROUTE:
            affected_routes.add(nid)
        elif node.node_type == GraphNodeType.SERVICE:
            affected_services.add(nid)

    # 2. Upstream dependents (excluding generic top-level application container from disruption)
    upstream = [
        nid
        for nid in index.bfs_incoming(
            sorted(affected_routes | affected_services),
            allowed_relationships=frozenset({GraphEdgeType.CALLS, GraphEdgeType.DEPENDS_ON}),
        )
        if nid not in affected_routes
        and nid not in affected_services
        and index.nodes[nid].node_type != GraphNodeType.APPLICATION
    ]

    # 3. Downstream accessed resources (databases, storage) — exposed, NOT necessarily disrupted
    accessed = index.bfs_outgoing(
        sorted(affected_services),
        allowed_relationships=frozenset({GraphEdgeType.ACCESSES}),
    )
    shared_resources = sorted(
        nid
        for nid in accessed
        if index.nodes[nid].node_type in {GraphNodeType.DATABASE, GraphNodeType.STORAGE}
    )

    # 4. Potential replacements via REPLACED_BY
    replacements = sorted(
        nid
        for nid in index.bfs_outgoing(
            sorted(affected_routes | affected_services),
            allowed_relationships=frozenset({GraphEdgeType.REPLACED_BY}),
            max_depth=2,
        )
        if index.nodes[nid].node_type == GraphNodeType.REPLACEMENT_IMPLEMENTATION
    )

    # 5. Unrelated nodes & preserved capabilities
    impacted_all = (
        set(affected_routes)
        | set(affected_services)
        | set(feature_control_nodes)
        | set(shared_resources)
        | set(replacements)
    )
    unrelated_nodes = sorted(
        nid
        for nid, node in index.nodes.items()
        if nid not in impacted_all and node.node_type != GraphNodeType.APPLICATION
    )

    affected_capabilities = sorted(
        {
            str(index.nodes[nid].metadata.get("component") or index.nodes[nid].label)
            for nid in affected_services
        }
    )
    preserved_capabilities = sorted(
        {
            str(
                index.nodes[nid].metadata.get("component")
                or index.nodes[nid].metadata.get("path")
                or index.nodes[nid].label
            )
            for nid in unrelated_nodes
            if index.nodes[nid].node_type in {GraphNodeType.ROUTE, GraphNodeType.SERVICE}
        }
    )

    # 6. Known security entry points (include declared aliases/variants from registry)
    entry_points: set[str] = set()
    for nid in affected_routes:
        path = index.nodes[nid].metadata.get("path")
        if isinstance(path, str):
            entry_points.add(path)
    if registry is not None:
        for entry in registry.routes:
            if entry.route == target_route or (
                mapping.selected_flag and mapping.selected_flag in entry.flags
            ):
                entry_points.add(entry.route)
                entry_points.update(entry.route_aliases)
                entry_points.update(entry.route_variants)

    missing_relationships: list[str] = []
    if not root_nodes:
        missing_relationships.append("no_matching_root_node_in_graph")
    if mapping.selected_flag and not feature_control_nodes:
        missing_relationships.append(f"missing_feature_node:{mapping.selected_flag}")

    assumptions = [
        "Declared graph edges represent static topology; runtime verification is still required."
    ]
    if is_fixture:
        assumptions.append("Graph and/or registry carry reference_fixture provenance.")

    uncertainties: list[str] = []
    if replacements:
        uncertainties.append(
            f"Replacement candidates {replacements} require deployment and security verification."
        )
    if missing_relationships:
        uncertainties.append(f"Incomplete graph relationships: {missing_relationships}.")

    return BlastRadiusResult(
        graph_valid=True,
        graph_version=graph.graph_version,
        graph_fingerprint=report.graph_fingerprint,
        environment=graph.environment,
        application_revision=application_revision or finding.repository_revision,
        root_vulnerable_nodes=sorted(root_nodes),
        affected_implementation_nodes=sorted(affected_services),
        affected_route_nodes=sorted(affected_routes),
        feature_control_nodes=sorted(set(feature_control_nodes)),
        upstream_dependents=upstream,
        downstream_dependencies=sorted(
            set(affected_services) | set(shared_resources)
        ),
        shared_resources=shared_resources,
        potentially_exposed_resources=shared_resources,
        unrelated_nodes=unrelated_nodes,
        potential_replacements=replacements,
        known_security_entry_points=sorted(entry_points),
        affected_capabilities=affected_capabilities,
        preserved_capabilities=preserved_capabilities,
        missing_relationships=missing_relationships,
        evidence_ids=list(mapping.evidence_ids or finding.evidence_ids),
        assumptions=assumptions,
        uncertainties=uncertainties,
        limitations=list(report.warnings),
        reason_codes=[],
        is_fixture_only=is_fixture,
        provenance=provenance,
    )
