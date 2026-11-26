"""Dashboard-compatible JSON serializer for BlastRadiusResult and DependencyGraph."""

from __future__ import annotations

from typing import Any

from shared.enums import GraphNodeType
from shared.schemas import DependencyGraph

from agent_core.graph_intelligence.models import BlastRadiusResult


def _node_display_category(node_id: str, node_type: GraphNodeType, br: BlastRadiusResult) -> str:
    if node_id in br.root_vulnerable_nodes:
        return "vulnerable"
    if node_id in br.affected_route_nodes or node_id in br.affected_implementation_nodes:
        return "affected"
    if node_id in br.potential_replacements:
        return "replacement"
    if node_id in br.shared_resources or node_type in {
        GraphNodeType.DATABASE,
        GraphNodeType.STORAGE,
    }:
        return "shared_dependency"
    if node_id in br.unrelated_nodes:
        return "preserved"
    return "unknown"


def serialize_blast_radius_dashboard(
    result: BlastRadiusResult,
    graph: DependencyGraph,
) -> dict[str, Any]:
    """Serialize graph topology and blast-radius classifications for dashboard rendering."""
    nodes_payload = [
        {
            "node_id": n.node_id,
            "node_type": n.node_type.value,
            "label": n.label,
            "display_category": _node_display_category(n.node_id, n.node_type, result),
        }
        for n in sorted(graph.nodes, key=lambda node: node.node_id)
    ]
    edges_payload = [
        {
            "source_id": e.source_id,
            "target_id": e.target_id,
            "relationship": e.relationship.value,
        }
        for e in sorted(
            graph.edges,
            key=lambda edge: (edge.source_id, edge.target_id, edge.relationship.value),
        )
    ]
    return {
        "graph_version": result.graph_version,
        "graph_fingerprint": result.graph_fingerprint,
        "environment": result.environment,
        "is_fixture_only": result.is_fixture_only,
        "nodes": nodes_payload,
        "edges": edges_payload,
        "root_vulnerable_nodes": list(result.root_vulnerable_nodes),
        "affected_nodes": sorted(
            set(result.affected_route_nodes) | set(result.affected_implementation_nodes)
        ),
        "protected_nodes": list(result.preserved_capabilities),
        "preserved_nodes": list(result.unrelated_nodes),
        "unaffected_nodes": list(result.unrelated_nodes),
        "potentially_exposed_nodes": list(result.potentially_exposed_resources),
        "selected_feature_nodes": list(result.feature_control_nodes),
        "replacement_nodes": list(result.potential_replacements),
        "unknown_nodes": list(result.missing_relationships),
        "known_security_entry_points": list(result.known_security_entry_points),
        "affected_capabilities": list(result.affected_capabilities),
        "preserved_capabilities": list(result.preserved_capabilities),
        "assumptions": list(result.assumptions),
        "uncertainties": list(result.uncertainties),
        "limitations": list(result.limitations),
    }
