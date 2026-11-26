"""Directed multigraph indexing, validation, and relationship-specific traversal."""

from __future__ import annotations

from collections import defaultdict, deque

from shared.enums import ContainmentReasonCode, GraphEdgeType, GraphNodeType
from shared.schemas import DependencyGraph, GraphEdge, GraphNode, RouteFlagRegistry
from shared.serialization import canonical_json, sha256_text

from agent_core.graph_intelligence.models import GraphValidationReport

_ALLOWED_EDGE_ENDPOINTS: dict[
    GraphEdgeType, tuple[frozenset[GraphNodeType], frozenset[GraphNodeType]]
] = {
    GraphEdgeType.CALLS: (
        frozenset({GraphNodeType.APPLICATION, GraphNodeType.ROUTE, GraphNodeType.SERVICE}),
        frozenset({GraphNodeType.ROUTE, GraphNodeType.SERVICE}),
    ),
    GraphEdgeType.DEPENDS_ON: (
        frozenset({GraphNodeType.APPLICATION, GraphNodeType.ROUTE, GraphNodeType.SERVICE}),
        frozenset(
            {
                GraphNodeType.ROUTE,
                GraphNodeType.SERVICE,
                GraphNodeType.DATABASE,
                GraphNodeType.STORAGE,
            }
        ),
    ),
    GraphEdgeType.CONTROLLED_BY: (
        frozenset(
            {GraphNodeType.ROUTE, GraphNodeType.SERVICE, GraphNodeType.REPLACEMENT_IMPLEMENTATION}
        ),
        frozenset({GraphNodeType.FEATURE_FLAG}),
    ),
    GraphEdgeType.ACCESSES: (
        frozenset({GraphNodeType.SERVICE, GraphNodeType.REPLACEMENT_IMPLEMENTATION}),
        frozenset({GraphNodeType.DATABASE, GraphNodeType.STORAGE}),
    ),
    GraphEdgeType.REPLACED_BY: (
        frozenset({GraphNodeType.SERVICE, GraphNodeType.ROUTE}),
        frozenset({GraphNodeType.REPLACEMENT_IMPLEMENTATION}),
    ),
}


def compute_graph_fingerprint(graph: DependencyGraph) -> str:
    """Compute a deterministic SHA-256 fingerprint over normalized graph nodes and edges."""
    payload = {
        "graph_version": graph.graph_version,
        "environment": graph.environment,
        "nodes": [
            {
                "node_id": n.node_id,
                "node_type": n.node_type.value,
                "label": n.label,
            }
            for n in sorted(graph.nodes, key=lambda node: node.node_id)
        ],
        "edges": [
            {
                "source_id": e.source_id,
                "target_id": e.target_id,
                "relationship": e.relationship.value,
            }
            for e in sorted(
                graph.edges,
                key=lambda edge: (edge.source_id, edge.target_id, edge.relationship.value),
            )
        ],
    }
    return sha256_text(canonical_json(payload))


class DirectedMultiGraphIndex:
    """O(V + E) adjacency index preserving multiple relationship types per node pair."""

    def __init__(self, graph: DependencyGraph) -> None:
        self.graph = graph
        self.fingerprint = compute_graph_fingerprint(graph)
        self.nodes: dict[str, GraphNode] = {n.node_id: n for n in graph.nodes}
        self.outgoing: dict[str, list[GraphEdge]] = defaultdict(list)
        self.incoming: dict[str, list[GraphEdge]] = defaultdict(list)
        self.by_route_path: dict[str, GraphNode] = {}
        self.by_component: dict[str, list[GraphNode]] = defaultdict(list)
        self.by_flag_key: dict[str, list[GraphNode]] = defaultdict(list)

        for node in sorted(graph.nodes, key=lambda n: n.node_id):
            path = node.metadata.get("path")
            if isinstance(path, str) and path:
                self.by_route_path[path] = node
            comp = node.metadata.get("component")
            if isinstance(comp, str) and comp:
                self.by_component[comp].append(node)
            flag_key = node.metadata.get("flag_key")
            if isinstance(flag_key, str) and flag_key:
                self.by_flag_key[flag_key].append(node)

        for edge in sorted(
            graph.edges,
            key=lambda e: (e.source_id, e.target_id, e.relationship.value),
        ):
            self.outgoing[edge.source_id].append(edge)
            self.incoming[edge.target_id].append(edge)

    def bfs_outgoing(
        self,
        start_ids: list[str],
        *,
        allowed_relationships: frozenset[GraphEdgeType],
        max_depth: int = 16,
    ) -> list[str]:
        """Bounded O(V + E) BFS following only ``allowed_relationships``."""
        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque((nid, 0) for nid in start_ids if nid in self.nodes)
        result: list[str] = []
        while queue:
            current, depth = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            result.append(current)
            if depth >= max_depth:
                continue
            for edge in self.outgoing.get(current, ()):
                if edge.relationship in allowed_relationships and edge.target_id not in visited:
                    queue.append((edge.target_id, depth + 1))
        return sorted(result)

    def bfs_incoming(
        self,
        start_ids: list[str],
        *,
        allowed_relationships: frozenset[GraphEdgeType],
        max_depth: int = 16,
    ) -> list[str]:
        """Bounded O(V + E) reverse BFS following only ``allowed_relationships``."""
        visited: set[str] = set()
        queue: deque[tuple[str, int]] = deque((nid, 0) for nid in start_ids if nid in self.nodes)
        result: list[str] = []
        while queue:
            current, depth = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            result.append(current)
            if depth >= max_depth:
                continue
            for edge in self.incoming.get(current, ()):
                if edge.relationship in allowed_relationships and edge.source_id not in visited:
                    queue.append((edge.source_id, depth + 1))
        return sorted(result)


def validate_graph(
    graph: DependencyGraph,
    *,
    registry: RouteFlagRegistry | None = None,
    expected_environment: str | None = None,
    max_nodes: int = 500,
) -> GraphValidationReport:
    """Validate graph integrity, size bounds, endpoint semantics, and registry consistency."""
    fingerprint = compute_graph_fingerprint(graph)
    errors: list[str] = []
    warnings: list[str] = []
    reason_codes: list[ContainmentReasonCode] = []

    if len(graph.nodes) > max_nodes:
        errors.append(f"Graph node count {len(graph.nodes)} exceeds bound {max_nodes}.")
        reason_codes.append(ContainmentReasonCode.INVALID_GRAPH)

    if expected_environment and graph.environment != expected_environment:
        errors.append(
            f"Graph environment {graph.environment!r} != expected {expected_environment!r}."
        )
        reason_codes.append(ContainmentReasonCode.GRAPH_ENVIRONMENT_MISMATCH)

    nodes_by_id: dict[str, GraphNode] = {}
    for node in graph.nodes:
        if node.node_id in nodes_by_id:
            errors.append(f"Duplicate node_id {node.node_id!r}.")
            reason_codes.append(ContainmentReasonCode.INVALID_GRAPH)
        nodes_by_id[node.node_id] = node

    for edge in graph.edges:
        src = nodes_by_id.get(edge.source_id)
        dst = nodes_by_id.get(edge.target_id)
        if src is None or dst is None:
            errors.append(
                f"Edge {edge.source_id!r} -> {edge.target_id!r} references missing node."
            )
            reason_codes.append(ContainmentReasonCode.INVALID_GRAPH)
            continue
        allowed = _ALLOWED_EDGE_ENDPOINTS.get(edge.relationship)
        if allowed is not None:
            allowed_src, allowed_dst = allowed
            if src.node_type not in allowed_src or dst.node_type not in allowed_dst:
                errors.append(
                    f"Invalid endpoint types for {edge.relationship.value}: "
                    f"{src.node_type.value} -> {dst.node_type.value}."
                )
                reason_codes.append(ContainmentReasonCode.INVALID_GRAPH)

    if registry is not None:
        if registry.environment != graph.environment:
            errors.append(
                f"Registry environment {registry.environment!r} != "
                f"graph environment {graph.environment!r}."
            )
            reason_codes.append(ContainmentReasonCode.GRAPH_ENVIRONMENT_MISMATCH)
        declared = set(registry.declared_features)
        for node in graph.nodes:
            if node.node_type == GraphNodeType.FEATURE_FLAG:
                fk = node.metadata.get("flag_key") or node.label
                if fk not in declared:
                    warnings.append(
                        f"Graph feature node {node.node_id!r} ({fk!r}) is not in registry."
                    )

    return GraphValidationReport(
        valid=len(errors) == 0,
        graph_version=graph.graph_version,
        graph_fingerprint=fingerprint,
        environment=graph.environment,
        errors=errors,
        warnings=warnings,
        reason_codes=sorted(set(reason_codes), key=lambda c: c.value),
    )
