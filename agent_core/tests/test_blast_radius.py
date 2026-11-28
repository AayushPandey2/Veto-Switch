"""Tests for DependencyGraph validation, traversal, blast radius, and counterfactuals."""

from __future__ import annotations

from datetime import UTC, datetime

from agent_core.blast_radius import analyze_blast_radius
from agent_core.graph_intelligence.counterfactual import simulate_counterfactual
from agent_core.graph_intelligence.engine import DirectedMultiGraphIndex, validate_graph
from agent_core.graph_intelligence.serializer import serialize_blast_radius_dashboard
from shared.config import load_dependency_graph, load_route_registry
from shared.enums import (
    ContainmentStrategyType,
    EvidenceProvenance,
    FeatureObservationStatus,
    FindingStatus,
    GraphEdgeType,
    GraphNodeType,
    MappingStatus,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.schemas import (
    DependencyGraph,
    FeatureState,
    Finding,
    GraphEdge,
    GraphNode,
    MappingResult,
)

NOW = datetime(2026, 11, 27, 0, 0, 0, tzinfo=UTC)


def _search_finding() -> Finding:
    return Finding(
        finding_id="fnd_br_01",
        incident_id="inc_br_01",
        category=VulnerabilityCategory.SQL_INJECTION,
        affected_route="/search",
        affected_component="search_service",
        severity=VulnerabilitySeverity.HIGH,
        status=FindingStatus.REPRODUCED,
        evidence_ids=["art_br_01"],
        environment="demo-staging",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )


def _search_mapping() -> MappingResult:
    return MappingResult(
        finding_id="fnd_br_01",
        mapping_status=MappingStatus.MATCHED,
        affected_route="/search",
        matched_component="search_service",
        candidate_flags=["search_v1", "search_v2"],
        selected_flag="search_v1",
        registry_version="1.0.0-demo",
        mapping_rationale="Verified search_v1.",
        evidence_ids=["art_br_01"],
        manual_review_required=False,
    )


def test_graph_validation_cycles_and_multi_edges() -> None:
    graph = load_dependency_graph()
    reg = load_route_registry()
    rep = validate_graph(graph, registry=reg, expected_environment="demo-staging")
    assert rep.valid is True

    # Environment mismatch rejected
    rep_env = validate_graph(graph, expected_environment="production")
    assert rep_env.valid is False

    # Cyclic graph terminates safely in BFS
    cyclic = DependencyGraph(
        graph_version="1.0.0-test",
        environment="demo-staging",
        nodes=[
            GraphNode(node_id="svc_a", node_type=GraphNodeType.SERVICE, label="A"),
            GraphNode(node_id="svc_b", node_type=GraphNodeType.SERVICE, label="B"),
        ],
        edges=[
            GraphEdge(source_id="svc_a", target_id="svc_b", relationship=GraphEdgeType.CALLS),
            GraphEdge(source_id="svc_b", target_id="svc_a", relationship=GraphEdgeType.CALLS),
            GraphEdge(source_id="svc_a", target_id="svc_b", relationship=GraphEdgeType.DEPENDS_ON),
        ],
    )
    idx = DirectedMultiGraphIndex(cyclic)
    assert len(idx.outgoing["svc_a"]) == 2
    assert idx.bfs_outgoing(["svc_a"], allowed_relationships=frozenset({GraphEdgeType.CALLS})) == [
        "svc_a",
        "svc_b",
    ]


def test_blast_radius_distinguishes_exposure_disruption_and_aliases() -> None:
    graph = load_dependency_graph()
    reg = load_route_registry()
    finding = _search_finding()
    mapping = _search_mapping()

    br = analyze_blast_radius(finding, mapping, graph, registry=reg)
    assert br.graph_valid is True
    assert "route_search" in br.affected_route_nodes
    assert "svc_search" in br.affected_implementation_nodes
    assert "db_primary" in br.shared_resources
    # Unrelated services & files route are preserved, NOT disrupted
    assert "svc_billing_unrelated" in br.unrelated_nodes
    assert "route_files" in br.unrelated_nodes
    # Security entry points include declared aliases & variants
    assert "/search" in br.known_security_entry_points
    assert "/legacy/search" in br.known_security_entry_points
    assert "/search/" in br.known_security_entry_points

    dash = serialize_blast_radius_dashboard(br, graph)
    assert "nodes" in dash and "edges" in dash
    assert "svc_billing_unrelated" in dash["preserved_nodes"]


def test_counterfactual_does_not_mutate_inputs() -> None:
    graph = load_dependency_graph()
    reg = load_route_registry()
    br = analyze_blast_radius(_search_finding(), _search_mapping(), graph, registry=reg)
    fs = FeatureState(
        environment="demo-staging",
        feature_id="fs_search_v1",
        feature_name="search_v1",
        observation_status=FeatureObservationStatus.OBSERVED,
        enabled=True,
        observed_at=NOW,
        observation_source=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    cf = simulate_counterfactual(
        strategy_id="strat_disable",
        strategy_type=ContainmentStrategyType.DISABLE_FEATURE_FLAG,
        target_flag="search_v1",
        desired_enabled=False,
        blast_radius=br,
        observed_features=[fs],
        registry=reg,
    )
    assert fs.enabled is True
    assert cf.state_before["search_v1"] is True
    assert cf.hypothetical_state_after["search_v1"] is False
    assert cf.qualifier == "requires_verification"
