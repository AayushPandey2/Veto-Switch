"""Unit tests verifying config/*.json fixture loading and dependency graph integrity."""

from __future__ import annotations

import pytest
from shared.config import (
    load_dependency_graph,
    load_rollout_policy,
    load_route_registry,
)
from shared.enums import CoverageStatus


@pytest.mark.unit
def test_configuration_fixtures_load_and_validate() -> None:
    """Scenarios 26 & 27: Route registry, dependency graph, and rollout policy load cleanly."""
    registry = load_route_registry()
    assert registry.registry_version == "1.0.0-demo"
    assert set(registry.declared_features) == {"search_v1", "search_v2", "files_v1"}
    routes_by_path = {entry.route: entry for entry in registry.routes}
    assert "/search" in routes_by_path
    assert "/files" in routes_by_path
    assert "/legacy-export" in routes_by_path
    assert routes_by_path["/legacy-export"].coverage_status == CoverageStatus.UNPROTECTED
    assert registry.is_fixture_assumption is True

    graph = load_dependency_graph()
    assert graph.is_fixture_assumption is True
    node_ids = {n.node_id for n in graph.nodes}
    assert "svc_billing_unrelated" in node_ids
    for edge in graph.edges:
        assert edge.source_id in node_ids
        assert edge.target_id in node_ids

    policy = load_rollout_policy()
    assert policy.stages_percent == [5, 25, 50, 100]
    assert policy.is_demo_default is True
    assert policy.require_human_approval is True
    assert policy.guardrails.max_error_rate == 0.02
