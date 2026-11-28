"""Phase 06 Feature Flag Coverage Auditing package."""

from agent_core.coverage.classification import (
    aggregate_sensitive_implementations,
    build_coverage_summary,
    project_coverage_findings,
)
from agent_core.coverage.control_flow import analyze_handler_paths
from agent_core.coverage.dashboard import (
    serialize_coverage_dashboard,
    serialize_flags_coverage_endpoint,
)
from agent_core.coverage.models import (
    CoverageAuditContext,
    CoverageAuditResult,
    CoverageAuditSummary,
    CoverageRecommendation,
    ExecutionPathAssessment,
    GuardCondition,
    ReconciliationDiscrepancy,
    RouteIdentity,
    RuntimeCorroborationSummary,
    SensitiveImplementation,
    SnapshotLimits,
    SourceFileEntry,
    SourceReference,
    SourceSnapshot,
)
from agent_core.coverage.recommendations import generate_coverage_recommendations
from agent_core.coverage.reconciliation import reconcile_coverage_sources
from agent_core.coverage.route_discovery import discover_routes_in_snapshot
from agent_core.coverage.runtime_evidence import corroborate_with_runtime_evidence
from agent_core.coverage.sensitive_paths import build_local_call_index
from agent_core.coverage.source_snapshot import (
    build_in_memory_snapshot,
    load_authorized_source_snapshot,
)

__all__ = [
    "CoverageAuditContext",
    "CoverageAuditResult",
    "CoverageAuditSummary",
    "CoverageRecommendation",
    "ExecutionPathAssessment",
    "GuardCondition",
    "ReconciliationDiscrepancy",
    "RouteIdentity",
    "RuntimeCorroborationSummary",
    "SensitiveImplementation",
    "SnapshotLimits",
    "SourceFileEntry",
    "SourceReference",
    "SourceSnapshot",
    "aggregate_sensitive_implementations",
    "analyze_handler_paths",
    "build_coverage_summary",
    "build_in_memory_snapshot",
    "build_local_call_index",
    "corroborate_with_runtime_evidence",
    "discover_routes_in_snapshot",
    "generate_coverage_recommendations",
    "load_authorized_source_snapshot",
    "project_coverage_findings",
    "reconcile_coverage_sources",
    "serialize_coverage_dashboard",
    "serialize_flags_coverage_endpoint",
]
