"""Phase 06 Flag Coverage Auditor — deterministic static control-flow & guard auditor.

Public entry point ``DeterministicFlagCoverageAuditor`` and convenience helper
``audit_flag_coverage(...)``. Read-only: zero LLM calls required for authoritative
decisions, never mutates feature flags, never executes analyzed source code.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol, runtime_checkable

from shared.enums import (
    CoverageReasonCode,
    CoverageStatus,
    EvidenceProvenance,
)
from shared.schemas import (
    DependencyGraph,
    FeatureState,
    RouteFlagRegistry,
    VerificationResult,
)
from shared.serialization import canonical_json, sha256_text

from agent_core.context import Clock, SystemClock
from agent_core.coverage.classification import (
    aggregate_sensitive_implementations,
    build_coverage_summary,
    project_coverage_findings,
)
from agent_core.coverage.control_flow import analyze_handler_paths
from agent_core.coverage.models import (
    CoverageAuditContext,
    CoverageAuditResult,
    SourceSnapshot,
)
from agent_core.coverage.recommendations import generate_coverage_recommendations
from agent_core.coverage.reconciliation import reconcile_coverage_sources
from agent_core.coverage.route_discovery import discover_routes_in_snapshot
from agent_core.coverage.runtime_evidence import corroborate_with_runtime_evidence
from agent_core.coverage.sensitive_paths import build_local_call_index


@runtime_checkable
class FlagCoverageAuditor(Protocol):
    """Read-only Phase 06 protocol for auditing feature-flag guard coverage."""

    async def audit(self, context: CoverageAuditContext) -> CoverageAuditResult: ...


class DeterministicFlagCoverageAuditor(FlagCoverageAuditor):
    """Deterministic AST-based feature-flag coverage auditor."""

    def __init__(
        self,
        *,
        clock: Clock | None = None,
        policy_version: str = "1.0.0-coverage",
    ) -> None:
        self._clock: Clock = clock or SystemClock()
        self._policy_version = policy_version

    async def audit(self, context: CoverageAuditContext) -> CoverageAuditResult:
        """Run bounded static route/guard analysis, reconciliation, and runtime corroboration."""
        snapshot = context.snapshot
        handlers, discovery_diags = discover_routes_in_snapshot(snapshot)
        call_index = build_local_call_index(snapshot)

        raw_assessments = [
            analyze_handler_paths(
                handler,
                call_index,
                max_call_depth=snapshot.limits.max_call_depth,
            )
            for handler in handlers
        ]

        if not snapshot.is_complete:
            # Mark any PROTECTED claims on an incomplete snapshot as UNKNOWN unless corroborated,
            # while preserving concrete UNPROTECTED bypasses already proven by present files.
            adjusted = []
            for a in raw_assessments:
                if a.status == CoverageStatus.PROTECTED:
                    adjusted.append(
                        a.model_copy(
                            update={
                                "status": CoverageStatus.UNKNOWN,
                                "reason_codes": list(
                                    dict.fromkeys(
                                        [
                                            *a.reason_codes,
                                            CoverageReasonCode.SOURCE_SNAPSHOT_INCOMPLETE,
                                        ]
                                    )
                                ),
                                "notes": [
                                    *a.notes,
                                    (
                                        "Source snapshot is incomplete; "
                                        "cannot prove all paths guarded."
                                    ),
                                ],
                            }
                        )
                    )
                else:
                    adjusted.append(a)
            raw_assessments = adjusted

        implementations, assessments = aggregate_sensitive_implementations(raw_assessments)

        discrepancies = reconcile_coverage_sources(
            assessments=assessments,
            source_revision=snapshot.source_revision,
            registry=context.registry,
            dependency_graph=context.dependency_graph,
            manifest_routes=context.manifest_routes,
        )

        runtime_summary = corroborate_with_runtime_evidence(
            assessments=assessments,
            observed_features=context.observed_features,
            verification_results=context.verification_results,
            environment=context.environment,
            is_fixture=context.is_fixture,
        )

        inventory_complete = snapshot.is_complete and not any(
            d == "dynamic_route_path_unresolved" or d.startswith("dynamic_route_path_unresolved")
            for d in discovery_diags
        )
        summary = build_coverage_summary(assessments, inventory_complete=inventory_complete)
        findings = project_coverage_findings(
            assessments,
            implementations=implementations,
            runtime_corroboration=runtime_summary,
        )
        recommendations = generate_coverage_recommendations(assessments)

        all_reasons: list[CoverageReasonCode] = []
        for a in assessments:
            all_reasons.extend(a.reason_codes)
        if not snapshot.is_complete:
            all_reasons.append(CoverageReasonCode.SOURCE_SNAPSHOT_INCOMPLETE)
        if runtime_summary.contradicted:
            all_reasons.append(CoverageReasonCode.RUNTIME_OBSERVATION_CONTRADICTS_STATIC)
        elif runtime_summary.missing_runtime_evidence:
            all_reasons.append(CoverageReasonCode.RUNTIME_OBSERVATION_MISSING)
        for disc in discrepancies:
            if disc.discrepancy_type in {
                "source_route_missing_from_registry",
                "registry_route_missing_from_source",
            }:
                all_reasons.append(CoverageReasonCode.REGISTRY_ROUTE_MISMATCH)
            elif disc.discrepancy_type == "undeclared_flag":
                all_reasons.append(CoverageReasonCode.REGISTRY_FLAG_MISMATCH)
            elif disc.discrepancy_type == "revision_mismatch":
                all_reasons.append(CoverageReasonCode.REVISION_MISMATCH)

        limitations = list(
            dict.fromkeys(
                [
                    *snapshot.diagnostics,
                    *discovery_diags,
                    *runtime_summary.notes,
                    *runtime_summary.contradiction_details,
                ]
            )
        )
        if not limitations:
            limitations.append(
                "Bounded AST static analysis; dynamic routing/reflection outside "
                "supported subset is not evaluated."
            )

        reg_fp = (
            sha256_text(canonical_json(context.registry.model_dump(mode="json")))
            if context.registry is not None
            else None
        )
        audit_id = "cov_audit_" + sha256_text(
            canonical_json(
                {
                    "app": context.application_id,
                    "env": context.environment,
                    "rev": snapshot.source_revision,
                    "tree_fp": snapshot.source_tree_fingerprint,
                    "reg_fp": reg_fp,
                }
            )
        )[:16]

        provenance = (
            EvidenceProvenance.REFERENCE_FIXTURE
            if context.is_fixture
            else EvidenceProvenance.DETERMINISTIC_REASONING
        )

        return CoverageAuditResult(
            audit_id=audit_id,
            application_id=context.application_id,
            environment=context.environment,
            source_revision=snapshot.source_revision,
            revision_namespace=snapshot.revision_namespace,
            source_tree_fingerprint=snapshot.source_tree_fingerprint,
            registry_version=context.registry.registry_version if context.registry else None,
            registry_fingerprint=reg_fp,
            graph_version=(
                context.dependency_graph.graph_version if context.dependency_graph else None
            ),
            policy_version=self._policy_version,
            observed_at=self._clock.now(),
            provenance=provenance,
            evidence_support=runtime_summary.evidence_support,
            is_fixture=context.is_fixture,
            summary=summary,
            findings=findings,
            route_assessments=assessments,
            sensitive_implementations=implementations,
            discrepancies=discrepancies,
            recommendations=recommendations,
            runtime_corroboration=runtime_summary,
            reason_codes=list(dict.fromkeys(all_reasons)),
            limitations=limitations,
        )


async def audit_flag_coverage(
    snapshot: SourceSnapshot,
    registry: RouteFlagRegistry | None = None,
    graph: DependencyGraph | None = None,
    observations: Sequence[FeatureState] | None = None,
    *,
    verification_results: Sequence[VerificationResult] = (),
    manifest_routes: Sequence[str] = (),
    is_fixture: bool = False,
) -> CoverageAuditResult:
    """Convenience async entry point for running a deterministic coverage audit."""
    auditor = DeterministicFlagCoverageAuditor()
    ctx = CoverageAuditContext(
        application_id=snapshot.application_id,
        environment=snapshot.environment,
        snapshot=snapshot,
        registry=registry,
        dependency_graph=graph,
        manifest_routes=list(manifest_routes),
        observed_features=list(observations or ()),
        verification_results=list(verification_results),
        is_fixture=is_fixture,
    )
    return await auditor.audit(ctx)
