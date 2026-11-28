"""Deterministic coverage aggregation, classification precedence, and Finding projection."""

from __future__ import annotations

from collections import defaultdict

from shared.enums import (
    CoverageApplicability,
    CoverageReasonCode,
    CoverageStatus,
)
from shared.schemas import CoverageFinding
from shared.serialization import sha256_text

from agent_core.coverage.models import (
    CoverageAuditSummary,
    ExecutionPathAssessment,
    RuntimeCorroborationSummary,
    SensitiveImplementation,
)


def aggregate_sensitive_implementations(
    assessments: list[ExecutionPathAssessment],
) -> tuple[list[SensitiveImplementation], list[ExecutionPathAssessment]]:
    """Group path assessments by sensitive implementation and propagate alternate-path bypasses."""
    by_impl: dict[str, list[ExecutionPathAssessment]] = defaultdict(list)
    for item in assessments:
        impl_id = item.route_identity.implementation_id
        if impl_id and item.applicability == CoverageApplicability.APPLICABLE:
            by_impl[impl_id].append(item)

    implementations: list[SensitiveImplementation] = []
    updated_assessments: list[ExecutionPathAssessment] = []
    bypass_notes: dict[str, list[str]] = {}

    for impl_id, group in sorted(by_impl.items()):
        guarded_paths = [p for p in group if p.status == CoverageStatus.PROTECTED]
        unprotected_paths = [p for p in group if p.status == CoverageStatus.UNPROTECTED]
        partial_paths = [p for p in group if p.status == CoverageStatus.PARTIALLY_PROTECTED]
        unknown_paths = [p for p in group if p.status == CoverageStatus.UNKNOWN]

        if unprotected_paths and (guarded_paths or partial_paths):
            impl_status = CoverageStatus.PARTIALLY_PROTECTED
        elif unprotected_paths:
            impl_status = CoverageStatus.UNPROTECTED
        elif partial_paths:
            impl_status = CoverageStatus.PARTIALLY_PROTECTED
        elif unknown_paths:
            impl_status = CoverageStatus.UNKNOWN
        else:
            impl_status = CoverageStatus.PROTECTED

        alternates = (
            [
                (
                    f"{p.route_identity.method} {p.route_identity.route} "
                    f"({p.route_identity.handler_name})"
                )
                for p in unprotected_paths
            ]
            if (unprotected_paths and (guarded_paths or partial_paths))
            else []
        )
        if alternates:
            bypass_notes[impl_id] = alternates

        reasons: list[CoverageReasonCode] = []
        for p in group:
            reasons.extend(p.reason_codes)
        if alternates and CoverageReasonCode.ALTERNATE_ENTRYPOINT_BYPASS not in reasons:
            reasons.append(CoverageReasonCode.ALTERNATE_ENTRYPOINT_BYPASS)

        first = group[0]
        implementations.append(
            SensitiveImplementation(
                implementation_id=impl_id,
                symbol_name=first.sensitive_implementation or impl_id,
                component=_component_for_impl(impl_id),
                expected_flags=list(first.expected_flags),
                source_ref=first.source_ref,
                paths=group,
                implementation_coverage_status=impl_status,
                alternate_entrypoints=alternates,
                reason_codes=list(dict.fromkeys(reasons)),
            )
        )

    for item in assessments:
        impl_id = item.route_identity.implementation_id
        if (
            impl_id
            and impl_id in bypass_notes
            and item.status == CoverageStatus.PROTECTED
            and item.applicability == CoverageApplicability.APPLICABLE
        ):
            # Route-level guard is sound, but implementation has an unguarded alternate entry point.
            new_reasons = list(item.reason_codes)
            if CoverageReasonCode.ALTERNATE_ENTRYPOINT_BYPASS not in new_reasons:
                new_reasons.append(CoverageReasonCode.ALTERNATE_ENTRYPOINT_BYPASS)
            updated_assessments.append(
                item.model_copy(
                    update={
                        "status": CoverageStatus.PARTIALLY_PROTECTED,
                        "reason_codes": new_reasons,
                        "notes": [
                            *item.notes,
                            (
                                f"Implementation {impl_id} is reachable via unguarded alternate "
                                f"path(s): {', '.join(bypass_notes[impl_id])}."
                            ),
                        ],
                    }
                )
            )
        else:
            updated_assessments.append(item)

    return implementations, updated_assessments


def build_coverage_summary(
    assessments: list[ExecutionPathAssessment],
    *,
    inventory_complete: bool,
) -> CoverageAuditSummary:
    """Compute denominator-explicit summary excluding exempt routes from sensitive_routes."""
    applicable = [a for a in assessments if a.applicability != CoverageApplicability.EXEMPT]
    exempt = [a for a in assessments if a.applicability == CoverageApplicability.EXEMPT]
    return CoverageAuditSummary(
        sensitive_routes=len(applicable),
        protected=sum(1 for a in applicable if a.status == CoverageStatus.PROTECTED),
        partially_protected=sum(
            1 for a in applicable if a.status == CoverageStatus.PARTIALLY_PROTECTED
        ),
        unprotected=sum(1 for a in applicable if a.status == CoverageStatus.UNPROTECTED),
        unknown=sum(1 for a in applicable if a.status == CoverageStatus.UNKNOWN),
        exempt_routes=len(exempt),
        inventory_complete=inventory_complete,
    )


def project_coverage_findings(
    assessments: list[ExecutionPathAssessment],
    *,
    implementations: list[SensitiveImplementation],
    runtime_corroboration: RuntimeCorroborationSummary,
    evidence_ids: list[str] | None = None,
) -> list[CoverageFinding]:
    """Project internal assessments into canonical ``shared.schemas.CoverageFinding`` records."""
    impl_by_id = {impl.implementation_id: impl for impl in implementations}
    findings: list[CoverageFinding] = []
    ev_ids = list(evidence_ids or [])

    for item in assessments:
        if item.applicability == CoverageApplicability.EXEMPT:
            continue
        impl_id = item.route_identity.implementation_id
        impl = impl_by_id.get(impl_id) if impl_id else None
        alternates = list(impl.alternate_entrypoints) if impl else []
        status = item.status
        if runtime_corroboration.contradicted and status == CoverageStatus.PROTECTED:
            status = CoverageStatus.UNKNOWN

        src_loc = (
            f"{item.source_ref.relative_path}:{item.source_ref.start_line}-{item.source_ref.end_line}"
            if item.source_ref
            else None
        )
        fid = "cov_" + sha256_text(
            f"{item.route_identity.application_id}:{item.route_identity.method}:{item.route_identity.route}"
        )[:16]
        findings.append(
            CoverageFinding(
                coverage_finding_id=fid,
                route=item.route_identity.route,
                component=impl.component if impl else _component_for_impl(impl_id or "unknown"),
                coverage_status=status,
                associated_flags=sorted(set(item.expected_flags) | set(item.observed_flags)),
                source_location=src_loc,
                alternate_execution_paths=alternates,
                evidence_ids=ev_ids,
                explanation=(
                    "; ".join(item.notes)
                    or (
                        f"Coverage classified as {status.value} "
                        f"({', '.join(r.value for r in item.reason_codes)})."
                    )
                ),
                recommended_action=_recommended_action_for_status(status, item),
                analysis_limitations=_limitations_for_item(item, runtime_corroboration),
            )
        )
    return findings


def _component_for_impl(impl_id: str) -> str:
    if "search" in impl_id:
        return "search_service"
    if "file" in impl_id:
        return "file_service"
    if "export" in impl_id:
        return "legacy_export_service"
    return "application_service"


def _recommended_action_for_status(
    status: CoverageStatus,
    item: ExecutionPathAssessment,
) -> str:
    if status == CoverageStatus.PROTECTED:
        return "No static flag guard change required; maintain regression verification."
    if status == CoverageStatus.PARTIALLY_PROTECTED:
        return (
            "Close alternate unguarded entry points or align guard conditions "
            "across all callers (review-only)."
        )
    if status == CoverageStatus.UNPROTECTED:
        flags = (
            ", ".join(item.expected_flags)
            if item.expected_flags
            else "a dedicated containment flag"
        )
        return (
            f"Insert dominating guard for {flags} before invoking "
            "sensitive implementation (review-only)."
        )
    return (
        "Collect complete source snapshot, resolve dynamic routing/helpers, "
        "or run authorized verification."
    )


def _limitations_for_item(
    item: ExecutionPathAssessment,
    runtime: RuntimeCorroborationSummary,
) -> list[str]:
    lims = [
        "Bounded AST static analysis; does not evaluate dynamic monkey-patches or reflection."
    ]
    if runtime.missing_runtime_evidence:
        lims.extend(runtime.missing_runtime_evidence)
    if runtime.contradicted:
        lims.extend(runtime.contradiction_details)
    if item.route_identity.is_dynamic:
        lims.append("Dynamic route registration could not be statically resolved.")
    return list(dict.fromkeys(lims))
