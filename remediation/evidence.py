"""Phase 11 Incident Evidence Intelligence Engine and compatible public interfaces."""

from __future__ import annotations

from typing import Any

from agent_core.context import EvidenceReporterAgent
from shared.enums import IncidentState
from shared.identifiers import format_utc_iso
from shared.schemas import ArtifactReference, EvidenceReport, IncidentEvent
from shared.serialization import sha256_canonical

from remediation.reporting.claims import (
    build_claim_evidence_links,
    evaluate_report_completeness,
)
from remediation.reporting.integrity import (
    detect_cross_record_inconsistencies,
    validate_event_history_for_report,
    verify_artifact_integrity,
)
from remediation.reporting.models import EvidenceReportContext, MissingEvidenceItem
from remediation.reporting.renderers import render_report_json, render_report_markdown


class IncidentEvidenceReporter(EvidenceReporterAgent):
    """Deterministic Phase 11 Incident Evidence Reporter (zero LLM calls)."""

    async def build_report(
        self,
        incident_id: str,
        events: list[IncidentEvent],
        artifacts: list[ArtifactReference],
    ) -> EvidenceReport:
        """Protocol-compatible EvidenceReporterAgent entrypoint."""
        ctx = EvidenceReportContext(
            incident_id=incident_id,
            incident_status=IncidentState.RECEIVED,
            accepted_events=list(events),
            artifact_references=list(artifacts),
            generation_timestamp=(
                events[-1].timestamp_utc
                if events
                else EvidenceReportContext(incident_id=incident_id).generation_timestamp
            ),
        )
        report, _ = self.build_report_with_details(ctx)
        return report

    def build_report_with_details(
        self, ctx: EvidenceReportContext
    ) -> tuple[EvidenceReport, list[MissingEvidenceItem]]:
        """Build canonical EvidenceReport + structured MissingEvidenceItems deterministically."""
        ordered_events = sorted(ctx.accepted_events, key=lambda e: e.sequence_number)
        max_seq = (
            ctx.snapshot_boundary.maximum_event_sequence
            if ctx.snapshot_boundary is not None
            else (ordered_events[-1].sequence_number if ordered_events else 0)
        )

        event_diags = validate_event_history_for_report(
            ordered_events, expected_incident_id=ctx.incident_id
        )
        cross_issues = detect_cross_record_inconsistencies(ctx)
        all_inconsistencies = [*event_diags, *cross_issues]

        integrity_results = [
            verify_artifact_integrity(
                ref,
                ctx.artifact_contents.get(ref.artifact_id),
                expected_incident_id=ctx.incident_id,
            )
            for ref in sorted(ctx.artifact_references, key=lambda a: a.artifact_id)
        ]

        claims = build_claim_evidence_links(ctx, integrity_results)
        completeness, missing_items, limitations = evaluate_report_completeness(
            ctx, claims, integrity_results, all_inconsistencies
        )

        snapshot_fp = sha256_canonical(
            {
                "incident_id": ctx.incident_id,
                "incident_status": ctx.incident_status.value,
                "max_seq": max_seq,
                "event_ids": [e.event_id for e in ordered_events],
                "artifact_ids": [a.artifact_id for a in ctx.artifact_references],
                "policy_version": ctx.reporting_policy_version,
            }
        )
        report_id = f"rep_{ctx.incident_id}_{snapshot_fp[:12]}"[:64]

        report = EvidenceReport(
            report_id=report_id,
            incident_id=ctx.incident_id,
            incident_status=ctx.incident_status,
            timeline=ordered_events,
            findings=list(ctx.findings),
            investigation_summaries=list(ctx.investigation_summaries),
            containment_decisions=list(ctx.containment_decisions),
            human_approvals=list(ctx.approvals),
            operation_receipts=list(ctx.operation_receipts),
            verification_outcomes=list(ctx.verification_results),
            patch_proposals=list(ctx.patch_proposals),
            patch_test_results=list(ctx.patch_test_results),
            deployment_evidence=list(ctx.deployment_evidence),
            rollout_plans=list(ctx.rollout_plans),
            rollout_decisions=list(ctx.rollout_decisions),
            rollback_history=list(ctx.rollback_proposals),
            coverage_findings=list(ctx.coverage_findings),
            artifact_references=sorted(ctx.artifact_references, key=lambda a: a.artifact_id),
            missing_evidence=[
                f"{m.missing_evidence_type}: {m.reason}" for m in missing_items
            ],
            limitations=list(dict.fromkeys(limitations)),
            completeness=completeness,
            generated_at=ctx.generation_timestamp,
            report_schema_version=ctx.schema_version,
            reporting_policy_version=ctx.reporting_policy_version,
            snapshot_sequence=max_seq if max_seq >= 1 else None,
            snapshot_fingerprint=snapshot_fp,
            feature_mapping_results=list(ctx.mapping_results),
            blast_radius_analysis=list(ctx.blast_radius_analysis),
            feature_state_observations=list(ctx.feature_state_observations),
            verified_safe_state_history=list(ctx.verified_safe_states),
            artifact_integrity_results=[r.model_dump(mode="json") for r in integrity_results],
            claim_evidence_links=[c.model_dump(mode="json") for c in claims],
            cross_record_inconsistencies=all_inconsistencies,
            redaction_summary={"policy_version": ctx.redaction_policy_version},
        )
        return report, missing_items

    def render_markdown(
        self,
        report: EvidenceReport,
        *,
        context: EvidenceReportContext | None = None,
        missing_items: list[MissingEvidenceItem] | None = None,
    ) -> str:
        """Render deterministic, redacted Markdown report."""
        ctx = context or EvidenceReportContext(
            incident_id=report.incident_id,
            incident_status=report.incident_status,
            generation_timestamp=report.generated_at,
        )
        return render_report_markdown(report, ctx, missing_items=missing_items)

    def render_json(
        self,
        report: EvidenceReport,
        *,
        context: EvidenceReportContext | None = None,
        missing_items: list[MissingEvidenceItem] | None = None,
    ) -> dict[str, Any]:
        """Render canonical redacted JSON dictionary."""
        ctx = context or EvidenceReportContext(
            incident_id=report.incident_id,
            incident_status=report.incident_status,
            generation_timestamp=report.generated_at,
        )
        return render_report_json(report, ctx, missing_items=missing_items)


def generate_report(
    events: list[IncidentEvent],
    artifacts: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    """Compatible public roadmap interface returning (markdown, json_dict)."""
    incident_id = (
        events[0].incident_id
        if events
        else str(artifacts.get("incident_id", "inc_unknown"))
    )
    refs = [
        ArtifactReference.model_validate(a) if not isinstance(a, ArtifactReference) else a
        for a in artifacts.get("artifact_references", [])
    ]
    ctx = EvidenceReportContext(
        incident_id=incident_id,
        incident_status=IncidentState(
            artifacts.get("incident_status", IncidentState.RECEIVED.value)
        ),
        accepted_events=list(events),
        artifact_references=refs,
        artifact_contents=dict(artifacts.get("artifact_contents", {})),
        generation_timestamp=(
            events[-1].timestamp_utc
            if events
            else EvidenceReportContext(incident_id=incident_id).generation_timestamp
        ),
        fixture_mode=bool(artifacts.get("fixture_mode", False)),
    )
    reporter = IncidentEvidenceReporter()
    report, missing_items = reporter.build_report_with_details(ctx)
    md = reporter.render_markdown(report, context=ctx, missing_items=missing_items)
    js = reporter.render_json(report, context=ctx, missing_items=missing_items)
    js["generated_at_iso"] = format_utc_iso(report.generated_at)
    return md, js
