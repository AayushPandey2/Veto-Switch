"""Deterministic, redacted JSON and Markdown renderers for EvidenceReport."""

from __future__ import annotations

import html
from typing import Any

from shared.identifiers import format_utc_iso
from shared.schemas import EvidenceReport

from remediation.reporting.models import EvidenceReportContext, MissingEvidenceItem
from remediation.reporting.redaction import redact_structured_data, redact_text


def _esc(value: Any) -> str:
    return html.escape(redact_text(str(value)), quote=True)


def render_report_json(
    report: EvidenceReport,
    ctx: EvidenceReportContext,
    *,
    missing_items: list[MissingEvidenceItem] | None = None,
) -> dict[str, Any]:
    """Render canonical machine-readable JSON dictionary with recursive redaction."""
    raw: dict[str, Any] = {
        "report_schema_version": report.report_schema_version,
        "reporting_policy_version": report.reporting_policy_version,
        "report_id": report.report_id,
        "incident_id": report.incident_id,
        "generated_at": format_utc_iso(report.generated_at),
        "snapshot": {
            "maximum_event_sequence": report.snapshot_sequence or len(report.timeline),
            "snapshot_fingerprint": report.snapshot_fingerprint,
            "fixture_mode": ctx.fixture_mode,
        },
        "summary": {
            "incident_status": report.incident_status.value,
            "evidence_completeness": report.completeness.value,
            "deployment_verified": any(
                d.deployment_status.value == "observed" and d.addressable
                for d in report.deployment_evidence
            ),
        },
        "findings": [f.model_dump(mode="json") for f in report.findings],
        "timeline": [
            {
                "sequence_number": e.sequence_number,
                "timestamp_utc": format_utc_iso(e.timestamp_utc),
                "event_id": e.event_id,
                "event_type": e.event_type.value,
                "actor": e.actor,
                "actor_type": e.actor_type.value,
                "payload": (
                    e.payload.model_dump(mode="json")
                    if hasattr(e.payload, "model_dump")
                    else e.payload
                ),
            }
            for e in sorted(report.timeline, key=lambda x: x.sequence_number)
        ],
        "investigation": [s.model_dump(mode="json") for s in report.investigation_summaries],
        "mapping": list(report.feature_mapping_results),
        "coverage": (
            [c.model_dump(mode="json") for c in report.coverage_findings]
            if report.coverage_findings
            else [{"status": "NOT AVAILABLE / NOT IMPLEMENTED (Phase 06)"}]
        ),
        "containment": [
            c.model_dump(mode="json") if hasattr(c, "model_dump") else c
            for c in report.containment_decisions
        ],
        "approvals": [a.model_dump(mode="json") for a in report.human_approvals],
        "operations": [o.model_dump(mode="json") for o in report.operation_receipts],
        "feature_state_observations": [
            fs.model_dump(mode="json") for fs in report.feature_state_observations
        ],
        "verification": [v.model_dump(mode="json") for v in report.verification_outcomes],
        "patches": [p.model_dump(mode="json") for p in report.patch_proposals],
        "patch_test_results": [p.model_dump(mode="json") for p in report.patch_test_results],
        "deployment": [d.model_dump(mode="json") for d in report.deployment_evidence],
        "rollout": {
            "plans": [p.model_dump(mode="json") for p in report.rollout_plans],
            "decisions": [d.model_dump(mode="json") for d in report.rollout_decisions],
        },
        "rollback": [r.model_dump(mode="json") for r in report.rollback_history],
        "cve_context": list(ctx.cve_context),
        "artifacts": [a.model_dump(mode="json") for a in report.artifact_references],
        "artifact_integrity_results": list(report.artifact_integrity_results),
        "claim_evidence_links": list(report.claim_evidence_links),
        "missing_evidence": (
            [m.model_dump(mode="json") for m in missing_items]
            if missing_items is not None
            else list(report.missing_evidence)
        ),
        "cross_record_inconsistencies": list(report.cross_record_inconsistencies),
        "limitations": list(report.limitations),
    }
    sanitized, summary = redact_structured_data(raw)
    sanitized["redaction_summary"] = summary
    return sanitized  # type: ignore[no-any-return]


def render_report_markdown(
    report: EvidenceReport,
    ctx: EvidenceReportContext,
    *,
    missing_items: list[MissingEvidenceItem] | None = None,
) -> str:
    """Render deterministic, escaped, redacted Markdown report from canonical EvidenceReport."""
    lines: list[str] = [
        "# Killswitch X — Incident Evidence Report",
        "",
        "## 1. Executive Summary",
        f"- **Incident ID:** `{_esc(report.incident_id)}`",
        f"- **Report ID:** `{_esc(report.report_id)}`",
        f"- **Current Status:** `{report.incident_status.value}`",
        f"- **Evidence Completeness:** `{report.completeness.value}`",
        f"- **Generated At (UTC):** `{format_utc_iso(report.generated_at)}`",
        f"- **Fixture Mode:** `{ctx.fixture_mode}`",
        "",
        "## 2. Vulnerability Finding & Reproduction",
    ]
    if report.findings:
        for f in report.findings:
            lines.append(
                f"- `{_esc(f.finding_id)}`: `{f.category.value}` ({f.severity.value}, "
                f"status=`{f.status.value}`, route=`{_esc(f.affected_route)}`)"
            )
    else:
        lines.append("- *No normalized findings recorded.*")

    lines.extend(["", "## 3. AI Investigation & Feature Mapping"])
    if report.investigation_summaries:
        for inv in report.investigation_summaries:
            lines.append(f"- `{_esc(inv.investigation_id)}`: {_esc(inv.executive_summary)}")
    else:
        lines.append("- *Investigation summary unavailable.*")

    lines.extend(["", "## 4. Coverage Audit"])
    if report.coverage_findings:
        for cov in report.coverage_findings:
            lines.append(
                f"- `{_esc(cov.coverage_finding_id)}` (`{_esc(cov.route)}`): "
                f"`{cov.coverage_status.value}`"
            )
    else:
        lines.append("- **Coverage audit:** `NOT AVAILABLE / NOT IMPLEMENTED` (Phase 06)")

    lines.extend(["", "## 5. Human Approvals & External Execution"])
    if report.human_approvals:
        for a in report.human_approvals:
            lines.append(
                f"- Approval `{_esc(a.approval_id)}` for `{_esc(a.proposal_id)}`: "
                f"`{a.decision.value}` by `{_esc(a.actor_id)}` at `{format_utc_iso(a.decided_at)}`"
            )
    else:
        lines.append("- *No human approvals recorded.*")
    if report.operation_receipts:
        for op in report.operation_receipts:
            lines.append(
                f"- Operation `{_esc(op.operation_id)}` on `{_esc(op.target_feature)}`: "
                f"`{op.outcome.value}` (observed_state=`{op.observed_state}`)"
            )
    else:
        lines.append("- *No external operation receipts recorded.*")

    lines.extend(["", "## 6. Verification, Patching & Deployment"])
    lines.append(f"- **Verification results:** {len(report.verification_outcomes)}")
    lines.append(f"- **Patch proposals:** {len(report.patch_proposals)}")
    lines.append(f"- **Patch test runs:** {len(report.patch_test_results)}")
    lines.append(f"- **Deployment evidence:** {len(report.deployment_evidence)}")

    lines.extend(["", "## 7. Progressive Rollout & Rollback History"])
    lines.append(f"- **Rollout plans:** {len(report.rollout_plans)}")
    lines.append(f"- **Rollout decisions:** {len(report.rollout_decisions)}")
    lines.append(f"- **Rollback proposals:** {len(report.rollback_history)}")

    lines.extend(["", "## 8. Incident Timeline (UTC)"])
    if report.timeline:
        lines.append("| Seq | Timestamp (UTC) | Event | Actor | Type |")
        lines.append("|---:|---|---|---|---|")
        for ev in sorted(report.timeline, key=lambda e: e.sequence_number):
            lines.append(
                f"| {ev.sequence_number} | `{format_utc_iso(ev.timestamp_utc)}` | "
                f"`{ev.event_type.value}` | `{_esc(ev.actor)}` | `{ev.actor_type.value}` |"
            )
    else:
        lines.append("- *No accepted events recorded.*")

    lines.extend(["", "## 9. Artifact Integrity Manifest"])
    if report.artifact_integrity_results:
        for air in report.artifact_integrity_results:
            lines.append(
                f"- `{_esc(air['artifact_id'])}` ({_esc(air['artifact_type'])}): "
                f"`{_esc(air['status'])}` — {_esc(air['message'])}"
            )
    else:
        lines.append("- *No artifact references recorded.*")

    lines.extend(["", "## 10. UNVERIFIED / INCOMPLETE EVIDENCE"])
    if missing_items:
        for item in missing_items:
            lines.append(
                f"- **{_esc(item.missing_evidence_type)}** (`{_esc(item.required_record)}`): "
                f"{_esc(item.reason)} Impact: {_esc(item.impact)}"
            )
    elif report.missing_evidence:
        for me in report.missing_evidence:
            lines.append(f"- {_esc(me)}")
    else:
        lines.append("- *No required evidence missing within declared report scope.*")

    lines.extend(["", "## 11. Known Limitations"])
    if report.limitations:
        for lim in report.limitations:
            lines.append(f"- {_esc(lim)}")
    else:
        lines.append("- *None recorded.*")

    return "\n".join(lines) + "\n"
