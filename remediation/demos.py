"""Runnable offline demonstrations (Demos A-H) for Phase 07 AI Patch Engineer."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any

from agent_core.context import EventProcessingResult, FixedClock, ProducerContext, TransitionContext
from agent_core.events import build_incident_event
from agent_core.orchestrator import IncidentOrchestrator
from agent_core.repositories.memory import InMemoryOrchestrationRepository
from shared.config import load_route_registry
from shared.enums import (
    ActorType,
    ArtifactType,
    EventType,
    EvidenceProvenance,
    FindingStatus,
    IncidentState,
    TestExecutionStatus,
    VerificationPhase,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.identifiers import generate_incident_id
from shared.schemas import ArtifactReference, Finding, VerificationResult
from shared.serialization import sha256_text

from remediation.patch_agent import EvidenceGroundedPatchEngineer
from remediation.patching.diff_validator import parse_unified_diff
from remediation.patching.review import serialize_patch_dashboard
from remediation.patching.source_access import (
    PLATFORM_DEMO_TARGET,
    STAND_IN_TARGET,
    build_patch_context,
    load_snapshot_from_files,
)

STAND_IN_APP_SOURCE = '''import os

DOC_ROOT = "/tmp/docs"

def search_v1(q: str):
    # DELIBERATELY VULNERABLE (demo only): user input concatenated into SQL.
    sql = ("SELECT title, owner FROM documents WHERE is_private = 0 AND title LIKE '%"
           + q + "%' ORDER BY title")
    return db().execute(sql).fetchall()

def files_v1(name: str):
    # DELIBERATELY VULNERABLE (demo only): no normalization or root check.
    path = os.path.join(DOC_ROOT, name)
    with open(path, encoding="utf-8") as f:
        return f.read()
'''

PLATFORM_VULN_SOURCE = '''def search_documents(conn, q: str):
    sql = f"SELECT title, owner FROM documents WHERE is_private = 0 AND title LIKE '%{q}%'"
    return conn.execute(sql).fetchall()
'''


async def run_patch_demos() -> list[dict[str, Any]]:
    """Execute offline Phase 07 Patch Engineer demonstrations A-H."""
    now = datetime(2026, 11, 27, 0, 0, 0, tzinfo=UTC)
    clock = FixedClock(now)
    repo = InMemoryOrchestrationRepository()
    engineer = EvidenceGroundedPatchEngineer(
        evidence_repository=repo,
        clock=clock,
        fixture_mode=True,
    )
    outputs: list[dict[str, Any]] = []

    standin_snap = load_snapshot_from_files(
        target=STAND_IN_TARGET, files={"app.py": STAND_IN_APP_SOURCE}
    )

    # Demo A — SQLi repair on stand_in
    f_sqli = Finding(
        finding_id="fnd_patch_demo_a",
        incident_id="inc_patch_demo_a",
        category=VulnerabilityCategory.SQL_INJECTION,
        affected_route="/search",
        affected_component="search_v1",
        severity=VulnerabilitySeverity.HIGH,
        status=FindingStatus.REPRODUCED,
        evidence_ids=["art_patch_demo_a"],
        repository_revision=STAND_IN_TARGET.source_revision,
        environment="demo-staging",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    ctx_a = build_patch_context(
        finding=f_sqli,
        target_descriptor=STAND_IN_TARGET,
        snapshot=standin_snap,
        registered_test_id="sqli_search",
        fixture_mode=True,
        evaluation_timestamp=now,
    )
    out_a = await engineer.generate_candidate(ctx_a, require_contained=False)
    outputs.append(
        {"demo": "Patch Demo A (SQLi)", **serialize_patch_dashboard(out_a, STAND_IN_TARGET)}
    )

    # Demo B — File-serving repair on stand_in
    f_files = Finding(
        finding_id="fnd_patch_demo_b",
        incident_id="inc_patch_demo_b",
        category=VulnerabilityCategory.PATH_TRAVERSAL,
        affected_route="/files",
        affected_component="files_v1",
        severity=VulnerabilitySeverity.HIGH,
        status=FindingStatus.REPRODUCED,
        evidence_ids=["art_patch_demo_b"],
        repository_revision=STAND_IN_TARGET.source_revision,
        environment="demo-staging",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
    )
    ctx_b = build_patch_context(
        finding=f_files,
        target_descriptor=STAND_IN_TARGET,
        snapshot=standin_snap,
        registered_test_id="traversal_files",
        fixture_mode=True,
        evaluation_timestamp=now,
    )
    out_b = await engineer.generate_candidate(ctx_b, require_contained=False)
    outputs.append(
        {"demo": "Patch Demo B (Files)", **serialize_patch_dashboard(out_b, STAND_IN_TARGET)}
    )

    # Demo C — Invalid patch rejection (unauthorized path)
    invalid_rejected = False
    try:
        parse_unified_diff("--- a/../secret.py\n+++ b/../secret.py\n@@ -1,1 +1,1 @@\n-a\n+b\n")
    except Exception:
        invalid_rejected = True
    outputs.append({"demo": "Patch Demo C (Invalid Patch Rejected)", "rejected": invalid_rejected})

    # Demo D & E — Stale source revision rejection
    f_stale = f_sqli.model_copy(update={"repository_revision": "stale-rev-999"})
    ctx_stale = build_patch_context(
        finding=f_stale,
        target_descriptor=STAND_IN_TARGET,
        snapshot=standin_snap,
        fixture_mode=True,
        evaluation_timestamp=now,
    )
    out_e = await engineer.generate_candidate(ctx_stale, require_contained=False)
    outputs.append(
        {
            "demo": "Patch Demo E (Stale Revision Rejected)",
            "accepted": out_e.accepted,
            "rejection_reasons": [r.value for r in out_e.rejection_reasons],
        }
    )

    # Demo F — Application target distinction (platform_demo_app not sandbox-supported)
    plat_snap = load_snapshot_from_files(
        target=PLATFORM_DEMO_TARGET,
        files={"vulnerable_search_service.py": PLATFORM_VULN_SOURCE},
    )
    f_plat = f_sqli.model_copy(
        update={
            "finding_id": "fnd_patch_demo_f",
            "repository_revision": PLATFORM_DEMO_TARGET.source_revision,
        }
    )
    ctx_f = build_patch_context(
        finding=f_plat,
        target_descriptor=PLATFORM_DEMO_TARGET,
        snapshot=plat_snap,
        fixture_mode=True,
        evaluation_timestamp=now,
    )
    out_f = await engineer.generate_candidate(ctx_f, require_contained=False)
    outputs.append(
        {
            "demo": "Patch Demo F (Platform Target Distinction)",
            "accepted": out_f.accepted,
            "sandbox_ready": out_f.sandbox_ready,
            "touched_files": out_f.proposal.touched_files if out_f.proposal else [],
        }
    )

    # Demo G — Review experience (PR summary)
    outputs.append(
        {
            "demo": "Patch Demo G (Review & PR Summary)",
            "has_checklist": out_a.checklist is not None,
            "has_pr_summary": bool(out_a.pr_summary_markdown),
        }
    )

    # Demo H — Integrated patch lifecycle (CONTAINED -> PATCH_PENDING -> PATCH_PROPOSED)
    reg = load_route_registry()
    orch = IncidentOrchestrator(
        repository=repo,
        evidence_repository=repo,
        route_registry=reg,
        clock=clock,
        fixture_mode=True,
        patch_engineer=engineer,
    )
    inc_id = generate_incident_id()
    art_bytes = b"reproduction proof"
    art_ref = ArtifactReference(
        artifact_id="art_patch_demo_h",
        incident_id=inc_id,
        artifact_type=ArtifactType.REPRODUCTION_LOG,
        content_hash=sha256_text(art_bytes.decode("utf-8")),
        storage_ref="repro/patch_h.log",
        created_at=now,
        producer="authorized_verifier",
        provenance=EvidenceProvenance.REFERENCE_FIXTURE,
        content_type="text/plain",
        size_bytes=len(art_bytes),
        source_revision=STAND_IN_TARGET.source_revision,
    )
    await repo.store_artifact(art_ref, art_bytes)
    f_h = f_sqli.model_copy(
        update={
            "finding_id": "fnd_patch_demo_h",
            "incident_id": inc_id,
            "evidence_ids": [art_ref.artifact_id],
        }
    )
    sys_prod = ProducerContext(
        producer_id="platform_api",
        actor_type=ActorType.SYSTEM,
        authenticated=True,
        trusted_channel="fixture_sim",
        provenance_mode="fixture",
    )
    eng_prod = ProducerContext(
        producer_id="deterministic_engine",
        actor_type=ActorType.DETERMINISTIC_ENGINE,
        authenticated=True,
        trusted_channel="fixture_sim",
        provenance_mode="fixture",
    )
    inc = await orch.create_incident(f_h, sys_prod)
    # Seed to CONTAINED via repository for focused Patch lifecycle demo
    stored_inc = await repo.get_incident(inc.incident_id)
    if stored_inc is None:
        raise RuntimeError(f"Incident {inc.incident_id} missing from repository.")
    seed_evt = build_incident_event(
        incident_id=inc.incident_id,
        event_type=EventType.CONTAINMENT_VERIFIED,
        actor="authorized_verifier",
        actor_type=ActorType.SECURITY_VERIFIER,
        sequence_number=2,
        correlation_id=inc.correlation_id,
        evidence_ids=[art_ref.artifact_id],
        timestamp_utc=now,
        payload={
            "verification_id": "ver_patch_demo_h",
            "phase": "after_containment",
            "execution_status": "test_passed",
        },
    )
    await repo.commit_transition(
        expected_version=stored_inc.incident_version,
        updated_incident=stored_inc.model_copy(
            update={
                "current_state": IncidentState.CONTAINED,
                "incident_version": stored_inc.incident_version + 1,
                "latest_event_sequence": 2,
                "latest_event_id": seed_evt.event_id,
            }
        ),
        event=seed_evt,
        result=EventProcessingResult(
            accepted=True,
            incident_id=inc.incident_id,
            event_id=seed_evt.event_id,
            previous_state=stored_inc.current_state,
            current_state=IncidentState.CONTAINED,
            incident_version=stored_inc.incident_version + 1,
            reason_code="CONTAINMENT_VERIFIED",
        ),
    )
    cont_ver = VerificationResult(
        verification_id="ver_patch_demo_h",
        incident_id=inc.incident_id,
        test_id="sqli_search",
        phase=VerificationPhase.AFTER_CONTAINMENT,
        execution_status=TestExecutionStatus.TEST_PASSED,
        passed=True,
        vulnerability_reproduced=False,
        tested_revision=STAND_IN_TARGET.source_revision,
    )
    ctx_h = build_patch_context(
        finding=f_h,
        target_descriptor=STAND_IN_TARGET,
        snapshot=standin_snap,
        containment_verification=cont_ver,
        fixture_mode=True,
        evaluation_timestamp=now,
    )
    prop_h, prop_res_h = await orch.execute_patch_generation(
        finding=f_h,
        containment_verification=cont_ver,
        producer_context=eng_prod,
        patch_context=ctx_h,
    )
    outputs.append(
        {
            "demo": "Patch Demo H (Orchestrator Lifecycle)",
            "incident_id": inc.incident_id,
            "final_state": prop_res_h.current_state.value if prop_res_h.current_state else None,
            "patch_id": prop_h.patch_id if prop_h else None,
        }
    )
    _ = TransitionContext
    return outputs


def main() -> int:
    for item in asyncio.run(run_patch_demos()):
        print(f"[PATCH DEMO] {item}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
