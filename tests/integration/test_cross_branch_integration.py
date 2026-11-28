"""Cross-branch integration and contract tests across Feature, feat/security, and feat/platform."""

from __future__ import annotations

import platform as stdlib_platform
from pathlib import Path

import pytest
from agent_core.adapters.security_contract import (
    normalize_security_finding,
    normalize_security_verification_result,
)
from agent_core.coverage.source_snapshot import load_authorized_source_snapshot
from agent_core.flag_auditor import audit_flag_coverage
from backend.app import create_app as create_platform_backend
from demo_app.app import create_app as create_demo_app
from fastapi.testclient import TestClient
from security.models import SecurityFinding, SecurityVerificationResult
from shared.enums import CoverageStatus, FindingStatus, TestExecutionStatus, VerificationPhase
from shared.schemas import Finding, VerificationResult

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.integration
def test_stdlib_platform_not_shadowed() -> None:
    """Ensure top-level platform/ directory does not shadow Python stdlib platform."""
    assert callable(stdlib_platform.system)
    assert isinstance(stdlib_platform.system(), str)


@pytest.mark.integration
def test_security_verifier_dto_and_normalization() -> None:
    """Exercise SecurityVerificationResult -> normalize_security_verification_result."""
    dto = SecurityVerificationResult(
        incident_id="inc_cross_1",
        test_id="sqli_search",
        target_id="platform_demo_app",
        phase="before",
        outcome="exploit_reproduced",
        passed=True,
        observed_flag_state="search_v1=on",
        revision="rev_demo_1",
        requested_revision="rev_demo_1",
        evidence_id="ev_cross_1",
    )
    canonical = normalize_security_verification_result(dto.model_dump())
    assert isinstance(canonical, VerificationResult)
    assert canonical.phase == VerificationPhase.BEFORE_CONTAINMENT
    assert canonical.execution_status == TestExecutionStatus.TEST_PASSED
    assert canonical.vulnerability_reproduced is True
    assert canonical.verification_id.startswith("ver_")

    # Deterministic ID stability when verification_id is omitted on security wire
    canonical2 = normalize_security_verification_result(dto.model_dump())
    assert canonical.verification_id == canonical2.verification_id


@pytest.mark.integration
def test_security_finding_dto_normalizes_to_canonical_finding() -> None:
    """Exercise SecurityFinding -> normalize_security_finding -> shared.schemas.Finding."""
    sec_finding = SecurityFinding(
        finding_id="fnd_cross_1",
        incident_id="inc_cross_1",
        category="sqli",
        affected_route="/search",
        affected_component="search_service",
        severity="high",
        status="reproduced",
        evidence_ids=["ev_cross_1"],
        tool="demo_scanner",
        tool_version="1.0",
    )
    canonical, extras = normalize_security_finding(sec_finding.model_dump())
    assert isinstance(canonical, Finding)
    assert canonical.status == FindingStatus.REPRODUCED
    assert canonical.affected_route == "/search"
    assert extras["raw_category"] == "sqli"


@pytest.mark.integration
@pytest.mark.asyncio
async def test_platform_demo_app_audited_by_phase06_and_served_by_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Audit real platform/demo_app/app.py via Phase 06 and verify backend /flags/coverage."""
    monkeypatch.setenv("KILLSWITCH_DEMO_ENV", "local")
    monkeypatch.setenv("KILLSWITCH_DEMO_MODE", "true")
    monkeypatch.setenv("KILLSWITCH_FLAG_ADAPTER", "local")
    db_path = tmp_path / "backend.db"
    monkeypatch.setenv("KILLSWITCH_DEMO_DATABASE", str(db_path))
    demo_root = REPO_ROOT / "platform" / "demo_app"
    snap = load_authorized_source_snapshot(
        root_dir=demo_root,
        relative_files=["app.py"],
        application_id="platform_demo_app",
        environment="local",
        source_revision="workspace-local",
    )
    audit_res = await audit_flag_coverage(snap, is_fixture=False)
    assert audit_res.summary.sensitive_routes >= 2
    assert audit_res.summary.exempt_routes >= 1
    assert any(a.route_identity.route == "/search" for a in audit_res.route_assessments)
    assert any(
        a.route_identity.route == "/health" and a.status == CoverageStatus.UNKNOWN
        for a in audit_res.route_assessments
    )

    # Verify demo app Flask factory responds cleanly
    flask_app = create_demo_app()
    with flask_app.test_client() as fc:
        resp = fc.get("/health")
        assert resp.status_code == 200

    # Verify FastAPI control-plane backend /flags/coverage returns both legacy & static_coverage
    backend_app = create_platform_backend(
        database_path=db_path,
        operator_passphrase="test-operator-passphrase",
        demo_app_url="http://127.0.0.1:1",
    )
    with TestClient(backend_app) as client:
        cov_resp = client.get(
            "/flags/coverage",
            headers={"X-Operator-Passphrase": "test-operator-passphrase"},
        )
        assert cov_resp.status_code == 200
        body = cov_resp.json()
        assert "routes" in body
        assert "static_coverage" in body
        assert body["static_coverage"]["application_id"] == "platform_demo_app"
