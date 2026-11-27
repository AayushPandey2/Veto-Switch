"""Local API for a persistent, human-approved containment demonstration."""

import asyncio
import hashlib
import hmac
import json
import os
from difflib import unified_diff
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

from backend.database import initialize_platform_database
from backend.models import (
    ApplyRequest,
    DecisionCreate,
    IncidentCreate,
    NormalizedFindingCreate,
    ReleaseApplyRequest,
    ReleaseDecisionCreate,
    RolloutRequest,
    SyntheticTrafficRequest,
)
from demo_app.config import DemoSettings
from demo_app.database import (
    DEMO_USERS,
    get_demo_identity_flag_override,
    get_demo_telemetry,
    get_connection,
    replace_demo_identity_flag_overrides,
    seed_demo_data,
    set_demo_flag_overrides,
)
from demo_app.manifest import ROUTE_MANIFEST
from demo_app.feature_flags import FeatureFlagProvider, FeatureState
from demo_app.file_service import read_public_demo_file
from demo_app.search_service import search_documents
from backend.flagsmith_client import (
    FlagsmithIntegrationError,
    FlagsmithManagementClient,
)

SCENARIOS = {
    "search_sqli": {"safe_flag": "search_v2", "vulnerable_flag": "search_v1"},
    "path_traversal": {"safe_flag": "files_v2", "vulnerable_flag": "files_v1"},
}
PATCH_SOURCE_FILES = {
    "search_sqli": ("vulnerable_search_service.py", "search_service.py"),
    "path_traversal": ("vulnerable_file_service.py", "file_service.py"),
}
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _flag_evaluation_known(payload: dict, names: tuple[str, ...]) -> bool:
    states = payload.get("flag_states")
    return isinstance(states, dict) and all(
        states.get(name) in {"enabled", "disabled"} for name in names
    )


def _target_environment(settings: DemoSettings) -> str:
    if settings.flag_adapter == "local":
        return "local"
    key_fingerprint = hashlib.sha256(
        (settings.flagsmith_environment_key or "").encode("utf-8")
    ).hexdigest()[:12]
    return f"flagsmith:{key_fingerprint}"


def _proposal_hash(
    *,
    proposal_id: str,
    incident_id: str,
    scenario: str,
    safe_flag: str,
    vulnerable_flag: str,
    target_environment: str,
    expected_flags: dict[str, str],
    expires_at: str,
) -> str:
    content = {
        "version": 3,
        "proposal_id": proposal_id,
        "incident_id": incident_id,
        "scenario": scenario,
        "safe_flag": safe_flag,
        "safe_flag_unchanged": True,
        "vulnerable_flag": vulnerable_flag,
        "vulnerable_enabled": False,
        "target_environment": target_environment,
        "expected_flags": expected_flags,
        "expires_at": expires_at,
    }
    return hashlib.sha256(_json(content).encode("utf-8")).hexdigest()


def _release_hash(
    *,
    release_id: str,
    incident_id: str,
    action: str,
    percentage: int,
    safe_flag: str,
    environment: str,
    before: dict[str, bool | None],
    desired: dict[str, bool | None],
    expires_at: str,
) -> str:
    payload = {
        "version": 1,
        "release_id": release_id,
        "incident_id": incident_id,
        "action": action,
        "percentage": percentage,
        "safe_flag": safe_flag,
        "environment": environment,
        "before": before,
        "desired": desired,
        "expires_at": expires_at,
    }
    return hashlib.sha256(_json(payload).encode("utf-8")).hexdigest()


def _decode_incident(row: dict) -> dict:
    incident = dict(row)
    try:
        incident["finding"] = json.loads(incident.get("finding_json") or "{}")
    except (TypeError, json.JSONDecodeError):
        incident["finding"] = {}
    incident.pop("finding_json", None)
    return incident


def _decode_release(row: dict) -> dict:
    release = dict(row)
    for column, key in (
        ("before_overrides_json", "before_overrides"),
        ("desired_identities_json", "desired_overrides"),
    ):
        try:
            release[key] = json.loads(release.pop(column))
        except (TypeError, json.JSONDecodeError):
            release[key] = {}
    receipt_json = release.pop("receipt_json", None)
    try:
        release["receipt"] = json.loads(receipt_json) if receipt_json else None
    except (TypeError, json.JSONDecodeError):
        release["receipt"] = None
    return release


def _record_event(
    database_path: Path,
    incident_id: str,
    event_type: str,
    actor: str,
    payload: object,
) -> None:
    with get_connection(database_path) as connection:
        connection.execute(
            """
            INSERT INTO audit_events
                (incident_id, event_type, actor, payload_json, created_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (incident_id, event_type, actor, _json(payload), _now()),
        )


def _get_row(database_path: Path, query: str, values: tuple[object, ...]) -> dict:
    with get_connection(database_path) as connection:
        row = connection.execute(query, values).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail={"code": "not_found"})
    return dict(row)


def _ensure_unexpired(proposal: dict) -> None:
    if datetime.fromisoformat(proposal["expires_at"]) <= datetime.now(UTC):
        raise HTTPException(
            status_code=409,
            detail={"code": "proposal_expired", "message": "Create a fresh proposal."},
        )


def _expire_release_proposals(database_path: Path, incident_id: str) -> None:
    """Close expired, unapplied releases so they cannot block a fresh proposal."""
    now = _now()
    with get_connection(database_path) as connection:
        expired = connection.execute(
            "SELECT id FROM release_proposals WHERE incident_id = ? "
            "AND status IN ('pending_approval', 'approved') AND expires_at <= ?",
            (incident_id, now),
        ).fetchall()
        if expired:
            connection.executemany(
                "UPDATE release_proposals SET status = 'expired' "
                "WHERE id = ? AND status IN ('pending_approval', 'approved') AND expires_at <= ?",
                [(row["id"], now) for row in expired],
            )
    for row in expired:
        _record_event(
            database_path,
            incident_id,
            "release_proposal_expired",
            "release_planner",
            {"release_proposal_id": row["id"]},
        )


def _ensure_release_unexpired(database_path: Path, release: dict) -> None:
    if datetime.fromisoformat(release["expires_at"]) <= datetime.now(UTC):
        _expire_release_proposals(database_path, release["incident_id"])
        raise HTTPException(
            status_code=409,
            detail={"code": "proposal_expired", "message": "Create a fresh proposal."},
        )


def _read_demo_patch(scenario: str) -> dict[str, str]:
    """Build a read-only diff from the demo's vulnerable and safe examples."""
    filenames = PATCH_SOURCE_FILES.get(scenario)
    if filenames is None:
        raise HTTPException(status_code=422, detail={"code": "patch_scenario_unsupported"})

    demo_app_dir = Path(__file__).resolve().parents[1] / "demo_app"
    vulnerable_name, safe_name = filenames
    try:
        vulnerable_lines = (demo_app_dir / vulnerable_name).read_text(
            encoding="utf-8"
        ).splitlines(keepends=True)
        safe_lines = (demo_app_dir / safe_name).read_text(
            encoding="utf-8"
        ).splitlines(keepends=True)
    except OSError:
        raise HTTPException(
            status_code=503,
            detail={"code": "patch_sources_unavailable"},
        ) from None

    diff = "".join(
        unified_diff(
            vulnerable_lines,
            safe_lines,
            fromfile=f"a/platform/demo_app/{vulnerable_name}",
            tofile=f"b/platform/demo_app/{safe_name}",
            n=3,
        )
    )
    if not diff:
        raise HTTPException(status_code=503, detail={"code": "patch_diff_unavailable"})
    return {
        "before_file": f"platform/demo_app/{vulnerable_name}",
        "after_file": f"platform/demo_app/{safe_name}",
        "diff": diff,
    }


def create_app(
    *,
    database_path: Path | None = None,
    operator_passphrase: str | None = None,
    demo_app_url: str = "http://127.0.0.1:5000",
) -> FastAPI:
    """Build the API; state-changing routes require a local operator passphrase."""
    settings = DemoSettings.from_env()
    if settings.flag_adapter == "flagsmith" and not settings.flagsmith_management_token:
        raise ValueError("The operator API requires the Flagsmith management token.")
    database_path = database_path or settings.database_path
    initialize_platform_database(database_path)

    demo_app_url = os.getenv("KILLSWITCH_DEMO_APP_URL", demo_app_url)
    parsed_url = urlparse(demo_app_url)
    allowed_hosts = set(LOOPBACK_HOSTS)
    if os.getenv("KILLSWITCH_CONTAINERIZED") == "true":
        allowed_hosts.add("demo-app")
    if parsed_url.scheme != "http" or parsed_url.hostname not in allowed_hosts:
        raise ValueError("The demo app URL must use HTTP on the local machine.")

    expected_passphrase = (
        operator_passphrase
        if operator_passphrase is not None
        else os.getenv("KILLSWITCH_OPERATOR_PASSPHRASE", "")
    )

    app = FastAPI(
        title="Standalone Platform Demo API",
        version="0.1.0",
        description="Loopback incident, approval and feature-flag demonstration.",
    )
    app.state.database_path = database_path
    app.state.demo_app_url = demo_app_url.rstrip("/")

    def require_operator(
        supplied_passphrase: str | None = Header(
            default=None,
            alias="X-Operator-Passphrase",
        ),
    ) -> None:
        if not expected_passphrase:
            raise HTTPException(
                status_code=503,
                detail={"code": "operator_auth_not_configured"},
            )
        if supplied_passphrase is None or not hmac.compare_digest(
            supplied_passphrase,
            expected_passphrase,
        ):
            raise HTTPException(
                status_code=401,
                detail={"code": "operator_auth_failed"},
            )

    def flag_provider() -> FeatureFlagProvider:
        return FeatureFlagProvider(
            demo_mode=settings.demo_mode,
            allow_vulnerable_routes=settings.allow_vulnerable_routes,
            database_path=database_path,
            adapter=settings.flag_adapter,
            flagsmith_server_environment_key=settings.flagsmith_server_environment_key,
        )

    def management_client() -> FlagsmithManagementClient:
        if (
            not settings.flagsmith_environment_key
            or not settings.flagsmith_management_token
        ):
            raise HTTPException(
                status_code=503,
                detail={"code": "flagsmith_credentials_not_configured"},
            )
        return FlagsmithManagementClient(
            environment_key=settings.flagsmith_environment_key,
            management_token=settings.flagsmith_management_token,
            api_url=settings.flagsmith_api_url,
        )

    def current_flag_states(
        names: tuple[str, ...],
        *,
        allow_missing: bool = False,
    ) -> dict[str, str]:
        if settings.flag_adapter == "flagsmith":
            try:
                observed = management_client().read_flags(
                    names,
                    allow_missing=allow_missing,
                )
                return {
                    name: (
                        FeatureState.UNKNOWN.value
                        if enabled is None
                        else FeatureState.ENABLED.value
                        if enabled
                        else FeatureState.DISABLED.value
                    )
                    for name, enabled in observed.items()
                }
            except FlagsmithIntegrationError as exc:
                raise HTTPException(
                    status_code=503,
                    detail={"code": exc.code},
                ) from None
        provider = flag_provider()
        return {name: provider.get_state(name).value for name in names}

    demo_identities = tuple(user[1] for user in DEMO_USERS)

    def identity_overrides(flag_name: str) -> dict[str, bool | None]:
        if settings.flag_adapter == "flagsmith":
            try:
                return management_client().read_identity_feature_overrides(
                    demo_identities,
                    flag_name,
                )
            except FlagsmithIntegrationError as exc:
                raise HTTPException(status_code=503, detail={"code": exc.code}) from None
        return {
            identity: get_demo_identity_flag_override(database_path, identity, flag_name)
            for identity in demo_identities
        }

    def apply_identity_overrides(
        flag_name: str,
        values: dict[str, bool | None],
        *,
        actor: str,
    ) -> dict[str, bool | None]:
        if settings.flag_adapter == "flagsmith":
            try:
                return management_client().apply_identity_feature_overrides(
                    values,
                    flag_name,
                )
            except FlagsmithIntegrationError as exc:
                raise HTTPException(status_code=503, detail={"code": exc.code}) from None
        replace_demo_identity_flag_overrides(
            database_path,
            flag_name,
            values,
            actor=actor,
        )
        return identity_overrides(flag_name)

    def evaluate_demo_identity(incident: dict, identity: str) -> dict:
        scenario = incident["scenario"]
        if scenario == "search_sqli":
            route = "/search"
            params = {"q": "demo_user_01", "identity": identity}
        elif scenario == "path_traversal":
            route = "/files"
            params = {"path": "readme.txt", "identity": identity}
        else:
            return {"identity": identity, "status": "unknown", "reason": "scenario_unmapped"}
        try:
            response = httpx.get(
                f"{app.state.demo_app_url}{route}",
                params=params,
                timeout=3.0,
            )
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("Expected an object response.")
        except (httpx.RequestError, ValueError):
            return {"identity": identity, "status": "unknown", "reason": "demo_app_unreachable"}
        required_flags = (
            ("search_v1", "search_v2")
            if scenario == "search_sqli"
            else ("files_v1", "files_v2")
        )
        if not _flag_evaluation_known(payload, required_flags):
            return {
                "identity": identity,
                "status": "unknown",
                "reason": "flag_evaluation_unknown",
                "http_status": response.status_code,
                "variant": payload.get("variant", "unknown"),
            }
        return {
            "identity": identity,
            "status": "observed" if response.status_code == 200 else "unknown",
            "http_status": response.status_code,
            "variant": payload.get("variant", "unknown"),
        }

    def create_release_proposal(
        *,
        incident_id: str,
        action: str,
        percentage: int,
        safe_flag: str,
        before: dict[str, bool | None],
        desired: dict[str, bool | None],
        source_release_id: str | None = None,
    ) -> dict:
        release_id = str(uuid4())
        created_at = _now()
        expires_at = (datetime.now(UTC) + timedelta(minutes=15)).isoformat()
        environment = _target_environment(settings)
        digest = _release_hash(
            release_id=release_id,
            incident_id=incident_id,
            action=action,
            percentage=percentage,
            safe_flag=safe_flag,
            environment=environment,
            before=before,
            desired=desired,
            expires_at=expires_at,
        )
        with get_connection(database_path) as connection:
            connection.execute(
                """
                INSERT INTO release_proposals
                    (id, incident_id, action, percentage, safe_flag,
                     target_environment, before_overrides_json,
                     desired_identities_json, source_proposal_id,
                     proposal_hash, status, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_approval', ?, ?)
                """,
                (
                    release_id,
                    incident_id,
                    action,
                    percentage,
                    safe_flag,
                    environment,
                    _json(before),
                    _json(desired),
                    source_release_id,
                    digest,
                    expires_at,
                    created_at,
                ),
            )
        _record_event(
            database_path,
            incident_id,
            "rollout_proposal_created" if action == "rollout" else "rollback_proposal_created",
            "local_release_planner",
            {
                "release_proposal_id": release_id,
                "action": action,
                "percentage": percentage,
                "proposal_hash": digest,
                "expires_at": expires_at,
                "affected_identity_count": sum(value is not None for value in desired.values()),
            },
        )
        return _decode_release(
            _get_row(database_path, "SELECT * FROM release_proposals WHERE id = ?", (release_id,))
        )

    def observe_before_change(incident: dict) -> dict:
        if incident["scenario"] == "search_sqli":
            route = "/search"
            params = {"q": "' OR 1=1 -- "}
        else:
            route = "/files"
            params = {"path": "../private/internal_note.txt"}
        try:
            response = httpx.get(
                f"{app.state.demo_app_url}{route}",
                params=params,
                timeout=2.0,
            )
            payload = response.json()
            if not isinstance(payload, dict):
                raise ValueError("Expected a JSON object.")
        except (httpx.RequestError, ValueError):
            result = {
                "status": "unknown",
                "reason": "demo_app_unreachable_or_response_invalid",
                "observed_at": _now(),
            }
        else:
            required_flags = (
                ("search_v1", "search_v2")
                if incident["scenario"] == "search_sqli"
                else ("files_v1", "files_v2")
            )
            if not _flag_evaluation_known(payload, required_flags):
                result = {
                    "status": "unknown",
                    "reason": "flag_evaluation_unknown",
                    "route": route,
                    "http_status": response.status_code,
                    "variant": payload.get("variant", "unknown"),
                    "observed_at": _now(),
                }
                _record_event(
                    database_path,
                    incident["id"],
                    "pre_change_security_check",
                    "local_verifier",
                    result,
                )
                return result
            if incident["scenario"] == "search_sqli":
                vulnerable_variant = payload.get("variant") == "search_v1"
                exposed_records = vulnerable_variant and payload.get("count", 0) > 0
                result = {
                    "status": (
                        "vulnerability_observed"
                        if exposed_records
                        else "attack_not_observed"
                        if response.status_code == 200 and payload.get("variant")
                        else "unknown"
                    ),
                    "route": route,
                    "http_status": response.status_code,
                    "variant": payload.get("variant", "unknown"),
                    "records_returned": payload.get("count", 0),
                    "checks": {"injection_returned_synthetic_records": bool(exposed_records)},
                    "observed_at": _now(),
                }
            else:
                vulnerable_variant = payload.get("variant") == "files_v1"
                exposed_private_demo_file = (
                    response.status_code == 200 and vulnerable_variant
                )
                blocked = response.status_code == 404
                result = {
                    "status": (
                        "vulnerability_observed"
                        if exposed_private_demo_file
                        else "attack_not_observed"
                        if blocked and payload.get("error")
                        else "unknown"
                    ),
                    "route": route,
                    "http_status": response.status_code,
                    "variant": payload.get("variant", "unknown"),
                    "checks": {
                        "traversal_returned_synthetic_private_file": bool(
                            exposed_private_demo_file
                        ),
                        "safe_route_blocked_traversal": bool(blocked),
                    },
                    "observed_at": _now(),
                }
        _record_event(
            database_path,
            incident["id"],
            "pre_change_security_check",
            "local_verifier",
            result,
        )
        return result

    @app.get("/health")
    def health() -> dict:
        return {
            "status": "healthy",
            "service": "standalone-platform-demo-api",
            "database": "sqlite",
            "flag_adapter": (
                "flagsmith_management_api"
                if settings.flag_adapter == "flagsmith"
                else "local_sqlite_demo"
            ),
            "demo_data": "synthetic",
            "reset_allowed": settings.flag_adapter == "local" and settings.environment == "local",
        }

    @app.get("/flags", dependencies=[Depends(require_operator)])
    def flags() -> dict:
        names = ("search_v1", "search_v2", "files_v1", "files_v2")
        adapter_name = (
            "flagsmith_management_api"
            if settings.flag_adapter == "flagsmith"
            else "local_sqlite_demo"
        )
        try:
            states = current_flag_states(names)
        except HTTPException as exc:
            return JSONResponse(
                status_code=exc.status_code,
                content={"adapter": adapter_name, "flags": {}, "error": exc.detail},
            )
        return {
            "adapter": adapter_name,
            "flags": states,
        }

    @app.get("/flags/coverage", dependencies=[Depends(require_operator)])
    def flag_coverage() -> dict:
        names = tuple(
            dict.fromkeys(flag for route in ROUTE_MANIFEST for flag in route["flags"])
        )
        error_code = None
        try:
            states = current_flag_states(names, allow_missing=True)
        except HTTPException as exc:
            detail = exc.detail
            error_code = detail.get("code", "flag_state_unavailable") if isinstance(detail, dict) else "flag_state_unavailable"
            states = {name: FeatureState.UNKNOWN.value for name in names}
        routes = []
        gaps = []
        for route in ROUTE_MANIFEST:
            route_states = {name: states[name] for name in route["flags"]}
            missing = [name for name, state in route_states.items() if state == "unknown"]
            routes.append(
                {
                    **route,
                    "flag_states": route_states,
                    "covered": not missing,
                    "coverage_gaps": missing,
                }
            )
            gaps.extend(
                {"route": route["path"], "flag": name} for name in missing
            )
        return {
            "status": "complete" if not gaps else "incomplete",
            "adapter": settings.flag_adapter,
            "routes": routes,
            "gaps": gaps,
            **({"error": error_code} if error_code else {}),
        }

    @app.post("/incidents", status_code=201, dependencies=[Depends(require_operator)])
    def create_incident(payload: IncidentCreate) -> dict:
        incident_id = str(uuid4())
        created_at = _now()
        finding = {
            "category": "sqli" if payload.scenario == "search_sqli" else "path_traversal",
            "affected_route": "/search" if payload.scenario == "search_sqli" else "/files",
            "severity": "high",
            "status": "reproduced",
            "evidence_ids": [],
            "evidence_summary": payload.evidence_summary,
            "reporter": payload.reporter,
        }
        with get_connection(database_path) as connection:
            connection.execute(
                """
                INSERT INTO incidents
                    (id, scenario, reporter, evidence_summary, finding_json, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    payload.scenario,
                    payload.reporter,
                    payload.evidence_summary,
                    _json(finding),
                    "finding_received",
                    created_at,
                ),
            )
        _record_event(
            database_path,
            incident_id,
            "finding_received",
            payload.reporter,
            {"scenario": payload.scenario, "evidence_summary": payload.evidence_summary},
        )
        return _decode_incident(
            _get_row(database_path, "SELECT * FROM incidents WHERE id = ?", (incident_id,))
        )

    @app.post("/findings", status_code=201, dependencies=[Depends(require_operator)])
    def intake_finding(payload: NormalizedFindingCreate) -> dict:
        """Accept the shared finding shape and map only supported demo scenarios."""
        existing = None
        with get_connection(database_path) as connection:
            existing = connection.execute(
                "SELECT * FROM incidents WHERE source_finding_id = ?",
                (payload.finding_id,),
            ).fetchone()
        if existing is not None:
            result = _decode_incident(dict(existing))
            result["duplicate"] = True
            return result

        scenario_by_category = {
            "sqli": "search_sqli",
            "path_traversal": "path_traversal",
        }
        scenario = scenario_by_category.get(payload.category, "unmapped")
        incident_id = str(uuid4())
        created_at = _now()
        finding = payload.model_dump()
        status = "finding_received"
        with get_connection(database_path) as connection:
            connection.execute(
                """
                INSERT INTO incidents
                    (id, scenario, reporter, evidence_summary, finding_json,
                     source_finding_id, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    scenario,
                    payload.reporter,
                    payload.evidence_summary,
                    _json(finding),
                    payload.finding_id,
                    status,
                    created_at,
                ),
            )
        _record_event(
            database_path,
            incident_id,
            "normalized_finding_received",
            payload.reporter,
            {
                "finding_id": payload.finding_id,
                "category": payload.category,
                "severity": payload.severity,
                "mapping": scenario if scenario != "unmapped" else "unsupported_demo_scenario",
            },
        )
        result = _decode_incident(
            _get_row(database_path, "SELECT * FROM incidents WHERE id = ?", (incident_id,))
        )
        result["duplicate"] = False
        result["mapped"] = scenario != "unmapped"
        return result

    @app.get("/incidents", dependencies=[Depends(require_operator)])
    def list_incidents() -> dict:
        with get_connection(database_path) as connection:
            rows = connection.execute(
                "SELECT * FROM incidents ORDER BY created_at DESC"
            ).fetchall()
        return {"incidents": [_decode_incident(dict(row)) for row in rows]}

    @app.get("/incidents/{incident_id}", dependencies=[Depends(require_operator)])
    def get_incident(incident_id: str) -> dict:
        incident = _get_row(
            database_path,
            "SELECT * FROM incidents WHERE id = ?",
            (incident_id,),
        )
        with get_connection(database_path) as connection:
            proposal = connection.execute(
                "SELECT * FROM proposals WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
        incident = _decode_incident(incident)
        incident["proposal"] = dict(proposal) if proposal else None
        if proposal is not None:
            with get_connection(database_path) as connection:
                decision = connection.execute(
                    "SELECT * FROM decisions WHERE proposal_id = ?",
                    (proposal["id"],),
                ).fetchone()
                receipt = connection.execute(
                    "SELECT receipt_json FROM operation_receipts WHERE proposal_id = ?",
                    (proposal["id"],),
                ).fetchone()
            incident["decision"] = dict(decision) if decision else None
            incident["operation_receipt"] = (
                json.loads(receipt["receipt_json"]) if receipt else None
            )
        else:
            incident["decision"] = None
            incident["operation_receipt"] = None
        with get_connection(database_path) as connection:
            releases = connection.execute(
                """
                SELECT rp.*, rd.decision AS release_decision,
                       rd.actor AS release_actor, rd.decided_at,
                       rr.receipt_json
                FROM release_proposals rp
                LEFT JOIN release_decisions rd ON rd.release_proposal_id = rp.id
                LEFT JOIN release_receipts rr ON rr.release_proposal_id = rp.id
                WHERE rp.incident_id = ? ORDER BY rp.created_at
                """,
                (incident_id,),
            ).fetchall()
            patch_rows = connection.execute(
                "SELECT result_json, created_at FROM patch_test_results "
                "WHERE incident_id = ? ORDER BY created_at",
                (incident_id,),
            ).fetchall()
        incident["releases"] = [_decode_release(dict(row)) for row in releases]
        incident["patch_tests"] = [
            {"result": json.loads(row["result_json"]), "created_at": row["created_at"]}
            for row in patch_rows
        ]
        return incident

    @app.post(
        "/incidents/{incident_id}/analyze",
        dependencies=[Depends(require_operator)],
    )
    def analyze_incident(incident_id: str) -> dict:
        incident = _get_row(
            database_path,
            "SELECT * FROM incidents WHERE id = ?",
            (incident_id,),
        )
        with get_connection(database_path) as connection:
            existing = connection.execute(
                "SELECT * FROM proposals WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
        if existing is not None:
            return dict(existing)

        if incident["scenario"] not in SCENARIOS:
            raise HTTPException(
                status_code=422,
                detail={"code": "finding_mapping_unavailable", "message": "This finding is stored, but no safe demo action is mapped."},
            )
        try:
            finding = json.loads(incident.get("finding_json") or "{}")
        except (TypeError, json.JSONDecodeError):
            finding = {}
        if finding.get("status") == "suspected":
            raise HTTPException(
                status_code=409,
                detail={"code": "finding_not_reproduced", "message": "Reproduce the finding before preparing a change."},
            )
        mapping = SCENARIOS[incident["scenario"]]
        observe_before_change(incident)
        target_environment = _target_environment(settings)
        expected_flags = current_flag_states(
            (mapping["safe_flag"], mapping["vulnerable_flag"])
        )
        proposal_id = str(uuid4())
        created_at = _now()
        expires_at = (datetime.now(UTC) + timedelta(minutes=15)).isoformat()
        digest = _proposal_hash(
            proposal_id=proposal_id,
            incident_id=incident_id,
            scenario=incident["scenario"],
            safe_flag=mapping["safe_flag"],
            vulnerable_flag=mapping["vulnerable_flag"],
            target_environment=target_environment,
            expected_flags=expected_flags,
            expires_at=expires_at,
        )
        with get_connection(database_path) as connection:
            connection.execute(
                """
                INSERT INTO proposals
                    (id, incident_id, safe_flag, vulnerable_flag,
                     target_environment, expected_flags_json, proposal_hash,
                     status, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    proposal_id,
                    incident_id,
                    mapping["safe_flag"],
                    mapping["vulnerable_flag"],
                    target_environment,
                    _json(expected_flags),
                    digest,
                    "pending_approval",
                    expires_at,
                    created_at,
                ),
            )
            connection.execute(
                "UPDATE incidents SET status = ? WHERE id = ?",
                ("pending_approval", incident_id),
            )
        _record_event(
            database_path,
            incident_id,
            "proposal_created",
            "local_analyzer",
            {
                "proposal_id": proposal_id,
                "safe_flag": mapping["safe_flag"],
                "vulnerable_flag": mapping["vulnerable_flag"],
                "target_environment": target_environment,
                "expected_flags": expected_flags,
                "proposal_hash": digest,
                "expires_at": expires_at,
            },
        )
        return _get_row(
            database_path,
            "SELECT * FROM proposals WHERE id = ?",
            (proposal_id,),
        )

    @app.post(
        "/proposals/{proposal_id}/decision",
        dependencies=[Depends(require_operator)],
    )
    def decide_proposal(proposal_id: str, payload: DecisionCreate) -> dict:
        proposal = _get_row(
            database_path,
            "SELECT * FROM proposals WHERE id = ?",
            (proposal_id,),
        )
        if payload.proposal_hash != proposal["proposal_hash"]:
            raise HTTPException(status_code=409, detail={"code": "proposal_hash_mismatch"})
        _ensure_unexpired(proposal)
        if proposal["status"] != "pending_approval":
            raise HTTPException(status_code=409, detail={"code": "proposal_not_pending"})

        decision_id = str(uuid4())
        decided_at = _now()
        with get_connection(database_path) as connection:
            updated = connection.execute(
                "UPDATE proposals SET status = ? WHERE id = ? AND status = 'pending_approval'",
                ("approved" if payload.decision == "approve" else "rejected", proposal_id),
            ).rowcount
            if updated != 1:
                raise HTTPException(status_code=409, detail={"code": "proposal_not_pending"})
            connection.execute(
                """
                INSERT INTO decisions
                    (id, proposal_id, decision, actor, proposal_hash, reason, decided_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    decision_id,
                    proposal_id,
                    payload.decision,
                    payload.actor,
                    payload.proposal_hash,
                    payload.reason,
                    decided_at,
                ),
            )
            connection.execute(
                "UPDATE incidents SET status = ? WHERE id = ?",
                ("approved" if payload.decision == "approve" else "rejected", proposal["incident_id"]),
            )
        _record_event(
            database_path,
            proposal["incident_id"],
            "proposal_approved" if payload.decision == "approve" else "proposal_rejected",
            payload.actor,
            {
                "proposal_id": proposal_id,
                "proposal_hash": payload.proposal_hash,
                "reason": payload.reason,
            },
        )
        return _get_row(
            database_path,
            "SELECT * FROM decisions WHERE id = ?",
            (decision_id,),
        )

    @app.post(
        "/proposals/{proposal_id}/apply",
        dependencies=[Depends(require_operator)],
    )
    def apply_proposal(proposal_id: str, payload: ApplyRequest) -> dict:
        proposal = _get_row(
            database_path,
            "SELECT * FROM proposals WHERE id = ?",
            (proposal_id,),
        )
        if proposal["target_environment"] != _target_environment(settings):
            raise HTTPException(
                status_code=409,
                detail={"code": "proposal_environment_changed"},
            )
        try:
            expected_flags = json.loads(proposal["expected_flags_json"])
        except (KeyError, TypeError, json.JSONDecodeError):
            raise HTTPException(
                status_code=409,
                detail={"code": "proposal_snapshot_invalid"},
            ) from None
        recalculated_hash = _proposal_hash(
            proposal_id=proposal["id"],
            incident_id=proposal["incident_id"],
            scenario=_get_row(
                database_path,
                "SELECT scenario FROM incidents WHERE id = ?",
                (proposal["incident_id"],),
            )["scenario"],
            safe_flag=proposal["safe_flag"],
            vulnerable_flag=proposal["vulnerable_flag"],
            target_environment=proposal["target_environment"],
            expected_flags=expected_flags,
            expires_at=proposal["expires_at"],
        )
        if (
            not hmac.compare_digest(payload.proposal_hash, proposal["proposal_hash"])
            or not hmac.compare_digest(recalculated_hash, proposal["proposal_hash"])
        ):
            raise HTTPException(status_code=409, detail={"code": "proposal_hash_mismatch"})

        with get_connection(database_path) as connection:
            existing = connection.execute(
                "SELECT receipt_json FROM operation_receipts WHERE proposal_id = ?",
                (proposal_id,),
            ).fetchone()
            decision = connection.execute(
                "SELECT * FROM decisions WHERE proposal_id = ?",
                (proposal_id,),
            ).fetchone()
        if existing is not None:
            return json.loads(existing["receipt_json"])
        if proposal["status"] != "approved":
            raise HTTPException(status_code=409, detail={"code": "proposal_not_approved"})
        if decision is None or decision["decision"] != "approve":
            raise HTTPException(status_code=409, detail={"code": "approval_required"})
        if decision["proposal_hash"] != proposal["proposal_hash"]:
            raise HTTPException(status_code=409, detail={"code": "approval_hash_mismatch"})
        _ensure_unexpired(proposal)

        vulnerable_flag = proposal["vulnerable_flag"]
        safe_flag = proposal["safe_flag"]
        flag_names = (vulnerable_flag, safe_flag)
        try:
            prior_states = current_flag_states(flag_names)
        except HTTPException:
            with get_connection(database_path) as connection:
                connection.execute("UPDATE proposals SET status = 'approved' WHERE id = ?", (proposal_id,))
            raise
        if prior_states != expected_flags:
            with get_connection(database_path) as connection:
                connection.execute(
                    "UPDATE proposals SET status = ? WHERE id = ?",
                    ("stale", proposal_id),
                )
                connection.execute(
                    "UPDATE incidents SET status = ? WHERE id = ?",
                    ("proposal_stale", proposal["incident_id"]),
                )
            _record_event(
                database_path,
                proposal["incident_id"],
                "proposal_stale",
                "approval_executor",
                {"proposal_id": proposal_id, "expected": expected_flags, "observed": prior_states},
            )
            raise HTTPException(status_code=409, detail={"code": "flag_state_changed"})

        # Reserve the one-shot operation before contacting Flagsmith. A duplicate
        # request can then return the saved receipt instead of applying twice.
        with get_connection(database_path) as connection:
            claimed = connection.execute(
                "UPDATE proposals SET status = 'applying' WHERE id = ? AND status = 'approved'",
                (proposal_id,),
            ).rowcount
        if claimed != 1:
            with get_connection(database_path) as connection:
                saved = connection.execute(
                    "SELECT receipt_json FROM operation_receipts WHERE proposal_id = ?",
                    (proposal_id,),
                ).fetchone()
            if saved is not None:
                return json.loads(saved["receipt_json"])
            raise HTTPException(status_code=409, detail={"code": "operation_already_in_progress"})

        # Read the snapshot again after reserving the operation so a change made
        # while the approval request was waiting cannot silently go stale.
        try:
            prior_states = current_flag_states(flag_names)
        except HTTPException:
            with get_connection(database_path) as connection:
                connection.execute("UPDATE proposals SET status = 'approved' WHERE id = ?", (proposal_id,))
            raise
        if prior_states != expected_flags:
            with get_connection(database_path) as connection:
                connection.execute("UPDATE proposals SET status = 'stale' WHERE id = ?", (proposal_id,))
                connection.execute(
                    "UPDATE incidents SET status = 'proposal_stale' WHERE id = ?",
                    (proposal["incident_id"],),
                )
            _record_event(
                database_path,
                proposal["incident_id"],
                "proposal_stale",
                "approval_executor",
                {"proposal_id": proposal_id, "expected": expected_flags, "observed": prior_states},
            )
            raise HTTPException(status_code=409, detail={"code": "flag_state_changed"})

        actor = decision["actor"]
        adapter_name = (
            "flagsmith_management_api"
            if settings.flag_adapter == "flagsmith"
            else "local_sqlite_demo"
        )
        error_code: str | None = None
        error_status_code: int | None = None
        if settings.flag_adapter == "flagsmith":
            try:
                adapter = management_client()
                adapter.set_flag_enabled(vulnerable_flag, False)
                after_states = current_flag_states(flag_names)
            except FlagsmithIntegrationError as exc:
                error_code = exc.code
                error_status_code = exc.status_code
                try:
                    after_states = current_flag_states(flag_names)
                except HTTPException:
                    after_states = {}
            except HTTPException as exc:
                error = exc.detail
                error_code = error.get("code", "flagsmith_unavailable") if isinstance(error, dict) else "flagsmith_unavailable"
                try:
                    after_states = current_flag_states(flag_names)
                except HTTPException:
                    after_states = {}
        else:
            set_demo_flag_overrides(
                database_path,
                {vulnerable_flag: False},
                actor=actor,
            )
            after_states = current_flag_states(flag_names)

        readback_verified = (
            after_states.get(vulnerable_flag) == FeatureState.DISABLED.value
            and error_code is None
        )
        receipt = {
            "operation_id": str(uuid4()),
            "proposal_id": proposal_id,
            "proposal_hash": proposal["proposal_hash"],
            "adapter": adapter_name,
            "environment": proposal["target_environment"],
            "before": prior_states,
            "after": after_states,
            "readback_verified": readback_verified,
            "operation": "disable_vulnerable_flag_only",
            "safe_flag_unchanged": True,
            "executed_at": _now(),
        }
        if error_code is not None:
            receipt["error_code"] = error_code
        if error_status_code is not None:
            receipt["error_status_code"] = error_status_code
        with get_connection(database_path) as connection:
            inserted = connection.execute(
                """
                INSERT OR IGNORE INTO operation_receipts
                    (id, proposal_id, receipt_json, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (receipt["operation_id"], proposal_id, _json(receipt), receipt["executed_at"]),
            ).rowcount
            saved = connection.execute(
                "SELECT receipt_json FROM operation_receipts WHERE proposal_id = ?",
                (proposal_id,),
            ).fetchone()
            connection.execute(
                "UPDATE proposals SET status = ? WHERE id = ?",
                ("applied" if readback_verified else "apply_failed", proposal_id),
            )
            connection.execute(
                "UPDATE incidents SET status = ? WHERE id = ?",
                (
                    "verification_pending" if readback_verified else "apply_failed",
                    proposal["incident_id"],
                ),
            )
        if inserted:
            _record_event(
                database_path,
                proposal["incident_id"],
                "flag_change_applied" if readback_verified else "flag_change_failed",
                actor,
                receipt,
            )
        saved_receipt = json.loads(saved["receipt_json"])
        if not saved_receipt["readback_verified"]:
            raise HTTPException(
                status_code=502,
                detail={
                    "code": saved_receipt.get("error_code", "flag_readback_failed"),
                    "receipt": saved_receipt,
                },
            )
        return saved_receipt

    @app.post(
        "/incidents/{incident_id}/verify",
        dependencies=[Depends(require_operator)],
    )
    async def verify_incident(incident_id: str):
        incident = _get_row(
            database_path,
            "SELECT * FROM incidents WHERE id = ?",
            (incident_id,),
        )
        with get_connection(database_path) as connection:
            proposal_row = connection.execute(
                "SELECT * FROM proposals WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
            receipt_row = connection.execute(
                """
                SELECT r.receipt_json FROM operation_receipts r
                JOIN proposals p ON p.id = r.proposal_id
                WHERE p.incident_id = ?
                """,
                (incident_id,),
            ).fetchone()
        if proposal_row is None or receipt_row is None:
            raise HTTPException(status_code=409, detail={"code": "approved_apply_required"})

        proposal = dict(proposal_row)
        receipt = json.loads(receipt_row["receipt_json"])
        provider = flag_provider()
        if not receipt["readback_verified"]:
            raise HTTPException(status_code=409, detail={"code": "vulnerable_flag_not_read_back"})
        vulnerable_flag_state = provider.get_state(proposal["vulnerable_flag"])
        if vulnerable_flag_state is FeatureState.UNKNOWN:
            result = {
                "status": "unknown",
                "reason": "demo_app_flag_evaluation_unknown",
                "observed_at": _now(),
            }
            _set_incident_status(database_path, incident_id, "verification_unavailable")
            _record_event(
                database_path,
                incident_id,
                "verification_unavailable",
                "local_verifier",
                result,
            )
            return JSONResponse(status_code=503, content=result)
        if vulnerable_flag_state is not FeatureState.DISABLED:
            checks = {"vulnerable_flag_evaluated_disabled": False}
            result = {"status": "failed", "checks": checks, "observed_at": _now()}
            _set_incident_status(database_path, incident_id, "verification_failed")
            _record_event(
                database_path,
                incident_id,
                "post_change_verification",
                "local_verifier",
                result,
            )
            return JSONResponse(status_code=409, content=result)

        try:
            async with httpx.AsyncClient(
                base_url=app.state.demo_app_url,
                timeout=2.0,
            ) as client:
                status_response = await client.get("/status")
                if incident["scenario"] == "search_sqli":
                    attack_response = await client.get(
                        "/search",
                        params={"q": "' OR 1=1 -- "},
                    )
                    attack_payload = attack_response.json()
                    route_flags_known = _flag_evaluation_known(
                        attack_payload, ("search_v1", "search_v2")
                    )
                    checks = {
                        "route_flags_evaluated": route_flags_known,
                        "vulnerable_flag_disabled": vulnerable_flag_state is FeatureState.DISABLED,
                        "safe_or_fallback_variant_served": (
                            attack_response.status_code == 200
                            and attack_payload.get("variant") in {"search_v2", "safe_fallback"}
                        ),
                        "injection_returns_no_rows": attack_payload.get("count") == 0,
                        "unrelated_status_route_healthy": (
                            status_response.status_code == 200
                            and status_response.json().get("status") == "operational"
                        ),
                    }
                else:
                    traversal_response = await client.get(
                        "/files",
                        params={"path": "../private/internal_note.txt"},
                    )
                    public_response = await client.get(
                        "/files",
                        params={"path": "readme.txt"},
                    )
                    public_payload = public_response.json()
                    route_flags_known = _flag_evaluation_known(
                        public_payload, ("files_v1", "files_v2")
                    )
                    checks = {
                        "route_flags_evaluated": route_flags_known,
                        "vulnerable_flag_disabled": vulnerable_flag_state is FeatureState.DISABLED,
                        "safe_or_fallback_variant_served": (
                            public_response.status_code == 200
                            and public_payload.get("variant") in {"files_v2", "safe_fallback"}
                        ),
                        "traversal_blocked": traversal_response.status_code == 404,
                        "unrelated_status_route_healthy": (
                            status_response.status_code == 200
                            and status_response.json().get("status") == "operational"
                        ),
                    }
        except (httpx.RequestError, ValueError):
            result = {"status": "unknown", "reason": "demo_app_unreachable"}
            _set_incident_status(database_path, incident_id, "verification_unavailable")
            _record_event(
                database_path,
                incident_id,
                "verification_unavailable",
                "local_verifier",
                result,
            )
            return JSONResponse(status_code=503, content=result)

        passed = all(checks.values())
        evaluation_unknown = not checks.get("route_flags_evaluated", True)
        result = {
            "status": "unknown" if evaluation_unknown else "verified" if passed else "failed",
            "checks": checks,
            "observed_at": _now(),
        }
        state = (
            "verification_unavailable"
            if evaluation_unknown
            else "verified"
            if passed
            else "verification_failed"
        )
        _set_incident_status(database_path, incident_id, state)
        _record_event(
            database_path,
            incident_id,
            "verification_unavailable" if evaluation_unknown else "post_change_verification",
            "local_verifier",
            result,
        )
        return JSONResponse(
            status_code=503 if evaluation_unknown else 200 if passed else 409,
            content=result,
        )

    @app.post(
        "/incidents/{incident_id}/patch",
        dependencies=[Depends(require_operator)],
    )
    def propose_patch(incident_id: str) -> dict:
        incident = _get_row(
            database_path,
            "SELECT * FROM incidents WHERE id = ?",
            (incident_id,),
        )
        proposal = _get_row(
            database_path,
            "SELECT * FROM proposals WHERE incident_id = ?",
            (incident_id,),
        )
        if incident["status"] != "verified":
            raise HTTPException(
                status_code=409,
                detail={"code": "containment_verification_required"},
            )

        patch = _read_demo_patch(incident["scenario"])
        result = {
            "status": "candidate_available",
            "incident_id": incident_id,
            "safe_variant": proposal["safe_flag"],
            **patch,
            "already_present_in_demo_app": True,
            "applied": False,
            "patch_test_status": "not_run",
            "note": "The safe demo variant exists in the app; no deployment was performed.",
        }
        _record_event(
            database_path,
            incident_id,
            "patch_candidate_reported",
            "local_patch_advisor",
            {key: value for key, value in result.items() if key != "diff"},
        )
        return result

    @app.post(
        "/incidents/{incident_id}/patch/test",
        dependencies=[Depends(require_operator)],
    )
    def test_patch(incident_id: str) -> dict:
        incident = _get_row(database_path, "SELECT * FROM incidents WHERE id = ?", (incident_id,))
        proposal = _get_row(database_path, "SELECT * FROM proposals WHERE incident_id = ?", (incident_id,))
        if incident["status"] != "verified":
            raise HTTPException(status_code=409, detail={"code": "containment_verification_required"})
        checks: dict[str, bool] = {}
        if incident["scenario"] == "search_sqli":
            checks = {
                "injection_query_returns_no_rows": len(search_documents(database_path, "' OR 1=1 -- ")) == 0,
                "normal_synthetic_search_still_works": len(search_documents(database_path, "demo_user_01")) == 1,
            }
        elif incident["scenario"] == "path_traversal":
            checks = {
                "traversal_path_is_not_readable": read_public_demo_file("../private/internal_note.txt") is None,
                "public_demo_file_still_works": read_public_demo_file("readme.txt") is not None,
            }
        else:
            raise HTTPException(status_code=422, detail={"code": "patch_scenario_unsupported"})

        vulnerable_state = flag_provider().get_state(proposal["vulnerable_flag"])
        checks["vulnerable_flag_is_disabled"] = vulnerable_state is FeatureState.DISABLED
        observation = evaluate_demo_identity(incident, demo_identities[0])
        checks["running_demo_route_is_safe"] = (
            observation.get("status") == "observed"
            and observation.get("variant") in {proposal["safe_flag"], "safe_fallback"}
        )
        passed = all(checks.values())
        result = {
            "status": "passed" if passed else "failed",
            "scenario": incident["scenario"],
            "checks": checks,
            "runtime_observation": observation,
            "observed_at": _now(),
            "execution": "fixed built-in synthetic checks; no shell commands executed",
        }
        created_at = _now()
        with get_connection(database_path) as connection:
            connection.execute(
                "INSERT INTO patch_test_results (id, incident_id, result_json, created_at) VALUES (?, ?, ?, ?)",
                (str(uuid4()), incident_id, _json(result), created_at),
            )
        _record_event(database_path, incident_id, "patch_test_result", "local_patch_tester", result)
        return result

    @app.post(
        "/incidents/{incident_id}/rollout",
        dependencies=[Depends(require_operator)],
    )
    def propose_rollout(incident_id: str, payload: RolloutRequest) -> dict:
        incident = _get_row(
            database_path,
            "SELECT id, status FROM incidents WHERE id = ?",
            (incident_id,),
        )
        if incident["status"] != "verified":
            raise HTTPException(
                status_code=409,
                detail={"code": "containment_verification_required"},
            )
        _expire_release_proposals(database_path, incident_id)
        with get_connection(database_path) as connection:
            latest_test = connection.execute(
                "SELECT result_json FROM patch_test_results WHERE incident_id = ? ORDER BY created_at DESC LIMIT 1",
                (incident_id,),
            ).fetchone()
            active_release = connection.execute(
                "SELECT id FROM release_proposals WHERE incident_id = ? "
                "AND status IN ('pending_approval', 'approved', 'applying') LIMIT 1",
                (incident_id,),
            ).fetchone()
        if latest_test is None or json.loads(latest_test["result_json"]).get("status") != "passed":
            raise HTTPException(status_code=409, detail={"code": "patch_test_must_pass"})
        if active_release is not None:
            raise HTTPException(status_code=409, detail={"code": "release_change_already_pending"})

        incident_row = _get_row(database_path, "SELECT scenario FROM incidents WHERE id = ?", (incident_id,))
        scenario = incident_row["scenario"]
        if scenario not in SCENARIOS:
            raise HTTPException(status_code=422, detail={"code": "finding_mapping_unavailable"})
        safe_flag = SCENARIOS[scenario]["safe_flag"]
        vulnerable_flag = SCENARIOS[scenario]["vulnerable_flag"]
        states = current_flag_states((safe_flag, vulnerable_flag))
        if states.get(vulnerable_flag) != FeatureState.DISABLED.value:
            raise HTTPException(status_code=409, detail={"code": "containment_not_active"})
        if states.get(safe_flag) != FeatureState.DISABLED.value:
            raise HTTPException(status_code=409, detail={"code": "safe_flag_default_must_be_disabled"})

        ranking = sorted(
            demo_identities,
            key=lambda identity: hashlib.sha256(f"{incident_id}:{identity}".encode("utf-8")).hexdigest(),
        )
        selected_count = (len(ranking) * payload.percentage + 99) // 100
        selected = set(ranking[:selected_count])
        before = identity_overrides(safe_flag)
        desired = {identity: identity in selected for identity in demo_identities}
        release = create_release_proposal(
            incident_id=incident_id,
            action="rollout",
            percentage=payload.percentage,
            safe_flag=safe_flag,
            before=before,
            desired=desired,
        )
        release["eligible_count"] = len(demo_identities)
        release["selected_count"] = selected_count
        release["selected_identities"] = sorted(selected)
        release["deterministic"] = True
        release["status"] = "pending_approval"
        return release

    @app.post(
        "/release-proposals/{proposal_id}/decision",
        dependencies=[Depends(require_operator)],
    )
    def decide_release(proposal_id: str, payload: ReleaseDecisionCreate) -> dict:
        release = _get_row(database_path, "SELECT * FROM release_proposals WHERE id = ?", (proposal_id,))
        if release["target_environment"] != _target_environment(settings):
            raise HTTPException(status_code=409, detail={"code": "proposal_environment_changed"})
        if not hmac.compare_digest(payload.proposal_hash, release["proposal_hash"]):
            raise HTTPException(status_code=409, detail={"code": "proposal_hash_mismatch"})
        _ensure_release_unexpired(database_path, release)
        if release["status"] != "pending_approval":
            raise HTTPException(status_code=409, detail={"code": "proposal_not_pending"})
        decision_id = str(uuid4())
        decided_at = _now()
        with get_connection(database_path) as connection:
            updated = connection.execute(
                "UPDATE release_proposals SET status = ? WHERE id = ? AND status = 'pending_approval'",
                ("approved" if payload.decision == "approve" else "rejected", proposal_id),
            ).rowcount
            if updated != 1:
                raise HTTPException(status_code=409, detail={"code": "proposal_not_pending"})
            connection.execute(
                """INSERT INTO release_decisions
                   (id, release_proposal_id, decision, actor, proposal_hash, reason, decided_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (decision_id, proposal_id, payload.decision, payload.actor,
                 payload.proposal_hash, payload.reason, decided_at),
            )
        _record_event(
            database_path,
            release["incident_id"],
            "release_approved" if payload.decision == "approve" else "release_rejected",
            payload.actor,
            {"release_proposal_id": proposal_id, "proposal_hash": payload.proposal_hash},
        )
        return _get_row(database_path, "SELECT * FROM release_decisions WHERE id = ?", (decision_id,))

    @app.post(
        "/release-proposals/{proposal_id}/apply",
        dependencies=[Depends(require_operator)],
    )
    def apply_release(proposal_id: str, payload: ReleaseApplyRequest) -> dict:
        release = _get_row(database_path, "SELECT * FROM release_proposals WHERE id = ?", (proposal_id,))
        before = json.loads(release["before_overrides_json"])
        desired = json.loads(release["desired_identities_json"])
        expected_hash = _release_hash(
            release_id=release["id"],
            incident_id=release["incident_id"],
            action=release["action"],
            percentage=release["percentage"],
            safe_flag=release["safe_flag"],
            environment=release["target_environment"],
            before=before,
            desired=desired,
            expires_at=release["expires_at"],
        )
        if (
            release["target_environment"] != _target_environment(settings)
            or not hmac.compare_digest(payload.proposal_hash, release["proposal_hash"])
            or not hmac.compare_digest(expected_hash, release["proposal_hash"])
        ):
            raise HTTPException(status_code=409, detail={"code": "proposal_hash_or_environment_mismatch"})
        with get_connection(database_path) as connection:
            existing = connection.execute(
                "SELECT receipt_json FROM release_receipts WHERE release_proposal_id = ?",
                (proposal_id,),
            ).fetchone()
            decision = connection.execute(
                "SELECT * FROM release_decisions WHERE release_proposal_id = ?",
                (proposal_id,),
            ).fetchone()
        if existing is not None:
            return json.loads(existing["receipt_json"])
        _ensure_release_unexpired(database_path, release)
        if release["status"] != "approved" or decision is None or decision["decision"] != "approve":
            raise HTTPException(status_code=409, detail={"code": "approval_required"})
        if decision["proposal_hash"] != release["proposal_hash"]:
            raise HTTPException(status_code=409, detail={"code": "approval_hash_mismatch"})
        try:
            current = identity_overrides(release["safe_flag"])
        except HTTPException:
            with get_connection(database_path) as connection:
                connection.execute("UPDATE release_proposals SET status = 'approved' WHERE id = ?", (proposal_id,))
            raise
        if current != before:
            with get_connection(database_path) as connection:
                connection.execute("UPDATE release_proposals SET status = 'stale' WHERE id = ?", (proposal_id,))
            _record_event(database_path, release["incident_id"], "release_proposal_stale", "release_executor", {"release_proposal_id": proposal_id})
            raise HTTPException(status_code=409, detail={"code": "identity_state_changed"})
        with get_connection(database_path) as connection:
            claimed = connection.execute(
                "UPDATE release_proposals SET status = 'applying' WHERE id = ? AND status = 'approved'",
                (proposal_id,),
            ).rowcount
        if claimed != 1:
            raise HTTPException(status_code=409, detail={"code": "operation_already_in_progress"})

        try:
            current = identity_overrides(release["safe_flag"])
        except HTTPException:
            with get_connection(database_path) as connection:
                connection.execute("UPDATE release_proposals SET status = 'approved' WHERE id = ?", (proposal_id,))
            raise
        if current != before:
            with get_connection(database_path) as connection:
                connection.execute("UPDATE release_proposals SET status = 'stale' WHERE id = ?", (proposal_id,))
            _record_event(database_path, release["incident_id"], "release_proposal_stale", "release_executor", {"release_proposal_id": proposal_id})
            raise HTTPException(status_code=409, detail={"code": "identity_state_changed"})

        error_code = None
        try:
            observed_overrides = apply_identity_overrides(
                release["safe_flag"], desired, actor=decision["actor"]
            )
        except (FlagsmithIntegrationError, HTTPException) as exc:
            if isinstance(exc, HTTPException):
                detail = exc.detail
                error_code = detail.get("code", "identity_override_failed") if isinstance(detail, dict) else "identity_override_failed"
            else:
                error_code = exc.code
            try:
                observed_overrides = identity_overrides(release["safe_flag"])
            except HTTPException:
                observed_overrides = {}
        incident_for_eval = _get_row(database_path, "SELECT * FROM incidents WHERE id = ?", (release["incident_id"],))
        evaluations = [evaluate_demo_identity(incident_for_eval, identity) for identity in demo_identities]
        expected_safe_variant = SCENARIOS[incident_for_eval["scenario"]]["safe_flag"]
        evaluation_checks = {
            item["identity"]: (
                item["status"] == "observed"
                and item["variant"] == (expected_safe_variant if desired.get(item["identity"]) else "safe_fallback")
            )
            for item in evaluations
        }
        evaluation_unknowns = [
            item["identity"] for item in evaluations if item["status"] == "unknown"
        ]
        guardrail_violations = [
            item["identity"]
            for item in evaluations
            if item["status"] == "observed"
            and not evaluation_checks[item["identity"]]
        ]
        verified = observed_overrides == desired and all(evaluation_checks.values()) and error_code is None
        guardrail_status = "passed" if verified else "violated" if guardrail_violations else "unknown"
        if error_code is None and evaluation_unknowns:
            error_code = "demo_identity_evaluation_unknown"
        recommendation = (
            "continue"
            if verified
            else "rollback_proposed"
            if guardrail_violations
            else "retry_verification"
        )
        receipt = {
            "operation_id": str(uuid4()),
            "release_proposal_id": proposal_id,
            "proposal_hash": release["proposal_hash"],
            "action": release["action"],
            "percentage": release["percentage"],
            "environment": release["target_environment"],
            "before": current,
            "desired": desired,
            "after": observed_overrides,
            "evaluations": evaluations,
            "evaluation_checks": evaluation_checks,
            "evaluation_unknowns": evaluation_unknowns,
            "readback_verified": observed_overrides == desired,
            "app_evaluation_verified": all(evaluation_checks.values()),
            "app_evaluation_unknown": bool(evaluation_unknowns),
            "guardrail_status": guardrail_status,
            "guardrail_violations": guardrail_violations,
            "recommendation": recommendation,
            "status": "applied" if verified else "failed",
            "executed_at": _now(),
        }
        if error_code:
            receipt["error_code"] = error_code
        with get_connection(database_path) as connection:
            connection.execute(
                "INSERT INTO release_receipts (id, release_proposal_id, receipt_json, created_at) VALUES (?, ?, ?, ?)",
                (receipt["operation_id"], proposal_id, _json(receipt), receipt["executed_at"]),
            )
            connection.execute(
                "UPDATE release_proposals SET status = ? WHERE id = ?",
                ("applied" if verified else "apply_failed", proposal_id),
            )
        _record_event(
            database_path,
            release["incident_id"],
            "release_applied"
            if verified
            else "release_guardrail_violation"
            if guardrail_violations
            else "release_verification_unknown",
            decision["actor"],
            receipt,
        )
        if not verified:
            status_code = 503 if evaluation_unknowns and not guardrail_violations else 502
            raise HTTPException(status_code=status_code, detail={"code": error_code or "release_verification_failed", "receipt": receipt})
        return receipt

    @app.post(
        "/incidents/{incident_id}/rollouts/{release_id}/rollback",
        dependencies=[Depends(require_operator)],
    )
    def propose_rollback(incident_id: str, release_id: str) -> dict:
        source = _get_row(
            database_path,
            "SELECT * FROM release_proposals WHERE id = ? AND incident_id = ?",
            (release_id, incident_id),
        )
        if source["action"] != "rollout" or source["status"] not in {"applied", "apply_failed"}:
            raise HTTPException(status_code=409, detail={"code": "rollback_source_not_applied"})
        with get_connection(database_path) as connection:
            latest = connection.execute(
                "SELECT id FROM release_proposals WHERE incident_id = ? AND status IN ('applied', 'apply_failed') "
                "ORDER BY created_at DESC LIMIT 1",
                (incident_id,),
            ).fetchone()
        if latest is None or latest["id"] != release_id:
            raise HTTPException(status_code=409, detail={"code": "rollback_source_not_latest"})
        with get_connection(database_path) as connection:
            receipt = connection.execute(
                "SELECT receipt_json FROM release_receipts WHERE release_proposal_id = ?",
                (release_id,),
            ).fetchone()
        if receipt is None:
            raise HTTPException(status_code=409, detail={"code": "rollback_receipt_required"})
        _expire_release_proposals(database_path, incident_id)
        with get_connection(database_path) as connection:
            pending = connection.execute(
                "SELECT id FROM release_proposals WHERE incident_id = ? "
                "AND status IN ('pending_approval', 'approved', 'applying') LIMIT 1",
                (incident_id,),
            ).fetchone()
        if pending is not None:
            raise HTTPException(status_code=409, detail={"code": "release_change_already_pending"})
        current = identity_overrides(source["safe_flag"])
        desired = json.loads(source["before_overrides_json"])
        percentage = sum(value is True for value in desired.values()) * 100 // len(demo_identities)
        release = create_release_proposal(
            incident_id=incident_id,
            action="rollback",
            percentage=percentage,
            safe_flag=source["safe_flag"],
            before=current,
            desired=desired,
            source_release_id=release_id,
        )
        release["restores_release_id"] = release_id
        release["status"] = "pending_approval"
        return release

    @app.get("/incidents/{incident_id}/events", dependencies=[Depends(require_operator)])
    def list_events(incident_id: str) -> dict:
        _get_row(database_path, "SELECT id FROM incidents WHERE id = ?", (incident_id,))
        with get_connection(database_path) as connection:
            rows = connection.execute(
                "SELECT * FROM audit_events WHERE incident_id = ? ORDER BY id",
                (incident_id,),
            ).fetchall()
        events = []
        for row in rows:
            event = dict(row)
            event["payload"] = json.loads(event.pop("payload_json"))
            events.append(event)
        return {"incident_id": incident_id, "events": events}

    @app.get(
        "/incidents/{incident_id}/events/stream",
        dependencies=[Depends(require_operator)],
    )
    async def stream_events(incident_id: str, request: Request, after: int = 0):
        _get_row(database_path, "SELECT id FROM incidents WHERE id = ?", (incident_id,))

        async def generate():
            last_id = max(after, 0)
            heartbeat_at = asyncio.get_running_loop().time()
            while not await request.is_disconnected():
                with get_connection(database_path) as connection:
                    rows = connection.execute(
                        "SELECT * FROM audit_events WHERE incident_id = ? AND id > ? ORDER BY id",
                        (incident_id, last_id),
                    ).fetchall()
                for row in rows:
                    event = dict(row)
                    event["payload"] = json.loads(event.pop("payload_json"))
                    last_id = event["id"]
                    yield f"id: {last_id}\nevent: {event['event_type']}\ndata: {_json(event)}\n\n"
                now = asyncio.get_running_loop().time()
                if now - heartbeat_at >= 15:
                    yield ": keep-alive\n\n"
                    heartbeat_at = now
                await asyncio.sleep(1)

        return StreamingResponse(
            generate(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    @app.get("/telemetry", dependencies=[Depends(require_operator)])
    def telemetry() -> dict:
        return get_demo_telemetry(database_path, limit=100)

    @app.post("/telemetry/generate", dependencies=[Depends(require_operator)])
    async def generate_telemetry(payload: SyntheticTrafficRequest) -> dict:
        observations = []
        try:
            async with httpx.AsyncClient(base_url=app.state.demo_app_url, timeout=3.0) as client:
                for index in range(payload.requests):
                    identity = demo_identities[index % len(demo_identities)]
                    params = (
                        {"q": f"demo_user_{index % len(demo_identities) + 1:02d}", "identity": identity}
                        if payload.route == "/search"
                        else {"path": "readme.txt", "identity": identity}
                    )
                    response = await client.get(payload.route, params=params)
                    try:
                        body = response.json()
                    except ValueError:
                        body = {}
                    observations.append(
                        {
                            "identity": identity,
                            "status_code": response.status_code,
                            "variant": body.get("variant", "unknown") if isinstance(body, dict) else "unknown",
                        }
                    )
        except (httpx.RequestError, ValueError):
            raise HTTPException(status_code=503, detail={"code": "demo_app_unreachable"}) from None
        return {
            "data_label": "DEMO / SYNTHETIC DATA",
            "simulation": True,
            "requested": payload.requests,
            "completed": len(observations),
            "route": payload.route,
            "observations": observations,
        }

    @app.post("/demo/reset", dependencies=[Depends(require_operator)])
    def reset_demo() -> dict:
        if settings.flag_adapter != "local" or settings.environment != "local":
            raise HTTPException(
                status_code=409,
                detail={"code": "reset_local_adapter_only", "message": "Reset is available only for the local SQLite demo."},
            )
        with get_connection(database_path) as connection:
            for table in (
                "release_receipts",
                "release_decisions",
                "release_proposals",
                "operation_receipts",
                "decisions",
                "proposals",
                "patch_test_results",
                "audit_events",
                "incidents",
                "demo_request_events",
                "demo_feature_flags",
                "demo_identity_feature_flags",
            ):
                connection.execute(f"DELETE FROM {table}")
        set_demo_flag_overrides(
            database_path,
            {name: False for name in ("search_v1", "search_v2", "files_v1", "files_v2")},
            actor="local_demo_reset",
        )
        seed_demo_data(database_path)
        return {
            "status": "reset",
            "data_label": "DEMO / SYNTHETIC DATA",
            "records": "deterministic 20-user fixture retained and reseeded",
            "flags": "local SQLite overrides cleared; environment defaults are active",
        }

    @app.get("/incidents/{incident_id}/report", dependencies=[Depends(require_operator)])
    def incident_report(incident_id: str) -> dict:
        incident = _get_row(
            database_path,
            "SELECT * FROM incidents WHERE id = ?",
            (incident_id,),
        )
        with get_connection(database_path) as connection:
            proposal_row = connection.execute(
                "SELECT * FROM proposals WHERE incident_id = ?",
                (incident_id,),
            ).fetchone()
            decision_row = None
            receipt_row = None
            if proposal_row is not None:
                proposal_id = proposal_row["id"]
                decision_row = connection.execute(
                    "SELECT * FROM decisions WHERE proposal_id = ?",
                    (proposal_id,),
                ).fetchone()
                receipt_row = connection.execute(
                    "SELECT receipt_json FROM operation_receipts WHERE proposal_id = ?",
                    (proposal_id,),
                ).fetchone()
            event_rows = connection.execute(
                "SELECT * FROM audit_events WHERE incident_id = ? ORDER BY id",
                (incident_id,),
            ).fetchall()
            release_rows = connection.execute(
                """SELECT rp.*, rd.decision AS release_decision,
                          rd.actor AS release_actor, rd.decided_at, rr.receipt_json
                   FROM release_proposals rp
                   LEFT JOIN release_decisions rd ON rd.release_proposal_id = rp.id
                   LEFT JOIN release_receipts rr ON rr.release_proposal_id = rp.id
                   WHERE rp.incident_id = ? ORDER BY rp.created_at""",
                (incident_id,),
            ).fetchall()
            patch_rows = connection.execute(
                "SELECT result_json, created_at FROM patch_test_results WHERE incident_id = ? ORDER BY created_at",
                (incident_id,),
            ).fetchall()

        events = []
        for row in event_rows:
            event = dict(row)
            event["payload"] = json.loads(event.pop("payload_json"))
            events.append(event)
        return {
            "data_label": "DEMO / SYNTHETIC DATA",
            "incident": _decode_incident(incident),
            "proposal": dict(proposal_row) if proposal_row else None,
            "decision": dict(decision_row) if decision_row else None,
            "operation_receipt": (
                json.loads(receipt_row["receipt_json"]) if receipt_row else None
            ),
            "events": events,
            "releases": [_decode_release(dict(row)) for row in release_rows],
            "patch_tests": [
                {"result": json.loads(row["result_json"]), "created_at": row["created_at"]}
                for row in patch_rows
            ],
        }

    return app


def _set_incident_status(database_path: Path, incident_id: str, status: str) -> None:
    with get_connection(database_path) as connection:
        connection.execute(
            "UPDATE incidents SET status = ? WHERE id = ?",
            (status, incident_id),
        )
