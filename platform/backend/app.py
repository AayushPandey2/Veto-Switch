"""Local API for a persistent, human-approved containment demonstration."""

import hashlib
import hmac
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlparse
from uuid import uuid4

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse

from backend.database import initialize_platform_database
from backend.models import ApplyRequest, DecisionCreate, IncidentCreate, RolloutRequest
from demo_app.config import DemoSettings
from demo_app.database import (
    get_connection,
    set_demo_flag_overrides,
)
from demo_app.manifest import ROUTE_MANIFEST
from demo_app.feature_flags import FeatureFlagProvider, FeatureState
from backend.flagsmith_client import (
    FlagsmithIntegrationError,
    FlagsmithManagementClient,
)

SCENARIOS = {
    "search_sqli": {"safe_flag": "search_v2", "vulnerable_flag": "search_v1"},
    "path_traversal": {"safe_flag": "files_v2", "vulnerable_flag": "files_v1"},
}
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


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
        "version": 2,
        "proposal_id": proposal_id,
        "incident_id": incident_id,
        "scenario": scenario,
        "safe_flag": safe_flag,
        "safe_enabled": True,
        "vulnerable_flag": vulnerable_flag,
        "vulnerable_enabled": False,
        "target_environment": target_environment,
        "expected_flags": expected_flags,
        "expires_at": expires_at,
    }
    return hashlib.sha256(_json(content).encode("utf-8")).hexdigest()


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
            flagsmith_environment_key=settings.flagsmith_environment_key,
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
        states = current_flag_states(names, allow_missing=True)
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
        }

    @app.post("/incidents", status_code=201, dependencies=[Depends(require_operator)])
    def create_incident(payload: IncidentCreate) -> dict:
        incident_id = str(uuid4())
        created_at = _now()
        with get_connection(database_path) as connection:
            connection.execute(
                """
                INSERT INTO incidents
                    (id, scenario, reporter, evidence_summary, status, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    payload.scenario,
                    payload.reporter,
                    payload.evidence_summary,
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
        return _get_row(
            database_path,
            "SELECT * FROM incidents WHERE id = ?",
            (incident_id,),
        )

    @app.get("/incidents", dependencies=[Depends(require_operator)])
    def list_incidents() -> dict:
        with get_connection(database_path) as connection:
            rows = connection.execute(
                "SELECT * FROM incidents ORDER BY created_at DESC"
            ).fetchall()
        return {"incidents": [dict(row) for row in rows]}

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
                "UPDATE proposals SET status = ? WHERE id = ?",
                ("approved" if payload.decision == "approve" else "rejected", proposal_id),
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
        if decision is None or decision["decision"] != "approve":
            raise HTTPException(status_code=409, detail={"code": "approval_required"})
        if decision["proposal_hash"] != proposal["proposal_hash"]:
            raise HTTPException(status_code=409, detail={"code": "approval_hash_mismatch"})
        _ensure_unexpired(proposal)

        vulnerable_flag = proposal["vulnerable_flag"]
        safe_flag = proposal["safe_flag"]
        flag_names = (vulnerable_flag, safe_flag)
        prior_states = current_flag_states(flag_names)
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

        actor = decision["actor"]
        adapter_name = (
            "flagsmith_management_api"
            if settings.flag_adapter == "flagsmith"
            else "local_sqlite_demo"
        )
        error_code: str | None = None
        if settings.flag_adapter == "flagsmith":
            try:
                adapter = management_client()
                adapter.set_flag_enabled(vulnerable_flag, False)
                adapter.set_flag_enabled(safe_flag, True)
                after_states = current_flag_states(flag_names)
            except FlagsmithIntegrationError as exc:
                error_code = exc.code
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
                {vulnerable_flag: False, safe_flag: True},
                actor=actor,
            )
            after_states = current_flag_states(flag_names)

        readback_verified = (
            after_states.get(vulnerable_flag) == FeatureState.DISABLED.value
            and after_states.get(safe_flag) == FeatureState.ENABLED.value
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
            "executed_at": _now(),
        }
        if error_code is not None:
            receipt["error_code"] = error_code
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
            raise HTTPException(status_code=409, detail={"code": "safe_flag_not_read_back"})
        safe_flag_state = provider.get_state(proposal["safe_flag"])
        if safe_flag_state is FeatureState.UNKNOWN:
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
        if safe_flag_state is not FeatureState.ENABLED:
            checks = {"safe_flag_evaluated_enabled": False}
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
                    checks = {
                        "safe_variant_served": (
                            attack_response.status_code == 200
                            and attack_payload.get("variant") == "search_v2"
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
                    checks = {
                        "safe_variant_served": (
                            public_response.status_code == 200
                            and public_response.json().get("variant") == "files_v2"
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
        result = {
            "status": "verified" if passed else "failed",
            "checks": checks,
            "observed_at": _now(),
        }
        state = "verified" if passed else "verification_failed"
        _set_incident_status(database_path, incident_id, state)
        _record_event(
            database_path,
            incident_id,
            "post_change_verification",
            "local_verifier",
            result,
        )
        return JSONResponse(status_code=200 if passed else 409, content=result)

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

        result = {
            "status": "candidate_available",
            "safe_variant": proposal["safe_flag"],
            "already_present_in_demo_app": True,
            "applied": False,
            "note": "The safe demo variant exists in the app; no deployment was performed.",
        }
        _record_event(
            database_path,
            incident_id,
            "patch_candidate_reported",
            "local_patch_advisor",
            result,
        )
        return result

    @app.post(
        "/incidents/{incident_id}/rollout",
        dependencies=[Depends(require_operator)],
    )
    def propose_rollout(incident_id: str, payload: RolloutRequest) -> dict:
        _get_row(
            database_path,
            "SELECT id FROM incidents WHERE id = ?",
            (incident_id,),
        )
        result = {
            "status": "hold",
            "requested_percentage": payload.percentage,
            "applied": False,
            "reason": "staged_targeting_not_configured",
            "message": "No Flagsmith targeting change was made; staged rollout is not wired yet.",
        }
        _record_event(
            database_path,
            incident_id,
            "rollout_held",
            "rollout_gate",
            result,
        )
        return result

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

        events = []
        for row in event_rows:
            event = dict(row)
            event["payload"] = json.loads(event.pop("payload_json"))
            events.append(event)
        return {
            "data_label": "DEMO / SYNTHETIC DATA",
            "incident": incident,
            "proposal": dict(proposal_row) if proposal_row else None,
            "decision": dict(decision_row) if decision_row else None,
            "operation_receipt": (
                json.loads(receipt_row["receipt_json"]) if receipt_row else None
            ),
            "events": events,
        }

    return app


def _set_incident_status(database_path: Path, incident_id: str, status: str) -> None:
    with get_connection(database_path) as connection:
        connection.execute(
            "UPDATE incidents SET status = ? WHERE id = ?",
            (status, incident_id),
        )
