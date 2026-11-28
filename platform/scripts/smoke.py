"""Exercise the local platform end to end; real Flagsmith writes need typed approval."""

from __future__ import annotations

import argparse
import os
import sys
from uuid import uuid4

import httpx
from dotenv import load_dotenv


def require_ok(response: httpx.Response, step: str) -> dict:
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    if not response.is_success:
        detail = payload.get("detail", {}) if isinstance(payload, dict) else {}
        code = detail.get("code", f"http_{response.status_code}") if isinstance(detail, dict) else f"http_{response.status_code}"
        raise RuntimeError(f"{step} stopped safely ({code}). No success is assumed.")
    return payload


def approve(client: httpx.Client, path: str, release: dict, actor: str, real: bool) -> None:
    change = (
        f"{release.get('vulnerable_flag')} off"
        if release.get("vulnerable_flag")
        else f"{release.get('action')} {release.get('safe_flag')} to {release.get('percentage')}%"
    )
    if real:
        code = release["proposal_hash"][:12]
        typed = input(
            f"\nTarget {release.get('target_environment')}; proposed change: {change}.\n"
            f"Type APPROVE {code} to record this human decision: "
        ).strip()
        if typed != f"APPROVE {code}":
            raise RuntimeError("Operator did not approve this change; nothing was applied.")
    require_ok(
        client.post(
            path,
            json={
                "decision": "approve",
                "actor": actor,
                "proposal_hash": release["proposal_hash"],
                "reason": "Operator confirmed in the local smoke script.",
            },
        ),
        "record approval",
    )


def main() -> int:
    load_dotenv()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api-root", default="http://127.0.0.1:8000")
    parser.add_argument("--stage", type=int, choices=(5, 25, 50, 100), default=5)
    parser.add_argument(
        "--allow-real-flagsmith",
        action="store_true",
        help="Permit the script to use Flagsmith only after typed approval prompts.",
    )
    args = parser.parse_args()
    passphrase = os.getenv("KILLSWITCH_OPERATOR_PASSPHRASE", "")
    if not passphrase:
        print("Set KILLSWITCH_OPERATOR_PASSPHRASE in your private .env first.", file=sys.stderr)
        return 2

    with httpx.Client(
        base_url=args.api_root.rstrip("/"),
        headers={"X-Operator-Passphrase": passphrase},
        timeout=10.0,
    ) as client:
        health = require_ok(client.get("/health"), "check API health")
        if health.get("status") != "healthy":
            raise RuntimeError("The operator API is not healthy.")
        real = health.get("flag_adapter") == "flagsmith_management_api"
        if real and not args.allow_real_flagsmith:
            raise RuntimeError("This API uses Flagsmith. Rerun with --allow-real-flagsmith to require explicit typed approvals.")

        finding_id = f"smoke-{uuid4()}"
        finding = require_ok(
            client.post(
                "/findings",
                json={
                    "finding_id": finding_id,
                    "category": "sqli",
                    "affected_route": "/search",
                    "severity": "high",
                    "status": "reproduced",
                    "evidence_ids": [f"synthetic-{finding_id}"],
                    "evidence_summary": "Synthetic local smoke-check finding; no customer data.",
                    "reporter": "platform-smoke-script",
                },
            ),
            "submit normalized finding",
        )
        incident_id = finding["id"]
        proposal = require_ok(client.post(f"/incidents/{incident_id}/analyze"), "analyze finding")
        print(f"Finding stored: {finding_id}; incident {incident_id}.")
        print(f"Containment approval hash: {proposal['proposal_hash']}")
        approve(client, f"/proposals/{proposal['id']}/decision", proposal, "smoke-operator", real)
        containment = require_ok(
            client.post(f"/proposals/{proposal['id']}/apply", json={"proposal_hash": proposal["proposal_hash"]}),
            "apply containment",
        )
        if not containment.get("readback_verified"):
            raise RuntimeError("Containment readback was not verified.")
        verification = require_ok(client.post(f"/incidents/{incident_id}/verify", json={}), "verify containment")
        if verification.get("status") != "verified":
            raise RuntimeError("The demo app did not verify containment; rollout was not attempted.")
        require_ok(client.post(f"/incidents/{incident_id}/patch"), "load safe patch candidate")
        patch_test = require_ok(client.post(f"/incidents/{incident_id}/patch/test"), "run fixed safe patch tests")
        if patch_test.get("status") != "passed":
            raise RuntimeError("Patch checks did not pass; rollout was not attempted.")

        stage = require_ok(
            client.post(f"/incidents/{incident_id}/rollout", json={"percentage": args.stage}),
            "prepare identity rollout",
        )
        print(f"Stage proposal created: {stage['selected_count']}/{stage['eligible_count']} seeded identities.")
        approve(client, f"/release-proposals/{stage['id']}/decision", stage, "smoke-operator", real)
        stage_receipt = require_ok(
            client.post(f"/release-proposals/{stage['id']}/apply", json={"proposal_hash": stage["proposal_hash"]}),
            "apply identity rollout",
        )
        if not stage_receipt.get("app_evaluation_verified"):
            raise RuntimeError("The app did not confirm the stage for all seeded identities.")

        rollback = require_ok(
            client.post(f"/incidents/{incident_id}/rollouts/{stage['id']}/rollback"),
            "prepare rollback proposal",
        )
        approve(client, f"/release-proposals/{rollback['id']}/decision", rollback, "smoke-operator", real)
        rollback_receipt = require_ok(
            client.post(
                f"/release-proposals/{rollback['id']}/apply",
                json={"proposal_hash": rollback["proposal_hash"]},
            ),
            "apply approved rollback",
        )
        if not rollback_receipt.get("app_evaluation_verified"):
            raise RuntimeError("The app did not confirm the approved rollback.")
        report = require_ok(client.get(f"/incidents/{incident_id}/report"), "export evidence report")
        print(
            "Smoke check complete: containment, safe patch checks, staged identity rollout, "
            f"approved rollback and evidence report verified ({len(report.get('events', []))} events)."
        )
        print(f"Incident report API: {args.api_root.rstrip('/')}/incidents/{incident_id}/report")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (httpx.RequestError, RuntimeError, KeyError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
