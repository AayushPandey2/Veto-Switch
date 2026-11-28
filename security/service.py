"""Security test service: the isolated verification API the platform backend calls.

Run:  uvicorn security.service:app --host 127.0.0.1 --port 8100

It only runs registered tests against allowlisted targets. There is no endpoint
that accepts a URL, a shell command or arbitrary code. Patch submission and patch
test runs require the shared X-KSX-Token (KSX_SECURITY_SERVICE_TOKEN); if the
token is not configured those endpoints refuse every request (fail closed).
"""

from __future__ import annotations

import hmac
import os

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from security import allowlist, cve_matcher, registry, sandbox, scanner
from security.evidence import ArtifactStore, event
from security.exploit_verifier import result_events, run_phase
from security.models import Phase
from security.patching import PatchRejected

app = FastAPI(title="Killswitch X security test service", version="1.0.0")


def require_token(x_ksx_token: str | None = Header(default=None)) -> None:
    expected = os.environ.get("KSX_SECURITY_SERVICE_TOKEN", "")
    if not expected or expected == "change-me":
        raise HTTPException(503, "service token not configured; patch endpoints are disabled")
    if not x_ksx_token or not hmac.compare_digest(x_ksx_token, expected):
        raise HTTPException(401, "missing or invalid X-KSX-Token")


class VerifyRequest(BaseModel):
    incident_id: str
    test_id: str
    target_id: str
    phase: Phase
    revision: str | None = None
    expected_flags: dict[str, bool] | None = None


class ScanRequest(BaseModel):
    target_id: str = "demo"
    include_dependencies: bool = True


class PatchSubmit(BaseModel):
    patch_id: str
    incident_id: str
    diff: str = Field(max_length=64 * 1024)
    base_revision: str
    source: str = sandbox.DEFAULT_SOURCE


class PatchTestRequest(BaseModel):
    patch_id: str
    revision: str
    test_ids: list[str]


class EnrichRequest(BaseModel):
    package: str
    version: str | None = None
    advisory_id: str


@app.get("/health")
def health():
    return {"status": "ok", "service": "security", "docker": sandbox.docker_available(),
            "local_sandbox_allowed": sandbox.local_allowed()}


@app.get("/registry")
def get_registry():
    return registry.public_view()


@app.get("/targets")
def get_targets():
    return allowlist.list_targets()


@app.post("/verify")
def verify(req: VerifyRequest):
    try:
        allowlist.resolve_target(req.target_id)
    except allowlist.TargetNotAllowed as e:
        raise HTTPException(403, str(e))
    res = run_phase(req.phase, req.incident_id, req.test_id, req.target_id,
                    revision=req.revision, expected_flags=req.expected_flags)
    return {"result": res.model_dump(), "events": [e.model_dump() for e in result_events(res)]}


@app.post("/scan")
def scan(req: ScanRequest):
    try:
        allowlist.resolve_target(req.target_id)
    except allowlist.TargetNotAllowed as e:
        raise HTTPException(403, str(e))
    findings, events = scanner.scan_demo_sync(req.target_id, include_dependencies=req.include_dependencies)
    return {"findings": [f.model_dump() for f in findings], "events": [e.model_dump() for e in events]}


@app.get("/patches/base-revision")
def patch_base_revision(source: str = sandbox.DEFAULT_SOURCE):
    if source not in sandbox.SOURCES:
        raise HTTPException(404, "unknown source")
    return {"source": source, "revision": sandbox.base_revision(source),
            "allowed_files": sorted(sandbox.SOURCES[source]["allowed_files"])}


@app.post("/patches", dependencies=[Depends(require_token)])
def submit_patch(req: PatchSubmit):
    try:
        rec = sandbox.PatchStore().submit(req.patch_id, req.diff, req.base_revision, req.incident_id, req.source)
    except (PatchRejected, ValueError) as e:
        raise HTTPException(422, f"patch rejected: {e}")
    return {k: v for k, v in rec.items() if k != "diff"}


@app.post("/patch-tests", dependencies=[Depends(require_token)])
def patch_tests(req: PatchTestRequest):
    report = sandbox.run_patch_tests_sync(req.patch_id, req.revision, req.test_ids)
    incident = report.get("incident_id") or "unassigned"
    ev = event(incident, "patch_tests_completed", {
        "patch_id": req.patch_id, "status": report["status"], "evidence_id": report.get("evidence_id"),
        "patched_revision": report.get("patched_revision"), "reason": report.get("reason")})
    return {"report": report, "events": [ev.model_dump()]}


@app.post("/cve/enrich")
def enrich(req: EnrichRequest):
    advisories = {a["id"]: a for a in cve_matcher.load_advisories()}
    adv = advisories.get(req.advisory_id)
    if adv is None:
        raise HTTPException(404, "advisory not in the saved advisory set")
    return cve_matcher.enrich_dependency_finding(req.package, req.version, adv)


@app.get("/artifacts/{incident_id}")
def artifacts(incident_id: str):
    store = ArtifactStore()
    try:
        return {"manifest": [r.model_dump() for r in store.manifest(incident_id)],
                "integrity": store.verify_integrity(incident_id)}
    except ValueError as e:
        raise HTTPException(400, str(e))


@app.get("/artifacts/{incident_id}/{evidence_id}")
def artifact(incident_id: str, evidence_id: str):
    try:
        return ArtifactStore().read(incident_id, evidence_id)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except FileNotFoundError:
        raise HTTPException(404, "no such artifact")
