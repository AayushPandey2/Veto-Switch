"""Evidence artifacts: sanitized, content-addressed, listed in a per-incident manifest.

Evidence IDs are derived from the observations (not the timestamp), so the same
observed behaviour always yields the same ID, and any change to it yields a new one.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

from security import ACTOR
from security.models import ArtifactRef
from security.redact import redact
from security.revision import sha256_text
from shared.schemas import IncidentEvent

_SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{1,80}$")


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def safe_id(value: str, what: str = "id") -> str:
    if not _SAFE_ID.match(value or "") or value in {".", ".."}:
        raise ValueError(f"invalid {what}: {value!r}")
    return value


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def evidence_id(kind: str, identity: dict) -> str:
    return f"ev-{kind}-{sha256_text(canonical(identity))[:16]}"


class ArtifactStore:
    def __init__(self, root: str | Path | None = None):
        self.root = Path(root or os.environ.get("KSX_ARTIFACT_DIR", "artifacts")).resolve()

    def _dir(self, incident_id: str) -> Path:
        d = self.root / safe_id(incident_id, "incident_id")
        d.mkdir(parents=True, exist_ok=True)
        return d

    def write(self, incident_id: str, kind: str, identity: dict, payload: dict) -> ArtifactRef:
        """Store a redacted artifact. `identity` (observations) determines the evidence ID."""
        eid = evidence_id(kind, redact(identity))
        for existing in self.manifest(incident_id):
            if existing.evidence_id == eid:
                return existing  # same observations already recorded; artifacts are immutable
        body = canonical({"evidence_id": eid, "kind": kind, "incident_id": incident_id,
                          "written_at_utc": utc_now(), "synthetic_data": True, **redact(payload)})
        path = self._dir(incident_id) / f"{eid}.json"
        path.write_text(body, encoding="utf-8")
        ref = ArtifactRef(evidence_id=eid, path=path.relative_to(self.root).as_posix(),
                          sha256=sha256_text(body), kind=kind)
        with (self._dir(incident_id) / "manifest.jsonl").open("a", encoding="utf-8") as f:
            f.write(ref.model_dump_json() + "\n")
        return ref

    def manifest(self, incident_id: str) -> list[ArtifactRef]:
        p = self._dir(incident_id) / "manifest.jsonl"
        if not p.exists():
            return []
        return [ArtifactRef.model_validate_json(line) for line in p.read_text(encoding="utf-8").splitlines() if line]

    def read(self, incident_id: str, eid: str) -> dict:
        p = self._dir(incident_id) / f"{safe_id(eid, 'evidence_id')}.json"
        return json.loads(p.read_text(encoding="utf-8"))

    def verify_integrity(self, incident_id: str) -> list[dict]:
        """Re-hash every artifact listed in the manifest; report tampering or loss."""
        out = []
        for ref in self.manifest(incident_id):
            p = self.root / ref.path
            ok = p.exists() and sha256_text(p.read_text(encoding="utf-8")) == ref.sha256
            out.append({"evidence_id": ref.evidence_id, "path": ref.path, "intact": ok})
        return out


def event(incident_id: str, event_type: str, payload: dict) -> IncidentEvent:
    return IncidentEvent(incident_id=incident_id, event_type=event_type, actor=ACTOR,
                         timestamp_utc=utc_now(), payload=redact(payload))
