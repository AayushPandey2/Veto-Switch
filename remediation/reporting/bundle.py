"""Atomic evidence bundle export, manifest generation, and read-only verification."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from shared.schemas import EvidenceReport
from shared.serialization import sha256_bytes
from shared.validation import validate_identifier

from remediation.reporting.models import (
    BundleFileEntry,
    BundleVerificationResult,
    ExportManifest,
)


def export_report_bundle(
    *,
    base_dir: Path,
    report: EvidenceReport,
    markdown_content: str,
    json_payload: dict[str, Any],
) -> tuple[Path, ExportManifest]:
    """Write an immutable Markdown/JSON evidence bundle with SHA-256 manifest."""
    inc_id = validate_identifier(report.incident_id, field_name="incident_id")
    rep_id = validate_identifier(report.report_id, field_name="report_id")
    bundle_dir = (base_dir / "incident_reports" / inc_id / rep_id).resolve()
    if not bundle_dir.is_relative_to(base_dir.resolve()):
        raise ValueError("Unsafe bundle path outside base_dir.")
    if bundle_dir.exists():
        raise FileExistsError(f"Immutable report bundle already exists: {bundle_dir}")

    bundle_dir.mkdir(parents=True, exist_ok=False)

    md_bytes = markdown_content.encode("utf-8")
    json_bytes = (json.dumps(json_payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
    integrity_bytes = (
        json.dumps(
            {
                "incident_id": inc_id,
                "report_id": rep_id,
                "completeness": report.completeness.value,
                "artifact_integrity_results": report.artifact_integrity_results,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")

    (bundle_dir / "report.md").write_bytes(md_bytes)
    (bundle_dir / "report.json").write_bytes(json_bytes)
    (bundle_dir / "integrity.json").write_bytes(integrity_bytes)

    manifest = ExportManifest(
        bundle_id=f"bndl_{rep_id}",
        incident_id=inc_id,
        report_id=rep_id,
        report_schema_version=report.report_schema_version,
        reporting_policy_version=report.reporting_policy_version,
        snapshot_fingerprint=report.snapshot_fingerprint or ("0" * 64),
        maximum_event_sequence=report.snapshot_sequence or len(report.timeline),
        files=[
            BundleFileEntry(
                relative_path="report.md",
                content_type="text/markdown",
                size_bytes=len(md_bytes),
                sha256=sha256_bytes(md_bytes),
            ),
            BundleFileEntry(
                relative_path="report.json",
                content_type="application/json",
                size_bytes=len(json_bytes),
                sha256=sha256_bytes(json_bytes),
            ),
            BundleFileEntry(
                relative_path="integrity.json",
                content_type="application/json",
                size_bytes=len(integrity_bytes),
                sha256=sha256_bytes(integrity_bytes),
            ),
        ],
        source_artifact_references=[a.artifact_id for a in report.artifact_references],
        limitations=list(report.limitations),
    )
    manifest_bytes = (manifest.model_dump_json(indent=2) + "\n").encode("utf-8")
    (bundle_dir / "manifest.json").write_bytes(manifest_bytes)
    return bundle_dir, manifest


def verify_report_bundle(bundle_path: Path | str) -> BundleVerificationResult:
    """Independently verify bundle structure, path safety, sizes, and SHA-256 digests."""
    root = Path(bundle_path).resolve()
    manifest_path = root / "manifest.json"
    if not manifest_path.is_file():
        return BundleVerificationResult(
            valid=False,
            bundle_path=str(root),
            failures=["Missing manifest.json in report bundle."],
        )
    try:
        manifest = ExportManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return BundleVerificationResult(
            valid=False,
            bundle_path=str(root),
            failures=[f"Invalid manifest.json schema: {exc}"],
        )

    failures: list[str] = []
    verified: list[str] = []
    for entry in manifest.files:
        rel = Path(entry.relative_path)
        if rel.is_absolute() or ".." in rel.parts:
            failures.append(f"Unsafe path in manifest: {entry.relative_path!r}")
            continue
        target = (root / rel).resolve()
        if not target.is_relative_to(root) or target.is_symlink():
            failures.append(f"Path traversal or symlink detected: {entry.relative_path!r}")
            continue
        if not target.is_file():
            failures.append(f"Missing bundle file: {entry.relative_path!r}")
            continue
        raw = target.read_bytes()
        if len(raw) != entry.size_bytes:
            failures.append(
                f"Size mismatch for {entry.relative_path!r}: "
                f"expected {entry.size_bytes}, got {len(raw)}."
            )
            continue
        actual_hash = sha256_bytes(raw)
        if actual_hash != entry.sha256:
            failures.append(
                f"SHA-256 mismatch for {entry.relative_path!r}: "
                f"expected {entry.sha256}, got {actual_hash}."
            )
            continue
        verified.append(entry.relative_path)

    return BundleVerificationResult(
        valid=len(failures) == 0,
        bundle_path=str(root),
        incident_id=manifest.incident_id,
        report_id=manifest.report_id,
        failures=failures,
        verified_files=verified,
    )
