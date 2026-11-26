"""Authorized source target descriptors, snapshot loading, AST localization, and context."""

from __future__ import annotations

import ast
from datetime import datetime
from pathlib import Path

from shared.enums import (
    EvidenceProvenance,
    PatchRejectionReason,
    VulnerabilityCategory,
)
from shared.exceptions import ContractValidationError
from shared.identifiers import utc_now
from shared.logging_config import redact_text
from shared.schemas import ArtifactReference, Finding, VerificationResult
from shared.serialization import canonical_json, sha256_text
from shared.validation import validate_relative_safe_path

from remediation.patching.models import (
    LocalizationResult,
    PatchGenerationContext,
    PatchLimitsConfig,
    PatchTargetDescriptor,
    SourceExcerpt,
    SourceSnapshot,
)

STAND_IN_TARGET = PatchTargetDescriptor(
    target_id="stand_in",
    application_id="security_stand_in_app",
    source_root="security/stand_in_app",
    source_revision="standin-rev-0000demo",
    revision_namespace="tree_sha256",
    allowed_files=["app.py"],
    contract_version="1.0.0-security-contract",
    supported_categories=[
        VulnerabilityCategory.SQL_INJECTION,
        VulnerabilityCategory.PATH_TRAVERSAL,
    ],
    registered_test_ids=[
        "sqli_search",
        "traversal_files",
        "functional_search",
        "negative_inputs_search",
        "functional_files",
        "negative_inputs_files",
        "smoke_status",
        "smoke_catalog",
    ],
    sandbox_supported=True,
    environment="demo-staging",
)

PLATFORM_DEMO_TARGET = PatchTargetDescriptor(
    target_id="platform_demo_app",
    application_id="platform_demo_app",
    source_root="platform/demo_app",
    source_revision="platform-rev-0000demo",
    revision_namespace="git_commit",
    allowed_files=["vulnerable_search_service.py"],
    contract_version="1.0.0-platform-contract",
    supported_categories=[VulnerabilityCategory.SQL_INJECTION],
    registered_test_ids=[],
    sandbox_supported=False,
    environment="demo-staging",
)

REGISTERED_PATCH_TARGETS: dict[str, PatchTargetDescriptor] = {
    "stand_in": STAND_IN_TARGET,
    "platform_demo_app": PLATFORM_DEMO_TARGET,
}


def compute_snapshot_fingerprint(files: dict[str, str], source_revision: str) -> str:
    """Compute canonical SHA-256 fingerprint binding source revision and file contents."""
    file_hashes = {path: sha256_text(content) for path, content in sorted(files.items())}
    return sha256_text(
        canonical_json({"source_revision": source_revision, "file_hashes": file_hashes})
    )


def load_snapshot_from_files(
    *,
    target: PatchTargetDescriptor,
    files: dict[str, str],
    limits: PatchLimitsConfig | None = None,
) -> SourceSnapshot:
    """Build a validated, bounded ``SourceSnapshot`` from an in-memory file mapping."""
    cfg = limits or PatchLimitsConfig()
    if len(files) > cfg.maximum_source_files:
        raise ContractValidationError(
            f"Snapshot file count {len(files)} exceeds limit {cfg.maximum_source_files}.",
            context={"reason": PatchRejectionReason.SOURCE_UNAVAILABLE.value},
        )
    allowed_set = set(target.allowed_files)
    validated_files: dict[str, str] = {}
    file_hashes: dict[str, str] = {}
    total_bytes = 0

    for raw_path, content in sorted(files.items()):
        rel = validate_relative_safe_path(raw_path, field_name="snapshot_file")
        if rel not in allowed_set:
            raise ContractValidationError(
                f"File {rel!r} is outside authorized target allowlist {target.allowed_files}.",
                context={"reason": PatchRejectionReason.PATCH_FILE_OUTSIDE_ALLOWLIST.value},
            )
        size = len(content.encode("utf-8"))
        total_bytes += size
        if total_bytes > cfg.maximum_source_bytes:
            raise ContractValidationError(
                f"Snapshot total bytes {total_bytes} exceeds limit {cfg.maximum_source_bytes}.",
                context={"reason": PatchRejectionReason.SOURCE_UNAVAILABLE.value},
            )
        validated_files[rel] = content.replace("\r\n", "\n")
        file_hashes[rel] = sha256_text(validated_files[rel])

    return SourceSnapshot(
        target_id=target.target_id,
        source_revision=target.source_revision,
        revision_namespace=target.revision_namespace,
        snapshot_fingerprint=compute_snapshot_fingerprint(
            validated_files, target.source_revision
        ),
        files=validated_files,
        file_hashes=file_hashes,
    )


def load_authorized_snapshot_from_disk(
    *,
    target: PatchTargetDescriptor,
    root_dir: Path,
    limits: PatchLimitsConfig | None = None,
) -> SourceSnapshot:
    """Safely read allowlisted files from ``root_dir`` rejecting symlinks and traversal."""
    resolved_root = root_dir.resolve()
    files: dict[str, str] = {}
    for rel in target.allowed_files:
        safe_rel = validate_relative_safe_path(rel, field_name="allowed_file")
        candidate = resolved_root / safe_rel
        if candidate.is_symlink():
            raise ContractValidationError(
                f"Symlink file {safe_rel!r} is prohibited in authorized source snapshot."
            )
        resolved_file = candidate.resolve()
        try:
            resolved_file.relative_to(resolved_root)
        except ValueError as exc:
            raise ContractValidationError(
                f"File {safe_rel!r} escapes authorized root {resolved_root}."
            ) from exc
        if not resolved_file.is_file():
            raise ContractValidationError(
                f"Authorized source file {safe_rel!r} does not exist in {resolved_root}."
            )
        files[safe_rel] = resolved_file.read_text(encoding="utf-8")
    return load_snapshot_from_files(target=target, files=files, limits=limits)


def localize_vulnerability(
    *,
    finding: Finding,
    snapshot: SourceSnapshot,
    target_function: str | None = None,
) -> LocalizationResult:
    """Locate target function via bounded Python AST inspection (no code execution)."""
    if not snapshot.files:
        return LocalizationResult(
            outcome="source_unavailable",
            limitations=["Source snapshot contains no files."],
        )

    desired_fn = target_function
    if desired_fn is None:
        if finding.category == VulnerabilityCategory.SQL_INJECTION or (
            finding.affected_route in {"/search", "/legacy/search", "/search/"}
        ):
            desired_fn = "search_v1"
        elif finding.category == VulnerabilityCategory.PATH_TRAVERSAL or (
            finding.affected_route in {"/files", "/files/"}
        ):
            desired_fn = "files_v1"

    matches: list[tuple[str, str]] = []
    for file_path, source in sorted(snapshot.files.items()):
        try:
            tree = ast.parse(source, filename=file_path)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and (
                desired_fn is not None and node.name == desired_fn
            ):
                matches.append((file_path, node.name))

    if len(matches) == 1:
        fp, fn = matches[0]
        return LocalizationResult(
            outcome="exact_function_match",
            file_path=fp,
            function_name=fn,
            candidate_locations=[f"{fp}:{fn}"],
        )
    if len(matches) > 1:
        return LocalizationResult(
            outcome="multiple_candidate_locations",
            candidate_locations=[f"{fp}:{fn}" for fp, fn in matches],
            limitations=["Multiple candidate functions matched; manual disambiguation needed."],
        )
    if len(snapshot.files) == 1:
        only_file = next(iter(snapshot.files))
        return LocalizationResult(
            outcome="component_source_match",
            file_path=only_file,
            candidate_locations=[only_file],
            limitations=["Exact function name not matched; falling back to single allowed file."],
        )
    return LocalizationResult(
        outcome="manual_review_required",
        limitations=["Could not localize vulnerable function across authorized files."],
    )


def _extract_bounded_excerpts(
    snapshot: SourceSnapshot,
    localization: LocalizationResult,
    limits: PatchLimitsConfig,
) -> list[SourceExcerpt]:
    excerpts: list[SourceExcerpt] = []
    target_files = (
        [localization.file_path] if localization.file_path else sorted(snapshot.files.keys())
    )
    for fp in target_files:
        source = snapshot.files.get(fp)
        if source is None:
            continue
        lines = source.splitlines()
        start_line = 1
        end_line = min(len(lines), limits.maximum_excerpt_lines)
        if localization.function_name:
            try:
                tree = ast.parse(source, filename=fp)
                for node in ast.walk(tree):
                    if (
                        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and node.name == localization.function_name
                    ):
                        start_line = max(1, node.lineno - 3)
                        end_line = min(
                            len(lines),
                            (node.end_lineno or node.lineno) + 3,
                            start_line + limits.maximum_excerpt_lines - 1,
                        )
                        break
            except SyntaxError:
                pass
        snippet = "\n".join(lines[start_line - 1 : end_line])
        redacted = redact_text(snippet)
        excerpts.append(
            SourceExcerpt(
                file_path=fp,
                start_line=start_line,
                end_line=max(start_line, end_line),
                symbol_name=localization.function_name,
                content=redacted,
                inclusion_reason=(
                    f"Localized {localization.outcome} for {localization.function_name or fp}."
                ),
            )
        )
    return excerpts


def build_patch_context(
    *,
    finding: Finding,
    target_descriptor: PatchTargetDescriptor,
    snapshot: SourceSnapshot,
    containment_verification: VerificationResult | None = None,
    reproduction_evidence: list[ArtifactReference] | None = None,
    registered_test_id: str | None = None,
    affected_implementation: str | None = None,
    required_test_ids: list[str] | None = None,
    target_function: str | None = None,
    fixture_mode: bool = False,
    evaluation_timestamp: datetime | None = None,
    limits: PatchLimitsConfig | None = None,
) -> PatchGenerationContext:
    """10-stage bounded context builder separating trusted metadata from untrusted text."""
    cfg = limits or PatchLimitsConfig()
    loc = localize_vulnerability(
        finding=finding,
        snapshot=snapshot,
        target_function=target_function or affected_implementation,
    )
    excerpts = _extract_bounded_excerpts(snapshot, loc, cfg)
    return PatchGenerationContext(
        finding=finding,
        incident_id=finding.incident_id,
        containment_verification=containment_verification,
        reproduction_evidence=list(reproduction_evidence or []),
        registered_test_id=registered_test_id,
        target_descriptor=target_descriptor,
        source_snapshot=snapshot,
        relevant_source_excerpts=excerpts,
        localization=loc,
        affected_component=finding.affected_component,
        affected_implementation=affected_implementation or loc.function_name,
        required_test_ids=list(required_test_ids or []),
        remediation_constraints=[
            f"Modify ONLY allowlisted files: {target_descriptor.allowed_files}.",
            "Produce a minimal unified diff preserving existing feature flags and contracts.",
            "Do not execute code, add network/process calls, or alter security tests.",
        ],
        fixture_mode=fixture_mode,
        provenance=(
            EvidenceProvenance.REFERENCE_FIXTURE
            if fixture_mode
            else EvidenceProvenance.DETERMINISTIC_REASONING
        ),
        evaluation_timestamp=evaluation_timestamp or utc_now(),
    )
