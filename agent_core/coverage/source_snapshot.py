"""Bounded, authorized read-only source snapshot loader and validator."""

from __future__ import annotations

import ast
from collections.abc import Mapping
from pathlib import Path

from shared.enums import EvidenceProvenance
from shared.exceptions import ContractValidationError
from shared.identifiers import utc_now
from shared.serialization import canonical_json, sha256_text

from agent_core.coverage.models import SnapshotLimits, SourceFileEntry, SourceSnapshot

ALLOWED_EXTENSIONS = {".py"}


def compute_source_tree_fingerprint(files: list[SourceFileEntry]) -> str:
    """Compute a deterministic SHA-256 fingerprint over sorted relative paths and hashes."""
    ordered = sorted(
        ({"path": f.relative_path, "sha256": f.sha256_hash} for f in files),
        key=lambda item: item["path"],
    )
    return str(sha256_text(canonical_json(ordered)))


def build_in_memory_snapshot(
    *,
    application_id: str,
    environment: str,
    source_revision: str,
    files: Mapping[str, str],
    source_root_descriptor: str = "in_memory_fixture",
    revision_namespace: str = "fixture_snapshot",
    provenance: EvidenceProvenance = EvidenceProvenance.REFERENCE_FIXTURE,
    is_complete: bool = True,
    diagnostics: list[str] | None = None,
    limits: SnapshotLimits | None = None,
) -> SourceSnapshot:
    """Build a validated in-memory ``SourceSnapshot`` for tests and static fixtures."""
    active_limits = limits or SnapshotLimits()
    entries: list[SourceFileEntry] = []
    diags = list(diagnostics or [])
    total_bytes = 0
    total_nodes = 0

    for rel_path in sorted(files):
        _validate_relative_path(rel_path)
        content = files[rel_path]
        encoded = content.encode("utf-8")
        if len(encoded) > active_limits.max_file_bytes:
            raise ContractValidationError(
                f"Snapshot file {rel_path!r} exceeds max_file_bytes "
                f"({active_limits.max_file_bytes})."
            )
        total_bytes += len(encoded)
        if total_bytes > active_limits.max_total_bytes:
            raise ContractValidationError(
                f"Snapshot total bytes exceed max_total_bytes "
                f"({active_limits.max_total_bytes})."
            )
        if len(entries) >= active_limits.max_files:
            raise ContractValidationError(
                f"Snapshot file count exceeds max_files ({active_limits.max_files})."
            )
        try:
            tree = ast.parse(content.lstrip("\ufeff"), filename=rel_path)
            node_count = sum(1 for _ in ast.walk(tree))
            total_nodes += node_count
            if total_nodes > active_limits.max_ast_nodes:
                raise ContractValidationError(
                    f"Snapshot AST node count exceeds max_ast_nodes "
                    f"({active_limits.max_ast_nodes})."
                )
        except SyntaxError as exc:
            diags.append(f"syntax_error:{rel_path}:{exc.lineno}:{exc.msg}")
            is_complete = False

        entries.append(
            SourceFileEntry(
                relative_path=rel_path,
                content=content,
                sha256_hash=sha256_text(content),
                size_bytes=len(encoded),
            )
        )

    if not entries:
        diags.append("source_snapshot_empty")
        is_complete = False

    return SourceSnapshot(
        application_id=application_id,
        environment=environment,
        source_root_descriptor=source_root_descriptor,
        source_revision=source_revision,
        revision_namespace=revision_namespace,
        source_tree_fingerprint=compute_source_tree_fingerprint(entries),
        provenance=provenance,
        captured_at=utc_now(),
        files=entries,
        diagnostics=diags,
        is_complete=is_complete,
        limits=active_limits,
    )


def load_authorized_source_snapshot(
    *,
    root_dir: Path,
    relative_files: list[str],
    application_id: str,
    environment: str,
    source_revision: str,
    revision_namespace: str = "git_commit",
    provenance: EvidenceProvenance = EvidenceProvenance.ACTUAL_OBSERVED,
    limits: SnapshotLimits | None = None,
) -> SourceSnapshot:
    """Load an explicit allowlist of Python files from ``root_dir`` safely.

    Rejects absolute paths, path traversal (``..``), symlinks escaping ``root_dir``,
    unsupported file extensions, and files exceeding configured bounds.
    Missing files are recorded as explicit diagnostics with ``is_complete=False``.
    """
    active_limits = limits or SnapshotLimits()
    resolved_root = root_dir.resolve()
    if not resolved_root.exists() or not resolved_root.is_dir():
        raise ContractValidationError(f"Authorized source root does not exist: {root_dir}")

    loaded: dict[str, str] = {}
    diags: list[str] = []
    is_complete = True

    for rel_path in sorted(set(relative_files)):
        _validate_relative_path(rel_path)
        candidate = root_dir / rel_path
        if candidate.is_symlink():
            target = candidate.resolve()
            if not target.is_relative_to(resolved_root):
                raise ContractValidationError(
                    f"Symlink {rel_path!r} escapes authorized root {resolved_root}."
                )
        resolved_candidate = candidate.resolve()
        if not resolved_candidate.is_relative_to(resolved_root):
            raise ContractValidationError(
                f"Path {rel_path!r} escapes authorized root {resolved_root}."
            )
        if not resolved_candidate.exists() or not resolved_candidate.is_file():
            diags.append(f"missing_source_file:{rel_path}")
            is_complete = False
            continue
        loaded[rel_path] = resolved_candidate.read_text(encoding="utf-8")

    return build_in_memory_snapshot(
        application_id=application_id,
        environment=environment,
        source_revision=source_revision,
        files=loaded,
        source_root_descriptor=resolved_root.name,
        revision_namespace=revision_namespace,
        provenance=provenance,
        is_complete=is_complete,
        diagnostics=diags,
        limits=active_limits,
    )


def _validate_relative_path(rel_path: str) -> None:
    p = Path(rel_path)
    if p.is_absolute() or ".." in p.parts:
        raise ContractValidationError(
            f"Source path {rel_path!r} must be relative and cannot traverse parent directories."
        )
    if p.suffix not in ALLOWED_EXTENSIONS:
        raise ContractValidationError(
            f"Unsupported source file type {rel_path!r}; allowed: {sorted(ALLOWED_EXTENSIONS)}."
        )
