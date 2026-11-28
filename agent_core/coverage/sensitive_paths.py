"""Sensitive implementation index and bounded local call-graph resolution."""

from __future__ import annotations

import ast
from dataclasses import dataclass, field

from agent_core.coverage.models import SourceFileEntry, SourceReference, SourceSnapshot


@dataclass(frozen=True)
class SensitiveSinkSpec:
    """Known sensitive legacy implementation or sink specification."""

    symbol_name: str
    implementation_id: str
    component: str
    expected_flags: tuple[str, ...]
    replacement_flags: tuple[str, ...] = ()


DEFAULT_SENSITIVE_SINKS: tuple[SensitiveSinkSpec, ...] = (
    SensitiveSinkSpec(
        symbol_name="vulnerable_search_documents_for_demo",
        implementation_id="search_v1",
        component="search_service",
        expected_flags=("search_v1",),
        replacement_flags=("search_v2",),
    ),
    SensitiveSinkSpec(
        symbol_name="legacy_search_query",
        implementation_id="search_v1",
        component="search_service",
        expected_flags=("search_v1",),
        replacement_flags=("search_v2",),
    ),
    SensitiveSinkSpec(
        symbol_name="vulnerable_read_demo_file_for_demo",
        implementation_id="files_v1",
        component="file_service",
        expected_flags=("files_v1",),
        replacement_flags=("files_v2",),
    ),
    SensitiveSinkSpec(
        symbol_name="legacy_read_file",
        implementation_id="files_v1",
        component="file_service",
        expected_flags=("files_v1",),
        replacement_flags=("files_v2",),
    ),
    SensitiveSinkSpec(
        symbol_name="legacy_export_records",
        implementation_id="legacy_export",
        component="legacy_export_service",
        expected_flags=(),
        replacement_flags=(),
    ),
)

SAFE_FALLBACK_SYMBOLS: frozenset[str] = frozenset(
    {
        "parameterized_search_documents",
        "safe_search_documents",
        "safe_search_fallback",
        "safe_read_public_file",
        "safe_files_fallback",
        "health_response",
        "status_response",
    }
)

DYNAMIC_CALL_NAMES: frozenset[str] = frozenset({"getattr", "eval", "exec", "__import__"})


@dataclass
class LocalCallIndex:
    """Indexed functions, imports, and sensitive sink specifications across a snapshot."""

    functions: dict[str, tuple[ast.FunctionDef | ast.AsyncFunctionDef, SourceFileEntry]] = field(
        default_factory=dict
    )
    import_aliases: dict[str, str] = field(default_factory=dict)
    sinks_by_symbol: dict[str, SensitiveSinkSpec] = field(default_factory=dict)
    source_revision: str = "unknown"

    def resolve_callee_name(self, call_node: ast.Call) -> str | None:
        """Resolve a static callee name if unambiguous; return None for dynamic dispatch."""
        func = call_node.func
        if isinstance(func, ast.Name):
            if func.id in DYNAMIC_CALL_NAMES:
                return None
            return self.import_aliases.get(func.id, func.id)
        if isinstance(func, ast.Attribute):
            return func.attr
        return None

    def make_source_ref(self, entry: SourceFileEntry, node: ast.AST) -> SourceReference:
        start = getattr(node, "lineno", 1)
        end = getattr(node, "end_lineno", start) or start
        return SourceReference(
            relative_path=entry.relative_path,
            start_line=start,
            end_line=end,
            file_hash=entry.sha256_hash,
            source_revision=self.source_revision,
        )


def build_local_call_index(
    snapshot: SourceSnapshot,
    *,
    sinks: tuple[SensitiveSinkSpec, ...] = DEFAULT_SENSITIVE_SINKS,
) -> LocalCallIndex:
    """Build a bounded symbol and import index without executing any analyzed code."""
    index = LocalCallIndex(
        sinks_by_symbol={spec.symbol_name: spec for spec in sinks},
        source_revision=snapshot.source_revision,
    )
    for entry in snapshot.files:
        try:
            tree = ast.parse(entry.content.lstrip("\ufeff"), filename=entry.relative_path)
        except SyntaxError:
            continue
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                index.functions[node.name] = (node, entry)
            elif isinstance(node, (ast.ImportFrom, ast.Import)):
                for alias in node.names:
                    local_name = alias.asname or alias.name
                    index.import_aliases[local_name] = alias.name
    return index
