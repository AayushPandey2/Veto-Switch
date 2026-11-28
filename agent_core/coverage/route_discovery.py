"""Static AST-based Flask route and entry-point discovery."""

from __future__ import annotations

import ast
from dataclasses import dataclass

from shared.enums import CoverageApplicability

from agent_core.coverage.models import (
    RouteIdentity,
    SourceFileEntry,
    SourceReference,
    SourceSnapshot,
)

EXEMPT_ROUTES = frozenset({"/health", "/status", "/manifest", "/catalog"})


@dataclass(frozen=True)
class DiscoveredHandler:
    """Internal AST record pairing a ``RouteIdentity`` with its ``ast.FunctionDef``."""

    identity: RouteIdentity
    func_node: ast.FunctionDef | ast.AsyncFunctionDef
    file_entry: SourceFileEntry


def discover_routes_in_snapshot(
    snapshot: SourceSnapshot,
    *,
    exempt_routes: frozenset[str] = EXEMPT_ROUTES,
) -> tuple[list[DiscoveredHandler], list[str]]:
    """Discover Flask routes and handlers statically without importing or executing code."""
    discovered: list[DiscoveredHandler] = []
    diagnostics: list[str] = []

    for entry in snapshot.files:
        try:
            tree = ast.parse(entry.content.lstrip("\ufeff"), filename=entry.relative_path)
        except SyntaxError as exc:
            diagnostics.append(f"route_discovery_syntax_error:{entry.relative_path}:{exc.lineno}")
            continue

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in node.decorator_list:
                extracted = _extract_flask_decorator(dec)
                if extracted is None:
                    continue
                route_path, methods, is_dynamic, reason = extracted
                if reason:
                    diagnostics.append(
                        f"{reason}:{entry.relative_path}:{node.lineno}:{node.name}"
                    )
                is_exempt = route_path in exempt_routes
                applicability = (
                    CoverageApplicability.EXEMPT
                    if is_exempt
                    else CoverageApplicability.APPLICABLE
                )
                src_ref = SourceReference(
                    relative_path=entry.relative_path,
                    start_line=node.lineno,
                    end_line=getattr(node, "end_lineno", node.lineno) or node.lineno,
                    file_hash=entry.sha256_hash,
                    source_revision=snapshot.source_revision,
                    snippet_summary=f"def {node.name}(...)",
                )
                for method in methods:
                    discovered.append(
                        DiscoveredHandler(
                            identity=RouteIdentity(
                                application_id=snapshot.application_id,
                                method=method.upper(),
                                route=route_path,
                                handler_name=node.name,
                                source_ref=src_ref,
                                is_dynamic=is_dynamic,
                                is_exempt=is_exempt,
                                applicability=applicability,
                            ),
                            func_node=node,
                            file_entry=entry,
                        )
                    )

        # Detect conditional route registration (routes registered inside an If block)
        for stmt in tree.body:
            if isinstance(stmt, ast.If):
                for inner in ast.walk(stmt):
                    if isinstance(inner, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                        _extract_flask_decorator(d) is not None for d in inner.decorator_list
                    ):
                        diagnostics.append(
                            f"conditional_route_registration:{entry.relative_path}:{inner.lineno}:{inner.name}"
                        )

    discovered.sort(
        key=lambda d: (
            d.identity.route,
            d.identity.method,
            d.identity.handler_name,
            d.identity.source_ref.start_line if d.identity.source_ref else 0,
        )
    )
    return discovered, diagnostics


def _extract_flask_decorator(
    dec: ast.expr,
) -> tuple[str, list[str], bool, str | None] | None:
    """Return ``(route, methods, is_dynamic, diagnostic)`` if ``dec`` is a Flask route decorator."""
    if not isinstance(dec, ast.Call):
        return None
    if not isinstance(dec.func, ast.Attribute):
        return None
    attr = dec.func.attr
    if attr not in {"route", "get", "post", "put", "delete", "patch"}:
        return None

    route_path = "<dynamic>"
    is_dynamic = False
    diagnostic: str | None = None

    if dec.args:
        arg0 = dec.args[0]
        if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
            route_path = arg0.value
        else:
            is_dynamic = True
            diagnostic = "dynamic_route_path_unresolved"
    else:
        for kw in dec.keywords:
            if kw.arg == "rule":
                if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                    route_path = kw.value.value
                else:
                    is_dynamic = True
                    diagnostic = "dynamic_route_path_unresolved"
                break
        else:
            is_dynamic = True
            diagnostic = "missing_route_rule_argument"

    if attr in {"get", "post", "put", "delete", "patch"}:
        methods = [attr.upper()]
    else:
        methods = _extract_methods_kw(dec.keywords)

    return route_path, methods, is_dynamic, diagnostic


def _extract_methods_kw(keywords: list[ast.keyword]) -> list[str]:
    for kw in keywords:
        if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple)):
            extracted: list[str] = []
            for elt in kw.value.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    extracted.append(elt.value.upper())
            if extracted:
                return extracted
    return ["GET"]
