"""Bounded AST control-flow and guard-dominance analyzer for Flask route handlers."""

from __future__ import annotations

import ast
from dataclasses import dataclass

from shared.enums import CoverageApplicability, CoverageReasonCode, CoverageStatus

from agent_core.coverage.guard_analysis import (
    BoolExpr,
    condition_blocks_when_flag_disabled,
    negate_expr,
    parse_guard_expr,
)
from agent_core.coverage.models import (
    ExecutionPathAssessment,
    GuardCondition,
    SourceFileEntry,
)
from agent_core.coverage.route_discovery import DiscoveredHandler
from agent_core.coverage.sensitive_paths import (
    DYNAMIC_CALL_NAMES,
    SAFE_FALLBACK_SYMBOLS,
    LocalCallIndex,
    SensitiveSinkSpec,
)


@dataclass(frozen=True)
class _SinkReach:
    sink: SensitiveSinkSpec
    call_chain: tuple[str, ...]
    dominating_guards: tuple[BoolExpr, ...]
    guard_nodes: tuple[ast.AST, ...]
    sink_node: ast.AST
    entry: SourceFileEntry
    post_sink_guards: tuple[BoolExpr, ...] = ()
    logging_only_flags: tuple[str, ...] = ()
    unresolved_calls: tuple[str, ...] = ()


def analyze_handler_paths(
    handler: DiscoveredHandler,
    call_index: LocalCallIndex,
    *,
    max_call_depth: int = 6,
) -> ExecutionPathAssessment:
    """Analyze all bounded paths from a route handler to sensitive sinks or safe fallbacks."""
    ident = handler.identity
    path_id = f"path_{ident.method.lower()}_{ident.handler_name}"

    if ident.is_dynamic:
        return ExecutionPathAssessment(
            path_id=path_id,
            route_identity=ident,
            status=CoverageStatus.UNKNOWN,
            applicability=CoverageApplicability.UNKNOWN,
            reason_codes=[CoverageReasonCode.DYNAMIC_ROUTE_UNRESOLVED],
            source_ref=ident.source_ref,
            notes=["Route path or registration could not be resolved statically."],
        )

    if ident.is_exempt:
        return ExecutionPathAssessment(
            path_id=path_id,
            route_identity=ident,
            status=CoverageStatus.UNKNOWN,
            applicability=CoverageApplicability.EXEMPT,
            reason_codes=[CoverageReasonCode.INTENTIONAL_EXEMPTION],
            source_ref=ident.source_ref,
            notes=[
                "Route is an intentional operational exemption "
                "(excluded from sensitive denominator)."
            ],
        )

    state_vars = _collect_state_dict_vars(handler.func_node)
    reaches: list[_SinkReach] = []
    unresolved: list[str] = []
    logging_flags: list[str] = []
    post_guards: list[BoolExpr] = []

    _walk_statements(
        handler.func_node.body,
        entry=handler.file_entry,
        call_index=call_index,
        state_vars=state_vars,
        active_guards=(),
        active_guard_nodes=(),
        call_chain=(ident.handler_name,),
        depth=0,
        max_call_depth=max_call_depth,
        reaches=reaches,
        unresolved=unresolved,
        logging_flags=logging_flags,
        post_guards=post_guards,
    )

    if unresolved and not reaches:
        return ExecutionPathAssessment(
            path_id=path_id,
            route_identity=ident,
            status=CoverageStatus.UNKNOWN,
            applicability=CoverageApplicability.APPLICABLE,
            reason_codes=[CoverageReasonCode.UNRESOLVED_HELPER_CALL],
            source_ref=ident.source_ref,
            notes=[f"Unresolved call targets prevent sound guard proof: {', '.join(unresolved)}"],
        )

    if not reaches:
        # No sensitive sink reached; still check if logging-only flags exist.
        fallback_notes = ["No sensitive sink reached on statically analyzed paths."]
        if logging_flags:
            fallback_notes.append(
                f"Flag referenced for logging/non-gating purpose only: {logging_flags}."
            )
        return ExecutionPathAssessment(
            path_id=path_id,
            route_identity=ident,
            status=CoverageStatus.PROTECTED,
            applicability=CoverageApplicability.APPLICABLE,
            observed_flags=sorted(set(logging_flags)),
            reason_codes=[CoverageReasonCode.GUARD_DOMINATES_SENSITIVE_PATH],
            source_ref=ident.source_ref,
            notes=fallback_notes,
        )

    # Evaluate every reach to a sensitive sink.
    primary_sink = reaches[0].sink
    expected_flags = list(primary_sink.expected_flags)
    all_observed_flags: set[str] = set(logging_flags)
    guard_models: list[GuardCondition] = []
    reason_codes: list[CoverageReasonCode] = []
    notes: list[str] = []
    all_reaches_blocked = True
    any_reach_blocked = False

    for reach in reaches:
        if not reach.dominating_guards:
            all_reaches_blocked = False
            if post_guards:
                reason_codes.append(CoverageReasonCode.GUARD_AFTER_SENSITIVE_OPERATION)
                notes.append("Flag check appears only after sensitive operation executes.")
            elif logging_flags:
                reason_codes.append(CoverageReasonCode.FLAG_REFERENCE_ONLY)
                notes.append(
                    "Flag is referenced only for logging/metadata without gating the sink."
                )
            else:
                reason_codes.append(CoverageReasonCode.GUARD_CONDITION_NOT_SUFFICIENT)
                notes.append(
                    f"Sensitive sink {reach.sink.symbol_name} reached without a "
                    "dominating flag guard."
                )
            continue

        combined = (
            reach.dominating_guards[0]
            if len(reach.dominating_guards) == 1
            else BoolExpr(
                kind="and",
                children=reach.dominating_guards,
                summary=" and ".join(g.summary for g in reach.dominating_guards),
            )
        )
        for f in combined.referenced_flags():
            all_observed_flags.add(f)

        blocks, detail = condition_blocks_when_flag_disabled(
            combined,
            expected_flags=reach.sink.expected_flags,
        )
        op_kind: str = (
            "and"
            if combined.kind == "and"
            else ("or" if combined.kind == "or" else "direct")
        )
        guard_models.append(
            GuardCondition(
                expression_summary=combined.summary,
                referenced_flags=combined.referenced_flags(),
                operator=op_kind,  # type: ignore[arg-type]
                blocks_when_disabled=blocks,
                dominates_sink=blocks,
                source_ref=call_index.make_source_ref(reach.entry, reach.guard_nodes[0]),
            )
        )
        if blocks:
            any_reach_blocked = True
            reason_codes.append(CoverageReasonCode.GUARD_DOMINATES_SENSITIVE_PATH)
        else:
            all_reaches_blocked = False
            if (
                expected_flags
                and all_observed_flags
                and not set(expected_flags).issubset(all_observed_flags)
            ):
                reason_codes.append(CoverageReasonCode.WRONG_FLAG_GUARD)
                notes.append(
                    f"Guard checks {sorted(all_observed_flags)} instead of "
                    f"expected {expected_flags}."
                )
            elif "unknown_provider_state" in detail:
                reason_codes.append(CoverageReasonCode.UNKNOWN_PROVIDER_STATE)
                notes.append(
                    f"Guard cannot prove fail-closed behavior under UNKNOWN state ({detail})."
                )
            else:
                reason_codes.append(CoverageReasonCode.GUARD_CONDITION_NOT_SUFFICIENT)
                notes.append(f"Guard does not block sink when disabled ({detail}).")

    if post_guards and CoverageReasonCode.GUARD_AFTER_SENSITIVE_OPERATION not in reason_codes:
        reason_codes.append(CoverageReasonCode.GUARD_AFTER_SENSITIVE_OPERATION)
        all_reaches_blocked = False

    if unresolved:
        reason_codes.append(CoverageReasonCode.UNRESOLVED_HELPER_CALL)
        notes.append(f"Unresolved helper call(s): {', '.join(unresolved)}")
        status = (
            CoverageStatus.UNKNOWN
            if not any_reach_blocked
            else CoverageStatus.PARTIALLY_PROTECTED
        )
    elif all_reaches_blocked and any_reach_blocked:
        status = CoverageStatus.PROTECTED
    elif any_reach_blocked:
        status = CoverageStatus.PARTIALLY_PROTECTED
    elif CoverageReasonCode.UNKNOWN_PROVIDER_STATE in reason_codes:
        status = CoverageStatus.UNKNOWN
    else:
        status = CoverageStatus.UNPROTECTED

    dedup_reasons = list(dict.fromkeys(reason_codes))
    updated_ident = ident.model_copy(
        update={"implementation_id": primary_sink.implementation_id}
    )
    return ExecutionPathAssessment(
        path_id=path_id,
        route_identity=updated_ident,
        sensitive_implementation=primary_sink.symbol_name,
        call_chain=list(reaches[0].call_chain),
        guard_conditions=guard_models,
        dominates_sink=all_reaches_blocked and any_reach_blocked,
        effective_when_disabled=all_reaches_blocked and any_reach_blocked,
        status=status,
        applicability=CoverageApplicability.APPLICABLE,
        expected_flags=expected_flags,
        observed_flags=sorted(all_observed_flags),
        reason_codes=dedup_reasons,
        source_ref=call_index.make_source_ref(reaches[0].entry, reaches[0].sink_node),
        notes=notes,
    )


def _collect_state_dict_vars(func_node: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    vars_found: set[str] = set()
    for node in ast.walk(func_node):
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Call)
            and isinstance(node.value.func, ast.Attribute)
            and node.value.func.attr == "get_states"
        ):
            for tgt in node.targets:
                if isinstance(tgt, ast.Name):
                    vars_found.add(tgt.id)
    return vars_found


def _walk_statements(
    stmts: list[ast.stmt],
    *,
    entry: SourceFileEntry,
    call_index: LocalCallIndex,
    state_vars: set[str],
    active_guards: tuple[BoolExpr, ...],
    active_guard_nodes: tuple[ast.AST, ...],
    call_chain: tuple[str, ...],
    depth: int,
    max_call_depth: int,
    reaches: list[_SinkReach],
    unresolved: list[str],
    logging_flags: list[str],
    post_guards: list[BoolExpr],
) -> bool:
    """Walk statements sequentially, propagating early-return negated guards.

    Returns True if all paths through ``stmts`` terminate (return/raise).
    """
    local_guards = active_guards
    local_guard_nodes = active_guard_nodes
    saw_sink_already = False

    for stmt in stmts:
        if isinstance(stmt, (ast.Return, ast.Raise)):
            # Check calls inside the return expression too (e.g. return vulnerable_search(...))
            _scan_expr_calls(
                stmt.value if isinstance(stmt, ast.Return) and stmt.value else stmt,
                entry=entry,
                call_index=call_index,
                state_vars=state_vars,
                active_guards=local_guards,
                active_guard_nodes=local_guard_nodes,
                call_chain=call_chain,
                depth=depth,
                max_call_depth=max_call_depth,
                reaches=reaches,
                unresolved=unresolved,
                logging_flags=logging_flags,
            )
            return True

        if isinstance(stmt, ast.If):
            cond_expr = parse_guard_expr(stmt.test, state_dict_vars=state_vars)
            if saw_sink_already and cond_expr.referenced_flags():
                post_guards.append(cond_expr)

            # Logging-only check detection (e.g. if flag: logger.info(...))
            if cond_expr.referenced_flags() and _is_logging_only_body(stmt.body):
                logging_flags.extend(cond_expr.referenced_flags())
                continue

            then_terminates = _walk_statements(
                stmt.body,
                entry=entry,
                call_index=call_index,
                state_vars=state_vars,
                active_guards=(*local_guards, cond_expr),
                active_guard_nodes=(*local_guard_nodes, stmt),
                call_chain=call_chain,
                depth=depth,
                max_call_depth=max_call_depth,
                reaches=reaches,
                unresolved=unresolved,
                logging_flags=logging_flags,
                post_guards=post_guards,
            )
            else_terminates = False
            if stmt.orelse:
                else_terminates = _walk_statements(
                    stmt.orelse,
                    entry=entry,
                    call_index=call_index,
                    state_vars=state_vars,
                    active_guards=(*local_guards, negate_expr(cond_expr)),
                    active_guard_nodes=(*local_guard_nodes, stmt),
                    call_chain=call_chain,
                    depth=depth,
                    max_call_depth=max_call_depth,
                    reaches=reaches,
                    unresolved=unresolved,
                    logging_flags=logging_flags,
                    post_guards=post_guards,
                )
            if then_terminates and not stmt.orelse:
                # Early return! Subsequent statements only run when NOT(cond_expr).
                local_guards = (*local_guards, negate_expr(cond_expr))
                local_guard_nodes = (*local_guard_nodes, stmt)
            elif then_terminates and else_terminates:
                return True
            continue

        reaches_before = len(reaches)
        _scan_expr_calls(
            stmt,
            entry=entry,
            call_index=call_index,
            state_vars=state_vars,
            active_guards=local_guards,
            active_guard_nodes=local_guard_nodes,
            call_chain=call_chain,
            depth=depth,
            max_call_depth=max_call_depth,
            reaches=reaches,
            unresolved=unresolved,
            logging_flags=logging_flags,
        )
        if len(reaches) > reaches_before:
            saw_sink_already = True

    return False


def _scan_expr_calls(
    node: ast.AST,
    *,
    entry: SourceFileEntry,
    call_index: LocalCallIndex,
    state_vars: set[str],
    active_guards: tuple[BoolExpr, ...],
    active_guard_nodes: tuple[ast.AST, ...],
    call_chain: tuple[str, ...],
    depth: int,
    max_call_depth: int,
    reaches: list[_SinkReach],
    unresolved: list[str],
    logging_flags: list[str],
) -> None:
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        callee = call_index.resolve_callee_name(sub)
        if callee is None:
            unresolved.append("<dynamic_call>")
            continue
        if isinstance(sub.func, ast.Name) and sub.func.id in DYNAMIC_CALL_NAMES:
            unresolved.append(sub.func.id)
            continue
        if callee in SAFE_FALLBACK_SYMBOLS:
            continue
        if callee in call_index.sinks_by_symbol:
            reaches.append(
                _SinkReach(
                    sink=call_index.sinks_by_symbol[callee],
                    call_chain=(*call_chain, callee),
                    dominating_guards=active_guards,
                    guard_nodes=active_guard_nodes,
                    sink_node=sub,
                    entry=entry,
                )
            )
            continue
        if callee in call_index.functions and callee not in call_chain:
            if depth >= max_call_depth:
                unresolved.append(f"{callee}(max_depth)")
                continue
            helper_node, helper_entry = call_index.functions[callee]
            helper_state_vars = state_vars | _collect_state_dict_vars(helper_node)
            post_tmp: list[BoolExpr] = []
            _walk_statements(
                helper_node.body,
                entry=helper_entry,
                call_index=call_index,
                state_vars=helper_state_vars,
                active_guards=active_guards,
                active_guard_nodes=active_guard_nodes,
                call_chain=(*call_chain, callee),
                depth=depth + 1,
                max_call_depth=max_call_depth,
                reaches=reaches,
                unresolved=unresolved,
                logging_flags=logging_flags,
                post_guards=post_tmp,
            )


def _is_logging_only_body(stmts: list[ast.stmt]) -> bool:
    if not stmts:
        return False
    for stmt in stmts:
        if isinstance(stmt, (ast.Return, ast.Raise)):
            return False
        if (
            isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Call)
            and isinstance(stmt.value.func, ast.Attribute)
            and stmt.value.func.attr in {"info", "debug", "warning", "error"}
        ):
            continue
        return False
    return True
