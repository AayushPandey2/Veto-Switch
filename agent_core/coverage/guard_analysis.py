"""Typed boolean guard extraction and three-valued FeatureState truth-table reasoning."""

from __future__ import annotations

import ast
from dataclasses import dataclass
from itertools import product
from typing import Literal

ThreeValuedState = Literal["ENABLED", "DISABLED", "UNKNOWN"]


@dataclass(frozen=True)
class BoolExpr:
    """Bounded boolean formula over feature-flag states."""

    kind: Literal["atom", "and", "or", "not", "unknown"]
    flag_name: str | None = None
    expected_state: Literal["ENABLED", "DISABLED"] = "ENABLED"
    negated: bool = False
    children: tuple[BoolExpr, ...] = ()
    summary: str = ""

    def referenced_flags(self) -> list[str]:
        flags: list[str] = []
        if self.kind == "atom" and self.flag_name:
            flags.append(self.flag_name)
        for child in self.children:
            for f in child.referenced_flags():
                if f not in flags:
                    flags.append(f)
        return flags

    def evaluate(self, assignment: dict[str, ThreeValuedState]) -> bool | None:
        """Evaluate formula under a 3-valued flag assignment.

        Returns ``True``/``False`` when determined, or ``None`` when indeterminate.
        Does NOT collapse ``UNKNOWN`` into ``DISABLED``.
        """
        if self.kind == "unknown":
            return None
        if self.kind == "atom":
            if self.flag_name is None:
                return None
            val = assignment.get(self.flag_name, "UNKNOWN")
            if val == "UNKNOWN":
                return None
            matches = val == self.expected_state
            return (not matches) if self.negated else matches
        if self.kind == "not":
            inner = self.children[0].evaluate(assignment)
            return None if inner is None else (not inner)
        if self.kind == "and":
            vals = [c.evaluate(assignment) for c in self.children]
            if any(v is False for v in vals):
                return False
            if all(v is True for v in vals):
                return True
            return None
        if self.kind == "or":
            vals = [c.evaluate(assignment) for c in self.children]
            if any(v is True for v in vals):
                return True
            if all(v is False for v in vals):
                return False
            return None
        return None


def negate_expr(expr: BoolExpr) -> BoolExpr:
    """Return logical negation of ``expr``."""
    if expr.kind == "not" and expr.children:
        return expr.children[0]
    return BoolExpr(kind="not", children=(expr,), summary=f"not ({expr.summary})")


def parse_guard_expr(
    node: ast.expr,
    *,
    state_dict_vars: set[str],
) -> BoolExpr:
    """Parse a Python AST boolean expression into a bounded ``BoolExpr``."""
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        inner = parse_guard_expr(node.operand, state_dict_vars=state_dict_vars)
        return BoolExpr(kind="not", children=(inner,), summary=f"not ({inner.summary})")

    if isinstance(node, ast.BoolOp):
        op_kind: Literal["and", "or"] = "and" if isinstance(node.op, ast.And) else "or"
        children = tuple(
            parse_guard_expr(v, state_dict_vars=state_dict_vars) for v in node.values
        )
        sep = f" {op_kind} "
        return BoolExpr(
            kind=op_kind,
            children=children,
            summary=sep.join(c.summary for c in children),
        )

    # provider.is_enabled("flag") or is_flag_enabled("flag")
    if isinstance(node, ast.Call):
        flag = _extract_is_enabled_flag(node)
        if flag is not None:
            return BoolExpr(
                kind="atom",
                flag_name=flag,
                expected_state="ENABLED",
                summary=f"is_enabled({flag!r})",
            )

    # states["search_v1"] is FeatureState.ENABLED / is not FeatureState.ENABLED / == ...
    if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
        parsed_cmp = _parse_state_compare(
            node.left, node.ops[0], node.comparators[0], state_dict_vars=state_dict_vars
        )
        if parsed_cmp is not None:
            return parsed_cmp

    if node_is_unparsed := (
        ast.unparse(node) if hasattr(ast, "unparse") else "<expr>"
    ):
        return BoolExpr(kind="unknown", summary=node_is_unparsed)
    return BoolExpr(kind="unknown", summary="<expr>")


def condition_blocks_when_flag_disabled(
    guard_expr: BoolExpr,
    *,
    expected_flags: tuple[str, ...],
) -> tuple[bool, str]:
    """Check via 3-valued truth table whether ``guard_expr`` blocks when flags are DISABLED.

    Returns ``(blocks_reliably, reason_detail)``.
    """
    if not expected_flags:
        return False, "no_expected_flag"
    flags = sorted(set(guard_expr.referenced_flags()) | set(expected_flags))
    if not flags or len(flags) > 5:
        return False, "guard_flags_unresolved_or_too_many"

    saw_unknown = False
    states_tuple: tuple[ThreeValuedState, ...] = ("ENABLED", "DISABLED", "UNKNOWN")
    for combo in product(states_tuple, repeat=len(flags)):
        assignment: dict[str, ThreeValuedState] = dict(zip(flags, combo, strict=True))
        # We care about states where ALL expected flags for this legacy sink are DISABLED.
        if not all(assignment[ef] == "DISABLED" for ef in expected_flags):
            continue
        res = guard_expr.evaluate(assignment)
        if res is True:
            return False, f"sink_reachable_when_disabled_under:{assignment}"
        if res is None:
            saw_unknown = True

    if saw_unknown:
        return False, "guard_indeterminate_for_unknown_provider_state"
    return True, "blocks_all_disabled_assignments"


def _extract_is_enabled_flag(call: ast.Call) -> str | None:
    is_attr_call = isinstance(call.func, ast.Attribute) and call.func.attr in {
        "is_enabled",
        "is_flag_enabled",
        "enabled",
    }
    is_name_call = isinstance(call.func, ast.Name) and call.func.id in {
        "is_enabled",
        "is_flag_enabled",
        "flag_enabled",
    }
    if (
        (is_attr_call or is_name_call)
        and call.args
        and isinstance(call.args[0], ast.Constant)
        and isinstance(call.args[0].value, str)
    ):
        return call.args[0].value
    return None


def _parse_state_compare(
    left: ast.expr,
    op: ast.cmpop,
    right: ast.expr,
    *,
    state_dict_vars: set[str],
) -> BoolExpr | None:
    flag_name = _extract_state_subscript_flag(left, state_dict_vars=state_dict_vars)
    if flag_name is None:
        return None
    target_state = _extract_feature_state_literal(right)
    if target_state is None:
        return None
    if isinstance(op, (ast.Is, ast.Eq)):
        return BoolExpr(
            kind="atom",
            flag_name=flag_name,
            expected_state=target_state,
            negated=False,
            summary=f"states[{flag_name!r}] is {target_state}",
        )
    if isinstance(op, (ast.IsNot, ast.NotEq)):
        return BoolExpr(
            kind="atom",
            flag_name=flag_name,
            expected_state=target_state,
            negated=True,
            summary=f"states[{flag_name!r}] is not {target_state}",
        )
    return None


def _extract_state_subscript_flag(expr: ast.expr, *, state_dict_vars: set[str]) -> str | None:
    if not isinstance(expr, ast.Subscript):
        return None
    if not isinstance(expr.value, ast.Name) or expr.value.id not in state_dict_vars:
        return None
    slc = expr.slice
    if isinstance(slc, ast.Constant) and isinstance(slc.value, str):
        return slc.value
    return None


def _extract_feature_state_literal(expr: ast.expr) -> Literal["ENABLED", "DISABLED"] | None:
    if isinstance(expr, ast.Attribute) and expr.attr in {"ENABLED", "DISABLED"}:
        return "ENABLED" if expr.attr == "ENABLED" else "DISABLED"
    if isinstance(expr, ast.Constant) and isinstance(expr.value, bool):
        return "ENABLED" if expr.value else "DISABLED"
    return None
