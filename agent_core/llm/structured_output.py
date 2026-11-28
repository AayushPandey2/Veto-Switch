"""Safe JSON parsing, Pydantic schema validation, and bounded output repair helpers."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError
from shared.enums import AIProviderErrorCategory
from shared.exceptions import LLMResponseValidationError

from agent_core.llm.error_mapping import NormalizedLLMError
from agent_core.llm.response import GatewayLLMResponse

SchemaT = TypeVar("SchemaT", bound=BaseModel)
SemanticValidatorFn = Callable[[BaseModel], list[str]]

_FENCE_PATTERN = re.compile(r"^\s*```(?:json)?\s*(.*?)\s*```\s*$", re.DOTALL | re.IGNORECASE)


def parse_json_object_safely(raw_text: str) -> dict[str, Any]:
    """Parse strictly a single JSON object without code evaluation or guessing.

    Strips at most a single surrounding markdown ````json``` fence. Rejects ambiguous
    multi-object text or non-object JSON roots.
    """
    stripped = raw_text.strip()
    if not stripped:
        raise LLMResponseValidationError(
            "LLM returned empty content when JSON object was expected."
        )

    match = _FENCE_PATTERN.match(stripped)
    candidate = match.group(1).strip() if match else stripped

    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError as exc:
        raise LLMResponseValidationError(
            "LLM output is not valid JSON.",
            context={"json_error": str(exc.msg), "line": exc.lineno, "col": exc.colno},
        ) from exc

    if not isinstance(parsed, dict):
        raise LLMResponseValidationError(
            f"Expected JSON object at root, received {type(parsed).__name__}.",
        )
    return parsed


def format_validation_errors_for_repair(exc: Exception) -> str:
    """Produce a concise, secret-free validation error summary for bounded repair."""
    if isinstance(exc, ValidationError):
        issues: list[str] = []
        for err in exc.errors()[:6]:
            loc = ".".join(str(part) for part in err.get("loc", ()))
            issues.append(f"- field '{loc}': {err.get('msg', 'invalid')}")
        return "\n".join(issues)
    if isinstance(exc, LLMResponseValidationError):
        return exc.message
    return f"{type(exc).__name__}: {exc}"


def validate_structured_response(
    response: GatewayLLMResponse,
    response_model: type[SchemaT],
    *,
    semantic_validator: SemanticValidatorFn | None = None,
) -> SchemaT:
    """Validate response status, JSON structure, strict Pydantic schema, and semantic rules."""
    if response.status not in {"ok", "incomplete"}:
        raise NormalizedLLMError(
            f"Provider response status {response.status!r} cannot be parsed as valid output.",
            category=AIProviderErrorCategory.RESPONSE_VALIDATION_FAILURE,
            provider=response.provider,
        )

    if response.structured_response is not None:
        raw_obj = response.structured_response
    else:
        raw_obj = parse_json_object_safely(response.content)

    try:
        validated = response_model.model_validate(raw_obj)
    except ValidationError as exc:
        raise LLMResponseValidationError(
            f"Response failed strict {response_model.__name__} schema validation.",
            context={"validation_summary": format_validation_errors_for_repair(exc)},
        ) from exc

    if semantic_validator is not None:
        semantic_errors = semantic_validator(validated)
        if semantic_errors:
            raise LLMResponseValidationError(
                "Response failed semantic validation checks.",
                context={"semantic_errors": semantic_errors[:8]},
            )

    return validated
