"""Category E tests: structured JSON parsing, strict schema checks, bounded repair."""

from __future__ import annotations

import pytest
from agent_core.intelligence.response_validator import RawInvestigationOutput
from agent_core.llm.gateway import LLMGateway
from agent_core.llm.provider_registry import ProviderRegistry
from agent_core.llm.providers.fixture import FixtureBehaviorMode, FixtureLLMProvider
from agent_core.llm.response import GatewayLLMResponse
from agent_core.llm.routing import ModelRouter
from agent_core.llm.structured_output import (
    parse_json_object_safely,
    validate_structured_response,
)
from agent_core.retry_policy import RetryPolicyConfig
from shared.enums import AITaskType
from shared.exceptions import LLMProviderError, LLMResponseValidationError
from shared.identifiers import utc_now


@pytest.mark.unit
def test_parse_json_object_safely_strips_single_fence_and_rejects_malformed() -> None:
    fenced = '```json\n{"a": 1}\n```'
    assert parse_json_object_safely(fenced) == {"a": 1}

    for bad in ("", "not json", "[1, 2, 3]", '{"a": 1}\nextra garbage'):
        with pytest.raises(LLMResponseValidationError):
            parse_json_object_safely(bad)


@pytest.mark.unit
def test_validate_structured_response_rejects_missing_bad_enum_and_extra_fields() -> None:
    base_resp = GatewayLLMResponse(
        request_id="lreq_1234",
        provider="offline_fixture",
        model="fixture-v1",
        timestamp=utc_now(),
        status="ok",
    )
    # Missing required fields
    with pytest.raises(LLMResponseValidationError):
        validate_structured_response(
            base_resp.model_copy(update={"structured_response": {"executive_summary": "hi"}}),
            RawInvestigationOutput,
        )

    # Extra unexpected field rejected under strict KillswitchModel (extra='forbid')
    valid_minimal = {
        "executive_summary": "SQLi summary",
        "technical_explanation": "Details",
        "affected_components": ["search_service"],
        "recommended_next_action": "request_verification",
        "unexpected_extra": "bad",
    }
    with pytest.raises(LLMResponseValidationError):
        validate_structured_response(
            base_resp.model_copy(update={"structured_response": valid_minimal}),
            RawInvestigationOutput,
        )

    # Invalid action enumeration rejected
    bad_enum = dict(valid_minimal)
    del bad_enum["unexpected_extra"]
    bad_enum["recommended_next_action"] = "disable_flag_now"
    with pytest.raises(LLMResponseValidationError):
        validate_structured_response(
            base_resp.model_copy(update={"structured_response": bad_enum}),
            RawInvestigationOutput,
        )


@pytest.mark.unit
async def test_gateway_repair_exhaustion_raises_validation_error() -> None:
    fix = FixtureLLMProvider(
        mode_sequence=[
            FixtureBehaviorMode.MALFORMED_JSON,
            FixtureBehaviorMode.SCHEMA_INVALID,
            FixtureBehaviorMode.UNEXPECTED_FIELDS,
        ]
    )
    reg = ProviderRegistry()
    reg.register(fix)
    gw = LLMGateway(
        registry=reg,
        router=ModelRouter(registry=reg),
        retry_config=RetryPolicyConfig(
            max_attempts=1, initial_backoff_seconds=0.0, max_backoff_seconds=0.0
        ),
        max_repair_attempts=1,
    )
    with pytest.raises(LLMProviderError):
        await gw.generate_structured(
            AITaskType.INVESTIGATION,
            {"finding": {"finding_id": "fnd_01"}},
            RawInvestigationOutput,
            incident_id="inc_01",
        )
    # Initial call + at most 1 bounded repair attempt = 2 calls total (not infinite loop)
    assert len(fix.invocations) == 2
