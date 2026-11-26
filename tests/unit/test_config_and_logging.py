"""Unit tests for configuration separation, secret redaction, and structured logging."""

from __future__ import annotations

import io
import json
import logging

import pytest
from shared.config import AIServiceSettings, PlatformPrivilegedSettings, load_ai_settings
from shared.constants import REDACTED_PLACEHOLDER
from shared.logging_config import (
    StructuredJsonFormatter,
    configure_logging,
    log_structured,
    redact_mapping,
    redact_text,
)


@pytest.mark.unit
def test_ai_settings_load_without_credentials() -> None:
    """Scenario 24: AI settings initialize cleanly with safe offline defaults."""
    settings = load_ai_settings()
    assert isinstance(settings, AIServiceSettings)
    assert settings.llm_provider == "offline_fixture"
    summary = settings.safe_summary()
    assert summary["llm_api_key_configured"] is False


@pytest.mark.unit
def test_settings_mask_synthetic_secrets_in_summaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Scenario 20: SecretStr credentials are never exposed by safe_summary()."""
    synthetic_llm_key = "sk-synthetic-demo-key-99999999"
    synthetic_flagsmith_token = "fs_synthetic_mgmt_token_888888"
    monkeypatch.setenv("KILLSWITCH_LLM_API_KEY", synthetic_llm_key)
    monkeypatch.setenv(
        "KILLSWITCH_PLATFORM_FLAGSMITH_MANAGEMENT_TOKEN", synthetic_flagsmith_token
    )

    ai_cfg = AIServiceSettings()
    plat_cfg = PlatformPrivilegedSettings()

    assert synthetic_llm_key not in str(ai_cfg.safe_summary())
    assert synthetic_flagsmith_token not in str(plat_cfg.safe_summary())
    assert ai_cfg.safe_summary()["llm_api_key_configured"] is True
    assert plat_cfg.safe_summary()["flagsmith_management_token_configured"] is True


@pytest.mark.unit
def test_secret_redaction_removes_synthetic_credentials() -> None:
    """Scenario 19: Text and mapping redaction scrub tokens, headers, and keys."""
    raw_text = (
        "Authorization: Bearer synth-token-abcdef123456 "
        "api_key=sk-synth-1234567890 password=synthetic_pw_42"
    )
    scrubbed = redact_text(raw_text)
    assert "synth-token-abcdef123456" not in scrubbed
    assert "sk-synth-1234567890" not in scrubbed
    assert "synthetic_pw_42" not in scrubbed
    assert REDACTED_PLACEHOLDER in scrubbed

    raw_map = {
        "incident_id": "inc_0001",
        "authorization": "Bearer synth_bearer_9999",
        "flagsmith_management_token": "fs_mgmt_synth_12345",
        "nested": {"session_token": "sess_synth_abcdef"},
    }
    clean_map = redact_mapping(raw_map)
    assert clean_map["incident_id"] == "inc_0001"
    assert clean_map["authorization"] == REDACTED_PLACEHOLDER
    assert clean_map["flagsmith_management_token"] == REDACTED_PLACEHOLDER
    assert clean_map["nested"]["session_token"] == REDACTED_PLACEHOLDER


@pytest.mark.unit
def test_structured_logging_does_not_leak_synthetic_credentials() -> None:
    """Scenario 20: Structured JSON log output redacts embedded synthetic credentials."""
    stream = io.StringIO()
    logger = configure_logging(level="INFO", log_format="json", logger_name="killswitch.test")
    logger.handlers[0].stream = stream  # type: ignore[attr-defined]
    logger.handlers[0].setFormatter(StructuredJsonFormatter())

    log_structured(
        logger,
        logging.INFO,
        "Connecting with Bearer synth_secret_token_9999",
        incident_id="inc_0001",
        correlation_id="corr_0001",
        event_type="finding_received",
        operation_status="ok",
        context={"api_key": "sk-synthetic-leak-check", "flag": "search_v1"},
    )
    output = stream.getvalue().strip()
    assert "synth_secret_token_9999" not in output
    assert "sk-synthetic-leak-check" not in output
    parsed = json.loads(output)
    assert parsed["incident_id"] == "inc_0001"
    assert parsed["context"]["api_key"] == REDACTED_PLACEHOLDER
    assert parsed["context"]["flag"] == "search_v1"
