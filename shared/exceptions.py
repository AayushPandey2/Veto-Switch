"""Standardized exception hierarchy for Killswitch X.

Every exception carries:
- ``error_code``: stable machine-readable identifier.
- ``message``: sanitized human-readable explanation.
- ``context``: sanitized structured metadata (sensitive keys are automatically redacted).
- ``retryable``: explicit indicator of whether bounded retry may be appropriate.
"""

from __future__ import annotations

from typing import Any

from shared.constants import REDACTED_PLACEHOLDER, SENSITIVE_FIELD_KEYWORDS


def _sanitize_context(context: dict[str, Any] | None) -> dict[str, Any]:
    """Redact any potentially sensitive keys before storing exception context."""
    if not context:
        return {}
    sanitized: dict[str, Any] = {}
    for key, value in context.items():
        lowered = key.lower()
        if any(keyword in lowered for keyword in SENSITIVE_FIELD_KEYWORDS):
            sanitized[key] = REDACTED_PLACEHOLDER
        elif isinstance(value, dict):
            sanitized[key] = _sanitize_context(value)
        else:
            sanitized[key] = value
    return sanitized


class KillswitchError(Exception):
    """Base exception for all Killswitch X domain and integration errors."""

    default_error_code: str = "KILLSWITCH_ERROR"
    default_retryable: bool = False

    def __init__(
        self,
        message: str,
        *,
        error_code: str | None = None,
        context: dict[str, Any] | None = None,
        retryable: bool | None = None,
    ) -> None:
        super().__init__(message)
        self.error_code: str = error_code or self.default_error_code
        self.message: str = message
        self.context: dict[str, Any] = _sanitize_context(context)
        self.retryable: bool = self.default_retryable if retryable is None else retryable

    def to_dict(self) -> dict[str, Any]:
        """Serialize exception details safely for structured logs or API error payloads."""
        return {
            "error_code": self.error_code,
            "message": self.message,
            "context": self.context,
            "retryable": self.retryable,
        }


class ConfigurationError(KillswitchError):
    """Invalid, missing, or inconsistent configuration."""

    default_error_code = "CONFIGURATION_ERROR"


class ContractValidationError(KillswitchError):
    """Data contract or schema invariant violation."""

    default_error_code = "CONTRACT_VALIDATION_ERROR"


class EvidenceValidationError(KillswitchError):
    """Evidence payload, provenance, or cross-reference validation failed."""

    default_error_code = "EVIDENCE_VALIDATION_ERROR"


class EvidenceNotFoundError(KillswitchError):
    """Referenced evidence artifact or record could not be located."""

    default_error_code = "EVIDENCE_NOT_FOUND"


class UnauthorizedOperationError(KillswitchError):
    """Attempted privileged or unapproved operation outside trust boundary."""

    default_error_code = "UNAUTHORIZED_OPERATION"


class InvalidApprovalError(KillswitchError):
    """Approval does not match proposal identity, hash, decision, or actor trust."""

    default_error_code = "INVALID_APPROVAL"


class ExpiredApprovalError(KillswitchError):
    """Approval has passed its expiration timestamp or was invalidated."""

    default_error_code = "EXPIRED_APPROVAL"


class InvalidTransitionError(KillswitchError):
    """Requested incident state transition violates deterministic state rules."""

    default_error_code = "INVALID_STATE_TRANSITION"


class UnknownFeatureError(KillswitchError):
    """Target feature flag is unknown or undeclared in the active registry."""

    default_error_code = "UNKNOWN_FEATURE"


class AmbiguousMappingError(KillswitchError):
    """Affected route/component maps to multiple flags and requires manual review."""

    default_error_code = "AMBIGUOUS_MAPPING"


class LLMProviderError(KillswitchError):
    """External or configured LLM provider request failed."""

    default_error_code = "LLM_PROVIDER_ERROR"
    default_retryable = True


class LLMTimeoutError(LLMProviderError):
    """LLM provider request exceeded configured timeout."""

    default_error_code = "LLM_TIMEOUT"
    default_retryable = True


class LLMResponseValidationError(KillswitchError):
    """LLM output failed structured schema validation or safety checks."""

    default_error_code = "LLM_RESPONSE_VALIDATION_ERROR"


class ArtifactValidationError(KillswitchError):
    """Artifact metadata, path, or SHA-256 integrity verification failed."""

    default_error_code = "ARTIFACT_VALIDATION_ERROR"


class RevisionMismatchError(KillswitchError):
    """Tested or deployed source revision does not match the expected revision."""

    default_error_code = "REVISION_MISMATCH"


class PatchValidationError(KillswitchError):
    """Candidate patch violates file allowlist, diff bounds, or safety constraints."""

    default_error_code = "PATCH_VALIDATION_ERROR"


class TestRunnerError(KillswitchError):
    """Isolated verification or patch test runner encountered an execution error."""

    default_error_code = "TEST_RUNNER_ERROR"
    default_retryable = True


class TelemetryUnavailableError(KillswitchError):
    """Required rollout telemetry or baseline reference is missing or unavailable."""

    default_error_code = "TELEMETRY_UNAVAILABLE"
    default_retryable = True


class DeploymentVerificationError(KillswitchError):
    """Deployment revision or implementation addressability could not be verified."""

    default_error_code = "DEPLOYMENT_VERIFICATION_ERROR"


class IntegrationUnavailableError(KillswitchError):
    """Dependent external service or repository backend is temporarily unreachable."""

    default_error_code = "INTEGRATION_UNAVAILABLE"
    default_retryable = True


class ConcurrencyConflictError(KillswitchError):
    """Optimistic concurrency version mismatch during incident commit."""

    default_error_code = "CONCURRENCY_CONFLICT"
    default_retryable = True


class IdempotencyConflictError(KillswitchError):
    """Same event or idempotency identifier submitted with conflicting payload."""

    default_error_code = "IDEMPOTENCY_CONFLICT"
    default_retryable = False


class ReplayIntegrityError(KillswitchError):
    """Recorded incident event history failed ordering, identity, or transition replay."""

    default_error_code = "REPLAY_INTEGRITY_ERROR"
    default_retryable = False
