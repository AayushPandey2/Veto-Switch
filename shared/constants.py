"""Centralized constants for Killswitch X shared contracts and utilities.

Avoids scattered magic numbers and ensures consistent schema versions, hash formats,
identifier prefixes, rollout demonstration defaults, and redaction keywords across all
subsystems.
"""

from __future__ import annotations

from typing import Final

SCHEMA_VERSION: Final[str] = "1.0.0"
POLICY_VERSION: Final[str] = "1.0.0"
PAYLOAD_MODEL_VERSION: Final[str] = "1.0.0"

HASH_ALGORITHM_SHA256: Final[str] = "sha256"
SHA256_HEX_LENGTH: Final[int] = 64

IDENTIFIER_MIN_LENGTH: Final[int] = 4
IDENTIFIER_MAX_LENGTH: Final[int] = 128

DEFAULT_LLM_TIMEOUT_SECONDS: Final[float] = 30.0
DEFAULT_LLM_MAX_RETRIES: Final[int] = 2
DEFAULT_LLM_MAX_CONTEXT_CHARS: Final[int] = 32_000
DEFAULT_PROPOSAL_EXPIRATION_SECONDS: Final[int] = 900

# Demonstration rollout stages (percentages, 0-100). Configurable via policy file.
DEFAULT_ROLLOUT_STAGES_PERCENT: Final[tuple[int, ...]] = (5, 25, 50, 100)

# Illustrative demonstration rollout guardrail defaults (not production thresholds).
DEMO_MAX_ERROR_RATE: Final[float] = 0.02  # 2% as ratio [0.0, 1.0]
DEMO_MAX_ERROR_RATE_INCREASE_PP: Final[float] = 1.0  # percentage points
DEMO_MAX_P95_LATENCY_INCREASE_PERCENT: Final[float] = 20.0  # percent
DEMO_MIN_REQUEST_COUNT: Final[int] = 100  # requests
DEMO_MIN_OBSERVATION_WINDOW_SECONDS: Final[int] = 30  # seconds

# Default configuration fixture paths relative to repository root.
DEFAULT_ARTIFACT_DIR: Final[str] = "artifacts"
DEFAULT_ROUTE_REGISTRY_PATH: Final[str] = "config/route_flag_map.json"
DEFAULT_DEPENDENCY_GRAPH_PATH: Final[str] = "config/dependency_graph.json"
DEFAULT_ROLLOUT_POLICY_PATH: Final[str] = "config/rollout_policy.json"

# Standardized entity identifier prefixes.
ID_PREFIXES: Final[dict[str, str]] = {
    "incident": "inc",
    "finding": "fnd",
    "investigation": "inv",
    "option": "opt",
    "proposal": "prop",
    "approval": "appr",
    "operation": "op",
    "verification": "ver",
    "event": "evt",
    "patch": "pat",
    "artifact": "art",
    "test_run": "trun",
    "deployment": "dep",
    "rollout_plan": "rplan",
    "rollout_stage": "rstage",
    "rollout_decision": "rdec",
    "rollback": "rbk",
    "metric_snapshot": "met",
    "coverage_finding": "cov",
    "report": "rep",
    "correlation": "corr",
    "idempotency": "idem",
}

REDACTED_PLACEHOLDER: Final[str] = "[REDACTED]"

# Lowercase substrings triggering redaction in diagnostic logging/error sanitization.
SENSITIVE_FIELD_KEYWORDS: Final[tuple[str, ...]] = (
    "api_key",
    "apikey",
    "authorization",
    "bearer",
    "password",
    "passwd",
    "secret",
    "token",
    "session_id",
    "session_token",
    "management_token",
    "private_key",
    "credential",
    "cookie",
    "signing_key",
)

# Canonical ordered fields included in ContainmentProposal.proposal_hash.
CANONICAL_PROPOSAL_HASH_FIELDS: Final[tuple[str, ...]] = (
    "proposal_id",
    "incident_id",
    "proposal_type",
    "environment",
    "flag_name",
    "desired_enabled",
    "expected_current_enabled",
    "registry_version",
    "policy_version",
    "approval_required",
    "idempotency_token",
)
