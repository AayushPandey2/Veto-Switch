"""Abstract service interfaces (Protocols) enforcing dependency inversion.

Design principles:
    - Core domain logic (``agent_core`` and ``remediation``) depends solely on these
      interfaces rather than concrete LLM providers, databases, or Flagsmith clients.
    - ``FeatureStateReader`` is strictly read-only. Privileged feature flag mutations
      live exclusively in the trusted platform layer and always require verified
      human approval.
    - ``LLMProvider`` and ``PatchTestRunner`` expose zero arbitrary shell execution
      surfaces.
"""

from __future__ import annotations

from typing import Any, Protocol, TypeVar, runtime_checkable

from pydantic import BaseModel, Field

from shared.enums import IncidentState
from shared.schemas import (
    ApprovalDecision,
    ArtifactReference,
    ContainmentProposal,
    DeploymentEvidence,
    FeatureState,
    IncidentEvent,
    IncidentRecord,
    MetricSnapshot,
    ModelMetadata,
    PatchProposal,
    PatchTestResult,
    VerificationResult,
)

SchemaT = TypeVar("SchemaT", bound=BaseModel)


class LLMRequest(BaseModel):
    """Bounded structured-generation request passed to an ``LLMProvider``."""

    task_name: str = Field(min_length=1, description="Logical reasoning task identifier.")
    system_prompt: str = Field(min_length=1, description="Trusted system instructions.")
    user_context: str = Field(
        min_length=1,
        description="Bounded, sanitized context (untrusted inputs must be delimited).",
    )
    max_context_chars: int = Field(default=32_000, ge=100, le=500_000)
    temperature: float = Field(default=0.0, ge=0.0, le=1.0)
    correlation_id: str | None = Field(default=None)


class LLMResponse(BaseModel):
    """Validated structured output and provider metadata returned by ``LLMProvider``."""

    parsed_payload: dict[str, Any] = Field(
        description="JSON object validated against requested target schema."
    )
    metadata: ModelMetadata = Field(description="Provider/model telemetry metadata.")


@runtime_checkable
class LLMProvider(Protocol):
    """Provider-independent interface for bounded structured LLM generation.

    Errors:
        Must raise ``LLMTimeoutError``, ``LLMProviderError``, or
        ``LLMResponseValidationError`` rather than fabricating fallback outputs.
    """

    async def generate_structured(
        self,
        request: LLMRequest,
        output_schema: type[SchemaT],
    ) -> tuple[SchemaT, ModelMetadata]:
        """Generate and validate a structured Pydantic instance from bounded context."""
        ...


@runtime_checkable
class IncidentRepository(Protocol):
    """Persistence contract for top-level incident state with optimistic concurrency."""

    async def create_incident(self, incident: IncidentRecord) -> IncidentRecord:
        """Persist a new incident record."""
        ...

    async def get_incident(self, incident_id: str) -> IncidentRecord | None:
        """Retrieve an incident by ID, or None if not found."""
        ...

    async def update_incident_state(
        self,
        incident_id: str,
        *,
        expected_version: int,
        new_state: IncidentState,
        active_proposal_id: str | None = None,
    ) -> IncidentRecord:
        """Atomically transition incident state when ``expected_version`` matches.

        Raises ``InvalidTransitionError`` or ``IntegrationUnavailableError`` on conflict.
        """
        ...

    async def get_incident_version(self, incident_id: str) -> int | None:
        """Return the current optimistic-concurrency version of an incident."""
        ...


@runtime_checkable
class EventRepository(Protocol):
    """Append-only event store contract supporting idempotent replay and auditing."""

    async def append_event(self, event: IncidentEvent) -> IncidentEvent:
        """Persist a new event, rejecting duplicate ``event_id`` or ``idempotency_token``."""
        ...

    async def list_events(self, incident_id: str) -> list[IncidentEvent]:
        """Return all events for an incident ordered by ascending ``sequence_number``."""
        ...

    async def get_event(self, event_id: str) -> IncidentEvent | None:
        """Retrieve a single event by identifier."""
        ...

    async def event_exists(self, event_id: str) -> bool:
        """Check whether an ``event_id`` has already been recorded."""
        ...


@runtime_checkable
class EvidenceRepository(Protocol):
    """Artifact and evidence metadata store enforcing existence and incident binding."""

    async def store_artifact(
        self, reference: ArtifactReference, content: bytes
    ) -> ArtifactReference:
        """Store artifact bytes and integrity-checked metadata."""
        ...

    async def get_artifact_reference(self, artifact_id: str) -> ArtifactReference | None:
        """Retrieve artifact metadata by identifier."""
        ...

    async def artifact_exists(self, artifact_id: str, *, incident_id: str) -> bool:
        """Verify that an artifact exists AND belongs to the specified incident."""
        ...

    async def list_incident_artifacts(self, incident_id: str) -> list[ArtifactReference]:
        """List all stored artifact references for an incident."""
        ...


@runtime_checkable
class FeatureStateReader(Protocol):
    """Strictly read-only feature-flag observation contract for AI and policy layers.

    IMPORTANT:
        This protocol intentionally omits all write/toggle/mutation methods.
        Feature mutations may only be executed by the privileged platform executor
        after authenticated human approval.
    """

    async def get_feature_state(self, environment: str, feature_name: str) -> FeatureState:
        """Read current observed state for a declared feature flag."""
        ...

    async def list_declared_features(self, environment: str) -> list[FeatureState]:
        """List declared features and their observation statuses in an environment."""
        ...

    async def get_environment_metadata(self, environment: str) -> dict[str, Any]:
        """Retrieve non-secret metadata describing the target Flagsmith environment."""
        ...

    async def get_targeting_configuration(
        self, environment: str, feature_name: str
    ) -> dict[str, Any]:
        """Read segment targeting / progressive percentage rules for a feature."""
        ...


@runtime_checkable
class SecurityVerifier(Protocol):
    """Contract for authorized, isolated security reproduction and regression checks."""

    async def request_verification(
        self,
        *,
        incident_id: str,
        finding_id: str,
        test_id: str,
        phase: str,
        expected_revision: str | None = None,
    ) -> str:
        """Request execution of an authorized security verification; returns ``test_run_id``."""
        ...

    async def get_verification_status(self, test_run_id: str) -> str:
        """Return current execution status string for a verification job."""
        ...

    async def get_verification_result(self, test_run_id: str) -> VerificationResult:
        """Retrieve completed security verification evidence."""
        ...


@runtime_checkable
class PatchTestRunner(Protocol):
    """Contract for bounded, isolated execution of candidate patches.

    Exposes NO arbitrary shell command execution; accepts only validated
    ``PatchProposal`` objects with explicit ``allowed_files`` and ``source_revision``.
    """

    async def submit_patch_test(self, proposal: PatchProposal) -> str:
        """Submit a bounded candidate patch for isolated testing; returns ``test_run_id``."""
        ...

    async def get_test_run_status(self, test_run_id: str) -> str:
        """Retrieve isolated patch test job status."""
        ...

    async def get_patch_test_result(self, test_run_id: str) -> PatchTestResult:
        """Retrieve completed patch test outcomes and artifact references."""
        ...


@runtime_checkable
class TelemetryReader(Protocol):
    """Read-only telemetry contract for deterministic rollout guardrail evaluation."""

    async def get_metric_snapshot(
        self,
        environment: str,
        feature_id: str,
        *,
        incident_id: str,
        window_seconds: int,
    ) -> MetricSnapshot:
        """Retrieve current metric snapshot (explicitly marked if synthetic)."""
        ...

    async def get_baseline_reference(
        self, environment: str, feature_id: str
    ) -> MetricSnapshot | None:
        """Retrieve baseline telemetry reference, or None if missing."""
        ...

    async def get_observation_window_seconds(self, environment: str, feature_id: str) -> int:
        """Return available observation window duration in seconds."""
        ...


@runtime_checkable
class ApprovalReader(Protocol):
    """Read-only contract for querying authenticated human approval decisions."""

    async def get_approval(self, approval_id: str) -> ApprovalDecision | None:
        """Retrieve an approval decision by identifier."""
        ...

    async def validate_proposal_approval(
        self,
        proposal: ContainmentProposal,
        approval_id: str,
    ) -> ApprovalDecision:
        """Validate that an authenticated, non-expired approval binds to ``proposal``."""
        ...

    async def get_authorization_evidence(
        self, authorization_context_ref: str
    ) -> dict[str, Any] | None:
        """Retrieve sanitized authorization context evidence for audit reporting."""
        ...


@runtime_checkable
class DeploymentStateReader(Protocol):
    """Read-only contract verifying deployed code revision and implementation addressability."""

    async def get_deployment_evidence(
        self, environment: str, feature_name: str
    ) -> DeploymentEvidence:
        """Retrieve observed deployment revision and addressability status."""
        ...

    async def is_implementation_addressable(
        self, environment: str, implementation_id: str
    ) -> bool:
        """Check whether an implementation is deployed and routable."""
        ...

    async def get_deployment_artifacts(
        self, deployment_id: str
    ) -> list[ArtifactReference]:
        """Retrieve artifact metadata supporting a deployment observation."""
        ...
