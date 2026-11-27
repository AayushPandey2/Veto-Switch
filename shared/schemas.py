"""Shared Pydantic data contracts for Killswitch X.

All models enforce strict validation (``extra="forbid"``), explicit UTC timestamps,
collision-resistant identifiers, and fail-closed invariants so missing or unverified
data cannot silently masquerade as verified success.

Units used by numeric fields:
    - ``error_rate`` / ``baseline_error_rate``: dimensionless ratio in ``[0.0, 1.0]``
      (e.g., ``0.02`` represents 2%).
    - ``max_error_rate_increase_pp``: percentage points in ``[0.0, 100.0]``.
    - ``exposure_percentage`` / ``observed_rollout_stage_percentage``: integer percent
      in ``[0, 100]``.
    - ``max_p95_latency_increase_percent``: percentage increase ``>= 0.0``.
    - ``p50_ms``, ``p95_ms``, ``p99_ms``: latency in milliseconds (``>= 0.0``).
    - ``observation_window_seconds``, ``minimum_observation_window_seconds``: seconds.
    - ``request_count``, ``failed_request_count``, ``minimum_request_count``: requests.
    - ``estimated_disruption``, ``estimated_residual_risk``, ``uncertainty``,
      ``relative_policy_score``: normalized policy estimates in ``[0.0, 1.0]``.
    - ``size_bytes``: artifact byte size (``>= 0``).
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, cast

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    field_validator,
    model_validator,
)

from shared.constants import (
    HASH_ALGORITHM_SHA256,
    PAYLOAD_MODEL_VERSION,
    POLICY_VERSION,
    SCHEMA_VERSION,
)
from shared.enums import (
    ActorType,
    ApprovalStatus,
    ArtifactType,
    ClaimCategory,
    ClaimValidationStatus,
    ContainmentStrategyType,
    CoverageStatus,
    DeploymentStatus,
    EventType,
    EvidenceCompleteness,
    EvidenceProvenance,
    EvidenceSupportLevel,
    FeatureObservationStatus,
    FeatureRole,
    FindingStatus,
    GraphEdgeType,
    GraphNodeType,
    IncidentState,
    InvestigationStatus,
    MappingStatus,
    OperationOutcome,
    PatchOrigin,
    PatchStatus,
    ProposalType,
    RedactionStatus,
    RollbackActionType,
    RolloutDecisionType,
    TestExecutionStatus,
    VerificationPhase,
    VulnerabilityCategory,
    VulnerabilitySeverity,
)
from shared.exceptions import KillswitchError
from shared.identifiers import utc_now
from shared.serialization import (
    compute_proposal_hash,
    compute_rollback_proposal_hash,
    sha256_canonical,
)
from shared.validation import (
    validate_dependency_graph_integrity,
    validate_evidence_reference_ids,
    validate_identifier,
    validate_non_empty_str,
    validate_relative_safe_path,
    validate_rollout_stages_ordering,
    validate_sha256_hex,
    validate_touched_files_within_allowlist,
    validate_unique_ids,
    validate_utc_datetime,
)


def _validate_utc_ts(value: datetime) -> datetime:
    return validate_utc_datetime(value, field_name="timestamp")


def _validate_id_field(value: str) -> str:
    return validate_identifier(value, field_name="identifier")


UtcDatetime = Annotated[datetime, AfterValidator(_validate_utc_ts)]
IdentifierStr = Annotated[str, AfterValidator(_validate_id_field)]


class KillswitchModel(BaseModel):
    """Base Pydantic model for all Killswitch X shared data contracts."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=False,
        str_strip_whitespace=True,
        validate_assignment=True,
        ser_json_timedelta="iso8601",
    )


class ModelMetadata(KillswitchModel):
    """Non-authoritative LLM invocation metadata attached to AI-assisted outputs."""

    provider: str = Field(min_length=1, description="Configured LLM provider identifier.")
    model_name: str = Field(min_length=1, description="Configured model name.")
    prompt_version: str = Field(
        default="1.0.0", min_length=1, description="Version of the prompt template used."
    )
    latency_ms: float | None = Field(
        default=None, ge=0.0, description="Observed model call latency in milliseconds."
    )
    token_usage: StrictInt | None = Field(
        default=None, ge=0, description="Total tokens consumed if reported by provider."
    )
    prompt_hash: str | None = Field(
        default=None, description="SHA-256 hash of exact versioned prompt templates used."
    )
    context_hash: str | None = Field(
        default=None, description="Canonical SHA-256 hash of sanitized bounded input context."
    )
    input_tokens: StrictInt | None = Field(
        default=None, ge=0, description="Measured input token count if reported; None if unknown."
    )
    output_tokens: StrictInt | None = Field(
        default=None, ge=0, description="Measured output token count if reported; None if unknown."
    )
    attempt_count: StrictInt | None = Field(
        default=None, ge=1, description="Total provider/repair attempts executed if known."
    )
    cache_hit: StrictBool = Field(
        default=False, description="True only when validated result came from bounded cache."
    )
    fallback_used: StrictBool = Field(
        default=False, description="True when deterministic fallback produced the output."
    )
    fallback_reason: str | None = Field(
        default=None, description="Sanitized explanation if deterministic fallback was activated."
    )
    synthetic_origin: StrictBool = Field(
        default=False,
        description="Explicit marker identifying synthetic/fixture provider outputs.",
    )


# ------------------------------------------------------------------------------
# 10.1 Finding
# ------------------------------------------------------------------------------
class Finding(KillswitchModel):
    """Normalized security finding received from an authorized testing or scanning tool."""

    finding_id: IdentifierStr = Field(description="Unique finding identifier.")
    incident_id: IdentifierStr = Field(description="Parent incident identifier.")
    category: VulnerabilityCategory = Field(description="Normalized vulnerability category.")
    affected_route: str | None = Field(
        default=None,
        description="Affected HTTP route or entrypoint; None when route is unknown.",
    )
    affected_component: str = Field(
        min_length=1,
        description="Affected application service, module, or dependency name.",
    )
    severity: VulnerabilitySeverity = Field(description="Normalized severity rating.")
    status: FindingStatus = Field(
        description="Normalized verification state ('suspected' or 'reproduced')."
    )
    evidence_ids: list[IdentifierStr] = Field(
        default_factory=list,
        description="Referenced evidence IDs; required and non-empty when reproduced.",
    )
    source_scanner: str | None = Field(
        default=None, description="Authorized scanner or verifier name."
    )
    repository_revision: str | None = Field(
        default=None, description="Git commit SHA or revision tag observed for the finding."
    )
    environment: str | None = Field(
        default=None, description="Target environment where the finding was observed."
    )
    cve_ids: list[str] = Field(
        default_factory=list, description="Associated CVE identifiers if applicable."
    )
    observed_impact: str | None = Field(
        default=None, description="Concise description of observed security impact."
    )
    detected_at: UtcDatetime = Field(
        default_factory=utc_now, description="UTC timestamp when finding was detected."
    )
    provenance: EvidenceProvenance = Field(
        default=EvidenceProvenance.SECURITY_TEST_OUTPUT,
        description="Origin classification of the finding.",
    )

    @field_validator("affected_route", "source_scanner", "repository_revision", "environment")
    @classmethod
    def _validate_optional_non_empty(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_non_empty_str(value, field_name="metadata_field")

    @field_validator("evidence_ids")
    @classmethod
    def _validate_evidence_ids(cls, value: list[str]) -> list[str]:
        return validate_evidence_reference_ids(value)

    @model_validator(mode="after")
    def _enforce_reproduced_requires_evidence(self) -> Finding:
        if self.status == FindingStatus.REPRODUCED and not self.evidence_ids:
            raise ValueError(
                "A reproduced finding must reference at least one reproduction evidence_id."
            )
        return self


# ------------------------------------------------------------------------------
# 10.2 InvestigationSummary & Grounding Models
# ------------------------------------------------------------------------------
class GroundedClaim(KillswitchModel):
    """Single factual, inferred, or assumption claim bound to explicit evidence references."""

    claim_id: IdentifierStr = Field(description="Stable claim identifier within investigation.")
    statement: str = Field(min_length=1, description="Technical claim text.")
    classification: ClaimCategory = Field(description="Claim epistemology classification.")
    evidence_ids: list[IdentifierStr] = Field(
        default_factory=list, description="Supplied supporting evidence IDs."
    )
    source_excerpt_ids: list[str] = Field(
        default_factory=list, description="Referenced bounded source excerpt identifiers."
    )
    environment: str | None = Field(default=None, description="Applicable environment if scoped.")
    source_revision: str | None = Field(default=None, description="Applicable code revision.")
    validation_status: ClaimValidationStatus = Field(
        default=ClaimValidationStatus.UNVERIFIED_INTERPRETATION,
        description="Deterministic reference/contradiction validation outcome.",
    )
    limitations: list[str] = Field(
        default_factory=list, description="Explicit validation or scope limitations."
    )

    @field_validator("evidence_ids")
    @classmethod
    def _validate_evidence_ids(cls, value: list[str]) -> list[str]:
        return validate_evidence_reference_ids(value)


class PotentialImpact(KillswitchModel):
    """Potential security implication explicitly marked as verified or unverified."""

    description: str = Field(min_length=1, description="Description of potential security impact.")
    verified: StrictBool = Field(
        default=False, description="True only when explicitly reproduced/observed in evidence."
    )
    limitations: list[str] = Field(
        default_factory=list, description="Conditions preventing confirmed impact verification."
    )


class GroundingValidationReport(KillswitchModel):
    """Audit report summarizing reference grounding and deterministic contradiction checks."""

    total_claims: StrictInt = Field(ge=0)
    claims_with_supplied_references: StrictInt = Field(ge=0)
    unknown_references: list[str] = Field(default_factory=list)
    direct_factual_contradictions: list[str] = Field(default_factory=list)
    unsupported_observed_claims: list[str] = Field(default_factory=list)
    hallucinated_identifiers: list[str] = Field(default_factory=list)
    claims_requiring_review: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    reference_checks_passed: StrictBool
    contradiction_checks_passed: StrictBool
    semantic_review_required: StrictBool
    overall_valid: StrictBool
    notes: list[str] = Field(default_factory=list)


class InvestigationSummary(KillswitchModel):
    """Structured AI-assisted investigation distinguishing facts from inferences."""

    investigation_id: IdentifierStr = Field(description="Unique investigation identifier.")
    finding_id: IdentifierStr = Field(description="Target finding identifier.")
    incident_id: IdentifierStr = Field(description="Parent incident identifier.")
    executive_summary: str = Field(
        min_length=1, description="Concise summary for human incident responders."
    )
    technical_explanation: str = Field(
        min_length=1, description="Technical analysis of vulnerability mechanism and scope."
    )
    affected_components: list[str] = Field(
        default_factory=list, description="Components identified as affected."
    )
    observed_effects: list[str] = Field(
        default_factory=list, description="Directly observed security or system effects."
    )
    verified_facts: list[str] = Field(
        default_factory=list,
        description="Facts backed directly by evidence references.",
    )
    assumptions: list[str] = Field(
        default_factory=list,
        description="Explicit assumptions made during analysis.",
    )
    uncertainties: list[str] = Field(
        default_factory=list,
        description="Known gaps or unverified areas requiring review.",
    )
    evidence_ids: list[IdentifierStr] = Field(
        default_factory=list, description="Supporting evidence artifact identifiers."
    )
    recommended_next_action: str = Field(
        min_length=1, description="Recommended deterministic workflow step."
    )
    reasoning_source: EvidenceProvenance = Field(
        default=EvidenceProvenance.LLM_INTERPRETATION,
        description="Whether reasoning came from LLM interpretation or deterministic logic.",
    )
    model_metadata: ModelMetadata | None = Field(
        default=None, description="Optional LLM provider metadata when AI-generated."
    )
    created_at: UtcDatetime = Field(default_factory=utc_now, description="UTC creation timestamp.")
    investigation_status: InvestigationStatus = Field(
        default=InvestigationStatus.COMPLETED,
        description="Completion status of the investigation workflow.",
    )
    finding_status: FindingStatus | None = Field(
        default=None,
        description="Authoritative FindingStatus preserved from supplied finding.",
    )
    affected_route: str | None = Field(
        default=None,
        description="Affected HTTP route or entrypoint if supplied or confirmed.",
    )
    grounded_facts: list[GroundedClaim] = Field(
        default_factory=list,
        description="Claim-level observed facts validated against supplied evidence.",
    )
    technical_interpretations: list[GroundedClaim] = Field(
        default_factory=list,
        description="Claim-level evidence-linked technical interpretations.",
    )
    potential_impacts: list[PotentialImpact] = Field(
        default_factory=list,
        description="Potential security implications explicitly separated from verified facts.",
    )
    missing_evidence: list[str] = Field(
        default_factory=list,
        description="Specific missing evidence items limiting investigation certainty.",
    )
    requires_manual_review: StrictBool = Field(
        default=False,
        description="True when human operator review is required due to gaps or risks.",
    )
    evidence_support_level: EvidenceSupportLevel = Field(
        default=EvidenceSupportLevel.LIMITED_EVIDENCE_SUPPORT,
        description="Explainable qualitative assessment of supporting evidence completeness.",
    )
    prompt_version: str | None = Field(
        default=None, description="Exact prompt version used if LLM-assisted."
    )
    prompt_hash: str | None = Field(
        default=None, description="SHA-256 content hash of prompt templates used."
    )
    context_hash: str | None = Field(
        default=None, description="Canonical SHA-256 hash of bounded investigation context."
    )
    fallback_used: StrictBool = Field(
        default=False,
        description="True when deterministic fallback produced this summary.",
    )
    fallback_reason: str | None = Field(
        default=None,
        description="Reason deterministic fallback was activated, if applicable.",
    )
    grounding_report: GroundingValidationReport | None = Field(
        default=None,
        description="Deterministic reference & factual consistency validation summary.",
    )

    @field_validator("evidence_ids")
    @classmethod
    def _validate_evidence_ids(cls, value: list[str]) -> list[str]:
        return validate_evidence_reference_ids(value)


# ------------------------------------------------------------------------------
# 10.3 MappingResult
# ------------------------------------------------------------------------------
class MappingResult(KillswitchModel):
    """Result of mapping an affected route/component to feature flags."""

    finding_id: IdentifierStr = Field(description="Target finding identifier.")
    mapping_status: MappingStatus = Field(
        description="Mapping outcome ('matched', 'ambiguous', or 'unmapped')."
    )
    affected_route: str | None = Field(
        default=None, description="Route evaluated during mapping, if known."
    )
    matched_component: str | None = Field(
        default=None, description="Matched application component name, if resolved."
    )
    candidate_flags: list[str] = Field(
        default_factory=list, description="Candidate feature flag keys considered."
    )
    selected_flag: str | None = Field(
        default=None,
        description="Single resolved flag key; permitted only when mapping_status == 'matched'.",
    )
    registry_version: str = Field(
        min_length=1, description="Version of the route-to-flag registry evaluated."
    )
    mapping_rationale: str = Field(
        min_length=1, description="Deterministic or assisted rationale for mapping result."
    )
    evidence_ids: list[IdentifierStr] = Field(
        default_factory=list, description="Supporting evidence identifiers."
    )
    manual_review_required: StrictBool = Field(
        default=False,
        description="Mandatory True when mapping is ambiguous or unmapped.",
    )
    diagnostics: dict[str, Any] | None = Field(
        default=None,
        description="Optional structured mapping diagnostics (method, reason_codes, readiness).",
    )

    @field_validator("evidence_ids")
    @classmethod
    def _validate_evidence_ids(cls, value: list[str]) -> list[str]:
        return validate_evidence_reference_ids(value)

    @model_validator(mode="after")
    def _enforce_mapping_invariants(self) -> MappingResult:
        if self.mapping_status == MappingStatus.MATCHED:
            if not self.selected_flag:
                raise ValueError("mapping_status='matched' requires a non-empty selected_flag.")
            if self.selected_flag not in self.candidate_flags:
                raise ValueError("selected_flag must be present in candidate_flags.")
        else:
            if self.selected_flag is not None:
                raise ValueError(
                    f"mapping_status={self.mapping_status.value!r} cannot set selected_flag."
                )
            if not self.manual_review_required:
                raise ValueError(
                    f"mapping_status={self.mapping_status.value!r} requires "
                    "manual_review_required=True."
                )
        return self


# ------------------------------------------------------------------------------
# 10.4 GraphNode, GraphEdge, and DependencyGraph
# ------------------------------------------------------------------------------
class GraphNode(KillswitchModel):
    """Node in the illustrative application dependency graph."""

    node_id: IdentifierStr = Field(description="Stable unique node identifier.")
    node_type: GraphNodeType = Field(description="Entity category of the node.")
    label: str = Field(min_length=1, description="Human-readable node label.")
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Additional non-secret node attributes."
    )


class GraphEdge(KillswitchModel):
    """Directed edge representing a dependency or control relationship."""

    source_id: IdentifierStr = Field(description="Origin node identifier.")
    target_id: IdentifierStr = Field(description="Destination node identifier.")
    relationship: GraphEdgeType = Field(description="Directed relationship semantics.")
    metadata: dict[str, Any] = Field(
        default_factory=dict, description="Additional non-secret edge attributes."
    )


class DependencyGraph(KillswitchModel):
    """Serializable dependency graph container for blast-radius analysis and UI rendering."""

    graph_version: str = Field(min_length=1, description="Version of the dependency graph.")
    environment: str = Field(min_length=1, description="Target environment represented.")
    provenance: EvidenceProvenance = Field(
        default=EvidenceProvenance.REFERENCE_FIXTURE,
        description="Explicit provenance distinguishing fixtures from discovered graphs.",
    )
    is_fixture_assumption: StrictBool = Field(
        default=True,
        description="True when the graph represents declared fixture assumptions.",
    )
    description: str = Field(
        default="", description="Human-readable notes about graph scope and assumptions."
    )
    nodes: list[GraphNode] = Field(default_factory=list, description="Graph nodes.")
    edges: list[GraphEdge] = Field(default_factory=list, description="Directed graph edges.")

    @model_validator(mode="after")
    def _enforce_graph_integrity(self) -> DependencyGraph:
        try:
            validate_dependency_graph_integrity(self)
        except KillswitchError as exc:
            raise ValueError(str(exc)) from exc
        return self


# ------------------------------------------------------------------------------
# 10.5 ContainmentOption
# ------------------------------------------------------------------------------
class ContainmentOption(KillswitchModel):
    """Candidate containment strategy evaluated before proposing an operational change."""

    option_id: IdentifierStr = Field(description="Unique containment option identifier.")
    incident_id: IdentifierStr = Field(description="Parent incident identifier.")
    strategy_type: ContainmentStrategyType = Field(description="Containment strategy category.")
    title: str = Field(min_length=1, description="Human-readable option title.")
    proposed_target: str | None = Field(
        default=None, description="Target flag or component identifier if applicable."
    )
    feasible: StrictBool = Field(
        description="Whether prerequisites are met for deterministic execution."
    )
    prerequisites: list[str] = Field(
        default_factory=list, description="Conditions required before option can execute."
    )
    infeasibility_reasons: list[str] = Field(
        default_factory=list, description="Explicit reasons why the option is infeasible."
    )
    estimated_disruption: float = Field(
        ge=0.0,
        le=1.0,
        description="Policy estimate of user/service disruption in [0.0, 1.0] (not a probability).",
    )
    estimated_residual_risk: float = Field(
        ge=0.0,
        le=1.0,
        description="Policy estimate of remaining vulnerability risk in [0.0, 1.0].",
    )
    dependency_reach: StrictInt = Field(
        ge=0, description="Count of downstream dependency nodes impacted."
    )
    uncertainty: float = Field(
        ge=0.0,
        le=1.0,
        description="Policy estimate of analytical uncertainty in [0.0, 1.0].",
    )
    relative_policy_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Deterministic policy ranking estimate in [0.0, 1.0] (higher = preferred).",
    )
    affected_nodes: list[IdentifierStr] = Field(
        default_factory=list, description="Dependency graph nodes impacted by this option."
    )
    protected_nodes: list[IdentifierStr] = Field(
        default_factory=list, description="Dependency graph nodes shielded by this option."
    )
    evidence_ids: list[IdentifierStr] = Field(
        default_factory=list, description="Supporting evidence identifiers."
    )
    limitations: list[str] = Field(
        default_factory=list, description="Known assumptions and analytical limitations."
    )

    @field_validator("evidence_ids")
    @classmethod
    def _validate_evidence_ids(cls, value: list[str]) -> list[str]:
        return validate_evidence_reference_ids(value)

    @model_validator(mode="after")
    def _enforce_infeasibility_reasons(self) -> ContainmentOption:
        if not self.feasible and not self.infeasibility_reasons:
            raise ValueError("Infeasible containment options must specify infeasibility_reasons.")
        return self


# ------------------------------------------------------------------------------
# 10.6 ContainmentProposal
# ------------------------------------------------------------------------------
class ContainmentProposal(KillswitchModel):
    """Formal containment change proposal requiring explicit human approval."""

    proposal_id: IdentifierStr = Field(description="Unique containment proposal identifier.")
    incident_id: IdentifierStr = Field(description="Parent incident identifier.")
    proposal_type: ProposalType = Field(
        default=ProposalType.CONTAINMENT_FLAG_DISABLE,
        description="Operational proposal category.",
    )
    environment: str = Field(min_length=1, description="Target Flagsmith environment.")
    flag_name: str = Field(min_length=1, description="Target feature flag key.")
    desired_enabled: StrictBool = Field(description="Requested boolean flag state.")
    expected_current_enabled: StrictBool | None = Field(
        default=None,
        description="Expected current flag state at proposal time; None if unknown.",
    )
    reason: str = Field(min_length=1, description="Evidence-backed justification for containment.")
    alternatives: list[str] = Field(
        default_factory=list, description="Alternative containment options considered."
    )
    expected_disruption: str = Field(
        min_length=1, description="Human-readable summary of expected operational disruption."
    )
    evidence_ids: list[IdentifierStr] = Field(
        min_length=1, description="Required supporting evidence identifiers."
    )
    approval_required: StrictBool = Field(
        default=True,
        description="Mandatory True; operational feature changes always require human approval.",
    )
    registry_version: str = Field(
        min_length=1, description="Route-to-flag registry version used."
    )
    policy_version: str = Field(
        default=POLICY_VERSION, min_length=1, description="Containment policy version."
    )
    created_at: UtcDatetime = Field(
        default_factory=utc_now, description="UTC timestamp when proposal was created."
    )
    expires_at: UtcDatetime = Field(
        description="UTC expiration timestamp after which proposal cannot be approved/executed."
    )
    idempotency_token: IdentifierStr = Field(
        description="Unique idempotency token preventing duplicate executions."
    )
    rollback_considerations: list[str] = Field(
        default_factory=list, description="Notes regarding reverting this containment action."
    )
    hash_version: str = Field(
        default="v1",
        min_length=1,
        description="Proposal canonical hash version ('v1' legacy fixture, 'v2' hardened).",
    )
    review_metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional review-binding metadata (graph/registry fingerprints, strategy ID).",
    )
    proposal_hash: str = Field(
        description="Canonical SHA-256 hash binding security-relevant proposal fields."
    )

    @field_validator("evidence_ids")
    @classmethod
    def _validate_evidence_ids(cls, value: list[str]) -> list[str]:
        return validate_evidence_reference_ids(value)

    @field_validator("proposal_hash")
    @classmethod
    def _validate_proposal_hash_format(cls, value: str) -> str:
        return validate_sha256_hex(value, field_name="proposal_hash")

    def canonical_hash_payload(self) -> dict[str, Any]:
        """Return the canonical dictionary covered by ``proposal_hash``."""
        base: dict[str, Any] = {
            "proposal_id": self.proposal_id,
            "incident_id": self.incident_id,
            "proposal_type": self.proposal_type.value,
            "environment": self.environment,
            "flag_name": self.flag_name,
            "desired_enabled": self.desired_enabled,
            "expected_current_enabled": self.expected_current_enabled,
            "registry_version": self.registry_version,
            "policy_version": self.policy_version,
            "approval_required": self.approval_required,
            "idempotency_token": self.idempotency_token,
        }
        if self.hash_version != "v1":
            base.update(
                {
                    "hash_version": self.hash_version,
                    "reason": self.reason,
                    "alternatives": list(self.alternatives),
                    "expected_disruption": self.expected_disruption,
                    "evidence_ids": sorted(self.evidence_ids),
                    "created_at": self.created_at.isoformat(),
                    "expires_at": self.expires_at.isoformat(),
                    "rollback_considerations": list(self.rollback_considerations),
                    "review_metadata": self.review_metadata,
                }
            )
        return base

    def compute_hash(self) -> str:
        """Compute deterministic SHA-256 digest of the proposal's canonical fields."""
        payload = self.canonical_hash_payload()
        if self.hash_version == "v1":
            return compute_proposal_hash(payload)
        return sha256_canonical(payload)

    def verify_hash(self) -> bool:
        """Return True iff stored ``proposal_hash`` matches computed canonical hash."""
        return self.proposal_hash == self.compute_hash()

    @classmethod
    def with_computed_hash(cls, **kwargs: Any) -> ContainmentProposal:
        """Construct a ContainmentProposal and compute its canonical ``proposal_hash``."""
        placeholder = "0" * 64
        draft = cls(proposal_hash=placeholder, **kwargs)
        return draft.model_copy(update={"proposal_hash": draft.compute_hash()})

    @model_validator(mode="after")
    def _enforce_proposal_invariants(self) -> ContainmentProposal:
        if not self.approval_required:
            raise ValueError(
                "approval_required must be True; autonomous flag changes are prohibited."
            )
        if self.expires_at <= self.created_at:
            raise ValueError("expires_at must be strictly later than created_at.")
        return self


# ------------------------------------------------------------------------------
# 10.7 ApprovalDecision
# ------------------------------------------------------------------------------
class ApprovalDecision(KillswitchModel):
    """Human decision bound to an exact ContainmentProposal hash and identity.

    Security note:
        ``actor_id`` alone is never proof of authentication. Trusted platform
        services must validate ``authorization_context_ref`` and session identity.
    """

    approval_id: IdentifierStr = Field(description="Unique approval decision identifier.")
    proposal_id: IdentifierStr = Field(description="Target proposal identifier.")
    proposal_hash: str = Field(
        description="Expected canonical SHA-256 hash of the exact approved proposal."
    )
    incident_id: IdentifierStr = Field(description="Parent incident identifier.")
    actor_id: str = Field(
        min_length=1,
        description="Operator identifier (not an authentication credential by itself).",
    )
    decision: ApprovalStatus = Field(description="Recorded approval lifecycle decision.")
    decided_at: UtcDatetime = Field(description="UTC timestamp when decision was recorded.")
    expires_at: UtcDatetime = Field(description="UTC expiration timestamp for this approval.")
    rejection_reason: str | None = Field(
        default=None, description="Reason recorded when decision is rejected."
    )
    authorization_context_ref: IdentifierStr = Field(
        description="Reference to authenticated session/authorization record in platform layer."
    )
    nonce: IdentifierStr = Field(
        description="Unique nonce/idempotency reference preventing replay."
    )

    @field_validator("proposal_hash")
    @classmethod
    def _validate_hash(cls, value: str) -> str:
        return validate_sha256_hex(value, field_name="proposal_hash")

    @model_validator(mode="after")
    def _enforce_approval_invariants(self) -> ApprovalDecision:
        if self.expires_at <= self.decided_at:
            raise ValueError("Approval expires_at must be strictly later than decided_at.")
        if self.decision == ApprovalStatus.REJECTED and not self.rejection_reason:
            raise ValueError("Rejected approvals must provide a rejection_reason.")
        return self


# ------------------------------------------------------------------------------
# 10.8 FeatureState
# ------------------------------------------------------------------------------
class FeatureState(KillswitchModel):
    """Read-only observation of a feature flag state in an environment.

    Unknown or unavailable states are represented explicitly via ``observation_status``
    with ``enabled=None`` so they are never conflated with ``enabled=False``.
    """

    environment: str = Field(min_length=1, description="Environment inspected.")
    feature_id: str = Field(min_length=1, description="Provider feature identifier.")
    feature_name: str = Field(min_length=1, description="Declared feature flag key.")
    observation_status: FeatureObservationStatus = Field(
        default=FeatureObservationStatus.OBSERVED,
        description="Whether state was actually observed, unavailable, or unknown.",
    )
    enabled: StrictBool | None = Field(
        default=None,
        description="Observed boolean state; must be None when observation_status != 'observed'.",
    )
    observed_at: UtcDatetime = Field(
        default_factory=utc_now, description="UTC timestamp of readback observation."
    )
    state_version: str | None = Field(
        default=None, description="Provider state version or ETag if available."
    )
    observation_source: EvidenceProvenance = Field(
        default=EvidenceProvenance.ACTUAL_OBSERVED,
        description="Provenance of the feature state observation.",
    )
    segment_targeting: dict[str, Any] = Field(
        default_factory=dict,
        description="Observed segment override or percentage rollout configuration.",
    )
    evidence_ids: list[IdentifierStr] = Field(
        default_factory=list, description="Associated observation artifact identifiers."
    )

    @field_validator("evidence_ids")
    @classmethod
    def _validate_evidence_ids(cls, value: list[str]) -> list[str]:
        return validate_evidence_reference_ids(value)

    @model_validator(mode="after")
    def _enforce_unknown_vs_disabled(self) -> FeatureState:
        if self.observation_status == FeatureObservationStatus.OBSERVED:
            if self.enabled is None:
                raise ValueError(
                    "observed FeatureState must include an explicit boolean enabled value."
                )
        else:
            if self.enabled is not None:
                raise ValueError(
                    "unavailable/unknown FeatureState must have enabled=None so it is not "
                    "confused with disabled (False)."
                )
        return self


# ------------------------------------------------------------------------------
# 10.9 OperationReceipt
# ------------------------------------------------------------------------------
class OperationReceipt(KillswitchModel):
    """Authoritative receipt emitted by the privileged external Flagsmith executor.

    A model-generated proposal must never be accepted as an execution receipt.
    """

    operation_id: IdentifierStr = Field(description="Unique external operation identifier.")
    incident_id: IdentifierStr = Field(description="Parent incident identifier.")
    proposal_id: IdentifierStr = Field(description="Approved proposal identifier.")
    approval_id: IdentifierStr = Field(description="Authorizing approval identifier.")
    environment: str = Field(min_length=1, description="Target environment executed against.")
    target_feature: str = Field(min_length=1, description="Feature flag key mutated.")
    requested_state: StrictBool = Field(description="Boolean state requested by proposal.")
    observed_state: StrictBool | None = Field(
        default=None,
        description="State confirmed via readback after operation; None if unconfirmed.",
    )
    outcome: OperationOutcome = Field(description="Execution outcome status.")
    provider_reference: str | None = Field(
        default=None, description="External provider audit or request ID."
    )
    idempotency_key: IdentifierStr = Field(
        description="Idempotency key matching the approved operation."
    )
    executed_at: UtcDatetime = Field(
        default_factory=utc_now, description="UTC timestamp of external execution."
    )
    provenance: EvidenceProvenance = Field(
        default=EvidenceProvenance.EXTERNAL_OPERATION_RECEIPT,
        description="Must reflect an external execution receipt or fixture, never LLM output.",
    )
    evidence_ids: list[IdentifierStr] = Field(
        default_factory=list, description="Stored receipt/readback artifact identifiers."
    )
    sanitized_error: str | None = Field(
        default=None, description="Sanitized error message if operation did not succeed."
    )

    @field_validator("evidence_ids")
    @classmethod
    def _validate_evidence_ids(cls, value: list[str]) -> list[str]:
        return validate_evidence_reference_ids(value)

    @model_validator(mode="after")
    def _enforce_receipt_integrity(self) -> OperationReceipt:
        if self.provenance == EvidenceProvenance.LLM_INTERPRETATION:
            raise ValueError(
                "An LLM interpretation can never be accepted as an OperationReceipt."
            )
        if (
            self.outcome == OperationOutcome.SUCCEEDED
            and self.observed_state != self.requested_state
        ):
            raise ValueError(
                "OperationReceipt with outcome='succeeded' requires "
                "observed_state == requested_state."
            )
        return self


# ------------------------------------------------------------------------------
# 10.10 VerificationResult
# ------------------------------------------------------------------------------
class VerificationResult(KillswitchModel):
    """Security verification outcome across baseline, containment, and patch phases.

    Distinguishes:
        - ``before_containment``: ``vulnerability_reproduced=True`` means the exploit
          was confirmed; ``passed=True`` indicates the baseline verification run
          successfully verified the vulnerability presence.
        - ``after_containment`` / ``after_patch``: ``vulnerability_reproduced=False``
          and ``passed=True`` confirm the exploit is blocked / mitigated.
    """

    verification_id: IdentifierStr = Field(description="Unique verification record identifier.")
    incident_id: IdentifierStr = Field(description="Parent incident identifier.")
    test_id: str = Field(min_length=1, description="Security test case identifier.")
    test_run_id: IdentifierStr | None = Field(
        default=None, description="Associated security test-run identifier."
    )
    phase: VerificationPhase = Field(description="Workflow phase in which test ran.")
    execution_status: TestExecutionStatus = Field(
        default=TestExecutionStatus.TEST_PASSED,
        description="Concrete execution status of the test harness.",
    )
    passed: StrictBool | None = Field(
        default=None,
        description="Whether phase objective passed; must be None if not_run or infra error.",
    )
    vulnerability_reproduced: StrictBool | None = Field(
        default=None,
        description="Explicit indicator of whether the exploit succeeded during this run.",
    )
    observed_feature_state: StrictBool | None = Field(
        default=None,
        description="Observed feature flag state during verification; None if unknown.",
    )
    expected_revision: str | None = Field(
        default=None, description="Expected source revision under test."
    )
    tested_revision: str | None = Field(
        default=None, description="Actual source revision executed by the verifier."
    )
    artifact_ids: list[IdentifierStr] = Field(
        default_factory=list, description="Evidence artifact identifiers."
    )
    artifact_hashes: dict[str, str] = Field(
        default_factory=dict, description="Mapping of artifact_id to SHA-256 hex digest."
    )
    started_at: UtcDatetime | None = Field(default=None, description="UTC start timestamp.")
    completed_at: UtcDatetime | None = Field(
        default=None, description="UTC completion timestamp."
    )
    exit_code: StrictInt | None = Field(default=None, description="Test runner process exit code.")
    infrastructure_error: str | None = Field(
        default=None, description="Sanitized error details if runner failed."
    )
    limitations: list[str] = Field(
        default_factory=list, description="Explicit test coverage or environment limitations."
    )
    provenance: EvidenceProvenance = Field(
        default=EvidenceProvenance.SECURITY_TEST_OUTPUT,
        description="Origin classification of this verification result.",
    )

    @field_validator("artifact_ids")
    @classmethod
    def _validate_artifact_ids(cls, value: list[str]) -> list[str]:
        return validate_evidence_reference_ids(value)

    @field_validator("artifact_hashes")
    @classmethod
    def _validate_artifact_hashes(cls, value: dict[str, str]) -> dict[str, str]:
        return {
            k: validate_sha256_hex(v, field_name=f"artifact_hashes[{k}]")
            for k, v in value.items()
        }

    @model_validator(mode="after")
    def _enforce_verification_consistency(self) -> VerificationResult:
        if self.execution_status in (
            TestExecutionStatus.NOT_RUN,
            TestExecutionStatus.INFRASTRUCTURE_ERROR,
        ):
            if self.passed is not None:
                raise ValueError(
                    f"passed must be None when execution_status={self.execution_status.value!r}."
                )
        elif self.passed is None:
            raise ValueError(
                "Completed verification runs must set an explicit boolean passed value."
            )

        if (
            self.execution_status == TestExecutionStatus.INFRASTRUCTURE_ERROR
            and not self.infrastructure_error
        ):
            raise ValueError(
                "infrastructure_error message is required when "
                "execution_status='infrastructure_error'."
            )

        if (
            self.started_at is not None
            and self.completed_at is not None
            and self.completed_at < self.started_at
        ):
            raise ValueError("completed_at cannot be earlier than started_at.")

        if (
            self.phase == VerificationPhase.AFTER_CONTAINMENT
            and self.passed is True
            and self.vulnerability_reproduced is True
        ):
            raise ValueError(
                "after_containment verification cannot be passed=True while "
                "vulnerability_reproduced=True."
            )
        return self


# ------------------------------------------------------------------------------
# 10.11 PatchProposal
# ------------------------------------------------------------------------------
class PatchProposal(KillswitchModel):
    """Bounded candidate source-code remediation patch proposal."""

    patch_id: IdentifierStr = Field(description="Unique patch proposal identifier.")
    incident_id: IdentifierStr = Field(description="Parent incident identifier.")
    finding_id: IdentifierStr = Field(description="Target vulnerability finding identifier.")
    source_revision: str = Field(
        min_length=1, description="Base repository revision the patch applies to."
    )
    candidate_artifact_id: IdentifierStr = Field(
        description="Artifact ID containing the candidate patch diff."
    )
    candidate_content_hash: str = Field(
        description="SHA-256 hex digest of the candidate patch content."
    )
    unified_diff: str = Field(
        min_length=1, description="Unified diff text or artifact summary."
    )
    allowed_files: list[str] = Field(
        min_length=1, description="Explicit relative file allowlist permitted for modification."
    )
    touched_files: list[str] = Field(
        min_length=1, description="Relative file paths modified by the candidate patch."
    )
    technical_rationale: str = Field(
        min_length=1, description="Explanation of how the patch fixes the root cause."
    )
    expected_behavior_changes: list[str] = Field(
        default_factory=list, description="Expected functional or API behavior changes."
    )
    required_tests: list[str] = Field(
        min_length=1, description="Required security and functional tests to execute."
    )
    potential_regressions: list[str] = Field(
        default_factory=list, description="Potential regression risks identified."
    )
    assumptions: list[str] = Field(
        default_factory=list, description="Explicit assumptions made in generating the patch."
    )
    patch_origin: PatchOrigin = Field(
        description="Distinguishes LLM candidate patches from static reference fixtures."
    )
    status: PatchStatus = Field(
        default=PatchStatus.PATCH_PROPOSED, description="Current patch lifecycle status."
    )
    model_metadata: ModelMetadata | None = Field(
        default=None, description="Model metadata when generated by an LLM."
    )
    review_required: StrictBool = Field(
        default=True, description="Mandatory human/engineering review flag."
    )
    created_at: UtcDatetime = Field(default_factory=utc_now, description="UTC creation timestamp.")

    @field_validator("candidate_content_hash")
    @classmethod
    def _validate_candidate_hash(cls, value: str) -> str:
        return validate_sha256_hex(value, field_name="candidate_content_hash")

    @field_validator("allowed_files", "touched_files")
    @classmethod
    def _validate_safe_paths(cls, value: list[str]) -> list[str]:
        return [validate_relative_safe_path(path, field_name="patch_file") for path in value]

    @model_validator(mode="after")
    def _enforce_patch_boundaries(self) -> PatchProposal:
        if not self.review_required:
            raise ValueError("review_required must be True for candidate patches.")
        validate_touched_files_within_allowlist(self.touched_files, self.allowed_files)
        return self


# ------------------------------------------------------------------------------
# 10.12 IndividualTestOutcome and PatchTestResult
# ------------------------------------------------------------------------------
class IndividualTestOutcome(KillswitchModel):
    """Outcome of a single test suite or test case inside an isolated patch test run."""

    test_name: str = Field(min_length=1, description="Test case or suite name.")
    category: str = Field(
        default="functional",
        description="Test classification such as 'security' or 'functional'.",
    )
    status: TestExecutionStatus = Field(description="Execution outcome of this test.")
    duration_seconds: float | None = Field(
        default=None, ge=0.0, description="Execution duration in seconds."
    )
    message: str | None = Field(default=None, description="Sanitized failure or summary note.")


class PatchTestResult(KillswitchModel):
    """Isolated verification result for a candidate PatchProposal."""

    test_run_id: IdentifierStr = Field(description="Unique patch test-run identifier.")
    patch_id: IdentifierStr = Field(description="Target patch proposal identifier.")
    incident_id: IdentifierStr = Field(description="Parent incident identifier.")
    expected_source_revision: str = Field(
        min_length=1, description="Expected source revision for this patch."
    )
    tested_source_revision: str = Field(
        min_length=1, description="Actual source revision checked out in isolated runner."
    )
    tested_candidate_hash: str = Field(
        description="SHA-256 hex digest of the patch content actually tested."
    )
    individual_outcomes: list[IndividualTestOutcome] = Field(
        default_factory=list, description="Per-test execution outcomes."
    )
    overall_status: TestExecutionStatus = Field(
        description="Overall isolated test execution status."
    )
    artifact_ids: list[IdentifierStr] = Field(
        default_factory=list, description="Stored test-log artifact identifiers."
    )
    sanitized_logs: str = Field(
        default="", description="Redacted test runner output summary."
    )
    started_at: UtcDatetime = Field(description="UTC start timestamp of test run.")
    completed_at: UtcDatetime = Field(description="UTC completion timestamp of test run.")
    exit_code: StrictInt | None = Field(default=None, description="Process exit code if executed.")
    limitations: list[str] = Field(
        default_factory=list, description="Known test environment or coverage limitations."
    )
    provenance: EvidenceProvenance = Field(
        default=EvidenceProvenance.SECURITY_TEST_OUTPUT,
        description="Provenance of the isolated test result.",
    )
    base_source_revision: str | None = Field(
        default=None,
        description="Authoritative base source revision against which the patch was generated.",
    )
    expected_patched_revision: str | None = Field(
        default=None,
        description="Expected post-patch revision derived from base revision and candidate hash.",
    )
    runner_computed_patched_revision: str | None = Field(
        default=None,
        description="Post-patch revision computed by the isolated runner after applying the diff.",
    )
    runtime_observed_revision: str | None = Field(
        default=None,
        description="Revision observed from the running patched target in the sandbox.",
    )
    source_target: str | None = Field(
        default=None,
        description="Source target identifier verified in isolation (e.g., stand_in).",
    )
    required_test_ids: list[str] = Field(
        default_factory=list,
        description="Authoritative mandatory test IDs required for acceptance.",
    )
    isolation_metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured sandbox isolation metadata (mode, network_disabled, etc.).",
    )
    verification_policy_version: str | None = Field(
        default=None,
        description="Policy version used by the isolated verification orchestrator.",
    )

    @field_validator("tested_candidate_hash")
    @classmethod
    def _validate_tested_hash(cls, value: str) -> str:
        return validate_sha256_hex(value, field_name="tested_candidate_hash")

    @field_validator("artifact_ids")
    @classmethod
    def _validate_artifact_ids(cls, value: list[str]) -> list[str]:
        return validate_evidence_reference_ids(value)

    @property
    def has_revision_mismatch(self) -> bool:
        """Return True when tested source revision differs from expected source revision."""
        if self.tested_source_revision != self.expected_source_revision:
            return True
        if (
            self.base_source_revision is not None
            and self.base_source_revision != self.expected_source_revision
        ):
            return True
        if (
            self.expected_patched_revision is not None
            and self.runner_computed_patched_revision is not None
            and self.expected_patched_revision != self.runner_computed_patched_revision
        ):
            return True
        if self.runtime_observed_revision is not None:
            reference_rev = self.runner_computed_patched_revision or self.tested_source_revision
            if self.runtime_observed_revision != reference_rev:
                return True
        return False

    @property
    def has_complete_required_tests(self) -> bool:
        """Return True when all declared required_test_ids have passing outcomes."""
        if not self.required_test_ids:
            return True
        outcomes_by_name = {item.test_name: item.status for item in self.individual_outcomes}
        return all(
            outcomes_by_name.get(test_id) == TestExecutionStatus.TEST_PASSED
            for test_id in self.required_test_ids
        )

    @property
    def is_trusted_pass(self) -> bool:
        """Return True only when status passed, revisions match, and all required tests passed."""
        if self.overall_status != TestExecutionStatus.TEST_PASSED:
            return False
        if self.has_revision_mismatch:
            return False
        if not self.individual_outcomes:
            return False
        if not self.has_complete_required_tests:
            return False
        if (
            self.isolation_metadata.get("require_runtime_revision_match") is True
            and not self.runtime_observed_revision
        ):
            return False
        return all(
            item.status == TestExecutionStatus.TEST_PASSED for item in self.individual_outcomes
        )

    @model_validator(mode="after")
    def _enforce_test_result_invariants(self) -> PatchTestResult:
        if self.completed_at < self.started_at:
            raise ValueError("completed_at cannot be earlier than started_at.")
        # Passing security tests must NEVER override failed functional tests or errors.
        has_any_failure_or_error = any(
            item.status
            in (TestExecutionStatus.TEST_FAILED, TestExecutionStatus.INFRASTRUCTURE_ERROR)
            for item in self.individual_outcomes
        )
        if has_any_failure_or_error and self.overall_status == TestExecutionStatus.TEST_PASSED:
            raise ValueError(
                "overall_status cannot be 'test_passed' when any individual test failed or errored."
            )
        return self


# ------------------------------------------------------------------------------
# 10.13 DeploymentEvidence
# ------------------------------------------------------------------------------
class DeploymentEvidence(KillswitchModel):
    """Observed evidence that an implementation revision is deployed and addressable.

    Explicitly distinct from candidate patch testing and feature flag activation.
    """

    deployment_id: IdentifierStr = Field(description="Unique deployment observation identifier.")
    environment: str = Field(min_length=1, description="Deployment target environment.")
    implementation_id: str = Field(
        min_length=1, description="Deployed service or implementation identifier."
    )
    feature_name: str = Field(
        min_length=1, description="Associated feature flag controlling exposure."
    )
    source_revision: str = Field(
        min_length=1, description="Observed deployed git commit/build revision."
    )
    implementation_hash: str = Field(
        description="SHA-256 hex digest of the deployed candidate or reference artifact."
    )
    deployed_at: UtcDatetime | None = Field(
        default=None, description="UTC timestamp when deployment was observed; None if missing."
    )
    deployment_status: DeploymentStatus = Field(
        description="Whether deployment was observed, pending, failed, missing, or unknown."
    )
    addressable: StrictBool = Field(
        description="Whether the deployed implementation is routable/addressable via feature flag."
    )
    evidence_ids: list[IdentifierStr] = Field(
        default_factory=list, description="Associated deployment manifest/receipt artifact IDs."
    )
    provenance: EvidenceProvenance = Field(
        default=EvidenceProvenance.ACTUAL_OBSERVED,
        description="Origin of the deployment evidence.",
    )

    @field_validator("implementation_hash")
    @classmethod
    def _validate_impl_hash(cls, value: str) -> str:
        return validate_sha256_hex(value, field_name="implementation_hash")

    @field_validator("evidence_ids")
    @classmethod
    def _validate_evidence_ids(cls, value: list[str]) -> list[str]:
        return validate_evidence_reference_ids(value)

    @model_validator(mode="after")
    def _enforce_deployment_invariants(self) -> DeploymentEvidence:
        if self.deployment_status == DeploymentStatus.OBSERVED and not self.evidence_ids:
            raise ValueError("Observed deployment requires at least one evidence_id.")
        if self.deployment_status != DeploymentStatus.OBSERVED and self.addressable:
            raise ValueError("Non-observed deployment cannot claim addressable=True.")
        return self


# ------------------------------------------------------------------------------
# 10.14 RolloutStage and RolloutGuardrailConfig
# ------------------------------------------------------------------------------
class RolloutGuardrailConfig(KillswitchModel):
    """Deterministic threshold configuration for progressive release evaluation."""

    max_error_rate: float = Field(
        ge=0.0,
        le=1.0,
        description="Maximum tolerable error rate as ratio in [0.0, 1.0] (e.g. 0.02 = 2%).",
    )
    max_error_rate_increase_pp: float = Field(
        ge=0.0,
        le=100.0,
        description="Maximum allowed error rate increase over baseline in percentage points.",
    )
    max_p95_latency_increase_percent: float = Field(
        ge=0.0,
        description="Maximum allowed p95 latency increase over baseline in percent.",
    )
    missing_data_decision: RolloutDecisionType = Field(
        default=RolloutDecisionType.HOLD,
        description="Fail-closed action when required telemetry or baseline is missing.",
    )
    is_demo_default: StrictBool = Field(
        default=True,
        description="Marks illustrative demonstration thresholds vs. calibrated production values.",
    )


class RolloutStage(KillswitchModel):
    """Single stage in a progressive feature-flag recovery rollout."""

    stage_id: IdentifierStr = Field(description="Unique rollout stage identifier.")
    exposure_percentage: StrictInt = Field(
        ge=0, le=100, description="Traffic exposure percentage in [0, 100]."
    )
    segment_configuration: dict[str, Any] = Field(
        default_factory=dict, description="Provider segment targeting parameters for this stage."
    )
    required_metrics: list[str] = Field(
        min_length=1, description="Metric names required before advancing past this stage."
    )
    minimum_observation_window_seconds: StrictInt = Field(
        ge=1, description="Minimum observation window duration in seconds."
    )
    minimum_request_count: StrictInt = Field(
        ge=0, description="Minimum sample size in requests required before evaluating."
    )
    guardrails: RolloutGuardrailConfig = Field(description="Stage guardrail configuration.")
    prerequisites: list[str] = Field(
        default_factory=list, description="Explicit prerequisites required to enter this stage."
    )
    approval_required: StrictBool = Field(
        default=True, description="Whether human approval is required to enter this stage."
    )


# ------------------------------------------------------------------------------
# 10.15 RolloutPlan
# ------------------------------------------------------------------------------
class RolloutPlan(KillswitchModel):
    """Ordered progressive recovery plan for re-enabling a patched feature."""

    plan_id: IdentifierStr = Field(description="Unique rollout plan identifier.")
    incident_id: IdentifierStr = Field(description="Parent incident identifier.")
    target_feature: str = Field(min_length=1, description="Feature flag key to roll out.")
    environment: str = Field(min_length=1, description="Target rollout environment.")
    target_implementation_revision: str = Field(
        min_length=1, description="Verified source revision required prior to rollout."
    )
    stages: list[RolloutStage] = Field(
        min_length=1, description="Strictly increasing ordered rollout stages."
    )
    current_stage_id: IdentifierStr | None = Field(
        default=None, description="Active stage identifier; None before rollout begins."
    )
    prerequisites: list[str] = Field(
        default_factory=list,
        description="Global prerequisites (patch tests, deployment, readback).",
    )
    guardrails: RolloutGuardrailConfig = Field(description="Default plan guardrail configuration.")
    evidence_ids: list[IdentifierStr] = Field(
        default_factory=list, description="Supporting verification and deployment evidence IDs."
    )
    policy_version: str = Field(
        default=POLICY_VERSION, min_length=1, description="Rollout policy version applied."
    )
    approval_required: StrictBool = Field(
        default=True, description="Mandatory human approval requirement for progressive changes."
    )

    @field_validator("evidence_ids")
    @classmethod
    def _validate_evidence_ids(cls, value: list[str]) -> list[str]:
        return validate_evidence_reference_ids(value)

    @model_validator(mode="after")
    def _enforce_stage_ordering(self) -> RolloutPlan:
        try:
            validate_rollout_stages_ordering(self.stages)
        except KillswitchError as exc:
            raise ValueError(str(exc)) from exc
        if self.current_stage_id is not None:
            valid_ids = {stage.stage_id for stage in self.stages}
            if self.current_stage_id not in valid_ids:
                raise ValueError(
                    f"current_stage_id {self.current_stage_id!r} is not present in stages."
                )
        return self


# ------------------------------------------------------------------------------
# 10.16 MetricSnapshot and LatencyStats
# ------------------------------------------------------------------------------
class LatencyStats(KillswitchModel):
    """Latency percentiles in milliseconds; None denotes unknown/unmeasured."""

    p50_ms: float | None = Field(
        default=None, ge=0.0, description="50th percentile latency in ms; None if unknown."
    )
    p95_ms: float | None = Field(
        default=None, ge=0.0, description="95th percentile latency in ms; None if unknown."
    )
    p99_ms: float | None = Field(
        default=None, ge=0.0, description="99th percentile latency in ms; None if unknown."
    )

    @model_validator(mode="after")
    def _enforce_percentile_monotonicity(self) -> LatencyStats:
        if self.p50_ms is not None and self.p95_ms is not None and self.p95_ms < self.p50_ms:
            raise ValueError("p95_ms cannot be smaller than p50_ms.")
        if self.p95_ms is not None and self.p99_ms is not None and self.p99_ms < self.p95_ms:
            raise ValueError("p99_ms cannot be smaller than p95_ms.")
        return self


class MetricSnapshot(KillswitchModel):
    """Telemetry observation snapshot with explicit provenance and unknown!=zero semantics."""

    snapshot_id: IdentifierStr = Field(description="Unique metric snapshot identifier.")
    incident_id: IdentifierStr = Field(description="Parent incident identifier.")
    environment: str = Field(min_length=1, description="Observed environment.")
    feature_id: str = Field(min_length=1, description="Feature identifier monitored.")
    observation_window_seconds: StrictInt = Field(
        ge=1, description="Duration of the observation window in seconds."
    )
    observed_at: UtcDatetime = Field(
        default_factory=utc_now, description="UTC timestamp when snapshot was captured."
    )
    request_count: StrictInt | None = Field(
        default=None, ge=0, description="Observed requests in window; None if unknown."
    )
    failed_request_count: StrictInt | None = Field(
        default=None, ge=0, description="Failed requests in window; None if unknown."
    )
    error_rate: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Observed error rate ratio in [0.0, 1.0]; None if unknown.",
    )
    latency_ms: LatencyStats = Field(
        default_factory=LatencyStats, description="Observed latency percentiles in ms."
    )
    baseline_error_rate: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Baseline error rate ratio in [0.0, 1.0]; None if missing.",
    )
    baseline_p95_latency_ms: float | None = Field(
        default=None,
        ge=0.0,
        description="Baseline p95 latency in ms; None if missing.",
    )
    security_regression_passed: StrictBool | None = Field(
        default=None,
        description="Post-exposure security regression status; None if not evaluated.",
    )
    observed_rollout_stage_percentage: StrictInt | None = Field(
        default=None,
        ge=0,
        le=100,
        description="Observed active exposure percentage [0, 100]; None if unknown.",
    )
    provenance: EvidenceProvenance = Field(
        description="Must explicitly indicate 'synthetic_telemetry' for synthetic metrics."
    )
    evidence_ids: list[IdentifierStr] = Field(
        default_factory=list, description="Associated telemetry artifact identifiers."
    )

    @field_validator("evidence_ids")
    @classmethod
    def _validate_evidence_ids(cls, value: list[str]) -> list[str]:
        return validate_evidence_reference_ids(value)

    @model_validator(mode="after")
    def _enforce_metric_consistency(self) -> MetricSnapshot:
        if (
            self.request_count is not None
            and self.failed_request_count is not None
            and self.failed_request_count > self.request_count
        ):
            raise ValueError("failed_request_count cannot exceed request_count.")
        if self.failed_request_count is not None and self.request_count is None:
            raise ValueError(
                "failed_request_count cannot be reported when request_count is unknown (None)."
            )
        return self


# ------------------------------------------------------------------------------
# 10.17 RolloutDecision
# ------------------------------------------------------------------------------
class RolloutDecision(KillswitchModel):
    """Deterministic rollout guardrail evaluation output."""

    decision_id: IdentifierStr = Field(description="Unique rollout decision identifier.")
    plan_id: IdentifierStr = Field(description="Parent RolloutPlan identifier.")
    incident_id: IdentifierStr = Field(description="Parent incident identifier.")
    current_stage_id: IdentifierStr = Field(description="Evaluated stage identifier.")
    proposed_next_stage_id: IdentifierStr | None = Field(
        default=None,
        description="Next stage identifier when decision_type=='advance'; else None.",
    )
    decision_type: RolloutDecisionType = Field(description="Deterministic rollout outcome.")
    evaluated_guardrails: list[str] = Field(
        default_factory=list, description="All guardrail checks evaluated."
    )
    passed_guardrails: list[str] = Field(
        default_factory=list, description="Guardrails that satisfied thresholds."
    )
    failed_guardrails: list[str] = Field(
        default_factory=list, description="Guardrails that breached thresholds."
    )
    missing_evidence: list[str] = Field(
        default_factory=list, description="Required telemetry, baseline, or verification missing."
    )
    explanation: str = Field(min_length=1, description="Deterministic decision rationale.")
    evidence_ids: list[IdentifierStr] = Field(
        default_factory=list, description="Metric and verification evidence identifiers."
    )
    approval_required: StrictBool = Field(
        default=True, description="Whether advancing or rolling back requires human approval."
    )
    decided_at: UtcDatetime = Field(default_factory=utc_now, description="UTC decision timestamp.")

    @field_validator("evidence_ids")
    @classmethod
    def _validate_evidence_ids(cls, value: list[str]) -> list[str]:
        return validate_evidence_reference_ids(value)

    @model_validator(mode="after")
    def _enforce_fail_closed_rollout_decision(self) -> RolloutDecision:
        if self.decision_type == RolloutDecisionType.ADVANCE:
            if self.failed_guardrails:
                raise ValueError("Cannot emit decision_type='advance' with failed_guardrails.")
            if self.missing_evidence:
                raise ValueError("Cannot emit decision_type='advance' with missing_evidence.")
            if self.proposed_next_stage_id is None:
                raise ValueError("decision_type='advance' requires proposed_next_stage_id.")
        return self


# ------------------------------------------------------------------------------
# 10.18 RollbackProposal & Typed Rollback Actions / VerifiedSafeState
# ------------------------------------------------------------------------------
class BooleanRollbackAction(KillswitchModel):
    """Typed Boolean feature-flag rollback action."""

    action_type: RollbackActionType = Field(default=RollbackActionType.BOOLEAN_STATE)
    target_feature: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    expected_current_enabled: StrictBool | None = None
    desired_enabled: StrictBool

    @model_validator(mode="after")
    def _validate_boolean_kind(self) -> BooleanRollbackAction:
        if self.action_type not in (
            RollbackActionType.BOOLEAN_STATE,
            RollbackActionType.SAFE_FALLBACK,
        ):
            raise ValueError(
                "BooleanRollbackAction requires boolean_state or safe_fallback, "
                f"got {self.action_type!r}."
            )
        return self


class TargetingRollbackAction(KillswitchModel):
    """Typed percentage / segment targeting rollback action."""

    action_type: RollbackActionType = Field(default=RollbackActionType.TARGETING_CONFIGURATION)
    target_feature: str = Field(min_length=1)
    environment: str = Field(min_length=1)
    expected_current_targeting_version: str | None = None
    expected_current_configuration: dict[str, Any] = Field(default_factory=dict)
    desired_targeting_configuration: dict[str, Any] = Field(default_factory=dict)
    expected_current_exposure: StrictInt | None = Field(default=None, ge=0, le=100)
    desired_exposure: StrictInt = Field(ge=0, le=100)

    @model_validator(mode="after")
    def _validate_targeting_kind(self) -> TargetingRollbackAction:
        if self.action_type != RollbackActionType.TARGETING_CONFIGURATION:
            raise ValueError(
                "TargetingRollbackAction requires action_type='targeting_configuration'."
            )
        return self


RollbackAction = BooleanRollbackAction | TargetingRollbackAction


class VerifiedSafeState(KillswitchModel):
    """Immutable, evidence-backed verified-safe checkpoint for a rollout stage."""

    safe_state_id: IdentifierStr = Field(description="Unique verified-safe checkpoint identifier.")
    incident_id: IdentifierStr = Field(description="Parent incident identifier.")
    plan_id: IdentifierStr = Field(description="RolloutPlan identifier.")
    stage_id: IdentifierStr = Field(description="RolloutStage identifier.")
    environment: str = Field(min_length=1)
    feature_name: str = Field(min_length=1)
    provider_feature_id: str | None = None
    implementation_id: str = Field(min_length=1)
    deployment_id: IdentifierStr = Field(description="Verified DeploymentEvidence identifier.")
    implementation_revision: str = Field(min_length=1)
    implementation_artifact_hash: str
    configured_exposure_percentage: StrictInt = Field(ge=0, le=100)
    targeting_configuration: dict[str, Any] = Field(default_factory=dict)
    targeting_fingerprint: str
    global_feature_state: StrictBool
    relevant_legacy_feature_states: dict[str, StrictBool] = Field(default_factory=dict)
    operation_receipt_id: IdentifierStr
    approval_id: IdentifierStr
    readback_evidence_ids: list[IdentifierStr] = Field(min_length=1)
    security_verification_ids: list[IdentifierStr] = Field(min_length=1)
    functional_verification_ids: list[IdentifierStr] = Field(min_length=1)
    telemetry_snapshot_ids: list[IdentifierStr] = Field(min_length=1)
    evaluated_guardrails: list[str] = Field(default_factory=list)
    verified_at: UtcDatetime = Field(default_factory=utc_now)
    policy_version: str = Field(default=POLICY_VERSION, min_length=1)
    provenance: EvidenceProvenance = Field(default=EvidenceProvenance.DETERMINISTIC_REASONING)

    @field_validator("implementation_artifact_hash", "targeting_fingerprint")
    @classmethod
    def _validate_sha256_fields(cls, value: str) -> str:
        return validate_sha256_hex(value)

    @field_validator(
        "readback_evidence_ids",
        "security_verification_ids",
        "functional_verification_ids",
        "telemetry_snapshot_ids",
    )
    @classmethod
    def _validate_evidence_lists(cls, value: list[str]) -> list[str]:
        return validate_evidence_reference_ids(value)


class RollbackProposal(KillswitchModel):
    """Human-reviewed rollback proposal when rollout guardrails fail.

    Never encodes a default assumption that a previously vulnerable implementation
    is a safe rollback target.
    """

    proposal_id: IdentifierStr = Field(description="Unique rollback proposal identifier.")
    incident_id: IdentifierStr = Field(description="Parent incident identifier.")
    plan_id: IdentifierStr | None = Field(
        default=None, description="Parent RolloutPlan identifier."
    )
    current_stage_id: IdentifierStr | None = Field(
        default=None, description="RolloutStage identifier active when rollback was proposed."
    )
    trigger_decision_id: IdentifierStr | None = Field(
        default=None, description="RolloutDecision identifier that triggered rollback."
    )
    target_environment: str = Field(min_length=1, description="Target environment.")
    target_feature: str = Field(min_length=1, description="Target feature flag key.")
    provider_feature_id: str | None = Field(
        default=None, description="External provider feature identifier if known."
    )
    deployment_identity: str | None = Field(
        default=None, description="Deployment revision or ID observed at proposal time."
    )
    candidate_identity: str | None = Field(
        default=None, description="Candidate patch or implementation identity."
    )
    action_type: RollbackActionType = Field(
        default=RollbackActionType.BOOLEAN_STATE,
        description="Typed rollback action category.",
    )
    targeting_action: RollbackAction | None = Field(
        default=None,
        description="Typed Boolean or targeting rollback action payload.",
    )
    current_state: StrictBool | None = Field(
        default=None, description="Observed current boolean state; None if unknown."
    )
    expected_targeting_version: str | None = Field(
        default=None, description="Expected current targeting version for compare-and-set."
    )
    last_verified_safe_state_known: StrictBool = Field(
        description="Explicitly indicates whether a verified-safe target state is known."
    )
    last_verified_safe_state: StrictBool | None = Field(
        default=None,
        description="Last verified-safe boolean state; None when unknown.",
    )
    last_verified_safe_state_id: IdentifierStr | None = Field(
        default=None,
        description="Identifier of the resolved VerifiedSafeState checkpoint, if known.",
    )
    proposed_state: StrictBool = Field(
        description="Proposed safe containment/fallback state (typically disabling feature)."
    )
    proposed_targeting_configuration: dict[str, Any] | None = Field(
        default=None,
        description="Proposed targeting configuration for percentage/segment rollback.",
    )
    triggering_evidence_ids: list[IdentifierStr] = Field(
        min_length=1, description="Evidence IDs triggering rollback recommendation."
    )
    supporting_evidence_ids: list[IdentifierStr] = Field(
        default_factory=list, description="Additional supporting evidence IDs."
    )
    rollback_rationale: str = Field(
        min_length=1, description="Explanation of guardrail failure and rollback objective."
    )
    alternative_strategies: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Bounded candidate rollback strategies considered.",
    )
    safety_limitations: list[str] = Field(
        default_factory=list,
        description="Explicit warnings about unknown prior states or vulnerable legacy paths.",
    )
    required_post_rollback_tests: list[str] = Field(
        default_factory=list,
        description="Mandatory post-rollback verification tests.",
    )
    policy_version: str = Field(default=POLICY_VERSION, min_length=1)
    manual_review_required: StrictBool = Field(
        default=True,
        description="Mandatory True when last_verified_safe_state_known is False.",
    )
    approval_required: StrictBool = Field(
        default=True, description="Mandatory True; rollbacks require human approval."
    )
    execution_authorized: StrictBool = Field(
        default=False, description="Always False on proposal; execution requires fresh approval."
    )
    created_at: UtcDatetime = Field(default_factory=utc_now, description="UTC creation timestamp.")
    expires_at: UtcDatetime | None = Field(
        default=None, description="Optional UTC proposal expiration timestamp."
    )
    idempotency_token: str | None = Field(
        default=None, description="Deterministic idempotency token for proposal."
    )
    proposal_hash: str | None = Field(
        default=None, description="Canonical SHA-256 hash over review-relevant fields."
    )

    @field_validator("proposal_hash")
    @classmethod
    def _validate_proposal_hash(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return validate_sha256_hex(value, field_name="proposal_hash")

    @field_validator("triggering_evidence_ids", "supporting_evidence_ids")
    @classmethod
    def _validate_triggering_evidence(cls, value: list[str]) -> list[str]:
        return validate_evidence_reference_ids(value)

    def compute_canonical_hash(self) -> str:
        """Compute canonical SHA-256 hash over review-relevant rollback proposal fields."""
        return compute_rollback_proposal_hash(
            {
                "proposal_id": self.proposal_id,
                "incident_id": self.incident_id,
                "plan_id": self.plan_id,
                "current_stage_id": self.current_stage_id,
                "trigger_decision_id": self.trigger_decision_id,
                "target_environment": self.target_environment,
                "target_feature": self.target_feature,
                "provider_feature_id": self.provider_feature_id,
                "deployment_identity": self.deployment_identity,
                "candidate_identity": self.candidate_identity,
                "action_type": self.action_type.value,
                "current_state": self.current_state,
                "expected_targeting_version": self.expected_targeting_version,
                "proposed_state": self.proposed_state,
                "proposed_targeting_configuration": self.proposed_targeting_configuration,
                "last_verified_safe_state_id": self.last_verified_safe_state_id,
                "policy_version": self.policy_version,
                "approval_required": self.approval_required,
                "idempotency_token": self.idempotency_token,
            }
        )

    @model_validator(mode="after")
    def _enforce_rollback_safety(self) -> RollbackProposal:
        if not self.approval_required:
            raise ValueError("RollbackProposal must set approval_required=True.")
        if not self.last_verified_safe_state_known:
            if self.last_verified_safe_state is not None:
                raise ValueError(
                    "last_verified_safe_state must be None when "
                    "last_verified_safe_state_known is False."
                )
            if not self.manual_review_required:
                raise ValueError(
                    "Unknown last verified-safe state requires manual_review_required=True."
                )
        elif self.last_verified_safe_state is None:
            raise ValueError(
                "last_verified_safe_state must be provided when "
                "last_verified_safe_state_known is True."
            )
        expected_hash = self.compute_canonical_hash()
        if self.proposal_hash is None:
            object.__setattr__(self, "proposal_hash", expected_hash)
        elif self.proposal_hash != expected_hash:
            raise ValueError(
                "RollbackProposal.proposal_hash does not match canonical payload hash."
            )
        return self


# ------------------------------------------------------------------------------
# 10.19 CoverageFinding
# ------------------------------------------------------------------------------
class CoverageFinding(KillswitchModel):
    """Audit result describing whether a route is protected by a containment feature flag."""

    coverage_finding_id: IdentifierStr = Field(description="Unique coverage finding identifier.")
    route: str = Field(min_length=1, description="Application route evaluated.")
    component: str = Field(min_length=1, description="Backing component or service name.")
    coverage_status: CoverageStatus = Field(description="Feature-flag coverage classification.")
    associated_flags: list[str] = Field(
        default_factory=list, description="Feature flags associated with this route."
    )
    source_location: str | None = Field(
        default=None, description="Relative source location if identified."
    )
    alternate_execution_paths: list[str] = Field(
        default_factory=list,
        description="Known bypasses or alternate entrypoints reaching the component.",
    )
    evidence_ids: list[IdentifierStr] = Field(
        default_factory=list, description="Supporting registry/audit evidence identifiers."
    )
    explanation: str = Field(min_length=1, description="Explanation of coverage classification.")
    recommended_action: str = Field(
        min_length=1, description="Recommended engineering or containment action."
    )
    analysis_limitations: list[str] = Field(
        default_factory=list, description="Known gaps in static or fixture-based coverage audit."
    )

    @field_validator("evidence_ids")
    @classmethod
    def _validate_evidence_ids(cls, value: list[str]) -> list[str]:
        return validate_evidence_reference_ids(value)


# ------------------------------------------------------------------------------
# 10.20 ArtifactReference
# ------------------------------------------------------------------------------
class ArtifactReference(KillswitchModel):
    """Integrity-checked metadata pointer to a stored evidence or patch artifact.

    Never stores raw credentials or unredacted sensitive payloads.
    """

    artifact_id: IdentifierStr = Field(description="Unique artifact identifier.")
    incident_id: IdentifierStr = Field(description="Parent incident identifier.")
    artifact_type: ArtifactType = Field(description="Artifact classification.")
    content_hash: str = Field(description="64-character lowercase SHA-256 hex digest.")
    hash_algorithm: str = Field(
        default=HASH_ALGORITHM_SHA256, description="Cryptographic hash algorithm used."
    )
    storage_ref: str = Field(
        min_length=1, description="Relative artifact storage URI or repository-local reference."
    )
    created_at: UtcDatetime = Field(
        default_factory=utc_now, description="UTC creation timestamp."
    )
    producer: str = Field(min_length=1, description="Subsystem or actor producing the artifact.")
    provenance: EvidenceProvenance = Field(description="Explicit artifact provenance.")
    content_type: str = Field(
        min_length=1, description="MIME content type (e.g. application/json)."
    )
    size_bytes: StrictInt | None = Field(
        default=None, ge=0, description="Artifact size in bytes."
    )
    source_revision: str | None = Field(
        default=None, description="Associated repository source revision if applicable."
    )
    redaction_status: RedactionStatus = Field(
        default=RedactionStatus.REDACTED,
        description="Whether sensitive fields have been scrubbed before storage.",
    )

    @field_validator("content_hash")
    @classmethod
    def _validate_hash(cls, value: str) -> str:
        return validate_sha256_hex(value, field_name="content_hash")

    @field_validator("hash_algorithm")
    @classmethod
    def _validate_algorithm(cls, value: str) -> str:
        if value.lower() != HASH_ALGORITHM_SHA256:
            raise ValueError(f"Unsupported hash_algorithm {value!r}; expected 'sha256'.")
        return HASH_ALGORITHM_SHA256


# ------------------------------------------------------------------------------
# 10.21 Typed Event Payloads and IncidentEvent
# ------------------------------------------------------------------------------
class FindingReceivedPayload(KillswitchModel):
    """Typed event payload for ``EventType.FINDING_RECEIVED``."""

    finding_id: IdentifierStr
    category: VulnerabilityCategory
    severity: VulnerabilitySeverity
    status: FindingStatus
    environment: str | None = None
    source_revision: str | None = None
    is_synthetic_fixture: StrictBool = False
    provenance: EvidenceProvenance | None = None


class StateTransitionPayload(KillswitchModel):
    """Typed event payload for ``EventType.INCIDENT_STATE_TRANSITION``."""

    from_state: IncidentState | None = None
    to_state: IncidentState
    reason: str = Field(min_length=1)


class ContainmentProposedPayload(KillswitchModel):
    """Typed event payload for ``EventType.CONTAINMENT_PROPOSED``."""

    proposal_id: IdentifierStr
    proposal_hash: str
    environment: str = Field(min_length=1)
    flag_name: str = Field(min_length=1)
    desired_enabled: StrictBool

    @field_validator("proposal_hash")
    @classmethod
    def _validate_hash(cls, value: str) -> str:
        return validate_sha256_hex(value, field_name="proposal_hash")


class ApprovalDecisionPayload(KillswitchModel):
    """Typed event payload for ``EventType.APPROVAL_RECORDED``."""

    approval_id: IdentifierStr
    proposal_id: IdentifierStr
    proposal_hash: str
    decision: ApprovalStatus

    @field_validator("proposal_hash")
    @classmethod
    def _validate_hash(cls, value: str) -> str:
        return validate_sha256_hex(value, field_name="proposal_hash")


class OperationReceiptPayload(KillswitchModel):
    """Typed event payload for ``EventType.FLAG_CHANGE_EXECUTED``."""

    operation_id: IdentifierStr
    proposal_id: IdentifierStr
    approval_id: IdentifierStr
    target_feature: str = Field(min_length=1)
    outcome: OperationOutcome
    observed_state: StrictBool | None = None


class VerificationCompletedPayload(KillswitchModel):
    """Typed event payload for ``EventType.CONTAINMENT_VERIFIED``."""

    verification_id: IdentifierStr
    phase: VerificationPhase
    execution_status: TestExecutionStatus
    passed: StrictBool | None = None


class RolloutDecisionPayload(KillswitchModel):
    """Typed event payload for ``EventType.ROLLOUT_DECISION_RECORDED``."""

    decision_id: IdentifierStr
    plan_id: IdentifierStr
    current_stage_id: IdentifierStr
    decision_type: RolloutDecisionType


TypedEventPayload = (
    FindingReceivedPayload
    | StateTransitionPayload
    | ContainmentProposedPayload
    | ApprovalDecisionPayload
    | OperationReceiptPayload
    | VerificationCompletedPayload
    | RolloutDecisionPayload
    | dict[str, Any]
)

_EVENT_PAYLOAD_MODELS: dict[EventType, type[KillswitchModel]] = {
    EventType.FINDING_RECEIVED: FindingReceivedPayload,
    EventType.INCIDENT_STATE_TRANSITION: StateTransitionPayload,
    EventType.CONTAINMENT_PROPOSED: ContainmentProposedPayload,
    EventType.APPROVAL_RECORDED: ApprovalDecisionPayload,
    EventType.FLAG_CHANGE_EXECUTED: OperationReceiptPayload,
    EventType.CONTAINMENT_VERIFIED: VerificationCompletedPayload,
    EventType.ROLLOUT_DECISION_RECORDED: RolloutDecisionPayload,
}


class IncidentEvent(KillswitchModel):
    """Immutable, versioned audit event supporting deterministic incident replay."""

    event_id: IdentifierStr = Field(description="Unique event identifier.")
    incident_id: IdentifierStr = Field(description="Parent incident identifier.")
    event_type: EventType = Field(description="Strongly-typed incident event category.")
    actor: str = Field(min_length=1, description="Actor identifier emitting the event.")
    actor_type: ActorType = Field(description="Category of the originating actor.")
    timestamp_utc: UtcDatetime = Field(
        default_factory=utc_now, description="UTC event emission timestamp."
    )
    correlation_id: IdentifierStr = Field(
        description="Correlation identifier spanning related workflow actions."
    )
    causation_id: IdentifierStr | None = Field(
        default=None, description="Identifier of the immediately preceding causal event."
    )
    sequence_number: StrictInt = Field(
        ge=1, description="Monotonically increasing per-incident event sequence number."
    )
    schema_version: str = Field(
        default=SCHEMA_VERSION, min_length=1, description="Event envelope schema version."
    )
    payload_model_version: str = Field(
        default=PAYLOAD_MODEL_VERSION, min_length=1, description="Typed payload schema version."
    )
    evidence_ids: list[IdentifierStr] = Field(
        default_factory=list, description="Evidence references associated with this event."
    )
    idempotency_token: IdentifierStr = Field(
        description="Unique idempotency token preventing duplicate event ingestion."
    )
    payload: TypedEventPayload = Field(
        default_factory=dict,
        description="Typed payload for security-critical events or structured dictionary.",
    )

    @field_validator("evidence_ids")
    @classmethod
    def _validate_evidence_ids(cls, value: list[str]) -> list[str]:
        return validate_evidence_reference_ids(value)

    @model_validator(mode="after")
    def _validate_typed_event_payload(self) -> IncidentEvent:
        expected_cls = _EVENT_PAYLOAD_MODELS.get(self.event_type)
        if expected_cls is not None:
            if isinstance(self.payload, expected_cls):
                return self
            if isinstance(self.payload, dict):
                self.payload = cast(
                    TypedEventPayload, expected_cls.model_validate(self.payload)
                )
            else:
                raise ValueError(
                    f"Event {self.event_type.value!r} requires payload of type "
                    f"{expected_cls.__name__}."
                )
        return self


# ------------------------------------------------------------------------------
# 10.22 EvidenceReport & IncidentRecord
# ------------------------------------------------------------------------------
class EvidenceReport(KillswitchModel):
    """Complete exportable audit bundle summarizing an incident's verified evidence."""

    report_id: IdentifierStr = Field(description="Unique evidence report identifier.")
    incident_id: IdentifierStr = Field(description="Parent incident identifier.")
    incident_status: IncidentState = Field(description="Final or current incident state.")
    timeline: list[IncidentEvent] = Field(
        default_factory=list, description="Ordered incident timeline events."
    )
    findings: list[Finding] = Field(default_factory=list, description="Normalized findings.")
    investigation_summaries: list[InvestigationSummary] = Field(
        default_factory=list, description="AI/deterministic investigation summaries."
    )
    containment_decisions: list[ContainmentProposal] = Field(
        default_factory=list, description="Proposed containment actions."
    )
    human_approvals: list[ApprovalDecision] = Field(
        default_factory=list, description="Recorded human approval decisions."
    )
    operation_receipts: list[OperationReceipt] = Field(
        default_factory=list, description="External operation execution receipts."
    )
    verification_outcomes: list[VerificationResult] = Field(
        default_factory=list, description="Security verification outcomes."
    )
    patch_proposals: list[PatchProposal] = Field(
        default_factory=list, description="Candidate source patches proposed."
    )
    patch_test_results: list[PatchTestResult] = Field(
        default_factory=list, description="Isolated patch test run outcomes."
    )
    deployment_evidence: list[DeploymentEvidence] = Field(
        default_factory=list, description="Observed deployment records."
    )
    rollout_plans: list[RolloutPlan] = Field(
        default_factory=list, description="Progressive rollout plans."
    )
    rollout_decisions: list[RolloutDecision] = Field(
        default_factory=list, description="Deterministic rollout stage decisions."
    )
    rollback_history: list[RollbackProposal] = Field(
        default_factory=list, description="Proposed rollback recommendations."
    )
    coverage_findings: list[CoverageFinding] = Field(
        default_factory=list, description="Feature flag coverage audit findings."
    )
    artifact_references: list[ArtifactReference] = Field(
        default_factory=list, description="Integrity-checked artifact metadata."
    )
    missing_evidence: list[str] = Field(
        default_factory=list, description="Explicit list of missing or unverified evidence items."
    )
    limitations: list[str] = Field(
        default_factory=list, description="Known limitations, synthetic data notes, or caveats."
    )
    completeness: EvidenceCompleteness = Field(
        description="Completeness assessment of the evidence bundle."
    )
    generated_at: UtcDatetime = Field(
        default_factory=utc_now, description="UTC report generation timestamp."
    )

    @model_validator(mode="after")
    def _enforce_report_consistency(self) -> EvidenceReport:
        if self.missing_evidence and self.completeness == EvidenceCompleteness.COMPLETE:
            raise ValueError(
                "EvidenceReport completeness cannot be 'complete' "
                "when missing_evidence is non-empty."
            )
        try:
            validate_unique_ids(
                [e.event_id for e in self.timeline], field_name="timeline.event_id"
            )
            validate_unique_ids(
                [f.finding_id for f in self.findings], field_name="findings.finding_id"
            )
            validate_unique_ids(
                [a.artifact_id for a in self.artifact_references],
                field_name="artifact_references.artifact_id",
            )
        except KillswitchError as exc:
            raise ValueError(str(exc)) from exc
        return self


class IncidentRecord(KillswitchModel):
    """Top-level persisted incident state envelope used by IncidentRepository."""

    incident_id: IdentifierStr = Field(description="Unique incident identifier.")
    state: IncidentState = Field(description="Current deterministic incident state.")
    version: StrictInt = Field(
        default=1, ge=1, description="Optimistic concurrency version counter."
    )
    environment: str = Field(min_length=1, description="Target environment.")
    primary_finding_id: IdentifierStr = Field(description="Originating finding identifier.")
    active_proposal_id: IdentifierStr | None = Field(
        default=None, description="Currently active containment proposal ID if any."
    )
    created_at: UtcDatetime = Field(default_factory=utc_now, description="UTC creation timestamp.")
    updated_at: UtcDatetime = Field(
        default_factory=utc_now, description="UTC last-modified timestamp."
    )


# ------------------------------------------------------------------------------
# Configuration Fixture Schemas (`config/*.json`)
# ------------------------------------------------------------------------------
class ImplementationBinding(KillswitchModel):
    """Explicit relationship between an application implementation and its controlling flag."""

    implementation_id: str = Field(min_length=1, description="Implementation or variant ID.")
    flag_name: str = Field(min_length=1, description="Declared feature flag controlling it.")
    role: FeatureRole = Field(
        default=FeatureRole.IMPLEMENTATION_GUARD,
        description="Declared role of the feature flag for this implementation.",
    )
    is_replacement: StrictBool = Field(
        default=False,
        description="Whether this implementation is a candidate replacement.",
    )
    fallback_behavior: str | None = Field(
        default=None,
        description="Declared behavior when the controlling flag is disabled.",
    )


class RouteFlagEntry(KillswitchModel):
    """Single route-to-flag declaration inside ``config/route_flag_map.json``."""

    route: str = Field(min_length=1, description="Canonical HTTP route path.")
    route_aliases: list[str] = Field(
        default_factory=list,
        description="Explicitly declared route aliases resolving to this canonical route.",
    )
    route_variants: list[str] = Field(
        default_factory=list,
        description="Explicitly declared route path variants (e.g. trailing slash).",
    )
    http_methods: list[str] = Field(
        default_factory=list,
        description="Supported HTTP methods for this route, when known.",
    )
    component: str = Field(min_length=1, description="Owning logical application component.")
    component_aliases: list[str] = Field(
        default_factory=list,
        description="Explicitly declared component aliases (e.g. security contract names).",
    )
    flags: list[str] = Field(
        default_factory=list, description="Declared feature flags guarding this route."
    )
    implementation_bindings: list[ImplementationBinding] = Field(
        default_factory=list,
        description="Explicit implementation-to-flag bindings for disambiguation.",
    )
    feature_roles: dict[str, FeatureRole] = Field(
        default_factory=dict,
        description="Optional per-flag role map within this route entry.",
    )
    shared_dependencies: list[str] = Field(
        default_factory=list,
        description="Declared shared feature dependencies affecting this route.",
    )
    fallback_route: str | None = Field(
        default=None, description="Safe fallback route or behavior when flag is disabled."
    )
    coverage_status: CoverageStatus = Field(description="Declared flag protection status.")
    deployment_assumptions: list[str] = Field(
        default_factory=list, description="Explicit fixture assumptions about deployment."
    )
    evidence_ids: list[IdentifierStr] = Field(
        default_factory=list,
        description="Optional evidence references supporting this declaration.",
    )
    is_fixture_assumption: StrictBool = Field(
        default=True, description="Marks unverified fixture declarations."
    )


class RouteFlagRegistry(KillswitchModel):
    """Schema for ``config/route_flag_map.json``."""

    schema_version: str = Field(default="1.0", min_length=1, description="Registry schema version.")
    registry_version: str = Field(min_length=1, description="Registry version string.")
    environment: str = Field(min_length=1, description="Target demonstration environment.")
    registry_fingerprint: str | None = Field(
        default=None,
        description="Optional SHA-256 content fingerprint of the registry.",
    )
    application_revision: str | None = Field(
        default=None,
        description="Application source-tree revision bound to this registry, if known.",
    )
    git_commit_sha: str | None = Field(
        default=None,
        description="Git commit SHA associated with this registry, if known.",
    )
    declared_features: list[str] = Field(
        min_length=1, description="Declared feature flags recognized by this environment."
    )
    safe_fallback: dict[str, Any] = Field(
        default_factory=dict, description="Safe fallback endpoint configuration."
    )
    provenance: EvidenceProvenance = Field(
        default=EvidenceProvenance.REFERENCE_FIXTURE,
        description="Explicit provenance marking fixture assumptions.",
    )
    is_fixture_assumption: StrictBool = Field(default=True)
    routes: list[RouteFlagEntry] = Field(min_length=1, description="Declared route mappings.")


class RolloutPolicyConfig(KillswitchModel):
    """Schema for ``config/rollout_policy.json``."""

    policy_version: str = Field(min_length=1, description="Rollout policy version.")
    is_demo_default: StrictBool = Field(
        default=True,
        description="Explicitly marks illustrative demonstration thresholds.",
    )
    units: dict[str, str] = Field(
        min_length=1, description="Explicit unit documentation for numeric policy fields."
    )
    stages_percent: list[StrictInt] = Field(
        min_length=1, description="Ordered rollout exposure percentages in [0, 100]."
    )
    require_security_verification: StrictBool = Field(default=True)
    require_deployment_evidence: StrictBool = Field(default=True)
    require_feature_state_readback: StrictBool = Field(default=True)
    require_human_approval: StrictBool = Field(default=True)
    rollback_manual_review_required: StrictBool = Field(default=True)
    guardrails: RolloutGuardrailConfig = Field(description="Default guardrail thresholds.")
    minimum_request_count: StrictInt = Field(
        ge=0, description="Minimum request sample size per stage."
    )
    minimum_observation_window_seconds: StrictInt = Field(
        ge=1, description="Minimum observation window duration in seconds."
    )

    @model_validator(mode="after")
    def _enforce_policy_invariants(self) -> RolloutPolicyConfig:
        if not self.require_human_approval:
            raise ValueError("RolloutPolicyConfig must keep require_human_approval=True.")
        prev = -1
        for pct in self.stages_percent:
            if not (0 <= pct <= 100):
                raise ValueError(f"Rollout stage percentage {pct} out of [0, 100] range.")
            if pct <= prev:
                raise ValueError("stages_percent must be strictly increasing.")
            prev = pct
        return self


class ContainmentPolicyWeights(KillswitchModel):
    """Normalized non-negative weights summing to 1.0 for containment policy scoring."""

    residual_exposure: float = Field(default=0.50, ge=0.0, le=1.0)
    operational_disruption: float = Field(default=0.25, ge=0.0, le=1.0)
    dependency_impact: float = Field(default=0.15, ge=0.0, le=1.0)
    uncertainty: float = Field(default=0.10, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _enforce_weights_sum_to_one(self) -> ContainmentPolicyWeights:
        total = (
            self.residual_exposure
            + self.operational_disruption
            + self.dependency_impact
            + self.uncertainty
        )
        if abs(total - 1.0) > 1e-6:
            raise ValueError(f"ContainmentPolicyWeights must sum to 1.0 (got {total}).")
        return self


class ContainmentPolicyConfig(KillswitchModel):
    """Schema for ``config/containment_policy.json``."""

    policy_version: str = Field(min_length=1, description="Containment policy version.")
    is_demo_default: StrictBool = Field(default=True)
    description: str = Field(default="")
    weights: ContainmentPolicyWeights = Field(default_factory=ContainmentPolicyWeights)
    max_traversal_depth: StrictInt = Field(default=16, ge=1, le=256)
    max_graph_nodes: StrictInt = Field(default=500, ge=10, le=100_000)
    default_proposal_ttl_seconds: StrictInt = Field(default=900, ge=30, le=86_400)


class RollbackPolicyConfig(KillswitchModel):
    """Schema for ``config/rollback_policy.json``."""

    policy_version: str = Field(
        default=POLICY_VERSION, min_length=1, description="Rollback policy version."
    )
    is_demo_default: StrictBool = Field(default=True)
    require_fresh_human_approval: StrictBool = Field(default=True)
    require_post_rollback_verification: StrictBool = Field(default=True)
    require_readback_reconciliation: StrictBool = Field(default=True)
    forbid_vulnerable_legacy_reactivation: StrictBool = Field(default=True)
    allow_partial_exposure_on_security_regression: StrictBool = Field(default=False)
    safe_state_max_age_seconds: StrictInt = Field(default=86_400, ge=60)
    proposal_expiration_seconds: StrictInt = Field(default=900, ge=30, le=86_400)
    post_rollback_hold_seconds: StrictInt = Field(default=300, ge=0, le=86_400)
    cooldown_suppresses_security_failure: StrictBool = Field(default=False)
    known_vulnerable_implementations: list[str] = Field(default_factory=lambda: ["search_v1"])
    precedence_order: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def _enforce_rollback_policy_invariants(self) -> RollbackPolicyConfig:
        if not self.require_fresh_human_approval:
            raise ValueError("RollbackPolicyConfig must keep require_fresh_human_approval=True.")
        if not self.forbid_vulnerable_legacy_reactivation:
            raise ValueError(
                "RollbackPolicyConfig must keep forbid_vulnerable_legacy_reactivation=True."
            )
        if self.allow_partial_exposure_on_security_regression:
            raise ValueError(
                "RollbackPolicyConfig cannot allow partial exposure on confirmed "
                "security regression."
            )
        if self.cooldown_suppresses_security_failure:
            raise ValueError("Cooldown must never suppress confirmed security failure.")
        return self
