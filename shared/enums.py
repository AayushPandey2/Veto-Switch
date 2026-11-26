"""Centralized, strongly-typed enumerations for Killswitch X.

All domain statuses, categories, lifecycle states, provenance labels, and event types
are defined here as ``StrEnum`` values so arbitrary raw strings are never scattered
across subsystems.
"""

from __future__ import annotations

from enum import StrEnum


class VulnerabilityCategory(StrEnum):
    """Normalized security vulnerability categories supported by Killswitch X."""

    SQL_INJECTION = "sql_injection"
    PATH_TRAVERSAL = "path_traversal"
    DEPENDENCY_CVE = "dependency_cve"
    OTHER = "other"


class VulnerabilitySeverity(StrEnum):
    """Severity rating for a normalized vulnerability finding."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class FindingStatus(StrEnum):
    """Normalized verification status of a security finding prior to containment.

    ``SUSPECTED`` indicates an unverified scanner report; ``REPRODUCED`` requires
    explicit reproduction evidence references.
    """

    SUSPECTED = "suspected"
    REPRODUCED = "reproduced"


class IncidentState(StrEnum):
    """Deterministic lifecycle states for a Killswitch X security incident.

    State transition rules are deferred to Phase 02 (`agent_core/orchestrator.py`).
    """

    RECEIVED = "RECEIVED"
    VALIDATION_REQUESTED = "VALIDATION_REQUESTED"
    REPRODUCED = "REPRODUCED"
    FLAG_MAPPED = "FLAG_MAPPED"
    CONTAINMENT_PROPOSED = "CONTAINMENT_PROPOSED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPLYING = "APPLYING"
    CONTAINMENT_TEST_PENDING = "CONTAINMENT_TEST_PENDING"
    CONTAINED = "CONTAINED"
    PATCH_PENDING = "PATCH_PENDING"
    PATCH_TESTED = "PATCH_TESTED"
    ROLLOUT_PENDING = "ROLLOUT_PENDING"
    RECOVERED = "RECOVERED"
    REJECTED = "REJECTED"
    UNVERIFIED = "UNVERIFIED"
    UNMAPPED = "UNMAPPED"
    CHANGE_FAILED = "CHANGE_FAILED"
    CONTAINMENT_FAILED = "CONTAINMENT_FAILED"
    PATCH_FAILED = "PATCH_FAILED"
    ROLLOUT_PAUSED = "ROLLOUT_PAUSED"
    ROLLBACK_PROPOSED = "ROLLBACK_PROPOSED"


class MappingStatus(StrEnum):
    """Result of mapping an affected route/component to a feature flag."""

    MATCHED = "matched"
    AMBIGUOUS = "ambiguous"
    UNMAPPED = "unmapped"


class ApprovalStatus(StrEnum):
    """Lifecycle status of an authenticated human approval decision."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    INVALIDATED = "invalidated"


class VerificationPhase(StrEnum):
    """Security verification phase relative to containment and patching."""

    BEFORE_CONTAINMENT = "before_containment"
    AFTER_CONTAINMENT = "after_containment"
    AFTER_PATCH = "after_patch"


class TestExecutionStatus(StrEnum):
    """Execution outcome of a security or patch test run."""

    __test__ = False

    TEST_PASSED = "test_passed"
    TEST_FAILED = "test_failed"
    INFRASTRUCTURE_ERROR = "infrastructure_error"
    NOT_RUN = "not_run"


class PatchStatus(StrEnum):
    """Lifecycle status of a candidate remediation patch.

    Note: ``PATCH_DEPLOYED`` denotes observed source deployment only and never
    implies feature-flag activation.
    """

    PATCH_PROPOSED = "patch_proposed"
    PATCH_TESTED = "patch_tested"
    PATCH_FAILED = "patch_failed"
    PATCH_DEPLOYED = "patch_deployed"


class RolloutDecisionType(StrEnum):
    """Deterministic decision produced after evaluating a rollout stage."""

    ADVANCE = "advance"
    HOLD = "hold"
    ROLLBACK_PROPOSED = "rollback_proposed"


class CoverageStatus(StrEnum):
    """Feature-flag protection coverage classification for an application route."""

    PROTECTED = "protected"
    PARTIALLY_PROTECTED = "partially_protected"
    UNPROTECTED = "unprotected"
    UNKNOWN = "unknown"


class EvidenceProvenance(StrEnum):
    """Explicit origin classification distinguishing observed facts from AI or fixtures."""

    ACTUAL_OBSERVED = "actual_observed"
    SECURITY_TEST_OUTPUT = "security_test_output"
    EXTERNAL_OPERATION_RECEIPT = "external_operation_receipt"
    LLM_INTERPRETATION = "llm_interpretation"
    DETERMINISTIC_REASONING = "deterministic_reasoning"
    DETERMINISTIC_FALLBACK = "deterministic_fallback"
    SYNTHETIC_TELEMETRY = "synthetic_telemetry"
    REFERENCE_FIXTURE = "reference_fixture"
    MANUAL_OPERATOR_INPUT = "manual_operator_input"


class ArtifactType(StrEnum):
    """Categories of stored evidence and candidate remediation artifacts."""

    SCANNER_REPORT = "scanner_report"
    REPRODUCTION_LOG = "reproduction_log"
    REGRESSION_LOG = "regression_log"
    FEATURE_STATE_SNAPSHOT = "feature_state_snapshot"
    OPERATION_RECEIPT = "operation_receipt"
    PATCH_DIFF = "patch_diff"
    PATCH_TEST_LOG = "patch_test_log"
    DEPLOYMENT_MANIFEST = "deployment_manifest"
    TELEMETRY_SNAPSHOT = "telemetry_snapshot"
    INCIDENT_EVIDENCE_BUNDLE = "incident_evidence_bundle"


class EventType(StrEnum):
    """Auditable event types emitted throughout the incident lifecycle.

    Preserves all Prompt 01 baseline values and adds granular Prompt 02 intake,
    investigation, mapping, approval, execution, verification, patching, rollout,
    rollback, and operational events.
    """

    # --- Intake & verification ---
    FINDING_RECEIVED = "finding_received"
    VALIDATION_REQUESTED = "validation_requested"
    VERIFICATION_REQUESTED = "verification_requested"
    VULNERABILITY_REPRODUCED = "vulnerability_reproduced"
    REPRODUCTION_CONFIRMED = "reproduction_confirmed"
    REPRODUCTION_NOT_CONFIRMED = "reproduction_not_confirmed"
    VULNERABILITY_UNVERIFIED = "vulnerability_unverified"
    VERIFICATION_INCONCLUSIVE = "verification_inconclusive"
    VERIFICATION_FAILED = "verification_failed"
    VERIFICATION_TIMEOUT = "verification_timeout"

    # --- Investigation & mapping ---
    INVESTIGATION_REQUESTED = "investigation_requested"
    INVESTIGATION_COMPLETED = "investigation_completed"
    INVESTIGATION_FAILED = "investigation_failed"
    MAPPING_REQUESTED = "mapping_requested"
    FLAG_MAPPED = "flag_mapped"
    MAPPING_MATCHED = "mapping_matched"
    MAPPING_AMBIGUOUS = "mapping_ambiguous"
    MAPPING_UNMAPPED = "mapping_unmapped"
    FLAG_MAPPING_FAILED = "flag_mapping_failed"
    MAPPING_FAILED = "mapping_failed"

    # --- Containment proposal & approval ---
    CONTAINMENT_PROPOSED = "containment_proposed"
    CONTAINMENT_PROPOSAL_INVALIDATED = "containment_proposal_invalidated"
    APPROVAL_REQUESTED = "approval_requested"
    APPROVAL_RECORDED = "approval_recorded"
    APPROVAL_GRANTED = "approval_granted"
    APPROVAL_REJECTED = "approval_rejected"
    APPROVAL_EXPIRED = "approval_expired"
    APPROVAL_INVALIDATED = "approval_invalidated"

    # --- External operations ---
    EXECUTION_REQUESTED = "execution_requested"
    EXECUTION_ACCEPTED = "execution_accepted"
    FLAG_CHANGE_EXECUTED = "flag_change_executed"
    FLAG_UPDATE_SUCCESS = "flag_update_success"
    FLAG_CHANGE_FAILED = "flag_change_failed"
    FLAG_UPDATE_FAILED = "flag_update_failed"
    FLAG_UPDATE_OUTCOME_UNKNOWN = "flag_update_outcome_unknown"
    FLAG_STATE_OBSERVED = "flag_state_observed"

    # --- Post-containment verification ---
    CONTAINMENT_VERIFICATION_REQUESTED = "containment_verification_requested"
    CONTAINMENT_VERIFIED = "containment_verified"
    CONTAINMENT_VERIFICATION_PASSED = "containment_verification_passed"
    CONTAINMENT_FAILED = "containment_failed"
    CONTAINMENT_VERIFICATION_FAILED = "containment_verification_failed"
    FUNCTIONAL_SMOKE_TEST_PASSED = "functional_smoke_test_passed"
    FUNCTIONAL_SMOKE_TEST_FAILED = "functional_smoke_test_failed"
    CONTAINMENT_CONFIRMED = "containment_confirmed"

    # --- Patching ---
    PATCH_REQUESTED = "patch_requested"
    PATCH_PROPOSED = "patch_proposed"
    PATCH_VALIDATION_FAILED = "patch_validation_failed"
    PATCH_TEST_REQUESTED = "patch_test_requested"
    PATCH_TEST_COMPLETED = "patch_test_completed"
    PATCH_TEST_PASSED = "patch_test_passed"
    PATCH_TEST_FAILED = "patch_test_failed"
    PATCH_TEST_INFRASTRUCTURE_ERROR = "patch_test_infrastructure_error"
    DEPLOYMENT_OBSERVED = "deployment_observed"
    PATCH_DEPLOYMENT_OBSERVED = "patch_deployment_observed"

    # --- Rollout ---
    ROLLOUT_PLANNED = "rollout_planned"
    ROLLOUT_PLAN_CREATED = "rollout_plan_created"
    ROLLOUT_STAGE_PROPOSED = "rollout_stage_proposed"
    ROLLOUT_STAGE_APPROVED = "rollout_stage_approved"
    ROLLOUT_STAGE_APPLIED = "rollout_stage_applied"
    ROLLOUT_STAGE_OBSERVED = "rollout_stage_observed"
    ROLLOUT_METRICS_RECEIVED = "rollout_metrics_received"
    ROLLOUT_DECISION_RECORDED = "rollout_decision_recorded"
    ROLLOUT_ADVANCE_PROPOSED = "rollout_advance_proposed"
    ROLLOUT_HOLD = "rollout_hold"
    ROLLOUT_COMPLETED = "rollout_completed"
    ROLLOUT_FAILED = "rollout_failed"

    # --- Rollback ---
    ROLLBACK_PROPOSED = "rollback_proposed"
    ROLLBACK_APPROVED = "rollback_approved"
    ROLLBACK_REJECTED = "rollback_rejected"
    ROLLBACK_APPLIED = "rollback_applied"
    ROLLBACK_VERIFICATION_PASSED = "rollback_verification_passed"
    ROLLBACK_VERIFICATION_FAILED = "rollback_verification_failed"

    # --- Operational & lifecycle ---
    OPERATION_RETRY_REQUESTED = "operation_retry_requested"
    OPERATION_RETRY_EXHAUSTED = "operation_retry_exhausted"
    INTEGRATION_UNAVAILABLE = "integration_unavailable"
    MANUAL_REVIEW_REQUESTED = "manual_review_requested"
    INCIDENT_STATE_TRANSITION = "incident_state_transition"
    INCIDENT_RECOVERED = "incident_recovered"
    INCIDENT_REOPENED = "incident_reopened"
    EVIDENCE_EXPORTED = "evidence_exported"


class ActorType(StrEnum):
    """Originating actor category for events and decisions."""

    SECURITY_SCANNER = "security_scanner"
    SECURITY_VERIFIER = "security_verifier"
    AI_AGENT = "ai_agent"
    DETERMINISTIC_ENGINE = "deterministic_engine"
    HUMAN_OPERATOR = "human_operator"
    PLATFORM_EXECUTOR = "platform_executor"
    SYSTEM = "system"


class ProposalType(StrEnum):
    """Classification of operational proposals requiring validation/approval."""

    CONTAINMENT_FLAG_DISABLE = "containment_flag_disable"
    CONTAINMENT_FLAG_SWITCH = "containment_flag_switch"
    ROLLOUT_ADVANCE = "rollout_advance"
    ROLLBACK = "rollback"


class OperationOutcome(StrEnum):
    """Execution outcome reported by an authorized external platform operation."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    REJECTED = "rejected"
    TIMED_OUT = "timed_out"
    UNKNOWN = "unknown"


class DeploymentStatus(StrEnum):
    """Observation status of a code deployment in a target environment."""

    OBSERVED = "observed"
    PENDING = "pending"
    FAILED = "failed"
    MISSING = "missing"
    UNKNOWN = "unknown"


class EvidenceCompleteness(StrEnum):
    """Completeness assessment of an exported incident evidence report."""

    COMPLETE = "complete"
    PARTIAL = "partial"
    INCOMPLETE = "incomplete"


class GraphNodeType(StrEnum):
    """Entity types represented in the application dependency graph."""

    APPLICATION = "application"
    ROUTE = "route"
    SERVICE = "service"
    FEATURE_FLAG = "feature_flag"
    DATABASE = "database"
    STORAGE = "storage"
    DEPENDENCY = "dependency"
    REPLACEMENT_IMPLEMENTATION = "replacement_implementation"


class GraphEdgeType(StrEnum):
    """Directed relationship types in the application dependency graph."""

    DEPENDS_ON = "depends_on"
    CONTROLLED_BY = "controlled_by"
    CALLS = "calls"
    ACCESSES = "accesses"
    REPLACED_BY = "replaced_by"


class ContainmentStrategyType(StrEnum):
    """Candidate containment approaches evaluated during incident response."""

    DISABLE_FEATURE_FLAG = "disable_feature_flag"
    SWITCH_TO_REPLACEMENT_FLAG = "switch_to_replacement_flag"
    RESTRICT_TARGETING = "restrict_targeting"
    MANUAL_MITIGATION_REQUIRED = "manual_mitigation_required"


class FeatureObservationStatus(StrEnum):
    """Distinguishes confirmed flag state from unavailable or unknown state."""

    OBSERVED = "observed"
    UNAVAILABLE = "unavailable"
    UNKNOWN = "unknown"


class RedactionStatus(StrEnum):
    """Tracks whether an artifact has undergone secret/PII redaction."""

    REDACTED = "redacted"
    NOT_REQUIRED = "not_required"
    PENDING = "pending"


class PatchOrigin(StrEnum):
    """Distinguishes AI-generated patch candidates from static reference fixtures."""

    LLM_CANDIDATE = "llm_candidate"
    REFERENCE_FIXTURE = "reference_fixture"
    HUMAN_AUTHORED = "human_authored"


class ClaimCategory(StrEnum):
    """Grounded claim classification separating facts from interpretations and risks."""

    OBSERVED = "observed"
    INFERRED = "inferred"
    ASSUMPTION = "assumption"
    POTENTIAL_IMPACT = "potential_impact"
    UNKNOWN = "unknown"


class ClaimValidationStatus(StrEnum):
    """Outcome of claim-level evidence grounding and contradiction validation."""

    VALIDATED = "validated"
    UNVERIFIED_INTERPRETATION = "unverified_interpretation"
    UNSUPPORTED_REFERENCE = "unsupported_reference"
    FACTUAL_CONTRADICTION = "factual_contradiction"
    REQUIRES_REVIEW = "requires_review"


class EvidenceSupportLevel(StrEnum):
    """Explainable qualitative evidence support classification (not a calibrated probability)."""

    HIGH_EVIDENCE_SUPPORT = "high_evidence_support"
    MODERATE_EVIDENCE_SUPPORT = "moderate_evidence_support"
    LIMITED_EVIDENCE_SUPPORT = "limited_evidence_support"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class InvestigationStatus(StrEnum):
    """Outcome status of an AI-assisted or deterministic fallback investigation."""

    COMPLETED = "completed"
    PARTIAL = "partial"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"
    FAILED = "failed"


class AIProviderErrorCategory(StrEnum):
    """Normalized provider-independent AI error categories."""

    AUTHENTICATION_ERROR = "authentication_error"
    INVALID_REQUEST = "invalid_request"
    RATE_LIMIT = "rate_limit"
    TIMEOUT = "timeout"
    TEMPORARY_UNAVAILABLE = "temporary_unavailable"
    INVALID_MODEL_CONFIGURATION = "invalid_model_configuration"
    UNSUPPORTED_CAPABILITY = "unsupported_capability"
    RESPONSE_VALIDATION_FAILURE = "response_validation_failure"
    TOKEN_BUDGET_EXCEEDED = "token_budget_exceeded"
    CONTENT_RESTRICTION = "content_restriction"
    UNKNOWN_PROVIDER_ERROR = "unknown_provider_error"


class DataClassification(StrEnum):
    """Data sensitivity classification used by model routing and failover policies."""

    PUBLIC = "public"
    INTERNAL = "internal"
    RESTRICTED_SECURITY = "restricted_security"
    SENSITIVE_SOURCE = "sensitive_source"


class AITaskType(StrEnum):
    """Logical AI task categories routed through the central LLMGateway."""

    INVESTIGATION = "investigation"
    CONTAINMENT_EXPLANATION = "containment_explanation"
    COVERAGE_EXPLANATION = "coverage_explanation"
    CANDIDATE_PATCH_GENERATION = "candidate_patch_generation"
    RELEASE_EXPLANATION = "release_explanation"


class FeatureRole(StrEnum):
    """Declared role of a feature flag within a route/component entry."""

    IMPLEMENTATION_GUARD = "implementation_guard"
    REPLACEMENT_GUARD = "replacement_guard"
    SHARED_DEPENDENCY = "shared_dependency"
    ROUTING_SELECTOR = "routing_selector"
    UNKNOWN = "unknown"


class MappingMethod(StrEnum):
    """Deterministic resolution tier used to produce a mapping decision."""

    VERIFIED_IMPLEMENTATION_BINDING = "verified_implementation_binding"
    EXACT_ROUTE_AND_COMPONENT = "exact_route_and_component"
    DECLARED_ALIAS_AND_IMPLEMENTATION = "declared_alias_and_implementation"
    COMPONENT_ONLY = "component_only"
    AMBIGUOUS_CANDIDATES = "ambiguous_candidates"
    UNMAPPED = "unmapped"


class MappingActionEligibility(StrEnum):
    """Operational readiness of a mapping result for downstream containment planning."""

    ELIGIBLE = "eligible"
    HOLD = "hold"
    BLOCKED = "blocked"


class MappingReasonCode(StrEnum):
    """Machine-readable deterministic reason codes emitted by the flag mapper."""

    EXACT_ROUTE_MATCH = "EXACT_ROUTE_MATCH"
    DECLARED_ALIAS_MATCH = "DECLARED_ALIAS_MATCH"
    DECLARED_VARIANT_MATCH = "DECLARED_VARIANT_MATCH"
    COMPONENT_MATCH = "COMPONENT_MATCH"
    COMPONENT_ALIAS_MATCH = "COMPONENT_ALIAS_MATCH"
    VERIFIED_IMPLEMENTATION_MATCH = "VERIFIED_IMPLEMENTATION_MATCH"
    SINGLE_VALID_CANDIDATE = "SINGLE_VALID_CANDIDATE"
    MULTIPLE_VALID_CANDIDATES = "MULTIPLE_VALID_CANDIDATES"
    UNKNOWN_ROUTE = "UNKNOWN_ROUTE"
    UNKNOWN_COMPONENT = "UNKNOWN_COMPONENT"
    ROUTE_COMPONENT_CONFLICT = "ROUTE_COMPONENT_CONFLICT"
    HTTP_METHOD_MISMATCH = "HTTP_METHOD_MISMATCH"
    NO_IMPLEMENTATION_BINDING = "NO_IMPLEMENTATION_BINDING"
    UNDECLARED_FEATURE = "UNDECLARED_FEATURE"
    INVALID_REGISTRY = "INVALID_REGISTRY"
    REGISTRY_VERSION_MISMATCH = "REGISTRY_VERSION_MISMATCH"
    REGISTRY_REVISION_MISMATCH = "REGISTRY_REVISION_MISMATCH"
    ENVIRONMENT_MISMATCH = "ENVIRONMENT_MISMATCH"
    FEATURE_STATE_OBSERVED = "FEATURE_STATE_OBSERVED"
    FEATURE_STATE_UNAVAILABLE = "FEATURE_STATE_UNAVAILABLE"
    FEATURE_STATE_UNKNOWN = "FEATURE_STATE_UNKNOWN"
    FEATURE_STATE_STALE = "FEATURE_STATE_STALE"
    FEATURE_STATE_CONFLICT = "FEATURE_STATE_CONFLICT"
    FEATURE_STATE_FUTURE_TIMESTAMP = "FEATURE_STATE_FUTURE_TIMESTAMP"
    SEGMENT_TARGETING_UNCERTAINTY = "SEGMENT_TARGETING_UNCERTAINTY"
    FEATURE_ALREADY_DISABLED = "FEATURE_ALREADY_DISABLED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    UNVERIFIED_FINDING = "UNVERIFIED_FINDING"
    FIXTURE_ONLY_EVIDENCE = "FIXTURE_ONLY_EVIDENCE"
    EVIDENCE_NOT_FOUND = "EVIDENCE_NOT_FOUND"
    EVIDENCE_INCIDENT_MISMATCH = "EVIDENCE_INCIDENT_MISMATCH"
    EVIDENCE_REVISION_MISMATCH = "EVIDENCE_REVISION_MISMATCH"
    MANUAL_REVIEW_REQUIRED = "MANUAL_REVIEW_REQUIRED"


class ContainmentReasonCode(StrEnum):
    """Machine-readable deterministic reason codes for blast-radius & containment decisions."""

    ELIGIBLE_FOR_PROPOSAL = "ELIGIBLE_FOR_PROPOSAL"
    MAPPING_NOT_ACTIONABLE = "MAPPING_NOT_ACTIONABLE"
    GRAPH_REVISION_MISMATCH = "GRAPH_REVISION_MISMATCH"
    GRAPH_ENVIRONMENT_MISMATCH = "GRAPH_ENVIRONMENT_MISMATCH"
    INVALID_GRAPH = "INVALID_GRAPH"
    UNKNOWN_CONTROL_CAPABILITY = "UNKNOWN_CONTROL_CAPABILITY"
    MISSING_FALLBACK_EVIDENCE = "MISSING_FALLBACK_EVIDENCE"
    STALE_FEATURE_STATE = "STALE_FEATURE_STATE"
    FEATURE_ALREADY_DISABLED = "FEATURE_ALREADY_DISABLED"
    REPLACEMENT_NOT_DEPLOYED = "REPLACEMENT_NOT_DEPLOYED"
    REPLACEMENT_NOT_VERIFIED = "REPLACEMENT_NOT_VERIFIED"
    REPLACEMENT_REVISION_MISMATCH = "REPLACEMENT_REVISION_MISMATCH"
    RESIDUAL_EXPOSURE_UNRESOLVED = "RESIDUAL_EXPOSURE_UNRESOLVED"
    UNSUPPORTED_MULTI_FLAG_ACTION = "UNSUPPORTED_MULTI_FLAG_ACTION"
    FIXTURE_ONLY_EVIDENCE = "FIXTURE_ONLY_EVIDENCE"
    UNVERIFIED_FINDING = "UNVERIFIED_FINDING"
    MANUAL_REVIEW_REQUIRED = "MANUAL_REVIEW_REQUIRED"


class PatchRejectionReason(StrEnum):
    """Stable machine-readable rejection reasons for Phase 07 Patch Engineer."""

    FINDING_NOT_REPRODUCED = "FINDING_NOT_REPRODUCED"
    MISSING_REPRODUCTION_EVIDENCE = "MISSING_REPRODUCTION_EVIDENCE"
    CONTAINMENT_NOT_VERIFIED = "CONTAINMENT_NOT_VERIFIED"
    SOURCE_TARGET_UNAUTHORIZED = "SOURCE_TARGET_UNAUTHORIZED"
    SOURCE_UNAVAILABLE = "SOURCE_UNAVAILABLE"
    SOURCE_REVISION_MISMATCH = "SOURCE_REVISION_MISMATCH"
    AMBIGUOUS_SOURCE_LOCATION = "AMBIGUOUS_SOURCE_LOCATION"
    UNSUPPORTED_VULNERABILITY_CATEGORY = "UNSUPPORTED_VULNERABILITY_CATEGORY"
    INVALID_STRUCTURED_OUTPUT = "INVALID_STRUCTURED_OUTPUT"
    MALFORMED_UNIFIED_DIFF = "MALFORMED_UNIFIED_DIFF"
    PATCH_FILE_OUTSIDE_ALLOWLIST = "PATCH_FILE_OUTSIDE_ALLOWLIST"
    PATCH_CONTEXT_MISMATCH = "PATCH_CONTEXT_MISMATCH"
    PATCH_SIZE_LIMIT_EXCEEDED = "PATCH_SIZE_LIMIT_EXCEEDED"
    UNSUPPORTED_FILE_OPERATION = "UNSUPPORTED_FILE_OPERATION"
    TOUCHED_FILE_MISMATCH = "TOUCHED_FILE_MISMATCH"
    SUSPICIOUS_CODE_CHANGE = "SUSPICIOUS_CODE_CHANGE"
    UNRELATED_SOURCE_MODIFICATION = "UNRELATED_SOURCE_MODIFICATION"
    REQUIRED_TEST_UNKNOWN = "REQUIRED_TEST_UNKNOWN"
    APPLICATION_CONTRACT_VIOLATION = "APPLICATION_CONTRACT_VIOLATION"
    MODEL_PROVIDER_UNAVAILABLE = "MODEL_PROVIDER_UNAVAILABLE"
    GENERATION_BUDGET_EXCEEDED = "GENERATION_BUDGET_EXCEEDED"
    FIXTURE_FALLBACK_UNAVAILABLE = "FIXTURE_FALLBACK_UNAVAILABLE"
    CANDIDATE_HASH_MISMATCH = "CANDIDATE_HASH_MISMATCH"
    MANUAL_REVIEW_REQUIRED = "MANUAL_REVIEW_REQUIRED"
