"""Execution receipt validation and reconciliation for rollback operations."""

from __future__ import annotations

from shared.enums import (
    EvidenceProvenance,
    OperationOutcome,
    RollbackActionType,
    RollbackReasonCode,
)
from shared.schemas import ApprovalDecision, OperationReceipt, RollbackProposal

from remediation.recovery.models import RollbackReceiptValidationResult


def validate_rollback_receipt(
    *,
    proposal: RollbackProposal,
    approval: ApprovalDecision | None,
    receipt: OperationReceipt | None,
    seen_operation_ids: set[str] | None = None,
    readback_completed: bool = False,
) -> RollbackReceiptValidationResult:
    """Validate an external OperationReceipt against a RollbackProposal and ApprovalDecision."""
    if receipt is None:
        return RollbackReceiptValidationResult(
            valid=False,
            status="execution_outcome_unknown",
            reason_codes=[RollbackReasonCode.EXECUTION_OUTCOME_UNKNOWN],
            message="Missing OperationReceipt for rollback operation.",
        )

    if receipt.provenance == EvidenceProvenance.LLM_INTERPRETATION:
        return RollbackReceiptValidationResult(
            valid=False,
            status="execution_failed",
            reason_codes=[RollbackReasonCode.EXECUTION_RECEIPT_MISMATCH],
            message="LLM output cannot act as a trusted OperationReceipt.",
        )

    if seen_operation_ids and receipt.operation_id in seen_operation_ids:
        return RollbackReceiptValidationResult(
            valid=True,
            status="execution_succeeded" if readback_completed else "readback_pending",
            duplicate=True,
            message=f"Duplicate OperationReceipt {receipt.operation_id!r} handled idempotently.",
        )

    if receipt.incident_id != proposal.incident_id:
        return RollbackReceiptValidationResult(
            valid=False,
            status="execution_failed",
            reason_codes=[RollbackReasonCode.EXECUTION_RECEIPT_MISMATCH],
            message="OperationReceipt incident_id does not match RollbackProposal.",
        )
    if receipt.proposal_id != proposal.proposal_id:
        return RollbackReceiptValidationResult(
            valid=False,
            status="execution_failed",
            reason_codes=[RollbackReasonCode.EXECUTION_RECEIPT_MISMATCH],
            message="OperationReceipt proposal_id does not match RollbackProposal.",
        )
    if approval is not None and receipt.approval_id != approval.approval_id:
        return RollbackReceiptValidationResult(
            valid=False,
            status="execution_failed",
            reason_codes=[RollbackReasonCode.EXECUTION_RECEIPT_MISMATCH],
            message="OperationReceipt approval_id does not match authorizing ApprovalDecision.",
        )
    if (
        receipt.environment != proposal.target_environment
        or receipt.target_feature != proposal.target_feature
    ):
        return RollbackReceiptValidationResult(
            valid=False,
            status="execution_failed",
            reason_codes=[RollbackReasonCode.EXECUTION_RECEIPT_MISMATCH],
            message="OperationReceipt environment or target_feature does not match proposal.",
        )

    if receipt.outcome in (OperationOutcome.TIMED_OUT, OperationOutcome.UNKNOWN):
        return RollbackReceiptValidationResult(
            valid=False,
            status="execution_outcome_unknown",
            reason_codes=[RollbackReasonCode.EXECUTION_OUTCOME_UNKNOWN],
            message=(
                f"Rollback execution outcome is {receipt.outcome.value!r}; "
                "reconcile state before retrying or concluding."
            ),
        )
    if receipt.outcome in (OperationOutcome.FAILED, OperationOutcome.REJECTED):
        return RollbackReceiptValidationResult(
            valid=False,
            status="execution_failed",
            reason_codes=[RollbackReasonCode.ROLLBACK_EXECUTION_FAILED],
            message=f"External rollback execution {receipt.outcome.value!r}.",
        )

    if (
        proposal.action_type == RollbackActionType.BOOLEAN_STATE
        and receipt.observed_state is not None
        and receipt.observed_state != proposal.proposed_state
    ):
        return RollbackReceiptValidationResult(
            valid=False,
            status="execution_failed",
            reason_codes=[RollbackReasonCode.EXECUTION_RECEIPT_MISMATCH],
            message="OperationReceipt observed_state does not match proposed Boolean state.",
        )

    return RollbackReceiptValidationResult(
        valid=True,
        status="execution_succeeded" if readback_completed else "readback_pending",
        message=(
            "Execution receipt validated; readback reconciliation required."
            if not readback_completed
            else "Execution receipt and readback validated."
        ),
    )
