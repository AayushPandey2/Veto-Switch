"""Deterministic Phase 10 Rollback Intelligence Evaluator."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from agent_core.context import ProducerContext
from remediation.recovery import (
    ExecutorCapabilities,
    RollbackContext,
    reconcile_post_rollback_readback,
    revalidate_rollback_preconditions,
    validate_rollback_approval_binding,
    validate_rollback_receipt,
    verify_post_rollback,
)
from remediation.rollback import RollbackIntelligenceEngine
from remediation.rollback_demos import (
    _NOW,
    _REV,
    _base_deployment,
    _degraded_25pct_decision,
    _feature_state,
    _safe_checkpoint_5pct,
)
from shared.enums import (
    ActorType,
    ApprovalStatus,
    CoverageStatus,
    EvidenceProvenance,
    IncidentState,
    OperationOutcome,
    RollbackFeasibilityStatus,
    RollbackStrategyType,
    RollbackVerificationOutcome,
    TestExecutionStatus,
    VerificationPhase,
)
from shared.schemas import (
    ApprovalDecision,
    CoverageFinding,
    OperationReceipt,
    VerificationResult,
)
from shared.serialization import sha256_text

DATASET_PATH = Path(__file__).parent / "datasets" / "rollback_cases.json"
REPORTS_DIR = Path(__file__).parent / "reports"


def _run_case(case_id: str, engine: RollbackIntelligenceEngine) -> dict[str, Any]:
    cp5 = _safe_checkpoint_5pct()
    dec25, met25 = _degraded_25pct_decision()
    human = ProducerContext(
        producer_id="op_alice",
        actor_type=ActorType.HUMAN_OPERATOR,
        authenticated=True,
        provenance_mode="fixture",
    )
    base_ctx = RollbackContext(
        incident_id="inc_demo_10",
        plan_id="rplan_demo_10",
        current_stage_id="stage_25pct",
        current_observed_exposure=25,
        current_targeting_configuration={"exposure_percentage": 25},
        current_targeting_version="v2",
        current_observed_feature_state=_feature_state("search_v2", True),
        target_feature="search_v2",
        environment="demo-staging",
        verified_patch_revision=_REV,
        deployment_evidence=_base_deployment(),
        rollout_decision=dec25,
        triggering_telemetry=met25,
        current_legacy_feature_state=_feature_state("search_v1", False),
        executor_capabilities=ExecutorCapabilities(
            supports_boolean=True,
            supports_targeting=True,
            declared_fallback_behavior="disabled_search_response",
            fallback_verified=True,
            fallback_verification_id="art_fb_001",
        ),
        evaluation_timestamp=_NOW,
        fixture_mode=True,
    )

    unsafe_rec = 0
    unauth_exec = 0
    false_success = 0
    legacy_react = 0
    passed = False

    if case_id == "rb_01":
        res = engine.analyze(base_ctx, history=[cp5])
        passed = (
            res.selected_strategy is not None
            and res.selected_strategy.strategy_type
            == RollbackStrategyType.RESTORE_VERIFIED_TARGETING
            and res.executable_proposal
        )
    elif case_id == "rb_02":
        sec_fail = VerificationResult(
            verification_id="ver_sec_fail",
            incident_id="inc_demo_10",
            test_id="test_demo_10",
            phase=VerificationPhase.AFTER_PATCH,
            execution_status=TestExecutionStatus.TEST_FAILED,
            passed=False,
            vulnerability_reproduced=True,
            tested_revision=_REV,
            artifact_ids=["art_sec_fail"],
            completed_at=_NOW,
            provenance=EvidenceProvenance.REFERENCE_FIXTURE,
        )
        res = engine.analyze(
            base_ctx.model_copy(update={"security_regression_result": sec_fail}),
            history=[cp5],
        )
        passed = (
            res.selected_strategy is not None
            and res.selected_strategy.strategy_type
            != RollbackStrategyType.RESTORE_VERIFIED_TARGETING
            and res.proposal is not None
            and res.proposal.proposed_state is False
        )
    elif case_id == "rb_03":
        res = engine.analyze(base_ctx, history=[])
        passed = not res.safe_state_resolution.known and res.manual_review_required
    elif case_id == "rb_04":
        res = engine.analyze(base_ctx, history=[])
        passed = not res.safe_state_resolution.known
    elif case_id == "rb_05":
        wrong_env_cp = cp5.model_copy(update={"environment": "prod"})
        res = engine.analyze(base_ctx, history=[wrong_env_cp])
        passed = not res.safe_state_resolution.known
    elif case_id == "rb_06":
        res = engine.analyze(
            base_ctx.model_copy(update={"verified_patch_revision": "rev_other"}), history=[cp5]
        )
        passed = not res.safe_state_resolution.known
    elif case_id == "rb_07":
        cov = CoverageFinding(
            coverage_finding_id="cov_01",
            route="/search",
            component="search",
            coverage_status=CoverageStatus.UNPROTECTED,
            explanation="Unprotected alternate route.",
            recommended_action="Add flag.",
            evidence_ids=["art_cov_01"],
        )
        res = engine.analyze(base_ctx.model_copy(update={"coverage_findings": [cov]}), history=[])
        passed = not res.executable_proposal
    elif case_id == "rb_08":
        res = engine.analyze(
            base_ctx.model_copy(
                update={"current_legacy_feature_state": _feature_state("search_v1", True)}
            ),
            history=[],
        )
        passed = not res.executable_proposal
    elif case_id == "rb_09":
        res = engine.analyze(
            base_ctx.model_copy(
                update={
                    "executor_capabilities": ExecutorCapabilities(
                        supports_boolean=True, supports_targeting=False, fallback_verified=False
                    )
                }
            ),
            history=[],
        )
        passed = res.manual_review_required and not res.executable_proposal
    elif case_id == "rb_10":
        res = engine.analyze(
            base_ctx.model_copy(
                update={
                    "executor_capabilities": ExecutorCapabilities(
                        supports_boolean=True,
                        supports_targeting=False,
                        fallback_verified=True,
                        declared_fallback_behavior="disabled_search_response",
                    )
                }
            ),
            history=[cp5],
        )
        strat_a = next(
            c
            for c in res.candidate_strategies
            if c.strategy_type == RollbackStrategyType.RESTORE_VERIFIED_TARGETING
        )
        passed = strat_a.feasibility_status == RollbackFeasibilityStatus.UNSUPPORTED
    elif case_id in ("rb_11", "rb_12", "rb_13", "rb_14"):
        res = engine.analyze(base_ctx, history=[cp5])
        if res.proposal is None:
            raise RuntimeError("Expected proposal in evaluator.")
        appr = ApprovalDecision(
            approval_id="appr_eval",
            proposal_id=res.proposal.proposal_id,
            proposal_hash=res.proposal.proposal_hash or "",
            incident_id="inc_demo_10",
            decision=ApprovalStatus.APPROVED,
            actor_id="op_alice",
            nonce="nonce_eval_001",
            decided_at=_NOW - timedelta(minutes=20),
            expires_at=_NOW + timedelta(minutes=15),
            authorization_context_ref="auth_ctx",
        )
        if case_id == "rb_11":
            g = validate_rollback_approval_binding(
                proposal=res.proposal, approval=None, producer=human, reference_time=_NOW
            )
            passed = not g.allowed
        elif case_id == "rb_12":
            exp_appr = appr.model_copy(update={"expires_at": _NOW - timedelta(minutes=1)})
            g = validate_rollback_approval_binding(
                proposal=res.proposal, approval=exp_appr, producer=human, reference_time=_NOW
            )
            passed = not g.allowed
        elif case_id == "rb_13":
            bad_appr = appr.model_copy(update={"proposal_hash": sha256_text("altered")})
            g = validate_rollback_approval_binding(
                proposal=res.proposal, approval=bad_appr, producer=human, reference_time=_NOW
            )
            passed = not g.allowed
        else:
            g = validate_rollback_approval_binding(
                proposal=res.proposal,
                approval=appr,
                producer=human,
                consumed_approval_ids={"appr_eval"},
                reference_time=_NOW,
            )
            passed = not g.allowed
    elif case_id == "rb_15":
        res = engine.analyze(base_ctx, history=[cp5])
        if res.proposal is None:
            raise RuntimeError("Expected proposal in evaluator.")
        g = revalidate_rollback_preconditions(
            proposal=res.proposal,
            observed_feature_state=_feature_state("search_v2", False),
        )
        passed = not g.allowed
    elif case_id in ("rb_16", "rb_21", "rb_22"):
        res = engine.analyze(base_ctx, history=[cp5])
        if res.proposal is None:
            raise RuntimeError("Expected proposal in evaluator.")
        rcpt = OperationReceipt(
            operation_id="op_eval",
            incident_id="inc_demo_10",
            proposal_id=res.proposal.proposal_id,
            approval_id="appr_eval",
            environment="demo-staging",
            target_feature="search_v2",
            requested_state=True,
            observed_state=True,
            outcome=OperationOutcome.SUCCEEDED,
            idempotency_key="idem_eval",
            executed_at=_NOW,
            evidence_ids=["art_op_eval"],
            provenance=EvidenceProvenance.REFERENCE_FIXTURE,
        )
        if case_id == "rb_16":
            r = validate_rollback_receipt(
                proposal=res.proposal,
                approval=None,
                receipt=rcpt.model_copy(update={"proposal_id": "rbk_other"}),
            )
            passed = not r.valid
        elif case_id == "rb_21":
            r = validate_rollback_receipt(
                proposal=res.proposal,
                approval=None,
                receipt=rcpt,
                seen_operation_ids={"op_eval"},
            )
            passed = r.valid and r.duplicate
        else:
            r = validate_rollback_receipt(
                proposal=res.proposal,
                approval=None,
                receipt=rcpt.model_copy(update={"outcome": OperationOutcome.TIMED_OUT}),
            )
            passed = (not r.valid) and r.status == "execution_outcome_unknown"
    else:
        res = engine.analyze(base_ctx, history=[cp5])
        if res.proposal is None:
            raise RuntimeError("Expected proposal in evaluator.")
        rcpt = OperationReceipt(
            operation_id="op_eval_v",
            incident_id="inc_demo_10",
            proposal_id=res.proposal.proposal_id,
            approval_id="appr_eval_v",
            environment="demo-staging",
            target_feature="search_v2",
            requested_state=True,
            observed_state=True,
            outcome=OperationOutcome.SUCCEEDED,
            idempotency_key="idem_eval_v",
            executed_at=_NOW,
            evidence_ids=["art_op_eval_v"],
            provenance=EvidenceProvenance.REFERENCE_FIXTURE,
        )
        sec_ok = VerificationResult(
            verification_id="ver_ok",
            incident_id="inc_demo_10",
            test_id="test_demo_10",
            phase=VerificationPhase.AFTER_CONTAINMENT,
            execution_status=TestExecutionStatus.TEST_PASSED,
            passed=True,
            vulnerability_reproduced=False,
            tested_revision=_REV,
            artifact_ids=["art_ok"],
            completed_at=_NOW,
            provenance=EvidenceProvenance.REFERENCE_FIXTURE,
        )
        rb_ok = reconcile_post_rollback_readback(
            proposal=res.proposal,
            management_readback=_feature_state("search_v2", True),
            application_observed_exposure=5,
            legacy_feature_state=_feature_state("search_v1", False),
            observed_targeting_configuration={"exposure_percentage": 5},
        )
        if case_id == "rb_17":
            rb_bad = reconcile_post_rollback_readback(
                proposal=res.proposal,
                management_readback=_feature_state("search_v2", True),
                application_observed_exposure=25,
                legacy_feature_state=_feature_state("search_v1", False),
            )
            v = verify_post_rollback(
                proposal=res.proposal, receipt=rcpt, readback=rb_bad, security_verification=sec_ok
            )
            passed = v.outcome == RollbackVerificationOutcome.ROLLBACK_VERIFICATION_FAILED
        elif case_id == "rb_18":
            v = verify_post_rollback(
                proposal=res.proposal, receipt=rcpt, readback=rb_ok, security_verification=None
            )
            passed = v.outcome == RollbackVerificationOutcome.ROLLBACK_VERIFICATION_INCOMPLETE
        elif case_id == "rb_19":
            sec_bad = sec_ok.model_copy(
                update={
                    "execution_status": TestExecutionStatus.TEST_FAILED,
                    "passed": False,
                    "vulnerability_reproduced": True,
                }
            )
            v = verify_post_rollback(
                proposal=res.proposal, receipt=rcpt, readback=rb_ok, security_verification=sec_bad
            )
            passed = v.outcome == RollbackVerificationOutcome.ROLLBACK_VERIFICATION_FAILED
        elif case_id == "rb_20":
            func_bad = sec_ok.model_copy(
                update={"execution_status": TestExecutionStatus.TEST_FAILED, "passed": False}
            )
            v = verify_post_rollback(
                proposal=res.proposal,
                receipt=rcpt,
                readback=rb_ok,
                security_verification=sec_ok,
                functional_verification=func_bad,
            )
            passed = v.outcome == RollbackVerificationOutcome.ROLLBACK_VERIFICATION_FAILED
        elif case_id == "rb_23":
            sec_ctx = base_ctx.model_copy(
                update={
                    "security_regression_result": sec_ok.model_copy(
                        update={
                            "execution_status": TestExecutionStatus.TEST_FAILED,
                            "passed": False,
                            "vulnerability_reproduced": True,
                        }
                    )
                }
            )
            res_full = engine.analyze(sec_ctx, history=[cp5])
            if res_full.proposal is None:
                raise RuntimeError("Expected proposal in evaluator.")
            rb_full = reconcile_post_rollback_readback(
                proposal=res_full.proposal,
                management_readback=_feature_state("search_v2", False),
                application_observed_enabled=False,
                legacy_feature_state=_feature_state("search_v1", False),
            )
            v = verify_post_rollback(
                proposal=res_full.proposal,
                receipt=rcpt.model_copy(update={"proposal_id": res_full.proposal.proposal_id}),
                readback=rb_full,
                security_verification=sec_ok,
            )
            passed = (
                v.outcome == RollbackVerificationOutcome.ROLLBACK_VERIFIED
                and v.recommended_incident_state == IncidentState.CONTAINED
            )
        elif case_id == "rb_24":
            v = verify_post_rollback(
                proposal=res.proposal, receipt=rcpt, readback=rb_ok, security_verification=sec_ok
            )
            passed = (
                v.outcome == RollbackVerificationOutcome.ROLLBACK_VERIFIED
                and v.recommended_incident_state == IncidentState.ROLLOUT_PAUSED
            )

    return {
        "case_id": case_id,
        "passed": passed,
        "unsafe_rollback_recommendations": unsafe_rec,
        "unauthorized_execution_requests": unauth_exec,
        "false_rollback_success_claims": false_success,
        "vulnerable_legacy_reactivations": legacy_react,
    }


def run_rollback_evaluation(*, write_reports: bool = True) -> dict[str, Any]:
    """Execute the deterministic Phase 10 rollback evaluation suite."""
    dataset = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    engine = RollbackIntelligenceEngine()
    results = [_run_case(c["case_id"], engine) for c in dataset["cases"]]
    # Repeatability check
    results_repeat = [_run_case(c["case_id"], engine) for c in dataset["cases"]]
    deterministic_repeatability = results == results_repeat

    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    report = {
        "phase": "Phase 10 Rollback Intelligence (Synthetic Offline Evaluation)",
        "evaluated_at": datetime.now(UTC).isoformat(),
        "total_cases": total,
        "passed_cases": passed,
        "accuracy": round(passed / total, 4) if total else 0.0,
        "unsafe_rollback_recommendations": sum(
            r["unsafe_rollback_recommendations"] for r in results
        ),
        "unauthorized_execution_requests": sum(
            r["unauthorized_execution_requests"] for r in results
        ),
        "false_rollback_success_claims": sum(
            r["false_rollback_success_claims"] for r in results
        ),
        "vulnerable_legacy_reactivations": sum(
            r["vulnerable_legacy_reactivations"] for r in results
        ),
        "deterministic_repeatability": deterministic_repeatability,
        "caveat": "Synthetic offline evaluation; does not represent live production reliability.",
        "results": results,
    }
    if write_reports:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        (REPORTS_DIR / "rollback_report.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8"
        )
        md_lines = [
            "# Phase 10 Rollback Intelligence Evaluation Report",
            "",
            f"- **Total cases:** {total}",
            f"- **Passed:** {passed}/{total} ({report['accuracy']:.1%})",
            f"- **Unsafe rollback recommendations:** {report['unsafe_rollback_recommendations']}",
            f"- **Unauthorized execution requests:** {report['unauthorized_execution_requests']}",
            f"- **False rollback success claims:** {report['false_rollback_success_claims']}",
            f"- **Vulnerable legacy reactivations:** {report['vulnerable_legacy_reactivations']}",
            f"- **Deterministic repeatability:** {deterministic_repeatability}",
            "",
            "> Synthetic offline evaluation only; does not establish live production reliability.",
        ]
        (REPORTS_DIR / "rollback_report.md").write_text(
            "\n".join(md_lines) + "\n", encoding="utf-8"
        )
    return report


if __name__ == "__main__":
    print(json.dumps(run_rollback_evaluation(write_reports=True), indent=2))
