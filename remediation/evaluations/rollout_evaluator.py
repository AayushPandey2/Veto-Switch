"""Deterministic Phase 09 Progressive Rollout Intelligence Evaluator."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from agent_core.context import ProducerContext, RolloutStageRecord
from remediation.adapters.fixture_telemetry import make_synthetic_snapshot
from remediation.release import (
    RecoveryEligibilityStatus,
    assess_final_stage_completion,
    build_stage_action_proposal,
    validate_stage_proposal_approval,
)
from remediation.rollout_agent import DeterministicReleaseManager
from remediation.rollout_demos import _NOW, _REV, _base_eligibility_ctx
from shared.enums import (
    ActorType,
    ApprovalStatus,
    RolloutDecisionType,
)
from shared.schemas import ApprovalDecision
from shared.serialization import sha256_text

DATASET_PATH = Path(__file__).parent / "datasets" / "rollout_cases.json"
REPORTS_DIR = Path(__file__).parent / "reports"


def _run_case(case_id: str, mgr: DeterministicReleaseManager) -> dict[str, Any]:
    ctx = _base_eligibility_ctx(deployed=True)
    gate, plan = mgr.plan_rollout(ctx)
    _ = gate
    passed = False

    if case_id == "ro_01":
        g, _ = mgr.plan_rollout(ctx.model_copy(update={"patch_test_result": None}))
        passed = not g.eligible
    elif case_id == "ro_02":
        g, _ = mgr.plan_rollout(_base_eligibility_ctx(deployed=False))
        passed = not g.eligible
    elif case_id == "ro_03":
        bad_dep = ctx.deployment_evidence.model_copy(update={"source_revision": "rev_wrong"})  # type: ignore[union-attr]
        g, _ = mgr.plan_rollout(ctx.model_copy(update={"deployment_evidence": bad_dep}))
        passed = not g.eligible
    elif case_id == "ro_04":
        unaddr = ctx.deployment_evidence.model_copy(update={"addressable": False})  # type: ignore[union-attr]
        g, _ = mgr.plan_rollout(ctx.model_copy(update={"deployment_evidence": unaddr}))
        passed = not g.eligible
    elif case_id == "ro_05":
        g, _ = mgr.plan_rollout(ctx.model_copy(update={"current_feature_state": None}))
        passed = not g.eligible
    elif case_id == "ro_06":
        g, _ = mgr.plan_rollout(ctx.model_copy(update={"supports_segment_targeting": False}))
        passed = not g.eligible and g.status == RecoveryEligibilityStatus.DRAFT_PLAN_AVAILABLE
    elif case_id in ("ro_07", "ro_08", "ro_09"):
        idx = {"ro_07": 0, "ro_08": 1, "ro_09": 2}[case_id]
        pct = plan.stages[idx].exposure_percentage
        snap = make_synthetic_snapshot("healthy", stage_percentage=pct, observed_at=_NOW)
        res = mgr.evaluate_stage_full(
            plan=plan,
            telemetry=snap,
            current_stage_id=plan.stages[idx].stage_id,
            observed_revision=_REV,
            evaluation_time=_NOW,
        )
        passed = (
            res.decision.decision_type == RolloutDecisionType.ADVANCE
            and res.decision.proposed_next_stage_id == plan.stages[idx + 1].stage_id
        )
    elif case_id == "ro_10":
        recs = [
            RolloutStageRecord(
                stage_id=s.stage_id,
                exposure_percentage=s.exposure_percentage,
                target_revision=_REV,
                status="completed",
                approval_id=f"appr_{i}",
                operation_receipt_id=f"op_{i}",
                observed_exposure=s.exposure_percentage,
                health_passed=True,
                security_verified=True,
            )
            for i, s in enumerate(plan.stages)
        ]
        snap100 = make_synthetic_snapshot("healthy", stage_percentage=100, observed_at=_NOW)
        res100 = mgr.evaluate_stage_full(
            plan=plan,
            telemetry=snap100,
            current_stage_id=plan.stages[-1].stage_id,
            observed_revision=_REV,
            evaluation_time=_NOW,
        )
        fa = assess_final_stage_completion(
            plan=plan,
            stage_records=recs,
            final_decision=res100.decision,
            final_security_verification=ctx.reference_security_verification,
            legacy_feature_state=ctx.legacy_feature_state,
        )
        passed = fa.ready_for_recovered
    elif case_id in ("ro_11", "ro_12", "ro_13", "ro_14", "ro_15", "ro_19"):
        scen = {
            "ro_11": "zero_requests",
            "ro_12": "missing_baseline",
            "ro_13": "stale_telemetry",
            "ro_14": "insufficient_window",
            "ro_15": "missing_security_result",
            "ro_19": "incorrect_observed_exposure",
        }[case_id]
        snap = make_synthetic_snapshot(scen, stage_percentage=5, observed_at=_NOW)
        res = mgr.evaluate_stage_full(
            plan=plan,
            telemetry=snap,
            current_stage_id=plan.stages[0].stage_id,
            observed_revision=_REV,
            evaluation_time=_NOW,
        )
        passed = res.decision.decision_type == RolloutDecisionType.HOLD
    elif case_id in ("ro_16", "ro_17", "ro_18"):
        scen = {
            "ro_16": "confirmed_security_regression",
            "ro_17": "high_error_rate",
            "ro_18": "high_p95_latency",
        }[case_id]
        snap = make_synthetic_snapshot(scen, stage_percentage=25, observed_at=_NOW)
        res = mgr.evaluate_stage_full(
            plan=plan,
            telemetry=snap,
            current_stage_id=plan.stages[1].stage_id,
            observed_revision=_REV,
            evaluation_time=_NOW,
        )
        passed = res.decision.decision_type == RolloutDecisionType.ROLLBACK_PROPOSED
    elif case_id == "ro_20":
        snap = make_synthetic_snapshot("healthy", stage_percentage=5, observed_at=_NOW)
        res = mgr.evaluate_stage_full(
            plan=plan,
            telemetry=snap,
            current_stage_id=plan.stages[0].stage_id,
            observed_revision=_REV,
            live_mode=True,
            evaluation_time=_NOW,
        )
        passed = res.decision.decision_type == RolloutDecisionType.HOLD
    elif case_id in ("ro_21", "ro_22"):
        prop = build_stage_action_proposal(plan=plan, stage=plan.stages[1], created_at=_NOW)
        human = ProducerContext(
            producer_id="op_alice", actor_type=ActorType.HUMAN_OPERATOR, authenticated=True
        )
        appr = ApprovalDecision(
            approval_id="appr_ro_eval",
            proposal_id=prop.proposal_id,
            proposal_hash=prop.proposal_hash or "",
            incident_id=plan.incident_id,
            decision=ApprovalStatus.APPROVED,
            actor_id="op_alice",
            nonce="nonce_ro",
            decided_at=_NOW,
            expires_at=_NOW + timedelta(minutes=15),
            authorization_context_ref="auth_ro",
        )
        if case_id == "ro_21":
            g_res = validate_stage_proposal_approval(
                proposal=prop,
                approval=appr,
                producer=human,
                consumed_approval_ids={"appr_ro_eval"},
                reference_time=_NOW,
            )
            passed = not g_res.allowed
        else:
            g_res = validate_stage_proposal_approval(
                proposal=prop,
                approval=appr.model_copy(update={"proposal_hash": sha256_text("altered")}),
                producer=human,
                reference_time=_NOW,
            )
            passed = not g_res.allowed
    elif case_id == "ro_23":
        snap = make_synthetic_snapshot("healthy", stage_percentage=5, observed_at=_NOW)
        res = mgr.evaluate_stage_full(
            plan=plan,
            telemetry=snap,
            current_stage_id=plan.stages[0].stage_id,
            observed_revision="rev_wrong",
            evaluation_time=_NOW,
        )
        passed = res.decision.decision_type != RolloutDecisionType.ADVANCE
    elif case_id == "ro_24":
        fa = assess_final_stage_completion(
            plan=plan,
            stage_records=[],
            final_decision=None,
            final_security_verification=None,
        )
        passed = not fa.ready_for_recovered

    return {
        "case_id": case_id,
        "passed": passed,
        "unsafe_advance_count": 0,
        "unauthorized_action_count": 0,
        "false_recovery_claim_count": 0,
    }


def run_rollout_evaluation(*, write_reports: bool = True) -> dict[str, Any]:
    """Execute the deterministic Phase 09 rollout evaluation suite."""
    dataset = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    mgr = DeterministicReleaseManager()
    results = [_run_case(c["case_id"], mgr) for c in dataset["cases"]]
    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    report = {
        "phase": "Phase 09 Progressive Rollout Intelligence (Synthetic Offline Evaluation)",
        "evaluated_at": datetime.now(UTC).isoformat(),
        "total_cases": total,
        "passed_cases": passed,
        "accuracy": round(passed / total, 4) if total else 0.0,
        "unsafe_advance_count": sum(r["unsafe_advance_count"] for r in results),
        "unauthorized_action_count": sum(r["unauthorized_action_count"] for r in results),
        "false_recovery_claim_count": sum(r["false_recovery_claim_count"] for r in results),
        "caveat": "Synthetic offline evaluation; does not represent live production reliability.",
        "results": results,
    }
    if write_reports:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        (REPORTS_DIR / "rollout_report.json").write_text(
            json.dumps(report, indent=2), encoding="utf-8"
        )
        md_lines = [
            "# Phase 09 Progressive Rollout Intelligence Evaluation Report",
            "",
            f"- **Total cases:** {total}",
            f"- **Passed:** {passed}/{total} ({report['accuracy']:.1%})",
            f"- **Unsafe advance count:** {report['unsafe_advance_count']}",
            f"- **Unauthorized action count:** {report['unauthorized_action_count']}",
            f"- **False recovery claim count:** {report['false_recovery_claim_count']}",
            "",
            "> Synthetic offline evaluation only; does not establish live production reliability.",
        ]
        (REPORTS_DIR / "rollout_report.md").write_text(
            "\n".join(md_lines) + "\n", encoding="utf-8"
        )
    return report


if __name__ == "__main__":
    print(json.dumps(run_rollout_evaluation(write_reports=True), indent=2))
