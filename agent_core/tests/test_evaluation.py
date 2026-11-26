"""Category M tests: evaluation dataset, metrics, skipped cases & reproducible reports."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from agent_core.evaluations.evaluator import (
    DEFAULT_DATASET_PATH,
    load_evaluation_dataset,
    run_evaluation_suite,
)
from agent_core.evaluations.metrics import check_fallback_correctness
from agent_core.evaluations.regression import render_markdown_report, run_and_write_reports
from shared.enums import EvidenceProvenance, FindingStatus


@pytest.mark.unit
def test_evaluation_dataset_loads_all_categories() -> None:
    ds = load_evaluation_dataset(DEFAULT_DATASET_PATH)
    assert ds["synthetic_dataset"] is True
    assert len(ds["cases"]) == 24
    categories = {c["category"] for c in ds["cases"]}
    assert len(categories) == 12


@pytest.mark.unit
async def test_offline_evaluation_suite_and_subset_skipping(tmp_path: Path) -> None:
    full_report = await run_evaluation_suite(evaluation_mode="offline_fixture")
    assert full_report.evaluation_mode == "offline_fixture"
    assert full_report.metrics.completed_cases == 24
    assert full_report.metrics.failed_cases == 0
    assert full_report.metrics.tool_policy_executed_violations == 0
    assert any("OFFLINE FIXTURE EVALUATION ONLY" in lim for lim in full_report.known_limitations)

    # Skipped case handling & live-without-gateway safety check
    subset = await run_evaluation_suite(
        evaluation_mode="offline_fixture", case_ids={"eval_sqli_repro_01"}
    )
    assert subset.metrics.completed_cases == 1
    assert subset.metrics.skipped_cases == 23

    live_unconfigured = await run_evaluation_suite(
        evaluation_mode="live_provider", gateway=None
    )
    assert live_unconfigured.evaluation_mode == "live_provider"
    assert live_unconfigured.metrics.skipped_cases == 24
    assert live_unconfigured.metrics.completed_cases == 0

    report, json_p, md_p = await run_and_write_reports(output_dir=tmp_path, live=False)
    assert json_p.exists() and md_p.exists()
    loaded_json = json.loads(json_p.read_text(encoding="utf-8"))
    assert loaded_json["evaluation_mode"] == "offline_fixture"
    assert "Offline" in render_markdown_report(report) or "offline_fixture" in md_p.read_text(
        encoding="utf-8"
    )


@pytest.mark.unit
def test_check_fallback_correctness_catches_mislabeled_or_status_flip() -> None:
    assert (
        check_fallback_correctness(
            fallback_used=True,
            expected_status=FindingStatus.SUSPECTED,
            actual_status=FindingStatus.REPRODUCED,
            reasoning_source=EvidenceProvenance.DETERMINISTIC_FALLBACK,
            unknown_refs_count=0,
            uncertainties=["missing"],
            missing_evidence=[],
        )
        is False
    )
    assert (
        check_fallback_correctness(
            fallback_used=True,
            expected_status=FindingStatus.SUSPECTED,
            actual_status=FindingStatus.SUSPECTED,
            reasoning_source=EvidenceProvenance.LLM_INTERPRETATION,
            unknown_refs_count=0,
            uncertainties=["missing"],
            missing_evidence=[],
        )
        is False
    )
