"""AI evaluation dataset, deterministic metrics, and reproducible regression suite."""

from agent_core.evaluations.evaluator import (
    DEFAULT_DATASET_PATH,
    EvaluationRunReport,
    load_evaluation_dataset,
    run_evaluation_suite,
)
from agent_core.evaluations.metrics import (
    HUMAN_EVALUATION_RUBRIC,
    CaseEvaluationResult,
    EvaluationMetricsSummary,
    aggregate_evaluation_metrics,
    check_fallback_correctness,
)

__all__ = [
    "DEFAULT_DATASET_PATH",
    "HUMAN_EVALUATION_RUBRIC",
    "CaseEvaluationResult",
    "EvaluationMetricsSummary",
    "EvaluationRunReport",
    "aggregate_evaluation_metrics",
    "check_fallback_correctness",
    "load_evaluation_dataset",
    "run_evaluation_suite",
]
