"""Deterministic, nested offline cohort targeting for progressive rollout demos."""

from __future__ import annotations

import hashlib

from remediation.release.models import CohortAssignment


def compute_cohort_bucket(cohort_namespace: str, identity: str) -> int:
    """Compute a deterministic bucket in [0, 9999] using SHA-256 (never Python hash())."""
    payload = f"{cohort_namespace}:{identity}".encode()
    digest = hashlib.sha256(payload).digest()
    return int.from_bytes(digest[:8], "big") % 10_000


def assign_cohort(
    *,
    cohort_namespace: str,
    identity: str | None,
    exposure_percentage: int,
) -> CohortAssignment:
    """Assign an identity deterministically to a nested exposure cohort."""
    if not (0 <= exposure_percentage <= 100):
        raise ValueError(f"exposure_percentage must be in [0, 100], got {exposure_percentage}.")
    if identity is None or not identity.strip():
        return CohortAssignment(
            cohort_namespace=cohort_namespace,
            identity=identity,
            bucket=None,
            exposure_percentage=exposure_percentage,
            included=False,
            reason="Missing identity excluded from cohort targeting.",
        )
    cleaned = identity.strip()
    bucket = compute_cohort_bucket(cohort_namespace, cleaned)
    if exposure_percentage == 0:
        included = False
    elif exposure_percentage == 100:
        included = True
    else:
        included = bucket < (exposure_percentage * 100)
    return CohortAssignment(
        cohort_namespace=cohort_namespace,
        identity=cleaned,
        bucket=bucket,
        exposure_percentage=exposure_percentage,
        included=included,
        reason=(
            f"Bucket {bucket} {'<' if included else '>='} "
            f"threshold {exposure_percentage * 100}."
        ),
    )
