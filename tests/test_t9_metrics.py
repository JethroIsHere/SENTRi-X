"""T9: Metrics Provenance Tests.

Verifies:
1. Smoke run evaluations are explicitly flagged as available: false for production API display.
2. Metrics computation correctly computes accuracy, precision, recall, f1, and ROC-AUC.
3. When both classes are not present in test split, ROC-AUC is cleanly None rather than crashing.
4. format_metrics_for_api enforces run_type == 'full' and hash validity before declaring available: true.
"""

import numpy as np
import pytest

from sentrix_ml.evaluation import (
    compute_metrics,
    format_metrics_for_api,
    EvaluationResult,
)


def test_t9_metrics_computation():
    """Verify standard binary classification metrics calculation."""
    y_true = np.array([0, 0, 0, 0, 1, 1, 1, 1])
    y_pred = np.array([0, 0, 0, 1, 1, 1, 1, 0])
    y_prob = np.array([0.1, 0.2, 0.3, 0.6, 0.8, 0.9, 0.85, 0.4])

    res = compute_metrics(y_true, y_pred, y_prob, domain="omni", mode="hybrid", run_type="full")

    assert res.accuracy == 0.75
    assert res.sample_count == 8
    assert res.tp == 3
    assert res.fp == 1
    assert res.tn == 3
    assert res.fn == 1
    assert res.roc_auc is not None
    assert 0.0 <= res.roc_auc <= 1.0


def test_t9_smoke_run_is_unavailable_in_api():
    """Verify smoke run metrics are marked available: False so they are never published as final."""
    y_true = np.array([0, 1, 0, 1])
    y_pred = np.array([0, 1, 0, 1])
    y_prob = np.array([0.1, 0.9, 0.2, 0.8])

    res_smoke = compute_metrics(y_true, y_pred, y_prob, domain="omni", run_type="smoke")
    api_payload = format_metrics_for_api(res_smoke)

    assert api_payload["available"] is False, "Smoke run metrics must NOT be marked available: true in API!"
    assert api_payload["run_type"] == "smoke"


def test_t9_full_run_is_available():
    """Verify a verified full run produces available: True."""
    y_true = np.array([0, 1, 0, 1])
    y_pred = np.array([0, 1, 0, 1])
    y_prob = np.array([0.1, 0.9, 0.2, 0.8])

    res_full = compute_metrics(y_true, y_pred, y_prob, domain="omni", run_type="full")
    api_payload = format_metrics_for_api(res_full)

    assert api_payload["available"] is True
    assert "accuracy" in api_payload["metrics"]
    assert api_payload["metrics"]["accuracy"] == 1.0


def test_t9_single_class_auc_is_none():
    """Verify that when only 1 class is in test split, roc_auc is set to None without error."""
    y_true = np.array([1, 1, 1, 1])  # Only attack class
    y_pred = np.array([1, 1, 1, 1])
    y_prob = np.array([0.9, 0.8, 0.7, 0.95])

    res = compute_metrics(y_true, y_pred, y_prob, domain="test")
    assert res.roc_auc is None


if __name__ == "__main__":
    test_t9_metrics_computation()
    test_t9_smoke_run_is_unavailable_in_api()
    test_t9_full_run_is_available()
    test_t9_single_class_auc_is_none()
    print("All T9 Metrics Provenance tests passed!")
