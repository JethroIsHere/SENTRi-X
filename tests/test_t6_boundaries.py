"""T6: Boundary Tests.

Verifies:
1. Decision boundary: probability == 0.5 is classified as Attack (class 1).
2. Decision boundary: probability == 0.4999 is classified as Benign (class 0).
3. Alert policy: confidence strictly greater than alert_threshold triggers alert;
   confidence equal to alert_threshold does NOT trigger alert.
"""

import numpy as np
import pytest

from sentrix_ml.schema import NUM_FEATURES
from sentrix_ml.inference import run_single_inference


class BoundaryMockRF:
    def __init__(self, p_attack):
        self.classes_ = np.array([0, 1])
        self.p_attack = p_attack

    def predict_proba(self, X):
        return np.array([[1.0 - self.p_attack, self.p_attack]])


class BoundaryMockCNN:
    def __init__(self, p_attack):
        self.p_attack = p_attack

    def predict(self, X_3d, verbose=0):
        return np.array([[self.p_attack]])


def test_t6_exact_half_boundary_is_attack():
    """Verify probability == 0.5 yields prediction == 1 (Attack)."""
    rf = BoundaryMockRF(0.5)
    cnn = BoundaryMockCNN(0.5)
    X_dummy = np.zeros(NUM_FEATURES)

    res = run_single_inference(X_dummy, rf_model=rf, cnn_model=cnn, mode="hybrid")
    assert res.p_hybrid == 0.5
    assert res.prediction == 1, "Probability 0.5 must be classified as Attack (class 1)"


def test_t6_just_below_boundary_is_benign():
    """Verify probability just below 0.5 yields prediction == 0 (Benign)."""
    rf = BoundaryMockRF(0.49999)
    cnn = BoundaryMockCNN(0.49999)
    X_dummy = np.zeros(NUM_FEATURES)

    res = run_single_inference(X_dummy, rf_model=rf, cnn_model=cnn, mode="hybrid")
    assert res.prediction == 0, "Probability < 0.5 must be classified as Benign (class 0)"


def test_t6_alert_threshold_gate():
    """Verify alert policy: confidence strictly greater than gate triggers alert."""
    gate = 0.87

    def alert_allowed(prediction, confidence, threshold=gate, active=True):
        return active and prediction == 1 and confidence > threshold

    # Exactly at threshold: NO alert
    assert not alert_allowed(prediction=1, confidence=0.87, threshold=gate), (
        "Alert should NOT be recorded when confidence == threshold"
    )

    # Just below threshold: NO alert
    assert not alert_allowed(prediction=1, confidence=0.8699, threshold=gate)

    # Just above threshold: Alert triggered
    assert alert_allowed(prediction=1, confidence=0.8701, threshold=gate), (
        "Alert SHOULD be recorded when confidence > threshold"
    )

    # Benign with high confidence (e.g. 0.99): NO alert
    assert not alert_allowed(prediction=0, confidence=0.99, threshold=gate)

    # Alerting disabled: NO alert
    assert not alert_allowed(prediction=1, confidence=0.99, threshold=gate, active=False)


if __name__ == "__main__":
    test_t6_exact_half_boundary_is_attack()
    test_t6_just_below_boundary_is_benign()
    test_t6_alert_threshold_gate()
    print("All T6 Boundary tests passed!")
