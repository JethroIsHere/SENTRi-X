"""T5: Hybrid Ensemble Regression Tests.

Verifies the critical fix for the broadcasting bug documented in Notebook 07 / Plan B6:
In the old code:
    rf_probs shape: (n, 2)
    cnn_probs shape: (n, 1)
    (rf_probs + cnn_probs) / 2 broadcasted cnn_probs to BOTH columns of rf_probs.
    argmax(hybrid_probs, axis=1) was identical to argmax(rf_probs), ignoring CNN!

Corrected behavior:
    p_rf = rf_probs[:, 1]  (attack probability)
    p_cnn = cnn_probs.reshape(-1)
    p_hybrid = (p_rf + p_cnn) / 2.0
    prediction = (p_hybrid >= 0.5).astype(int)

For RF = [0.8 (benign), 0.2 (attack)] and CNN = 0.9 (attack):
    p_hybrid = (0.2 + 0.9) / 2.0 = 0.55
    prediction = 1 (Attack)
Under the old bug, RF argmax was 0 (Benign) because 0.8 + 0.9 > 0.2 + 0.9!
"""

import numpy as np
import pytest

from sentrix_ml.schema import NUM_FEATURES
from sentrix_ml.inference import hybrid_predict, run_single_inference


class MockRF:
    """Mock Random Forest model returning prescribed probabilities."""

    def __init__(self, benign_prob: float, attack_prob: float):
        self.classes_ = np.array([0, 1])
        self.probs = np.array([[benign_prob, attack_prob]])

    def predict_proba(self, X):
        return np.repeat(self.probs, len(X), axis=0)


class MockCNN:
    """Mock CNN returning prescribed sigmoid attack probability."""

    def __init__(self, attack_prob: float):
        self.prob = np.array([[attack_prob]])

    def predict(self, X_3d, verbose=0):
        return np.repeat(self.prob, len(X_3d), axis=0)


def test_t5_hybrid_broadcast_regression():
    """Verify RF [0.8, 0.2] + CNN 0.9 yields p=0.55 and Attack (1), NOT Benign (0)."""
    rf = MockRF(benign_prob=0.8, attack_prob=0.2)
    cnn = MockCNN(attack_prob=0.9)

    X_dummy = np.zeros((1, NUM_FEATURES))

    # Old buggy calculation for comparison:
    old_rf_probs = np.array([[0.8, 0.2]])
    old_cnn_probs = np.array([[0.9]])
    old_hybrid = (old_rf_probs + old_cnn_probs) / 2.0  # [[0.85, 0.55]]
    old_prediction = int(np.argmax(old_hybrid, axis=1)[0])  # 0 (Benign!)

    assert old_prediction == 0, "Old code was expected to fail with Benign (0)"

    # New corrected hybrid implementation:
    preds, probs, p_rf, p_cnn = hybrid_predict(
        X_dummy, rf_model=rf, cnn_model=cnn, mode="hybrid"
    )

    assert p_rf[0] == pytest.approx(0.2, abs=1e-6)
    assert p_cnn[0] == pytest.approx(0.9, abs=1e-6)
    assert probs[0] == pytest.approx(0.55, abs=1e-6)
    assert preds[0] == 1, "Corrected hybrid prediction must be Attack (1)!"

    # Also test convenience wrapper run_single_inference
    res = run_single_inference(X_dummy[0], rf_model=rf, cnn_model=cnn, mode="hybrid")
    assert res.prediction == 1
    assert res.p_hybrid == pytest.approx(0.55, abs=1e-6)
    assert res.confidence == pytest.approx(0.55, abs=1e-6)
    assert res.p_rf == pytest.approx(0.2, abs=1e-6)
    assert res.p_cnn == pytest.approx(0.9, abs=1e-6)


def test_t5_rf_and_cnn_standalone_modes():
    """Verify 'rf' and 'cnn' execution modes only query their respective model."""
    rf = MockRF(benign_prob=0.8, attack_prob=0.2)
    cnn = MockCNN(attack_prob=0.9)
    X_dummy = np.zeros((1, NUM_FEATURES))

    # RF only mode
    res_rf = run_single_inference(X_dummy[0], rf_model=rf, cnn_model=None, mode="rf")
    assert res_rf.prediction == 0
    assert res_rf.p_hybrid == pytest.approx(0.2, abs=1e-6)
    assert res_rf.confidence == pytest.approx(0.8, abs=1e-6)  # 1 - 0.2

    # CNN only mode
    res_cnn = run_single_inference(X_dummy[0], rf_model=None, cnn_model=cnn, mode="cnn")
    assert res_cnn.prediction == 1
    assert res_cnn.p_hybrid == pytest.approx(0.9, abs=1e-6)
    assert res_cnn.confidence == pytest.approx(0.9, abs=1e-6)


def test_t5_invalid_probability_rejection():
    """Verify NaN or out-of-range probabilities raise RuntimeError."""
    class NanModel:
        def predict_proba(self, X):
            return np.array([[np.nan, np.nan]])

    rf = NanModel()
    cnn = MockCNN(0.5)
    X_dummy = np.zeros((1, NUM_FEATURES))

    with pytest.raises(RuntimeError, match="non-finite probability"):
        hybrid_predict(X_dummy, rf_model=rf, cnn_model=cnn, mode="hybrid")


if __name__ == "__main__":
    test_t5_hybrid_broadcast_regression()
    test_t5_rf_and_cnn_standalone_modes()
    test_t5_invalid_probability_rejection()
    print("All T5 Hybrid Regression tests passed!")
