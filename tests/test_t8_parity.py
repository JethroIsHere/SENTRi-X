"""T8: Prediction Parity Tests.

Verifies:
For the same loaded models and canonical input sample, offline inference and
backend inference produce identical predictions and probabilities across all
three execution modes: 'hybrid', 'rf', and 'cnn'.
"""

import numpy as np
import pytest
from sklearn.ensemble import RandomForestClassifier

from sentrix_ml.schema import NUM_FEATURES, EXPECTED_FEATURES
from sentrix_ml.preprocessing import PreprocessingPipeline, build_feature_row
from sentrix_ml.inference import run_single_inference, hybrid_predict


class ParityMockCNN:
    def __init__(self, weight_vector):
        self.weights = weight_vector  # (NUM_FEATURES,)

    def predict(self, X_3d, verbose=0):
        # Dot product with sigmoid
        scores = []
        for sample in X_3d:
            flat = sample.reshape(-1)
            logit = np.dot(flat, self.weights)
            sig = 1.0 / (1.0 + np.exp(-logit))
            scores.append([sig])
        return np.array(scores)


def test_t8_offline_backend_parity_all_modes():
    """Verify parity across hybrid, rf, and cnn modes."""
    np.random.seed(42)
    # Fit small RF on dummy data
    X_train = np.random.randn(50, NUM_FEATURES)
    y_train = np.random.choice([0, 1], size=50)
    rf = RandomForestClassifier(n_estimators=10, random_state=42)
    rf.fit(X_train, y_train)

    # Mock CNN
    cnn_weights = np.random.randn(NUM_FEATURES) * 0.1
    cnn = ParityMockCNN(cnn_weights)

    # Fit pipeline
    pipeline = PreprocessingPipeline().fit(X_train)

    # Test sample as dictionary (incoming live flow)
    packet_data = {
        "duration": 1.5,
        "src_bytes": 320,
        "dst_bytes": 800,
        "missed_bytes": 0,
        "src_pkts": 3,
        "src_ip_bytes": 450,
        "dst_pkts": 4,
        "dst_ip_bytes": 950,
        "dns_qclass": 0,
        "dns_qtype": 0,
        "dns_rcode": 0,
        "http_request_body_len": 0,
        "http_response_body_len": 0,
        "http_status_code": 0,
        "proto": "tcp",
        "conn_state": "SF",
    }

    # 1. Pipeline transform
    frame = build_feature_row(packet_data)
    scaled = pipeline.transform(frame)

    for mode in ["hybrid", "rf", "cnn"]:
        # Direct offline call via hybrid_predict
        preds_off, probs_off, p_rf_off, p_cnn_off = hybrid_predict(
            scaled, rf_model=rf, cnn_model=cnn, mode=mode
        )

        # Backend-style run_single_inference
        res_backend = run_single_inference(
            scaled, rf_model=rf, cnn_model=cnn, mode=mode
        )

        assert res_backend.prediction == preds_off[0], f"Prediction mismatch in {mode} mode!"
        assert res_backend.p_hybrid == pytest.approx(probs_off[0], abs=1e-12), f"Prob mismatch in {mode} mode!"

        if mode in ("rf", "hybrid"):
            assert res_backend.p_rf == pytest.approx(p_rf_off[0], abs=1e-12)
        if mode in ("cnn", "hybrid"):
            assert res_backend.p_cnn == pytest.approx(p_cnn_off[0], abs=1e-12)


if __name__ == "__main__":
    test_t8_offline_backend_parity_all_modes()
    print("All T8 Prediction Parity tests passed!")
