"""Test Suite for LIME Explanation Fidelity and Sensitivity (Recommendation #6).

Verifies:
1. Local surrogate linear model fidelity (R^2 score) is positive and captured in ExplanationResult.
2. Local prediction probability closely tracks black-box RF probability.
3. Feature stability/sensitivity under input perturbations (Jaccard similarity >= 0.50).
4. Synthetic background retains mutually exclusive network constraints (TCP xor UDP, single conn_state).
"""

import numpy as np
import pandas as pd
import pytest
from sklearn.ensemble import RandomForestClassifier

from sentrix_ml.schema import (
    EXPECTED_FEATURES,
    NUM_FEATURES,
    PROTO_FEATURE_NAMES,
    CONN_STATE_FEATURE_NAMES,
)
from sentrix_ml.xai import create_lime_explainer, explain_with_lime, ExplanationResult


@pytest.fixture
def trained_rf_and_explainer():
    """Create a deterministic synthetic dataset, trained RF, and LIME explainer."""
    np.random.seed(42)
    n_samples = 300
    X_raw = np.random.uniform(0.0, 100.0, size=(n_samples, NUM_FEATURES))

    # Fix protocol and conn_state columns to be valid mutually exclusive one-hot
    for i in range(n_samples):
        # Proto
        is_tcp = int(np.random.rand() > 0.3)
        X_raw[i, EXPECTED_FEATURES.index("proto_tcp")] = is_tcp
        X_raw[i, EXPECTED_FEATURES.index("proto_udp")] = 1 - is_tcp
        # Conn state: set one random state to 1
        for cs in CONN_STATE_FEATURE_NAMES:
            X_raw[i, EXPECTED_FEATURES.index(cs)] = 0.0
        active_cs = np.random.choice(CONN_STATE_FEATURE_NAMES)
        X_raw[i, EXPECTED_FEATURES.index(active_cs)] = 1.0

    # Rule: high dst_bytes or high src_pkts indicates attack
    dst_b_idx = EXPECTED_FEATURES.index("dst_bytes")
    src_p_idx = EXPECTED_FEATURES.index("src_pkts")
    y = ((X_raw[:, dst_b_idx] > 50.0) | (X_raw[:, src_p_idx] > 60.0)).astype(int)

    rf = RandomForestClassifier(n_estimators=30, random_state=42)
    rf.fit(X_raw, y)

    df_bg = pd.DataFrame(X_raw, columns=EXPECTED_FEATURES)
    explainer = create_lime_explainer(df_bg, feature_names=list(EXPECTED_FEATURES))

    return rf, explainer, df_bg


def test_lime_fidelity_score_and_local_prediction(trained_rf_and_explainer):
    """Verify that LIME explanations return a positive fidelity score (R^2) and valid local prediction."""
    rf, explainer, df_bg = trained_rf_and_explainer

    # Test sample: distinct attack pattern
    test_sample = np.zeros(NUM_FEATURES)
    test_sample[EXPECTED_FEATURES.index("dst_bytes")] = 85.0
    test_sample[EXPECTED_FEATURES.index("src_pkts")] = 75.0
    test_sample[EXPECTED_FEATURES.index("proto_tcp")] = 1.0
    test_sample[EXPECTED_FEATURES.index("conn_state_SF")] = 1.0

    def predict_fn(arr):
        return rf.predict_proba(arr)

    res = explain_with_lime(explainer, test_sample, predict_fn, num_features=3)

    assert isinstance(res, ExplanationResult)
    assert res.method == "local_rf_lime"
    assert len(res.features) == 3

    # Fidelity score (R^2 of local surrogate regression)
    assert res.fidelity_score is not None
    assert res.fidelity_score > 0.0, f"Expected positive R^2 fidelity score, got {res.fidelity_score}"

    # Local prediction should be near black-box RF prediction
    p_rf_true = rf.predict_proba(test_sample.reshape(1, -1))[0, 1]
    assert res.local_prediction is not None
    assert abs(res.local_prediction - p_rf_true) < 0.40, (
        f"Local surrogate prediction {res.local_prediction} diverged excessively from RF {p_rf_true}"
    )


def test_lime_sensitivity_under_input_perturbations(trained_rf_and_explainer):
    """Verify explanation stability: top features maintain high Jaccard overlap under slight noise."""
    rf, explainer, df_bg = trained_rf_and_explainer

    base_sample = np.zeros(NUM_FEATURES)
    base_sample[EXPECTED_FEATURES.index("dst_bytes")] = 90.0
    base_sample[EXPECTED_FEATURES.index("src_pkts")] = 80.0
    base_sample[EXPECTED_FEATURES.index("duration")] = 12.0
    base_sample[EXPECTED_FEATURES.index("proto_tcp")] = 1.0
    base_sample[EXPECTED_FEATURES.index("conn_state_SF")] = 1.0

    def predict_fn(arr):
        return rf.predict_proba(arr)

    # Base explanation
    base_res = explain_with_lime(explainer, base_sample, predict_fn, num_features=3)
    base_top_feats = {item["f"].split("<")[0].split(">")[0].split("=")[0].strip() for item in base_res.features}

    # Perturbed explanation (+/- 3% continuous noise)
    np.random.seed(99)
    noise = np.random.normal(0, 0.03, size=NUM_FEATURES) * base_sample
    perturbed_sample = np.clip(base_sample + noise, 0.0, None)
    # Preserve categorical flags
    perturbed_sample[EXPECTED_FEATURES.index("proto_tcp")] = 1.0
    perturbed_sample[EXPECTED_FEATURES.index("conn_state_SF")] = 1.0

    perturbed_res = explain_with_lime(explainer, perturbed_sample, predict_fn, num_features=3)
    perturbed_top_feats = {item["f"].split("<")[0].split(">")[0].split("=")[0].strip() for item in perturbed_res.features}

    # Jaccard overlap of top-3 features
    intersection = len(base_top_feats & perturbed_top_feats)
    union = len(base_top_feats | perturbed_top_feats)
    jaccard = intersection / union if union > 0 else 0.0

    assert jaccard >= 0.50, f"Expected Jaccard stability >= 0.50 under small perturbation, got {jaccard}"


def test_synthetic_background_protocol_constraints():
    """Verify generated XAI background adheres to protocol and connection state mutual exclusivity."""
    from backend.main import generate_xai_background, engine, load_models_and_data

    # Ensure engine has active model
    load_models_and_data(target="omni", dataset="omni", is_startup=True)
    if engine.scaler is None or engine.rf_model is None:
        pytest.skip("Omni model/scaler unavailable for background test.")

    bg = generate_xai_background(n_samples=200)
    assert bg is not None
    assert len(bg) == 200

    # Constraint 1: Protocol mutual exclusivity (proto_tcp + proto_udp <= 1)
    proto_sum = bg["proto_tcp"] + bg["proto_udp"]
    assert (proto_sum <= 1.0).all(), "Found background rows violating protocol mutual exclusivity"

    # Constraint 2: Conn state mutual exclusivity (sum <= 1)
    conn_sum = bg[list(CONN_STATE_FEATURE_NAMES)].sum(axis=1)
    assert (conn_sum <= 1.0).all(), "Found background rows violating connection state exclusivity"
