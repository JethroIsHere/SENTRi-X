"""T4: Transformation Coverage Tests.

Verifies:
1. Scaling occurs exactly once through PreprocessingPipeline.
2. Input column ordering does not alter the canonical feature vector contract.
3. Unfitted pipeline raises RuntimeError rather than returning silently unscaled data.
"""

import numpy as np
import pandas as pd
import pytest

from sentrix_ml.schema import EXPECTED_FEATURES, NUM_FEATURES
from sentrix_ml.preprocessing import PreprocessingPipeline, build_feature_row


def test_t4_input_order_invariance():
    """Verify dictionary or Series with scrambled key order always aligns to EXPECTED_FEATURES."""
    from sentrix_ml.schema import NUMERIC_FEATURE_NAMES
    reversed_num = list(reversed(NUMERIC_FEATURE_NAMES))
    sample = {k: float(i + 1) for i, k in enumerate(reversed_num)}
    sample["proto"] = "tcp"
    sample["conn_state"] = "SF"

    row = build_feature_row(sample)

    assert list(row.columns) == EXPECTED_FEATURES
    for k in NUMERIC_FEATURE_NAMES:
        expected_val = float(reversed_num.index(k) + 1)
        assert row.at[0, k] == expected_val
    assert row.at[0, "proto_tcp"] == 1.0
    assert row.at[0, "conn_state_SF"] == 1.0


def test_t4_single_scaling_policy():
    """Verify pipeline transforms data exactly once and standardizes on unit variance."""
    np.random.seed(42)
    # Generate data with known mean=100, std=15
    train_data = np.random.normal(loc=100.0, scale=15.0, size=(1000, NUM_FEATURES))
    pipeline = PreprocessingPipeline().fit(train_data)

    transformed = pipeline.transform(train_data)

    # Transformed data should have mean ~ 0 and std ~ 1
    means = np.mean(transformed, axis=0)
    stds = np.std(transformed, axis=0)

    np.testing.assert_allclose(means, 0.0, atol=1e-2)
    np.testing.assert_allclose(stds, 1.0, atol=1e-2)


def test_t4_unfitted_pipeline_raises():
    """Verify attempting to transform with an unfitted pipeline raises RuntimeError."""
    pipeline = PreprocessingPipeline(scaler=None, is_fitted=False)
    sample = np.zeros((1, NUM_FEATURES))

    # Should raise RuntimeError because it's not fitted
    # (unless identity policy)
    pipeline_non_identity = PreprocessingPipeline(is_fitted=False, policy="standard_scaler_on_train")
    with pytest.raises(RuntimeError):
        pipeline_non_identity.transform(sample)


def test_t4_shape_validation():
    """Verify transforming an array with wrong number of features raises ValueError."""
    pipeline = PreprocessingPipeline.identity()
    wrong_features = np.zeros((1, 15))  # 15 instead of 28

    with pytest.raises(ValueError, match="Expected 28 features"):
        pipeline.transform(wrong_features)


if __name__ == "__main__":
    test_t4_input_order_invariance()
    test_t4_single_scaling_policy()
    test_t4_unfitted_pipeline_raises()
    test_t4_shape_validation()
    print("All T4 Transformation tests passed!")
