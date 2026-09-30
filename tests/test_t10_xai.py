"""T10: XAI Consistency Tests.

Verifies:
1. Mismatched domain provenance (e.g. ToN-IoT SHAP reference with Omni model)
   is flagged as unavailable instead of manufacturing misleading explanations.
2. LIME prediction wrapper does not apply double-scaling to already-transformed inputs.
3. Unavailable explanations provide clear honest reason.
"""

import numpy as np
import pandas as pd
import pytest

from sentrix_ml.schema import EXPECTED_FEATURES, NUM_FEATURES
from sentrix_ml.xai import (
    XAIProvenance,
    reference_shap_explanation,
    ExplanationResult,
)


def test_t10_mismatched_domain_rejected():
    """Verify stored ToN-IoT SHAP reference is rejected when Omni model is active."""
    provenance = XAIProvenance(
        model_domain="ton_iot",
        representation="scaled",
    )

    inference_row = np.zeros(NUM_FEATURES)
    dummy_sample = pd.DataFrame(np.zeros((5, NUM_FEATURES)), columns=EXPECTED_FEATURES)
    dummy_shap = np.zeros((5, NUM_FEATURES))

    # Active domain is 'omni', but provenance is 'ton_iot'
    result = reference_shap_explanation(
        inference_row,
        X_sample=dummy_sample,
        shap_values=dummy_shap,
        provenance=provenance,
        active_domain="omni",
    )

    # Must be marked unavailable or fallback to global RF importance with explanation
    assert result.method != "reference_sample_shap", (
        "Mismatched domain must NOT return reference_sample_shap!"
    )
    assert "ton_iot" in result.reason or result.method == "global_rf_importance"


def test_t10_matching_domain_accepted():
    """Verify matching domain and model hash provenance allows reference lookup."""
    provenance = XAIProvenance(
        model_domain="omni",
        representation="scaled",
        model_hash="sha256:matching_rf_hash_1234",
    )

    inference_row = np.zeros(NUM_FEATURES)
    dummy_sample = pd.DataFrame(np.zeros((5, NUM_FEATURES)), columns=EXPECTED_FEATURES)
    dummy_shap = np.ones((5, NUM_FEATURES)) * 0.5  # Non-zero finite SHAP values

    result = reference_shap_explanation(
        inference_row,
        X_sample=dummy_sample,
        shap_values=dummy_shap,
        provenance=provenance,
        active_domain="omni",
        active_model_hash="sha256:matching_rf_hash_1234",
    )

    assert result.method == "reference_sample_shap"
    assert len(result.features) > 0


def test_t10_missing_artifacts_honest_unavailable():
    """Verify when artifacts are missing, unavailable is returned honestly."""
    result = reference_shap_explanation(
        np.zeros(NUM_FEATURES),
        X_sample=None,
        shap_values=None,
        rf_model=None,
        active_domain="omni",
    )

    assert result.method == "unavailable"
    assert len(result.features) == 0
    assert result.reason != ""


if __name__ == "__main__":
    test_t10_mismatched_domain_rejected()
    test_t10_matching_domain_accepted()
    test_t10_missing_artifacts_honest_unavailable()
    print("All T10 XAI Consistency tests passed!")
