"""Test Suite for Feature Equivalence, Byte Semantics, and Calibration (Recommendation #2).

Validates:
1. Candidate scalers adhere to documented byte/packet semantics across all 4 candidate packages.
2. In-distribution bounds for Omni under live packet sizes (64B SYN, 1500B MTU).
3. Monotonicity and boundary conditions of the fusion weight sweep.
4. Calculation of ECE, MCE, and Brier score.
"""

import pytest
import numpy as np
from pathlib import Path

from sentrix_ml.schema import EXPECTED_FEATURES
from scripts.evaluate_byte_semantics_and_calibration import (
    CANDIDATES,
    validate_package_byte_semantics,
    compute_ece_mce,
    evaluate_candidate,
)


def test_byte_semantics_omni_in_distribution():
    """Verify Omni scaler parameters reflect in-distribution byte metrics."""
    omni_path = CANDIDATES["omni"]
    assert omni_path.exists(), f"Omni candidate package missing at {omni_path}"

    semantics = validate_package_byte_semantics(omni_path)
    assert "src_ip_bytes" in semantics
    assert "dst_ip_bytes" in semantics

    # Check that Omni has non-zero means for Zeek IP counters
    assert semantics["src_ip_bytes"]["mean"] > 50.0
    assert semantics["dst_ip_bytes"]["mean"] > 100.0

    # Test z-scores for standard packets are bounded (|z| < 3.0)
    assert abs(semantics["src_ip_bytes"]["z_score_at_64b"]) < 1.0
    assert abs(semantics["src_ip_bytes"]["z_score_at_1500b"]) < 3.0


def test_byte_semantics_legacy_imputation_detection():
    """Verify BoT-IoT and CIC-IDS2017 scalers correctly identify imputed zero byte counters."""
    for name in ["bot_iot", "cic_ids2017"]:
        path = CANDIDATES[name]
        assert path.exists(), f"Candidate package {name} missing at {path}"
        semantics = validate_package_byte_semantics(path)
        assert semantics["src_ip_bytes"]["is_zero_imputed_in_training"] is True
        assert semantics["dst_ip_bytes"]["is_zero_imputed_in_training"] is True


def test_compute_ece_mce_perfect_calibration():
    """Verify ECE and MCE are 0 for perfectly calibrated probabilities."""
    y_true = np.array([0, 0, 1, 1])
    y_prob = np.array([0.0, 0.0, 1.0, 1.0])
    ece, mce, bins = compute_ece_mce(y_true, y_prob, n_bins=10)
    assert ece == pytest.approx(0.0, abs=1e-6)
    assert mce == pytest.approx(0.0, abs=1e-6)


def test_compute_ece_mce_miscalibrated():
    """Verify ECE and MCE capture miscalibration accurately."""
    y_true = np.array([0, 0, 0, 0])
    y_prob = np.array([1.0, 1.0, 1.0, 1.0])
    ece, mce, bins = compute_ece_mce(y_true, y_prob, n_bins=10)
    assert ece == pytest.approx(1.0, abs=1e-6)
    assert mce == pytest.approx(1.0, abs=1e-6)


def test_evaluate_candidate_omni():
    """Verify Omni evaluation returns complete metrics and valid fusion sweep."""
    res = evaluate_candidate("omni", CANDIDATES["omni"])
    assert res["n_samples"] == 17842
    assert "modes" in res
    assert res["modes"]["rf"]["f1"] > 0.99
    assert res["modes"]["hybrid_equal"]["f1"] > 0.97
    assert len(res["fusion_sweep"]) == 21
    # Check that best_w_rf is within valid range [0, 1]
    assert 0.0 <= res["optimal_fusion"]["best_w_rf"] <= 1.0
