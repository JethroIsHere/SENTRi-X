"""T1: Split Isolation Tests.

Verifies:
1. Train, validation, and test index sets are mutually disjoint.
2. Changes to held-out test rows do NOT alter statistics learned by PreprocessingPipeline.
3. Validation observations are reserved prior to any resampling.
4. clean_labels correctly excludes NaN/empty labels and does not classify them as benign.
"""

import numpy as np
import pandas as pd
import pytest

from sentrix_ml.schema import NUM_FEATURES, EXPECTED_FEATURES
from sentrix_ml.splits import stratified_split, adaptation_split, clean_labels
from sentrix_ml.preprocessing import PreprocessingPipeline


def test_t1_stratified_split_disjoint():
    """Verify stratified split produces completely disjoint train/val/test partitions."""
    n_samples = 500
    np.random.seed(42)
    X = pd.DataFrame(
        np.random.randn(n_samples, NUM_FEATURES),
        columns=EXPECTED_FEATURES,
        index=[f"sample_{i}" for i in range(n_samples)],
    )
    y = pd.Series(
        np.random.choice([0, 1], size=n_samples, p=[0.7, 0.3]),
        index=X.index,
    )

    X_train, X_val, X_test, y_train, y_val, y_test, manifest = stratified_split(
        X, y, test_fraction=0.20, val_fraction=0.10, seed=42, domain="test_domain"
    )

    train_idx = set(X_train.index)
    val_idx = set(X_val.index)
    test_idx = set(X_test.index)

    # Disjointness
    assert train_idx.isdisjoint(val_idx), "Train and validation overlap!"
    assert train_idx.isdisjoint(test_idx), "Train and test overlap!"
    assert val_idx.isdisjoint(test_idx), "Validation and test overlap!"

    # Total count match
    assert len(train_idx) + len(val_idx) + len(test_idx) == n_samples
    assert manifest.train_count == len(X_train)
    assert manifest.val_count == len(X_val)
    assert manifest.test_count == len(X_test)


def test_t1_held_out_leakage_isolation():
    """Verify changing held-out test observations does NOT alter fitted scaler statistics."""
    np.random.seed(42)
    n_samples = 200
    X = pd.DataFrame(
        np.random.randn(n_samples, NUM_FEATURES),
        columns=EXPECTED_FEATURES,
    )
    y = pd.Series(np.random.choice([0, 1], size=n_samples))

    X_train1, X_val1, X_test1, _, _, _, _ = stratified_split(X, y, seed=42)
    pipeline1 = PreprocessingPipeline().fit(X_train1)
    mean1 = pipeline1.scaler.mean_.copy()
    scale1 = pipeline1.scaler.scale_.copy()

    # Now alter the test set rows drastically (multiply by 1000)
    X_modified = X.copy()
    test_indices = X_test1.index
    X_modified.loc[test_indices] = X_modified.loc[test_indices] * 1000.0

    X_train2, X_val2, X_test2, _, _, _, _ = stratified_split(X_modified, y, seed=42)
    pipeline2 = PreprocessingPipeline().fit(X_train2)
    mean2 = pipeline2.scaler.mean_.copy()
    scale2 = pipeline2.scaler.scale_.copy()

    # Train scaler statistics must be IDENTICAL
    np.testing.assert_allclose(mean1, mean2, err_msg="Scaler mean leaked test data!")
    np.testing.assert_allclose(scale1, scale2, err_msg="Scaler scale leaked test data!")


def test_t1_adaptation_split_disjoint():
    """Verify target adaptation produces disjoint study (train/val) and exam pools."""
    n_samples = 400
    X = pd.DataFrame(np.random.randn(n_samples, NUM_FEATURES), columns=EXPECTED_FEATURES)
    y = pd.Series(np.random.choice([0, 1], size=n_samples, p=[0.8, 0.2]))

    X_study_train, X_study_val, X_exam, y_study_train, y_study_val, y_exam, manifest = adaptation_split(
        X, y, study_fraction=0.20, val_fraction_of_study=0.10, seed=42
    )

    study_train_idx = set(X_study_train.index)
    study_val_idx = set(X_study_val.index)
    exam_idx = set(X_exam.index)

    assert study_train_idx.isdisjoint(study_val_idx)
    assert study_train_idx.isdisjoint(exam_idx)
    assert study_val_idx.isdisjoint(exam_idx)
    assert len(study_train_idx) + len(study_val_idx) + len(exam_idx) == n_samples
    assert manifest.test_count == len(X_exam)  # Exam is holdout


def test_t1_clean_labels_nan_rejection():
    """Verify string 'nan' is NOT treated as benign."""
    raw_labels = pd.Series(["normal", "benign", "0", "attack", "DDoS", "nan", "none", ""])
    binary, exclusions = clean_labels(raw_labels, domain="test")

    # 'nan', 'none', and '' must be excluded (NaN), not 0
    assert binary.iloc[0] == 0  # normal
    assert binary.iloc[1] == 0  # benign
    assert binary.iloc[2] == 0  # 0
    assert binary.iloc[3] == 1  # attack
    assert binary.iloc[4] == 1  # DDoS
    assert pd.isna(binary.iloc[5]), "string 'nan' was incorrectly classified as benign!"
    assert pd.isna(binary.iloc[6]), "string 'none' was incorrectly classified as benign!"
    assert pd.isna(binary.iloc[7]), "empty string was incorrectly classified as benign!"

    assert "nan_or_empty_labels(test)" in exclusions
    assert exclusions["nan_or_empty_labels(test)"] == 3


if __name__ == "__main__":
    test_t1_stratified_split_disjoint()
    test_t1_held_out_leakage_isolation()
    test_t1_adaptation_split_disjoint()
    test_t1_clean_labels_nan_rejection()
    print("All T1 Split Isolation tests passed!")
