"""Categorical-safe random oversampling of the fitting partition only.

This explicit replacement for the old SMOTE step duplicates original training
rows; it never interpolates one-hot flags or consumes validation/test data.
"""
import hashlib
import numpy as np


def balance_training_rows(X_train, y_train, *, seed=42):
    X = np.asarray(X_train)
    y = np.asarray(y_train, dtype=int)
    classes, counts = np.unique(y, return_counts=True)
    if classes.tolist() != [0, 1] or counts.min() < 2:
        raise ValueError("Training-only oversampling requires at least two original rows in each class")
    rng = np.random.default_rng(seed)
    majority_count = int(counts.max())
    positions = [np.arange(len(y))]
    for label, count in zip(classes, counts):
        positions.append(rng.choice(np.flatnonzero(y == label), majority_count - int(count), replace=True))
    indices = np.concatenate(positions)
    rng.shuffle(indices)
    audit = {
        "method": "random_oversampling_training_only_v1", "seed": seed,
        "original_class_counts": {str(k): int(v) for k, v in zip(classes, counts)},
        "resampled_class_counts": {"0": majority_count, "1": majority_count},
        "selected_training_positions_sha256": hashlib.sha256(indices.astype("<i8").tobytes()).hexdigest(),
        "validation_test_resampled": False,
        "preprocessing_fit": "original_training_rows_before_resampling",
    }
    return X[indices], y[indices], audit
