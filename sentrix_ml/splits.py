"""Train / validation / test splitting with metadata preservation.

All splits:
* Are performed BEFORE any preprocessing (scaling, SMOTE).
* Preserve sample identifiers (original DataFrame index) for traceability.
* Record seed, counts, class prevalence, and exclusion reasons.
* Support stratified splitting.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split


@dataclass
class SplitManifest:
    """Records the exact split configuration and resulting partition sizes."""

    seed: int = 42
    test_fraction: float = 0.20
    val_fraction: float = 0.10  # Fraction of the *training* pool
    total_rows: int = 0
    excluded_rows: int = 0
    exclusion_reasons: dict = field(default_factory=dict)
    source_file_hashes: dict[str, str] = field(default_factory=dict)
    duplicate_group_policy: str = "keep_first_disjoint"

    train_count: int = 0
    val_count: int = 0
    test_count: int = 0

    train_class_counts: dict = field(default_factory=dict)
    val_class_counts: dict = field(default_factory=dict)
    test_class_counts: dict = field(default_factory=dict)

    train_indices: Optional[list] = None
    val_indices: Optional[list] = None
    test_indices: Optional[list] = None

    dataset_domain: str = ""
    split_type: str = "stratified_random"
    notes: str = ""

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        data = asdict(self)
        # Convert numpy types for JSON serialization
        for key in ("train_indices", "val_indices", "test_indices"):
            if data[key] is not None:
                data[key] = [int(x) for x in data[key]]
        for key in ("train_class_counts", "val_class_counts", "test_class_counts",
                     "exclusion_reasons"):
            data[key] = {str(k): int(v) for k, v in data[key].items()}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def load(path: str | Path) -> "SplitManifest":
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return SplitManifest(**data)


def clean_labels(
    y: pd.Series,
    benign_values: tuple[str, ...] = ("0", "0.0", "normal", "benign"),
    *,
    domain: str = "",
) -> tuple[pd.Series, dict]:
    """Convert labels to binary 0/1.  Reject NaN-string labels explicitly.

    Returns:
        (binary_labels, exclusion_info) where exclusion_info maps reason to count.
    """
    y_str = y.astype(str).str.strip().str.lower()
    exclusions: dict[str, int] = {}

    # Flag 'nan' strings — these are NOT benign, they're missing
    nan_mask = y_str.isin(("nan", "none", ""))
    nan_count = int(nan_mask.sum())
    if nan_count > 0:
        exclusions[f"nan_or_empty_labels({domain})"] = nan_count

    # Build binary labels: benign=0, attack=1, nan=excluded
    binary = pd.Series(np.nan, index=y.index, dtype=float)
    benign_mask = y_str.isin(benign_values) & ~nan_mask
    attack_mask = ~benign_mask & ~nan_mask
    binary[benign_mask] = 0
    binary[attack_mask] = 1

    return binary, exclusions


def stratified_split(
    X: pd.DataFrame,
    y: pd.Series,
    *,
    test_fraction: float = 0.20,
    val_fraction: float = 0.10,
    seed: int = 42,
    domain: str = "",
    source_file_hashes: dict[str, str] | None = None,
    exclusion_reasons: dict | None = None,
) -> tuple[
    pd.DataFrame, pd.DataFrame, pd.DataFrame,
    pd.Series, pd.Series, pd.Series,
    SplitManifest,
]:
    """Perform a stratified train/val/test split.

    ``val_fraction`` is the fraction of the *training pool* (after test split).

    Returns:
        (X_train, X_val, X_test, y_train, y_val, y_test, manifest)
    """
    # Drop rows with NaN labels
    valid_mask = y.notna()
    X_valid = X.loc[valid_mask]
    y_valid = y.loc[valid_mask].astype(int)
    excluded = int((~valid_mask).sum())

    # First split: train_pool / test
    X_pool, X_test, y_pool, y_test = train_test_split(
        X_valid, y_valid,
        test_size=test_fraction,
        random_state=seed,
        stratify=y_valid,
    )

    # Second split: train / val (from pool)
    X_train, X_val, y_train, y_val = train_test_split(
        X_pool, y_pool,
        test_size=val_fraction,
        random_state=seed,
        stratify=y_pool,
    )

    merged_exclusions = dict(exclusion_reasons or {})
    if excluded:
        merged_exclusions["nan_labels"] = excluded

    manifest = SplitManifest(
        seed=seed,
        test_fraction=test_fraction,
        val_fraction=val_fraction,
        total_rows=len(X) + excluded,
        excluded_rows=excluded,
        exclusion_reasons=merged_exclusions,
        source_file_hashes=dict(source_file_hashes or {}),
        train_count=len(X_train),
        val_count=len(X_val),
        test_count=len(X_test),
        train_class_counts=dict(y_train.value_counts()),
        val_class_counts=dict(y_val.value_counts()),
        test_class_counts=dict(y_test.value_counts()),
        train_indices=list(X_train.index),
        val_indices=list(X_val.index),
        test_indices=list(X_test.index),
        dataset_domain=domain,
    )

    return X_train, X_val, X_test, y_train, y_val, y_test, manifest


def adaptation_split(
    X: pd.DataFrame | np.ndarray,
    y: pd.Series | np.ndarray,
    *,
    study_fraction: float = 0.20,
    val_fraction_of_study: float = 0.10,
    seed: int = 42,
    domain: str = "",
) -> tuple:
    """Split for target-domain adaptation: 20% study / 80% exam.

    Within the study pool, ``val_fraction_of_study`` is reserved for validation.

    Returns:
        (X_study_train, X_study_val, X_exam,
         y_study_train, y_study_val, y_exam,
         manifest)
    """
    if isinstance(X, np.ndarray):
        X = pd.DataFrame(X)
    if isinstance(y, np.ndarray):
        y = pd.Series(y)

    X_study, X_exam, y_study, y_exam = train_test_split(
        X, y,
        test_size=1.0 - study_fraction,
        random_state=seed,
        stratify=y,
    )

    X_study_train, X_study_val, y_study_train, y_study_val = train_test_split(
        X_study, y_study,
        test_size=val_fraction_of_study,
        random_state=seed,
        stratify=y_study,
    )

    manifest = SplitManifest(
        seed=seed,
        test_fraction=1.0 - study_fraction,
        val_fraction=val_fraction_of_study,
        total_rows=len(X),
        train_count=len(X_study_train),
        val_count=len(X_study_val),
        test_count=len(X_exam),
        train_class_counts=dict(pd.Series(y_study_train).value_counts()),
        val_class_counts=dict(pd.Series(y_study_val).value_counts()),
        test_class_counts=dict(pd.Series(y_exam).value_counts()),
        train_indices=list(X_study_train.index),
        val_indices=list(X_study_val.index),
        test_indices=list(X_exam.index),
        dataset_domain=domain,
        split_type="adaptation_study_exam",
    )

    return (X_study_train, X_study_val, X_exam,
            y_study_train, y_study_val, y_exam,
            manifest)
