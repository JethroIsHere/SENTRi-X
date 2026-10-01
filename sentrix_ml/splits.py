"""Train / validation / test splitting with metadata preservation and duplicate isolation.

All splits:
* Are performed BEFORE any preprocessing (scaling, SMOTE).
* Enforce duplicate group policy ('keep_first_disjoint') prior to splitting.
* Guarantee zero duplicate group leakage across train, val, and test partitions.
* Preserve sample identifiers and raw source flow IDs for end-to-end traceability.
* Record seed, counts, class prevalence, file hashes, and exclusion reasons.
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
    """Records the exact split configuration, lineage, and resulting partition sizes."""

    seed: int = 42
    test_fraction: float = 0.20
    val_fraction: float = 0.10  # Fraction of the training pool
    total_rows: int = 0
    excluded_rows: int = 0
    exclusion_reasons: dict = field(default_factory=dict)
    source_file_hashes: dict[str, str] = field(default_factory=dict)
    duplicate_group_policy: str = "keep_first_disjoint"
    duplicate_rows_excluded: int = 0
    unique_groups_count: int = 0

    train_count: int = 0
    val_count: int = 0
    test_count: int = 0

    train_class_counts: dict = field(default_factory=dict)
    val_class_counts: dict = field(default_factory=dict)
    test_class_counts: dict = field(default_factory=dict)

    train_indices: Optional[list] = None
    val_indices: Optional[list] = None
    test_indices: Optional[list] = None

    train_flow_ids: list[str] = field(default_factory=list)
    val_flow_ids: list[str] = field(default_factory=list)
    test_flow_ids: list[str] = field(default_factory=list)

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
        for key in ("train_flow_ids", "val_flow_ids", "test_flow_ids"):
            if data[key] is not None:
                data[key] = [str(x) for x in data[key]]
        for key in ("train_class_counts", "val_class_counts", "test_class_counts",
                     "exclusion_reasons"):
            data[key] = {str(k): int(v) for k, v in data[key].items()}
        for k in ("source_file_hashes",):
            data[k] = {str(k_sub): str(v_sub) for k_sub, v_sub in data[k].items()}

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def load(path: str | Path) -> "SplitManifest":
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        valid_keys = set(SplitManifest.__dataclass_fields__.keys())
        filtered_data = {k: v for k, v in data.items() if k in valid_keys}
        return SplitManifest(**filtered_data)


def clean_labels(
    y: pd.Series,
    benign_values: tuple[str, ...] = ("0", "0.0", "normal", "benign"),
    *,
    domain: str = "",
) -> tuple[pd.Series, dict]:
    """Convert labels to binary 0/1. Reject NaN-string labels explicitly.

    Returns:
        (binary_labels, exclusion_info) where exclusion_info maps reason to count.
    """
    y_str = y.astype(str).str.strip().str.lower()
    exclusions: dict[str, int] = {}

    nan_mask = y_str.isin(("nan", "none", ""))
    nan_count = int(nan_mask.sum())
    if nan_count > 0:
        exclusions[f"nan_or_empty_labels({domain})"] = nan_count

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
    metadata: pd.DataFrame | None = None,
    test_fraction: float = 0.20,
    val_fraction: float = 0.10,
    seed: int = 42,
    domain: str = "",
    source_file_hashes: dict[str, str] | None = None,
    duplicate_group_policy: str = "keep_first_disjoint",
    exclusion_reasons: dict | None = None,
) -> tuple[
    pd.DataFrame, pd.DataFrame, pd.DataFrame,
    pd.Series, pd.Series, pd.Series,
    SplitManifest,
]:
    """Perform a stratified train/val/test split with duplicate group isolation.

    Enforces duplicate_group_policy='keep_first_disjoint' prior to splitting.
    Subsequent duplicate group occurrences are dropped and recorded in exclusion_reasons.
    Guarantees zero duplicate group leakage between train, val, and test partitions.

    Returns:
        (X_train, X_val, X_test, y_train, y_val, y_test, manifest)
    """
    valid_mask = y.notna()
    X_valid = X.loc[valid_mask].copy()
    y_valid = y.loc[valid_mask].astype(int)
    meta_valid = metadata.loc[valid_mask].copy() if metadata is not None else None
    nan_excluded = int((~valid_mask).sum())

    # Identify duplicate group IDs
    if meta_valid is not None and "group_id" in meta_valid.columns:
        group_series = meta_valid["group_id"].astype(str)
    else:
        group_series = pd.util.hash_pandas_object(X_valid, index=False).astype(str)

    unique_groups = int(group_series.nunique())

    if duplicate_group_policy == "keep_first_disjoint":
        is_dup = group_series.duplicated(keep="first")
        dup_count = int(is_dup.sum())
        if dup_count > 0:
            X_dedup = X_valid.loc[~is_dup]
            y_dedup = y_valid.loc[~is_dup]
            meta_dedup = meta_valid.loc[~is_dup] if meta_valid is not None else None
            groups_dedup = group_series.loc[~is_dup]
        else:
            X_dedup = X_valid
            y_dedup = y_valid
            meta_dedup = meta_valid
            groups_dedup = group_series
        dup_excluded = dup_count
    else:
        raise ValueError(f"Unsupported duplicate_group_policy: '{duplicate_group_policy}'")

    class_min = y_dedup.value_counts().min() if len(y_dedup) > 0 else 0
    test_expected = int(np.round(len(X_dedup) * test_fraction))
    pool_expected = len(X_dedup) - test_expected
    stratify_pool = y_dedup if (class_min >= 2 and test_expected >= 2 and pool_expected >= 2) else None

    # First split: train_pool / test
    X_pool, X_test, y_pool, y_test = train_test_split(
        X_dedup, y_dedup,
        test_size=test_fraction,
        random_state=seed,
        stratify=stratify_pool,
    )

    # Second split: train / val (from pool)
    if len(X_pool) <= 1:
        X_train, X_val, y_train, y_val = X_pool, X_pool.iloc[:0], y_pool, y_pool.iloc[:0]
    elif len(X_pool) == 2:
        X_train, X_val, y_train, y_val = X_pool.iloc[:1], X_pool.iloc[1:], y_pool.iloc[:1], y_pool.iloc[1:]
    else:
        class_min_pool = y_pool.value_counts().min() if len(y_pool) > 0 else 0
        val_expected = int(np.round(len(X_pool) * val_fraction))
        train_expected = len(X_pool) - val_expected
        stratify_val = y_pool if (class_min_pool >= 2 and val_expected >= 2 and train_expected >= 2) else None
        X_train, X_val, y_train, y_val = train_test_split(
            X_pool, y_pool,
            test_size=val_fraction,
            random_state=seed,
            stratify=stratify_val,
        )

    # Invariant assertion: duplicate groups cannot cross partitions
    train_grps = set(groups_dedup.loc[X_train.index])
    val_grps = set(groups_dedup.loc[X_val.index])
    test_grps = set(groups_dedup.loc[X_test.index])
    assert train_grps.isdisjoint(test_grps), "Duplicate group leaked between train and test partitions!"
    assert train_grps.isdisjoint(val_grps), "Duplicate group leaked between train and val partitions!"
    assert val_grps.isdisjoint(test_grps), "Duplicate group leaked between val and test partitions!"

    # Extract source flow IDs
    if meta_dedup is not None and "source_flow_id" in meta_dedup.columns:
        train_flow_ids = [str(x) for x in meta_dedup.loc[X_train.index, "source_flow_id"]]
        val_flow_ids = [str(x) for x in meta_dedup.loc[X_val.index, "source_flow_id"]]
        test_flow_ids = [str(x) for x in meta_dedup.loc[X_test.index, "source_flow_id"]]
    else:
        train_flow_ids = [f"{domain or 'flow'}:{idx}" for idx in X_train.index]
        val_flow_ids = [f"{domain or 'flow'}:{idx}" for idx in X_val.index]
        test_flow_ids = [f"{domain or 'flow'}:{idx}" for idx in X_test.index]

    merged_exclusions = dict(exclusion_reasons or {})
    if nan_excluded:
        merged_exclusions["nan_labels"] = nan_excluded
    if dup_excluded:
        merged_exclusions["duplicate_rows_excluded"] = dup_excluded

    manifest = SplitManifest(
        seed=seed,
        test_fraction=test_fraction,
        val_fraction=val_fraction,
        total_rows=len(X),
        excluded_rows=nan_excluded + dup_excluded,
        exclusion_reasons=merged_exclusions,
        source_file_hashes=dict(source_file_hashes or {}),
        duplicate_group_policy=duplicate_group_policy,
        duplicate_rows_excluded=dup_excluded,
        unique_groups_count=unique_groups,
        train_count=len(X_train),
        val_count=len(X_val),
        test_count=len(X_test),
        train_class_counts=dict(y_train.value_counts()),
        val_class_counts=dict(y_val.value_counts()),
        test_class_counts=dict(y_test.value_counts()),
        train_indices=list(X_train.index),
        val_indices=list(X_val.index),
        test_indices=list(X_test.index),
        train_flow_ids=train_flow_ids,
        val_flow_ids=val_flow_ids,
        test_flow_ids=test_flow_ids,
        dataset_domain=domain,
        split_type="stratified_random",
    )

    return X_train, X_val, X_test, y_train, y_val, y_test, manifest


def adaptation_split(
    X: pd.DataFrame | np.ndarray,
    y: pd.Series | np.ndarray,
    *,
    metadata: pd.DataFrame | None = None,
    study_fraction: float = 0.20,
    val_fraction_of_study: float = 0.10,
    seed: int = 42,
    domain: str = "",
    source_file_hashes: dict[str, str] | None = None,
    duplicate_group_policy: str = "keep_first_disjoint",
    exclusion_reasons: dict | None = None,
) -> tuple:
    """Split for target-domain adaptation: 20% study / 80% exam with duplicate isolation.

    Enforces duplicate_group_policy='keep_first_disjoint' prior to splitting.
    Guarantees zero duplicate group leakage between study train, study val, and exam holdout.

    Returns:
        (X_study_train, X_study_val, X_exam,
         y_study_train, y_study_val, y_exam,
         manifest)
    """
    if isinstance(X, np.ndarray):
        X = pd.DataFrame(X)
    if isinstance(y, np.ndarray):
        y = pd.Series(y)

    valid_mask = y.notna()
    X_valid = X.loc[valid_mask].copy()
    y_valid = y.loc[valid_mask].astype(int)
    meta_valid = metadata.loc[valid_mask].copy() if metadata is not None else None
    nan_excluded = int((~valid_mask).sum())

    if meta_valid is not None and "group_id" in meta_valid.columns:
        group_series = meta_valid["group_id"].astype(str)
    else:
        group_series = pd.util.hash_pandas_object(X_valid, index=False).astype(str)

    unique_groups = int(group_series.nunique())

    if duplicate_group_policy == "keep_first_disjoint":
        is_dup = group_series.duplicated(keep="first")
        dup_count = int(is_dup.sum())
        if dup_count > 0:
            X_dedup = X_valid.loc[~is_dup]
            y_dedup = y_valid.loc[~is_dup]
            meta_dedup = meta_valid.loc[~is_dup] if meta_valid is not None else None
            groups_dedup = group_series.loc[~is_dup]
        else:
            X_dedup = X_valid
            y_dedup = y_valid
            meta_dedup = meta_valid
            groups_dedup = group_series
        dup_excluded = dup_count
    else:
        raise ValueError(f"Unsupported duplicate_group_policy: '{duplicate_group_policy}'")

    class_min = y_dedup.value_counts().min() if len(y_dedup) > 0 else 0
    exam_expected = int(np.round(len(X_dedup) * (1.0 - study_fraction)))
    study_expected = len(X_dedup) - exam_expected
    stratify_study = y_dedup if (class_min >= 2 and exam_expected >= 2 and study_expected >= 2) else None

    X_study, X_exam, y_study, y_exam = train_test_split(
        X_dedup, y_dedup,
        test_size=1.0 - study_fraction,
        random_state=seed,
        stratify=stratify_study,
    )

    if len(X_study) <= 1:
        X_study_train, X_study_val, y_study_train, y_study_val = X_study, X_study.iloc[:0], y_study, y_study.iloc[:0]
    elif len(X_study) == 2:
        X_study_train, X_study_val, y_study_train, y_study_val = X_study.iloc[:1], X_study.iloc[1:], y_study.iloc[:1], y_study.iloc[1:]
    else:
        class_min_study = y_study.value_counts().min() if len(y_study) > 0 else 0
        val_expected = int(np.round(len(X_study) * val_fraction_of_study))
        study_train_expected = len(X_study) - val_expected
        stratify_val = y_study if (class_min_study >= 2 and val_expected >= 2 and study_train_expected >= 2) else None
        X_study_train, X_study_val, y_study_train, y_study_val = train_test_split(
            X_study, y_study,
            test_size=val_fraction_of_study,
            random_state=seed,
            stratify=stratify_val,
        )

    # Invariant assertion: duplicate groups cannot cross partitions
    s_train_grps = set(groups_dedup.loc[X_study_train.index])
    s_val_grps = set(groups_dedup.loc[X_study_val.index])
    exam_grps = set(groups_dedup.loc[X_exam.index])
    assert s_train_grps.isdisjoint(exam_grps), "Study train and exam holdout share duplicate groups!"
    assert s_val_grps.isdisjoint(exam_grps), "Study val and exam holdout share duplicate groups!"
    assert s_train_grps.isdisjoint(s_val_grps), "Study train and study val share duplicate groups!"

    if meta_dedup is not None and "source_flow_id" in meta_dedup.columns:
        train_flow_ids = [str(x) for x in meta_dedup.loc[X_study_train.index, "source_flow_id"]]
        val_flow_ids = [str(x) for x in meta_dedup.loc[X_study_val.index, "source_flow_id"]]
        test_flow_ids = [str(x) for x in meta_dedup.loc[X_exam.index, "source_flow_id"]]
    else:
        train_flow_ids = [f"{domain or 'study_train'}:{idx}" for idx in X_study_train.index]
        val_flow_ids = [f"{domain or 'study_val'}:{idx}" for idx in X_study_val.index]
        test_flow_ids = [f"{domain or 'exam'}:{idx}" for idx in X_exam.index]

    merged_exclusions = dict(exclusion_reasons or {})
    if nan_excluded:
        merged_exclusions["nan_labels"] = nan_excluded
    if dup_excluded:
        merged_exclusions["duplicate_rows_excluded"] = dup_excluded

    manifest = SplitManifest(
        seed=seed,
        test_fraction=1.0 - study_fraction,
        val_fraction=val_fraction_of_study,
        total_rows=len(X),
        excluded_rows=nan_excluded + dup_excluded,
        exclusion_reasons=merged_exclusions,
        source_file_hashes=dict(source_file_hashes or {}),
        duplicate_group_policy=duplicate_group_policy,
        duplicate_rows_excluded=dup_excluded,
        unique_groups_count=unique_groups,
        train_count=len(X_study_train),
        val_count=len(X_study_val),
        test_count=len(X_exam),
        train_class_counts=dict(pd.Series(y_study_train).value_counts()),
        val_class_counts=dict(pd.Series(y_study_val).value_counts()),
        test_class_counts=dict(pd.Series(y_exam).value_counts()),
        train_indices=list(X_study_train.index),
        val_indices=list(X_study_val.index),
        test_indices=list(X_exam.index),
        train_flow_ids=train_flow_ids,
        val_flow_ids=val_flow_ids,
        test_flow_ids=test_flow_ids,
        dataset_domain=domain,
        split_type="adaptation_study_exam",
    )

    return (X_study_train, X_study_val, X_exam,
            y_study_train, y_study_val, y_exam,
            manifest)
