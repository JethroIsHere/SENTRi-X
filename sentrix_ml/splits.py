"""Train / validation / test splitting with metadata preservation and duplicate isolation.

All splits:
* Are performed BEFORE any preprocessing (scaling, SMOTE).
* Keep first exact raw duplicate and preserve distinct observations in a session group.
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

    train_group_ids: list[str] = field(default_factory=list)
    val_group_ids: list[str] = field(default_factory=list)
    test_group_ids: list[str] = field(default_factory=list)
    train_records: list[dict] = field(default_factory=list)
    val_records: list[dict] = field(default_factory=list)
    test_records: list[dict] = field(default_factory=list)
    sampling_metadata: dict = field(default_factory=dict)
    partition_support: dict = field(default_factory=dict)
    inclusion_probabilities: dict = field(default_factory=dict)
    sampling_weights: dict = field(default_factory=dict)
    conflict_policy: str = "retain_and_group"
    identity_policy: str = ""
    grouping_policy: str = ""

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
                data[key] = [x.item() if isinstance(x, np.generic) else x for x in data[key]]
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

    nan_mask = y.isna() | y_str.isna() | y_str.isin(("nan", "none", ""))
    nan_count = int(nan_mask.sum())
    if nan_count > 0:
        exclusions[f"nan_or_empty_labels({domain})"] = nan_count

    binary = pd.Series(np.nan, index=y.index, dtype=float)
    benign_mask = y_str.isin(benign_values) & ~nan_mask
    attack_mask = ~benign_mask & ~nan_mask
    binary[benign_mask] = 0
    binary[attack_mask] = 1

    return binary, exclusions


class PartitionSupportError(ValueError):
    """The frozen sample/groups cannot support the configured experiment."""


def validate_partition_support(y_train, y_val, y_test, *, domains=None, indices=None):
    """Check original partitions, before balancing; never redraw a failed split."""
    result = {}
    for name, labels, minimum in (("train", y_train, 2), ("validation", y_val, 1), ("test", y_test, 1)):
        counts = {str(k): int(v) for k, v in pd.Series(labels).value_counts().items()}
        result[name] = counts
        if set(counts) != {"0", "1"} or min(counts.values()) < minimum:
            raise PartitionSupportError(
                f"{name} partition lacks class support: {counts}; requires benign=0 and attack=1 "
                f"with at least {minimum} original rows each. Increase the declared source sample "
                "or revise the grouping protocol before freezing a new experiment. No automatic redraw."
            )
    if domains is not None:
        for domain in sorted(set(domains)):
            for name, labels, idx in zip(("train", "validation", "test"),
                                         (y_train, y_val, y_test), indices):
                selected = labels.loc[domains.loc[idx] == domain]
                counts = {str(k): int(v) for k, v in selected.value_counts().items()}
                if set(counts) != {"0", "1"}:
                    raise PartitionSupportError(f"{domain} {name} partition lacks both classes: {counts}. "
                                                "Increase the predeclared domain sample; no automatic redraw.")
                result[f"{domain}/{name}"] = counts
    return result


def _prepare(X, y, metadata, domain, *, conflict_policy: str = "retain_and_group"):
    if isinstance(X, np.ndarray):
        X = pd.DataFrame(X)
    if isinstance(y, np.ndarray):
        y = pd.Series(y, index=X.index)
    if not X.index.is_unique or not X.index.equals(y.index):
        raise ValueError("Feature/label indices must be unique and exactly aligned")
    if metadata is not None and not metadata.index.equals(X.index):
        raise ValueError("Raw metadata indices must exactly match feature indices")
    valid = y.notna()
    Xv, yv = X.loc[valid].copy(), y.loc[valid].astype(int)
    if not set(yv.unique()) <= {0, 1}:
        raise ValueError("Expected binary labels 0 and 1")
    meta = metadata.loc[valid].copy() if metadata is not None else pd.DataFrame(index=Xv.index)
    if "source_flow_id" not in meta:
        meta["source_flow_id"] = [f"{domain or 'unverified'}:row:{i}" for i in Xv.index]
    if "duplicate_id" not in meta:
        # Explicit source identity is usable; equal model features are NOT proof of a duplicate.
        meta["duplicate_id"] = meta["source_flow_id"]
    if "group_id" not in meta:
        meta["group_id"] = meta["duplicate_id"]
    for col in ("source_flow_id", "duplicate_id", "group_id"):
        if meta[col].isna().any() or (meta[col].astype(str).str.len() == 0).any():
            raise ValueError(f"Missing {col} in raw metadata")
        meta[col] = meta[col].astype(str)

    # Check for conflicting labels within duplicate_id / group_id groups
    check_col = "duplicate_id" if "duplicate_id" in meta and conflict_policy == "keep_first" else "group_id"
    conflict = yv.groupby(meta[check_col]).nunique()
    conflicting_ids = conflict[conflict > 1].index
    conflicting_label_rows = 0
    if len(conflicting_ids) > 0:
        conflicting_label_rows = int(meta[check_col].isin(conflicting_ids).sum())

    if conflict_policy == "keep_first":
        if conflicting_label_rows > 0:
            import warnings
            warnings.warn(
                f"{len(conflicting_ids)} duplicate_id group(s) ({conflicting_label_rows} rows) have "
                f"conflicting labels; resolved by keep-first deduplication.",
                stacklevel=2,
            )
        if (meta.groupby("duplicate_id").group_id.nunique() > 1).any():
            raise ValueError("One raw duplicate identity maps to different split groups")
        duplicates = meta.duplicate_id.duplicated(keep="first")
        return (Xv.loc[~duplicates], yv.loc[~duplicates], meta.loc[~duplicates],
                int((~valid).sum()), int(duplicates.sum()), conflicting_label_rows)
    else:
        # Retain-and-group: preserve all source observations and original labels.
        # Deduplicate only true duplicate source rows (same file and row offset).
        if conflicting_label_rows > 0:
            import warnings
            warnings.warn(
                f"{len(conflicting_ids)} measurement group(s) ({conflicting_label_rows} rows) have "
                f"conflicting labels; retained in candidate pool without keep-first deletion.",
                stacklevel=2,
            )
        duplicates = meta.source_flow_id.duplicated(keep="first")
        return (Xv.loc[~duplicates], yv.loc[~duplicates], meta.loc[~duplicates],
                int((~valid).sum()), int(duplicates.sum()), conflicting_label_rows)


def _partition(index, y, groups, fraction, seed, domains=None):
    """Single seeded draw. Whole groups are stratified by their label/domain profile.

    For singleton groups this is ordinary row-stratified splitting. With repeated
    groups the requested fraction applies to group counts; actual row fractions
    are saved because group sizes may differ. No scoring or retry selects a split.
    """
    if not 0 < fraction < 1:
        raise ValueError("Partition fractions must lie strictly between 0 and 1")
    strata = y.loc[index].astype(str)
    if domains is not None:
        strata = domains.loc[index].astype(str) + ":" + strata
    frame = pd.DataFrame({"group": groups.loc[index], "stratum": strata}, index=index)
    profiles = frame.groupby("group", sort=False).stratum.agg(lambda x: "|".join(sorted(set(x))))
    counts = profiles.value_counts()
    n_test = int(np.ceil(len(profiles) * fraction))
    n_train = len(profiles) - n_test
    if len(profiles) < 2:
        raise PartitionSupportError("Only one independent session/group remains; cannot create disjoint partitions")
    if counts.min() < 2 or min(n_test, n_train) < len(counts):
        raise PartitionSupportError(
            f"Insufficient independent groups for a stratified {fraction:.0%} partition: "
            f"{counts.to_dict()}. Increase the declared sample or revise the grouping protocol."
        )
    train_groups, test_groups = train_test_split(profiles.index.to_numpy(), test_size=fraction,
                                               random_state=seed, stratify=profiles.to_numpy())
    return index[groups.loc[index].isin(train_groups)], index[groups.loc[index].isin(test_groups)]


def _split(X, y, *, metadata, test_fraction, val_fraction, seed, domain,
           source_file_hashes, duplicate_group_policy, exclusion_reasons,
           sampling_metadata, require_class_support, split_type,
           conflict_policy: str | None = None):
    if duplicate_group_policy not in ("keep_first_disjoint", "retain_and_group_disjoint"):
        raise ValueError(f"Unsupported duplicate_group_policy: {duplicate_group_policy}")

    if conflict_policy is None:
        conflict_policy = "keep_first" if duplicate_group_policy == "keep_first_disjoint" else "retain_and_group"

    original_count = len(X)
    X, y, meta, nan_count, dup_count, conflict_count = _prepare(
        X, y, metadata, domain, conflict_policy=conflict_policy
    )
    if require_class_support and set(y.unique()) != {0, 1}:
        raise PartitionSupportError("Single-class sample after cleaning/deduplication; both classes are required")
    domains = meta["domain"] if domain == "omni" and "domain" in meta else None
    pool, test = _partition(X.index, y, meta.group_id, test_fraction, seed, domains)
    train, val = _partition(pool, y, meta.group_id, val_fraction, seed, domains)
    idx = (train, val, test)
    labels = tuple(y.loc[i] for i in idx)
    support = {}
    if require_class_support:
        support = validate_partition_support(*labels, domains=domains, indices=idx)
    group_sets = [set(meta.loc[i, "group_id"]) for i in idx]
    if any(group_sets[i] & group_sets[j] for i, j in ((0, 1), (0, 2), (1, 2))):
        raise ValueError("Split groups overlap")
    exclusions = dict(exclusion_reasons or {})
    exclusions.update(nan_labels=nan_count, duplicate_rows_excluded=dup_count)
    if conflict_count > 0:
        if conflict_policy == "keep_first":
            exclusions["conflicting_label_duplicates_resolved"] = conflict_count
        else:
            exclusions["conflicting_label_groups_retained"] = conflict_count

    samp_meta = sampling_metadata or {}
    inc_probs = samp_meta.get("inclusion_probabilities", {})
    samp_weights = samp_meta.get("sampling_weights", {})

    manifest = SplitManifest(
        seed=seed, test_fraction=test_fraction, val_fraction=val_fraction,
        total_rows=original_count, excluded_rows=nan_count + dup_count,
        exclusion_reasons=exclusions, source_file_hashes=dict(source_file_hashes or {}),
        duplicate_group_policy=duplicate_group_policy, duplicate_rows_excluded=dup_count,
        unique_groups_count=int(meta.group_id.nunique()), dataset_domain=domain, split_type=split_type,
        sampling_metadata=samp_meta, partition_support=support,
        inclusion_probabilities=inc_probs, sampling_weights=samp_weights,
        conflict_policy=conflict_policy,
        identity_policy="raw_record_sha256_v2" if metadata is not None and "duplicate_id" in metadata else "source_identity_only",
        grouping_policy="session_start_else_tuple_else_raw_record_v2",
        notes="Retain all distinct observations and original labels in each split group. "
              "Fractions target groups; row/class counts below are authoritative. No feature-vector deduplication.",
    )
    records_columns = [c for c in ("domain", "source_file", "source_file_hash", "source_row_index",
                                   "source_flow_id", "duplicate_id", "group_id", "group_scope",
                                   "original_flow_id", "inclusion_probability", "sampling_weight") if c in meta]
    for name, i, label in zip(("train", "val", "test"), idx, labels):
        setattr(manifest, name + "_count", len(i))
        setattr(manifest, name + "_class_counts", {str(k): int(v) for k, v in label.value_counts().items()})
        setattr(manifest, name + "_indices", list(i))
        setattr(manifest, name + "_flow_ids", meta.loc[i, "source_flow_id"].tolist())
        setattr(manifest, name + "_group_ids", meta.loc[i, "group_id"].tolist())
        setattr(manifest, name + "_records", json.loads(meta.loc[i, records_columns].to_json(orient="records")))
    return (*(X.loc[i] for i in idx), *labels, manifest)


def stratified_split(X, y, *, metadata=None, test_fraction=0.20, val_fraction=0.10,
                     seed=42, domain="", source_file_hashes=None,
                     duplicate_group_policy="keep_first_disjoint", exclusion_reasons=None,
                     sampling_metadata=None, require_class_support=False,
                     conflict_policy: str | None = None):
    return _split(X, y, metadata=metadata, test_fraction=test_fraction, val_fraction=val_fraction,
                  seed=seed, domain=domain, source_file_hashes=source_file_hashes,
                  duplicate_group_policy=duplicate_group_policy, exclusion_reasons=exclusion_reasons,
                  sampling_metadata=sampling_metadata, require_class_support=require_class_support,
                  split_type="stratified_session_groups", conflict_policy=conflict_policy)


def adaptation_split(X, y, *, metadata=None, study_fraction=0.20, val_fraction_of_study=0.10,
                     seed=42, domain="", source_file_hashes=None,
                     duplicate_group_policy="keep_first_disjoint", exclusion_reasons=None,
                     sampling_metadata=None, require_class_support=False,
                     conflict_policy: str | None = None):
    return _split(X, y, metadata=metadata, test_fraction=1.0-study_fraction, val_fraction=val_fraction_of_study,
                  seed=seed, domain=domain, source_file_hashes=source_file_hashes,
                  duplicate_group_policy=duplicate_group_policy, exclusion_reasons=exclusion_reasons,
                  sampling_metadata=sampling_metadata, require_class_support=require_class_support,
                  split_type="adaptation_session_groups", conflict_policy=conflict_policy)
