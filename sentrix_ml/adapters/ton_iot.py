"""ToN-IoT dataset adapter.

Reads raw ToN-IoT Network_dataset CSV files, performs cleaning, and
produces a canonical DataFrame with the SENTRi-X schema.

Key corrections vs original:
* Full source population traversal across all files without early termination.
* Deterministic bounded reservoir sampling (Algorithm R) bounds RAM to O(K).
* Preserves true population class prevalence for evaluation holdouts.
* Retains raw source metadata (file, row, flow ID, 5-tuple group ID) outside predictors.
* SHA-256 file hashing and complete provenance tracking.
"""

from __future__ import annotations

import glob
import os
from pathlib import Path

import numpy as np
import pandas as pd

from sentrix_ml.schema import (
    NUMERIC_FEATURE_NAMES,
    REQUIRED_NUMERIC_FEATURES,
    OPTIONAL_NUMERIC_FEATURES,
    EXPECTED_FEATURES,
)
from sentrix_ml.preprocessing import encode_dataframe
from sentrix_ml.splits import clean_labels
from sentrix_ml.sampler import stream_dataset_files, file_sha256


# Columns that are identifiers/timestamps — must not become predictors
_DROP_COLUMNS = ["ts", "src_ip", "src_port", "dst_ip", "dst_port"]

# Mandatory raw traffic measurement columns: input cannot be merely a label column
MANDATORY_RAW_COLUMNS = ["duration", "src_bytes", "dst_bytes", "src_pkts", "dst_pkts"]

# The 'type' column is a multi-class label — preserved as metadata, not a predictor
_LABEL_COL = "label"
_TYPE_COL = "type"


def _clean_and_extract_ton_chunk(
    chunk: pd.DataFrame,
    fname: str,
    row_offset: int,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series, dict[str, int]]:
    missing = [c for c in MANDATORY_RAW_COLUMNS if c not in chunk.columns]
    if missing:
        raise ValueError(
            f"ToN-IoT raw dataset is missing mandatory traffic columns: {missing}. "
            "A dataset with only labels is invalid."
        )
    if _LABEL_COL not in chunk.columns:
        raise ValueError("ToN-IoT dataset missing 'label' column")

    has_5tuple = all(c in chunk.columns for c in ["src_ip", "src_port", "dst_ip", "dst_port", "proto"])

    # Clean labels
    y_bin, exclusions = clean_labels(chunk[_LABEL_COL], domain="ton_iot")

    # Coerce optional numerics (fill '-' with 0.0)
    for col in OPTIONAL_NUMERIC_FEATURES:
        if col in chunk.columns:
            if not pd.api.types.is_numeric_dtype(chunk[col]):
                chunk[col] = pd.to_numeric(chunk[col].replace("-", np.nan), errors="coerce").fillna(0.0)
            else:
                chunk[col] = chunk[col].fillna(0.0)

    # Coerce required numerics
    for col in REQUIRED_NUMERIC_FEATURES:
        if col in chunk.columns and not pd.api.types.is_numeric_dtype(chunk[col]):
            chunk[col] = pd.to_numeric(chunk[col].replace("-", np.nan), errors="coerce")

    # Replace infinities
    chunk.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Validity masks
    req_cols = [c for c in REQUIRED_NUMERIC_FEATURES if c in chunk.columns]
    nan_mask = chunk[req_cols].isna().any(axis=1) if req_cols else pd.Series(False, index=chunk.index)
    neg_mask = (chunk[req_cols] < 0).any(axis=1) if req_cols else pd.Series(False, index=chunk.index)
    drop_mask = nan_mask | neg_mask
    dropped_count = int(drop_mask.sum())
    if dropped_count > 0:
        exclusions["invalid_or_missing_required_numerics"] = (
            exclusions.get("invalid_or_missing_required_numerics", 0) + dropped_count
        )

    valid_mask = y_bin.notna() & (~drop_mask)

    clean_chunk = chunk.loc[valid_mask].copy()
    clean_y = y_bin.loc[valid_mask].astype(int)
    raw_valid = chunk.loc[valid_mask]
    has_ts = "ts" in raw_valid.columns
    has_type = _TYPE_COL in raw_valid.columns

    def meta_fn(idx: int) -> dict:
        orig_row = row_offset + int(raw_valid.index[idx])
        if has_5tuple:
            r = raw_valid.iloc[idx]
            group_id = f"{r['src_ip']}:{r['src_port']}->{r['dst_ip']}:{r['dst_port']}/{r['proto']}"
        else:
            group_id = f"{fname}:{orig_row}"
        rec = {
            "__meta_source_file__": fname,
            "__meta_source_row_index__": orig_row,
            "__meta_source_flow_id__": f"{fname}:{orig_row}",
            "__meta_group_id__": group_id,
        }
        if has_ts:
            rec["__meta_ts__"] = raw_valid["ts"].iloc[idx]
        if has_type:
            rec["__meta_attack_type__"] = raw_valid[_TYPE_COL].iloc[idx]
        return rec

    # Drop non-predictor identifier columns
    drop_now = [c for c in _DROP_COLUMNS + [_LABEL_COL, _TYPE_COL] if c in clean_chunk.columns]
    clean_chunk.drop(columns=drop_now, inplace=True)

    return clean_chunk, meta_fn, clean_y, exclusions


def load_ton_iot(
    data_dir: str | Path,
    *,
    max_files: int | None = None,
    nrows_per_file: int | None = None,
    sample_n: int | None = None,
    seed: int = 42,
    chunksize: int = 50_000,
) -> tuple[pd.DataFrame, pd.Series, dict]:
    """Load and clean ToN-IoT raw CSVs.

    Args:
        data_dir: Path to ``data/raw/ton_iot/`` or a single CSV file.
        max_files: Load at most this many files (None = all).
        nrows_per_file: Read at most this many rows per file.
        sample_n: Subsample to this many rows using reservoir sampling.
        seed: Random seed for sampling.
        chunksize: Streaming chunk size in rows.

    Returns:
        (X_encoded, y_binary, info) where X_encoded has EXPECTED_FEATURES columns,
        y_binary is 0/1, and info contains row counts, file hashes, and metadata.
    """
    data_dir = Path(data_dir)
    if data_dir.is_file():
        all_files = [str(data_dir)]
    else:
        all_files = sorted(glob.glob(str(data_dir / "Network_dataset_*.csv")))
        if not all_files:
            all_files = sorted(glob.glob(str(data_dir / "*.csv")))
    if not all_files:
        raise FileNotFoundError(f"No ToN-IoT files found in {data_dir}")

    if max_files:
        all_files = all_files[:max_files]

    features_df, y_binary, metadata_df, info = stream_dataset_files(
        all_files,
        clean_and_extract_fn=_clean_and_extract_ton_chunk,
        sample_n=sample_n,
        seed=seed,
        chunksize=chunksize,
        nrows_per_file=nrows_per_file,
    )

    info["domain"] = "ton_iot"
    info["raw_rows"] = info["total_rows_considered"]
    info["cleaned_rows"] = info["total_valid_rows"]
    info["valid_label_rows"] = info["total_valid_rows"]
    if sample_n:
        info["sampled_to"] = len(y_binary)

    if len(features_df) > 0:
        X_encoded = encode_dataframe(features_df)
    else:
        X_encoded = pd.DataFrame(columns=EXPECTED_FEATURES)

    info["final_shape"] = X_encoded.shape
    info["class_counts"] = {str(k): int(v) for k, v in y_binary.value_counts().items()}

    return X_encoded, y_binary, info
