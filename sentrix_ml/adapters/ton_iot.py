"""ToN-IoT dataset adapter.

Reads raw ToN-IoT Network_dataset CSV files, performs cleaning, and
produces a canonical DataFrame with the SENTRi-X schema.

Key corrections vs the original notebook:
* Column dropping uses only metadata/identifier columns (no 30% threshold
  that could vary with data).
* Feature types are coerced without dropping rows first (avoids the
  "reloading" issue from the original Cell 2).
* Labels are cleaned using ``clean_labels`` (rejects string 'nan').
* No scaling is applied — that's the ``PreprocessingPipeline``'s job.
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


# Columns that are identifiers/timestamps — must not become predictors
_DROP_COLUMNS = ["ts", "src_ip", "src_port", "dst_ip", "dst_port"]

# The 'type' column is a multi-class label — preserved as metadata, not a predictor
_LABEL_COL = "label"
_TYPE_COL = "type"


def load_ton_iot(
    data_dir: str | Path,
    *,
    max_files: int | None = None,
    nrows_per_file: int | None = None,
    sample_n: int | None = None,
    seed: int = 42,
) -> tuple[pd.DataFrame, pd.Series, dict]:
    """Load and clean ToN-IoT raw CSVs.

    Args:
        data_dir: Path to ``data/raw/ton_iot/``
        max_files: Load at most this many files (None = all)
        nrows_per_file: Read at most this many rows per file
        sample_n: Subsample to this many rows (bounds ingestion memory)
        seed: Random seed for sampling

    Returns:
        (X_encoded, y_binary, info) where X_encoded has EXPECTED_FEATURES columns,
        y_binary is 0/1, and info contains row counts and exclusions.
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

    # Memory-bounded ingestion: if sample_n is specified and nrows_per_file is not,
    # calculate a safe per-file limit so we don't load 3.3GB into RAM.
    effective_nrows = nrows_per_file
    if effective_nrows is None and sample_n is not None:
        effective_nrows = int(np.ceil((sample_n * 1.5) / len(all_files))) + 100

    chunks = []
    for f in all_files:
        chunk = pd.read_csv(f, low_memory=False, nrows=effective_nrows)
        chunks.append(chunk)
    df = pd.concat(chunks, ignore_index=True)

    info = {
        "raw_rows": len(df),
        "files_loaded": len(all_files),
        "exclusion_reasons": {},
    }

    # Drop identifier columns
    df.drop(
        columns=[c for c in _DROP_COLUMNS if c in df.columns],
        inplace=True,
    )

    # Optional numeric features: '-' or NaN means not applicable (e.g. non-DNS, non-HTTP)
    # The schema specifies 0.0 for absent optional values. DO NOT drop rows for these!
    for col in OPTIONAL_NUMERIC_FEATURES:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col].replace("-", np.nan), errors="coerce").fillna(0.0)

    # Required numeric features: must be valid finite numbers
    for col in REQUIRED_NUMERIC_FEATURES:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col].replace("-", np.nan), errors="coerce")

    # Replace infinities with NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Drop rows ONLY when required numeric features are missing or negative
    req_cols = [c for c in REQUIRED_NUMERIC_FEATURES if c in df.columns]
    nan_mask = df[req_cols].isna().any(axis=1)
    neg_mask = (df[req_cols] < 0).any(axis=1)
    drop_mask = nan_mask | neg_mask
    dropped_count = int(drop_mask.sum())
    if dropped_count > 0:
        info["exclusion_reasons"]["invalid_or_missing_required_numerics"] = dropped_count
        df = df.loc[~drop_mask].reset_index(drop=True)

    info["dropped_required_nan_rows"] = dropped_count
    info["cleaned_rows"] = len(df)

    # Clean labels (rejects string 'nan' / 'none')
    if _LABEL_COL not in df.columns:
        raise ValueError("ToN-IoT dataset missing 'label' column")

    y_binary, exclusions = clean_labels(df[_LABEL_COL], domain="ton_iot")
    info["exclusion_reasons"].update(exclusions)

    # Keep only valid-label rows
    valid_mask = y_binary.notna()
    df = df.loc[valid_mask].reset_index(drop=True)
    y_binary = y_binary.loc[valid_mask].astype(int).reset_index(drop=True)
    info["valid_label_rows"] = len(df)

    # Subsample to exact requested size
    if sample_n and len(df) > sample_n:
        idx = df.sample(n=sample_n, random_state=seed).index
        df = df.loc[idx].reset_index(drop=True)
        y_binary = y_binary.loc[idx].reset_index(drop=True)
        info["sampled_to"] = sample_n

    # Encode to EXPECTED_FEATURES (no scaling)
    X_encoded = encode_dataframe(df)

    info["final_shape"] = X_encoded.shape
    info["class_counts"] = {str(k): int(v) for k, v in y_binary.value_counts().items()}

    return X_encoded, y_binary, info
