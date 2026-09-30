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

from sentrix_ml.schema import NUMERIC_FEATURE_NAMES, EXPECTED_FEATURES
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
        sample_n: Subsample to this many rows after loading
        seed: Random seed for sampling

    Returns:
        (X_encoded, y_binary, info) where X_encoded has EXPECTED_FEATURES columns,
        y_binary is 0/1, and info contains row counts and exclusions.
    """
    data_dir = Path(data_dir)
    all_files = sorted(glob.glob(str(data_dir / "Network_dataset_*.csv")))
    if not all_files:
        raise FileNotFoundError(f"No ToN-IoT files found in {data_dir}")

    if max_files:
        all_files = all_files[:max_files]

    chunks = []
    for f in all_files:
        chunk = pd.read_csv(f, low_memory=False, nrows=nrows_per_file)
        chunks.append(chunk)
    df = pd.concat(chunks, ignore_index=True)

    info = {"raw_rows": len(df), "files_loaded": len(all_files)}

    # Drop identifier columns
    df.drop(
        columns=[c for c in _DROP_COLUMNS if c in df.columns],
        inplace=True,
    )

    # Coerce numeric columns
    for col in df.select_dtypes(include=["object"]).columns:
        if col not in (_LABEL_COL, _TYPE_COL, "proto", "conn_state"):
            df[col] = pd.to_numeric(df[col].replace("-", np.nan), errors="coerce")

    # Replace infinities and drop rows with NaN in critical features
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    before = len(df)
    df.dropna(subset=[c for c in NUMERIC_FEATURE_NAMES if c in df.columns], inplace=True)
    info["dropped_nan_rows"] = before - len(df)
    info["cleaned_rows"] = len(df)

    # Clean labels
    if _LABEL_COL not in df.columns:
        raise ValueError("ToN-IoT dataset missing 'label' column")

    y_binary, exclusions = clean_labels(df[_LABEL_COL], domain="ton_iot")
    info["label_exclusions"] = exclusions

    # Keep only valid-label rows
    valid_mask = y_binary.notna()
    df = df.loc[valid_mask].reset_index(drop=True)
    y_binary = y_binary.loc[valid_mask].astype(int).reset_index(drop=True)
    info["valid_label_rows"] = len(df)

    # Subsample if requested
    if sample_n and len(df) > sample_n:
        idx = df.sample(n=sample_n, random_state=seed).index
        df = df.loc[idx].reset_index(drop=True)
        y_binary = y_binary.loc[idx].reset_index(drop=True)
        info["sampled_to"] = sample_n

    # Encode to EXPECTED_FEATURES (no scaling)
    X_encoded = encode_dataframe(df)

    info["final_shape"] = X_encoded.shape
    info["class_counts"] = dict(y_binary.value_counts())

    return X_encoded, y_binary, info
