"""CIC-IDS2017 dataset adapter.

Reads raw CIC-IDS2017 CSV files (or pre-mapped CSV), performs schema mapping,
cleans labels, and produces a canonical DataFrame with the SENTRi-X schema.

Key corrections vs original notebook:
* Duration converted from microseconds to seconds.
* Explicit handling of missing proto and conn_state (neutral injection).
* No full-dataset scaling during ingestion.
* Labels cleaned with clean_labels.
"""

from __future__ import annotations

import glob
from pathlib import Path

import numpy as np
import pandas as pd

from sentrix_ml.schema import (
    EXPECTED_FEATURES,
    REQUIRED_NUMERIC_FEATURES,
    OPTIONAL_NUMERIC_FEATURES,
)
from sentrix_ml.preprocessing import encode_dataframe
from sentrix_ml.splits import clean_labels


SCHEMA_MAPPING = {
    "total length of fwd packets": "src_bytes",
    "total length of bwd packets": "dst_bytes",
    "total fwd packets": "src_pkts",
    "total backward packets": "dst_pkts",
    "flow duration": "duration",
}


def load_cic_ids2017(
    data_dir: str | Path,
    *,
    use_mapped: bool = False,
    allow_legacy_mapped: bool = False,
    max_files: int | None = None,
    nrows_per_file: int | None = None,
    sample_n: int | None = None,
    seed: int = 42,
    convert_duration_us: bool = True,
) -> tuple[pd.DataFrame, pd.Series, dict]:
    """Load and clean CIC-IDS2017 dataset.

    Args:
        data_dir: Path to data/raw/cic_ids2017/
        use_mapped: If True, load cic_ids2017_mapped.csv (requires allow_legacy_mapped=True)
        allow_legacy_mapped: Explicit acknowledgement that legacy mapped file is used
        max_files: Load at most this many raw files
        nrows_per_file: Read at most this many rows per file
        sample_n: Subsample to this many rows (bounds ingestion memory)
        seed: Random seed for sampling
        convert_duration_us: Convert duration from microseconds to seconds (divide by 1e6)

    Returns:
        (X_encoded, y_binary, info)
    """
    data_dir = Path(data_dir)
    info = {
        "domain": "cic_ids2017",
        "duration_unit": "seconds",
        "exclusion_reasons": {},
    }

    if use_mapped:
        if not allow_legacy_mapped:
            raise ValueError(
                "Legacy mapped CIC-IDS2017 CSV has unverified unit/scale provenance. "
                "Rebuild from raw CSVs or explicitly pass allow_legacy_mapped=True."
            )
        mapped_path = data_dir / "cic_ids2017_mapped.csv"
        if not mapped_path.exists():
            mapped_path = data_dir.parent.parent / "cic_ids2017_mapped.csv"
        if not mapped_path.exists():
            raise FileNotFoundError(f"Missing mapped file: {mapped_path}")
        df = pd.read_csv(mapped_path, low_memory=False, nrows=nrows_per_file or sample_n)
        info["files_loaded"] = [str(mapped_path)]
        info["source_type"] = "legacy_mapped_csv"
        # Check if duration is in microseconds
        if "duration" in df.columns:
            dur_series = pd.to_numeric(df["duration"], errors="coerce")
            if dur_series.median() > 1000.0 and convert_duration_us:
                df["duration"] = dur_series / 1e6
                info["duration_converted_from_us"] = True
    else:
        if data_dir.is_file():
            all_files = [str(data_dir)]
        else:
            all_files = sorted(
                [
                    f for f in glob.glob(str(data_dir / "*.csv"))
                    if not f.endswith("mapped.csv") and not f.endswith("cic_ids2017_mapped.csv")
                ]
            )
        if not all_files:
            raise FileNotFoundError(
                f"No CIC-IDS2017 raw CSV files found in {data_dir}. "
                "Raw CSV files are required for uncompromised provenance."
            )

        if max_files:
            all_files = all_files[:max_files]

        effective_nrows = nrows_per_file
        if effective_nrows is None and sample_n is not None:
            effective_nrows = int(np.ceil((sample_n * 1.5) / len(all_files))) + 100

        chunks = []
        for f in all_files:
            try:
                chunk = pd.read_csv(f, encoding="cp1252", low_memory=False, nrows=effective_nrows)
            except UnicodeDecodeError:
                chunk = pd.read_csv(f, encoding="utf-8", errors="replace", low_memory=False, nrows=effective_nrows)
            chunks.append(chunk)
        df = pd.concat(chunks, ignore_index=True)
        info["files_loaded"] = all_files
        info["source_type"] = "raw_csvs"

        # Strip whitespace and lowercase column names
        df.columns = df.columns.str.strip().str.lower()

        # Rename to canonical schema
        df.rename(columns=SCHEMA_MAPPING, inplace=True)

        # Convert duration from microseconds to seconds
        if convert_duration_us and "duration" in df.columns:
            df["duration"] = pd.to_numeric(df["duration"], errors="coerce") / 1e6
            info["duration_converted_from_us"] = True

        # Injected columns for missing network fields
        if "proto" not in df.columns:
            df["proto"] = "other"
        if "conn_state" not in df.columns:
            df["conn_state"] = "OTH"

    info["raw_rows"] = len(df)

    # Standardize label column
    label_col = "label"
    if "label" not in df.columns and "label" in [c.lower() for c in df.columns]:
        for c in df.columns:
            if c.lower() == "label":
                df.rename(columns={c: "label"}, inplace=True)
                break

    if "label" not in df.columns:
        raise ValueError("CIC-IDS2017 missing label column")

    # Optional numeric features: impute absent with 0.0
    for col in OPTIONAL_NUMERIC_FEATURES:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col].replace("-", np.nan), errors="coerce").fillna(0.0)

    # Required numeric features: coerce to float
    for col in REQUIRED_NUMERIC_FEATURES:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col].replace("-", np.nan), errors="coerce")

    # Replace infinities
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

    # Clean labels
    y_binary, exclusions = clean_labels(df["label"], domain="cic_ids2017")
    info["exclusion_reasons"].update(exclusions)

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

    X_encoded = encode_dataframe(df)
    info["final_shape"] = X_encoded.shape
    info["class_counts"] = {str(k): int(v) for k, v in y_binary.value_counts().items()}

    return X_encoded, y_binary, info
