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

from sentrix_ml.schema import EXPECTED_FEATURES, NUMERIC_FEATURE_NAMES
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
    max_files: int | None = None,
    nrows_per_file: int | None = None,
    sample_n: int | None = None,
    seed: int = 42,
    convert_duration_us: bool = True,
) -> tuple[pd.DataFrame, pd.Series, dict]:
    """Load and clean CIC-IDS2017 dataset.

    Args:
        data_dir: Path to data/raw/cic_ids2017/
        use_mapped: If True, load cic_ids2017_mapped.csv directly
        max_files: Load at most this many raw files
        nrows_per_file: Read at most this many rows per file
        sample_n: Subsample to this many rows
        seed: Random seed for sampling
        convert_duration_us: If True, convert duration from microseconds to seconds (divide by 1e6)

    Returns:
        (X_encoded, y_binary, info)
    """
    data_dir = Path(data_dir)
    info = {"domain": "cic_ids2017"}

    if use_mapped:
        mapped_path = data_dir / "cic_ids2017_mapped.csv"
        if not mapped_path.exists():
            raise FileNotFoundError(f"Missing mapped file: {mapped_path}")
        df = pd.read_csv(mapped_path, low_memory=False, nrows=nrows_per_file)
        info["files_loaded"] = [str(mapped_path)]
    else:
        all_files = sorted(
            [
                f for f in glob.glob(str(data_dir / "*.csv"))
                if not f.endswith("cic_ids2017_mapped.csv")
            ]
        )
        if not all_files:
            mapped_path = data_dir / "cic_ids2017_mapped.csv"
            if mapped_path.exists():
                return load_cic_ids2017(
                    data_dir,
                    use_mapped=True,
                    nrows_per_file=nrows_per_file,
                    sample_n=sample_n,
                    seed=seed,
                )
            raise FileNotFoundError(f"No CIC-IDS2017 raw files found in {data_dir}")

        if max_files:
            all_files = all_files[:max_files]

        chunks = []
        for f in all_files:
            try:
                chunk = pd.read_csv(f, encoding="cp1252", low_memory=False, nrows=nrows_per_file)
            except UnicodeDecodeError:
                chunk = pd.read_csv(f, encoding="utf-8", errors="replace", low_memory=False, nrows=nrows_per_file)
            chunks.append(chunk)
        df = pd.concat(chunks, ignore_index=True)
        info["files_loaded"] = all_files

        # Strip whitespace and lowercase column names
        df.columns = df.columns.str.strip().str.lower()

        # Rename to canonical schema
        df.rename(columns=SCHEMA_MAPPING, inplace=True)

        # Convert duration from microseconds to seconds
        if convert_duration_us and "duration" in df.columns:
            df["duration"] = pd.to_numeric(df["duration"], errors="coerce") / 1e6

        # Injected columns
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

    # Coerce numeric columns
    for col in df.select_dtypes(include=["object"]).columns:
        if col not in ("label", "proto", "conn_state"):
            df[col] = pd.to_numeric(df[col].replace("-", np.nan), errors="coerce")

    # Replace infinities and drop NaNs in key numerics
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    before = len(df)
    key_numerics = [c for c in NUMERIC_FEATURE_NAMES if c in df.columns]
    if key_numerics:
        df.dropna(subset=key_numerics, inplace=True)
    info["dropped_nan_rows"] = before - len(df)

    # Clean labels
    y_binary, exclusions = clean_labels(df["label"], domain="cic_ids2017")
    info["label_exclusions"] = exclusions

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

    X_encoded = encode_dataframe(df)
    info["final_shape"] = X_encoded.shape
    info["class_counts"] = dict(y_binary.value_counts())

    return X_encoded, y_binary, info
