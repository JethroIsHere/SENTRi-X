"""BoT-IoT dataset adapter.

Reads raw BoT-IoT CSV chunks (or pre-mapped CSV), performs dialect translation,
cleans labels, and produces a canonical DataFrame with the SENTRi-X schema.

Key corrections vs original notebook:
* Log/quantile transforms are NOT applied during data ingestion (no leakage).
  Scaling is delegated to PreprocessingPipeline fitted on train split.
* Labels cleaned using clean_labels (rejects string 'nan').
* Explicit flag for TnBPSrcIP/TnBPDstIP aggregate semantic mismatch.
"""

from __future__ import annotations

import glob
from pathlib import Path

import numpy as np
import pandas as pd

from sentrix_ml.schema import EXPECTED_FEATURES, NUMERIC_FEATURE_NAMES
from sentrix_ml.preprocessing import encode_dataframe
from sentrix_ml.splits import clean_labels


STATE_TRANSLATOR = {
    "CON": "SF",
    "RST": "RSTR",
    "REQ": "S0",
    "INT": "OTH",
    "FIN": "SF",
    "URP": "OTH",
}

SCHEMA_MAPPING = {
    "sbytes": "src_bytes",
    "dbytes": "dst_bytes",
    "spkts": "src_pkts",
    "dpkts": "dst_pkts",
    "dur": "duration",
    "TnBPSrcIP": "src_ip_bytes",
    "TnBPDstIP": "dst_ip_bytes",
    "state": "conn_state",
    "proto": "proto",
    "attack": "label",
}


def load_bot_iot(
    data_dir: str | Path,
    *,
    use_mapped: bool = False,
    max_files: int | None = None,
    nrows_per_file: int | None = None,
    sample_n: int | None = None,
    seed: int = 42,
) -> tuple[pd.DataFrame, pd.Series, dict]:
    """Load and clean BoT-IoT dataset.

    Args:
        data_dir: Path to data/raw/bot_iot/
        use_mapped: If True, load bot_iot_mapped.csv directly instead of raw chunks
        max_files: Load at most this many raw files
        nrows_per_file: Read at most this many rows per file
        sample_n: Subsample to this many rows
        seed: Random seed for sampling

    Returns:
        (X_encoded, y_binary, info)
    """
    data_dir = Path(data_dir)
    info = {"domain": "bot_iot"}

    if use_mapped:
        mapped_path = data_dir / "bot_iot_mapped.csv"
        if not mapped_path.exists():
            raise FileNotFoundError(f"Missing mapped file: {mapped_path}")
        df = pd.read_csv(mapped_path, low_memory=False, nrows=nrows_per_file)
        info["files_loaded"] = [str(mapped_path)]
    else:
        all_files = sorted(glob.glob(str(data_dir / "UNSW_2018_IoT_Botnet_Full5pc_*.csv")))
        if not all_files:
            mapped_path = data_dir / "bot_iot_mapped.csv"
            if mapped_path.exists():
                return load_bot_iot(
                    data_dir,
                    use_mapped=True,
                    nrows_per_file=nrows_per_file,
                    sample_n=sample_n,
                    seed=seed,
                )
            raise FileNotFoundError(f"No BoT-IoT files found in {data_dir}")

        if max_files:
            all_files = all_files[:max_files]

        chunks = []
        for f in all_files:
            chunk = pd.read_csv(f, low_memory=False, nrows=nrows_per_file)
            chunks.append(chunk)
        df = pd.concat(chunks, ignore_index=True)
        info["files_loaded"] = all_files

        # State translation
        if "state" in df.columns:
            df["state"] = df["state"].astype(str).str.strip().replace(STATE_TRANSLATOR)

        # Rename columns to standard schema
        df.rename(columns=SCHEMA_MAPPING, inplace=True)

    info["raw_rows"] = len(df)

    # Coerce numeric columns
    label_col = "label" if "label" in df.columns else ("attack" if "attack" in df.columns else None)
    if label_col is None:
        raise ValueError("BoT-IoT missing label column")

    for col in df.select_dtypes(include=["object"]).columns:
        if col not in (label_col, "proto", "conn_state", "category", "subcategory"):
            df[col] = pd.to_numeric(df[col].replace("-", np.nan), errors="coerce")

    # Replace infinities and drop NaNs in key numerics
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    before = len(df)
    key_numerics = [c for c in NUMERIC_FEATURE_NAMES if c in df.columns]
    if key_numerics:
        df.dropna(subset=key_numerics, inplace=True)
    info["dropped_nan_rows"] = before - len(df)

    # Clean labels
    y_binary, exclusions = clean_labels(df[label_col], domain="bot_iot")
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
