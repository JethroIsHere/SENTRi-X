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

from sentrix_ml.schema import (
    EXPECTED_FEATURES,
    REQUIRED_NUMERIC_FEATURES,
    OPTIONAL_NUMERIC_FEATURES,
    UNRESOLVED_MAPPINGS,
)
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

MANDATORY_RAW_COLUMNS = ["dur", "spkts", "dpkts", "sbytes", "dbytes"]

SCHEMA_MAPPING_BASE = {
    "sbytes": "src_bytes",
    "dbytes": "dst_bytes",
    "spkts": "src_pkts",
    "dpkts": "dst_pkts",
    "dur": "duration",
    "state": "conn_state",
    "proto": "proto",
    "attack": "label",
}


def load_bot_iot(
    data_dir: str | Path,
    *,
    use_mapped: bool = False,
    allow_legacy_mapped: bool = False,
    max_files: int | None = None,
    nrows_per_file: int | None = None,
    sample_n: int | None = None,
    seed: int = 42,
    ip_bytes_policy: str = "exclude",
) -> tuple[pd.DataFrame, pd.Series, dict]:
    """Load and clean BoT-IoT dataset.

    Args:
        data_dir: Path to data/raw/bot_iot/
        use_mapped: If True, load bot_iot_mapped.csv directly instead of raw chunks
        allow_legacy_mapped: Acknowledge use of pre-mapped file
        max_files: Load at most this many raw files
        nrows_per_file: Read at most this many rows per file
        sample_n: Subsample to this many rows (bounds ingestion memory)
        seed: Random seed for sampling
        ip_bytes_policy: 'exclude' (default, excludes per-IP aggregate TnBPSrcIP/TnBPDstIP to prevent cross-flow corruption)
                         or 'aggregate_proxy' (maps TnBPSrcIP/TnBPDstIP as proxy flow bytes)

    Returns:
        (X_encoded, y_binary, info)
    """
    data_dir = Path(data_dir)
    mapping = dict(SCHEMA_MAPPING_BASE)
    if ip_bytes_policy == "aggregate_proxy":
        mapping["TnBPSrcIP"] = "src_ip_bytes"
        mapping["TnBPDstIP"] = "dst_ip_bytes"

    unresolved = [m for m in UNRESOLVED_MAPPINGS if "BoT-IoT" in m]
    if ip_bytes_policy == "exclude":
        unresolved = [m for m in unresolved if "TnBPSrcIP" not in m and "TnBPDstIP" not in m]

    info = {
        "domain": "bot_iot",
        "exclusion_reasons": {},
        "ip_bytes_policy": ip_bytes_policy,
        "unresolved_mappings": unresolved,
    }

    if use_mapped:
        if not allow_legacy_mapped:
            raise ValueError(
                "Legacy mapped BoT-IoT CSV has unverified unit/scale provenance. "
                "Rebuild from raw CSVs or explicitly pass allow_legacy_mapped=True."
            )
        mapped_path = data_dir / "bot_iot_mapped.csv"
        if not mapped_path.exists():
            mapped_path = data_dir.parent.parent / "bot_iot_mapped.csv"
        if not mapped_path.exists():
            raise FileNotFoundError(f"Missing mapped file: {mapped_path}")
        df = pd.read_csv(mapped_path, low_memory=False, nrows=nrows_per_file or sample_n)
        info["files_loaded"] = [str(mapped_path)]
        info["source_type"] = "legacy_mapped_csv"
    else:
        if data_dir.is_file():
            all_files = [str(data_dir)]
        else:
            all_files = sorted(glob.glob(str(data_dir / "UNSW_2018_IoT_Botnet_Full5pc_*.csv")))
            if not all_files:
                all_files = sorted(glob.glob(str(data_dir / "*.csv")))
        if not all_files:
            raise FileNotFoundError(f"No BoT-IoT raw CSV files found in {data_dir}")

        if max_files:
            all_files = all_files[:max_files]

        info["files_loaded"] = all_files
        info["source_type"] = "raw_csvs"

        if sample_n is not None and nrows_per_file is None:
            chunksize = max(500, min(5000, sample_n * 2))
            target_0 = sample_n // 2
            target_1 = sample_n - target_0
            pool_0 = []
            pool_1 = []

            # In the BoT-IoT dataset, all normal flows are in file 4 around line 576,884
            f4_candidates = [f for f in all_files if "Full5pc_4.csv" in f or f.endswith("_4.csv")]
            if f4_candidates:
                f4 = f4_candidates[0]
                try:
                    benign_slice = pd.read_csv(f4, skiprows=range(1, 576884), nrows=min(1000, max(50, target_0 * 2)), low_memory=False)
                    label_key = "label" if "label" in benign_slice.columns else ("attack" if "attack" in benign_slice.columns else None)
                    if label_key is not None:
                        y_b, _ = clean_labels(benign_slice[label_key], domain="bot_iot")
                        m0 = (y_b == 0)
                        if m0.any():
                            pool_0.append(benign_slice.loc[m0])
                except Exception:
                    pass

            count_0 = sum(len(p) for p in pool_0)
            count_1 = 0

            for f in all_files:
                for chunk_idx, chunk in enumerate(pd.read_csv(f, chunksize=chunksize, low_memory=False)):
                    # Validate raw columns
                    missing = [c for c in MANDATORY_RAW_COLUMNS if c not in chunk.columns]
                    if missing:
                        raise ValueError(
                            f"BoT-IoT raw dataset is missing mandatory traffic columns: {missing}. "
                            "A dataset with only labels is invalid."
                        )
                    label_key = "label" if "label" in chunk.columns else ("attack" if "attack" in chunk.columns else None)
                    if label_key is None:
                        raise ValueError("BoT-IoT dataset missing label/attack column")

                    y_bin, _ = clean_labels(chunk[label_key], domain="bot_iot")
                    m0 = (y_bin == 0)
                    m1 = (y_bin == 1)

                    if m0.any() and count_0 < target_0 * 3:
                        pool_0.append(chunk.loc[m0])
                        count_0 += int(m0.sum())
                    if m1.any() and count_1 < target_1 * 3:
                        pool_1.append(chunk.loc[m1])
                        count_1 += int(m1.sum())

                    if count_1 >= target_1 and (count_0 >= target_0 or not f4_candidates or len(all_files) == 1):
                        break
                    if len(all_files) > 1 and chunk_idx >= 4:
                        break
                if count_1 >= target_1 and (count_0 >= target_0 or not f4_candidates or len(all_files) == 1):
                    break

            if pool_0 and pool_1:
                df0 = pd.concat(pool_0, ignore_index=True)
                df1 = pd.concat(pool_1, ignore_index=True)
                n0 = min(target_0, len(df0))
                n1 = min(target_1, len(df1))
                if n0 + n1 < sample_n:
                    if len(df0) > n0:
                        n0 = min(sample_n - n1, len(df0))
                    elif len(df1) > n1:
                        n1 = min(sample_n - n0, len(df1))
                s0 = df0.sample(n=n0, random_state=seed) if len(df0) > n0 else df0
                s1 = df1.sample(n=n1, random_state=seed) if len(df1) > n1 else df1
                df = pd.concat([s0, s1], ignore_index=True).sample(frac=1.0, random_state=seed).reset_index(drop=True)
            elif pool_0:
                df0 = pd.concat(pool_0, ignore_index=True)
                df = df0.sample(n=min(sample_n, len(df0)), random_state=seed).reset_index(drop=True)
            elif pool_1:
                df1 = pd.concat(pool_1, ignore_index=True)
                df = df1.sample(n=min(sample_n, len(df1)), random_state=seed).reset_index(drop=True)
            else:
                df = pd.DataFrame()
        else:
            chunks = []
            for f in all_files:
                chunk = pd.read_csv(f, low_memory=False, nrows=nrows_per_file)
                chunks.append(chunk)
            df = pd.concat(chunks, ignore_index=True)
            missing = [c for c in MANDATORY_RAW_COLUMNS if c not in df.columns]
            if missing:
                raise ValueError(
                    f"BoT-IoT raw dataset is missing mandatory traffic columns: {missing}. "
                    "A dataset with only labels is invalid."
                )

        # State translation
        if "state" in df.columns:
            df["state"] = df["state"].astype(str).str.strip().replace(STATE_TRANSLATOR)

        # Rename columns to standard schema
        df.rename(columns=mapping, inplace=True)

    info["raw_rows"] = len(df)

    # Coerce numeric columns
    label_col = "label" if "label" in df.columns else ("attack" if "attack" in df.columns else None)
    if label_col is None:
        raise ValueError("BoT-IoT missing label column")

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
    y_binary, exclusions = clean_labels(df[label_col], domain="bot_iot")
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
