"""CIC-IDS2017 dataset adapter.

Reads raw CIC-IDS2017 CSV files (or pre-mapped CSV), performs schema mapping,
cleans labels, and produces a canonical DataFrame with the SENTRi-X schema.

Key corrections vs original:
* Full source population traversal across all files without early termination.
* Deterministic bounded reservoir sampling (Algorithm R) bounds RAM to O(K).
* Preserves true population class prevalence for evaluation holdouts.
* Retains raw source metadata (file, row, flow ID, 5-tuple group ID) outside predictors.
* Duration converted from microseconds to seconds.
* Explicit handling of missing proto and conn_state (neutral injection).
* SHA-256 file hashing and complete provenance tracking.
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
from sentrix_ml.sampler import stream_dataset_files, file_sha256
from sentrix_ml.provenance import raw_metadata_factory


SCHEMA_MAPPING = {
    "total length of fwd packets": "src_bytes",
    "total length of bwd packets": "dst_bytes",
    "total fwd packets": "src_pkts",
    "total backward packets": "dst_pkts",
    "flow duration": "duration",
}

MANDATORY_RAW_COLUMNS = [
    "flow duration",
    "total fwd packets",
    "total backward packets",
    "total length of fwd packets",
    "total length of bwd packets",
]

_DROP_METADATA_COLUMNS = [
    "flow id", "source ip", "source port", "destination ip", "destination port",
    "timestamp", "external ip",
]


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
    chunksize: int = 50_000,
) -> tuple[pd.DataFrame, pd.Series, dict]:
    """Load and clean CIC-IDS2017 dataset.

    Args:
        data_dir: Path to data/raw/cic_ids2017/ or single CSV file
        use_mapped: If True, load cic_ids2017_mapped.csv (requires allow_legacy_mapped=True)
        allow_legacy_mapped: Explicit acknowledgement that legacy mapped file is used
        max_files: Load at most this many raw files
        nrows_per_file: Read at most this many rows per file
        sample_n: Subsample to this many rows using reservoir sampling
        seed: Random seed for sampling
        convert_duration_us: Convert duration from microseconds to seconds (divide by 1e6)

    Returns:
        (X_encoded, y_binary, info)
    """
    data_dir = Path(data_dir)
    info: dict = {
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

        info["files_considered"] = [mapped_path.name]
        info["files_loaded"] = 1
        info["source_file_hashes"] = {mapped_path.name: file_sha256(mapped_path)}
        info["source_type"] = "legacy_mapped_csv"
        info["selection_policy"] = "head_read"

        df = pd.read_csv(mapped_path, low_memory=False, nrows=nrows_per_file or sample_n)
        if "duration" in df.columns:
            dur_series = pd.to_numeric(df["duration"], errors="coerce")
            if dur_series.median() > 1000.0 and convert_duration_us:
                df["duration"] = dur_series / 1e6
                info["duration_converted_from_us"] = True

        label_col = "label" if "label" in df.columns else None
        if label_col is None:
            raise ValueError("CIC-IDS2017 missing label column")

        y_binary, exclusions = clean_labels(df[label_col], domain="cic_ids2017")
        info["exclusion_reasons"].update(exclusions)
        valid_mask = y_binary.notna()
        df = df.loc[valid_mask].reset_index(drop=True)
        y_binary = y_binary.loc[valid_mask].astype(int).reset_index(drop=True)

        meta_df = pd.DataFrame({
            "source_file": [mapped_path.name] * len(df),
            "source_row_index": list(range(len(df))),
            "source_flow_id": [f"{mapped_path.name}:{i}" for i in range(len(df))],
            "group_id": [f"mapped_flow:{i}" for i in range(len(df))],
        })
        info["metadata"] = meta_df
        X_encoded = encode_dataframe(df)
        info["final_shape"] = X_encoded.shape
        info["class_counts"] = {str(k): int(v) for k, v in y_binary.value_counts().items()}
        return X_encoded, y_binary, info

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

    def _clean_and_extract_cic_chunk(
        chunk: pd.DataFrame,
        fname: str,
        row_offset: int,
    ) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series, dict[str, int]]:
        chunk_len = len(chunk)
        # Normalize column names
        chunk.columns = chunk.columns.str.strip().str.lower()

        missing = [c for c in MANDATORY_RAW_COLUMNS if c not in chunk.columns and SCHEMA_MAPPING.get(c) not in chunk.columns]
        if missing:
            raise ValueError(
                f"CIC-IDS2017 raw dataset is missing mandatory traffic columns: {missing}. "
                "A dataset with only labels is invalid."
            )
        if "label" not in chunk.columns:
            raise ValueError("CIC-IDS2017 dataset missing label column")

        chunk = chunk.reset_index(drop=True)
        metadata_for_row = raw_metadata_factory(
            chunk, domain="cic_ids2017", filename=fname, row_offset=row_offset,
            tuple_columns=["source ip", "source port", "destination ip", "destination port", "protocol"], time_column="timestamp",
        )
        has_flowid = "flow id" in chunk.columns
        has_ts = "timestamp" in chunk.columns

        # Rename to canonical schema
        chunk.rename(columns=SCHEMA_MAPPING, inplace=True)

        # Convert duration from microseconds to seconds
        if convert_duration_us and "duration" in chunk.columns:
            chunk["duration"] = pd.to_numeric(chunk["duration"], errors="coerce") / 1e6

        # Injected columns for missing network fields
        if "proto" not in chunk.columns:
            chunk["proto"] = chunk["protocol"].astype(str).str.strip().replace({"6": "tcp", "17": "udp", "6.0": "tcp", "17.0": "udp"}) if "protocol" in chunk else "other"
        if "conn_state" not in chunk.columns:
            chunk["conn_state"] = "OTH"

        # Clean labels
        y_bin, exclusions = clean_labels(chunk["label"], domain="cic_ids2017")

        # Coerce optional numerics
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

        chunk.replace([np.inf, -np.inf], np.nan, inplace=True)

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

        def meta_fn(idx: int) -> dict:
            return metadata_for_row(raw_valid.index[idx])

        drop_now = [c for c in _DROP_METADATA_COLUMNS + ["label"] if c in clean_chunk.columns]
        clean_chunk.drop(columns=drop_now, inplace=True)

        return clean_chunk, meta_fn, clean_y, exclusions

    features_df, y_binary, metadata_df, stream_info = stream_dataset_files(
        all_files,
        clean_and_extract_fn=_clean_and_extract_cic_chunk,
        sample_n=sample_n,
        seed=seed,
        chunksize=chunksize,
        nrows_per_file=nrows_per_file,
        read_csv_kwargs={"dtype": str},
    )

    info.update(stream_info)
    info["source_type"] = "raw_csvs"
    info["duration_converted_from_us"] = convert_duration_us
    info["raw_rows"] = info["total_rows_considered"]
    info["cleaned_rows"] = info["total_valid_rows"]
    info["valid_label_rows"] = info["total_valid_rows"]
    if sample_n:
        info["sampled_to"] = len(y_binary)

    if len(features_df) > 0:
        X_encoded = encode_dataframe(features_df)
    else:
        X_encoded = pd.DataFrame(columns=EXPECTED_FEATURES)

    info.update(max_files=max_files, chunksize=chunksize)
    info["final_shape"] = X_encoded.shape
    info["class_counts"] = {str(k): int(v) for k, v in y_binary.value_counts().items()}

    return X_encoded, y_binary, info
