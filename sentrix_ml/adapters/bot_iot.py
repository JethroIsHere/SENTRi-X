"""BoT-IoT dataset adapter.

Reads raw BoT-IoT CSV chunks (or pre-mapped CSV), performs dialect translation,
cleans labels, and produces a canonical DataFrame with the SENTRi-X schema.

Key corrections vs original:
* Full source population traversal across all files without early termination.
* Unverified hardcoded row-position slice (skiprows near 576884) removed.
* Deterministic bounded reservoir sampling (Algorithm R) bounds RAM to O(K).
* Preserves true population class prevalence for evaluation holdouts.
* Retains raw source metadata (file, row, pkSeqID, 5-tuple group ID) outside predictors.
* Explicit flag for TnBPSrcIP/TnBPDstIP aggregate semantic mismatch.
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
    UNRESOLVED_MAPPINGS,
)
from sentrix_ml.preprocessing import encode_dataframe
from sentrix_ml.splits import clean_labels
from sentrix_ml.sampler import stream_dataset_files, file_sha256, StratifiedReservoirBuffer
from sentrix_ml.provenance import raw_metadata_factory


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

_DROP_METADATA_COLUMNS = [
    "pkSeqID", "saddr", "sport", "daddr", "dport", "seq", "flgs",
    "category", "subcategory", "stime", "ltime", "TnBPSrcIP", "TnBPDstIP",
    "TnP_PSrcIP", "TnP_PDstIP", "TnP_PerProto", "TnP_Per_Dport", "AR_P_Proto_P_Dport",
]


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
    chunksize: int = 50_000,
) -> tuple[pd.DataFrame, pd.Series, dict]:
    """Load and clean BoT-IoT dataset.

    Args:
        data_dir: Path to data/raw/bot_iot/
        use_mapped: If True, load bot_iot_mapped.csv directly instead of raw chunks
        allow_legacy_mapped: Acknowledge use of pre-mapped file
        max_files: Load at most this many raw files
        nrows_per_file: Read at most this many rows per file
        sample_n: Subsample to this many rows using reservoir sampling
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

    info: dict = {
        "domain": "bot_iot",
        "ip_bytes_policy": ip_bytes_policy,
        "unresolved_mappings": unresolved,
        "exclusion_reasons": {},
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

        info["files_considered"] = [mapped_path.name]
        info["files_loaded"] = 1
        info["source_file_hashes"] = {mapped_path.name: file_sha256(mapped_path)}
        info["source_type"] = "legacy_mapped_csv"
        info["selection_policy"] = "head_read"

        df = pd.read_csv(mapped_path, low_memory=False, nrows=nrows_per_file or sample_n)
        label_col = "label" if "label" in df.columns else ("attack" if "attack" in df.columns else None)
        if label_col is None:
            raise ValueError("BoT-IoT missing label column")

        y_binary, exclusions = clean_labels(df[label_col], domain="bot_iot")
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
        all_files = sorted(glob.glob(str(data_dir / "UNSW_2018_IoT_Botnet_Full5pc_*.csv")))
        if not all_files:
            all_files = sorted(glob.glob(str(data_dir / "*.csv")))
    if not all_files:
        raise FileNotFoundError(f"No BoT-IoT raw CSV files found in {data_dir}")

    if max_files:
        all_files = all_files[:max_files]

    def _clean_and_extract_bot_chunk(
        chunk: pd.DataFrame,
        fname: str,
        row_offset: int,
    ) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series, dict[str, int]]:
        chunk_len = len(chunk)
        # Check mandatory columns
        missing = [c for c in MANDATORY_RAW_COLUMNS if c not in chunk.columns and mapping.get(c) not in chunk.columns]
        if missing:
            raise ValueError(
                f"BoT-IoT raw dataset is missing mandatory traffic columns: {missing}. "
                "A dataset with only labels is invalid."
            )
        label_raw = "attack" if "attack" in chunk.columns else ("label" if "label" in chunk.columns else None)
        if label_raw is None:
            raise ValueError("BoT-IoT dataset missing label/attack column")

        chunk = chunk.reset_index(drop=True)
        metadata_for_row = raw_metadata_factory(
            chunk, domain="bot_iot", filename=fname, row_offset=row_offset,
            tuple_columns=["saddr", "sport", "daddr", "dport", "proto"], time_column="stime",
        )
        has_pkseq = "pkSeqID" in chunk.columns
        has_cat = "category" in chunk.columns
        has_subcat = "subcategory" in chunk.columns

        # State translation
        if "state" in chunk.columns:
            chunk["state"] = chunk["state"].astype(str).str.strip().replace(STATE_TRANSLATOR)

        # Rename columns to standard schema
        chunk.rename(columns=mapping, inplace=True)

        # Clean labels
        y_bin, exclusions = clean_labels(chunk["label"], domain="bot_iot")

        # Exclude aggregate ip_bytes if policy requires
        if ip_bytes_policy == "exclude":
            chunk["src_ip_bytes"] = 0.0
            chunk["dst_ip_bytes"] = 0.0

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

    # Use stratified reservoir for raw-CSV sampling to guarantee the rare
    # benign class (477 / 3.67M = 0.013%) enters the sample.  Without this,
    # uniform Algorithm R draws only ~4-6 benign rows in a 50k sample,
    # causing PartitionSupportError during stratified splitting.
    buffer = None
    if sample_n is not None and nrows_per_file is None:
        buffer = StratifiedReservoirBuffer(
            capacity=sample_n, minority_label=0, seed=seed,
        )

    features_df, y_binary, metadata_df, stream_info = stream_dataset_files(
        all_files,
        clean_and_extract_fn=_clean_and_extract_bot_chunk,
        sample_n=sample_n,
        seed=seed,
        chunksize=chunksize,
        nrows_per_file=nrows_per_file,
        read_csv_kwargs={"dtype": str},
        reservoir_buffer=buffer,
    )

    info.update(stream_info)
    info["source_type"] = "raw_csvs"
    if buffer is not None:
        info["selection_policy"] = "stratified_reservoir_sampling"
        info["minority_label"] = 0
        info["minority_records_collected"] = len(buffer.minority_records)
        info["majority_records_sampled"] = len(buffer.majority_records)
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
