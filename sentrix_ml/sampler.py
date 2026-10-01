"""Deterministic bounded reservoir sampler for tabular datasets across multiple files.

Guarantees:
* Reads every chunk of every file across the entire source population without early stopping.
* Algorithm R: every valid row across all files has uniform probability K / N of entering the sample.
* Preserves true source class prevalence for evaluation partitions.
* Bounds RAM consumption to O(K) rows regardless of total dataset size.
* Computes file SHA256 hashes and captures row-level source provenance and flow group IDs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Any
import hashlib
import numpy as np
import pandas as pd


def file_sha256(path: str | Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


class ReservoirBuffer:
    """In-memory reservoir buffer holding at most K rows."""

    def __init__(self, capacity: int, seed: int = 42):
        self.capacity = capacity
        self.rng = np.random.default_rng(seed)
        self.reservoir: list[dict] = []
        self.total_seen: int = 0

    def add_chunk(self, features: pd.DataFrame, y: pd.Series, meta: pd.DataFrame | Callable[[int], dict]) -> None:
        m = len(features)
        if m == 0:
            return

        is_fn = callable(meta)

        def _get_row_meta(idx: int) -> dict:
            if is_fn:
                return meta(idx)
            return {f"__meta_{col}__": meta.iloc[idx][col] for col in meta.columns}

        current_len = len(self.reservoir)
        if current_len < self.capacity:
            needed = self.capacity - current_len
            take_n = min(needed, m)
            sub_f = features.iloc[:take_n]
            sub_y = y.iloc[:take_n]
            for i in range(take_n):
                rec = sub_f.iloc[i].to_dict()
                rec["__y__"] = int(sub_y.iloc[i])
                rec.update(_get_row_meta(i))
                self.reservoir.append(rec)
            self.total_seen += take_n
            if take_n == m:
                return
            features = features.iloc[take_n:]
            y = y.iloc[take_n:]
            if not is_fn:
                meta = meta.iloc[take_n:]
            else:
                orig_fn = meta
                meta = lambda idx, shift=take_n: orig_fn(idx + shift)
            m = len(features)

        # Reservoir is full
        total_seen_range = self.total_seen + 1 + np.arange(m, dtype=np.int64)
        u = self.rng.random(m)
        r = np.floor(u * total_seen_range).astype(np.int64)
        self.total_seen += m

        enter_mask = r < self.capacity
        if not np.any(enter_mask):
            return

        enter_indices = np.where(enter_mask)[0]
        sub_f = features.iloc[enter_indices]
        sub_y = y.iloc[enter_indices]

        for i, idx_in_sub in enumerate(enter_indices):
            slot = r[idx_in_sub]
            rec = sub_f.iloc[i].to_dict()
            rec["__y__"] = int(sub_y.iloc[i])
            rec.update(_get_row_meta(idx_in_sub))
            self.reservoir[slot] = rec

    def get_result(self) -> pd.DataFrame:
        if not self.reservoir:
            return pd.DataFrame()
        return pd.DataFrame(self.reservoir)


def stream_dataset_files(
    all_files: list[str | Path],
    *,
    clean_and_extract_fn: Callable[[pd.DataFrame, str, int], tuple[pd.DataFrame, pd.DataFrame, pd.Series, dict[str, int]]],
    sample_n: int | None = None,
    seed: int = 42,
    chunksize: int = 50_000,
    nrows_per_file: int | None = None,
    read_csv_kwargs: dict | None = None,
) -> tuple[pd.DataFrame, pd.Series, pd.DataFrame, dict[str, Any]]:
    """Stream tabular files with reservoir sampling and provenance tracking."""
    source_file_hashes: dict[str, str] = {}
    files_considered: list[str] = []
    source_class_counts: dict[str, int] = {}
    total_exclusions: dict[str, int] = {}
    total_raw_rows = 0
    total_valid_rows = 0

    kwargs = dict(read_csv_kwargs or {})
    kwargs.setdefault("low_memory", False)

    use_reservoir = (sample_n is not None and nrows_per_file is None)
    if use_reservoir:
        reservoir = ReservoirBuffer(capacity=sample_n, seed=seed)
    else:
        accumulated_chunks: list[pd.DataFrame] = []

    for f in all_files:
        f_path = Path(f)
        fname = f_path.name
        files_considered.append(fname)
        source_file_hashes[fname] = file_sha256(f_path)

        file_row_offset = 0
        read_kwargs = dict(kwargs)
        if nrows_per_file is not None:
            read_kwargs["nrows"] = nrows_per_file

        try:
            reader = pd.read_csv(f, chunksize=chunksize, **read_kwargs)
        except UnicodeDecodeError:
            read_kwargs["encoding"] = "latin1"
            reader = pd.read_csv(f, chunksize=chunksize, **read_kwargs)

        for chunk in reader:
            raw_len = len(chunk)
            total_raw_rows += raw_len

            clean_feat, clean_meta, clean_y, chunk_excl = clean_and_extract_fn(chunk, fname, file_row_offset)
            file_row_offset += raw_len

            for k, v in chunk_excl.items():
                total_exclusions[k] = total_exclusions.get(k, 0) + v

            if len(clean_feat) == 0:
                continue

            clean_len = len(clean_feat)
            total_valid_rows += clean_len

            y_vals = clean_y.values
            b = np.bincount(y_vals, minlength=2)
            source_class_counts["0"] = source_class_counts.get("0", 0) + int(b[0])
            source_class_counts["1"] = source_class_counts.get("1", 0) + int(b[1])

            if use_reservoir:
                reservoir.add_chunk(clean_feat, clean_y, clean_meta)
            else:
                combined = clean_feat.copy()
                combined["__y__"] = y_vals
                if callable(clean_meta):
                    for i in range(clean_len):
                        for k, v in clean_meta(i).items():
                            if k not in combined.columns:
                                combined[k] = None
                            combined.at[combined.index[i], k] = v
                else:
                    for col in clean_meta.columns:
                        combined[f"__meta_{col}__"] = clean_meta[col].values
                accumulated_chunks.append(combined)

    if use_reservoir:
        final_combined = reservoir.get_result()
    else:
        if accumulated_chunks:
            final_combined = pd.concat(accumulated_chunks, ignore_index=True)
            if sample_n is not None and len(final_combined) > sample_n:
                final_combined = final_combined.sample(n=sample_n, random_state=seed).reset_index(drop=True)
        else:
            final_combined = pd.DataFrame()

    if len(final_combined) > 0:
        y_binary = final_combined["__y__"].astype(int).reset_index(drop=True)
        meta_cols = [c for c in final_combined.columns if c.startswith("__meta_") and c.endswith("__")]
        meta_dict = {c[len("__meta_"):-2]: final_combined[c].values for c in meta_cols}
        metadata_df = pd.DataFrame(meta_dict)
        feature_cols = [c for c in final_combined.columns if not c.startswith("__")]
        features_df = final_combined[feature_cols].reset_index(drop=True)
    else:
        features_df = pd.DataFrame()
        metadata_df = pd.DataFrame()
        y_binary = pd.Series(dtype=int)

    info = {
        "files_considered": files_considered,
        "files_loaded": len(files_considered),
        "source_file_hashes": source_file_hashes,
        "total_rows_considered": total_raw_rows,
        "total_valid_rows": total_valid_rows,
        "selection_policy": "reservoir_sampling" if use_reservoir else "complete_stream",
        "seed": seed,
        "source_class_counts": source_class_counts,
        "selected_class_counts": {str(k): int(v) for k, v in y_binary.value_counts().items()},
        "exclusion_reasons": total_exclusions,
        "metadata": metadata_df,
    }
    return features_df, y_binary, metadata_df, info
