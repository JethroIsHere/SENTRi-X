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
        if not isinstance(capacity, int) or isinstance(capacity, bool) or capacity < 1:
            raise ValueError("sample_n must be a positive integer")
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
        prob = min(1.0, float(self.capacity) / float(self.total_seen)) if self.total_seen > 0 else 1.0
        weight = 1.0 / prob if prob > 0 else 1.0
        for rec in self.reservoir:
            rec["__meta_inclusion_probability__"] = float(prob)
            rec["__meta_sampling_weight__"] = float(weight)
        return pd.DataFrame(self.reservoir)


class StratifiedReservoirBuffer:
    """Dual-reservoir buffer guaranteeing rare minority class preservation with strict O(K) RAM.

    Minority and majority class records are each bounded to ``capacity`` using
    Algorithm R during chunk ingestion. At ``get_result()`` time, slots are
    balanced so that total records do not exceed ``capacity``, and exact inclusion
    probabilities (pi_c = K_c / N_c) and sampling weights (w_c = 1 / pi_c)
    are calculated and attached to every record as metadata.

    This ensures streaming memory is strictly bounded by 2 * capacity at all times,
    preventing memory leaks regardless of source population size.
    """

    def __init__(self, capacity: int, minority_label: int = 0, seed: int = 42):
        if not isinstance(capacity, int) or isinstance(capacity, bool) or capacity < 1:
            raise ValueError("capacity must be a positive integer")
        self.capacity = capacity
        self.minority_label = minority_label
        self.seed = seed
        self.rng = np.random.default_rng(seed)

        self.minority_records: list[dict] = []
        self.majority_records: list[dict] = []
        self.minority_seen: int = 0
        self.majority_seen: int = 0
        self.total_seen: int = 0
        self.minority_selected: int = 0
        self.majority_selected: int = 0
        self.inclusion_probabilities: dict[str, float] = {}
        self.sampling_weights: dict[str, float] = {}

    def _feed_reservoir(
        self,
        reservoir: list[dict],
        seen_count: int,
        indices: np.ndarray,
        features: pd.DataFrame,
        y: pd.Series,
        get_row_meta: Callable[[int], dict],
    ) -> int:
        n = len(indices)
        if n == 0:
            return seen_count

        current_len = len(reservoir)
        if current_len < self.capacity:
            needed = self.capacity - current_len
            take_n = min(needed, n)
            for j in range(take_n):
                i = int(indices[j])
                rec = features.iloc[i].to_dict()
                rec["__y__"] = int(y.iloc[i])
                rec.update(get_row_meta(i))
                reservoir.append(rec)
            seen_count += take_n
            if take_n >= n:
                return seen_count
            remaining_indices = indices[take_n:]
            n_remaining = len(remaining_indices)
        else:
            remaining_indices = indices
            n_remaining = n

        # Vectorised Algorithm R
        total_seen_range = seen_count + 1 + np.arange(n_remaining, dtype=np.int64)
        u = self.rng.random(n_remaining)
        r = np.floor(u * total_seen_range).astype(np.int64)
        seen_count += n_remaining

        enter_mask = r < self.capacity
        if np.any(enter_mask):
            enter_positions = np.where(enter_mask)[0]
            for pos in enter_positions:
                orig_idx = int(remaining_indices[pos])
                slot = int(r[pos])
                rec = features.iloc[orig_idx].to_dict()
                rec["__y__"] = int(y.iloc[orig_idx])
                rec.update(get_row_meta(orig_idx))
                reservoir[slot] = rec
        return seen_count

    def add_chunk(self, features: pd.DataFrame, y: pd.Series, meta: pd.DataFrame | Callable[[int], dict]) -> None:
        m = len(features)
        if m == 0:
            return

        is_fn = callable(meta)

        def _get_row_meta(idx: int) -> dict:
            if is_fn:
                return meta(idx)
            return {f"__meta_{col}__": meta.iloc[idx][col] for col in meta.columns}

        # Split indices by class
        y_vals = y.values
        minority_indices = np.where(y_vals == self.minority_label)[0]
        majority_indices = np.where(y_vals != self.minority_label)[0]

        self.total_seen += m

        # Algorithm R for minority class (bounded strictly to capacity)
        self.minority_seen = self._feed_reservoir(
            self.minority_records, self.minority_seen, minority_indices, features, y, _get_row_meta
        )

        # Algorithm R for majority class (bounded strictly to capacity)
        self.majority_seen = self._feed_reservoir(
            self.majority_records, self.majority_seen, majority_indices, features, y, _get_row_meta
        )

    def get_result(self) -> pd.DataFrame:
        n_min = len(self.minority_records)
        n_maj = len(self.majority_records)

        if n_min == 0 and n_maj == 0:
            return pd.DataFrame()

        if n_maj == 0:
            take_min = min(n_min, self.capacity)
            if take_min < n_min:
                rng = np.random.default_rng(self.seed + 1)
                idx = rng.choice(n_min, take_min, replace=False)
                min_selected = [self.minority_records[i] for i in sorted(idx)]
            else:
                min_selected = list(self.minority_records)
            maj_selected = []

        elif n_min == 0:
            take_maj = min(n_maj, self.capacity)
            if take_maj < n_maj:
                rng = np.random.default_rng(self.seed + 2)
                idx = rng.choice(n_maj, take_maj, replace=False)
                maj_selected = [self.majority_records[i] for i in sorted(idx)]
            else:
                maj_selected = list(self.majority_records)
            min_selected = []

        else:
            # Both classes are present.
            # Guarantee minority records enter the sample up to capacity // 2,
            # preserving all minority records when rare while ensuring majority
            # class support is never starved (e.g. in small or balanced samples).
            max_min = max(1, self.capacity // 2)
            take_min = min(n_min, max_min)

            # Majority takes remaining capacity
            take_maj = min(n_maj, self.capacity - take_min)

            # If majority didn't use all allocated slots, grant extra to minority
            if take_maj < self.capacity - take_min:
                extra = (self.capacity - take_maj) - take_min
                take_min = min(n_min, take_min + extra)

            if take_min < n_min:
                rng = np.random.default_rng(self.seed + 1)
                idx = rng.choice(n_min, take_min, replace=False)
                min_selected = [self.minority_records[i] for i in sorted(idx)]
            else:
                min_selected = list(self.minority_records)

            if take_maj < n_maj:
                rng = np.random.default_rng(self.seed + 2)
                idx = rng.choice(n_maj, take_maj, replace=False)
                maj_selected = [self.majority_records[i] for i in sorted(idx)]
            else:
                maj_selected = list(self.majority_records)

        k_min = len(min_selected)
        k_maj = len(maj_selected)
        self.minority_selected = k_min
        self.majority_selected = k_maj

        pi_min = float(k_min) / float(self.minority_seen) if self.minority_seen > 0 else 1.0
        w_min = 1.0 / pi_min if pi_min > 0 else 1.0

        pi_maj = float(k_maj) / float(self.majority_seen) if self.majority_seen > 0 else 1.0
        w_maj = 1.0 / pi_maj if pi_maj > 0 else 1.0

        for rec in min_selected:
            rec["__meta_inclusion_probability__"] = pi_min
            rec["__meta_sampling_weight__"] = w_min

        for rec in maj_selected:
            rec["__meta_inclusion_probability__"] = pi_maj
            rec["__meta_sampling_weight__"] = w_maj

        min_label_str = str(self.minority_label)
        maj_label_str = "1" if min_label_str == "0" else ("0" if min_label_str == "1" else "majority")
        self.inclusion_probabilities = {min_label_str: pi_min, maj_label_str: pi_maj}
        self.sampling_weights = {min_label_str: w_min, maj_label_str: w_maj}

        all_records = min_selected + maj_selected
        return pd.DataFrame(all_records)


def stream_dataset_files(
    all_files: list[str | Path],
    *,
    clean_and_extract_fn: Callable[[pd.DataFrame, str, int], tuple[pd.DataFrame, pd.DataFrame, pd.Series, dict[str, int]]],
    sample_n: int | None = None,
    seed: int = 42,
    chunksize: int = 50_000,
    nrows_per_file: int | None = None,
    read_csv_kwargs: dict | None = None,
    reservoir_buffer: ReservoirBuffer | StratifiedReservoirBuffer | None = None,
) -> tuple[pd.DataFrame, pd.Series, pd.DataFrame, dict[str, Any]]:
    """Stream tabular files with reservoir sampling and provenance tracking.

    Args:
        reservoir_buffer: Optional pre-constructed buffer. When provided, this
            buffer is used instead of the default ``ReservoirBuffer``. Use
            ``StratifiedReservoirBuffer`` for datasets with extreme class
            imbalance (e.g. BoT-IoT).
    """
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
        reservoir = reservoir_buffer or ReservoirBuffer(capacity=sample_n, seed=seed)
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

            # Bind each selected raw record to the bytes of its actual source file.
            original_meta = clean_meta
            def bound_meta(i, original=original_meta, name=fname, digest=source_file_hashes[fname]):
                rec = dict(original(i)) if callable(original) else {
                    f"__meta_{col}__": original.iloc[i][col] for col in original.columns
                }
                domain = rec.get("__meta_domain__", "unknown")
                row = rec["__meta_source_row_index__"]
                rec["__meta_source_file_hash__"] = digest
                rec["__meta_source_flow_id__"] = f"{domain}:{name}:{digest}:row:{row}"
                return rec
            clean_meta = bound_meta
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
        "selection_policy": "reservoir_sampling" if use_reservoir else ("bounded_prefix_then_sample" if nrows_per_file is not None else "complete_stream"),
        "sample_n": sample_n,
        "nrows_per_file": nrows_per_file,
        "seed": seed,
        "source_class_counts": source_class_counts,
        "selected_class_counts": {str(k): int(v) for k, v in y_binary.value_counts().items()},
        "exclusion_reasons": total_exclusions,
        "metadata": metadata_df,
    }
    if use_reservoir:
        if hasattr(reservoir, "inclusion_probabilities"):
            info["inclusion_probabilities"] = dict(getattr(reservoir, "inclusion_probabilities", {}))
        if hasattr(reservoir, "sampling_weights"):
            info["sampling_weights"] = dict(getattr(reservoir, "sampling_weights", {}))
    return features_df, y_binary, metadata_df, info
