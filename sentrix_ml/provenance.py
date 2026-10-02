"""Raw record identity, distinct from model features and split grouping.

Fingerprints exclude labels and generated row counters, but include every other
raw field (including timestamps). Without session identifiers, identical raw
observations are indistinguishable: this limitation is recorded in the audit.
"""
from __future__ import annotations

import hashlib
import json
import math
import numbers

import pandas as pd


IDENTITY_POLICY = "raw_record_sha256_v1"
GROUP_POLICY = "session_start_else_tuple_else_raw_record_v1"
_ANNOTATIONS = {"label", "attack", "type", "category", "subcategory"}
_COUNTERS = {"pkseqid", "seq", "unnamed: 0"}


def _value(value):
    if pd.isna(value):
        return None
    if isinstance(value, numbers.Real):
        number = float(value)
        return format(number, ".17g") if math.isfinite(number) else str(number)
    return str(value).strip()


def _digest(parts):
    encoded = json.dumps(parts, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def raw_metadata_factory(raw_chunk, *, domain, filename, row_offset, tuple_columns, time_column=None):
    """Capture the unmodified chunk and its positional, file-relative row IDs.

    Adapter callers reset the chunk index first. Cleaning can then retain these
    indices; no pandas reader-global index is added to row_offset a second time.
    Work is lazy: hashes are computed only for rows admitted to the reservoir.
    """
    raw = raw_chunk.copy(deep=True)
    columns = sorted(c for c in raw.columns if c.lower() not in _ANNOTATIONS | _COUNTERS)
    has_tuple = all(c in raw.columns for c in tuple_columns)

    def record(position):
        row = raw.iloc[int(position)]
        raw_id = _digest([domain, [(c, _value(row[c])) for c in columns]])
        duplicate_id = f"{domain}:raw:{raw_id}"
        group = duplicate_id
        group_scope = "raw_record_only"
        if has_tuple and all(_value(row[c]) not in (None, "", "-") for c in tuple_columns):
            # Canonical endpoint order keeps both directions of a session together.
            src_ip, src_port, dst_ip, dst_port, proto = [_value(row[c]) for c in tuple_columns]
            endpoints = sorted([(src_ip, src_port), (dst_ip, dst_port)])
            parts = [domain, endpoints, proto]
            group_scope = "tuple_without_session_start"
            if time_column in raw.columns and _value(row[time_column]) not in (None, "", "-"):
                parts.append(_value(row[time_column]))
                group_scope = "tuple_and_session_start"
            group = f"{domain}:session:{_digest(parts)}"
        result = {
            "__meta_domain__": domain,
            "__meta_source_file__": filename,
            "__meta_source_row_index__": row_offset + int(position),
            "__meta_duplicate_id__": duplicate_id,
            "__meta_group_id__": group,
            "__meta_group_scope__": group_scope,
        }
        for col, target in (("pkSeqID", "original_flow_id"), ("flow id", "original_flow_id"),
                            ("type", "attack_type"), ("category", "attack_category"),
                            ("subcategory", "attack_subcategory")):
            if col in raw.columns:
                result[f"__meta_{target}__"] = _value(row[col])
        if time_column in raw.columns:
            result["__meta_session_start__"] = _value(row[time_column])
        return result
    return record


def sampling_audit(info):
    """JSON-safe source selection metadata saved in the hashed split manifest."""
    keys = ("domain", "files_considered", "source_file_hashes", "total_rows_considered",
            "total_valid_rows", "selection_policy", "seed", "source_class_counts",
            "selected_class_counts", "exclusion_reasons", "sample_n", "nrows_per_file",
            "max_files", "chunksize", "ip_bytes_policy", "duration_unit")
    audit = {key: info[key] for key in keys if key in info}
    audit.update(identity_policy=IDENTITY_POLICY, grouping_policy=GROUP_POLICY,
                 limitation="Without session fields, identical raw observations cannot be distinguished; "
                            "tuple-only groups may include multiple sessions. No feature-vector deduplication.")
    metadata = info.get("metadata")
    if metadata is not None and "group_scope" in metadata:
        audit["selected_group_scopes"] = {str(k): int(v) for k, v in metadata.group_scope.value_counts().items()}
    return audit
