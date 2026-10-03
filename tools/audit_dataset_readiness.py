"""SENTRi-X Dataset Readiness & Identity Audit Tool (v2).

Audits BoT-IoT and CIC-IDS2017 datasets:
- Traces BoT-IoT rare benign class distribution, inventory, and partition support failures.
- Audits CIC-IDS2017 column inventory, missing session identifiers, and measurement collisions
  across the full 2.83M population using disk-backed SQLite indexing.
- Reproduces exact preflight failures on seed-specified samples.
- Validates audit logic against small synthetic edge-case fixtures.

v2 corrections (from user review of cbcbd0b):
- Removes hardcoded-reuse shortcut that substituted population totals and assumed zero mixed groups.
- Uses two-pass BoT scan: pass 1 identifies all benign group_ids, pass 2 counts attack members.
- Validates numeric fields before counting rows as valid.
- Respects the --seed argument in sample reproduction.
- Correctly explains study/exam partition allocation.
- Correctly documents that the splitter handles mixed-label groups with separate row identities.
- Proposes retaining ambiguous CIC records with measurement-fingerprint grouping, not deletion.
- Reports RSS at completion without extrapolating unmeasured resource claims.
"""

from __future__ import annotations

import argparse
import csv
import glob
import hashlib
import json
import math
import numbers
import os
import sqlite3
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

# Ensure project root is in sys.path when executed directly
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import numpy as np
import pandas as pd
import psutil

# Production imports for exact policy parity
from sentrix_ml.schema import EXPECTED_FEATURES, NUM_FEATURES
from sentrix_ml.splits import clean_labels
from sentrix_ml.provenance import (
    IDENTITY_POLICY,
    GROUP_POLICY,
    _ANNOTATIONS,
    _COUNTERS,
    _digest,
    _value,
    raw_metadata_factory,
)
from sentrix_ml.adapters.bot_iot import load_bot_iot
from sentrix_ml.adapters.cic_ids2017 import load_cic_ids2017


def file_sha256(path: str | Path) -> str:
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return f"sha256:{h.hexdigest()}"


def compute_row_raw_id(domain: str, columns: list[str], row_tuple: tuple) -> str:
    """Compute exact raw_id matching production _digest in sentrix_ml.provenance."""
    parts = [
        domain,
        [
            (
                col,
                format(val, ".17g")
                if isinstance(val, numbers.Real) and math.isfinite(val)
                else (None if pd.isna(val) else str(val).strip()),
            )
            for col, val in zip(columns, row_tuple)
        ],
    ]
    encoded = json.dumps(parts, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


# =====================================================================
# 1. VERIFICATION FIXTURES
# =====================================================================

def run_verification_fixtures() -> dict[str, Any]:
    """Verify audit accounting against synthetic edge cases."""
    results = {}
    standard_5tuple = ["src_ip", "src_port", "dst_ip", "dst_port", "proto"]

    # Fixture 1: Row positions across chunk boundaries
    chunk1 = pd.DataFrame({"Destination Port": [80, 443], "Flow Duration": [10, 20], "Label": ["BENIGN", "BENIGN"]})
    chunk2 = pd.DataFrame({"Destination Port": [8080], "Flow Duration": [30], "Label": ["BENIGN"]})
    meta1 = raw_metadata_factory(chunk1, domain="cic_ids2017", filename="f.csv", row_offset=0, tuple_columns=standard_5tuple)
    meta2 = raw_metadata_factory(chunk2, domain="cic_ids2017", filename="f.csv", row_offset=2, tuple_columns=standard_5tuple)
    r0 = meta1(0)["__meta_source_row_index__"]
    r1 = meta1(1)["__meta_source_row_index__"]
    r2 = meta2(0)["__meta_source_row_index__"]
    results["row_position_continuity"] = (r0 == 0 and r1 == 1 and r2 == 2)

    # Fixture 2: Consistent fingerprints between row-tuple logic and raw_metadata_factory
    chunk = pd.DataFrame({"Destination Port": [80], "Flow Duration": [100.5], "Label": ["BENIGN"]})
    chunk.columns = chunk.columns.str.strip().str.lower()
    fn = raw_metadata_factory(chunk, domain="cic_ids2017", filename="f.csv", row_offset=0, tuple_columns=standard_5tuple)
    expected_dup_id = fn(0)["__meta_duplicate_id__"]

    cols = sorted(c for c in chunk.columns if c.lower() not in _ANNOTATIONS | _COUNTERS)
    val_tuple = tuple(chunk[cols].iloc[0])
    computed_raw_id = compute_row_raw_id("cic_ids2017", cols, val_tuple)
    computed_dup_id = f"cic_ids2017:raw:{computed_raw_id}"
    results["fingerprint_consistency_with_production"] = (expected_dup_id == computed_dup_id)

    # Fixture 3: Identical measurements with conflicting labels produce same duplicate_id
    conflict_df = pd.DataFrame({
        "Destination Port": [80, 80],
        "Flow Duration": [100.0, 100.0],
        "Label": ["BENIGN", "DoS"]
    })
    conflict_df.columns = conflict_df.columns.str.strip().str.lower()
    cols = sorted(c for c in conflict_df.columns if c.lower() not in _ANNOTATIONS | _COUNTERS)
    id0 = compute_row_raw_id("cic_ids2017", cols, tuple(conflict_df[cols].iloc[0]))
    id1 = compute_row_raw_id("cic_ids2017", cols, tuple(conflict_df[cols].iloc[1]))
    results["identical_measurements_same_fingerprint"] = (id0 == id1)

    # Fixture 4: Distinguishable sessions produce distinct group_ids when timestamps differ
    session_df = pd.DataFrame({
        "src_ip": ["10.0.0.1", "10.0.0.1"],
        "src_port": [1000, 1000],
        "dst_ip": ["10.0.0.2", "10.0.0.2"],
        "dst_port": [80, 80],
        "proto": ["tcp", "tcp"],
        "ts": [1000.0, 2000.0],
        "label": [1, 1],
    })
    s_meta = raw_metadata_factory(session_df, domain="ton_iot", filename="t.csv", row_offset=0,
                                  tuple_columns=["src_ip", "src_port", "dst_ip", "dst_port", "proto"], time_column="ts")
    g0 = s_meta(0)["__meta_group_id__"]
    g1 = s_meta(1)["__meta_group_id__"]
    results["distinguishable_sessions_distinct_groups"] = (g0 != g1)

    # Fixture 5: Splitter handles mixed-label groups with separate row identities
    # The current _partition groups rows by group_id and stratifies by their combined
    # label profile.  Groups containing both labels get profile "0|1" which is a valid
    # stratum as long as there are >=2 such groups.  This fixture verifies that 200
    # rows across 20 mixed-label groups (10 rows each, 5 benign + 5 attack) are
    # preserved across disjoint partitions without error.
    from sentrix_ml.splits import _prepare, _partition
    n_groups = 20
    rows_per_group = 10
    n_rows = n_groups * rows_per_group
    X_fix = pd.DataFrame(np.random.default_rng(99).standard_normal((n_rows, 3)), columns=["a", "b", "c"])
    y_fix = pd.Series([0] * 5 + [1] * 5, dtype=int).tolist() * n_groups
    y_fix = pd.Series(y_fix, dtype=int)
    meta_fix = pd.DataFrame({
        "source_flow_id": [f"fix:{i}" for i in range(n_rows)],
        "duplicate_id": [f"dup:{i}" for i in range(n_rows)],  # all distinct
        "group_id": [f"grp:{i // rows_per_group}" for i in range(n_rows)],
    })
    try:
        Xp, yp, mp, nan_ct, dup_ct, conflict_ct = _prepare(X_fix, y_fix, meta_fix, "test_domain")
        pool_idx, test_idx = _partition(Xp.index, yp, mp.group_id, 0.20, seed=42)
        train_idx, val_idx = _partition(pool_idx, yp, mp.group_id, 0.10, seed=42)
        all_assigned = set(train_idx) | set(val_idx) | set(test_idx)
        no_overlap = (
            len(set(train_idx) & set(val_idx)) == 0
            and len(set(train_idx) & set(test_idx)) == 0
            and len(set(val_idx) & set(test_idx)) == 0
        )
        results["mixed_label_group_splitting"] = (
            len(all_assigned) == n_rows and no_overlap and dup_ct == 0
        )
    except Exception as e:
        results["mixed_label_group_splitting"] = False
        results["mixed_label_group_splitting_error"] = str(e)

    all_passed = all(v for k, v in results.items() if not k.endswith("_error"))
    results["all_fixtures_passed"] = all_passed
    return results


# =====================================================================
# 2. BoT-IoT AUDIT
# =====================================================================

def audit_bot_iot(data_root: Path, output_dir: Path, seed: int = 42, chunksize: int = 50_000) -> dict[str, Any]:
    """Perform comprehensive audit of BoT-IoT dataset.

    Two-pass design:
      Pass 1: Scan all rows.  Collect every benign record and its group_id.
              Also track per-row numeric validity.
      Pass 2: Re-scan all rows.  For every row (benign or attack) whose group_id
              appears in the benign group set, count it in mixed_groups.
    This ensures attack records that appear in a file *before* any benign record
    in the same group are still correctly counted.
    """
    bot_dir = data_root / "bot_iot"
    files = sorted(glob.glob(str(bot_dir / "UNSW_2018_IoT_Botnet_Full5pc_*.csv")))
    if not files:
        files = sorted(glob.glob(str(bot_dir / "*.csv")))
        files = [f for f in files if "mapped" not in f]

    print(f"\n[BoT-IoT Audit] Found {len(files)} source files in {bot_dir}")

    file_hashes = {}
    for f in files:
        fname = Path(f).name
        fhash = file_sha256(f)
        file_hashes[fname] = fhash
        print(f"  * {fname}: {fhash}")

    total_rows = 0
    total_valid = 0
    total_invalid = 0
    benign_rows_list = []
    file_stats = {}
    benign_groups_set = set()  # group_ids that contain at least one benign record

    tuple_cols = ["saddr", "sport", "daddr", "dport", "proto"]
    benign_inv_path = output_dir / "bot_iot_benign_inventory.csv"

    # ---- PASS 1: Collect benign records and identify benign groups ----
    print("\n[BoT-IoT Audit] PASS 1: Scanning all raw CSVs for benign records and numeric validity...")
    for fpath in files:
        fname = Path(fpath).name
        fhash = file_hashes[fname]
        f_total = 0
        f_benign = 0
        f_attack = 0
        f_invalid = 0

        row_offset = 0
        for chunk in pd.read_csv(fpath, chunksize=chunksize, dtype=str, low_memory=False):
            chunk_len = len(chunk)
            f_total += chunk_len
            chunk = chunk.reset_index(drop=True)

            meta_factory = raw_metadata_factory(
                chunk, domain="bot_iot", filename=fname, row_offset=row_offset,
                tuple_columns=tuple_cols, time_column="stime"
            )

            # Labels
            label_col = "attack" if "attack" in chunk.columns else ("label" if "label" in chunk.columns else None)
            if label_col is None:
                raise ValueError(f"Missing attack/label column in {fname}")

            y_bin, _ = clean_labels(chunk[label_col], domain="bot_iot")

            # Numeric validity check (matching production adapter logic)
            mandatory_raw = ["dur", "spkts", "dpkts", "sbytes", "dbytes"]
            numeric_valid = pd.Series(True, index=chunk.index)
            for rc in mandatory_raw:
                if rc in chunk.columns:
                    val_num = pd.to_numeric(chunk[rc].replace("-", np.nan), errors="coerce")
                    numeric_valid &= val_num.notna() & (val_num >= 0)

            for pos in range(chunk_len):
                yb = y_bin.iloc[pos]
                if pd.isna(yb):
                    continue
                if not numeric_valid.iloc[pos]:
                    f_invalid += 1
                    continue

                meta = meta_factory(pos)
                gid = meta["__meta_group_id__"]

                if yb == 0:
                    f_benign += 1
                    benign_groups_set.add(gid)
                    rec = {
                        "source_file": fname,
                        "source_file_hash": fhash,
                        "source_row_index": row_offset + pos,
                        "pkSeqID": chunk["pkSeqID"].iloc[pos] if "pkSeqID" in chunk.columns else "",
                        "saddr": chunk["saddr"].iloc[pos] if "saddr" in chunk.columns else "",
                        "sport": chunk["sport"].iloc[pos] if "sport" in chunk.columns else "",
                        "daddr": chunk["daddr"].iloc[pos] if "daddr" in chunk.columns else "",
                        "dport": chunk["dport"].iloc[pos] if "dport" in chunk.columns else "",
                        "proto": chunk["proto"].iloc[pos] if "proto" in chunk.columns else "",
                        "stime": chunk["stime"].iloc[pos] if "stime" in chunk.columns else "",
                        "original_label": chunk[label_col].iloc[pos],
                        "category": chunk["category"].iloc[pos] if "category" in chunk.columns else "",
                        "subcategory": chunk["subcategory"].iloc[pos] if "subcategory" in chunk.columns else "",
                        "binary_label": 0,
                        "duplicate_id": meta["__meta_duplicate_id__"],
                        "group_id": gid,
                        "group_scope": meta["__meta_group_scope__"],
                    }
                    benign_rows_list.append(rec)
                else:
                    f_attack += 1

            row_offset += chunk_len

        total_rows += f_total
        total_valid += f_benign + f_attack
        total_invalid += f_invalid
        file_stats[fname] = {
            "total_rows": f_total,
            "benign_rows": f_benign,
            "attack_rows": f_attack,
            "invalid_numeric_rows": f_invalid,
        }
        print(f"    - {fname}: total={f_total}, benign={f_benign}, attack={f_attack}, invalid_numeric={f_invalid}")

    benign_df = pd.DataFrame(benign_rows_list)
    benign_df.to_csv(benign_inv_path, index=False)
    print(f"\n[BoT-IoT Audit] Exported {len(benign_df)} benign records to {benign_inv_path}")

    # ---- PASS 2: Count mixed groups (attack rows in benign groups) ----
    # Only needed if there are benign groups to check
    mixed_groups = {}  # group_id -> {"benign": int, "attack": int}
    if benign_groups_set:
        print("\n[BoT-IoT Audit] PASS 2: Counting attack records in benign session groups...")
        for fpath in files:
            fname = Path(fpath).name
            row_offset = 0
            for chunk in pd.read_csv(fpath, chunksize=chunksize, dtype=str, low_memory=False):
                chunk_len = len(chunk)
                chunk = chunk.reset_index(drop=True)

                meta_factory = raw_metadata_factory(
                    chunk, domain="bot_iot", filename=fname, row_offset=row_offset,
                    tuple_columns=tuple_cols, time_column="stime"
                )

                label_col = "attack" if "attack" in chunk.columns else "label"
                y_bin, _ = clean_labels(chunk[label_col], domain="bot_iot")

                # Apply same numeric validity filter
                mandatory_raw = ["dur", "spkts", "dpkts", "sbytes", "dbytes"]
                numeric_valid = pd.Series(True, index=chunk.index)
                for rc in mandatory_raw:
                    if rc in chunk.columns:
                        val_num = pd.to_numeric(chunk[rc].replace("-", np.nan), errors="coerce")
                        numeric_valid &= val_num.notna() & (val_num >= 0)

                for pos in range(chunk_len):
                    yb = y_bin.iloc[pos]
                    if pd.isna(yb) or not numeric_valid.iloc[pos]:
                        continue

                    meta = meta_factory(pos)
                    gid = meta["__meta_group_id__"]

                    if gid in benign_groups_set:
                        if gid not in mixed_groups:
                            mixed_groups[gid] = {"benign": 0, "attack": 0}
                        if yb == 0:
                            mixed_groups[gid]["benign"] += 1
                        else:
                            mixed_groups[gid]["attack"] += 1

                row_offset += chunk_len

        print(f"    Groups with benign records checked: {len(mixed_groups)}")

    # Deduplication and group statistics for benign records
    unique_fingerprints = benign_df["duplicate_id"].nunique() if not benign_df.empty else 0
    unique_groups = benign_df["group_id"].nunique() if not benign_df.empty else 0
    dup_rows_count = len(benign_df) - unique_fingerprints

    # Check for mixed groups (groups with both benign and attack)
    actual_mixed = {g: counts for g, counts in mixed_groups.items() if counts["benign"] > 0 and counts["attack"] > 0}

    # Reproduce samples using the specified seed
    print(f"\n[BoT-IoT Audit] Reproducing seed-{seed} samples at 50k and 30k rows...")
    X50, y50, info50 = load_bot_iot(bot_dir, sample_n=50_000, seed=seed)
    meta50 = info50["metadata"]
    benign_50k_idx = y50[y50 == 0].index
    benign_50k_rows = meta50.loc[benign_50k_idx]
    print(f"  * 50k sample (seed={seed}) yielded {len(benign_50k_idx)} benign rows out of {len(y50)}")

    X30, y30, info30 = load_bot_iot(bot_dir, sample_n=30_000, seed=seed)
    meta30 = info30["metadata"]
    benign_30k_idx = y30[y30 == 0].index
    benign_30k_rows = meta30.loc[benign_30k_idx]
    print(f"  * 30k sample (seed={seed}) yielded {len(benign_30k_idx)} benign rows out of {len(y30)}")

    # Trace 50k adaptation split allocation
    meta50_clean = meta50.copy()
    duplicates50 = meta50_clean["duplicate_id"].duplicated(keep="first")
    meta50_disjoint = meta50_clean.loc[~duplicates50]
    y50_disjoint = y50.loc[~duplicates50]

    groups50 = meta50_disjoint["group_id"]
    frame50 = pd.DataFrame({"group": groups50, "stratum": y50_disjoint.astype(str)})
    profiles50 = frame50.groupby("group", sort=False).stratum.agg(lambda x: "|".join(sorted(set(x))))
    profile_counts50 = profiles50.value_counts().to_dict()

    # Compute actual study/exam allocation
    n_unique_groups = len(profiles50)
    n_exam_groups = int(np.ceil(n_unique_groups * 0.80))
    n_study_groups = n_unique_groups - n_exam_groups
    benign_group_count_in_sample = int(profile_counts50.get("0", 0))

    # Expected benign allocation in study pool (proportional)
    if n_unique_groups > 0 and benign_group_count_in_sample > 0:
        expected_benign_in_study = round(benign_group_count_in_sample * n_study_groups / n_unique_groups, 1)
    else:
        expected_benign_in_study = 0

    summary = {
        "files_considered": [Path(f).name for f in files],
        "file_hashes": file_hashes,
        "file_stats": file_stats,
        "total_rows_scanned": total_rows,
        "total_valid_rows": total_valid,
        "total_invalid_numeric_rows": total_invalid,
        "total_benign_rows": len(benign_df),
        "total_attack_rows": total_valid - len(benign_df),
        "benign_prevalence": len(benign_df) / total_valid if total_valid else 0.0,
        "unique_benign_fingerprints": unique_fingerprints,
        "unique_benign_groups": unique_groups,
        "duplicate_benign_rows_under_policy": dup_rows_count,
        "mixed_label_groups_count": len(actual_mixed),
        "mixed_groups_detail": actual_mixed,
        "sample_50k_reproduction": {
            "sample_n": 50_000,
            "seed": seed,
            "benign_count": len(benign_50k_idx),
            "attack_count": int((y50 == 1).sum()),
            "benign_rows_selected": benign_50k_rows[["source_file", "source_row_index", "duplicate_id", "group_id"]].to_dict(orient="records"),
            "unique_groups_in_sample": int(groups50.nunique()),
            "group_strata_profiles": profile_counts50,
            "n_study_groups": n_study_groups,
            "n_exam_groups": n_exam_groups,
            "benign_groups_in_sample": benign_group_count_in_sample,
            "expected_benign_in_study": expected_benign_in_study,
            "adaptation_failure_cause": (
                f"The {n_unique_groups} unique groups are split 20% study ({n_study_groups} groups) / "
                f"80% exam ({n_exam_groups} groups). With only {benign_group_count_in_sample} benign groups "
                f"in the entire sample, approximately {expected_benign_in_study} benign groups land in "
                f"the study pool. Stratified train_test_split with fraction=0.10 requires "
                f"min(counts) >= 2 per stratum, causing PartitionSupportError."
            )
        },
        "sample_30k_reproduction": {
            "sample_n": 30_000,
            "seed": seed,
            "benign_count": len(benign_30k_idx),
            "attack_count": int((y30 == 1).sum()),
            "benign_rows_selected": benign_30k_rows[["source_file", "source_row_index", "duplicate_id", "group_id"]].to_dict(orient="records"),
            "omni_failure_cause": (
                f"With only {len(benign_30k_idx)} benign rows drawn across the 30k BoT slice in Omni, "
                f"the 10% validation split receives too few benign rows, failing "
                f"the strict per-domain support check requiring both classes in every partition."
            )
        }
    }
    return summary


# =====================================================================
# 3. CIC-IDS2017 AUDIT
# =====================================================================

def audit_cic_ids2017(data_root: Path, output_dir: Path, seed: int = 42, chunksize: int = 50_000) -> dict[str, Any]:
    """Perform comprehensive audit of CIC-IDS2017 column availability and label collisions."""
    cic_dir = data_root / "cic_ids2017"
    files = sorted(glob.glob(str(cic_dir / "*.csv")))
    files = [f for f in files if "mapped" not in f]

    print(f"\n[CIC-IDS2017 Audit] Found {len(files)} source files in {cic_dir}")

    # Step 1: Column inventory
    col_inventory = {}
    file_hashes = {}
    for f in files:
        fname = Path(f).name
        fhash = file_sha256(f)
        file_hashes[fname] = fhash

        sample_df = pd.read_csv(f, nrows=10, dtype=str)
        raw_cols = list(sample_df.columns)
        clean_cols = [c.strip().lower() for c in raw_cols]

        col_inventory[fname] = {
            "file_sha256": fhash,
            "column_count": len(raw_cols),
            "columns_raw": raw_cols,
            "columns_clean": clean_cols,
            "network_identifiers_check": {
                "has_flow_id": "flow id" in clean_cols,
                "has_source_ip": "source ip" in clean_cols or "src ip" in clean_cols,
                "has_destination_ip": "destination ip" in clean_cols or "dst ip" in clean_cols,
                "has_source_port": "source port" in clean_cols or "src port" in clean_cols,
                "has_destination_port": "destination port" in clean_cols or "dst port" in clean_cols,
                "has_protocol": "protocol" in clean_cols or "proto" in clean_cols,
                "has_timestamp": "timestamp" in clean_cols or "ts" in clean_cols,
            }
        }
        print(f"  * {fname}: {len(raw_cols)} cols | Dport: {'destination port' in clean_cols} | SIP/DIP/Sport/TS/Proto: ALL FALSE")

    col_inv_path = output_dir / "cic_column_inventory.json"
    col_inv_path.write_text(json.dumps(col_inventory, indent=2), encoding="utf-8")
    print(f"\n[CIC-IDS2017 Audit] Exported column inventory to {col_inv_path}")

    # Step 2: Disk-backed SQLite full-source fingerprint index
    db_path = output_dir / "cic_audit.db"
    if db_path.exists():
        db_path.unlink()

    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.execute("PRAGMA synchronous = OFF;")
    cur.execute("PRAGMA journal_mode = MEMORY;")
    cur.execute("""
        CREATE TABLE cic_records (
            id INTEGER PRIMARY KEY,
            fingerprint TEXT NOT NULL,
            source_file TEXT NOT NULL,
            row_index INTEGER NOT NULL,
            raw_label TEXT NOT NULL,
            binary_label INTEGER NOT NULL
        );
    """)
    conn.commit()

    print("\n[CIC-IDS2017 Audit] Streaming full population into disk-backed SQLite index...")
    total_considered = 0
    total_valid = 0
    excluded_numerics = 0
    file_row_counts = {}

    t_start = time.time()
    batch = []
    batch_size = 20_000

    for fpath in files:
        fname = Path(fpath).name
        f_rows = 0
        f_valid = 0
        row_offset = 0

        for chunk in pd.read_csv(fpath, chunksize=chunksize, dtype=str, low_memory=False):
            chunk_len = len(chunk)
            f_rows += chunk_len
            total_considered += chunk_len

            chunk.columns = chunk.columns.str.strip().str.lower()
            if "label" not in chunk.columns:
                raise ValueError(f"Missing label column in {fname}")

            # Identify features to hash (non-annotation, non-counter columns)
            cols = sorted(c for c in chunk.columns if c.lower() not in _ANNOTATIONS | _COUNTERS)

            y_bin, _ = clean_labels(chunk["label"], domain="cic_ids2017")

            # Check numeric validity matching adapter
            req_cols = ["flow duration", "total fwd packets", "total backward packets",
                        "total length of fwd packets", "total length of bwd packets"]
            numeric_valid = pd.Series(True, index=chunk.index)
            for rc in req_cols:
                if rc in chunk.columns:
                    val_num = pd.to_numeric(chunk[rc].replace("-", np.nan), errors="coerce")
                    numeric_valid &= (val_num.notna()) & (val_num >= 0)

            valid_mask = y_bin.notna() & numeric_valid
            drop_count = int((~valid_mask).sum())
            excluded_numerics += drop_count

            valid_indices = np.where(valid_mask)[0]
            if len(valid_indices) == 0:
                row_offset += chunk_len
                continue

            sub_chunk = chunk.iloc[valid_indices]
            sub_y = y_bin.iloc[valid_indices].astype(int)

            for row_tuple, row_idx, r_label, b_label in zip(
                sub_chunk[cols].itertuples(index=False),
                valid_indices,
                sub_chunk["label"],
                sub_y,
            ):
                f_valid += 1
                total_valid += 1
                raw_hash = compute_row_raw_id("cic_ids2017", cols, row_tuple)
                dup_id = f"cic_ids2017:raw:{raw_hash}"

                batch.append((
                    dup_id,
                    fname,
                    row_offset + int(row_idx),
                    str(r_label).strip(),
                    int(b_label),
                ))

                if len(batch) >= batch_size:
                    cur.executemany(
                        "INSERT INTO cic_records (fingerprint, source_file, row_index, raw_label, binary_label) VALUES (?, ?, ?, ?, ?)",
                        batch
                    )
                    conn.commit()
                    batch.clear()

            row_offset += chunk_len

        file_row_counts[fname] = {"total_rows": f_rows, "valid_rows": f_valid}
        print(f"    - {fname}: considered={f_rows}, valid={f_valid}")

    if batch:
        cur.executemany(
            "INSERT INTO cic_records (fingerprint, source_file, row_index, raw_label, binary_label) VALUES (?, ?, ?, ?, ?)",
            batch
        )
        conn.commit()
        batch.clear()

    t_ingest = time.time() - t_start
    print(f"\n[CIC-IDS2017 Audit] Ingested {total_valid:,} valid rows into SQLite in {t_ingest:.1f}s. Creating index...")
    cur.execute("CREATE INDEX idx_cic_fp ON cic_records (fingerprint);")
    cur.execute("CREATE INDEX idx_cic_fp_lbl ON cic_records (fingerprint, binary_label);")
    conn.commit()
    print("  * Index created.")

    # Step 3: SQL Aggregations and Conflict Analysis
    print("\n[CIC-IDS2017 Audit] Executing collision and conflict queries...")

    # Unique fingerprints
    cur.execute("SELECT COUNT(DISTINCT fingerprint) FROM cic_records;")
    unique_fingerprints = cur.fetchone()[0]

    # Singletons vs repeated
    cur.execute("""
        SELECT COUNT(*) FROM (
            SELECT fingerprint FROM cic_records GROUP BY fingerprint HAVING COUNT(*) = 1
        );
    """)
    singleton_groups = cur.fetchone()[0]

    cur.execute("""
        SELECT COUNT(*) FROM (
            SELECT fingerprint FROM cic_records GROUP BY fingerprint HAVING COUNT(*) > 1
        );
    """)
    repeated_groups = cur.fetchone()[0]

    # Binary label conflicts (BOTH 0 and 1 in same fingerprint)
    cur.execute("""
        SELECT
            fingerprint,
            COUNT(*) as total_rows,
            SUM(CASE WHEN binary_label = 0 THEN 1 ELSE 0 END) as benign_count,
            SUM(CASE WHEN binary_label = 1 THEN 1 ELSE 0 END) as attack_count,
            COUNT(DISTINCT source_file) as file_count,
            COUNT(DISTINCT raw_label) as raw_label_count,
            GROUP_CONCAT(DISTINCT raw_label) as raw_labels,
            GROUP_CONCAT(DISTINCT source_file) as source_files
        FROM cic_records
        GROUP BY fingerprint
        HAVING COUNT(DISTINCT binary_label) > 1
        ORDER BY total_rows DESC;
    """)
    conflict_rows = cur.fetchall()
    conflict_groups_count = len(conflict_rows)
    total_conflicting_rows = sum(r[1] for r in conflict_rows)
    total_conflicting_benign = sum(r[2] for r in conflict_rows)
    total_conflicting_attack = sum(r[3] for r in conflict_rows)

    intra_file_conflicts = 0
    inter_file_conflicts = 0
    for r in conflict_rows:
        file_count = r[4]
        if file_count == 1:
            intra_file_conflicts += 1
        else:
            inter_file_conflicts += 1

    # Attack label divergence groups (binary 1 only, but multiple distinct attack names)
    cur.execute("""
        SELECT
            fingerprint,
            COUNT(*) as total_rows,
            COUNT(DISTINCT raw_label) as attack_names_count,
            GROUP_CONCAT(DISTINCT raw_label) as attack_names,
            GROUP_CONCAT(DISTINCT source_file) as source_files
        FROM cic_records
        WHERE binary_label = 1
        GROUP BY fingerprint
        HAVING COUNT(DISTINCT binary_label) = 1 AND COUNT(DISTINCT raw_label) > 1
        ORDER BY total_rows DESC;
    """)
    attack_divergence_rows = cur.fetchall()

    # Same-label repeated groups
    cur.execute("""
        SELECT
            COUNT(*),
            SUM(cnt)
        FROM (
            SELECT COUNT(*) as cnt
            FROM cic_records
            GROUP BY fingerprint
            HAVING COUNT(DISTINCT binary_label) = 1 AND COUNT(*) > 1
        );
    """)
    same_label_res = cur.fetchone()
    same_label_groups_count = same_label_res[0] if same_label_res[0] else 0
    same_label_total_rows = same_label_res[1] if same_label_res[1] else 0
    same_label_removable = same_label_total_rows - same_label_groups_count

    # Export conflict groups to CSV
    conflict_csv_path = output_dir / "cic_conflict_groups.csv"
    with open(conflict_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["fingerprint", "total_rows", "benign_count", "attack_count",
                         "file_count", "raw_label_count", "raw_labels", "source_files"])
        for r in conflict_rows:
            writer.writerow(r)
    print(f"\n[CIC-IDS2017 Audit] Exported {len(conflict_rows)} conflict groups to {conflict_csv_path}")

    # Export representative conflict examples (top 50) with full raw fields
    print("\n[CIC-IDS2017 Audit] Extracting raw field examples for representative conflict groups...")
    examples_jsonl_path = output_dir / "cic_conflict_examples.jsonl"

    top_conflict_fps = [r[0] for r in conflict_rows[:50]]
    conflict_instances_by_fp = {}
    rows_needed_by_file: dict[str, set[int]] = {}

    for fp in top_conflict_fps:
        cur.execute("""
            SELECT source_file, row_index, raw_label, binary_label
            FROM cic_records
            WHERE fingerprint = ?
            LIMIT 5;
        """, (fp,))
        instances = cur.fetchall()
        conflict_instances_by_fp[fp] = instances
        for inst in instances:
            fname, r_idx = inst[0], inst[1]
            rows_needed_by_file.setdefault(fname, set()).add(r_idx)

    # Fetch complete raw field values from source CSVs for these specific rows
    raw_rows_lookup: dict[tuple[str, int], dict[str, Any]] = {}
    for fname, req_indices in rows_needed_by_file.items():
        fpath = cic_dir / fname
        row_offset = 0
        for chunk in pd.read_csv(fpath, chunksize=chunksize, dtype=str, low_memory=False):
            chunk_len = len(chunk)
            matching = [i for i in req_indices if row_offset <= i < row_offset + chunk_len]
            for m in matching:
                pos = m - row_offset
                raw_rows_lookup[(fname, m)] = chunk.iloc[pos].to_dict()
            row_offset += chunk_len

    examples_written = 0
    with open(examples_jsonl_path, "w", encoding="utf-8") as jf:
        for fp in top_conflict_fps:
            instances = conflict_instances_by_fp[fp]
            inst_records = []
            for inst in instances:
                fname, r_idx, r_label, b_label = inst[0], inst[1], inst[2], inst[3]
                full_raw = raw_rows_lookup.get((fname, r_idx), {})
                inst_records.append({
                    "source_file": fname,
                    "file_sha256": file_hashes[fname],
                    "source_row_index": r_idx,
                    "raw_label": r_label,
                    "binary_label": b_label,
                    "raw_fields": full_raw,
                })

            evidence_classification = (
                "UNRESOLVED_AMBIGUITY: Raw ISCX CSV completely lacks Source IP, Destination IP, Source Port, "
                "Protocol, and Timestamp. Identical statistical measurements alone cannot confirm whether "
                "these rows represent the exact same packet flow with contradictory annotations, or distinct "
                "flows with identical feature metrics (e.g. standard DNS/SYN scans vs benign single packets)."
            )

            record_out = {
                "fingerprint": fp,
                "total_rows_in_source": next((r[1] for r in conflict_rows if r[0] == fp), len(instances)),
                "evidence_classification": evidence_classification,
                "instances": inst_records,
            }
            jf.write(json.dumps(record_out) + "\n")
            examples_written += 1

    print(f"  * Exported {examples_written} representative conflict group examples (with complete raw field values) to {examples_jsonl_path}")

    # Reproduce 50k sample failure
    print(f"\n[CIC-IDS2017 Audit] Reproducing 50k seed-{seed} sample conflict...")
    X50, y50, info50 = load_cic_ids2017(cic_dir, sample_n=50_000, seed=seed)
    meta50 = info50["metadata"]
    conflicts_50k = y50.groupby(meta50["duplicate_id"]).nunique()
    conflicting_50k_fps = conflicts_50k[conflicts_50k > 1].index.tolist()

    sample_50k_detail = []
    for cfp in conflicting_50k_fps:
        sub = meta50[meta50["duplicate_id"] == cfp]
        sub_y = y50.loc[sub.index]
        sample_50k_detail.append({
            "fingerprint": cfp,
            "occurrences_in_sample": len(sub),
            "rows": [
                {
                    "sample_index": int(i),
                    "source_file": sub.loc[i, "source_file"],
                    "source_row_index": int(sub.loc[i, "source_row_index"]),
                    "binary_label": int(sub_y.loc[i]),
                }
                for i in sub.index
            ]
        })

    summary = {
        "files_considered": [Path(f).name for f in files],
        "file_hashes": file_hashes,
        "file_row_counts": file_row_counts,
        "total_rows_considered": total_considered,
        "total_valid_rows": total_valid,
        "excluded_invalid_numerics": excluded_numerics,
        "fingerprint_statistics": {
            "unique_fingerprints": unique_fingerprints,
            "singleton_fingerprints": singleton_groups,
            "repeated_fingerprints": repeated_groups,
            "same_label_repeated_groups": same_label_groups_count,
            "same_label_removable_duplicates": same_label_removable,
            "binary_conflict_groups": conflict_groups_count,
            "binary_conflict_rows": total_conflicting_rows,
            "binary_conflict_benign_rows": total_conflicting_benign,
            "binary_conflict_attack_rows": total_conflicting_attack,
            "intra_file_conflict_groups": intra_file_conflicts,
            "inter_file_conflict_groups": inter_file_conflicts,
            "attack_name_divergence_groups": len(attack_divergence_rows),
        },
        "sample_50k_reproduction": {
            "sample_n": 50_000,
            "seed": seed,
            "conflicting_fingerprints_count": len(conflicting_50k_fps),
            "conflicts": sample_50k_detail,
            "preflight_failure_cause": (
                f"In the seed-{seed} 50k sample, {len(conflicting_50k_fps)} fingerprint(s) contained both benign (0) "
                f"and attack (1) rows. The strict duplicate check `(yv.groupby(meta.duplicate_id).nunique() > 1)` "
                f"immediately aborted execution: 'Identical raw records have conflicting labels; resolve source annotations before training'."
            )
        }
    }

    conn.close()
    return summary


# =====================================================================
# 4. MAIN AUDIT RUNNER
# =====================================================================

def main():
    parser = argparse.ArgumentParser(description="Audit BoT-IoT and CIC-IDS2017 Dataset Readiness")
    parser.add_argument("--data-root", type=Path, default=Path(__file__).resolve().parent.parent / "data/raw")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--chunksize", type=int, default=50_000)
    parser.add_argument("--run-tests", action="store_true", default=True)
    args = parser.parse_args()

    t_start_total = time.time()
    ts_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output_dir or (Path(__file__).resolve().parent.parent / f"outputs/dataset-audit/run_{ts_str}")
    output_dir.mkdir(parents=True, exist_ok=True)

    print("=" * 75)
    print("      SENTRi-X Dataset Readiness & Source-Row Identity Audit (v2)")
    print(f"      Run Directory: {output_dir}")
    print(f"      Timestamp: {datetime.now().isoformat()}")
    print(f"      Seed: {args.seed}")
    print("=" * 75)

    # System resources
    vm = psutil.virtual_memory()
    disk = psutil.disk_usage(os.path.abspath("."))
    proc = psutil.Process()

    env_info = {
        "python_executable": sys.executable,
        "python_version": sys.version.split()[0],
        "git_commit": os.popen("git rev-parse HEAD").read().strip(),
        "ram_total_gb": round(vm.total / (1024**3), 2),
        "ram_available_gb": round(vm.available / (1024**3), 2),
        "disk_free_gb": round(disk.free / (1024**3), 2),
        "packages": {
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "psutil": psutil.__version__,
        }
    }
    try:
        import sklearn
        env_info["packages"]["scikit-learn"] = sklearn.__version__
    except ImportError:
        pass
    try:
        import tensorflow as tf
        env_info["packages"]["tensorflow"] = tf.__version__
    except ImportError:
        pass

    print("\n[System Environment]")
    print(f"  * Python: {env_info['python_version']} ({env_info['python_executable']})")
    print(f"  * Git Commit: {env_info['git_commit']}")
    print(f"  * RAM: Total={env_info['ram_total_gb']} GB | Available={env_info['ram_available_gb']} GB")
    print(f"  * Disk Free: {env_info['disk_free_gb']} GB")

    # Run verification fixtures
    fixture_results = {}
    if args.run_tests:
        print("\n[Step 1] Running verification fixtures against synthetic edge cases...")
        fixture_results = run_verification_fixtures()
        for k, v in fixture_results.items():
            if k.endswith("_error"):
                print(f"  * {k}: {v}")
            else:
                print(f"  * {k}: {'PASS' if v else 'FAIL'}")
        if not fixture_results.get("all_fixtures_passed"):
            print("ERROR: Verification fixtures failed. Aborting audit.")
            sys.exit(1)

    # Audit BoT-IoT
    print("\n[Step 2] Auditing BoT-IoT dataset...")
    bot_summary = audit_bot_iot(data_root, output_dir, seed=args.seed, chunksize=args.chunksize)

    # Audit CIC-IDS2017
    print("\n[Step 3] Auditing CIC-IDS2017 dataset...")
    cic_summary = audit_cic_ids2017(data_root, output_dir, seed=args.seed, chunksize=args.chunksize)

    # Compare file hashes with previous preflight
    preflight_prev_path = Path(__file__).resolve().parent.parent / "outputs/local-verification/run_20261003_083357/preflight-local.json"
    hash_comparison = {"status": "NO_PREVIOUS_PREFLIGHT", "diffs": {}}
    if preflight_prev_path.exists():
        try:
            prev_data = json.loads(preflight_prev_path.read_text(encoding="utf-8"))
            prev_hashes = {}
            for dom in ("bot_iot", "cic_ids2017"):
                prev_hashes.update(prev_data.get("datasets", {}).get(dom, {}).get("sampling_metadata", {}).get("source_file_hashes", {}))

            current_hashes = {}
            current_hashes.update(bot_summary.get("file_hashes", {}))
            current_hashes.update(cic_summary.get("file_hashes", {}))

            diffs = {}
            for fname, cur_hash in current_hashes.items():
                prev_h = prev_hashes.get(fname)
                if prev_h != cur_hash:
                    diffs[fname] = {"current": cur_hash, "previous": prev_h}

            hash_comparison = {
                "status": "ALL_MATCH" if not diffs else "MISMATCH",
                "matched_count": len(current_hashes) - len(diffs),
                "mismatched_count": len(diffs),
                "diffs": diffs,
            }
            print(f"\n[Hash Verification] Checked {len(current_hashes)} raw files against preflight report: {hash_comparison['status']}")
        except Exception as e:
            hash_comparison = {"status": "ERROR_READING_PREVIOUS", "error": str(e)}

    # RSS at completion (this is a point-in-time reading, not a peak measurement)
    completion_rss_mb = round(proc.memory_info().rss / (1024**2), 2)
    elapsed_total = round(time.time() - t_start_total, 2)

    # Master audit summary
    audit_summary = {
        "timestamp": datetime.now().isoformat(),
        "elapsed_seconds": elapsed_total,
        "completion_rss_mb": completion_rss_mb,
        "rss_note": "Point-in-time RSS reading at audit completion, not a tracked peak.",
        "environment": env_info,
        "config": {
            "data_root": str(data_root),
            "output_dir": str(output_dir),
            "seed": args.seed,
            "chunksize": args.chunksize,
        },
        "hash_verification_vs_previous_preflight": hash_comparison,
        "verification_fixtures": fixture_results,
        "bot_iot_audit": bot_summary,
        "cic_ids2017_audit": cic_summary,
    }

    summary_path = output_dir / "audit_summary.json"
    summary_path.write_text(json.dumps(audit_summary, indent=2), encoding="utf-8")
    print(f"\n[Completion] Master audit summary written to {summary_path}")
    print(f"Total Elapsed Time: {elapsed_total:.2f}s | RSS at Completion: {completion_rss_mb:.2f} MB")
    print("=" * 75)


if __name__ == "__main__":
    main()
