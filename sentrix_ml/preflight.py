"""Data and environment preflight verification script for SENTRi-X.

Guarantees:
* Readiness depends strictly on successful adapter test-runs and valid outputs
* Adapter failures immediately mark dataset status as FAILED
* Exit code is non-zero (1) on any blocking failure
* Scoped to requested target domain (--target all|ton_iot|bot_iot|cic_ids2017|omni)
* Exact dataset paths matching training loaders

Usage:
    python -m sentrix_ml.preflight
    python -m sentrix_ml.preflight --target ton_iot --require-tf
"""

from __future__ import annotations

import argparse
import glob
import os
import sys
from pathlib import Path

import numpy as np
import pandas as pd

from sentrix_ml.schema import EXPECTED_FEATURES, NUM_FEATURES, SCHEMA_VERSION


def parse_args():
    parser = argparse.ArgumentParser(description="SENTRi-X Preflight Verification")
    parser.add_argument(
        "--target",
        choices=["all", "ton_iot", "bot_iot", "cic_ids2017", "omni"],
        default="all",
        help="Target scope for preflight check",
    )
    parser.add_argument(
        "--require-tf",
        action="store_true",
        help="Require TensorFlow to be installed (mandatory before full training runs)",
    )
    return parser.parse_args()


def check_environment(require_tf: bool = False) -> tuple[dict, bool]:
    info = {"python_version": sys.version.split()[0]}
    has_blocking_error = False

    packages = {
        "numpy": "numpy",
        "pandas": "pandas",
        "scikit-learn": "sklearn",
        "joblib": "joblib",
        "psutil": "psutil",
    }
    for name, mod in packages.items():
        try:
            m = __import__(mod)
            info[name] = getattr(m, "__version__", "installed")
        except ImportError:
            info[name] = "MISSING [BLOCKING]"
            has_blocking_error = True

    # TensorFlow check
    try:
        import tensorflow as tf
        info["tensorflow"] = tf.__version__
    except ImportError:
        if require_tf:
            info["tensorflow"] = "MISSING [BLOCKING for full training]"
            has_blocking_error = True
        else:
            info["tensorflow"] = "NOT INSTALLED (mock fallback allowed for smoke tests only)"

    # Hardware resources
    try:
        import psutil
        vm = psutil.virtual_memory()
        info["ram_total_gb"] = round(vm.total / (1024**3), 2)
        info["ram_available_gb"] = round(vm.available / (1024**3), 2)
        disk = psutil.disk_usage(os.path.abspath("."))
        info["disk_free_gb"] = round(disk.free / (1024**3), 2)
    except Exception as e:
        info["resources_error"] = str(e)

    return info, not has_blocking_error


def check_ton_iot(data_dir: Path) -> dict:
    ton_files = sorted(glob.glob(str(data_dir / "Network_dataset_*.csv")))
    if not ton_files:
        return {"status": "MISSING", "path": str(data_dir), "error": "No raw CSV files matching Network_dataset_*.csv found."}

    total_size_mb = sum(os.path.getsize(f) for f in ton_files) / (1024 * 1024)
    res = {
        "status": "CHECKING",
        "file_count": len(ton_files),
        "total_size_mb": round(total_size_mb, 1),
        "sample_file": os.path.basename(ton_files[0]),
    }

    try:
        from sentrix_ml.adapters.ton_iot import load_ton_iot
        X, y, info = load_ton_iot(data_dir, sample_n=50)
        if len(X) == 0 or len(y) == 0:
            res["status"] = "FAILED"
            res["error"] = "Adapter returned 0 rows."
            return res
        if X.shape[1] != NUM_FEATURES or list(X.columns) != EXPECTED_FEATURES:
            res["status"] = "FAILED"
            res["error"] = f"Schema mismatch: got {X.shape[1]} features, expected {NUM_FEATURES}."
            return res
        source_class_counts = info.get("source_class_counts", {})
        class_counts = dict(y.value_counts())
        effective_counts = source_class_counts if len(source_class_counts) > 0 else class_counts
        if len(effective_counts) < 2 or any(c < 2 for c in effective_counts.values()):
            res["status"] = "FAILED"
            res["error"] = (
                f"Adapter returned single-class or underpopulated sample: {effective_counts}. "
                "Both benign (0) and attack (1) classes are required to construct valid "
                "training, validation, and test partitions."
            )
            return res
        res["status"] = "READY"
        res["adapter_test"] = f"PASS (shape={X.shape}, labels={class_counts})"
        res["source_class_counts"] = source_class_counts
        res["files_considered"] = info.get("files_considered", [])
        res["source_file_hashes"] = info.get("source_file_hashes", {})
        res["selection_policy"] = info.get("selection_policy", "reservoir_sampling")
        res["exclusions"] = info.get("exclusion_reasons", {})
    except Exception as e:
        res["status"] = "FAILED"
        res["error"] = str(e)

    return res


def check_bot_iot(data_dir: Path) -> dict:
    bot_files = sorted(glob.glob(str(data_dir / "UNSW_2018_IoT_Botnet_Full5pc_*.csv")))
    if not bot_files:
        return {"status": "MISSING", "path": str(data_dir), "error": "No raw BoT-IoT CSV chunks found."}

    total_size_mb = sum(os.path.getsize(f) for f in bot_files) / (1024 * 1024)
    res = {
        "status": "CHECKING",
        "file_count": len(bot_files),
        "total_size_mb": round(total_size_mb, 1),
        "sample_file": os.path.basename(bot_files[0]),
    }

    try:
        from sentrix_ml.adapters.bot_iot import load_bot_iot
        X, y, info = load_bot_iot(data_dir, sample_n=50, ip_bytes_policy="exclude")
        if len(X) == 0 or len(y) == 0:
            res["status"] = "FAILED"
            res["error"] = "Adapter returned 0 rows."
            return res
        if X.shape[1] != NUM_FEATURES or list(X.columns) != EXPECTED_FEATURES:
            res["status"] = "FAILED"
            res["error"] = f"Schema mismatch: got {X.shape[1]} features, expected {NUM_FEATURES}."
            return res
        source_class_counts = info.get("source_class_counts", {})
        class_counts = dict(y.value_counts())
        effective_counts = source_class_counts if len(source_class_counts) > 0 else class_counts
        if len(effective_counts) < 2 or any(c < 2 for c in effective_counts.values()):
            res["status"] = "FAILED"
            res["error"] = (
                f"Adapter returned single-class or underpopulated sample: {effective_counts}. "
                "Both benign (0) and attack (1) classes are required to construct valid "
                "training, validation, and test partitions."
            )
            return res
        res["status"] = "READY"
        res["adapter_test"] = f"PASS (shape={X.shape}, labels={class_counts})"
        res["source_class_counts"] = source_class_counts
        res["files_considered"] = info.get("files_considered", [])
        res["source_file_hashes"] = info.get("source_file_hashes", {})
        res["selection_policy"] = info.get("selection_policy", "reservoir_sampling")
        res["ip_bytes_policy"] = info.get("ip_bytes_policy", "exclude")
        res["exclusions"] = info.get("exclusion_reasons", {})
        res["unresolved_mappings"] = info.get("unresolved_mappings", [])
    except Exception as e:
        res["status"] = "FAILED"
        res["error"] = str(e)

    return res


def check_cic_ids2017(data_dir: Path) -> dict:
    cic_files = sorted([f for f in glob.glob(str(data_dir / "*.csv")) if not f.endswith("mapped.csv")])
    if not cic_files:
        return {"status": "MISSING", "path": str(data_dir), "error": "No raw CIC-IDS2017 CSV files found."}

    total_size_mb = sum(os.path.getsize(f) for f in cic_files) / (1024 * 1024)
    res = {
        "status": "CHECKING",
        "file_count": len(cic_files),
        "total_size_mb": round(total_size_mb, 1),
        "sample_file": os.path.basename(cic_files[0]),
    }

    try:
        from sentrix_ml.adapters.cic_ids2017 import load_cic_ids2017
        X, y, info = load_cic_ids2017(data_dir, sample_n=50)
        if len(X) == 0 or len(y) == 0:
            res["status"] = "FAILED"
            res["error"] = "Adapter returned 0 rows."
            return res
        if X.shape[1] != NUM_FEATURES or list(X.columns) != EXPECTED_FEATURES:
            res["status"] = "FAILED"
            res["error"] = f"Schema mismatch: got {X.shape[1]} features, expected {NUM_FEATURES}."
            return res
        source_class_counts = info.get("source_class_counts", {})
        class_counts = dict(y.value_counts())
        effective_counts = source_class_counts if len(source_class_counts) > 0 else class_counts
        if len(effective_counts) < 2 or any(c < 2 for c in effective_counts.values()):
            res["status"] = "FAILED"
            res["error"] = (
                f"Adapter returned single-class or underpopulated sample: {effective_counts}. "
                "Both benign (0) and attack (1) classes are required to construct valid "
                "training, validation, and test partitions."
            )
            return res
        res["status"] = "READY"
        res["adapter_test"] = f"PASS (shape={X.shape}, labels={class_counts})"
        res["source_class_counts"] = source_class_counts
        res["files_considered"] = info.get("files_considered", [])
        res["source_file_hashes"] = info.get("source_file_hashes", {})
        res["selection_policy"] = info.get("selection_policy", "reservoir_sampling")
        res["duration_unit"] = info.get("duration_unit", "seconds")
        res["exclusions"] = info.get("exclusion_reasons", {})
    except Exception as e:
        res["status"] = "FAILED"
        res["error"] = str(e)

    return res


def run_preflight():
    args = parse_args()
    project_root = Path(__file__).resolve().parent.parent
    data_dir = project_root / "data" / "raw"

    print("=" * 75)
    print("           SENTRi-X ML Pipeline: Preflight Verification")
    print(f"           Schema: {SCHEMA_VERSION} ({NUM_FEATURES} features) | Scope: {args.target.upper()}")
    print("=" * 75)

    print("\n[1] Environment & Dependencies:")
    env_info, env_ok = check_environment(require_tf=args.require_tf)
    for k, v in env_info.items():
        print(f"  - {k:22s}: {v}")

    print("\n[2] Raw Datasets & Schema Adapters:")
    datasets = {}
    if args.target in ("all", "ton_iot", "omni"):
        datasets["ton_iot"] = check_ton_iot(data_dir / "ton_iot")
    if args.target in ("all", "bot_iot", "omni"):
        datasets["bot_iot"] = check_bot_iot(data_dir / "bot_iot")
    if args.target in ("all", "cic_ids2017", "omni"):
        datasets["cic_ids2017"] = check_cic_ids2017(data_dir / "cic_ids2017")

    datasets_ok = True
    for name, details in datasets.items():
        st = details.get("status", "UNKNOWN")
        print(f"  * {name.upper()}: [{st}]")
        for k, v in details.items():
            if k != "status":
                print(f"      {k}: {v}")
        if st != "READY":
            datasets_ok = False

    print("\n" + "=" * 75)
    if env_ok and datasets_ok:
        print(f"PREFLIGHT STATUS: READY FOR TRAINING ({args.target.upper()})")
        print("=" * 75)
        sys.exit(0)
    else:
        print("PREFLIGHT STATUS: FAILED — BLOCKING ISSUES DETECTED")
        if not env_ok:
            print("  ! Environment dependencies missing.")
        if not datasets_ok:
            print("  ! One or more required dataset adapters failed or files are missing.")
        print("=" * 75)
        sys.exit(1)


if __name__ == "__main__":
    run_preflight()
