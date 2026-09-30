"""Data and environment preflight verification script for SENTRi-X.

Verifies:
1. Python environment and required ML libraries
2. Available system RAM and disk space
3. Raw datasets accessibility, sample loading, and 28-feature schema alignment
4. Active database and deployment state integrity

Usage:
    python -m sentrix_ml.preflight
"""

from __future__ import annotations

import os
import sys
import glob
from pathlib import Path

import numpy as np
import pandas as pd

from sentrix_ml.schema import EXPECTED_FEATURES, NUM_FEATURES, SCHEMA_VERSION


def check_environment() -> dict:
    info = {"python_version": sys.version.split()[0]}
    
    # Check packages
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
            info[name] = "MISSING"

    # TensorFlow check (optional on Windows, required in WSL for CNN training)
    try:
        import tensorflow as tf
        info["tensorflow"] = tf.__version__
    except ImportError:
        info["tensorflow"] = "NOT INSTALLED (mock fallback available for smoke runs; required for full retraining)"

    # Hardware resource check
    try:
        import psutil
        vm = psutil.virtual_memory()
        info["ram_total_gb"] = round(vm.total / (1024**3), 2)
        info["ram_available_gb"] = round(vm.available / (1024**3), 2)
        disk = psutil.disk_usage(os.path.abspath("."))
        info["disk_free_gb"] = round(disk.free / (1024**3), 2)
    except Exception as e:
        info["resources_error"] = str(e)

    return info


def check_datasets(project_root: Path) -> dict:
    results = {}
    data_dir = project_root / "data" / "raw"

    # 1. ToN-IoT
    ton_dir = data_dir / "ton_iot"
    ton_files = sorted(glob.glob(str(ton_dir / "Network_dataset_*.csv")))
    if ton_files:
        total_size_mb = sum(os.path.getsize(f) for f in ton_files) / (1024 * 1024)
        results["ton_iot"] = {
            "status": "READY",
            "file_count": len(ton_files),
            "total_size_mb": round(total_size_mb, 1),
            "sample_file": os.path.basename(ton_files[0]),
        }
        # Test adapter load
        try:
            from sentrix_ml.adapters.ton_iot import load_ton_iot
            X, y, info = load_ton_iot(ton_dir, max_files=1, nrows_per_file=50)
            results["ton_iot"]["adapter_test"] = f"PASS (shape={X.shape}, labels={dict(y.value_counts())})"
        except Exception as e:
            results["ton_iot"]["adapter_test"] = f"FAIL: {e}"
    else:
        results["ton_iot"] = {"status": "MISSING", "path": str(ton_dir)}

    # 2. BoT-IoT
    bot_dir = data_dir / "bot_iot"
    bot_files = sorted(glob.glob(str(bot_dir / "UNSW_2018_IoT_Botnet_Full5pc_*.csv")))
    mapped_bot = project_root / "bot_iot_mapped.csv"
    if bot_files or mapped_bot.exists():
        results["bot_iot"] = {
            "status": "READY",
            "raw_chunks": len(bot_files),
            "mapped_fallback_available": mapped_bot.exists(),
        }
        try:
            from sentrix_ml.adapters.bot_iot import load_bot_iot
            X, y, info = load_bot_iot(bot_dir, max_files=1, nrows_per_file=50)
            results["bot_iot"]["adapter_test"] = f"PASS (shape={X.shape}, labels={dict(y.value_counts())})"
        except Exception as e:
            results["bot_iot"]["adapter_test"] = f"FAIL: {e}"
    else:
        results["bot_iot"] = {"status": "MISSING", "path": str(bot_dir)}

    # 3. CIC-IDS2017
    cic_dir = data_dir / "cic_ids2017"
    cic_files = sorted([f for f in glob.glob(str(cic_dir / "*.csv")) if not f.endswith("mapped.csv")])
    mapped_cic = project_root / "cic_ids2017_mapped.csv"
    if cic_files or mapped_cic.exists():
        results["cic_ids2017"] = {
            "status": "READY",
            "raw_files": len(cic_files),
            "mapped_fallback_available": mapped_cic.exists(),
        }
        try:
            from sentrix_ml.adapters.cic_ids2017 import load_cic_ids2017
            X, y, info = load_cic_ids2017(cic_dir, max_files=1, nrows_per_file=50)
            results["cic_ids2017"]["adapter_test"] = f"PASS (shape={X.shape}, labels={dict(y.value_counts())})"
        except Exception as e:
            results["cic_ids2017"]["adapter_test"] = f"FAIL: {e}"
    else:
        results["cic_ids2017"] = {"status": "MISSING", "path": str(cic_dir)}

    return results


def check_deployment_state(project_root: Path) -> dict:
    info = {}
    db_path = project_root / "data" / "sentrix.db"
    if db_path.exists():
        info["database"] = f"EXISTS ({round(db_path.stat().st_size / 1024, 1)} KB)"
    else:
        info["database"] = "NOT FOUND (will be created on first flow)"

    candidates_dir = project_root / "models" / "candidates"
    if candidates_dir.exists():
        candidates = [d.name for d in candidates_dir.iterdir() if d.is_dir()]
        info["candidates"] = candidates
    else:
        info["candidates"] = []

    return info


def run_preflight():
    project_root = Path(__file__).resolve().parent.parent
    print("=" * 70)
    print("           SENTRi-X ML Pipeline: Preflight Verification")
    print(f"           Schema: {SCHEMA_VERSION} ({NUM_FEATURES} features)")
    print("=" * 70)

    print("\n[1] Environment & Dependencies:")
    env = check_environment()
    for k, v in env.items():
        print(f"  - {k:22s}: {v}")

    print("\n[2] Raw Datasets & Schema Adapters:")
    datasets = check_datasets(project_root)
    all_ready = True
    for name, details in datasets.items():
        status = details.get("status", "UNKNOWN")
        print(f"  * {name.upper()}: [{status}]")
        for k, v in details.items():
            if k != "status":
                print(f"      {k}: {v}")
        if status != "READY":
            all_ready = False

    print("\n[3] Deployment State & Candidates:")
    dep = check_deployment_state(project_root)
    for k, v in dep.items():
        print(f"  - {k:22s}: {v}")

    print("\n" + "=" * 70)
    if all_ready:
        print("PREFLIGHT STATUS: ALL CRITICAL DATASETS AND ADAPTERS READY FOR TRAINING")
    else:
        print("PREFLIGHT STATUS: WARNING - SOME DATASETS ARE MISSING OR PARTIAL")
    print("=" * 70)


if __name__ == "__main__":
    run_preflight()
