"""Check the exact configured sample and partitions before any model fitting."""
from __future__ import annotations
import argparse
import json
import os
import sys
from pathlib import Path
import numpy as np
import pandas as pd
from sentrix_ml.schema import EXPECTED_FEATURES, NUM_FEATURES, SCHEMA_VERSION
from sentrix_ml.datasets import LOADERS, load_omni
from sentrix_ml.provenance import sampling_audit
from sentrix_ml.splits import stratified_split, adaptation_split


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="SENTRi-X configured-run preflight")
    parser.add_argument("--target", choices=["all", "ton_iot", "bot_iot", "cic_ids2017", "omni"], default="all")
    parser.add_argument("--require-tf", action="store_true")
    parser.add_argument("--data-root", type=Path, default=Path(__file__).resolve().parent.parent / "data/raw")
    parser.add_argument("--sample-n", type=int, default=50000)
    parser.add_argument("--sample-per-domain", type=int, default=30000)
    parser.add_argument("--test-fraction", type=float, default=.20)
    parser.add_argument("--study-fraction", type=float, default=.20)
    parser.add_argument("--val-fraction", type=float, default=.10)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--report-json", type=Path)
    return parser.parse_args(argv)


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


def _check(data_dir, domain, *, sample_n=50000, seed=42, test_fraction=.20,
           study_fraction=.20, val_fraction=.10):
    result = {"status": "CHECKING", "domain": domain, "sample_n": sample_n, "seed": seed}
    try:
        if domain == "omni":
            X, y, info = load_omni(data_dir, sample_per_domain=sample_n, seed=seed)
            audit = info["sampling_metadata"]
        else:
            X, y, info = LOADERS[domain](data_dir, sample_n=sample_n, seed=seed)
            audit = sampling_audit(info)
        if X.empty or list(X.columns) != EXPECTED_FEATURES:
            raise ValueError("Empty sample or invalid canonical feature schema")
        result.update(selected_class_counts={str(k): int(v) for k, v in y.value_counts().items()},
                      sampling_metadata=audit)
        kwargs = dict(metadata=info["metadata"], seed=seed, domain=domain,
                      source_file_hashes=info["source_file_hashes"], sampling_metadata=audit,
                      exclusion_reasons=info["exclusion_reasons"], require_class_support=True)
        if domain == "ton_iot":
            from sentrix_ml.train_source import split_source_data
            parts = split_source_data(X, y, info, test_fraction=test_fraction,
                                      val_fraction=val_fraction, seed=seed)
        elif domain == "omni":
            parts = stratified_split(X, y, test_fraction=test_fraction, val_fraction=val_fraction, **kwargs)
        else:
            parts = adaptation_split(X, y, study_fraction=study_fraction,
                                     val_fraction_of_study=val_fraction, **kwargs)
        manifest = parts[-1]
        result.update(status="READY", partition_class_counts=manifest.partition_support,
                      duplicate_group_policy=manifest.duplicate_group_policy,
                      duplicate_rows_excluded=manifest.duplicate_rows_excluded,
                      unique_groups=manifest.unique_groups_count,
                      actual_partition_rows={"train": manifest.train_count, "validation": manifest.val_count, "test": manifest.test_count},
                      note="Configured data/partition gate passed; measure resources for the chosen fitting job.")
    except Exception as exc:
        result.update(status="FAILED", error=str(exc))
    return result


def check_ton_iot(data_dir, **kwargs):
    return _check(data_dir, "ton_iot", **kwargs)


def check_bot_iot(data_dir, **kwargs):
    return _check(data_dir, "bot_iot", **kwargs)


def check_cic_ids2017(data_dir, **kwargs):
    return _check(data_dir, "cic_ids2017", **kwargs)


def run_preflight(argv=None):
    args = parse_args(argv)
    env_info, env_ok = check_environment(require_tf=args.require_tf)
    targets = list(LOADERS) + ["omni"] if args.target == "all" else [args.target]
    datasets = {}
    for domain in targets:
        datasets[domain] = _check(args.data_root if domain == "omni" else args.data_root / domain,
            domain, sample_n=args.sample_per_domain if domain == "omni" else args.sample_n,
            seed=args.seed, test_fraction=args.test_fraction, study_fraction=args.study_fraction,
            val_fraction=args.val_fraction)
    ready = env_ok and all(d["status"] == "READY" for d in datasets.values())
    report = {"schema": SCHEMA_VERSION, "environment": env_info, "datasets": datasets,
              "status": "READY" if ready else "FAILED", "config": {k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()}}
    print(json.dumps(report, indent=2))
    print("PREFLIGHT STATUS: " + ("READY FOR CONFIGURED RUN" if ready else "FAILED — BLOCKING ISSUES DETECTED"))
    if args.report_json:
        args.report_json.parent.mkdir(parents=True, exist_ok=True)
        args.report_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
    return 0 if ready else 1


if __name__ == "__main__":
    raise SystemExit(run_preflight())
