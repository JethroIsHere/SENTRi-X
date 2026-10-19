#!/usr/bin/env python3
"""SENTRi-X Performance & Inference Latency Benchmark.

Addresses Chapter 5 Recommendation #5:
- Measures per-flow and batched inference latency across RF, CNN, and Hybrid modes.
- Measures host CPU% and Memory RSS footprint.
- Validates sustained throughput (flows/second).
"""

import sys
import time
import json
import psutil
from pathlib import Path
import numpy as np

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from sentrix_ml.schema import NUM_FEATURES
from sentrix_ml.preprocessing import PreprocessingPipeline
from sentrix_ml.inference import hybrid_predict, run_single_inference
import joblib


def benchmark_engine(candidate_dir: Path, n_iterations: int = 500) -> dict:
    rf_path = candidate_dir / "rf_model.joblib"
    cnn_path = candidate_dir / "cnn_model.h5"
    pipe_path = candidate_dir / "pipeline.joblib"

    if not (rf_path.exists() and pipe_path.exists()):
        return {"error": f"Missing artifacts in {candidate_dir}"}

    rf = joblib.load(rf_path)
    pipe = joblib.load(pipe_path)
    cnn = None
    if cnn_path.exists():
        from tensorflow.keras.models import load_model
        cnn = load_model(cnn_path, compile=False)

    np.random.seed(42)
    dummy_raw = np.random.uniform(0.0, 1000.0, size=(n_iterations, NUM_FEATURES))
    dummy_scaled = pipe.transform(dummy_raw)

    proc = psutil.Process()
    mem_before = proc.memory_info().rss / (1024 * 1024)

    results = {
        "candidate": candidate_dir.name,
        "n_samples": n_iterations,
        "modes": {},
        "memory_rss_mib": round(mem_before, 2),
    }

    # Warmup
    _ = hybrid_predict(dummy_scaled[:5], rf_model=rf, cnn_model=cnn, mode="hybrid")

    for mode in ["rf", "cnn", "hybrid"]:
        if mode in ("cnn", "hybrid") and cnn is None:
            continue

        latencies_ms = []
        t_start = time.perf_counter()

        for i in range(n_iterations):
            row = dummy_scaled[i:i+1]
            t0 = time.perf_counter()
            _ = hybrid_predict(row, rf_model=rf, cnn_model=cnn, mode=mode)
            t1 = time.perf_counter()
            latencies_ms.append((t1 - t0) * 1000.0)

        total_time = time.perf_counter() - t_start
        throughput = n_iterations / total_time if total_time > 0 else 0.0

        results["modes"][mode] = {
            "mean_latency_ms": round(float(np.mean(latencies_ms)), 4),
            "median_latency_ms": round(float(np.median(latencies_ms)), 4),
            "p95_latency_ms": round(float(np.percentile(latencies_ms, 95)), 4),
            "p99_latency_ms": round(float(np.percentile(latencies_ms, 99)), 4),
            "throughput_flows_per_sec": round(float(throughput), 2),
        }

    return results


def main():
    candidate_path = ROOT_DIR / "models" / "candidates" / "omni_v2"
    print(f"Running performance benchmark on {candidate_path.name}...")
    res = benchmark_engine(candidate_path, n_iterations=300)
    print(json.dumps(res, indent=2))

    out_file = ROOT_DIR / "outputs" / "performance_benchmark.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w") as f:
        json.dump(res, f, indent=2)
    print(f"Benchmark results saved to {out_file}")


if __name__ == "__main__":
    main()
