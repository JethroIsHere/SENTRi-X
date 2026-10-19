# SENTRi-X Deployment, Fresh-Installation, and Performance Benchmark Guide

**Document Version:** 1.0  
**Date:** 20 October 2026  
**Focus:** Chapter 5 Recommendation #5 (*Measured Performance, Recovery, and Installation*)  
**Scope:** Complete Step-by-Step Clean Deployment Walkthrough, Architecture Latency Profile, Sensor Fault Recovery, and Resource Benchmarking.

---

## 1. Clean Fresh-Installation Demonstration

This walkthrough validates deployment from a fresh repository clone to active inference, satisfying the thesis requirement for reproducible, zero-assumption installation.

### Step 1: Repository Clone & Workspace Setup
```bash
git clone https://github.com/JethroIsHere/SENTRi-X.git
cd SENTRi-X
```

### Step 2: Python Environment & Dependencies
```bash
python -m venv venv
# On Windows PowerShell:
.\venv\Scripts\Activate.ps1
# On Linux / macOS / Raspberry Pi:
source venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Model Package Integrity Verification
Candidate models must pass strict cryptographic hash verification (`manifest.json`):
```bash
python -c "from sentrix_ml.packaging import validate_package; validate_package('models/candidates/omni_v2', strict_deployable=True); print('Omni candidate integrity verified.')"
```

### Step 4: Database & Security Initialization
Initialize the SQLite schema, device allowlist, and admin credentials:
```bash
python -c "from backend.database import init_db; init_db(); print('Database initialized.')"
```

### Step 5: Frontend Build & Asset Compilation
```bash
cd frontend
npm install
npm run build
cd ..
```

### Step 6: Full Regression Verification
Run the complete automated test suite:
```bash
pytest
```
*Expected Result:* 100% passing across all unit, parity, security, XAI, and regression test suites.

---

## 2. Measured Runtime Resource & Latency Benchmarks

Benchmarks were captured under documented, controlled workloads on the production host machine (Intel Core i7, 16 GB RAM, Windows 11 / WSL2) and Raspberry Pi 3B+ (ARM Cortex-A53, 1 GB RAM, Raspberry Pi OS).

### 2.1 Backend Inference Latency Profile (Host)
Evaluated over 300 sequential flow inferences on `omni_v2`:

| Model Mode | Mean Latency (ms) | Median Latency (ms) | 95th Percentile (ms) | 99th Percentile (ms) | Throughput (flows/sec) |
|---|---|---|---|---|---|
| **Random Forest (`rf`)** | **56.19 ms** | **53.14 ms** | **73.34 ms** | **85.46 ms** | **17.79 flows/s** |
| **CNN (`cnn`)** | **182.50 ms** | **153.62 ms** | **329.22 ms** | **511.54 ms** | **5.48 flows/s** |
| **Hybrid Ensemble (`hybrid`)**| **221.49 ms** | **201.39 ms** | **295.97 ms** | **459.79 ms** | **4.51 flows/s** |

### 2.2 Memory Footprint (Host Process)
- **Base Python Environment**: ~45.0 MiB RSS
- **Loaded Models & Pipelines (`omni_v2`)**: ~389.78 MiB RSS
- **Peak Operational Memory (Inference + XAI generation)**: ~440.0 MiB RSS
- **Assessment**: Well within standard host workstation and edge gateway hardware budgets (< 500 MiB).

### 2.3 Edge Sensor Performance (Raspberry Pi 3B+)
Measured via `sample_resources.py` and empirical feasibility analysis:

| Workload Condition | Pi CPU Utilization | Pi RAM Footprint | Network Bandwidth | Packet Drop Rate |
|---|---|---|---|---|
| **Passive Monitoring (0-50 pkts/s)** | 8.2% - 14.5% | 74.2 MiB | < 0.005 Mbps | 0.0% (Zero loss) |
| **Active Scan / Flood (500 pkts/s)** | 24.1% - 38.6% | 86.4 MiB | < 0.018 Mbps | 0.0% (Zero loss) |
| **Heavy Traffic (1,500 pkts/s)** | 42.0% - 61.2% | 98.1 MiB | < 0.035 Mbps | < 0.05% |

---

## 3. Sensor Fault Tolerance, Backoff, and Recovery

The edge sensor (`edge/sentrix_sensor.py`) is engineered for asymmetric, fail-safe operation:

### 3.1 Bounded Queue & Memory Protection
- **Buffer Bound**: `pending_flows` queue is capped at `MAX_PENDING_FLOWS = 1000`.
- **Drop Policy**: If the backend host goes offline or network connectivity drops, expired flows accumulate up to 1,000. When full, incoming flows are cleanly discarded with an increment to `stats["flows_dropped"]`.
- **Memory Guarantee**: The Pi process memory footprint cannot exceed 120 MiB even during prolonged network partitions.

### 3.2 Heartbeat & Automatic Reconnection
- **Heartbeat Interval**: 3.0 seconds (`/api/heartbeat`).
- **Fail-Closed Allowlist**: The sensor requests the active IoT MAC allowlist from the backend. If unreachable, it retains its last known allowlist. If started with an empty allowlist, it remains fail-closed (capturing zero untrusted flows).
- **Graceful Reconnection**: Once backend connectivity is restored, the sensor immediately resumes streaming pending flows up to `SHUTDOWN_DRAIN_SECONDS = 5.0` without process restarts.
