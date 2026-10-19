# SENTRi-X Live Hardware Demo Guide

This guide provides a step-by-step walkthrough to run a live demonstration of the **SENTRi-X Intrusion Detection System**, including the Raspberry Pi edge sensor, Snort baseline comparison, and the automated **Live Demo Matrix** (`demo_matrix.py`).

---

## Architecture & IP Quick Reference

| Component | Host / Device | IP / Address | Notes |
| :--- | :--- | :--- | :--- |
| **Backend API** | Windows host (WSL2) | `127.0.0.1:8000` / `192.168.254.141:8000` | Port `8000` forwarded from Windows to WSL2 |
| **Frontend UI** | Windows host | `http://localhost:5173` | React + Vite dashboard |
| **Edge Sensor** | Raspberry Pi | Mirrored switch port | Sniffs IoT traffic, posts 28-feature flows |
| **Target Service** | Lab Target machine | `192.168.254.184:8088` | MAC: `b8:27:eb:98:08:95` |
| **Snort IDS** | Windows host (WSL2) | Interface `eth0` | Signature-based baseline comparator |

---

## Step 1: Start the SENTRi-X Backend (WSL)

The backend hosts the ML inference engines (Random Forest, 1D-CNN, Hybrid) and the live telemetry API.

1. **Start the backend** using the automated script:
   ```powershell
   # From Windows PowerShell:
   wsl bash /mnt/c/Users/LENOVO/SENTRi-X/backend/start_backend.sh
   ```
   *Or inside a WSL Ubuntu terminal:*
   ```bash
   cd /mnt/c/Users/LENOVO/SENTRi-X
   source wsl_venv/bin/activate
   cd backend
   python -u -m uvicorn main:app --host 0.0.0.0 --port 8000
   ```
2. **Verify Backend Status**:
   In PowerShell or browser, verify the API is alive:
   ```powershell
   curl.exe http://127.0.0.1:8000/api/status
   ```
   *Expected output:*
   - `"api_version": 2`
   - `"data_source": "live_hardware"`
   - `"rf_online": true`, `"cnn_online": true`
   - `"node_status": "Waiting for Pi"` (switches to `"Active Sensor"` once the Pi starts)

---

## Step 2: Start the SENTRi-X Frontend (Windows)

1. Open a PowerShell terminal and start the Vite dev server:
   ```powershell
   cd C:\Users\LENOVO\SENTRi-X\frontend
   npm run dev
   ```
2. Open your browser to **`http://localhost:5173`**.
3. **Demo Tip:** Navigate to **Threat Logs** (`http://localhost:5173/threat-logs`) to watch real-time detections and XAI explanations land during attack runs.

---

## Step 3: Start the Edge Sensor (Raspberry Pi)

The Pi captures packets at the network edge, extracts 28 flow features, and streams them with a periodic heartbeat to the backend.

1. SSH into the Raspberry Pi:
   ```bash
   ssh pi@<PI_IP>
   ```
2. Navigate to the project directory and start the sensor:
   ```bash
   cd ~/SENTRi-X
   source venv/bin/activate

   # Explicitly set the host backend URL (Host IP: 192.168.254.141)
   SENTRIX_BACKEND_URL="http://192.168.254.141:8000/api/ingest-flow" \
   SENTRIX_HEARTBEAT_URL="http://192.168.254.141:8000/api/heartbeat" \
   sudo -E python3 edge/sentrix_sensor.py
   ```
3. **Check Connection**:
   - The Pi console will display flow transmission summaries.
   - On the web dashboard, the status badge will turn green (**"Sensor Online"**).
   - `curl.exe http://127.0.0.1:8000/api/status` will show `"is_hardware_live": true`.

---

## Step 4: Start Snort (WSL - Optional / For Comparison)

If you are including Snort in the live comparison matrix:

1. In a WSL terminal, ensure Snort is running and logging alerts:
   ```bash
   sudo /usr/sbin/snort -m 027 -D -d -l /var/log/snort -u snort -g snort -c /etc/snort/snort.conf -i eth0
   ```
2. *Note:* If running the demo without Snort, simply add the `--no-snort` flag to the matrix command in Step 6.

---

## Step 5: Start the Lab Target Service

The lab target is a lightweight HTTP service running on the monitored machine whose traffic is mirrored to the Pi sensor.

1. On the lab target device (`192.168.254.184`):
   ```bash
   cd attack_scripts/TestKit
   python lab_target.py --bind 192.168.254.184 --port 8088 --log target_evidence/service.jsonl
   ```
2. Verify the port is listening and accessible from the generator host.

---

## Step 6: Run the Live Demo Matrix (`demo_matrix.py`)

The live demo matrix script automates the entire evaluation:
- Dynamically switches backend models (`omni`, `ton_iot`, `bot_iot`, `cic_ids2017`) via `POST /api/switch`.
- Executes bounded test cases:
  - **B0**: Benign background baseline (no attacks).
  - **S1**: Bounded TCP connect scan (50 ports + banner grab).
  - **S2**: 20 failed HTTP credential logins (brute force).
- Logs candidate alerts from the dashboard in real time.
- Compiles a self-contained HTML report with side-by-side comparison charts.

The trial configuration is located at `attack_scripts/TestKit/config.demo.json`.

### Option A: Plan Preview (Dry-Run - 0 seconds)
Verify configuration and backend reachability without injecting network traffic:
```powershell
cd C:\Users\LENOVO\SENTRi-X\attack_scripts\TestKit
python demo_matrix.py --config config.demo.json --backend http://127.0.0.1:8000 --dry-run
```

### Option B: Fast Live Presentation Demo (~15-20 minutes)
Runs all 4 dataset models in **Hybrid Mode** + Snort baseline at fast pacing (`--pace fast`):
```powershell
cd C:\Users\LENOVO\SENTRi-X\attack_scripts\TestKit
python demo_matrix.py --config config.demo.json --backend http://127.0.0.1:8000 --pace fast --yes
```

### Option C: Single-Dataset Quick Demo (~5 minutes)
Runs only the `omni` dataset model (ideal for quick 5-minute defense presentations):
```powershell
cd C:\Users\LENOVO\SENTRi-X\attack_scripts\TestKit
python demo_matrix.py --config config.demo.json --backend http://127.0.0.1:8000 --datasets omni --pace fast --yes
```

### Option D: Full 45-Trial Evaluation Matrix (~90-120 minutes)
Runs all 4 datasets across all 3 model modes (`rf`, `cnn`, `hybrid`) + Snort at full standard pacing:
```powershell
cd C:\Users\LENOVO\SENTRi-X\attack_scripts\TestKit
python demo_matrix.py --config config.demo.json --backend http://127.0.0.1:8000 --pace full --modes rf cnn hybrid --yes
```

> **Tip:** If Snort is not running or not needed, append `--no-snort` to any of the commands above.

---

## Step 7: View the HTML Report & Evidence

1. Once the matrix run completes, open the generated HTML report:
   ```powershell
   # Opens the latest report in your default browser:
   explorer.exe (Get-ChildItem -Directory "demo_*" | Sort-Object CreationTime -Descending | Select-Object -First 1).FullName\demo_matrix_report.html
   ```
2. The report presents:
   - Bar charts comparing candidate alert counts for **B0**, **S1**, and **S2** across models and Snort.
   - Pacing and timing metadata.
   - Direct links to per-trial raw evidence bundles under `evidence/<trial_id>/`.

---

## Step 8: Manual Single-Trial Execution (Alternative)

If you only want to demonstrate a single individual trial without the matrix runner:

- **Case B0 (Normal Behavior):**
  ```powershell
  python run_trial.py --config config.demo.json --case B0 --engine hybrid --trial-id DEMO-B0-001 --execute
  ```

- **Case S1 (Port Scanning):**
  ```powershell
  python run_trial.py --config config.demo.json --case S1 --engine hybrid --trial-id DEMO-S1-001 --execute
  ```

- **Case S2 (Repeated Failed Logins):**
  ```powershell
  python run_trial.py --config config.demo.json --case S2 --engine hybrid --trial-id DEMO-S2-001 --execute
  ```
