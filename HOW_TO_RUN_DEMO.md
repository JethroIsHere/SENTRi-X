# SENTRi-X Live Hardware Demo Guide

This guide provides a step-by-step walkthrough to run a live demonstration of the **SENTRi-X Intrusion Detection System**, including the Raspberry Pi edge sensor, Snort baseline comparison, automated **Live Demo Matrix** (`demo_matrix.py`), and the **6-Trial Scored Demonstration Protocol**.

---

## Architecture & IP Quick Reference (Single-Laptop Topology)

In this testbed, **your laptop** acts as the **Attacker** (injecting traffic via Python/WSL) and hosts the **SENTRi-X Engine & Dashboard**, while your **physical IoT device** (or Pi target) acts as the **Victim / Protected Asset**, and the **Raspberry Pi 3B+** acts as the **Edge Sensor / Defender probe**. A second laptop is **not** required.

| Component | Role in Lab | Host / Device | IP / Address | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Attacker Generator** | Attacker | Windows / WSL2 (Your Laptop) | `192.168.254.156` | Runs `demo_matrix.py`, `run_trial.py`, or attack scripts |
| **Backend API** | Defender Core | Windows host (WSL2) | `127.0.0.1:8000` / `192.168.254.141:8000` | Random Forest + 1D-CNN + XAI API |
| **Frontend UI** | Monitoring Station | Windows host (Your Laptop) | `http://localhost:5173` | React + Vite live dashboard |
| **Edge Sensor (Pi)** | Defender Probe | Raspberry Pi (`raspy3`) | **`192.168.254.184`** (mDNS: `raspy3.local`) | SSH: `ssh raspy3@192.168.254.184`; sniffs subnet traffic |
| **Target Device (IoT)** | Victim / Protected Asset | Physical Smart Socket / Plug | `192.168.254.xxx` | Protected smart device (or Pi target port `8088`) |
| **Snort IDS** | Baseline Comparator | Windows host (WSL2) | Interface `eth0` | Manuscript baseline comparator (optional; use `--no-snort`) |

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

1. **SSH directly into the Raspberry Pi:**
   ```bash
   ssh raspy3@192.168.254.184
   ```
   *(Or using mDNS hostname: `ssh raspy3@raspy3.local`)*
   
   > **Important Details:**
   > - **Username:** `raspy3`
   > - **IP Address:** `192.168.254.184`
   > - **Hostname:** `raspy3.local` (*Do NOT use `raspberrypi.local`, as the Pi hostname is configured as `raspy3`*).
   > - **Tip (If IP changed via DHCP):** On Windows PowerShell, find the Pi by its Raspberry Pi MAC address prefix:
   >   ```powershell
   >   Get-NetNeighbor | Where-Object { $_.LinkLayerAddress -like "b8-27-eb*" }
   >   ```

2. **Start the Sensor on the Pi:**
   ```bash
   # Option A: If your sensor script is in the home directory:
   sudo python3 ~/sentrix_sensor.py
   ```
   *Option B: If running from the cloned repository on the Pi:*
   ```bash
   cd ~/SENTRi-X
   source venv/bin/activate

   # Explicitly set the host backend URL (Defending host IP: 192.168.254.141 or 192.168.254.156)
   SENTRIX_BACKEND_URL="http://192.168.254.141:8000/api/ingest-flow" \
   SENTRIX_HEARTBEAT_URL="http://192.168.254.141:8000/api/heartbeat" \
   sudo -E python3 edge/sentrix_sensor.py
   ```

3. **Check Connection**:
   - The Pi console will display flow transmission summaries (`[FLOW] Sent flow ... 200 OK`).
   - On the web dashboard, the status badge will turn green (**"Sensor Online"**).
   - `curl.exe http://127.0.0.1:8000/api/status` will show `"is_hardware_live": true` and `"node_status": "Active Sensor"`.

---

## Step 4: Snort Status (Optional Baseline)

* **Is Snort required for the live defense demo?** **No.**
* Snort is an offline/manuscript benchmark for Chapters 3 and 4. During live evaluation, append `--no-snort` to avoid extraneous daemon overhead.
* If you do wish to run Snort concurrently for live comparison:
  ```bash
  sudo /usr/sbin/snort -m 027 -D -d -l /var/log/snort -u snort -g snort -c /etc/snort/snort.conf -i eth0
  ```
*(For full details and verbal defense scripts regarding Snort, see [THESIS_DEFENSE_AND_SNORT_BASELINE_GUIDE.md](THESIS_DEFENSE_AND_SNORT_BASELINE_GUIDE.md)).*

---

## Step 5: Configure the Target Device (Physical IoT Device or Pi Service)

You can direct attack traffic toward either a **real physical smart device** (recommended for defense impact) or the **Raspberry Pi target service**:

### Option A: Physical IoT Device as Target (Recommended)
1. **Find Smart Device IP and MAC**:
   - Look at the **Observed Devices** section in the SENTRi-X dashboard (`http://localhost:5173`) or your Wi-Fi router.
   - Example: IP `192.168.254.210`, MAC `d8:1f:12:34:56:78`.
2. **Ensure Device is Enrolled**:
   - Go to **System Settings** (`/system-settings`) and ensure the device MAC is listed in **Monitored Devices** so the sensor attributes and tracks its flows.
3. **Set Target in `config.demo.json`**:
   - In `attack_scripts/TestKit/config.demo.json`, update `target_ip` and `target_mac`:
     ```json
     "target_ip": "192.168.254.210",
     "target_mac": "d8:1f:12:34:56:78",
     ```
   *(Physical smart devices are always on; no target daemon needs to be launched on the plug itself).*

### Option B: Raspberry Pi Target Service (Automated Alternative)
If the smart plug is unavailable or you want a dedicated HTTP test service:
1. **SSH into the Raspberry Pi:**
   ```bash
   ssh raspy3@192.168.254.184
   ```
2. **Start the target service:**
   ```bash
   cd ~/SENTRi-X/attack_scripts/TestKit
   python3 lab_target.py --bind 192.168.254.184 --port 8088 --log target_evidence/service.jsonl
   ```

---

## Step 6: Run the Live Demo Matrix (`demo_matrix.py`) from your Laptop

Your laptop injects attacks toward the target (the IoT device or Pi) while the Pi sensor captures the traffic and streams flow windows to the SENTRi-X backend in real time.

The trial configuration is located at `attack_scripts/TestKit/config.demo.json`.

### Option A: Plan Preview (Dry-Run - 0 seconds)
Verify configuration and backend reachability without injecting network traffic:
```powershell
cd C:\Users\LENOVO\SENTRi-X\attack_scripts\TestKit
python demo_matrix.py --config config.demo.json --backend http://127.0.0.1:8000 --dry-run
```

### Option B: Fast Live Presentation Demo (~15-20 minutes, Recommended)
Runs all 4 dataset models in **Hybrid Mode** at fast pacing (`--pace fast`) without Snort:
```powershell
cd C:\Users\LENOVO\SENTRi-X\attack_scripts\TestKit
python demo_matrix.py --config config.demo.json --backend http://127.0.0.1:8000 --pace fast --no-snort --yes
```

### Option C: Single-Dataset Quick Demo (~5 minutes)
Runs only the `omni` dataset model (ideal for quick 5-minute defense presentations):
```powershell
cd C:\Users\LENOVO\SENTRi-X\attack_scripts\TestKit
python demo_matrix.py --config config.demo.json --backend http://127.0.0.1:8000 --datasets omni --pace fast --no-snort --yes
```

### Option D: Full 45-Trial Evaluation Matrix (~90-120 minutes)
Runs all 4 datasets across all 3 model modes (`rf`, `cnn`, `hybrid`):
```powershell
cd C:\Users\LENOVO\SENTRi-X\attack_scripts\TestKit
python demo_matrix.py --config config.demo.json --backend http://127.0.0.1:8000 --pace full --modes rf cnn hybrid --no-snort --yes
```

---

## Step 7: View the HTML Report & Evidence

1. Once the matrix run completes, open the generated HTML report:
   ```powershell
   # Opens the latest report in your default browser:
   explorer.exe (Get-ChildItem -Directory "demo_*" | Sort-Object CreationTime -Descending | Select-Object -First 1).FullName\demo_matrix_report.html
   ```
2. The report presents:
   - Bar charts comparing candidate alert counts for **B0** (Benign), **S1** (Port Scan), and **S2** (Failed Logins).
   - Pacing and timing metadata.
   - Direct links to per-trial raw evidence bundles under `evidence/<trial_id>/`.

---

## Step 8: Scored Demonstration Trials (6-Trial Controlled Protocol)

For a structured, verifiable evaluation protocol (prepared for supplementary defense materials), execute the 6 controlled trials detailed in [SCORED_DEMO_PROTOCOL.md](attack_scripts/TestKit/SCORED_DEMO_PROTOCOL.md):

```bash
cd attack_scripts/TestKit

# 2x Benign Baseline Trials (B0)
python3 run_trial.py --config config.demo.json --case B0 --engine hybrid --trial-id SCORED-B0-01 --execute
python3 run_trial.py --config config.demo.json --case B0 --engine hybrid --trial-id SCORED-B0-02 --execute

# 2x Bounded Port Scan Trials (S1)
python3 run_trial.py --config config.demo.json --case S1 --engine hybrid --trial-id SCORED-S1-01 --execute
python3 run_trial.py --config config.demo.json --case S1 --engine hybrid --trial-id SCORED-S1-02 --execute

# 2x HTTP Brute-Force Trials (S2)
python3 run_trial.py --config config.demo.json --case S2 --engine hybrid --trial-id SCORED-S2-01 --execute
python3 run_trial.py --config config.demo.json --case S2 --engine hybrid --trial-id SCORED-S2-02 --execute
```

- Each trial runs ~3.5 minutes (60s warmup + 30s action + 120s scoring window).
- Summarize results as raw counts: *"Of 4 attack runs, X produced an alert in-window; of 2 passive windows, Y stayed quiet."*

---

## Step 9: Manual Single-Trial Execution (Alternative)

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
