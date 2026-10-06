# SENTRi-X Live Hardware Demo Guide

This guide explains how to start the SENTRi-X platform, the Raspberry Pi edge sensor, Snort (for baseline comparison), and how to inject attacks that both systems can detect during a live demonstration.

---

## 1. Start the SENTRi-X Backend (WSL/Linux)
The backend hosts the API and the machine learning inference engine. It must run inside WSL or Linux.

1. Open a WSL Ubuntu terminal.
2. Navigate to the project directory:
   ```bash
   cd /mnt/c/Users/LENOVO/SENTRi-X
   ```
3. Activate the WSL virtual environment:
   ```bash
   source wsl_venv/bin/activate
   ```
4. Start the Uvicorn server:
   ```bash
   cd backend
   python -m uvicorn main:app --host 0.0.0.0 --port 8000
   ```
*Wait for the `Application startup complete.` message. The machine learning models take 10-20 seconds to load into memory.*

---

## 2. Start the SENTRi-X Frontend (Windows)
The frontend is the React dashboard that visualizes the threats and XAI explanations.

1. Open a Windows PowerShell terminal.
2. Navigate to the frontend directory:
   ```powershell
   cd C:\Users\LENOVO\SENTRi-X\frontend
   ```
3. Start the Vite development server:
   ```powershell
   npm run dev
   ```
4. Open your browser and navigate to `http://localhost:5173`.

---

## 3. Start the Edge Sensor (Raspberry Pi)
The Raspberry Pi sits on the network edge, captures live packets, extracts features, and streams them to the backend.

1. SSH into the Raspberry Pi.
2. Navigate to the SENTRi-X project directory:
   ```bash
   cd ~/SENTRi-X
   ```
3. Activate the Pi's virtual environment:
   ```bash
   source venv/bin/activate
   ```
4. Run the sensor script as **root** (required for packet sniffing):
   ```bash
   sudo venv/bin/python edge/sentrix_sensor.py
   ```
*The sensor will automatically discover the backend on the network and begin streaming 28-feature flow data.*

---

## 4. Start Snort (WSL/Linux)
Snort is used to demonstrate the baseline capabilities of a signature-based IDS compared to SENTRi-X.

1. Open a second WSL Ubuntu terminal.
2. Start Snort in console mode to monitor live alerts on the `eth0` interface:
   ```bash
   sudo snort -i eth0 -c /etc/snort/snort.conf -A console
   ```

---

## 5. Running the Attack Scripts (Lab Test Kit)

The legacy `launch_attack.py` and `trigger_snort_baseline.py` scripts have been phased out. We now use the **SENTRi-X Lab Test Kit** (`run_trial.py` and `lab_target.py`) to generate bounded physical evaluation traffic.

### A. Set Up the Target Service
Run the lab target on a separate VM or lab computer (whose traffic is mirrored to the Pi sensor):
1. Extract `SENTRi-X_Lab_Test_Kit_v1.1.0.zip` to your target machine.
2. Run the target service:
   ```bash
   python lab_target.py --bind <LAB_TARGET_IPV4> --port 8088 --log target_evidence/service.jsonl
   ```
3. *Important*: Ensure the target machine's MAC address is added to `IOT_DEVICES` in the Pi's `sentrix_sensor.py` so the traffic is captured!

### B. Configure the Trial Generator
On the machine that will generate the attacks (can be this Windows host):
1. Open a PowerShell terminal and navigate to the extracted Test Kit folder:
   ```powershell
   cd C:\Users\LENOVO\SENTRi-X\attack_scripts\TestKit
   ```
2. Make a copy of `config.example.json` named `lab_config.json`.
3. Edit `lab_config.json` with the target's IP (`target_ip`) and MAC (`target_mac`), and ensure the backend URL points to the running backend API.

### C. Run the Evaluation Trials
Execute the three trial cases using the `run_trial.py` script. (If running on Windows PowerShell, use `py -3` or `python` instead of `python3`).

**Case B0 (Normal Behavior / Baseline):**
```powershell
python run_trial.py --config lab_config.json --case B0 --engine hybrid --trial-id DEMO-B0-001 --execute
```

**Case S1 (TCP Connect Scanning):**
```powershell
python run_trial.py --config lab_config.json --case S1 --engine hybrid --trial-id DEMO-S1-001 --execute
```
*(Both Snort and SENTRi-X should flag this activity depending on rules.)*

**Case S2 (Repeated Failed Logins / Stealthy Exploit):**
```powershell
python run_trial.py --config lab_config.json --case S2 --engine hybrid --trial-id DEMO-S2-001 --execute
```
*(Demonstrates advanced behavior capture where Snort stays silent, but SENTRi-X triggers an alert based on ML anomalies.)*

*Note: Allow the full three-minute warm-up/observation sequence to finish for each trial.*
