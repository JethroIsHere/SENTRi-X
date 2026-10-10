# Chapter 4 Empirical Evaluation: Physical Hardware Trial Matrix

**Execution Date:** 2026-10-10 10:39:10 UTC  
**Testbed:** SENTRi-X Edge Sensor (Raspberry Pi 3B) + SENTRi-X Dual-Engine API + Snort IDS Baseline  

---

## 1. Master Evaluation Results Table

| Trial ID | Dataset | Engine | Workload Case | Status | Alerts Observed | Detection Outcome | Latency (s) | Duration |
|---|---|---|---|---|---|---|---|---|
| `CH4-OMNI-RF-B0-9257` | **omni** | `rf` | `B0` | completed | 34 | false_positive | — | 182.0s |
| `CH4-OMNI-RF-S1-9444` | **omni** | `rf` | `S1` | completed | 49 | detected | — | 181.9s |
| `CH4-OMNI-RF-S2-9631` | **omni** | `rf` | `S2` | completed | 34 | detected | — | 183.0s |
| `CH4-OMNI-CNN-B0-9819` | **omni** | `cnn` | `B0` | completed | 33 | false_positive | — | 181.9s |
| `CH4-OMNI-CNN-S1-0006` | **omni** | `cnn` | `S1` | completed | 52 | detected | — | 181.9s |
| `CH4-OMNI-CNN-S2-0193` | **omni** | `cnn` | `S2` | completed | 32 | detected | — | 182.1s |
| `CH4-OMNI-HYBRID-B0-0380` | **omni** | `hybrid` | `B0` | completed | 31 | false_positive | — | 182.2s |
| `CH4-OMNI-HYBRID-S1-0568` | **omni** | `hybrid` | `S1` | completed | 51 | detected | — | 182.4s |
| `CH4-OMNI-HYBRID-S2-0755` | **omni** | `hybrid` | `S2` | preflight_failed | 0 | none | — | 4.5s |
| `CH4-TON_IOT-RF-B0-0779` | **ton_iot** | `rf` | `B0` | completed | 29 | false_positive | — | 182.9s |
| `CH4-TON_IOT-RF-S1-0967` | **ton_iot** | `rf` | `S1` | completed | 50 | detected | — | 182.5s |
| `CH4-TON_IOT-RF-S2-1155` | **ton_iot** | `rf` | `S2` | completed | 32 | detected | — | 182.2s |
| `CH4-TON_IOT-CNN-B0-1342` | **ton_iot** | `cnn` | `B0` | completed | 24 | false_positive | — | 182.1s |
| `CH4-TON_IOT-CNN-S1-1529` | **ton_iot** | `cnn` | `S1` | preflight_failed | 0 | none | — | 2.7s |
| `CH4-TON_IOT-CNN-S2-1537` | **ton_iot** | `cnn` | `S2` | completed | 26 | detected | — | 182.0s |
| `CH4-TON_IOT-HYBRID-B0-1724` | **ton_iot** | `hybrid` | `B0` | completed | 30 | false_positive | — | 182.2s |
| `CH4-TON_IOT-HYBRID-S1-1911` | **ton_iot** | `hybrid` | `S1` | completed | 44 | detected | — | 182.5s |
| `CH4-TON_IOT-HYBRID-S2-2099` | **ton_iot** | `hybrid` | `S2` | completed | 28 | detected | — | 182.0s |
| `CH4-BOT_IOT-RF-B0-2294` | **bot_iot** | `rf` | `B0` | completed | 25 | false_positive | — | 182.1s |
| `CH4-BOT_IOT-RF-S1-2481` | **bot_iot** | `rf` | `S1` | completed | 43 | detected | — | 182.5s |
| `CH4-BOT_IOT-RF-S2-2669` | **bot_iot** | `rf` | `S2` | completed | 27 | detected | — | 182.4s |
| `CH4-BOT_IOT-CNN-B0-2856` | **bot_iot** | `cnn` | `B0` | completed | 0 | clean | — | 182.8s |
| `CH4-BOT_IOT-CNN-S1-3044` | **bot_iot** | `cnn` | `S1` | completed | 0 | missed | — | 182.6s |
| `CH4-BOT_IOT-CNN-S2-3231` | **bot_iot** | `cnn` | `S2` | completed | 0 | missed | — | 182.2s |
| `CH4-BOT_IOT-HYBRID-B0-3419` | **bot_iot** | `hybrid` | `B0` | completed | 0 | clean | — | 182.3s |
| `CH4-BOT_IOT-HYBRID-S1-3606` | **bot_iot** | `hybrid` | `S1` | completed | 0 | missed | — | 183.2s |
| `CH4-BOT_IOT-HYBRID-S2-3794` | **bot_iot** | `hybrid` | `S2` | completed | 0 | missed | — | 182.3s |
| `CH4-CIC_IDS2017-RF-B0-3991` | **cic_ids2017** | `rf` | `B0` | completed | 0 | clean | — | 182.7s |
| `CH4-CIC_IDS2017-RF-S1-4178` | **cic_ids2017** | `rf` | `S1` | completed | 0 | missed | — | 182.4s |
| `CH4-CIC_IDS2017-RF-S2-4366` | **cic_ids2017** | `rf` | `S2` | completed | 0 | missed | — | 182.1s |
| `CH4-CIC_IDS2017-CNN-B0-4553` | **cic_ids2017** | `cnn` | `B0` | completed | 26 | false_positive | — | 181.9s |
| `CH4-CIC_IDS2017-CNN-S1-4740` | **cic_ids2017** | `cnn` | `S1` | completed | 44 | detected | — | 182.0s |
| `CH4-CIC_IDS2017-CNN-S2-4927` | **cic_ids2017** | `cnn` | `S2` | completed | 27 | detected | — | 182.1s |
| `CH4-CIC_IDS2017-HYBRID-B0-5114` | **cic_ids2017** | `hybrid` | `B0` | completed | 4 | false_positive | — | 182.3s |
| `CH4-CIC_IDS2017-HYBRID-S1-5302` | **cic_ids2017** | `hybrid` | `S1` | completed | 37 | detected | — | 182.2s |
| `CH4-CIC_IDS2017-HYBRID-S2-5489` | **cic_ids2017** | `hybrid` | `S2` | completed | 4 | detected | — | 182.0s |
| `CH4-SNORT-B0-5676` | **snort** | `snort` | `B0` | completed | 0 | clean | — | 181.5s |
| `CH4-SNORT-S1-5862` | **snort** | `snort` | `S1` | completed | 0 | missed | — | 181.6s |
| `CH4-SNORT-S2-6049` | **snort** | `snort` | `S2` | completed | 0 | missed | — | 181.6s |
| `CH4-RERUN-OMNI-HYBRID-S2` | **omni** | `hybrid` | `S2` | completed | 32 | detected | — | 182.0s |
| `CH4-RERUN-TON-CNN-S1` | **ton_iot** | `cnn` | `S1` | completed | 44 | detected | — | 182.0s |
| `CH4-RERUN-OMNI-HYBRID-B0` | **omni** | `hybrid` | `B0` | completed | 15 | false_positive | — | 182.0s |
| `CH4-RERUN-OMNI-HYBRID-S1` | **omni** | `hybrid` | `S1` | completed | 51 | detected | — | 182.0s |

---

## 2. Snort vs. SENTRi-X Comparative Summary (Table 4.1)

| Workload Case | Scenario Description | Snort Baseline | SENTRi-X (Hybrid) | Primary Advantage |
|---|---|---|---|---|
| **B0 (Synthetic)** | Benign HTTP Authentication (20 rapid logins in 30s) | 0 Alerts (Normal) | 31 False Positives | Rapid login burst flagged anomalous (0.83–0.95 conf); motivates passive baseline redesign |
| **B0 (Passive)** | Benign Passive Baseline (0 synthetic requests) | 0 Alerts (Normal) | 15 Candidate Alerts | Idle baseline without synthetic burst artifacts; observes natural device traffic |
| **S1** | Bounded TCP Port Scan (50 ports) | 0 Alerts (Missed) | Detected (51 alerts) | Behavioral anomaly detection where Snort static signatures failed |
| **S2** | Credential Probing (20 failed logins) | 0 Alerts (Missed) | Detected (32 alerts) | Behavioral detection of brute force probing (validated via `CH4-RERUN-OMNI-HYBRID-S2`) |

---

## 3. Multi-Model Performance Comparison on Live Hardware (Table 4.2)

| Model Domain | Engine | Port Scan (S1) Detection | Credential Probing (S2) Detection | Benign (B0) False Alarms |
|---|---|---|---|---|
| **bot_iot** | `cnn` | Missed | Missed | 0 FP (Clean) |
| **bot_iot** | `hybrid` | Missed | Missed | 0 FP (Clean) |
| **bot_iot** | `rf` | Detected | Detected | 25 FP |
| **cic_ids2017** | `cnn` | Detected | Detected | 26 FP |
| **cic_ids2017** | `hybrid` | Detected | Detected | 4 FP |
| **cic_ids2017** | `rf` | Missed | Missed | 0 FP (Clean) |
| **omni** | `cnn` | Detected | Detected | 33 FP |
| **omni** | `hybrid` | Detected | Detected (32 alerts)* | 31 FP (15 FP Passive)* |
| **omni** | `rf` | Detected | Detected | 34 FP |
| **ton_iot** | `cnn` | Detected (44 alerts)* | Detected | 24 FP |
| **ton_iot** | `hybrid` | Detected | Detected | 30 FP |
| **ton_iot** | `rf` | Detected | Detected | 29 FP |

*\*Updated with remediated hardware re-runs (`CH4-RERUN-OMNI-HYBRID-S2`, `CH4-RERUN-TON-CNN-S1`, and `CH4-RERUN-OMNI-HYBRID-B0`).*

---

## 4. Empirical Remediation & Trial Audit Analysis

### Phase 1: B0 False Positive Diagnosis
- **Investigation:** Examined raw flow records and candidate alerts across all B0 trials.
- **Findings:**
  1. *Synthetic burst anomaly:* The initial B0 test generated 20 rapid HTTP logins in 30 seconds to port 8088 (`192.168.254.184:8088`). All models classified these bursts as anomalous (confidence 0.83–0.95), indistinguishable from S2 credential probing. Twenty logins in 30s is not natural user behavior.
  2. *Natural IoT Traffic:* Background IoT traffic from monitored devices (e.g. Tuya cloud heartbeats from `192.168.254.100` to `47.236.105.163:8883` on MQTT/TLS) was correctly scored as **benign (`is_anomaly = 0`)** by the hybrid ensemble.
  3. *Passive B0 Redesign:* B0 was redesigned (commit `2b5bc5b`) to generate zero synthetic traffic, passively observing natural device behavior for the 30-second action window.

### Phase 2: Whitelist Status
- Background IoT cloud endpoints (`47.236.105.163:8883`) and LAN broadcast packets (`255.255.255.255`) did **not** trigger alerts under the classifier (`is_anomaly = 0`). Consequently, IP whitelist rules were not required for cloud services.
- Remaining candidate alerts during passive baseline correspond to inter-host telemetry and health preflight checks between the laptop (`192.168.254.156`) and the defending Pi (`192.168.254.184`).

### Phase 3: Remediated Trials (Preflight Resolution)
Two trials in the initial matrix failed preflight due to transient target HTTP timeouts. With target health verified and service active, both trials were re-executed:
- `CH4-RERUN-OMNI-HYBRID-S2`: **Detected** (32 candidate alerts, 20/20 probe actions executed).
- `CH4-RERUN-TON-CNN-S1`: **Detected** (44 candidate alerts, 40 port scan actions executed).

### Phase 4: Validation Trials
- `CH4-RERUN-OMNI-HYBRID-B0` (Passive Benign Baseline): Completed with 0 planned and 0 attempted synthetic actions. Candidate alerts dropped from 31 to 15.
- `CH4-RERUN-OMNI-HYBRID-S1` (Port Scan Validation): **Detected** with 51 candidate alerts, confirming attack detection efficacy remained uncompromised.

*Generated automatically by SENTRi-X Lab Test Kit Batch Orchestrator.*
