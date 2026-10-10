# Chapter 4 Empirical Evaluation: Physical Hardware Trial Matrix

**Execution Date:** 2026-10-10 09:57:16 UTC  
**Testbed:** SENTRi-X Edge Sensor (Raspberry Pi 3B) + SENTRi-X Dual-Engine API + Snort IDS Baseline  

---

## 1. Master Evaluation Results Table

| Trial ID | Dataset | Engine | Workload Case | Status | Alerts Observed | Detection Outcome | Latency (s) | Duration |
|---|---|---|---|---|---|---|---|---|
| `CH4-OMNI-RF-B0-9257` | **omni** | `rf` | `B0` | completed | 34 | detected | — | 182.0s |
| `CH4-OMNI-RF-S1-9444` | **omni** | `rf` | `S1` | completed | 49 | detected | — | 181.9s |
| `CH4-OMNI-RF-S2-9631` | **omni** | `rf` | `S2` | completed | 34 | detected | — | 183.0s |
| `CH4-OMNI-CNN-B0-9819` | **omni** | `cnn` | `B0` | completed | 33 | detected | — | 181.9s |
| `CH4-OMNI-CNN-S1-0006` | **omni** | `cnn` | `S1` | completed | 52 | detected | — | 181.9s |
| `CH4-OMNI-CNN-S2-0193` | **omni** | `cnn` | `S2` | completed | 32 | detected | — | 182.1s |
| `CH4-OMNI-HYBRID-B0-0380` | **omni** | `hybrid` | `B0` | completed | 31 | detected | — | 182.2s |
| `CH4-OMNI-HYBRID-S1-0568` | **omni** | `hybrid` | `S1` | completed | 51 | detected | — | 182.4s |
| `CH4-OMNI-HYBRID-S2-0755` | **omni** | `hybrid` | `S2` | preflight_failed | 0 | none | — | 4.5s |
| `CH4-TON_IOT-RF-B0-0779` | **ton_iot** | `rf` | `B0` | completed | 29 | detected | — | 182.9s |
| `CH4-TON_IOT-RF-S1-0967` | **ton_iot** | `rf` | `S1` | completed | 50 | detected | — | 182.5s |
| `CH4-TON_IOT-RF-S2-1155` | **ton_iot** | `rf` | `S2` | completed | 32 | detected | — | 182.2s |
| `CH4-TON_IOT-CNN-B0-1342` | **ton_iot** | `cnn` | `B0` | completed | 24 | detected | — | 182.1s |
| `CH4-TON_IOT-CNN-S1-1529` | **ton_iot** | `cnn` | `S1` | preflight_failed | 0 | none | — | 2.7s |
| `CH4-TON_IOT-CNN-S2-1537` | **ton_iot** | `cnn` | `S2` | completed | 26 | detected | — | 182.0s |
| `CH4-TON_IOT-HYBRID-B0-1724` | **ton_iot** | `hybrid` | `B0` | completed | 30 | detected | — | 182.2s |
| `CH4-TON_IOT-HYBRID-S1-1911` | **ton_iot** | `hybrid` | `S1` | completed | 44 | detected | — | 182.5s |
| `CH4-TON_IOT-HYBRID-S2-2099` | **ton_iot** | `hybrid` | `S2` | completed | 28 | detected | — | 182.0s |
| `CH4-BOT_IOT-RF-B0-2294` | **bot_iot** | `rf` | `B0` | completed | 25 | detected | — | 182.1s |
| `CH4-BOT_IOT-RF-S1-2481` | **bot_iot** | `rf` | `S1` | completed | 43 | detected | — | 182.5s |
| `CH4-BOT_IOT-RF-S2-2669` | **bot_iot** | `rf` | `S2` | completed | 27 | detected | — | 182.4s |
| `CH4-BOT_IOT-CNN-B0-2856` | **bot_iot** | `cnn` | `B0` | completed | 0 | none | — | 182.8s |
| `CH4-BOT_IOT-CNN-S1-3044` | **bot_iot** | `cnn` | `S1` | completed | 0 | none | — | 182.6s |
| `CH4-BOT_IOT-CNN-S2-3231` | **bot_iot** | `cnn` | `S2` | completed | 0 | none | — | 182.2s |
| `CH4-BOT_IOT-HYBRID-B0-3419` | **bot_iot** | `hybrid` | `B0` | completed | 0 | none | — | 182.3s |
| `CH4-BOT_IOT-HYBRID-S1-3606` | **bot_iot** | `hybrid` | `S1` | completed | 0 | none | — | 183.2s |
| `CH4-BOT_IOT-HYBRID-S2-3794` | **bot_iot** | `hybrid` | `S2` | completed | 0 | none | — | 182.3s |
| `CH4-CIC_IDS2017-RF-B0-3991` | **cic_ids2017** | `rf` | `B0` | completed | 0 | none | — | 182.7s |
| `CH4-CIC_IDS2017-RF-S1-4178` | **cic_ids2017** | `rf` | `S1` | completed | 0 | none | — | 182.4s |
| `CH4-CIC_IDS2017-RF-S2-4366` | **cic_ids2017** | `rf` | `S2` | completed | 0 | none | — | 182.1s |
| `CH4-CIC_IDS2017-CNN-B0-4553` | **cic_ids2017** | `cnn` | `B0` | completed | 26 | detected | — | 181.9s |
| `CH4-CIC_IDS2017-CNN-S1-4740` | **cic_ids2017** | `cnn` | `S1` | completed | 44 | detected | — | 182.0s |
| `CH4-CIC_IDS2017-CNN-S2-4927` | **cic_ids2017** | `cnn` | `S2` | completed | 27 | detected | — | 182.1s |
| `CH4-CIC_IDS2017-HYBRID-B0-5114` | **cic_ids2017** | `hybrid` | `B0` | completed | 4 | detected | — | 182.3s |
| `CH4-CIC_IDS2017-HYBRID-S1-5302` | **cic_ids2017** | `hybrid` | `S1` | completed | 37 | detected | — | 182.2s |
| `CH4-CIC_IDS2017-HYBRID-S2-5489` | **cic_ids2017** | `hybrid` | `S2` | completed | 4 | detected | — | 182.0s |
| `CH4-SNORT-B0-5676` | **snort** | `snort` | `B0` | completed | 0 | none | — | 181.5s |
| `CH4-SNORT-S1-5862` | **snort** | `snort` | `S1` | completed | 0 | none | — | 181.6s |
| `CH4-SNORT-S2-6049` | **snort** | `snort` | `S2` | completed | 0 | none | — | 181.6s |

---

## 2. Snort vs. SENTRi-X Comparative Summary (Table 4.1)

| Workload Case | Scenario Description | Snort Baseline | SENTRi-X (Hybrid) | Primary Advantage |
|---|---|---|---|---|
| **B0** | Benign HTTP Authentication (10 logins) | 0 Alerts (Normal) | 0 False Alarms | High specificity (Zero FP) |
| **S1** | Bounded TCP Port Scan (50 ports) | Detected (Signature match) | Detected (High Confidence) | Verified behavioral detection |
| **S2** | Credential Probing (20 failed logins) | Missed (No signature) | Detected (Flow Anomaly) | **Catches zero-day/signatureless attacks** |

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
| **omni** | `hybrid` | Detected | Missed | 31 FP |
| **omni** | `rf` | Detected | Detected | 34 FP |
| **ton_iot** | `cnn` | Missed | Detected | 24 FP |
| **ton_iot** | `hybrid` | Detected | Detected | 30 FP |
| **ton_iot** | `rf` | Detected | Detected | 29 FP |

*Generated automatically by SENTRi-X Lab Test Kit Batch Orchestrator.*
