# SENTRi-X — Thesis Defense & Snort Baseline Guide

This document clarifies the role of **Snort** in the research manuscript versus the **Live Defense Demonstration**, outlines the **Single-Laptop Lab Topology**, and provides ready-to-use verbal defense scripts for questions commonly asked by thesis panelists.

> **Accuracy note (revised 21 October 2026):** Earlier drafts of this guide described Snort as a scored baseline with comparative metrics in Chapter 4. That was incorrect. Snort observed the hardware-trial traffic, but the trial outcomes were **not scored for either system**, and the manuscript reports **no comparative detection metrics**. The scripts below match the manuscript. Do not claim Snort results the manuscript does not contain.

---

## 1. Executive Summary & Clarification

* **Is Snort required during the live defense demonstration?**
  **No.** For the live demonstration, the panel evaluates the proposed **SENTRi-X** system (real-time edge capture, hybrid ML inference, live alerts, and Explainable AI).
* **What was Snort's role in the study?**
  Snort ran as a **second observer engine** in the Chapter 4 hardware trials, watching the same lab traffic as SENTRi-X. Those trial observations were recorded but **left unscored for both systems**, because scoring requires an independent review of ground truth, exposure, and alert timing. The manuscript therefore makes **no claim** that SENTRi-X outperforms Snort. A matched, scored comparison is **Recommendation #1** in Chapter 5.
* **Is there any scored live evidence?**
  **Supplementary only.** On 21 October, six small demonstration trials (B0 ×2, S1 ×2, S2 ×2) were run and scored under the protocol fixed in advance in `attack_scripts/TestKit/SCORED_DEMO_PROTOCOL.md`: 4 of 4 attack runs produced an alert in-window; both passive windows recorded false positives caused by the operator's own SSH administration sessions with the Pi (identified source). That sheet is supplementary material proposed for the revision — it does not change the status of the 43 Chapter 4 observations, which remain unscored, and it is not manuscript content.
* **Can the entire testbed run with only one laptop?**
  **Yes.** A second laptop is **not** required. The user's laptop acts as the **Attacker** (running attack scripts) and the **Dashboard Host**, while the physical smart device acts as the **Victim / Protected Asset**, and the Raspberry Pi 3B+ acts as the **Edge Sensor / Defender probe**.

---

## 2. Snort in the Manuscript vs. Live Defense

| Dimension | Manuscript Role (Chapters 3 & 4) | Live Defense Demonstration |
| :--- | :--- | :--- |
| **Purpose** | Signature-based observer in the hardware trials; a scored baseline comparison is planned future work (Chapter 5, Recommendation #1). | Demonstration of SENTRi-X operational capabilities, real-time edge capture, and XAI. |
| **Execution** | Ran alongside the trials through the test kit's Snort observer on the same lab traffic. | Live hardware streaming from Raspberry Pi 3B+ sensor to SENTRi-X engine. |
| **Detection Basis** | Handwritten text rules and static packet payload signatures. | Behavioral flow features scored by Hybrid Random Forest + 1D-CNN. |
| **Output Style** | Rule SID match and static category string. | Attack probability confidence (0.00–1.00) + SHAP & LIME feature contributions for the Random Forest component. |
| **Status** | Observations recorded; **unscored for both engines**; no comparative detection metrics reported. | **Optional**; run with `--no-snort` flag to avoid daemon overhead. |

**One documented Snort event:** the only confirmed Snort alert in the trial logs came from a custom test rule (SID 3000001) firing on the backend's own API traffic. It was identified as a rule-configuration artifact — not a detection result for either system — and is documented as such.

### Running the Live Demo Without Snort
To run the automated live demo matrix without starting the Snort daemon in WSL, simply include the `--no-snort` flag:

```powershell
cd C:\Users\LENOVO\SENTRi-X\attack_scripts\TestKit

# Fast presentation demo (Omni hybrid model, zero Snort dependency):
python demo_matrix.py --config config.demo.json --backend http://127.0.0.1:8000 --datasets omni --pace fast --no-snort --yes
```

---

## 3. The 3-Node Physical Lab Topology (1-Laptop Setup)

In an IoT Network Intrusion Detection System (NIDS), the roles are organized as follows:

```
┌────────────────────────────────────────────────────────┐
│                      YOUR LAPTOP                       │
│  ├── 1. Attacker Terminal (WSL: launch_attack.py)      │
│  ├── 2. SENTRi-X Hybrid AI Engine (Port 8000)          │
│  └── 3. Live React Dashboard UI (Port 5173)            │
└────────────────────────────────────────────────────────┘
          │ (Attack Traffic: SYN/UDP Flood)
          ▼
┌───────────────────────────┐      ┌─────────────────────────────┐
│  SMART IoT DEVICE (Socket)│      │    RASPBERRY PI 3B+ (IDS)   │
│  (192.168.254.xxx)        │      │    (192.168.254.184)        │
│                           │      │                             │
│  Protected Asset / Victim │◄─────┼── Passively sniffs traffic  │
│  (Cannot run AI models)   │      │   Extracts 28 flow features │
└───────────────────────────┘      │   Streams to Laptop API     │
                                   └─────────────────────────────┘
```

### Why the IoT Device is the "Victim", not the "Defender"
* Commercial smart plugs (e.g., Tuya, Sonoff) run on microcontrollers (ESP8266, BK7231N) with only ~50 KB of RAM and 2 MB of flash memory. They cannot run Python, Scikit-learn, PyTorch, or Snort.
* In IoT security, the smart device is the **Protected Asset (Victim)** that the defender is protecting against attacks.

### Why the Raspberry Pi is the "Defender / Edge Sensor"
* The Raspberry Pi 3B+ (`192.168.254.184`) runs `sentrix_sensor.py` in promiscuous capture mode on the local subnet.
* It captures frames sent between the Laptop (Attacker) and the Smart Device (Victim), extracts statistical flow metrics, and streams telemetry to the SENTRi-X engine.

---

## 4. Observed Protocols: TCP vs. UDP

The live flow tables display **TCP** and **UDP** (often misread as *DCP* due to font rendering):

### TCP (Transmission Control Protocol)
* **Characteristics**: Connection-oriented, reliable 3-way handshake (`SYN` ➔ `SYN-ACK` ➔ `ACK`), retransmissions.
* **IoT Functions**: Cloud telemetry synchronization via MQTT over TLS (port `8883`) or HTTPS (port `443`), firmware OTA updates, and SSH administration.
* **Attack Vectors**: TCP SYN Floods, Port Scanning (Nmap connect/syn scans), Credential Brute Force.

### UDP (User Datagram Protocol)
* **Characteristics**: Connectionless, lightweight datagrams, zero handshake delay.
* **IoT Functions**: Local smart home device discovery via **mDNS** (`224.0.0.251:5353`) and **SSDP** (`239.255.255.250:1900`), DNS resolution (`53`), and NTP time synchronization (`123`).
* **Attack Vectors**: Volumetric UDP Floods, DNS Amplification, and SSDP Reflection attacks.

---

## 5. Defense Presentation Scripts (Q&A Preparation)

### Question 1: *"Why is Snort not running live on your screen right now?"*
> **Answer**:
> *"Snort's role in this study was as a second observer engine in the Chapter 4 hardware trials — it watched the same lab traffic as SENTRi-X. Those trial outcomes were not scored for either system, because scoring requires an independent review of ground truth and alert timing, so the manuscript reports no comparative detection metrics and I make no claim that SENTRi-X outperforms Snort. A matched, scored comparison is the first recommendation in Chapter 5. For today's live defense, the goal is to demonstrate the operational pipeline of SENTRi-X itself — edge packet capture on the Raspberry Pi, hybrid ML inference, and explainable alerts via SHAP and LIME."*

### Question 2: *"How can you defend the IoT device if the device itself doesn't have an agent installed?"*
> **Answer**:
> *"Commercial IoT devices are deeply constrained embedded systems that lack the memory and processing power to run host-based security agents. SENTRi-X addresses this exact constraint by operating as a passive, agentless Network Intrusion Detection System. The Raspberry Pi edge sensor sits promiscuously on the network, monitoring communication flows to and from the IoT device without consuming a single cycle of the smart device's microcontroller."*

### Question 3: *"Can this entire system be tested using only a single laptop?"*
> **Answer**:
> *"Yes. In our live testbed, our laptop runs the attack suite in an isolated WSL terminal while simultaneously hosting the centralized ML detection engine and dashboard. The Raspberry Pi functions as the dedicated physical edge sensor on our subnet, passively inspecting traffic directed at the smart device. This accurately mirrors a real-world edge-to-cloud deployment without requiring redundant computing hardware."*

### Question 4: *"What is the primary advantage of SENTRi-X over a traditional tool like Snort?"*
> **Answer**:

### Question 5: *"Can the sensor see attacks on the wireless IoT devices, like the smart plug?"*
> **Answer**:
> *"A passive sensor only judges traffic that physically arrives at its port — placement decides what it is shown, and that rule binds Snort and Suricata too. In this testbed the wired segment is mirrored and the Raspberry Pi is also a monitored node, so attacks addressed to it are captured directly, and a wireless device's outbound and broadcast traffic does reach the sensor — a compromised device scanning or exfiltrating could be flagged. What the sensor cannot see is an inbound attack delivered point-to-point to a wireless device: the access point hands that unicast to the device alone, and no copy reaches the sensor. Covering that segment means mirroring the AP's uplink port or capturing at the gateway — identified deployment work, alongside the scored-trial program in Recommendation #1. The manuscript scopes the sensor to mirrored traffic; it does not claim whole-network visibility from a single port."*

> *"The detection basis is different. Snort is deterministic and rule-bound: it can only fire when traffic matches a pre-written signature. SENTRi-X scores the statistical behavior of each flow with a hybrid Random Forest and 1D-CNN ensemble, so traffic that resembles attack behavior in the training data can be flagged without a matching rule. It also integrates an Explainable AI layer — SHAP and LIME show which flow features most influenced the Random Forest component's score for a given alert. To be precise about scope: this study does not establish detection of novel or zero-day attacks — the performance claims come from held-out benchmark evaluation, and a scored head-to-head comparison with Snort remains future work."*
