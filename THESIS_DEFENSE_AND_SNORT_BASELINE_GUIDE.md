# SENTRi-X — Thesis Defense & Snort Baseline Guide

This document clarifies the role of **Snort** in the research manuscript versus the **Live Defense Demonstration**, outlines the **Single-Laptop Lab Topology**, and provides ready-to-use verbal defense scripts for questions commonly asked by thesis panelists.

---

## 1. Executive Summary & Clarification

* **Is Snort required during the live defense demonstration?**  
  **No.** Snort was used as the formal signature-based empirical baseline for **Chapters 3 and 4** of the manuscript. For the live demonstration, the panel evaluates the proposed **SENTRi-X** system (real-time edge capture, hybrid ML inference, live alerts, and Explainable AI).
* **Can the entire testbed run with only one laptop?**  
  **Yes.** A second laptop is **not** required. The user's laptop acts as the **Attacker** (running attack scripts) and the **Dashboard Host**, while the physical smart device acts as the **Victim / Protected Asset**, and the Raspberry Pi 3B+ acts as the **Edge Sensor / Defender probe**.

---

## 2. Snort in the Manuscript vs. Live Defense

| Dimension | Manuscript Role (Chapters 3 & 4) | Live Defense Demonstration |
| :--- | :--- | :--- |
| **Purpose** | Rigorous empirical baseline to benchmark detection accuracy against industry standard. | Demonstration of SENTRi-X operational capabilities, real-time edge capture, and XAI. |
| **Execution** | Controlled batch evaluation across test datasets and historical PCAP trials. | Live hardware streaming from Raspberry Pi 3B+ sensor to SENTRi-X engine. |
| **Detection Basis** | Handwritten text rules and static packet payload signatures. | Behavioral flow features scored by Hybrid Random Forest + 1D-CNN. |
| **Output Style** | Rule SID match and static category string. | Attack probability confidence (0.00–1.00) + LIME & SHAP feature importances. |
| **Requirement** | **Mandatory** for academic validity and comparative tables. | **Optional**; run with `--no-snort` flag to avoid daemon overhead. |

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
> *"Snort was utilized in Chapter 4 as our formal baseline comparator to benchmark signature-based detection against our proposed machine learning models under identical traffic splits. For today's live defense, our goal is to demonstrate the operational real-time pipeline of SENTRi-X—specifically edge packet capture on the Raspberry Pi, asymmetric feature streaming, and explainable inference via LIME and SHAP. The full comparative metrics against Snort are documented in Chapter 4, Table 4.X."*

### Question 2: *"How can you defend the IoT device if the device itself doesn't have an agent installed?"*
> **Answer**:  
> *"Commercial IoT devices are deeply constrained embedded systems that lack the memory and processing power to run host-based security agents. SENTRi-X addresses this exact constraint by operating as a passive, agentless Network Intrusion Detection System. The Raspberry Pi edge sensor sits promiscuously on the network, monitoring communication flows to and from the IoT device without consuming a single cycle of the smart device's microcontroller."*

### Question 3: *"Can this entire system be tested using only a single laptop?"*
> **Answer**:  
> *"Yes. In our live testbed, our laptop runs the attack suite in an isolated WSL terminal while simultaneously hosting the centralized ML detection engine and dashboard. The Raspberry Pi functions as the dedicated physical edge sensor on our subnet, passively inspecting traffic directed at the smart device. This accurately mirrors a real-world edge-to-cloud deployment without requiring redundant computing hardware."*

### Question 4: *"What is the primary advantage of SENTRi-X over a traditional tool like Snort?"*
> **Answer**:  
> *"Snort is deterministic and rule-bound: if an attack pattern does not match a pre-written signature, it fails silently. SENTRi-X uses a hybrid ensemble of Random Forest and 1D-CNN to detect statistical anomalies in flow behavior, allowing it to flag zero-day or modified attacks. Furthermore, SENTRi-X integrates an Explainable AI (XAI) layer with SHAP and LIME, showing network analysts exactly which feature attributes—such as packet inter-arrival times or byte volume—triggered the alert."*
