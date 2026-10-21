# Physical Testbed Network Dynamics & Live Evaluation Findings

**Project**: SENTRi-X (Hybrid NIDS for IoT Networks)  
**Date**: 21 October 2026  
**Status**: Live Hardware Trial Observations — candidate alerts, unscored pending independent review  
> **Wording note (revised 21 October 2026):** An earlier draft described trial outputs as "detected alerts" with a "detection latency." That overstated the evidence state. Per the project's evidence discipline (EVIDENCE_CORRECTIONS.md), trial outputs are candidate alerts and the outcome remains unscored until independent review.

---

## Executive Summary

During live hardware evaluation trials using the automated test harness (`demo_matrix.py` and `run_trial.py`), critical networking, sensor-filtering, and detection dynamics were identified and validated. Most notably, **Trial `TEST-LIVE-S1` (Bounded TCP Connect Port Scan against the Raspberry Pi target node) produced 50 candidate alerts in the scoring window, with dashboard confidence up to 0.99**, exercising the end-to-end SENTRi-X live pipeline. These are candidate alerts; the trial outcome remains unscored pending independent review.

This document details the network architecture constraints, kernel BPF filter requirements, and defense-ready justification scripts.

---

## 1. Network Topology: Why Attacking Wi-Fi IoT Devices Directly Fails on Switched LANs

When attempting to direct attack workloads from the laptop (`192.168.254.156`) toward the physical Wi-Fi Smart Plug (`192.168.254.100`), the Raspberry Pi edge sensor (`192.168.254.184`) observed zero attack flows.

### The Underlying Causes:
1. **Layer-2 Switch Unicast Isolation**:
   - In standard Ethernet switches and Wi-Fi Access Points, unicast traffic addressed to a specific destination MAC (`68:57:2d:db:39:7d`) is forwarded **strictly to that destination port/radio**.
   - A passive sensor on a third port (`eth0`) never receives unicast traffic between two other endpoints unless an enterprise managed switch with **Port Mirroring (SPAN)** is installed.
2. **WPA2/WPA3 Pairwise Encryption**:
   - Each wireless device negotiates a unique Pairwise Transient Key (PTK) with the access point.
   - Even in RF proximity, the Pi cannot decrypt unicast Wi-Fi frames passing between the laptop and the smart plug.
3. **Consumer Router AP/VLAN Isolation**:
   - Many consumer gateway routers isolate wired Ethernet interfaces from wireless interfaces, causing ARP resolution to time out (`errno: 10035, outcome: timeout`) when cross-communicating.
4. **Why the Pi Saw the Smart Plug Previously**:
   - Database records confirmed the sensor only captured **UDP Broadcasts** (`255.255.255.255:6667`) and DNS queries from the plug. Switches flood broadcast packets to all ports, but unicast attack packets remain strictly private.

### The Architectural Solution: Monitored Node Architecture
In consumer/lab environments without enterprise SPAN hardware, the **Raspberry Pi operates as both the Edge Sensor and the Monitored IoT Target Node**:
* The attacker transmits workloads directly to `192.168.254.184:8088`.
* All attack packets (SYN scans, credential probing) physically enter the sensor's `eth0` interface with 1 ms latency.
* The sensor extracts all 28 flow features and passes them to the AI engine for real-time inference.

---

## 2. Sensor Kernel BPF Filter Requirement

In `edge/sentrix_sensor.py`, Scapy compiles a low-level **Berkeley Packet Filter (BPF)** at startup to drop irrelevant packets inside the Linux kernel driver:

```python
bpf_filter = " or ".join(f"ether host {mac}" for mac, _ in startup_macs)
```

> [!IMPORTANT]
> **Sensor Restart Required After Enrolling New Devices**:  
> While the Python-side allowlist refreshes via periodic backend heartbeats, **the kernel BPF filter is compiled only at sensor launch**. When a new device (such as `target_pi_node` `b8:27:eb:98:08:95`) is added to `Monitored_Devices`, the sensor process on the Pi must be restarted (`Ctrl+C` then `sudo python3 ~/sentrix_sensor.py`) so the kernel driver captures traffic destined for that MAC.

---

## 3. Live Hardware Trial Observation: Trial `TEST-LIVE-S1`

* **Case**: S1 (Bounded TCP connect port scan, 50 ports)
* **Target**: `192.168.254.184:8088` (Raspberry Pi target node)
* **Model**: OMNI / Hybrid Ensemble (RF + CNN)
* **Threshold**: 0.50 (Alert threshold)
* **Evidence Directory**: `attack_scripts/TestKit/evidence/TEST-LIVE-S1/`

### Recorded Metrics:
* **Planned Actions**: 50 port connection attempts
* **Scoring Window**: 120 seconds
* **Candidate Alerts in Scoring Window**: **50 alerts**
* **Threat Classification**: `Critical` (Confidence: `0.99`) and `High packet rate (heuristic)`
* **First Candidate Alert**: Observed at `1.52s` into the scoring window (candidate timing only — not a reviewed detection latency; detector latency cannot be derived from unreviewed candidate delay)

> [!NOTE]
> **Understanding the TestKit Disclaimer**:  
> The terminal output `"Detection outcome remains blank until independent evidence and alert scope are reviewed"` is **not** an error or a failure to detect. The TestKit deliberately leaves the final outcome cell blank to require manual review of `summary.json`, preventing confirmation bias. Inspecting `summary.json` confirms **`"new_alerts_observed": 50`**.

---

## 4. Defense Presentation Verbal Scripts (Q&A)

### Q1: *"Why does your evaluation attack the Raspberry Pi node instead of attacking the smart plug directly over Wi-Fi?"*
> **Candidate Response:**  
> *"In consumer network topologies without enterprise managed switches supporting SPAN port mirroring, Layer-2 switching and WPA2 pairwise encryption prevent a passive third-party sensor from capturing unicast traffic passing between two other hosts. In our physical testbed, the Raspberry Pi acts as both the edge sensor and the monitored IoT target node. Because the workloads are addressed to the Pi itself, the attack packets physically traverse the sensor's interface for flow extraction and model inference — no synthetic simulation or ARP poisoning is involved."*

### Q2: *"Why does the TestKit report say 'Detection outcome remains blank'?"*
> **Candidate Response:**  
> *"The SENTRi-X lab evaluation harness strictly enforces scientific separation between automated data acquisition and ground-truth validation. The kit logs candidate alerts in real time—50 candidate alerts were logged in Trial S1, with dashboard confidence up to 0.99—while keeping the final verdict cell blank until packet timestamps and service logs are independently verified."*
