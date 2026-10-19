# SENTRi-X Expert Review Follow-Up & Unpresented Features Packet

**Document Version:** 1.1  
**Date:** 20 October 2026  
**Focus:** Chapter 5 Recommendation #7 (*Instrument Clarification and Product Packaging*)  
**Target:** Domain Expert Panel (Cybersecurity & IoT Operations)  
**Reference Worksheet:** SENTRi-X Expert Review Worksheet v1.1  

---

## 1. Background & Context of this Follow-Up

In the initial evaluation of SENTRi-X (Chapter 4), expert feedback indicated that certain questions in the evaluation instrument conflated separate system dimensions, and four key architectural capabilities were not explicitly demonstrated during the live walkthrough.

This packet formally addresses **Recommendation #7** by:
1. Clarifying the revised evaluation worksheet anchors (v1.1), including the split of **EFS03** and the formal handling of **ESA02**.
2. Providing a clear, evidence-based demonstration of the **four previously unpresented features**.
3. Providing the targeted follow-up questionnaire for expert re-scoring.

---

## 2. Clarifications in Instrument Worksheet v1.1

### 2.1 Resolution of EFS03 Split
- **Original EFS03**: Conflated visual explanation quality (SHAP/LIME charts) with explanation generation speed.
- **Revised Instrument v1.1**:
  - **EFS03-A (Explanation Interpretability)**: *"The visual feature attribution charts (SHAP waterfall/bar and LIME weights) clearly indicate which specific network parameters contributed to the threat classification."*
  - **EFS03-B (Operational Latency)**: *"The explanation generation time is sufficiently rapid to support triage without disrupting real-time monitoring."*

### 2.2 ESA02 Architectural Clarification
- **Item ESA02**: Evaluates edge deployment feasibility and operational placement.
- **Clarification**: In the initial session, the distinction between running deep learning inference directly on the Raspberry Pi versus running an asymmetric capture probe was underspecified. Our empirical feasibility study ([docs/RASPBERRY_PI_EDGE_INFERENCE_FEASIBILITY_STUDY.md](RASPBERRY_PI_EDGE_INFERENCE_FEASIBILITY_STUDY.md)) demonstrates why an asymmetric probe architecture is the only viable engineering choice for resource-constrained ARM SBCs.

---

## 3. Demonstration of the Four Previously Unpresented Features

### Feature 1: Asymmetric Edge-Probe Architecture with Bounded Memory
- **Problem Addressed**: Microcontroller and SBC devices (e.g. Raspberry Pi 3B+) suffer memory exhaustion (>85% RAM) and high packet drop rates (>38%) when executing 1D-CNN tensor calculations and SHAP/LIME regressions locally.
- **Implemented Architecture**:
  - The edge sensor (`edge/sentrix_sensor.py`) operates strictly as an asynchronous capture and flow extraction probe using Scapy.
  - Extracted flow summaries (28 numerical features) are batched and streamed via HTTP/REST to the central SENTRi-X gateway backend.
  - Bounded FIFO queue (`MAX_PENDING_FLOWS = 1000`) prevents memory growth during network disconnects.
  - Bandwidth consumption is under 0.02 Mbps, leaving the local network unburdened.
- **Evidence Anchor**: Verified in `docs/RASPBERRY_PI_EDGE_INFERENCE_FEASIBILITY_STUDY.md` and `tests/test_sensor_recovery_and_resilience.py`.

### Feature 2: Attributable Security Administration & Tamper-Evident Audit Trail
- **Problem Addressed**: Multi-tenant IoT security gateways require non-repudiation and role-based protection so that sensor configuration changes, device additions, and alert clearances are strictly attributable.
- **Implemented Architecture**:
  - **Authentication**: Pre-shared API Key / Bearer token authentication (`X-API-Key`) protecting mutating REST endpoints (`/api/settings`, `/api/switch`, `/api/clear`, `/api/monitored-devices`, `/api/whitelisted-*`).
  - **Audit Logging**: SQLite `Admin_Audit_Logs` table capturing timestamp, actor, action, target resource, client IP, outcome (`SUCCESS`, `DENIED`, `FAILED`), and JSON diff parameters.
  - **Automated Retention**: Automated 90-day pruning with a 10,000-record cap to guarantee database performance.
  - **Frontend UI**: Dedicated `AdminSecurityCard` and live filterable `AdminAuditTrail` in System Settings.
- **Evidence Anchor**: Verified in `tests/test_admin_security_and_audit.py` (100% test pass).

### Feature 3: Data-Driven Alert Thresholding and Calibration Optimization
- **Problem Addressed**: Uncalibrated models produce alert storms, leading to operator fatigue.
- **Implemented Architecture**:
  - Full threshold sweep conducted across 17,842 held-out flows, establishing $\tau = 0.50$ as the mathematically optimal F1 operating point ($\text{F1} = 0.9798$, $\text{Precision} = 0.9985$, $\text{Recall} = 0.9618$).
  - Dynamic user-adjustable threshold control in System Settings ($0.50 \le \tau \le 0.99$) with real-time classification / suppression indicators.
  - Rigorous probability calibration analysis confirming that Random Forest maintains an Expected Calibration Error under $0.50\%$ and Brier score of $0.0050$.
- **Evidence Anchor**: Verified in `docs/FEATURE_EQUIVALENCE_AND_CALIBRATION_STUDY.md` and `scripts/evaluate_byte_semantics_and_calibration.py`.

### Feature 4: Accessible Incident Visualization & Printable Executive PDF Export
- **Problem Addressed**: Security operations centers (SOCs) require accessible visualizations that do not rely solely on color cues, as well as formal offline report exports for incident response handoff.
- **Implemented Architecture**:
  - **Accessible Graph Visuals**: Nodes differentiated by distinct geometric shapes (rounded rectangle with `[IoT]` text badge for monitored devices, circles for external endpoints). Communication edges use solid lines for benign flows and high-contrast dashed lines with warning diamond badges (`!`) for attack alerts.
  - **Executive Report Generation**: One-click "Print Report / Save as PDF" in Threat Logs generating an executive incident intelligence briefing with severity distributions, category breakdowns, and timestamp ranges.
- **Evidence Anchor**: Implemented in `frontend/src/pages/NetworkGraph/NetworkGraphPage.tsx` and `frontend/src/pages/ThreatLogs/ThreatLogsPage.tsx`.

---

## 4. ESA02 Follow-Up Questionnaire for Domain Experts

Please review the architectural demonstrations and rate each item on a 1–5 scale:
*(1 = Strongly Disagree, 2 = Disagree, 3 = Neutral, 4 = Agree, 5 = Strongly Agree, N/O = Not Observed)*

| Item ID | Evaluation Statement | Rating (1-5 / N/O) | Qualitative Observations / Feedback |
|---|---|:---:|---|
| **ESA02-A** | The asymmetric probe architecture (edge capture + central gateway inference) effectively overcomes Raspberry Pi hardware constraints while preserving network monitoring integrity. | `[   ]` | |
| **ESA02-B** | The API key authentication and attributable audit logging provide sufficient accountability for SOC compliance and administrative oversight. | `[   ]` | |
| **ESA02-C** | The data-driven threshold calibration ($\tau = 0.50$) and explicit alert suppression pipeline effectively mitigate operator alert fatigue. | `[   ]` | |
| **ESA02-D** | The accessible network graph styling (shapes + badges) and printable executive PDF export satisfy SOC operational reporting requirements. | `[   ]` | |
| **EFS03-A** | The SHAP and LIME feature attribution visualizers provide clear, interpretable indicators of malicious flow characteristics. | `[   ]` | |
| **EFS03-B** | The real-time throughput and explanation latency are acceptable for live operational network environments. | `[   ]` | |

---

## 5. Summary of Expert Verification Protocol

To verify these features interactively:
1. **Live Interface**: Access `http://localhost:5173/settings` to review Admin Key Authentication, the Live Audit Trail, and Alert Threshold Controls.
2. **Accessible Graph**: Navigate to `http://localhost:5173/graph` to observe geometric node distinctions and badge overlays.
3. **Printable Export**: Navigate to `http://localhost:5173/logs` and click **"Print / Export PDF"** to preview the formatted incident briefing.
