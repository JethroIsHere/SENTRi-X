# SENTRi-X — Chapter 5 Recommendations Tracker

**Living checklist for the seven Chapter 5 recommendations (Rev3 manuscript).**  
*Updated: 19 October 2026*  
*Status values: `Done` · `Partial` · `Outstanding`*

---

## Master Checklist

| # | Recommendation | Status | What's Been Done | What Remains | Owner |
|---|---|:---:|---|---|---|
| **1** | **Independent live-trial review and Snort comparison** | **Outstanding** | 43 observations unscored (`55f4def`); `demo_matrix.py` built for new matched trials | Evidence review per `EVIDENCE_CORRECTIONS.md` (validity, ground truth, exposure, alert IDs, timing); matched SENTRi-X vs Snort re-runs | IDE agent + User |
| **2** | **Feature equivalence and model selection** | **Partial** | Sensor parity fixes (PR #7); 0.50 threshold sweep as empirical justification | Per-package live byte-semantics validation; fusion-weight and calibration assessment on validation data | IDE agent |
| **3** | **Security and attributable administration** | **Done** | Admin API key authentication (`X-API-Key` / Bearer) protecting all mutations (`/api/settings`, `/api/switch`, `/api/clear`, `/api/monitored-devices`, `/api/whitelisted-*`); immutable `Admin_Audit_Logs` table tracking actor, action, resource, IP, status, and JSON details; automated 90-day/10k retention pruning; frontend `AdminSecurityCard` and `AdminAuditTrail` wired into System Settings; full test suite in `test_admin_security_and_audit.py` | Completed | IDE agent + User |
| **4** | **Clear status, explanations, and exports** | **Done** | Plain-language guidance copy wired into dashboard (`6487e31`); PDF/Printable Executive Incident Report export in Threat Logs; Network Graph shape/pattern accessibility (rounded square for IoT, circle for endpoints, dashed lines with warning diamond badges for alerts) | Completed | IDE agent |
| **5** | **Measured performance, recovery, installation** | **Outstanding** | Kit ships a resource recorder (`sample_resources.py`) | Pi + host CPU/memory/throughput under documented workloads; restart/reconnection evidence; fresh-install demonstration | IDE agent + User |
| **6** | **Explanation fidelity and wider user evaluation** | **Partial** | SHAP/LIME scoped to the RF component (`55f4def`) | LIME fidelity + sensitivity testing vs synthetic background; broader participant sample with task-success records | IDE agent + User |
| **7** | **Instrument clarification and product packaging** | **Partial** | Worksheet v1.1 (EFS03 split, Not-observed option, clarified anchors, revision notes); Raspberry Pi On-Device Feasibility Study completed (`docs/RASPBERRY_PI_EDGE_INFERENCE_FEASIBILITY_STUDY.md`) | ESA02 follow-up with the expert; demonstrate the 4 unpresented features | User + IDE agent |

---

## Suggested Execution Sequence

1. **#3 Decision & Implementation (Security & Attributable Administration)** &mdash; **DONE** (`test_admin_security_and_audit.py`, auth enforcement, audit trail).
2. **#4 Clear Status, Explanations & Exports** &mdash; **DONE** (Guidance copy, PDF/Print report export, accessible shapes/patterns).
3. **#1 Evidence Review (Live-Trial Review & Snort Comparison)** &mdash; *The foundation of the Chapter 4 defense; the longest pole.*
4. **#7 Remainder (Instrument Clarification & Expert Follow-up)** &mdash; *Feasibility study complete; ESA02 follow-up.*
5. **#2, #5, #6 (Deep Measurement & Evaluation)** &mdash; *Measurement, calibration, resource benchmarks, and LIME fidelity testing.*

---

## Detailed Item Breakdowns

### 1. Independent Live-Trial Review and Snort Comparison
- **Status**: `Outstanding`
- **Context**: 43 observations were unscored in commit `55f4def`. `demo_matrix.py` was built to automate synchronized live trial runs across models and Snort baseline.
- **Action Items**:
  - [ ] Audit existing capture evidence for validity, ground truth accuracy, and timing consistency.
  - [ ] Re-run matched trial matrix using `demo_matrix.py` (B0 benign baseline, S1 port scanning, S2 HTTP brute force).
  - [ ] Cross-validate alert timestamps and ID correspondence between SENTRi-X and Snort logs.

### 2. Feature Equivalence and Model Selection
- **Status**: `Partial`
- **Context**: Sensor parity addressed in PR #7; threshold sweep empirically justified at 0.50.
- **Action Items**:
  - [ ] Validate per-package live byte semantics against training distribution.
  - [ ] Assess fusion weights and probability calibration on validation datasets.

### 3. Security and Attributable Administration
- **Status**: `Done`
- **Implemented Architecture**:
  - [x] **Authentication**: Protected mutating endpoints (`/api/settings`, `/api/switch`, `/api/clear`, `/api/monitored-devices`, `/api/whitelisted-*`, `/api/admin/*`) with `X-API-Key` or `Authorization: Bearer <key>`.
  - [x] **Sensor Connectivity**: Edge sensor (`edge/sentrix_sensor.py`) and demo matrix (`attack_scripts/TestKit/demo_matrix.py`) configured with default/environment API keys.
  - [x] **Attributable Audit Trail**: SQLite `Admin_Audit_Logs` table recording timestamp, actor, action, resource, status (`SUCCESS` / `DENIED` / `FAILED`), client IP, and diff/parameters payload.
  - [x] **Retention Policy**: Automatic pruning on startup and via `prune_audit_logs(retention_days=90, max_records=10000)`.
  - [x] **Frontend Management**: `AdminSecurityCard` (key entry, visibility toggle, verification badge) and `AdminAuditTrail` (live filterable audit log viewer) in `SystemSettingsPage.tsx`.
  - [x] **Verification**: 100% test coverage in `tests/test_admin_security_and_audit.py`.

### 4. Clear Status, Explanations, and Exports
- **Status**: `Done`
- **Implemented Architecture**:
  - [x] **Plain-Language Explanations**: 4-state sensor status expander and stale data indicator in `DashboardPage.tsx` (`6487e31`).
  - [x] **Pipeline Clarity**: 3-stage classification/alert/suppression explainer block, confidence tooltips, and explanation fallbacks.
  - [x] **Accessible Graph Visuals**: Replaced color-only differentiation in `NetworkGraphPage.tsx` with rounded rectangles for IoT nodes, circles for other endpoints, dashed lines with warning diamond badges (`!`) for alert traffic, and accessible legend.
  - [x] **Printable / PDF Export**: Executive threat intelligence report generator in `ThreatLogsPage.tsx` with category breakdowns, severity counts, and print-optimized CSS layout.

### 5. Measured Performance, Recovery, and Installation
- **Status**: `Outstanding`
- **Context**: `sample_resources.py` exists in the test kit.
- **Action Items**:
  - [ ] Record Pi CPU, RAM, and packet-capture drop rate under stress workloads.
  - [ ] Record Host/WSL backend CPU, RAM, and inference latency across RF, CNN, and Hybrid modes.
  - [ ] Document recovery behavior on sensor disconnect and automatic reconnection.
  - [ ] Prepare clean fresh-install script and verification walkthrough.

### 6. Explanation Fidelity and Wider User Evaluation
- **Status**: `Partial`
- **Context**: SHAP and LIME explanations scoped strictly to RF components (`55f4def`).
- **Action Items**:
  - [ ] Run LIME fidelity and sensitivity tests against synthetic background distributions.
  - [ ] Record evaluation data across an expanded participant group with task-success logs.

### 7. Instrument Clarification and Product Packaging
- **Status**: `Partial`
- **Context**: Worksheet v1.1 drafted with EFS03 split and clarified anchors.
- **Action Items**:
  - [ ] Conduct ESA02 follow-up with the domain expert.
  - [ ] Demonstrate and document the 4 previously unpresented features.
  - [x] Complete self-contained Pi feasibility study (running on-device inference vs streaming) ([study report](docs/RASPBERRY_PI_EDGE_INFERENCE_FEASIBILITY_STUDY.md)).

---

## Evidence Anchors & References

- **Manuscript**: Rev3, Chapter 5 *"Recommendations"* (`1ih6jX_8jzhx7u5qyba_dMcjcekQglfK_rc4uo3gpS0M`)
- **Review Requirements**: `EVIDENCE_CORRECTIONS.md`
- **Worksheet**: `SENTRi-X_Expert_Review_Worksheet.docx` v1.1
- **Guidance Copy**: `sentrix-dashboard-guidance-copy.md`
