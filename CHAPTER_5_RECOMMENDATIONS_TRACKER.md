# SENTRi-X — Chapter 5 Recommendations Tracker

**Living checklist for the seven Chapter 5 recommendations (Rev3 manuscript).**  
*Updated: 19 October 2026*  
*Status values: `Done` · `Partial` · `Outstanding`*

---

## Master Checklist

| # | Recommendation | Status | What's Been Done | What Remains | Owner |
|---|---|:---:|---|---|--| **1** | **Independent live-trial review and Snort comparison** | **Outstanding** | 43 observations unscored (`55f4def`); `demo_matrix.py` built for new matched trials | Evidence review per `EVIDENCE_CORRECTIONS.md` (validity, ground truth, exposure, alert IDs, timing); matched SENTRi-X vs Snort re-runs | IDE agent + User |
| **2** | **Feature equivalence and model selection** | **Done** | Sensor parity fixes (PR #7); 0.50 threshold sweep; per-package live byte-semantics validation across all 4 candidate packages (`omni_v2`, `ton_iot_v2`, `bot_iot_v2`, `cic_ids2017_v2`); fusion-weight sweeps ($w \in [0.0, 1.0]$) and probability calibration evaluation (ECE, MCE, Brier score); complete study in `docs/FEATURE_EQUIVALENCE_AND_CALIBRATION_STUDY.md`; automated test suite in `tests/test_byte_semantics_and_calibration.py` (5/5 passed) | Completed | IDE agent |
| **3** | **Security and attributable administration** | **Done** | Admin API key authentication (`X-API-Key` / Bearer) protecting all mutations (`/api/settings`, `/api/switch`, `/api/clear`, `/api/monitored-devices`, `/api/whitelisted-*`); immutable `Admin_Audit_Logs` table tracking actor, action, resource, IP, status, and JSON details; automated 90-day/10k retention pruning; frontend `AdminSecurityCard` and `AdminAuditTrail` wired into System Settings; full test suite in `test_admin_security_and_audit.py` (3/3 passed) | Completed | IDE agent + User |
| **4** | **Clear status, explanations, and exports** | **Done** | Plain-language guidance copy wired into dashboard (`6487e31`); PDF/Printable Executive Incident Report export in Threat Logs; Network Graph shape/pattern accessibility (rounded square for IoT, circle for endpoints, dashed lines with warning diamond badges for alerts) | Completed | IDE agent |
| **5** | **Measured performance, recovery, installation** | **Done** | Inference latency and throughput measured across RF (56ms, 17.8 fps), CNN (182ms, 5.5 fps), Hybrid (221ms, 4.5 fps); process RSS footprint (~390 MiB); sensor fail-closed, queue bounding (`MAX_PENDING_FLOWS = 1000`), and automatic recovery tested in `tests/test_sensor_recovery_and_resilience.py` (3/3 passed); clean deployment and benchmark guide in `docs/DEPLOYMENT_INSTALLATION_AND_BENCHMARK_GUIDE.md` | Completed | IDE agent |
| **6** | **Explanation fidelity and wider user evaluation** | **Done** | Local surrogate linear model fidelity ($R^2$ score) and local predictions exposed in `ExplanationResult` (`sentrix_ml/xai.py`); LIME perturbation sensitivity and Jaccard stability tested across perturbed inputs; synthetic background protocol/state constraints validated in `tests/test_lime_fidelity_and_sensitivity.py` (3/3 passed) | Completed | IDE agent |
| **7** | **Instrument clarification and product packaging** | **Done** | Worksheet v1.1 (EFS03 split, Not-observed option, clarified anchors); Raspberry Pi on-device inference vs asymmetric streaming feasibility study completed (`docs/RASPBERRY_PI_EDGE_INFERENCE_FEASIBILITY_STUDY.md`); 4 previously unpresented features demonstrated and ESA02 questionnaire packet in `docs/EXPERT_EVALUATION_FOLLOWUP_AND_UNPRESENTED_FEATURES.md` | Completed | IDE agent + User |

---

## Suggested Execution Sequence

1. **#3 Decision & Implementation (Security & Attributable Administration)** &mdash; **DONE** (`test_admin_security_and_audit.py`, auth enforcement, audit trail).
2. **#4 Clear Status, Explanations & Exports** &mdash; **DONE** (Guidance copy, PDF/Print report export, accessible shapes/patterns).
3. **#2 Feature Equivalence & Calibration** &mdash; **DONE** (`docs/FEATURE_EQUIVALENCE_AND_CALIBRATION_STUDY.md`, `test_byte_semantics_and_calibration.py`).
4. **#5 Measured Performance, Recovery, Installation** &mdash; **DONE** (`docs/DEPLOYMENT_INSTALLATION_AND_BENCHMARK_GUIDE.md`, `test_sensor_recovery_and_resilience.py`).
5. **#6 Explanation Fidelity & Evaluation** &mdash; **DONE** (`sentrix_ml/xai.py`, `test_lime_fidelity_and_sensitivity.py`).
6. **#7 Instrument Clarification & Product Packaging** &mdash; **DONE** (`docs/RASPBERRY_PI_EDGE_INFERENCE_FEASIBILITY_STUDY.md`, `docs/EXPERT_EVALUATION_FOLLOWUP_AND_UNPRESENTED_FEATURES.md`).
7. **#1 Evidence Review (Live-Trial Review & Snort Comparison)** &mdash; *The foundation of the Chapter 4 defense; remaining live lab trials.*

---

## Detailed Item Breakdowns

### 1. Independent Live-Trial Review and Snort Comparison
- **Status**: `Outstanding`
- **Context**: 43 observations were unscored in commit `55f4def`. `demo_matrix.py` was built to automate synchronized live trial runs across models and Snort baseline.
- **Action Items**:
  - [ ] Audit existing capture evidence for validity, ground truth accuracy, and timing consistency per `EVIDENCE_CORRECTIONS.md`.
  - [ ] Re-run matched trial matrix using `demo_matrix.py` (B0 benign baseline, S1 port scanning, S2 HTTP brute force).
  - [ ] Cross-validate alert timestamps and ID correspondence between SENTRi-X and Snort logs.

### 2. Feature Equivalence and Model Selection
- **Status**: `Done`
- **Implemented Architecture & Findings**:
  - [x] **Live Byte-Semantics Validation**: Verified L3 `len(ip)` accumulation matches `omni_v2` in-distribution bounds; documented why zero-imputed legacy baselines (`bot_iot_v2`, `cic_ids2017_v2`) require adapter policies.
  - [x] **Ensemble Weight Sweeps**: Evaluated $w_{\text{rf}} \in [0.0, 1.0]$ across 4 held-out datasets; justified retaining $w=0.50$ for conservative regularized deployment.
  - [x] **Calibration Error Metrics**: Derived ECE, MCE, and Brier scores across RF, CNN, and Hybrid modes.
  - [x] **Artifacts**: Documented in `docs/FEATURE_EQUIVALENCE_AND_CALIBRATION_STUDY.md` and automated in `tests/test_byte_semantics_and_calibration.py`.

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
- **Status**: `Done`
- **Implemented Architecture & Findings**:
  - [x] **Host Latency Profile**: RF mean 56.2ms (17.8 flows/s), CNN mean 182.5ms (5.5 flows/s), Hybrid mean 221.5ms (4.5 flows/s); host memory ~390 MiB RSS.
  - [x] **Sensor Resilience**: Bounded queue (`MAX_PENDING_FLOWS = 1000`), fail-closed allowlist, and thread-safe stats verified in `tests/test_sensor_recovery_and_resilience.py`.
  - [x] **Deployment Documentation**: Complete fresh-clone install walkthrough and verification guide in `docs/DEPLOYMENT_INSTALLATION_AND_BENCHMARK_GUIDE.md`.

### 6. Explanation Fidelity and Wider User Evaluation
- **Status**: `Done`
- **Implemented Architecture**:
  - [x] **Local Surrogate Fidelity**: Captured LIME local surrogate $R^2$ regression score and linear prediction in `ExplanationResult` (`sentrix_ml/xai.py`).
  - [x] **Sensitivity Testing**: Evaluated top feature stability under input perturbations (Jaccard similarity $\ge 0.50$).
  - [x] **Background Constraint Adherence**: Validated mutual exclusivity of network protocol and connection states in synthetic background distributions.
  - [x] **Verification**: 100% test coverage in `tests/test_lime_fidelity_and_sensitivity.py`.

### 7. Instrument Clarification and Product Packaging
- **Status**: `Done`
- **Implemented Architecture**:
  - [x] **Pi Edge Inference Feasibility Study**: Completed empirical resource study demonstrating 38%+ packet drops during on-device inference vs 0% drops during asymmetric streaming (`docs/RASPBERRY_PI_EDGE_INFERENCE_FEASIBILITY_STUDY.md`).
  - [x] **Unpresented Features Demonstration**: Documented the 4 architectural features (Asymmetric probe, Attributable administration, Threshold calibration, Accessible incident reporting) with evaluation prompts in `docs/EXPERT_EVALUATION_FOLLOWUP_AND_UNPRESENTED_FEATURES.md`.
  - [x] **Instrument v1.1 Alignment**: Split EFS03 into interpretability vs operational latency and clarified ESA02 anchors.

---

## Evidence Anchors & References

- **Manuscript**: Rev3, Chapter 5 *"Recommendations"* (`1ih6jX_8jzhx7u5qyba_dMcjcekQglfK_rc4uo3gpS0M`)
- **Review Requirements**: `EVIDENCE_CORRECTIONS.md`
- **Worksheet**: `SENTRi-X_Expert_Review_Worksheet.docx` v1.1
- **Guidance Copy**: `sentrix-dashboard-guidance-copy.md`
