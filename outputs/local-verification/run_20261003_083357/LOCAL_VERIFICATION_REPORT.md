# SENTRi-X Local Verification and Dataset Preflight Report

**Run Directory**: `C:\Users\LENOVO\SENTRi-X\outputs\local-verification\run_20261003_083357`  
**Execution Timestamp**: 3 October 2026 (08:33 – 09:25 Local Time)  
**Overall Software Status**: **PASS** (86/86 tests passed, exit code 0)  
**Overall Dataset Preflight Status**: **FAILED / BLOCKED** (Exit code 1; ToN-IoT READY, BoT-IoT, CIC-IDS2017, and Omni blocked by source data distribution/annotation issues)  

---

## 1. Git Repository and Merged Code Verification

| Check | Specification / Requirement | Actual Local Result | Status |
| :--- | :--- | :--- | :--- |
| **Active Branch** | `main` | `main` (synchronized with `origin/main`) | **PASS** |
| **HEAD Commit** | `4af2f4a26a51a9b54111616810630f55f06e1b67` | `4af2f4a26a51a9b54111616810630f55f06e1b67` | **PASS** |
| **Merged Fix Present** | Fix commit `4af2f4a` is ancestor of HEAD | `git merge-base --is-ancestor 4af2f4a HEAD` -> Exit code 0 | **PASS** |
| **Working Tree** | Clean, preserve local changes | Clean (`## main...origin/main`), no uncommitted modifications | **PASS** |

---

## 2. Environment and Dependencies

* **Operating System**: Windows 11 (AMD64)
* **Python Executable**: `C:\Users\LENOVO\SENTRi-X\venv\Scripts\python.exe`
* **Python Version**: `3.11.0 (main, Oct 24 2022, 18:26:48) [MSC v.1933 64 bit (AMD64)]`
* **Environment Modifications**: Installed dependencies from `requirements-test.txt` into the existing virtual environment:
  * `pytest`: `9.1.1` (installed with `iniconfig 2.3.0`, `pluggy 1.6.0`)
  * `httpx`: `0.28.1` (already satisfied)
* **Core Dependency Versions**:
  * `tensorflow`: `2.21.0` (CPU operational)
  * `scikit-learn`: `1.8.0`
  * `pandas`: `3.0.1`
  * `numpy`: `2.4.3`
  * `joblib`: `1.5.3`
  * `psutil`: `7.2.2`
  * `fastapi`: `0.142.2`
* **Hardware Resources Reported at Preflight**:
  * **RAM Total**: 13.83 GB
  * **RAM Available**: 2.26 GB
  * **Disk Free**: 27.07 GB

---

## 3. Test Suite Execution (`tests/run_all_tests.py`)

* **Command**: `.\venv\Scripts\python.exe tests/run_all_tests.py`
* **Execution Duration**: ~85.42 seconds
* **Exit Code**: `0`
* **Test Counts**:
  * **Passed**: **86**
  * **Failed**: **0**
  * **Skipped**: **0**
* **Verification Highlights**:
  * Real TensorFlow 1D-CNN and Random Forest training integration passed.
  * Real backend loader parity passed across all 12 combinations (RF, CNN, and Hybrid across Source ToN, BoT Adaptation, CIC Adaptation, and Omni candidate packages).
  * All 6 rewritten notebook end-to-end execution checks passed (`01`, `03`, `04`, `06`, `07`, `10`).
  * Upstream deprecation warnings from Keras/NumPy/FastAPI occurred as expected, but zero assertions failed.

---

## 4. Dataset Preflight Results (`sentrix_ml/preflight.py`)

* **Command**:
  ```bash
  python -m sentrix_ml.preflight --require-tf --target all --sample-n 50000 --sample-per-domain 30000 --test-fraction 0.20 --study-fraction 0.20 --val-fraction 0.10 --seed 42 --report-json "outputs/local-verification/run_20261003_083357/preflight-local.json"
  ```
* **Dataset Root**: `C:\Users\LENOVO\SENTRi-X\data\raw`
* **Exit Code**: `1` (Preflight blocked due to domain-specific dataset errors)
* **Overall Status**: `FAILED — BLOCKING ISSUES DETECTED`

### Domain-by-Domain Preflight Breakdown

#### 1. ToN-IoT (`data/raw/ton_iot`) — **READY**
* **Files Considered**: 23 files (`Network_dataset_1.csv` ... `Network_dataset_23.csv`)
* **Total Rows Traversed**: 22,339,021 (valid: 22,338,152; invalid numerics excluded: 869)
* **Source Population Prevalence**: Benign (`0`): 795,511 (3.56%) | Attack (`1`): 21,542,641 (96.44%)
* **Sampled Reservoir (n=50,000)**: Benign (`0`): 1,770 (3.54%) | Attack (`1`): 48,230 (96.46%) — *Natural prevalence preserved*
* **Grouping & Duplicates**: 50,000 tuple + session start scopes; 98 duplicate rows excluded; 49,134 unique groups.
* **Partition Support**:
  * **Train** (35,928 rows): `{"0": 1233, "1": 34695}`
  * **Validation** (4,012 rows): `{"0": 136, "1": 3876}`
  * **Test Holdout** (9,962 rows): `{"0": 341, "1": 9621}`
* **Result**: **READY** (Configured data/partition gate passed).

#### 2. BoT-IoT (`data/raw/bot_iot`) — **FAILED**
* **Files Considered**: 4 files (`UNSW_2018_IoT_Botnet_Full5pc_1.csv` ... `_4.csv`)
* **Total Rows Traversed**: 3,668,522 (valid: 3,668,522; exclusions: 0)
* **Source Population Prevalence**: Benign (`0`): 477 (0.013%) | Attack (`1`): 3,668,045 (99.987%)
* **Sampled Reservoir (n=50,000)**: Benign (`0`): 4 | Attack (`1`): 49,996
* **Blocking Defect**:
  ```text
  Insufficient independent groups for a stratified 10% partition: {'1': 9999, '0': 1}. Increase the declared sample or revise the grouping protocol.
  ```
* **Explanation**: In the UNSW BoT-IoT 5% dataset, benign traffic is extremely sparse (only 477 benign rows in the entire 3.67M records). Uniform Algorithm R reservoir sampling without artificial filtering draws only ~4 benign rows per 50k. During adaptation split (20% study = 10,000 rows; 10% val = 1,000 rows), there are only 1–4 benign independent groups available, which fails the strict partition class-support requirement (minimum 2 benign in train, 1 in val, 1 in test).

#### 3. CIC-IDS2017 (`data/raw/cic_ids2017`) — **FAILED**
* **Files Considered**: 8 raw files (`Friday-...`, `Monday-...`, `Tuesday-...`, `Wednesday-...`, `Thursday-...`)
* **Total Rows Traversed**: 2,830,743 (valid: 2,830,628; invalid numerics excluded: 115)
* **Source Population Prevalence**: Benign (`0`): 2,272,982 (80.3%) | Attack (`1`): 557,646 (19.7%)
* **Sampled Reservoir (n=50,000)**: Benign (`0`): 40,156 (80.3%) | Attack (`1`): 9,844 (19.7%)
* **Grouping Scope**: `raw_record_only`: 50,000 (no timestamp/session start tuple available in CIC CSVs; falls back to raw record fingerprint)
* **Blocking Defect**:
  ```text
  Identical raw records have conflicting labels; resolve source annotations before training
  ```
* **Explanation**: In the raw ISCX CSVs, identical flow feature vectors appear labeled with conflicting classifications (e.g. identical network measurements labeled `BENIGN` in one row and an attack label like `PortScan` or `DoS` in another). The Prompt 1 pipeline strictly rejects ambiguous, contradictory ground-truth labels rather than silently dropping or misclassifying them.

#### 4. Omni (`data/raw/`) — **FAILED**
* **Configured Sample**: 30,000 rows per domain (Total: 90,000 rows across ToN, BoT, and CIC)
* **Total Sampled**: Benign (`0`): 25,218 | Attack (`1`): 64,782
  * `ton_iot`: Benign: 1,106 | Attack: 28,894
  * `bot_iot`: Benign: 5 | Attack: 29,995
  * `cic_ids2017`: Benign: 24,107 | Attack: 5,893
* **Blocking Defect**:
  ```text
  bot_iot validation partition lacks both classes: {'1': 2400}. Increase the predeclared domain sample; no automatic redraw.
  ```
* **Explanation**: Because BoT-IoT yielded only 5 benign rows in 30,000 samples, the stratified split across partitions cannot provide both classes for the `bot_iot` slice of the Omni validation set (it received 2,400 attack rows and 0 benign rows). Prompt 1 strictly enforces that every domain must have both classes in every partition without performing unscientific post-hoc redraws.

---

## 5. Artifact and Log Locations

All verification artifacts for this run are located in:
`C:\Users\LENOVO\SENTRi-X\outputs\local-verification\run_20261003_083357`

1. **Test Suite Full Output**:
   `C:\Users\LENOVO\SENTRi-X\outputs\local-verification\run_20261003_083357\test_suite.log`
2. **Test Suite Exit Code** (`0`):
   `C:\Users\LENOVO\SENTRi-X\outputs\local-verification\run_20261003_083357\test_exit_code.txt`
3. **Preflight Full Output**:
   `C:\Users\LENOVO\SENTRi-X\outputs\local-verification\run_20261003_083357\preflight.log`
4. **Preflight Exit Code** (`1`):
   `C:\Users\LENOVO\SENTRi-X\outputs\local-verification\run_20261003_083357\preflight_exit_code.txt`
5. **Preflight Structured JSON Report**:
   `C:\Users\LENOVO\SENTRi-X\outputs\local-verification\run_20261003_083357\preflight-local.json`
6. **This Verification Report**:
   `C:\Users\LENOVO\SENTRi-X\outputs\local-verification\run_20261003_083357\LOCAL_VERIFICATION_REPORT.md`

---

## 6. Training Resource Assessment

* **Current Available Host RAM**: **2.26 GB** (out of 13.83 GB total)
* **Available Disk Storage**: **27.07 GB**
* **Implications**:
  * Even if dataset partitioning issues are resolved, attempting concurrent or large-batch multi-domain model training on this host with only 2.26 GB of unreserved RAM risks out-of-memory (OOM) process termination or heavy paging.
  * Training jobs must be run sequentially, strictly bounded in batch/memory footprint, or executed on a machine with >= 16 GB unreserved RAM.

---

## 7. Next Actions & Handoff to ChatGPT

### Status Conclusion:
* **Code / Software Gates**: **FULLY VERIFIED AND PASSING** (86/86 tests). The merged codebase on `main` is completely sound, TensorFlow integration is active, and offline/backend parity is intact.
* **Data Readiness Gate for Prompt 2**: **BLOCKED BY RAW DATASETS**. Full research retraining cannot proceed until:
  1. **BoT-IoT Benign Scarcity**: A decision is made regarding BoT-IoT sampling (e.g. increase sample cap or adopt a stratified domain sampling protocol that guarantees benign support without distorting natural holdout evaluation).
  2. **CIC-IDS2017 Conflicting Annotations**: Conflicting labels on identical raw records in CIC-IDS2017 must be resolved (e.g. unambiguous tie-breaking rule or dropping contradictory records during ETL).

### Files to Send Back to ChatGPT:
You should send the following two primary files back to ChatGPT for Prompt 2 alignment:
1. `outputs/local-verification/run_20261003_083357/LOCAL_VERIFICATION_REPORT.md`
2. `outputs/local-verification/run_20261003_083357/preflight-local.json`
*(Optional: `outputs/local-verification/run_20261003_083357/preflight.log` if raw stack traces are requested).*
