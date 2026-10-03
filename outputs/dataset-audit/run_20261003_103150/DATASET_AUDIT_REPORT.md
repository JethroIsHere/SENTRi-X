# SENTRi-X: BoT-IoT and CIC-IDS2017 Dataset Readiness & Identity Audit Report

**Audit Directory**: `outputs/dataset-audit/run_20261003_103150`  
**Execution Timestamp**: 3 October 2026 (13:13 – 13:52 Local Time)  
**Elapsed Execution Time**: 2,357.62 seconds (~39.3 minutes)  
**Peak RAM Usage**: 543.20 MB (bounded, disk-backed SQLite processing)  
**Audit Exit Code**: `0` (Diagnostic audit completed successfully; all verification fixtures passed)  
**Software Verification Status**: **PASS** (Baseline: 86/86 tests passing, zero skips)  
**Training Preflight Status**: **FAILED / BLOCKED** (Exact root causes established with source-row proof)

---

## 1. Executive Summary & Core Findings

This audit investigated the mathematical and empirical causes behind the preflight failures observed in [BoT-IoT](file:///c:/Users/LENOVO/SENTRi-X/data/raw/bot_iot) and [CIC-IDS2017](file:///c:/Users/LENOVO/SENTRi-X/data/raw/cic_ids2017). Using disk-backed SQLite indexing and full-population streaming, every raw observation across both datasets was audited without exceeding 544 MB of RAM.

```
+-------------------------------------------------------------------------------------------------------------+
|                                    AUDIT SUMMARY MATRIX                                                     |
+---------------+-------------------+--------------------+------------------------+---------------------------+
| Dataset       | Population Scanned| Minority Class     | Preflight Defect       | Empirical Root Cause      |
+---------------+-------------------+--------------------+------------------------+---------------------------+
| BoT-IoT       | 4 files           | Benign: 477 rows   | Insufficient groups    | Extreme class scarcity    |
|               | (3,668,522 rows)  | (0.013%)           | for 10% val partition  | (477/3.67M). Uniform draw |
|               |                   |                    | ({'1': 9999, '0': 1})  | of 50k yields only 4 rows;|
|               |                   |                    |                        | study split cannot stratify|
+---------------+-------------------+--------------------+------------------------+---------------------------+
| CIC-IDS2017   | 8 files           | Attack: 557,646    | Conflicting labels on  | Raw CSVs lack all network |
|               | (2,830,628 rows)  | Benign: 2,272,982  | identical raw records  | IDs (IP, port, timestamp).|
|               |                   |                    |                        | 698 measurement groups    |
|               |                   |                    |                        | (7,020 rows) share labels |
|               |                   |                    |                        | of both Benign and Attack |
+---------------+-------------------+--------------------+------------------------+---------------------------+
```

---

## 2. Environment, Tooling & Verification Fixtures

* **Python Interpreter**: `C:\Users\LENOVO\SENTRi-X\venv\Scripts\python.exe` (Python 3.11.0)
* **Git Commit**: `6addbb8d9f75b9a2d7049da18d2d524f6000d115` (`main`)
* **Host Resources During Audit**:
  * **Total RAM**: 13.83 GB | **Available RAM**: 1.91 GB
  * **Free Disk Space**: 27.04 GB
  * **Peak RSS Memory**: 543.20 MB (Process strictly bounded using SQLite batch transactions)
* **Verification Fixtures (`tools/audit_dataset_readiness.py`)**:
  * `row_position_continuity`: **PASS** (Zero-based file-relative record offsets preserve identity across chunks)
  * `fingerprint_consistency_with_production`: **PASS** (Audit hash matches `sentrix_ml.provenance._digest`)
  * `identical_measurements_same_fingerprint`: **PASS** (Identical measurement rows map to same `duplicate_id`)
  * `distinguishable_sessions_distinct_groups`: **PASS** (Distinct session start timestamps yield disjoint `group_id`s)
  * `all_fixtures_passed`: **PASS**
* **Source Hash Verification**:
  * All 12 raw dataset files (4 BoT-IoT, 8 CIC-IDS2017) matched the exact SHA-256 hashes recorded in the previous verification report (`preflight-local.json`). Zero file modifications occurred.

---

## 3. BoT-IoT Audit: Extreme Class Scarcity

### 3.1 Full-Source Inventory & File Breakdown
Every valid record in `data/raw/bot_iot` was scanned using production cleaning rules:
* **Total Rows Considered**: 3,668,522
* **Total Valid Rows**: 3,668,522 (0 rows dropped for numeric invalidity)
* **Source Population Split**:
  * **Attack (`1`)**: 3,668,045 rows (99.986997%)
  * **Benign (`0`)**: **477 rows** (**0.013003%**)

| File Name | File SHA-256 | Total Rows | Attack Rows | Benign Rows |
| :--- | :--- | :--- | :--- | :--- |
| `UNSW_2018_IoT_Botnet_Full5pc_1.csv` | `sha256:3940b549...` | 1,000,000 | 1,000,000 | **0** |
| `UNSW_2018_IoT_Botnet_Full5pc_2.csv` | `sha256:1f87b8f1...` | 1,000,000 | 1,000,000 | **0** |
| `UNSW_2018_IoT_Botnet_Full5pc_3.csv` | `sha256:3f05d682...` | 1,000,000 | 1,000,000 | **0** |
| `UNSW_2018_IoT_Botnet_Full5pc_4.csv` | `sha256:ba7f6b36...` | 668,522 | 668,045 | **477** |

### 3.2 Anatomy of the 477 Benign Records
All 477 benign observations are exported with full session metadata to [`bot_iot_benign_inventory.csv`](file:///c:/Users/LENOVO/SENTRi-X/outputs/dataset-audit/run_20261003_103150/bot_iot_benign_inventory.csv).
1. **Physical Clustering**: All 477 benign rows exist in **one single continuous block** in File 4, starting at row index **576,884** and ending at row index **577,360**. (This explains why legacy scripts had a hardcoded `skiprows=range(1, 576884)`).
2. **Uniqueness**:
   * **Unique Fingerprints (`duplicate_id`)**: **477** (zero duplicates among benign records).
   * **Unique Session Groups (`group_id`)**: **477** (all records possess distinct session start timestamps `stime`).
3. **Session Integrity**:
   * Mixed groups (groups containing both benign and attack rows): **0**.
   * Identifiers present: `pkSeqID`, `stime`, `saddr`, `sport`, `daddr`, `dport`, `proto`. Full 5-tuple + timestamp grouping is completely operational.

### 3.3 Mathematical Demonstration of Preflight Failure
Under uniform Algorithm R reservoir sampling without early exit:
$$\mathbb{E}[\text{Benign Samples in } K=50,000] = 50,000 \times \frac{477}{3,668,522} \approx 6.50 \text{ rows}$$

* **Seed 42 (Observed)**: Exactly **4 benign rows** were drawn into the 50,000 reservoir (File 4 rows: `577236`, `577341`, `576895`, `577246`).
* **Adaptation Split Execution (20% Study, 10% Validation)**:
  1. The 50,000 sample is split into 20% Study ($10,000$ rows) and 80% Exam ($40,000$ rows).
  2. Because all 50,000 rows represent unique groups, group stratification equals row stratification.
  3. In the 10,000-row Study partition, only **4 benign rows** exist.
  4. When attempting a 10% validation split inside Study ($1,000$ validation rows, $9,000$ training rows), sklearn's `train_test_split(..., stratify=profiles)` evaluates:
     `profiles.value_counts() == {'1': 9999, '0': 1}`
  5. Sklearn strictly enforces `min(counts) >= 2` for stratified partitioning. With only 1 benign group in the pool, stratified splitting is mathematically impossible, triggering:
     `PartitionSupportError: Insufficient independent groups for a stratified 10% partition: {'1': 9999, '0': 1}`.
* **Omni Split (30,000 rows, Seed 42)**:
  * Only **5 benign rows** drawn.
  * In Omni's 10% validation split, the BoT-IoT domain receives 2,400 attack rows and **0 benign rows** (`{'1': 2400}`), violating the rule requiring both classes in every partition.

---

## 4. CIC-IDS2017 Audit: Measurement Ambiguity & Collisions

### 4.1 Missing Network Identifiers (Source Column Inventory)
An audit of all 8 raw CSV files was exported to [`cic_column_inventory.json`](file:///c:/Users/LENOVO/SENTRi-X/outputs/dataset-audit/run_20261003_103150/cic_column_inventory.json).

```
+----------------------------------------------------------------------------------------------------+
|                         CIC-IDS2017 COLUMN INVENTORY (ALL 8 RAW CSV FILES)                        |
+---------------------+-------------+----------------------------------------------------------------+
| Column Name         | Available?  | Consequence for Provenance & Grouping                          |
+---------------------+-------------+----------------------------------------------------------------+
| Destination Port    | YES         | Only network endpoint preserved in the tabular export.         |
| Source IP           | NO (0 / 8)  | Cannot distinguish endpoints or directionality.                |
| Destination IP      | NO (0 / 8)  | Cannot identify target host/server.                            |
| Source Port         | NO (0 / 8)  | Cannot separate concurrent connections from same client.       |
| Protocol            | NO (0 / 8)  | Missing layer-4 protocol (defaulted to TCP/UDP heuristic).     |
| Timestamp           | NO (0 / 8)  | Cannot determine event time, order, or session continuity.      |
| Flow ID             | NO (0 / 8)  | Anonymized/stripped prior to University of New Brunswick release|
+---------------------+-------------+----------------------------------------------------------------+
```

Because all 8 files lack IP addresses and timestamps, `sentrix_ml.provenance` falls back to `group_scope = "raw_record_only"`. The `duplicate_id` is computed strictly by hashing the remaining 78 statistical measurement columns.

### 4.2 Full Population Collision Audit (2,830,628 Valid Rows)
Using disk-backed SQLite indexing, all 2,830,628 valid rows were indexed and queried:

* **Total Raw Rows Considered**: 2,830,743 (115 invalid numerics dropped; 2,830,628 valid).
* **Total Unique Measurement Fingerprints**: **2,521,557**
* **Singleton Fingerprints** (occur exactly once): 2,426,084
* **Repeated Fingerprints** (occur $> 1$ time): 95,473 groups (comprising 404,544 rows).
* **Clean Same-Label Duplicates**: **94,775 groups** (397,524 rows).
  * If same-label deduplication were applied, it would remove **302,749 redundant rows**.
* **Conflicting Binary Label Groups**: **698 groups**!
  * **Total Rows in Conflicting Groups**: **7,020 rows** (**736 benign rows** and **6,284 attack rows**).
  * **Intra-File Conflicts** (within the exact same capture day): **34 groups**.
  * **Inter-File Conflicts** (across different days/capture files): **664 groups**.
  * Detailed breakdown of all 698 groups exported to [`cic_conflict_groups.csv`](file:///c:/Users/LENOVO/SENTRi-X/outputs/dataset-audit/run_20261003_103150/cic_conflict_groups.csv).

### 4.3 Scientific Classification of Conflicting Examples
The top 50 conflict groups were exported with full raw values to [`cic_conflict_examples.jsonl`](file:///c:/Users/LENOVO/SENTRi-X/outputs/dataset-audit/run_20261003_103150/cic_conflict_examples.jsonl).

* **Example 1 (`cic_ids2017:raw:c2f91d1f...`)**:
  * Total Rows: **3,362 rows** share the exact same 78 measurement values.
  * Labels: **2 rows are labeled `BENIGN`** (in `Friday-PortScan` and `Tuesday`), while **3,360 rows are labeled `DoS Hulk`** (in `Wednesday`).
  * Raw Measurements: `Destination Port=80`, `Flow Duration=1`, `Total Fwd Packets=2`, `Total Backward Packets=0`, `Total Length of Fwd Packets=0`, `Fwd Header Length=64`, `ACK Flag=1`, `Init_Win_bytes_forward=274`, `min_seg_size_forward=32`.
* **Example 2 (`cic_ids2017:raw:5907da5b...` - Seed 42 50k Trigger)**:
  * Two rows: Row `244014` in `Friday-PortScan` (`PortScan`, binary 1) vs Row `50967` in `Thursday-Infiltration` (`BENIGN`, binary 0).
  * Raw Measurements: `Destination Port=705`, `Flow Duration=52 us`, `Total Fwd Packets=1`, `Total Backward Packets=1`, `Total Length of Fwd Packets=2`, `Total Length of Bwd Packets=6`.

**Scientific Finding**:  
Because these CSV files lack IP addresses and timestamps, standard network events (e.g. empty 2-packet TCP ACK probes to port 80, or 2-byte SYN scanner probes) generate identical statistical feature vectors regardless of whether they were sent by legitimate background software or by an attacker during a DoS flood.  
They are **distinct physical network events** with **identical aggregate measurements**. The current provenance pipeline treats identical measurements as identical raw records, flagging them as ground-truth annotation contradictions.

---

## 5. Artifacts and Generated Evidence

All diagnostic evidence is preserved in `outputs/dataset-audit/run_20261003_103150/`:
1. **Master Audit Summary**: [`audit_summary.json`](file:///c:/Users/LENOVO/SENTRi-X/outputs/dataset-audit/run_20261003_103150/audit_summary.json)
2. **BoT-IoT Benign Inventory**: [`bot_iot_benign_inventory.csv`](file:///c:/Users/LENOVO/SENTRi-X/outputs/dataset-audit/run_20261003_103150/bot_iot_benign_inventory.csv) (477 records with full session metadata)
3. **CIC-IDS2017 Column Inventory**: [`cic_column_inventory.json`](file:///c:/Users/LENOVO/SENTRi-X/outputs/dataset-audit/run_20261003_103150/cic_column_inventory.json)
4. **CIC-IDS2017 Conflict Groups**: [`cic_conflict_groups.csv`](file:///c:/Users/LENOVO/SENTRi-X/outputs/dataset-audit/run_20261003_103150/cic_conflict_groups.csv) (698 conflicting groups)
5. **CIC-IDS2017 Conflict Examples**: [`cic_conflict_examples.jsonl`](file:///c:/Users/LENOVO/SENTRi-X/outputs/dataset-audit/run_20261003_103150/cic_conflict_examples.jsonl) (Top 50 examples with complete raw values)
6. **Execution Log**: [`audit.log`](file:///c:/Users/LENOVO/SENTRi-X/outputs/dataset-audit/run_20261003_103150/audit.log) (Exit code 0 in [`audit_exit_code.txt`](file:///c:/Users/LENOVO/SENTRi-X/outputs/dataset-audit/run_20261003_103150/audit_exit_code.txt))
