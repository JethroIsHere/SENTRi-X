# SENTRi-X: Sampling, Identity & Partitioning Correction Proposal

**Author**: Antigravity Pair Programmer  
**Date**: 3 October 2026  
**Target Milestone**: Prompt 2 (Research Retraining & Cross-Domain Evaluation)  
**Audited Datasets**: BoT-IoT (3.67M rows) & CIC-IDS2017 (2.83M rows)  

---

## 1. Context & Motivation

The Prompt 1 corrections resolved software regressions, duplicate leakage, and offline/backend prediction parity (86/86 unit/integration tests passing). However, running preflight against the actual raw datasets identified two fundamental data blockers:
1. **BoT-IoT Minority Class Scarcity**: Only 477 benign rows exist in the entire 3,668,522-row dataset (0.013%). Uniform Algorithm R reservoir sampling at $K=50,000$ draws only ~4 benign rows, rendering stratified validation partitioning mathematically impossible (`min(counts) < 2`).
2. **CIC-IDS2017 Measurement Collisions**: Raw ISCX CSVs completely lack Source IP, Destination IP, Source Port, Protocol, and Timestamp. Aggregating 78 numeric measurements without session identifiers results in 698 fingerprint groups (7,020 rows) where identical measurements are annotated as both `BENIGN` and `ATTACK` (e.g. DoS Hulk or PortScan). The pipeline strictly rejects conflicting annotations.

This proposal evaluates concrete, scientifically defensible solutions for both datasets and outlines the exact code changes, test updates, and governance required.

---

## 2. BoT-IoT Proposals (Addressing Benign Scarcity)

### 2.1 Option A: Scale Up Uniform Reservoir Sample Size ($K$)
To obtain enough benign rows under uniform Algorithm R sampling ($P = K / N$ where $N = 3,668,522$):
* To achieve $\mathbb{E}[N_{ben}] = 50$ rows:
  $$K \ge 50 \times \frac{3,668,522}{477} \approx 384,541 \text{ rows}$$
* To achieve $\mathbb{E}[N_{ben}] = 100$ rows:
  $$K \ge 769,082 \text{ rows}$$

**Evaluation of Option A**:
* **Scientific Merit**: Preserves natural population prevalence ($\approx 0.013\%$).
* **Resource Impact (Host Hardware)**:
  * Ingesting and training RF and CNN models on 385,000 to 769,000 rows in memory requires 8–16 GB of unreserved RAM.
  * The current host laptop has ~1.91 GB available RAM. Running a 700k-row training job on this laptop would cause immediate Out-Of-Memory (OOM) paging or process failure.
* **Partition Vulnerability**:
  * Even with $K = 384,541$ (drawing 50 benign rows): taking a 20% Study split yields only $\approx 10$ benign rows. Taking a 10% validation split inside Study yields only **1 benign row**, which still risks failing `min(counts) >= 2`.
* **Conclusion**: Option A is computationally infeasible on the thesis laptop and does not reliably guarantee partition support without extreme sample sizes ($K > 800,000$).

---

### 2.2 Option B (Recommended): Dual-Reservoir Class-Guaranteed Ingestion with Prevalence Weighting

Instead of a single uniform reservoir where minority records are lost in a 99.987% attack flood, the BoT-IoT adapter maintains two deterministic, bounded reservoirs:
1. **Benign Reservoir**: Capacity $K_{ben} = 477$ (preserves all available valid benign records across the entire dataset).
2. **Attack Reservoir**: Capacity $K_{att} = K - K_{ben}$ (e.g. $49,523$ rows for a $K=50,000$ target), sampled uniformly via Algorithm R across all 3.67M attack rows.

#### Split Protocol under Option B:
1. **Group Partitioning**: All 477 benign groups and $K_{att}$ attack groups are partitioned *before* model training:
   * **Adaptation Split**: 20% Study ($95$ benign, $9,905$ attack) and 80% Exam ($382$ benign, $39,618$ attack).
   * **Validation Split**: 10% of Study ($10$ benign, $990$ attack) allocated to validation; remaining 90% ($85$ benign, $8,915$ attack) allocated to training.
2. **Partition Support Guarantee**: Every partition receives ample support:
   * Train: 85 benign, 8,915 attack (well above `min=2`).
   * Validation: 10 benign, 990 attack (well above `min=1`).
   * Test Holdout (Exam): 382 benign, 39,618 attack (well above `min=1`).
3. **Scientific Evaluation & Honest Reporting**:
   * The evaluation holdout prevalence under this protocol is $382 / 40,000 = 0.955\%$, which is enriched relative to the raw source prevalence ($0.013\%$).
   * **Mandatory Requirement**: In the evaluation report, metrics must be reported in two ways:
     1. *Enriched Empirical Metrics*: Raw accuracy, precision, recall, and F1 on the test holdout.
     2. *Prevalence-Calibrated Metrics*: Precision and F1 recalculated using Bayes' theorem / importance sampling weights ($w_{ben} = \frac{477 / 3,668,522}{382 / 40,000} \approx 0.0136$, $w_{att} \approx 1.009$) so that thesis claims accurately reflect performance in the physical 0.013% environment.

---

## 3. CIC-IDS2017 Proposals (Addressing Measurement Collisions)

### 3.1 Option A: Recover Richer Raw Source Files (PCAPs / Full Flow Records)
* **Investigation Finding**: The audit proved that all 8 raw CSVs in `data/raw/cic_ids2017/` are pre-extracted tabular files lacking Source IP, Destination IP, Source Port, Protocol, and Timestamp. The repository only contains a 7 KB demo pcap (`cicids2017_ddos.pcap`), not the multi-gigabyte raw pcaps of the 2017 capture week.
* **Conclusion**: Richer session identifiers cannot be recovered from the existing local dataset directory without re-downloading ~50 GB of original PCAPs from the University of New Brunswick repository.

---

### 3.2 Option B: Measurement Fingerprint Partition Grouping
* Keep separate source row identities (`cic_ids2017:{file}:{row_index}`) but group identical measurement fingerprints into the same split partition.
* **Defect**: When a measurement fingerprint contains *both* Benign and Attack records, assigning the entire group to one partition causes label contamination, and sklearn's stratified splitter fails because the group's profile is mixed (`0|1`).

---

### 3.3 Option C (Recommended): Quarantined Ambiguity Exclusion Policy

* **Audit Finding**: Out of 2,521,557 unique measurement fingerprints across 2.83M rows, exactly **698 groups** (comprising **7,020 rows**, or **0.248%** of the dataset) have contradictory ground-truth labels (labeled both `BENIGN` and an attack such as `DoS Hulk` or `PortScan`).
* **Root Cause**: Because the ISCX CSV lacks IP addresses and timestamps, standard 2-packet TCP ACK probes (0 bytes, port 80, window 274) sent during normal web browsing have identical statistical metrics to 2-packet TCP ACK probes sent during a DoS flood. No machine learning algorithm can predict both 0 and 1 for the identical input vector.
* **Proposed Protocol**:
  1. During the CIC-IDS2017 adapter streaming pass, identify measurement fingerprints that have contradictory ground-truth labels across the dataset.
  2. Drop the 7,020 contradictory observations as:
     `exclusion_reasons["ambiguous_conflicting_measurement_fingerprint"] = 7020`
  3. The remaining **2,823,608 valid rows (99.752%)** have 100% consistent ground-truth annotations and clean measurement fingerprints.
  4. Deduplicate clean same-label repeated fingerprints (`keep="first"`) as currently designed, leaving **2,520,859 completely disjoint, unambiguous, unique flow records**.
  5. The split manifest explicitly records the SHA-256 digests and row counts of all quarantined collision groups in `quarantined_collision_fingerprints`.

---

## 4. Implementation Specification

To maintain complete architectural integrity, the proposed corrections will be implemented uniformly across the entire pipeline:

```
+-------------------------------------------------------------------------------------------------------+
|                                    AFFECTED ARCHITECTURAL COMPONENTS                                  |
+------------------------------------+------------------------------------------------------------------+
| Component                          | Intended Modification                                            |
+------------------------------------+------------------------------------------------------------------+
| sentrix_ml/sampler.py              | Add `StratifiedReservoirBuffer` (dual-reservoir sampling for rare|
|                                    | minority classes like BoT-IoT benign).                           |
| sentrix_ml/adapters/bot_iot.py     | Integrate dual-reservoir sampling to guarantee all 477 benign    |
|                                    | records enter the candidate sample without changing chunk reads. |
| sentrix_ml/adapters/cic_ids2017.py | Add two-pass or index-based quarantine for the 698 contradictory |
|                                    | measurement collision fingerprints (0.248% excluded).           |
| sentrix_ml/splits.py               | Update `_prepare` to log quarantined ambiguity exclusions and    |
|                                    | increment policy to `duplicate_group_policy="keep_first_disjoint_v2"`|
| sentrix_ml/preflight.py            | Update preflight checks to validate calibrated partition support |
|                                    | and verify collision quarantine.                                 |
| tests/test_data_integrity.py       | Add regression tests verifying BoT minority support (>10 rows per|
|                                    | partition) and CIC collision quarantine.                         |
+------------------------------------+------------------------------------------------------------------+
```

---

## 5. Decision & Next Actions

1. **Review and Approval**:
   * Approve **BoT-IoT Option B** (Dual-reservoir class-guaranteed ingestion with calibrated evaluation metrics).
   * Approve **CIC-IDS2017 Option C** (Quarantine 0.248% ambiguous contradictory measurement fingerprints).
2. **Execute Implementation**:
   * Implement the changes in `sentrix_ml/adapters/` and `sentrix_ml/splits.py`.
   * Run the test suite (`python tests/run_all_tests.py`) to verify zero regressions.
   * Run preflight (`python -m sentrix_ml.preflight --require-tf --target all`) to achieve **PREFLIGHT STATUS: READY FOR CONFIGURED RUN**.
3. **Proceed to Prompt 2**:
   * Once preflight passes cleanly with real dataset support, freeze sample seeds and execute Prompt 2 research training sequentially.
