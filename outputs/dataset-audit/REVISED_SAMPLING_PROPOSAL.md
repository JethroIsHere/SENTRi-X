# SENTRi-X: Revised Sampling, Identity & Partitioning Proposal (v2)

**Supersedes**: `outputs/dataset-audit/run_20261003_103150/SAMPLING_AND_IDENTITY_PROPOSAL.md`  
**Date**: 3 October 2026  
**Target Milestone**: Prompt 2 (Research Retraining & Cross-Domain Evaluation)  

---

## 1. Context

Prompt 1 corrections resolved software regressions, duplicate leakage, and offline/backend prediction parity (86/86 tests passing). Running preflight against the actual raw datasets identified two data blockers:

1. **BoT-IoT**: Only 477 benign rows in 3.67M total (0.013%). Uniform reservoir sampling at K=50,000 draws ~4–6 benign rows, making stratified validation partitioning impossible.
2. **CIC-IDS2017**: Raw CSVs lack Source IP, Destination IP, Source Port, Protocol, and Timestamp. 698 measurement fingerprint groups (7,020 rows) carry both BENIGN and attack labels. The pipeline's strict duplicate check rejects these as conflicting annotations.

---

## 2. BoT-IoT: Dual-Reservoir Class-Guaranteed Ingestion

### Mechanism
Instead of a single uniform reservoir where minority records are lost in a 99.987% attack flood, the BoT-IoT adapter maintains two deterministic, bounded reservoirs:

1. **Benign Reservoir**: Capacity K_ben = 477 (preserves all available valid benign records).
2. **Attack Reservoir**: Capacity K_att = K - K_ben (e.g. 49,523 rows for K=50,000), sampled uniformly via Algorithm R across all attack rows.

### Partition Allocation
All 477 benign groups and K_att attack groups are partitioned before model training:

| Partition | Benign Groups | Attack Groups | Purpose |
|:----------|:-------------|:-------------|:--------|
| Study (20%) | ~95 | ~9,905 | Train + Validation pool |
| → Training (90% of Study) | ~85 | ~8,915 | Model fitting |
| → Validation (10% of Study) | ~10 | ~990 | Early stopping / hyperparameters |
| Exam (80%) | ~382 | ~39,618 | Final evaluation holdout |

Every partition receives ≥10 benign groups, well above the `min(counts) >= 2` requirement.

### Evaluation Reporting
The test holdout prevalence (~0.955% benign) is enriched relative to the raw source prevalence (0.013%). Metrics must be reported in two ways:

1. **Enriched Empirical Metrics**: Raw accuracy, precision, recall, and F1 on the test holdout as-is.
2. **Source-Dataset-Calibrated Metrics**: Precision and F1 recalculated using importance weights to reflect the 0.013% benign prevalence of the *source dataset*.

> **Note**: These weights calibrate to the BoT-IoT dataset's observed prevalence. They do not establish the benign prevalence of any live IoT network deployment.

### What This Does NOT Do
- Does not extrapolate resource requirements beyond what is measured.
- Does not claim BoT-IoT prevalence represents any particular live network.
- Does not change the existing `ReservoirBuffer` API; it extends it with `StratifiedReservoirBuffer`.

---

## 3. CIC-IDS2017: Measurement-Fingerprint Grouping (Retain All Records)

### Rationale
The user review established that:
- The exported evidence correctly classifies the 7,020 conflicting rows as `UNRESOLVED_AMBIGUITY`.
- The current splitter (`_partition`) successfully handles mixed-label groups when row identities are separate. A verification fixture confirmed this with 20 mixed-label groups (200 rows) across disjoint partitions.
- Deleting all 7,020 rows could bias evaluation by systematically removing specific flow patterns.

### Revised Protocol
Instead of quarantining (deleting) the 7,020 ambiguous records, the CIC-IDS2017 adapter:

1. **Retains all records** with their original source labels.
2. **Groups rows by measurement fingerprint** (`duplicate_id`). Rows with identical measurements share the same `duplicate_id` but have distinct source identities (`source_flow_id = cic_ids2017:{file}:{hash}:row:{index}`).
3. **The splitter assigns whole fingerprint groups** to a single partition via `_partition`'s group-stratified splitting. This prevents the same measurement pattern from appearing in both train and test.
4. **Mixed-label fingerprint groups** (containing both benign and attack rows) receive profile `"0|1"`. As long as there are ≥2 such groups (there are 698), sklearn's stratified split succeeds.
5. **The existing deduplication** (`keep_first_disjoint`) removes exact-duplicate rows within each fingerprint group, keeping one representative per fingerprint. For mixed-label groups, the first row encountered is kept.

### What Changes in the CIC Adapter
- **No records are deleted**. The 7,020 rows remain in the candidate pool.
- **No new quarantine logic** is needed. The existing `_prepare` function already handles deduplication.
- **The conflict check in `_prepare`** (line 181-183 of `splits.py`) must be relaxed for CIC-IDS2017: when rows share a `duplicate_id` but have different labels, this is expected ambiguity, not a data error. The deduplication step (`keep="first"`) resolves it by keeping one representative.

### Implementation Detail
In `_prepare`, the current conflict check:
```python
conflict = yv.groupby(meta.duplicate_id).nunique()
if (conflict > 1).any():
    raise ValueError("Identical raw records have conflicting labels; ...")
```

Should be modified to:
```python
conflict = yv.groupby(meta.duplicate_id).nunique()
conflicting_ids = conflict[conflict > 1].index
if len(conflicting_ids) > 0:
    # Log the count but don't abort — deduplication (keep="first") resolves this
    n_conflicting = int(meta.duplicate_id.isin(conflicting_ids).sum())
    # Record in exclusion metadata rather than raising
```

The `keep="first"` deduplication that follows immediately after already resolves the conflict: only one row per `duplicate_id` survives, so each fingerprint maps to exactly one label in the final training data.

---

## 4. Implementation Summary

| Component | Change | Rationale |
|:----------|:-------|:----------|
| `sentrix_ml/sampler.py` | Add `StratifiedReservoirBuffer` | Dual-reservoir for BoT-IoT minority guarantee |
| `sentrix_ml/adapters/bot_iot.py` | Use `StratifiedReservoirBuffer` | All 477 benign records enter sample |
| `sentrix_ml/splits.py` `_prepare` | Relax conflict check to log + deduplicate | CIC mixed-label fingerprints are expected |
| `sentrix_ml/adapters/cic_ids2017.py` | No deletion of ambiguous rows | Retain all 7,020 records with grouping |
| `tools/audit_dataset_readiness.py` | Two-pass BoT scan, seed forwarding, numeric validation | Correct audit accounting |
| `tests/` | Add mixed-label group splitting fixture | Verify splitter handles the CIC scenario |

---

## 5. Decision Required

1. **Approve BoT-IoT dual-reservoir** with source-dataset-calibrated evaluation metrics.
2. **Approve CIC-IDS2017 retain-and-group** with relaxed conflict check and `keep="first"` deduplication.
3. **Then proceed** to implement, test, rerun preflight, and unblock Prompt 2.
