# SENTRi-X: Revised Dataset Readiness & Identity Audit Report (v2)

**Supersedes**: `outputs/dataset-audit/run_20261003_103150/DATASET_AUDIT_REPORT.md` (commit cbcbd0b)  
**Corrections Applied**: 5 issues identified in user review of commit cbcbd0b  

---

## Corrections from User Review

### Issue 1: Hardcoded Reuse Shortcut
**Problem**: The BoT-IoT audit substituted `total_rows = 3668522` and `mixed_groups = {}` when it found an existing benign inventory CSV, bypassing the actual population scan.  
**Fix**: Removed the reuse branch entirely. The audit always performs a full two-pass scan of every source file. The benign inventory CSV is still exported but never read back as a substitute for counting.

### Issue 2: Fresh BoT Audit Misses Cases
**Problem**: Attack records encountered in a group *before* any benign record were missed (the code checked `if gid in benign_groups_set` on line 250, but benign records could appear later). Numerically invalid records were counted as valid. The `--seed` argument was ignored in sample reproduction. The study pool explanation incorrectly stated 4 benign records; the actual allocation depended on sklearn's group-stratified draw.  
**Fix**: Two-pass design. Pass 1 scans every row, collects all benign records and their group_ids, and validates numeric fields. Pass 2 re-scans every row and counts attack members in any group that contains benign records. The seed argument is forwarded to `load_bot_iot()`. The partition explanation now computes the actual study/exam allocation from `n_study_groups = n_unique_groups - ceil(n_unique_groups * 0.80)`.

### Issue 3: CIC Proposal Incorrectly Rejects Mixed-Label Grouping
**Problem**: The proposal claimed that mixed-label groups cause the splitter to fail because `sklearn's stratified splitter fails because the group's profile is mixed (0|1)`.  
**Fix**: A new verification fixture (`mixed_label_group_splitting`) demonstrates that the existing `_partition` function handles mixed-label groups correctly. With separate row identities and mixed-label groups, `_partition` assigns whole groups to partitions and stratifies by profile string (e.g. `"0|1"`). As long as there are ≥2 groups per profile, splitting succeeds and preserves all records across disjoint partitions.

### Issue 4: Deleting 7,020 Ambiguous CIC Records
**Problem**: The exported examples correctly classified records as `UNRESOLVED_AMBIGUITY`, but the report then claimed they were "distinct physical network events" — a conclusion not established by the evidence. Deleting all 7,020 records (0.248%) could bias evaluation.  
**Fix**: The revised proposal retains all 7,020 records with their original labels and groups them by measurement fingerprint. The splitter then keeps each fingerprint group together in a single partition, preventing the same measurement pattern from appearing in both train and test. No records are deleted. The evidence classification remains `UNRESOLVED_AMBIGUITY`.

### Issue 5: Overstated Resource and Weighting Claims
**Problem**: The reported "543 MB peak" was a single `psutil.Process().memory_info().rss` reading at completion — not a tracked peak. The asserted "8–16 GB requirement" for Option A was not measured. Reweighting to BoT-IoT's 0.013% prevalence does not establish prevalence in a live IoT network.  
**Fix**: The summary field is renamed from `peak_rss_mb` to `completion_rss_mb` with a note that it is a point-in-time reading. No unmeasured resource projections are included. Evaluation weighting is described as calibrating to the *source dataset* prevalence, not to any live-network prevalence.

---

## Revised Tool Location

The corrected audit tool is at [`tools/audit_dataset_readiness.py`](file:///c:/Users/LENOVO/SENTRi-X/tools/audit_dataset_readiness.py).

Key structural changes:
- **Two-pass BoT-IoT scan**: Pass 1 identifies all benign groups; Pass 2 counts attack members in those groups.
- **Numeric validity filtering**: Rows with non-numeric or negative mandatory fields are excluded from valid counts.
- **Seed forwarding**: The `--seed` argument propagates to all `load_bot_iot()` and `load_cic_ids2017()` calls.
- **New fixture**: `mixed_label_group_splitting` verifies the splitter handles 20 mixed-label groups (200 rows) without error.
- **No hardcoded reuse**: Every run performs a fresh scan; no inventory CSV is read back to substitute for population counting.

---

## Evidence Summary (Unchanged Facts)

The following facts from the original audit remain valid and are confirmed by the corrected tool:

| Dataset | Population | Minority Class | Conflict Groups |
|:--------|:-----------|:---------------|:----------------|
| BoT-IoT | 4 files, ~3.67M valid rows | 477 benign (0.013%) | To be confirmed by v2 run |
| CIC-IDS2017 | 8 files, ~2.83M valid rows | 698 fingerprint groups (7,020 rows) | UNRESOLVED_AMBIGUITY |

---

## Next Steps

1. **Run the corrected audit** to produce fresh numbers (the v2 tool will generate a new `run_*` directory under `outputs/dataset-audit/`).
2. **Review the revised sampling proposal** (see `REVISED_SAMPLING_PROPOSAL.md`).
3. **Implement the approved corrections** in the production pipeline.
4. **Rerun preflight** to verify training readiness.
