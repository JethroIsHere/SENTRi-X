# SENTRi-X latest-push review and audit repair (v3)

Reviewed commit `557a68c5bd6611e0fcbddbfcdae158a8add18dfc` on 3 October 2026.

**Prompt 2 research retraining is not cleared.** The commit improves BoT class inclusion and removes several audit defects, but passing the current preparation gate does not validate its new conflict policy or evaluation population. This document replaces the v2 interpretation; it does not claim a new full-data run.

## Findings in the reviewed push

### 1. Conflicting CIC labels are selected by record order

`sentrix_ml/splits.py::_prepare` warns and then applies `duplicate_id.duplicated(keep="first")` to every domain. It retains one row per fingerprint and removes the others, including rows with different original labels. This contradicts the v2 proposal's retain-all-records claim and also weakens the previous ToN/BoT conflict check.

Reproduction using the actual CIC raw adapter and two copies of one measurement record:

| Source row order | Retained binary labels | Rows discarded |
| --- | --- | ---: |
| BENIGN, DoS | [0] | 1 |
| DoS, BENIGN | [1] | 1 |

Reversing the source order changes the selected ground truth. A warning does not resolve event identity or label correctness. The new mixed-group test deliberately alternates first labels and expects 180 records to become 30; it tests deletion, not preservation of ambiguity.

Required pipeline work: distinguish source-row identity from fingerprint grouping, retain original CIC observations and labels, assign whole groups, and update manifests/package checks consistently. See the revised protocol proposal.

### 2. BoT evaluation changes without the proposed weighting

The adapter now class-samples before study/exam allocation. This can preserve rare benign examples, but it enriches the heldout sample as well as the fitting sample. `sentrix_ml/evaluation.py` still computes only unweighted metrics; no inclusion weights are carried into prediction evidence or the metric calls. The commit changes neither evaluation nor training integration.

Unweighted metrics can describe the declared enriched sample. They cannot be presented as source-population-calibrated metrics merely because the proposal mentions weighting. Declare the sampling/partition protocol and implement its inclusion probabilities and evaluation integration before the thesis training run. Source-dataset prevalence does not establish live-network prevalence.

### 3. The audit CLI cannot complete

The pushed `main()` passes `data_root` to both domain audits and summary output without defining it. The parser defines `args.data_root`. The executed entry point raised:

~~~text
NameError: name 'data_root' is not defined
~~~

For this reproduction only, process-RSS lookup was stubbed because that OS metric is unavailable in the review sandbox. Dataset functions and the runner were not stubbed. The repaired CLI is exercised end to end against temporary source files, including the combined Omni replay.

The pushed audit also produces failure explanations without executing the current allocations, and its BoT numeric check accepts positive infinity. The audit repair uses production-equivalent eligibility and actual split traces, and records failed or successful stages rather than inserting a predicted outcome.

### 4. Minority storage is not bounded by sample capacity

`StratifiedReservoirBuffer.add_chunk` appends every minority row and trims only in `get_result()`. A capacity-10 buffer stored 10,000 benign records while returning 10. The observed 477 benign records may be manageable for the earlier laptop files, but that observation does not establish a general memory bound. Also, `minority_records_collected` and `majority_records_sampled` are buffer sizes before trimming, not necessarily final selection counts.

Required pipeline work: use a bounded reservoir for each class, record seen and selected counts separately, and explicitly define overflow/allocation behavior. Do not hard-code the historical 477 count.

### 5. New all-READY evidence is not committed

The commit message claims 89 passing tests and READY for all four targets. The commit contains seven changed files and no new raw-data preflight JSON or run log. The only committed raw-data preflight remains `outputs/local-verification/run_20261003_083357/preflight-local.json`, whose overall status is FAILED. This does not prove the newer laptop run failed; it means its claimed results cannot be checked from the push.

## Verification actually performed

- On unmodified `557a68c`: 17 data-integrity/split tests passed; the additional reproductions above exposed defects those tests did not reject.
- After the audit repair: 41 focused tests passed, no failures or skips, with four existing pandas deprecation warnings.
- Tests use temporary raw CSVs, real loaders/splitters and SQLite indexes. They verify row/fingerprint parity, group counting, requested seeds/caps, source preservation, strict JSON, measured split failures, conflict deletion reporting and the full CLI/Omni path.
- The full TensorFlow/backend suite and full laptop datasets were not rerun here. These checks establish audit behavior, not thesis detection accuracy.

## What the repair changes

The repaired audit records both the actual production class-support outcome and the integrity limitation. A production READY result after conflicting-label deletion becomes `status: REVIEW_REQUIRED` in the trace while `production_partition_status: READY` preserves what the production gate actually did. Before/after class counts, warnings and removed counts remain visible. No production policy is silently changed by the diagnostic tool.

Fresh runs scan the sources, reject reused output artifacts, preserve source hashes and count finite eligible rows. CIC conflict examples include both classes; within-file conflicts and conflicts spanning files have separately measured overlap. The audit records sampled RSS and end RSS separately and never interprets completion as training approval.

The historical numeric summary remains unchanged except for a review annotation; five nonstandard NaN values in the archived JSONL are normalized to null. The archived narrative is corrected with explicit historical scope.

For the exact laptop commands, see [AUDIT_CORRECTIONS.md](../../AUDIT_CORRECTIONS.md). For the remaining shared training-pipeline work, see [REVISED_SAMPLING_PROPOSAL.md](REVISED_SAMPLING_PROPOSAL.md). Run the repaired audit, implement the consistent sampling/identity/evaluation protocol, and save fresh actual-data preflight evidence before Prompt 2 research training.
