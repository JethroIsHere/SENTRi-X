# SENTRi-X — Prompt 1 correction verification

Date: 2 October 2026. Base commit: `bbea010d69a78cc1ae7f5809cd5241eb9180ef6d`.

**The reviewed software regressions are corrected. Full research retraining still requires a successful preflight on the actual local datasets and an adequate resource budget for the configured jobs.**

## Changes

1. **Separate record identity from split groups.** Each selected row has its original zero-based file-relative record index, source filename/domain, file SHA-256, and a namespaced source ID. Raw-record fingerprints exclude label annotations and generated counters, but retain timestamps and traffic measurements. Conflicting labels for identical raw records cause an error. No encoded-feature-vector deduplication is performed.
2. **Preserve distinct sessions.** An available connection tuple plus session-start timestamp defines a split group. Without the timestamp, the full tuple is kept together as a conservative group; without tuple fields, the raw-record fingerprint is used. Exact raw duplicates keep their first selected occurrence. All other observations remain, with whole groups assigned to one partition.
3. **Correct chunk row offsets.** Adapters assign file-relative positions once before cleaning. Removed rows keep their original positions, and reservoir replacement preserves each selected row's metadata. Raw fields are parsed as strings before domain conversion so identity does not depend on chunk type inference.
4. **Validate actual partitions.** Preflight uses the requested sample size, seed, source/adaptation fractions, and Omni domain caps. It runs the same cleaning/grouping/splitting paths as training. Training repeats the support checks before fitting. At least two original rows per binary class are required in training and one per class in validation/test; Omni also requires both classes in each domain's partitions. A failure does not trigger automatic holdout redraws.
5. **Balance training only.** Seeded random oversampling duplicates original fitting rows to equal binary class counts. This is an explicit change from the old SMOTE method: no fractional one-hot values are manufactured and no nearest-neighbor assumption is needed. The scaler fits original training rows first; validation/test are never resampled. The method, seed, before/after counts, and a digest of selected training positions are exported.
6. **Persist selection and lineage.** The hashed split manifest now contains the source traversal/selection audit, class counts, raw record references, and group IDs for all partitions. Omni source hashes are namespaced by domain. Adaptation records its source-candidate hash. Strict package checks reject missing/inconsistent lineage or cross-partition group/record overlap. Nonempty candidate output directories are not overwritten.
7. **Exercise the real backend.** A new integration test trains actual RF/CNN source, BoT adaptation, CIC adaptation, and Omni packages; serializes and independently reloads them; loads each through the real backend validator; switches RF/CNN/Hybrid modes through HTTP; and submits flows to `/api/ingest-flow`. It compares probabilities, predictions, transforms, and artifact hashes. Tests use temporary databases and candidate directories.
8. **Make notebook tests independent of local datasets.** All six rewritten notebooks execute against temporary synthetic raw files. The three ToN split notebooks now pass source metadata and use the corrected policy. Tests never remove or overwrite a real notebook candidate directory. CIC's available raw protocol field is mapped to TCP/UDP instead of being discarded.

## Split and identity limitations

The source/Omni target remains 20% final holdout, with 10% of the remaining pool for validation. Adaptation targets 20% study and 80% exam, with validation inside study.

Splitting uses one seeded stratified draw of groups, stratified by the group's class/domain profile. For singleton groups this reduces to row-level stratification. When group sizes differ, fractions apply to independent groups and actual row fractions can differ; saved row counts are authoritative. The algorithm does not optimize against model scores or try seeds until a favorable result appears.

Without session identifiers, identical raw observations cannot be distinguished as separate physical sessions. The fallback is explicitly recorded in the sampling audit. Tuple-only grouping may be too coarse to produce viable partitions; preflight then blocks the affected run. Fix the documented sampling/grouping protocol before freezing an experiment. Do not force balanced evaluation data or silently fall back to splitting related groups.

## Executed verification

Command from the project root:

```bash
python tests/run_all_tests.py
```

Result in the isolated review environment:

```text
86 passed, 0 failed, 0 skipped
```

The real integration check completed **12 backend comparisons**: RF, CNN, and Hybrid for each of the four packages. It used 200 synthetic records per domain, three RF trees, and one CNN epoch. Six notebook executions also passed. These checks validate software plumbing and isolation; their fixture metrics are not thesis accuracy or live attack-detection results.

The suite also checks multi-chunk provenance after invalid-row removal, stable sampling across chunk sizes, reused tuples with distinct timestamps, whole-group preservation, exact duplicates without tuple fields, conflicting labels, rare-class rejection, and categorical-safe training-only balancing.

The environment used Python 3.12.14, TensorFlow CPU 2.21.0, Keras 3.13.2, scikit-learn 1.8.0, NumPy 2.3.5, pandas 2.2.3, FastAPI 0.142.2, pytest 9.1.1, and httpx 0.28.1. Upstream Keras/pandas/FastAPI deprecation warnings remain; they did not fail the checks. This is not a claim that the user's Windows environment was measured again.

## Run on the user's machine after updating

Use the existing project virtual environment. Install the test dependencies if needed:

```bash
python -m pip install -r requirements-test.txt
python tests/run_all_tests.py
python -m sentrix_ml.preflight --require-tf --target all --sample-n 50000 --sample-per-domain 30000 --seed 42 --report-json preflight-local.json
```

The sample caps above match the default source/adaptation and Omni training commands. Preflight scans the selected full source scope to build bounded reservoirs; it does not train on every raw row. On real BoT data these caps may not provide enough benign observations after grouping; a blocked run is intentional and must be resolved before training. Other valid domains can be assessed with `--target ton_iot`, `--target bot_iot`, `--target cic_ids2017`, or `--target omni`.

The local report records current RAM/disk availability. Passing the data/dependency checks is not a measured guarantee that every training job fits available memory. Use CPU execution, sequential jobs, and documented limits; assess resources for the chosen configuration.

Older candidate packages without the new raw lineage will fail strict loading. Test this branch separately from the running deployment and regenerate validated candidates before switching the deployed backend to this pipeline.

## Remaining milestones

- Actual-dataset preflight and measured resource assessment on the training machine.
- Prompt 2 research training and candidate evaluation with frozen samples/partitions and separate versioned output directories.
- Candidate activation, current Pi feature-contract parity, both-device physical checks, and controlled attack/Snort trials.
- Expert evaluation and thesis results based on the actual recorded experiments.

Prompt 2 covers training and candidate evaluation. Activation remains separate. This correction did not alter the user's active deployment or hardware database, run physical attacks, administer questionnaires, or change thesis results.
