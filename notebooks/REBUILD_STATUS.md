# ToN baseline notebook rebuild — draft checkpoint

This branch preserves the first notebook rebuild while the latest laptop code is
being reconciled. It is not a retraining approval or a replacement for missing
implementation changes on the user's laptop.

## Implemented here

- One visible ToN baseline notebook, using a shared split for RF and a real CNN.
- Training-only scaling and oversampling, fixed fusion/threshold, one holdout.
- Shared source split/export helpers in the existing `train_source.py` module.
- ToN preflight uses that same split helper; the ToN path explicitly retains
  distinct source records and labels and isolates duplicate/session groups.
- Singleton group profiles use one seeded allocation; actual class support is
  still required. Other allocation limitations are reported without declaring
  every possible group allocation infeasible.
- Prediction evidence keeps probability precision at the 0.5 boundary and source
  row references. ToN metrics explicitly describe the sampled holdout, not a
  source-population estimate.
- Earlier ToN notebooks preserved byte-for-byte in `archive/ton_iot/`.

## Verification performed before the new push

The following completed with **52 passed, 4 existing pandas warnings, no skips**:

```text
python -m pytest tests/test_ton_baseline.py tests/test_dataset_audit.py tests/test_data_integrity.py tests/test_t1_splits.py tests/test_t9_metrics.py -q -ra
```

TensorFlow CPU 2.21.0 trained real models. Every Python notebook cell ran in fresh
processes from both the repository root and the notebooks directory, using 400
generated source rows, a 200-row selection, three RF trees and one CNN epoch.
Saved evidence reproduced the metrics and source labels. Smoke packages remained
nondeployable. No full research retraining, model activation or raw research-data
validation was performed.

The hosted environment blocked Jupyter kernel sockets. The checks executed the
actual Python cell sources in fresh Python processes, not through a Jupyter
frontend. The laptop notebook/kernel run remains to be done.

## Latest main review: 901b071 (2026-10-04)

Commit `d29321f` ("Implement v3 sampling protocol for retrain readiness") adds only
`tests/test_sampling_protocol_v3.py`. Across `c40c935..901b071`, no `sentrix_ml` or
notebook implementation file changed. The new test module imports absent symbols:

- `RARE_PROFILE_POLICY` from `sentrix_ml.splits`;
- `eval_weights_from_manifest_records` and `eval_provenance_from_manifest_records`
  from `sentrix_ml.evaluation`.

On a clean checkout of `901b071`, running that test file fails during collection
with `ImportError: cannot import name 'RARE_PROFILE_POLICY'`. No v3 tests execute.
This is also an unresolved integration issue for this draft branch; it does not
implement the missing v3 API just to satisfy the new test imports.

The committed laptop preflight reports all four targets READY and exit code 0,
but it is a partition-support report. It still records 98 ToN rows, 1,507 CIC rows
and 846 Omni rows excluded as duplicates. This evidence does not establish that
the proposed retain-and-group/weighted v3 implementation is in GitHub or verified.

Next: locate and push the actual edited `sentrix_ml` implementation from the
laptop (or provide those files). Reconcile this notebook with that implementation
and rerun the relevant checks before merging. BoT/CIC/Omni, XAI and Pi feature
parity remain separate unfinished work.
