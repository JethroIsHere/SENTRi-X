# SENTRi-X notebooks

Start with **[01_ToN_IoT_Baseline.ipynb](01_ToN_IoT_Baseline.ipynb)**.
It replaces the separate ToN ETL, RF, CNN and fusion workflow with one visible,
top-to-bottom experiment. The old ToN notebooks, including the previous XAI work,
are preserved without content changes in [archive/ton_iot](archive/ton_iot/).

## First run on your laptop

1. Pull or check out the notebook rebuild branch and open the repository in your IDE.
2. Open `notebooks/01_ToN_IoT_Baseline.ipynb`.
3. Select your project's Python environment that has TensorFlow installed. In your
   existing Windows setup this is normally `venv\Scripts\python.exe`.
4. Keep your raw ToN CSV files in `data/raw/ton_iot/`, or change `args.data_dir` in
   the configuration cell. The adapter prefers `Network_dataset_*.csv` and falls
   back to all CSVs when there are no matching files.
5. Leave `RUN_TYPE = "smoke"`. Restart the kernel and run all cells in order.
6. Check the partition table, real CNN training output, three-mode metrics and final
   candidate verification. The last cell prints the saved candidate and figure paths.

The smoke settings are 2,000 selected rows, five RF trees and one CNN epoch. The
loader still scans the selected CSV files to form the sample. Both models are real;
a missing TensorFlow dependency stops execution. These scores are execution checks,
not thesis findings.

No old processed matrices or earlier notebook executions are needed. If you rerun
the notebook, restart at the configuration cell to get fresh output directories.
If a class-support check fails, keep that evidence and review the stated sampling
protocol; do not try seeds until the check passes.

## Declared ToN baseline

The notebook's `full` preset uses the existing 50,000-row sample, 100 RF trees,
10 CNN epochs, batch size 256 and seed 42. Reserve 20% of groups for testing and
10% of the remaining groups for validation. Fractions target groups; actual row
counts are saved. Distinct source records and original labels remain intact.
Common group profiles are stratified; singleton profiles use one seeded allocation.
The final partitions must pass the original-row class-support check.

Scaling fits only original training rows. Random oversampling applies only to the
training partition. RF and CNN use those same fitting rows. Equal-weight fusion
and the 0.5 attack threshold are fixed before the holdout is evaluated.

Metrics describe this sampled, group-disjoint ToN holdout. They are not estimates
of all source traffic or real Pi performance. `inclusion_probability` and
`sampling_weight` in prediction evidence describe ingestion only; the metrics are
explicitly unweighted. Grouping uses the existing raw metadata implementation;
its recorded limitations about missing session identifiers still apply.

After the laptop smoke run succeeds, start a fresh kernel/run for the declared
full baseline. Keep the configuration and saved evidence. Do not choose parameters
or rerun seeds based on test scores. The notebook saves a candidate and does not
activate it in the dashboard.

## Files used by the notebook

The notebook shows each research stage. Existing `sentrix_ml` functions provide the
reusable adapter, scaler, training, inference and artifact packaging. In particular,
the notebook, source CLI and ToN preflight share `split_source_data` in
`sentrix_ml/train_source.py`. No new training module or audit script was introduced.

Each run creates:

- `models/candidates/<run_id>/`: RF, CNN, fitted pipeline, split manifest,
  prediction evidence, metrics and package manifest with artifact hashes.
- `outputs/notebook_runs/<run_id>/`: configuration, partition counts, CNN history,
  metric table and two PNG figures.

The canonical feature mapping is shared with inference, but parity between the
Pi sensor's feature meanings and training measurements still needs verification.

## Remaining notebook work

This change rebuilds the ToN baseline only. XAI must be rebuilt against this exact
candidate, followed by BoT-IoT and CIC-IDS2017 adaptation and Omni. The other old
notebooks remain in the repository and are not approved research workflows by this
change. Their sampling/weighting integration findings remain open.

Archive notebooks are historical references: their relative paths and processed
artifacts may be obsolete. Use Git history if you need their original locations.

## Verification

From the repository root, use the project's TensorFlow Python environment:

```powershell
.\venv\Scripts\python.exe -m pytest tests/test_ton_baseline.py -q -ra
```

The regression test executes every Python notebook cell in fresh processes using
generated raw fixtures, real RF/CNN training and temporary output directories. It
also verifies that saved prediction evidence reproduces the metrics and source
labels. It does not execute a Jupyter frontend or use the research CSV files.
