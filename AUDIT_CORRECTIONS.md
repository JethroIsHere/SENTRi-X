# Dataset audit corrections

Base: 557a68c5bd6611e0fcbddbfcdae158a8add18dfc, reviewed 3 October 2026. The prepared corrections to cbcbd0b have been reconciled with this newer push.

The audit tool and its interpretation are corrected. The production training pipeline has not been changed by this patch. The full raw datasets are on the user's laptop and have not been rerun in the correction environment. **Prompt 2 is not cleared:** the latest production changes still discard conflicting CIC labels, omit the proposed source-population evaluation weights, and store an unbounded minority list. See [the latest-push review](outputs/dataset-audit/REVISED_AUDIT_REPORT.md).

## Changes

- Removed unvalidated inventory reuse and fixed population constants. A run requires fresh output files and scans the source population.
- Counts all valid group members in a disk-backed index, including attack rows preceding benign rows. Numeric/label eligibility is checked against both real production adapters in regression tests.
- Honors the requested seed and sample capacities. Split traces execute production preparation and both allocations, preserving the actual pool counts and failure stage.
- Repairs the undefined `data_root` in the latest audit CLI and uses the latest six-value production preparation result. Trace output records input/retained/removed class counts, conflict counts and warnings. A production partition that passes only after conflicting-label records are discarded is marked `REVIEW_REQUIRED`, with the actual production gate outcome recorded separately.
- Saves the production sampling metadata for each replay, including the new BoT class-stratified policy and observed source/selected class counts.
- Distinguishes a BoT-only diagnostic from a combined Omni replay.
- Counts CIC within-file conflicts and conflicts spanning files separately, with their overlap. Attack-name divergence counts now exclude mixed benign/attack groups.
- Exports examples from both labels, with source references and strict JSON. Ambiguous examples remain labelled unresolved.
- Samples RSS over the run and reports the interval and scope. Unavailable process metrics are reported as unavailable; they are not replaced with invented values. TensorFlow is not imported merely to check its installed version.
- Checks source hashes for additions, removals and changes, and detects source changes between scanning and replay.
- Corrected the archived narrative and sampling proposal. The historical numerical summary is preserved with explicit validity annotations; five nonstandard missing-value constants in the historical JSONL were converted to JSON null.

The revised proposal retains CIC source rows and original labels, separates identity from grouping, and describes a BoT design with explicit source-group assignment, sample inclusion probabilities and evaluation weights. It withdraws unsupported memory and deployment-prevalence claims. It is a specification for subsequent shared pipeline work. The latest push's keep-first conflict policy remains visible in production replays; this audit does not silently replace that policy or approve it.

## Executed verification

~~~text
python -m pytest tests/test_dataset_audit.py tests/test_data_integrity.py tests/test_t1_splits.py -q -ra
41 passed, 0 failed, 0 skipped
~~~

These checks use temporary raw CSVs, the real production loaders and split functions, and temporary SQLite indexes. They cover the reported defects, exact row/fingerprint parity, preservation of input files, missing data, both-class examples, split failures, rare mixed profiles, full CLI execution and an actual three-domain Omni replay on fixtures. They also verify that a passing production gate cannot hide the loss of 150 of 180 ambiguous fixture rows in the audit output.

Four warnings came from an existing pandas deprecation in the CIC adapter. The prior 86-test laptop run remains historical evidence. The latest commit message claims 89 tests and all-dataset readiness, but includes no updated run evidence; the only committed raw-data preflight report still says FAILED. The full TensorFlow/backend suite was not rerun in this correction environment, and fixture results are not thesis accuracy or full-dataset results.

## Run on the laptop after updating

Use PowerShell from C:\Users\LENOVO\SENTRi-X and the existing environment.

Run the focused checks:

~~~powershell
.\venv\Scripts\python.exe -m pytest tests/test_dataset_audit.py tests/test_data_integrity.py tests/test_t1_splits.py -q -ra
~~~

Then run a fresh full-source BoT/CIC audit:

~~~powershell
.\venv\Scripts\python.exe tools/audit_dataset_readiness.py --data-root data/raw --seed 42 --sample-n 50000 --sample-per-domain 30000 --chunksize 10000
~~~

The script creates a new timestamped directory under outputs/dataset-audit/, prints progress, and writes audit_summary.json, audit_exit_code.txt, inventories, conflict summaries/examples and local SQLite indexes. Capture the terminal output in the IDE. Existing output directories are not silently reused.

To also reproduce the combined Omni allocation, add --include-omni. This additionally scans ToN using the production Omni loader's normal chunk defaults. Without that flag, the full Omni replay is explicitly marked NOT_RUN.

Keep SQLite indexes local; they are already excluded by the repository's *.db rule. Return the new audit_summary.json and terminal log for review.

An audit exit code of zero means the diagnostic operations completed. Split traces may still show FAILED or REVIEW_REQUIRED, and training_readiness remains NOT_ESTABLISHED_BY_AUDIT. Even READY in a trace only refers to partition support. The sampling/identity proposal must be implemented consistently in preflight, training, evaluation, manifests and package validation before Prompt 2 can be declared ready.
