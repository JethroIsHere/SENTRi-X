# SENTRi-X sampling and identity proposal (v3)

Reviewed against commit `557a68c` on 3 October 2026. **The shared protocol below remains proposed work. The audit repair does not implement it.**

This replaces the v2 proposal, which contradicted itself by promising to retain all ambiguous CIC records and then recommending keep-first deletion. Equal measured fields do not establish which source label is correct, and selecting the first record is not an ambiguity-resolution method.

The complete implementation specification is maintained in [SAMPLING_AND_IDENTITY_PROPOSAL.md](run_20261003_103150/SAMPLING_AND_IDENTITY_PROPOSAL.md). The latest-push findings and executed checks are in [REVISED_AUDIT_REPORT.md](REVISED_AUDIT_REPORT.md).

## Required behavior

1. **CIC identity and grouping:** retain eligible source observations and original labels; identify them by domain, file hash and original row position. Use measurement fingerprints as conservative partition groups where physical identity is unavailable. Keep same-label repeats and mixed-label groups together rather than choosing one representative label.
2. **BoT sampling:** freeze source-group assignments before within-partition sampling under the recommended design. Use bounded class-aware fitting samples. Evaluate full heldout partitions in batches or a declared within-partition probability sample with recorded inclusion probabilities and weights. Do not hard-code 477.
3. **Allocation and support:** preserve whole groups and enforce original class/domain support with a deterministic documented allocation rule. Report infeasible configurations. Two mixed groups in the source do not by themselves guarantee that both subsequent allocations are feasible.
4. **Evaluation:** report unweighted enriched-sample metrics separately from source-heldout-population estimates. Carry valid design weights through all reported metric variants, confusion totals and prediction evidence. Declare the validation/early-stopping/threshold criterion before fitting; keep exam results out of selection.
5. **Shared integration:** apply the policy consistently in provenance, adapters, sampling, splits, Omni, preflight, training/notebooks, evaluation, packaging and backend metric labels. Version manifests and reject incompatible packages explicitly.

The current dual-reservoir implementation is an intermediate class-sampling change, not the complete protocol. It stores all benign rows before trimming and the current evaluator does not implement population weighting. The current keep-first conflict handling is also not the recommended CIC behavior.

## Next execution sequence

1. Run audit v3 in a fresh directory on the laptop using [AUDIT_CORRECTIONS.md](../../AUDIT_CORRECTIONS.md). Preserve raw-data files and collect the new JSON and log.
2. Implement and verify the shared protocol, including bounded minority overflow, retained CIC multiplicity, rare mixed groups, disjointness and evaluation-weight arithmetic.
3. Rerun the full software suite and actual-data preflight for the exact declared training configuration. Commit the fresh evidence, including source hashes, class counts and measured resources.
4. Once those checks and the protocol are reviewed, proceed to sequential Prompt 2 candidate training and evaluation. Pi feature parity, physical attack/Snort comparisons and expert evaluation remain later milestones.

An audit exit code of zero or a class-support READY result alone does not clear these research requirements.
