# SENTRi-X sampling and identity correction proposal

Revised 3 October 2026. This supersedes the original proposal in commit `cbcbd0b`.

**Status: proposed training-pipeline work, not implemented by the audit repair.** The original dataset files and existing training behavior remain unchanged. Dataset labels, identity evidence and evaluation scope must not be changed merely to make preflight pass.

## 1. Evidence and scope

The earlier production preflight found only 477 benign records among 3,668,522 BoT rows. Its uniform 50,000-row sample contained four benign records, of which one entered the study pool. The corrected full-source audit must establish group counts and mixed groups before an experiment is frozen.

CIC exports contain 698 mixed-label measurement groups covering 7,020 rows. Their physical event identity is unresolved. Equal recorded measurements are not proof of duplicate events, even when labels agree.

Counts above describe these source files. They are neither runtime constants for ingestion nor measured prevalence in the live Pi network.

## 2. BoT: group partitioning followed by bounded sampling

Recommended design:

1. Enumerate eligible source rows and session groups with file-hash/row lineage, using bounded processing and a disk-backed index.
2. Assign whole source groups to study/exam once, using the declared seed and class-count information. Assign study groups to fitting/validation once. Keep the existing 20% study / 80% exam and 10% validation-within-study targets as the baseline; report actual row fractions when groups have unequal sizes.
3. Only after group assignment, select bounded fitting rows. Retain or sample benign fitting rows under declared capacity rules; sample attack fitting rows using a seeded reservoir. Do not hard-code 477 or silently truncate an overflowing minority allocation.
4. Fit preprocessing on original selected fitting rows, then apply declared training-only balancing. No duplicate source record or group may cross partitions.
5. Evaluate either the complete held-out partitions in bounded batches or an explicitly documented probability sample from each held-out partition.

This changes the old "uniform global sample, then split" protocol and therefore needs a new versioned sampling manifest. It is not a silent change to an existing frozen experiment.

### Evaluation choices

**Full held-out population:** stream predictions, keep original class prevalence and save prediction-level evidence. Avoid loading all raw predictors into RAM. Runtime, model memory and artifact size still need measurement.

**Bounded class-stratified evaluation:** if full evaluation is too costly, sample within the already assigned validation and exam partitions. Record each class population `N_c`, selected count `K_c`, inclusion probability `pi_c = K_c / N_c` and row weight `1 / pi_c` for uniform within-class row sampling. Every represented class must have positive inclusion probability.

That simple weight formula applies to the stated within-partition uniform row design. A different group/cluster selection scheme needs its actual inclusion probabilities. Do not use a prevalence ratio as a substitute for an unspecified sampling design.

Report:

- Unweighted sample confusion matrices and metrics, clearly labelled as enriched-sample results.
- Source-heldout-population estimates computed consistently from the saved weights and predictions for RF, CNN and Hybrid.
- Weighted confusion totals, accuracy, precision, recall, specificity/false-positive rate and F1; compute weighted ROC/PR summaries where reported.
- Observed class support and uncertainty, especially for the rare benign class.

A minimum class-support check only establishes that a computation is possible; one or a few validation examples do not establish stable estimates. Declare the validation/early-stopping/threshold-selection criterion in advance, including whether it uses sampling weights. Keep final exam outcomes out of model selection.

Source-population weighting does not establish deployment calibration or live detection performance. Those require later physical trials and a separately measured target population.

### Alternative: larger uniform reservoir

This remains a possible design. Expected benign support is `K * 477 / 3,668,522`, not a guarantee. For example, roughly 384,541 rows gives an expectation near 50 benign rows before grouping and subsequent splits.

Assess actual group support and memory for a predeclared configuration. Do not scan seeds or sample sizes until a preferred score appears. The earlier blanket 8–16 GB requirement and guaranteed OOM prediction are withdrawn.

## 3. CIC: separate source-row identity from measurement grouping

Recommended primary analysis:

1. Preserve each eligible source record and its original label.
2. Identify rows by domain, file SHA-256 and original record position.
3. Where physical identifiers are absent, treat the full nonlabel measurement fingerprint as a conservative **partition grouping key**, not proof that rows should be merged or labels rejected.
4. Assign every member of a measurement group to one partition, including same-label repeated observations and mixed-label observations.
5. Keep IPs, timestamps, source filenames, row IDs, fingerprints and labels outside predictor features unless explicitly part of the declared model contract.

This prevents matching measurement groups from leaking across partitions while retaining the observed ambiguity and multiplicity.

At cbcbd0b the preparation step rejected mixed labels attached to the same duplicate identity. Commit 557a68c replaced that rejection with a warning and keep-first deletion; this does not implement retain-and-group. Preparation must become domain/policy aware and preserve the source observations for the proposed primary analysis. Package checks must separately validate source-row overlap and group overlap; changing the identity field without updating lineage validation is incomplete.

The current stratifier accepts mixed profiles when sufficiently represented, but its rare-profile checks can block a single mixed group. Add and document a deterministic group-allocation rule that uses group class-count vectors, keeps groups intact and checks per-class/per-domain support. It must not require every rare composite profile in every partition, choose seeds using evaluation scores, or silently fall back to row splitting. If the declared constraints cannot be met, report the infeasibility.

### Other options and limits

Richer existing CSV/flow exports may improve event identity. Inventory them before claiming that a particular download or storage size is required. Do not infer omitted protocol fields using an undocumented heuristic.

A quarantined version may be a separately labelled sensitivity analysis if there is a documented reason. Exclude an entire predefined group consistently, retain every exclusion reference and report changes to class composition. Preserve an unfiltered primary result or clearly limit claims to the altered population. Do not describe every measurement collision as erroneous annotation or claim that filtering establishes correct ground truth.

## 4. Required implementation coverage

| Component | Required consistency |
| --- | --- |
| `sentrix_ml/provenance.py` | Distinguish source-row identity, measured event identity where available, and grouping fingerprints. Version the policy. |
| `sentrix_ml/sampler.py` and adapters | Implement the declared post-partition sampling design with source counts, capacities and actual inclusion probabilities. |
| `sentrix_ml/splits.py` | Keep whole groups, retain CIC observations and mixed labels, handle rare profiles under the declared rule, and validate support. |
| `sentrix_ml/datasets.py` | Apply the same rules to Omni, with domain-qualified identities and explicit domain-mixture weights. |
| `sentrix_ml/preflight.py` | Exercise exactly the configured training/evaluation selection and allocations. |
| Training entry points and notebooks | Consume the same frozen partitions and weights; fit preprocessing and balancing on fitting data only. |
| `sentrix_ml/evaluation.py` | Export predictions with source references, inclusion probabilities and weights; distinguish empirical and population-estimated metrics. |
| `sentrix_ml/packaging.py` | Validate the new policy, manifests, weights, source hashes and disjointness. Reject incompatible legacy packages explicitly. |
| Backend metric reporting | Label the evaluation population, sample design and metric variant; preserve artifact provenance. |
| Tests | Cover order/chunk stability, minority overflow, rare/mixed groups, retained CIC multiplicity, no overlap, weight arithmetic and unchanged RF/CNN/backend prediction parity. |

Do not implement an audit- or preflight-only exception that training cannot reproduce. Keep class-support and lineage gates enforced. A passed gate under the latest keep-first conflict policy is not approval of the research protocol; replace that behavior consistently before treating the dataset as ready.

## 5. Next execution sequence

1. Run the repaired audit in a fresh directory on the actual source files. Review actual groups, corrected split traces and resource observations.
2. Implement the chosen design across the components above, with focused regressions and full integration verification.
3. Run actual-dataset preflight using the exact declared training configuration. Save its manifest, class counts, source hashes and resource evidence.
4. Freeze the protocol and proceed with sequential Prompt 2 candidate training and evaluation. Activation, Pi feature parity, physical attack/Snort trials and expert evaluation remain subsequent milestones.
