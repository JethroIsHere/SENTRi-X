# SENTRi-X dataset audit: corrected interpretation

Reviewed 3 October 2026 against commit `cbcbd0b`. This document supersedes the original interpretation of the archived run `run_20261003_103150`. For the subsequent production changes in `557a68c`, see [the latest-push review](../REVISED_AUDIT_REPORT.md).

**Training remains blocked.** The corrected audit tool has not yet scanned the user's full datasets. The original logs remain historical evidence; exit code zero meant that the old script finished, not that its conclusions or training readiness were verified.

## What the archived evidence supports

| Observation | Evidence and limits |
| --- | --- |
| BoT source population | The earlier production preflight reported 3,668,522 valid rows: 477 benign and 3,668,045 attack. The archived audit's source hashes match those files, but its log shows inventory reuse rather than a new BoT population scan. |
| BoT benign inventory | The exported CSV contains 477 records, 477 distinct stored fingerprints and 477 distinct stored group IDs. It contains **465 distinct start times**, not 477; a group uses the tuple plus time. Its correspondence to source rows and mixed-group counts needs a fresh corrected audit. |
| BoT uniform samples | Production loader calls in the archived audit reproduced four benign rows at 50,000 and five at 30,000, seed 42. These are observed draws; the expected benign count at 50,000 is about 6.50. |
| CIC measurement conflicts | The exported group CSV contains 698 groups and 7,020 rows: 736 benign and 6,284 attack. Its examples label the evidence **UNRESOLVED_AMBIGUITY**. |
| CIC identifiers | The column export shows destination port present and source/destination IP, source port, protocol, timestamp and flow ID absent. It does not establish why those fields are absent or prove that PCAP download is the only alternative. |
| Previous software checks | The separate laptop verification recorded 86 tests passing. Those tests did not cover the new audit's defective cache and counting paths. |

## Corrections to the BoT findings

The old script reused any existing benign inventory, substituted fixed population counts and set mixed groups to an empty dictionary. Even its fresh-scan path counted only attack rows occurring after a matching benign row. Therefore the archived **zero mixed groups is unverified**.

The script also treated valid labels as sufficient for population eligibility, omitting the production numeric checks. Its declared seed was not passed to the sample loaders. These defects are fixed in audit version 3.

For the archived 50,000 singleton-group profile (49,996 attack, four benign), the actual production 80% exam allocation gives:

| Partition | Benign | Attack |
| --- | ---: | ---: |
| Study pool | 1 | 9,999 |
| Exam | 3 | 39,997 |

The next 10% validation allocation fails because the **study pool contains one benign group**. The old narrative incorrectly reused the entire sample's four benign groups as the study count.

The prior full Omni preflight reported zero benign records in BoT validation. The old audit did not replay that combined allocation; it inserted the prior outcome into text. Version 3 labels the BoT-only slice explicitly and offers `--include-omni` for an actual combined replay.

## Corrections to the CIC findings

The 698 groups are equal observed measurement fingerprints with different binary labels. Without reliable session identifiers, the evidence does not decide whether particular rows are repeated observations, distinct events with matching statistics, or annotation errors.

The archived same-label count of 302,749 removable rows describes what the old deduplication policy would remove. It does not prove those rows are redundant physical events.

Mixed-label groups are not inherently invalid. A local regression using separate row identities retained 200 rows in disjoint mixed-label groups successfully. The current splitter can nevertheless fail on a rare profile such as a single `0|1` group; that is an allocation constraint to handle explicitly, not evidence of label contamination.

The old values 34 and 664 count conflicting groups confined to one file versus spanning multiple files. They are not mutually exclusive counts of all within-file and across-file label conflicts. A spanning group may also contain a within-file contradiction. The corrected audit measures the overlap.

Do not automatically delete the 7,020 rows before the primary evaluation. Doing so selects evaluation cases using their labels and changes the problem being measured. The revised proposal preserves source rows and labels and separates row identity from conservative grouping.

There is also no basis for the old claim that the remaining data have verified ground truth. Removing full-raw-fingerprint collisions would not even establish label consistency for the smaller canonical model feature representation.

## Resource and reporting corrections

The archived 543.20 MB value was the process RSS at completion, **not a measured peak**. The old claims of a necessary 8–16 GB of free RAM and inevitable immediate out-of-memory failure were not measured.

Version 3 reports a sampled RSS maximum, sample interval, scope and end RSS. If process information is unavailable, it reports that explicitly. It does not import TensorFlow just to read its installed version.

Raw-dataset prevalence is not measured prevalence on the deployed IoT network. Any proposed reweighting must identify its source-population estimand and assumptions.

## Status of the evidence files

Original log messages and numerical observations in `audit_summary.json` remain available, with a `review_corrections` annotation identifying unreliable fields. Missing-cell nonstandard JSON constants in the historical example JSONL have been normalized to JSON null; source references, labels and observed nonmissing values are unchanged.

For executable fixes, verification and the new laptop command, see [AUDIT_CORRECTIONS.md](../../../AUDIT_CORRECTIONS.md). For the proposed future training protocol, see [SAMPLING_AND_IDENTITY_PROPOSAL.md](SAMPLING_AND_IDENTITY_PROPOSAL.md).
