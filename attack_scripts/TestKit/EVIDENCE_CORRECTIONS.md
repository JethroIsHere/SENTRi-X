# Hardware evaluation corrections

The matrix records 43 trial observations. It does not establish scored attack detection,
false-positive rates, misses, or superiority over Snort. Candidate counts, execution details,
and prior labels are preserved in `chapter_4_matrix_results.csv`; prior scores are retained
only in `legacy_detection_outcome` for audit history.

`pending_review` means execution completed with exit code 0 and still needs independent
review. `inconclusive` means execution or trial checks need investigation. Exit code 3
can indicate observer issues, incomplete actions, or unexpected target responses.

To rebuild the tables without running network trials, from this directory:

```bash
python run_chapter4_matrix.py --report-only chapter_4_matrix_results.csv
```

Before scoring Chapter 4, inspect each original `evidence/<trial_id>/` bundle and its
`review.csv`. Preserve independent PCAP or target service logs. Establish valid exposure,
ground truth, eligible alert IDs, endpoints/ports, attack start, scoring window, clock
uncertainty, and the reviewer. Investigate preflight/background traffic and observer issues.
Verify Snort capture and enabled rules separately. Keep passive and synthetic B0 variants
separate, and retain original and repeated trials with their IDs.

If the original bundles support a valid trial, review them before deciding to repeat it.
If they are missing or exposure/recording cannot be verified, that trial remains unscored
and needs a documented replacement. Detector latency cannot be derived from run duration
or unreviewed candidate delay. The report intentionally does not ingest manual scores.

RF/CNN predictions remain binary. Dashboard heuristic labels describe individual flow
patterns, such as rejected connections or high packet rate; they do not verify scanning,
password guessing, or DoS. Missing SNI is not treated as suspicious because the sensor
does not collect it. SHAP/LIME explain the RF component, not the CNN or fused hybrid output.
Stored legacy alerts retain their original content and are labelled as requiring review.

After applying the code, restart the backend and rebuild the frontend. New alerts use
the corrected assessments. No retraining is required for these reporting changes.
