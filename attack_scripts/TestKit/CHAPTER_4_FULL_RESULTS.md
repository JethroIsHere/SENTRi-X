# Chapter 4 Hardware Trial Observations — Evidence Review Pending

**Report generated:** 2026-10-10 17:21:08 UTC (not the trial execution date)

Candidate counts are recorded observations, not confirmed detections, false positives, true negatives, or misses. No detector superiority or accuracy is established by this table. Detection latency remains unavailable until scope, ground truth, exposure, and timing are reviewed.

`pending_review` means the run completed with exit code 0 but is unscored. `inconclusive` means execution or trial checks require investigation; exit code 3 can reflect incomplete actions, unexpected responses, or observer issues. Failed preflight is not a missed attack. An empty alert log is not proof of a clean baseline.

## 1. Recorded trials

| Trial ID | Domain | Engine | Case | Status | Exit code | Candidate count | Review state | Duration (s) |
|---|---|---|---|---|---|---|---|---|
| `CH4-OMNI-RF-B0-9257` | omni | rf | B0 | completed | 3 | 34 | inconclusive | 182.0 |
| `CH4-OMNI-RF-S1-9444` | omni | rf | S1 | completed | 3 | 49 | inconclusive | 181.9 |
| `CH4-OMNI-RF-S2-9631` | omni | rf | S2 | completed | 3 | 34 | inconclusive | 183.0 |
| `CH4-OMNI-CNN-B0-9819` | omni | cnn | B0 | completed | 3 | 33 | inconclusive | 181.9 |
| `CH4-OMNI-CNN-S1-0006` | omni | cnn | S1 | completed | 3 | 52 | inconclusive | 181.9 |
| `CH4-OMNI-CNN-S2-0193` | omni | cnn | S2 | completed | 3 | 32 | inconclusive | 182.1 |
| `CH4-OMNI-HYBRID-B0-0380` | omni | hybrid | B0 | completed | 3 | 31 | inconclusive | 182.2 |
| `CH4-OMNI-HYBRID-S1-0568` | omni | hybrid | S1 | completed | 3 | 51 | inconclusive | 182.4 |
| `CH4-OMNI-HYBRID-S2-0755` | omni | hybrid | S2 | preflight_failed | 2 | — | inconclusive | 4.5 |
| `CH4-TON_IOT-RF-B0-0779` | ton_iot | rf | B0 | completed | 3 | 29 | inconclusive | 182.9 |
| `CH4-TON_IOT-RF-S1-0967` | ton_iot | rf | S1 | completed | 3 | 50 | inconclusive | 182.5 |
| `CH4-TON_IOT-RF-S2-1155` | ton_iot | rf | S2 | completed | 3 | 32 | inconclusive | 182.2 |
| `CH4-TON_IOT-CNN-B0-1342` | ton_iot | cnn | B0 | completed | 3 | 24 | inconclusive | 182.1 |
| `CH4-TON_IOT-CNN-S1-1529` | ton_iot | cnn | S1 | preflight_failed | 2 | — | inconclusive | 2.7 |
| `CH4-TON_IOT-CNN-S2-1537` | ton_iot | cnn | S2 | completed | 3 | 26 | inconclusive | 182.0 |
| `CH4-TON_IOT-HYBRID-B0-1724` | ton_iot | hybrid | B0 | completed | 3 | 30 | inconclusive | 182.2 |
| `CH4-TON_IOT-HYBRID-S1-1911` | ton_iot | hybrid | S1 | completed | 3 | 44 | inconclusive | 182.5 |
| `CH4-TON_IOT-HYBRID-S2-2099` | ton_iot | hybrid | S2 | completed | 3 | 28 | inconclusive | 182.0 |
| `CH4-BOT_IOT-RF-B0-2294` | bot_iot | rf | B0 | completed | 3 | 25 | inconclusive | 182.1 |
| `CH4-BOT_IOT-RF-S1-2481` | bot_iot | rf | S1 | completed | 3 | 43 | inconclusive | 182.5 |
| `CH4-BOT_IOT-RF-S2-2669` | bot_iot | rf | S2 | completed | 3 | 27 | inconclusive | 182.4 |
| `CH4-BOT_IOT-CNN-B0-2856` | bot_iot | cnn | B0 | completed | 3 | 0 | inconclusive | 182.8 |
| `CH4-BOT_IOT-CNN-S1-3044` | bot_iot | cnn | S1 | completed | 3 | 0 | inconclusive | 182.6 |
| `CH4-BOT_IOT-CNN-S2-3231` | bot_iot | cnn | S2 | completed | 0 | 0 | pending_review | 182.2 |
| `CH4-BOT_IOT-HYBRID-B0-3419` | bot_iot | hybrid | B0 | completed | 3 | 0 | inconclusive | 182.3 |
| `CH4-BOT_IOT-HYBRID-S1-3606` | bot_iot | hybrid | S1 | completed | 3 | 0 | inconclusive | 183.2 |
| `CH4-BOT_IOT-HYBRID-S2-3794` | bot_iot | hybrid | S2 | completed | 0 | 0 | pending_review | 182.3 |
| `CH4-CIC_IDS2017-RF-B0-3991` | cic_ids2017 | rf | B0 | completed | 0 | 0 | pending_review | 182.7 |
| `CH4-CIC_IDS2017-RF-S1-4178` | cic_ids2017 | rf | S1 | completed | 3 | 0 | inconclusive | 182.4 |
| `CH4-CIC_IDS2017-RF-S2-4366` | cic_ids2017 | rf | S2 | completed | 0 | 0 | pending_review | 182.1 |
| `CH4-CIC_IDS2017-CNN-B0-4553` | cic_ids2017 | cnn | B0 | completed | 3 | 26 | inconclusive | 181.9 |
| `CH4-CIC_IDS2017-CNN-S1-4740` | cic_ids2017 | cnn | S1 | completed | 3 | 44 | inconclusive | 182.0 |
| `CH4-CIC_IDS2017-CNN-S2-4927` | cic_ids2017 | cnn | S2 | completed | 3 | 27 | inconclusive | 182.1 |
| `CH4-CIC_IDS2017-HYBRID-B0-5114` | cic_ids2017 | hybrid | B0 | completed | 3 | 4 | inconclusive | 182.3 |
| `CH4-CIC_IDS2017-HYBRID-S1-5302` | cic_ids2017 | hybrid | S1 | completed | 3 | 37 | inconclusive | 182.2 |
| `CH4-CIC_IDS2017-HYBRID-S2-5489` | cic_ids2017 | hybrid | S2 | completed | 3 | 4 | inconclusive | 182.0 |
| `CH4-SNORT-B0-5676` | snort | snort | B0 | completed | 0 | 0 | pending_review | 181.5 |
| `CH4-SNORT-S1-5862` | snort | snort | S1 | completed | 3 | 0 | inconclusive | 181.6 |
| `CH4-SNORT-S2-6049` | snort | snort | S2 | completed | 0 | 0 | pending_review | 181.6 |
| `CH4-RERUN-OMNI-HYBRID-S2` | omni | hybrid | S2 | completed | 0 | 32 | pending_review | 182.0 |
| `CH4-RERUN-TON-CNN-S1` | ton_iot | cnn | S1 | completed | 0 | 44 | pending_review | 182.0 |
| `CH4-RERUN-OMNI-HYBRID-B0` | omni | hybrid | B0 | completed | 0 | 15 | pending_review | 182.0 |
| `CH4-RERUN-OMNI-HYBRID-S1` | omni | hybrid | S1 | completed | 0 | 51 | pending_review | 182.0 |

## 2. Snort and OMNI Hybrid observations

Counts below are derived from the recorded rows. Repeats are retained separately. Matched traffic exposure, enabled Snort rules, capture/log continuity, and identical baseline variants must be verified before comparing detectors.

| Case | Workload | Snort | OMNI Hybrid |
|---|---|---|---|
| B0 | Baseline observation (verify passive/synthetic variant in trial configuration) | 0 candidates (pending_review; `CH4-SNORT-B0-5676`) | 31 candidates (inconclusive; `CH4-OMNI-HYBRID-B0-0380`) / 15 candidates (pending_review; `CH4-RERUN-OMNI-HYBRID-B0`) |
| S1 | TCP Port Scan (50 ports) | 0 candidates (inconclusive; `CH4-SNORT-S1-5862`) | 51 candidates (inconclusive; `CH4-OMNI-HYBRID-S1-0568`) / 51 candidates (pending_review; `CH4-RERUN-OMNI-HYBRID-S1`) |
| S2 | Credential Probing (20 attempts) | 0 candidates (pending_review; `CH4-SNORT-S2-6049`) | No valid observation (preflight_failed; `CH4-OMNI-HYBRID-S2-0755`) / 32 candidates (pending_review; `CH4-RERUN-OMNI-HYBRID-S2`) |

## 3. Observations by model domain and engine

| Domain | Engine | B0 candidates | S1 candidates | S2 candidates |
|---|---|---|---|---|
| bot_iot | cnn | 0 candidates (inconclusive; `CH4-BOT_IOT-CNN-B0-2856`) | 0 candidates (inconclusive; `CH4-BOT_IOT-CNN-S1-3044`) | 0 candidates (pending_review; `CH4-BOT_IOT-CNN-S2-3231`) |
| bot_iot | hybrid | 0 candidates (inconclusive; `CH4-BOT_IOT-HYBRID-B0-3419`) | 0 candidates (inconclusive; `CH4-BOT_IOT-HYBRID-S1-3606`) | 0 candidates (pending_review; `CH4-BOT_IOT-HYBRID-S2-3794`) |
| bot_iot | rf | 25 candidates (inconclusive; `CH4-BOT_IOT-RF-B0-2294`) | 43 candidates (inconclusive; `CH4-BOT_IOT-RF-S1-2481`) | 27 candidates (inconclusive; `CH4-BOT_IOT-RF-S2-2669`) |
| cic_ids2017 | cnn | 26 candidates (inconclusive; `CH4-CIC_IDS2017-CNN-B0-4553`) | 44 candidates (inconclusive; `CH4-CIC_IDS2017-CNN-S1-4740`) | 27 candidates (inconclusive; `CH4-CIC_IDS2017-CNN-S2-4927`) |
| cic_ids2017 | hybrid | 4 candidates (inconclusive; `CH4-CIC_IDS2017-HYBRID-B0-5114`) | 37 candidates (inconclusive; `CH4-CIC_IDS2017-HYBRID-S1-5302`) | 4 candidates (inconclusive; `CH4-CIC_IDS2017-HYBRID-S2-5489`) |
| cic_ids2017 | rf | 0 candidates (pending_review; `CH4-CIC_IDS2017-RF-B0-3991`) | 0 candidates (inconclusive; `CH4-CIC_IDS2017-RF-S1-4178`) | 0 candidates (pending_review; `CH4-CIC_IDS2017-RF-S2-4366`) |
| omni | cnn | 33 candidates (inconclusive; `CH4-OMNI-CNN-B0-9819`) | 52 candidates (inconclusive; `CH4-OMNI-CNN-S1-0006`) | 32 candidates (inconclusive; `CH4-OMNI-CNN-S2-0193`) |
| omni | hybrid | 31 candidates (inconclusive; `CH4-OMNI-HYBRID-B0-0380`) / 15 candidates (pending_review; `CH4-RERUN-OMNI-HYBRID-B0`) | 51 candidates (inconclusive; `CH4-OMNI-HYBRID-S1-0568`) / 51 candidates (pending_review; `CH4-RERUN-OMNI-HYBRID-S1`) | No valid observation (preflight_failed; `CH4-OMNI-HYBRID-S2-0755`) / 32 candidates (pending_review; `CH4-RERUN-OMNI-HYBRID-S2`) |
| omni | rf | 34 candidates (inconclusive; `CH4-OMNI-RF-B0-9257`) | 49 candidates (inconclusive; `CH4-OMNI-RF-S1-9444`) | 34 candidates (inconclusive; `CH4-OMNI-RF-S2-9631`) |
| ton_iot | cnn | 24 candidates (inconclusive; `CH4-TON_IOT-CNN-B0-1342`) | No valid observation (preflight_failed; `CH4-TON_IOT-CNN-S1-1529`) / 44 candidates (pending_review; `CH4-RERUN-TON-CNN-S1`) | 26 candidates (inconclusive; `CH4-TON_IOT-CNN-S2-1537`) |
| ton_iot | hybrid | 30 candidates (inconclusive; `CH4-TON_IOT-HYBRID-B0-1724`) | 44 candidates (inconclusive; `CH4-TON_IOT-HYBRID-S1-1911`) | 28 candidates (inconclusive; `CH4-TON_IOT-HYBRID-S2-2099`) |
| ton_iot | rf | 29 candidates (inconclusive; `CH4-TON_IOT-RF-B0-0779`) | 50 candidates (inconclusive; `CH4-TON_IOT-RF-S1-0967`) | 32 candidates (inconclusive; `CH4-TON_IOT-RF-S2-1155`) |

## 4. Evidence required for scoring

1. Preserve each trial's summary.json, events.jsonl, frozen configuration, observer logs, and independent packet capture or target service logs. These bundles are not included in the committed matrix CSV.
2. Complete each trial's review.csv: validity, independently established ground truth, relevant_alarm, eligible_alert_ids, reference_evidence, reviewer, and timing fields. Correlate endpoints, ports, flow IDs, scoring windows, and preflight/background traffic.
3. Investigate nonzero exit codes and observer continuity issues. Keep invalid trials separate from scored negatives and document every repeat rather than silently replacing rows.
4. Verify passive versus synthetic B0 from saved configurations; the existing CSV does not encode this distinction. Review benign exposure before counting false positives.
5. Verify Snort version, configuration, enabled rule set, capture interface, packet counters, and log output. Zero logged candidates alone cannot establish a missed attack.
6. Compute latency only for independently eligible alerts with a reviewed attack start and clock/polling uncertainty. Candidate delay and whole-run duration are not detection latency.

Prior detection labels in the CSV are retained only in legacy_detection_outcome for auditability. They are withdrawn as scored results. Historical narrative claims about cloud traffic, preflight attribution, and confirmed attack efficacy require the original evidence bundles.
