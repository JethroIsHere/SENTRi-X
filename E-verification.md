# Appendix E — Implementation and evidence verification

| Component | Recorded implementation or evidence source |
| --- | --- |
| Sensing node | Raspberry Pi 3 Model B+; eth0; managed-switch SPAN; edge/sentrix_sensor.py |
| Flow buffering | 5-second idle and 30-second maximum flow windows; 4,096 active flows; 1,000 pending flows |
| Central processing | Ubuntu 22.04 / WSL 2 host; FastAPI; CPU inference; SQLite persistence; React dashboard |
| Candidate packages | models/candidates/ton_iot_v2, bot_iot_v2, cic_ids2017_v2, and omni_v2 |
| Model evaluation | evaluation_metrics.json for each package; RF, CNN, and equal-weight Hybrid; binary p(Attack) boundary 0.50 |
| Operational explanations | Current-flow RF TreeSHAP when available and local RF LIME; method, target, and fallback provenance; no CNN or full-Hybrid explanation |
| Lab evidence | chapter_4_matrix_results.csv; original configuration, summary, events, observer logs, and independent PCAP or target-service evidence required for scoring |

## Package verification

Record the model artifact versions, split manifests, preprocessing provenance, ordered features and scaler, runtime dependencies, active detector, and alert settings before comparing packages.

## Trial review

Record independent ground truth, the eligible capture interval, relevant alarms, clock uncertainty, and detector coverage. Use an independently reviewed event and relevant alarm before reporting detection or latency. Count host and Pi resource use separately.

The public supplement contains no packet captures, device identifiers, credentials, or site-specific logs.
