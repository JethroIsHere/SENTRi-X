# SENTRi-X controlled lab evaluation kit

Version 1.0.0 · Start with `START_HERE.md` for the commands.

## Purpose and scope

Generate repeatable traffic against one disposable lab service, observe detector output, and retain evidence for review. The kit evaluates defined scenarios; it cannot establish that a system is universally accurate or that one model is better before measurements exist.

| Case | Default workload | Independent evidence | What it evaluates |
| --- | --- | --- | --- |
| B0 | 10 successful HTTP Basic logins, 1 per second | Target logs show authentication success; responses are HTTP 200 | A controlled benign workload for false-alarm assessment |
| S1 | TCP connections to 50 explicit ports at 2/sec, with banner grab on open ports | Mirrored PCAP shows attempts to the configured ports | Bounded TCP connect scanning with service fingerprinting |
| S2 | 20 failed HTTP Basic logins at 2/sec, cycling through 5 dummy wrong passwords | Target logs show authentication failure; responses are HTTP 401 | A credential-probing pattern on a lab endpoint |

S1 uses ordinary TCP connections, not a SYN flood. On open ports it reads up to 512 bytes to capture the service banner (standard scanner behavior). Closed ports may refuse the connection. A timeout alone does not establish whether the packet reached the target or mirror.

S2 cycles through 5 obviously-fake dummy passwords against the disposable lab service only — it performs no credential discovery against real systems and does not log into a real device. Describe it as **credential probing**, or as a limited behavioral proxy if the adviser accepts that terminology. The current Pi sensor reports HTTP status/body features as zero and exports each TCP connection as a separate flow. It has no cross-flow failed-login counter. Therefore this case may reveal a detection limitation. A positive result still requires ruling out incidental service or packet-size differences; it does not prove that the model understands authentication failures.

B0 is one benign service workload. Supplement it with the protocol's normal IoT activity windows before generalizing false-positive performance to the bulb and temperature sensor. The kit does not generate DoS, exploitation, compromise, persistence, or arbitrary third-party traffic.

## Requirements and topology

- Python 3.9+ on the traffic generator and disposable target; tested here on Python 3.12/Linux.
- One private IPv4 target running `lab_target.py`; the runner verifies that service before every case.
- A verified path from generator to target through the monitored network. Pi `eth0` receives the SPAN copy; the Pi's management/API connection remains separate as in your existing setup.
- The target's MAC added to the Pi filter. Verify the actual MAC visible at the mirror, especially with APs, VLANs, routing, or virtualization. A heartbeat only confirms connectivity to the backend.
- An independently recorded PCAP at the monitored point and the target's service log. Preserve capture-drop statistics, Pi drop/unconfirmed counters, and backend errors.
- For SENTRi-X: a running live-only backend with the reviewed API v2 contract. Its `execution_mode`, model domain, Pi liveness, loaded models, and persisted alert settings must match the configuration.
- For Snort: Snort 3 already configured with the chosen ruleset and a capture interface that sees the trial traffic, plus a live local/readable `alert_json` file.

The Snort file observer runs in the same process/host as the traffic generator so trial start and observation use one monotonic clock. If Snort runs elsewhere, its log must be continuously available to that host during the trial, and the transport/buffering delay must be documented. Copying a completed log afterward cannot measure live alert latency. Alternatively arrange the generator and Snort on a host with the appropriate capture access. Verify packet exposure independently for both systems; the kit does not configure mirrors, adapters, Snort rules, or remote log transport.

WSL can use a NATed source address. The target health response records the client IP it actually sees; alert matching uses that address. Preserve both the generator's local address/port and the target's view. NAT may also change source ports, so use PCAP/target evidence when resolving exact flows.

## Configuration and fixed conditions

Copy `config.example.json` to `lab_config.json` and replace the placeholders. Target address, MAC and build ID are mandatory. Only one RFC1918 IPv4 target is accepted; hostnames, address ranges and public targets are rejected. The explicit `--smoke` option permits only `127.0.0.1` and marks the output as a local software check.

`configuration_id` is a reference to your experimental configuration record, not automatic proof of its contents. Record the repository commit, sensor source/hash, RF/CNN/scaler/feature-schema hashes, selected dataset domain, fusion rule, thresholds, Snort version/rules/hash, capture locations, topology, device identities, and resource scopes there. The runner hashes its own Python files and saves the effective configuration. It cannot attest to remote model or ruleset files.

Default procedure:

1. Verify target and observer. The health request occurs before warm-up.
2. Observe for 60 seconds of warm-up, excluding its alerts from the scored interval.
3. Start a 120-second observation interval. Its start is the kit's `t0`.
4. Begin workload actions immediately; all must begin within the first 30 seconds.
5. Continue observation through the full interval. With this sensor's 5-second idle and 30-second maximum-age windows, the remaining time accommodates normal expiry/delivery delays; it does not guarantee that an overloaded queue will drain.

The maximum action count is bounded, the minimum spacing is 0.5 seconds, and the default spacing is 1 second. Late schedules do not send catch-up bursts. Socket operations have timeouts; the runner records actual starts and outcomes, including incomplete workloads.

Freeze these parameters before scored comparisons. The previously proposed 60-run matrix means 3 cases × 4 engines × 5 repetitions **for one model domain**. It is a draft, not an approved sample-size calculation. If your study compares multiple dataset domains, define that additional factor and the Snort comparison policy before collecting the final set. Balance/randomize run order and preserve failed attempts with reasons. Do not repeatedly adjust the traffic or thresholds until the preferred model wins.

Run only one workload at a time on the chosen path. Wait for pending Pi flows to settle between runs; preserve normal background activity under consistent conditions. Do not clear evidence or reset the backend during a trial. The runner reads APIs and does not switch modes, reset counters, inject simulated attacks, or modify your dashboard.

## SENTRi-X observation

Select the correct model domain and RF, CNN, or Hybrid mode in the dashboard before starting. Use a matching `--engine rf`, `--engine cnn`, or `--engine hybrid`. A mismatched status, missing model, disconnected Pi, disabled alerting, or different threshold causes preflight failure before scenario actions.

The adapter was checked against the source snapshot at commit `55eab4bb134db0f871d56a08c6f5b98b4f5862c3`. It expects:

- `GET /api/status`, with `api_version: 2`, live state, model/mode, settings, and counter epoch.
- `GET /api/threat-logs?source=live_hardware&limit=500`, returning `{"logs": [...]}` with stable alert IDs.

Existing alert IDs are excluded at baseline. New raw alerts and status samples are saved. A full 500-record response without overlap with the previous poll flags a possible gap. API failures and observed configuration/restart changes are recorded for review; they are not converted into a successful zero-alert result. Short changes between polls can still be missed, so freeze configuration throughout the run.

The reviewed backend stores alerts only when its classification and alert policy both allow them. A model's attack prediction and a saved dashboard alert are different measurements. This kit observes **saved live alerts**. Export the actual flow records/probabilities separately if evaluating classification metrics; do not infer all predictions from the alert log.

The alert response lacks TCP ports in the reviewed version. An IP-pair match is therefore only a candidate. Review its `flow_id` against the backend flow record and preserved PCAP before assigning it to the workload. Current ingested flow records persist ports and are available through `/api/flows?source=live_hardware&limit=500`; preserve the relevant rows or database export before the latest-500 window moves past them. The kit does not automatically archive that flow endpoint. Direction can be reversed because the sensor makes the monitored endpoint `src_ip`.

## Snort 3 logging

Keep your chosen Snort ruleset and configuration fixed. This kit adds no detection rules and does not guarantee that the selected rules recognize these low-rate scenarios. Record whether the baseline is stock or custom; treat later rule tuning as a separate experimental configuration.

The official Snort 3 logger supports `alert_json` with endpoint and rule fields. Configure it to write a file. The following is a **command template**; replace the configuration path and interface with your verified values:

```text
snort -q -c /absolute/path/to/your/snort.lua -i CAPTURE_INTERFACE -A alert_json -l /absolute/path/to/snort_logs --lua "alert_json = {file = true, fields = 'timestamp pkt_num proto src_ap dst_ap rule action msg class'}"
```

Create the selected output directory first and use the capture privileges required by your installation. The JSON logger writes `alert_json.txt`. Set `snort_json_file` to its actual path as visible to the runner. Relative paths resolve from the configuration file's directory. Snort 2 text/fast logs are not accepted by this adapter.

Confirm the Snort process is running, its rules loaded, the capture interface sees the trial packets, and its logger is writing the configured file. A readable empty file does not prove any of those facts. Complete this setup check before a scored run. Retain the startup/configuration and capture statistics separately.

Example pilot after setup:

```bash
python3 run_trial.py --config lab_config.json --case S1 --engine snort --trial-id PILOT-S1-SNORT-001 --pilot --execute
```

The observer starts at the existing file's end, reads only new complete JSON lines, and saves each raw record. It flags malformed records, truncation, rotation, or an incomplete final line. The rule ID and message remain intact for eligibility review.

Reference: [Snort 3 Rule Writing Guide: alert logging](https://docs.snort.org/start/alert_logging).

## Evidence and scoring

Every execution gets a new `evidence/TRIAL_ID/` folder. Existing Trial IDs cannot be overwritten.

| Output | Contents |
| --- | --- |
| `manifest.json` | Trial/case/engine, pilot or candidate designation, configuration and script hashes, host/runtime, external evidence references |
| `events.jsonl` | Preflight, warm-up/scoring boundaries, actual action starts/results, raw alerts, observer polls, status samples and errors |
| `summary.json` | Run completion, workload counts, candidate alerts, observation issues; classification accuracy and confirmed results remain null |
| `review.csv` | One row for your reviewer to complete and transfer into the evaluation workbook |
| Target `service.jsonl` | Independent received requests, authentication outcomes and response attempts; public dummy passwords are not logged |

Add references when running, for example `--reference-evidence mirror/S1-001.pcap --reference-evidence target/service.jsonl`. The runner stores these references but does not create, copy, or verify those files. Transfer and preserve the real files with the trial evidence afterward.

Before scoring, review:

1. Was the prescribed workload delivered, and was it visible at the monitored point? S1 requires packet evidence because most scanned ports have no application log. For B0/S2, correlate request IDs and TCP endpoints with the target log and PCAP.
2. Was the configured detector operating with the frozen artifacts/rules and an intact observer? Record generator/preflight/observer problems separately from detector misses.
3. Does each candidate alert belong to this trial and meet the **prespecified** relevance policy? Retain unrelated alerts and policy warnings, but do not relabel or exclude them selectively after seeing results. Apply the same agreed outcome definition consistently.
4. Was the alarm first observed within the interval? Alerts outside the interval stay in raw evidence where observed and are not silently moved into it. Review alerts whose poll crossed `t0` for pre-existing activity.
5. Record validity, ground truth, binary relevant alarm, eligible alert IDs, evidence references, reviewer and notes in `review.csv` and your workbook.

For a verified attack window, a relevant alarm gives a trial-level TP and no alarm gives FN. For a verified benign window, an alarm gives FP and no alarm gives TN. Keep the raw eligible alert count separately; five alerts from one trial do not make five successful trials. Pipeline drops or missed capture inside the system under evaluation may be legitimate end-to-end failures when independent evidence confirms exposure. Do not discard such runs merely because detection failed. A failed generator, missing independent exposure evidence, or broken measurement instrument requires an explicit validity decision, not an automatic TN/FN.

Derive recall, precision, false-positive rate and accuracy from the reviewed trial-level confusion matrix with the correct denominators. Undefined denominators remain unavailable. These are scenario-window measures, not packet- or flow-classification accuracy. Preserve held-out dataset evaluation separately.

### Timing

The kit's `t0` is the local monotonic scoring-window start immediately before scheduling actions. Actual action starts are also logged. A first-packet or first-service-request definition of `t0` would require a documented protocol change and aligned evidence clocks; do not mix definitions.

Both alert adapters record when an alert becomes available to the observer. For Snort, the raw `timestamp` is a packet timestamp; it is not used as alert-availability time. After eligibility review, observer latency is first eligible alert observation minus `t0`. No detected alert means latency is **blank**, not zero and not the full window duration.

The default poll interval is 0.5 seconds, with additional request, scheduling, file buffering or remote-log delays. Report these limitations; a polling result is not exact model inference time. Candidate delays in JSON are unscored until reviewed. Use the recorded monotonic difference on the observer host; check its recorded wall-clock drift when correlating other hosts' UTC evidence. Synchronize and record clock offsets for cross-host PCAP/service/resource evidence.

## Optional resource recording

Install only if using `sample_resources.py`:

```bash
python3 -m pip install -r requirements-optional.txt
```

Run a separate recorder on the Pi, backend host, and Snort host as required. Find the actual process PID in that host's process list; replace `ACTUAL_PID` below. Start recording before the trial and allow enough time to include its entire warm-up and observation interval:

```text
python3 sample_resources.py --scope pi_sensor --pid ACTUAL_PID --duration 240 --interval 1 --output resource_evidence/TRIAL_ID-pi.jsonl
python3 sample_resources.py --scope backend --pid ACTUAL_PID --duration 240 --interval 1 --output resource_evidence/TRIAL_ID-backend.jsonl
python3 sample_resources.py --scope snort --pid ACTUAL_PID --duration 240 --interval 1 --output resource_evidence/TRIAL_ID-snort.jsonl
```

These are separate commands on the respective hosts, not three commands with the same PID. Use appropriate permissions to inspect the process. The recorder does not automatically include child/worker processes; explicitly account for all required processes and shared-memory double counting in your measurement method. Avoid development auto-reload during evaluation.

Process CPU uses a one-core-equals-100% basis and may exceed 100% for multiple cores. Process memory is RSS in bytes, with MiB also recorded. Omit `--pid` only when intentionally measuring the entire host; that uses host CPU percent and host used-memory bytes. A WSL host measurement describes the WSL environment, not the physical Pi. The backend dashboard resource values likewise cannot substitute for Pi measurements.

The first CPU call only primes the measurement and is excluded. Errors remain errors, not zero usage. A summary sidecar covers the recorder's whole interval; select raw samples belonging to the scored interval before comparing trials. CPU samples average the preceding sampling interval, so account for samples that straddle boundaries. Ctrl+C preserves a partial summary marked interrupted.

Reference: [psutil CPU and process-memory documentation](https://psutil.readthedocs.io/stable/).

## Exit codes and troubleshooting

| Code | Meaning |
| --- | --- |
| 0 | Planned workload completed and no recorded observation issues; this does **not** mean the detector succeeded |
| 2 | Setup/preflight failure, interrupted run, or execution failure |
| 3 | Completed run needs attention: incomplete workload, wrong HTTP outcomes, or observer issues |

`sample_resources.py` uses 0 for measured samples without errors, 2 for setup issues, and 3 for incomplete/error/interrupted recording.

- **Target unavailable:** check its service, IP, port and firewall. HTTP preflight must reach the kit's companion service; an unrelated HTTP server is insufficient.
- **Pi connected but no target flows:** inspect the actual mirrored traffic and target MAC, then check the BPF allowlist. Do not infer packet visibility from heartbeat status.
- **Status mismatch:** select the matching mode/domain and saved alert threshold. Do not weaken checks to conceal a mismatch.
- **No alerts:** first confirm workload, exposure, detector health and observer continuity. If these are valid, retain a miss or correct benign result as appropriate.
- **500-row gap/API timeout/log rotation:** retain evidence and resolve continuity before treating zero observed alerts as zero generated alerts.
- **Trial ID already exists:** use a new ID. Do not erase the previous attempt to reuse it.

Run the supplied local tests with `python3 -m unittest discover -s tests -v`. They exercise the kit; their mock API/Snort records are explicitly synthetic test fixtures and must never enter the thesis results.
