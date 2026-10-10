# SENTRi-X lab test kit — start here

Version 1.0.0 · Prepared 30 September 2026 (UTC+8)

This kit generates real, bounded lab traffic and records evidence for your thesis. It does not call SENTRi-X's disabled simulation endpoint. It can observe RF, CNN, Hybrid, or Snort alerts without changing their settings.

**Use it for setup and pilot runs now. Complete the training/inference and sensor feature corrections before collecting final thesis measurements.** Successful transmission to the dashboard is already established by your logs; matching the model's training features is still a separate requirement.

## What is included

| File | Purpose |
| --- | --- |
| `run_trial.py` | Runs B0 normal logins, S1 TCP connect scanning, or S2 repeated failed logins; observes one selected engine |
| `lab_target.py` | Disposable HTTP login service with independent request logs |
| `config.example.json` | Physical lab settings to copy and edit |
| `config.smoke.json` | Short loopback checks that never count as physical evaluation |
| `sample_resources.py` | Optional CPU/memory recording on each measured host |
| `README.md` | Full procedure, Snort setup, evidence review, and interpretation |
| `SENSOR_INTEGRATION.md` | Exact findings from your supplied Pi code and instructions for Claude |
| `TEST_REPORT.md` | What was tested before delivery and what remains to verify in your lab |

Keep the whole folder together. The Python files import code from `sentrix_lab/`.

## 1. Check the kit locally

Extract the ZIP. Open two terminals in the extracted folder. The core scripts use Python's standard library; they do not need Scapy or administrator privileges. Python 3.9+ is intended; the delivered tests were run on Python 3.12.

On Windows PowerShell, replace `python3` with `py -3` in the commands below. WSL/Linux can use them as written.

Terminal 1:

```bash
python3 lab_target.py --bind 127.0.0.1 --port 8088 --log target_evidence/smoke.jsonl
```

Terminal 2, one command at a time:

```bash
python3 run_trial.py --config config.smoke.json --case B0 --engine none --trial-id SMOKE-B0-001 --smoke --execute
python3 run_trial.py --config config.smoke.json --case S1 --engine none --trial-id SMOKE-S1-001 --smoke --execute
python3 run_trial.py --config config.smoke.json --case S2 --engine none --trial-id SMOKE-S2-001 --smoke --execute
```

Each check takes about three seconds and writes to `evidence/TRIAL_ID/`. Use new IDs when repeating. These checks verify the scripts locally; they do not measure SENTRi-X, Snort, the Pi, or SPAN capture. Stop Terminal 1 with Ctrl+C afterward.

## 2. Choose a real lab target

Use a separate lab computer with Python, or a VM whose traffic you have confirmed crosses the monitored physical network. Run the disposable service there. Do not substitute the bulb or temperature sensor's IP: they do not run this service.

Record the target's actual IPv4 address and the Ethernet MAC visible in the Pi's mirrored capture. The target and generator should be on the same lab LAN, with traffic passing through the switch/AP port being mirrored. Same-laptop loopback and internal VM traffic often never reach that mirror.

Run on the target, replacing the placeholder with its actual private LAN address:

```text
python3 lab_target.py --bind LAB_TARGET_IPV4 --port 8088 --log target_evidence/service.jsonl
```

Allow the service port on that lab host if its firewall blocks it. Keep the service running during the trials. It uses public dummy credentials; use it only as a disposable test service.

## 3. Update the Pi's capture list

Your supplied sensor currently accepts only the bulb and temperature sensor MACs. A test computer will be ignored until you add its actual observed MAC to `IOT_DEVICES` in `~/sentrix_sensor.py`.

Read `SENSOR_INTEGRATION.md` before editing. Add the **target** MAC with the name `lab_target`; leave the traffic generator out of the monitored list. Restart the sensor after the edit and verify the target's flows appear. Identify the new device as a lab endpoint in your records, not a physical IoT device.

The uploaded Markdown contains escaped characters, code fences, and missing indentation. Do not paste that Markdown directly over your working Python file. Make changes to the working `.py` file, keeping a backup.

## 4. Configure the generator

Make a copy of `config.example.json` named `lab_config.json`. Edit it in your IDE:

| Setting | What to enter |
| --- | --- |
| `target_ip` | Actual private IPv4 of the disposable target |
| `target_mac` | Actual target MAC observed at the capture point |
| `configuration_id` | Your frozen build/model/ruleset record ID; replace the `SET_...` placeholder |
| `backend_url` | Currently `http://192.168.254.156:8000`, if still correct |
| `model_domain` | The selected domain: `omni`, `ton_iot`, `bot_iot`, or `cic_ids2017` |
| `expected_alert_threshold` | The persisted dashboard alert threshold; example is `0.87` |
| `snort_json_file` | Actual live Snort 3 JSON log path, when testing Snort |

Keep the timing, rate, counts, ports, and thresholds fixed across comparison runs. The defaults implement the proposed draft procedure: 60 seconds warm-up, 120 seconds observation, actions within the first 30 seconds, one action per second.

## 5. Run an unscored physical pilot

Start independent packet capture at the mirror and preserve the target service log. Select the model domain and **Hybrid** in your existing dashboard, enable alerting, and confirm the Pi is connected.

First print the plan; this sends no requests:

```bash
python3 run_trial.py --config lab_config.json --case S1 --engine hybrid --trial-id PILOT-S1-HYB-001 --pilot
```

Then run it:

```bash
python3 run_trial.py --config lab_config.json --case S1 --engine hybrid --trial-id PILOT-S1-HYB-001 --pilot --execute
```

Allow the full three-minute warm-up/observation sequence to finish. Inspect the evidence, Pi counters, independent capture, and target log. Zero alerts can be a real result; it is not automatically a broken script.

Repeat B0 and S2 with different Trial IDs. Select RF or CNN in the dashboard before using `--engine rf` or `--engine cnn`. For Snort, follow the logging and capture instructions in `README.md` first, then use `--engine snort`.

## 6. Move to final evaluation only after the pilot is valid

Finish feature parity and model retraining, freeze the tested build and protocol, and confirm capture/observer continuity. Then run the approved matrix with new IDs, omitting `--pilot`. The software still calls these `physical_trial_candidate` runs until the evidence is reviewed.

S1 tests TCP connect scanning. S2 tests a limited pattern of failed authentication to a lab service; it does not demonstrate password compromise or automatic recognition of wrong passwords by your current sensor. Keep misses and false alarms in the results.
