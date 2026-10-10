# Pi integration and sensor review

Based on the sensor pasted into this conversation and the supplied `Pasted markdown(3).md`. The findings below describe that source, not a new inspection of the running Pi. The intended code can deliver accepted flows, as your earlier Pi logs already showed.

## File to edit

On the Pi, your running command is:

```bash
sudo python3 ~/sentrix_sensor.py
```

Therefore edit **`/home/raspy3/sentrix_sensor.py`** on that Pi. Editing a separate `edge_sensor.py` on the laptop does not update this running script unless you explicitly transfer and run it. The test-kit scripts belong on the generator/target hosts and do not replace the Pi sensor.

The uploaded Markdown is not directly runnable Python: it includes escaped `\#` and `\_`, Markdown links inside URL strings, code fences, and flattened indentation. This does not prove the actual Pi file has those problems; its earlier successful output suggests the working copy differs from the formatted upload. Preserve the working file and edit it in a plain-text code editor.

## Small setup edit for the lab target

Stop the foreground sensor with Ctrl+C and allow its shutdown to finish. Back up the file using a previously unused backup name, then open it:

```bash
cp -n ~/sentrix_sensor.py ~/sentrix_sensor.before-lab.py
nano ~/sentrix_sensor.py
```

If that backup name already exists, keep it and choose another unused name for a current backup.

The connection constants must contain plain URL strings:

```python
INTERFACE = "eth0"
BACKEND_URL = "http://192.168.254.156:8000/api/ingest-flow"
HEARTBEAT_URL = "http://192.168.254.156:8000/api/heartbeat"
```

Keep the two device entries and add the lab target's **actual MAC observed at the mirror**:

```python
IOT_DEVICES = {
    "20:f1:b2:68:cc:63": "smart_bulb",
    "e4:ae:e4:fb:91:a0": "temp_humidity_sensor",
    "REPLACE_WITH_ACTUAL_TARGET_MAC": "lab_target",
}
```

The placeholder must be replaced with six lowercase hexadecimal octets separated by colons before running. Do not add the generator MAC. In this implementation, if both endpoints are monitored, the source-MAC branch takes precedence and reverse-direction packets can become a second differently oriented flow. Keeping only the target monitored avoids that ambiguity for these tests.

In nano, save with Ctrl+O, Enter, and exit with Ctrl+X. Check syntax, then run:

```bash
python3 -m py_compile ~/sentrix_sensor.py
sudo python3 ~/sentrix_sensor.py
```

Compilation checks syntax only; it does not establish capture visibility, endpoint correctness or feature parity. Verify all of these separately:

1. A real generator-to-target exchange appears in the mirror PCAP with the target's MAC.
2. The Pi's accepted flow log identifies `lab_target` with the expected endpoint pair.
3. The backend stores that flow with the correct device, ports, source and chosen model/mode.
4. B0/S2 request IDs and outcomes appear in the target service log.

The heartbeat means the backend acknowledged the sensor. `captured_packets` counts packets accepted by this sensor's monitored IPv4 TCP/UDP filter; it is not a count of all traffic on the network.

## Findings that affect final evaluation

| Area | Supplied implementation | Consequence / required decision |
| --- | --- | --- |
| Monitored scope | Only two MACs in `IOT_DEVICES`, also used in the capture filter | A new lab target is invisible until its actual observed MAC is included |
| Protocol scope | Requires Ethernet and IPv4; accepts TCP or UDP | No IPv6/ICMP coverage claim from this sensor |
| Direction | `src_*` always refers to the monitored device, regardless of who initiated the connection | Inbound scans/logins are oriented target-to-generator; reconcile with each training dataset's direction convention |
| Byte features | `src_bytes`/`dst_bytes` add `len(packet)` | These are captured frame lengths, not automatically equivalent to training payload-byte or transport-byte features |
| IP byte features | Adds `len(packet[IP])` | Verify padding, truncation and IP total-length behavior against the declared training definition |
| Duration | Differences between monotonic callback-processing times | Not packet-capture timestamps; load/scheduling can affect values |
| Segmentation | 5-second idle expiry, 30-second maximum age; checked every second | A long connection becomes multiple windows; training on complete connections is a different unit |
| TCP states | `SF` for traffic in both directions without checking FIN/termination; SYN/RST checks assume the IoT endpoint is initiator | State names alone do not establish Zeek-equivalent semantics; an inbound rejected scan can receive `RSTO` |
| Non-TCP state | The final state function also runs for UDP | TCP-looking state indicators can be emitted without a TCP handshake; define the intended non-TCP encoding |
| HTTP features | Request-body length, response-body length and status are always zero | No direct distinction between HTTP 200 and 401 reaches the model; S2 cannot prove recognition of failed passwords |
| Missed bytes | Always zero | Does not measure capture loss or TCP content gaps |
| DNS | Last observed question/class and response code are retained where available | Declare how multiple DNS transactions in one window are represented |
| Cross-flow behavior | Flow key uses addresses, protocol and ports; no cross-flow attempt counter | Repeated logins or multi-port scans may be split into individually ordinary-looking flows |
| Delivery | Bounded active/pending queues; unconfirmed sends are not replayed automatically | Preserve overflow, dropped and unconfirmed counts. An unconfirmed response may already have been processed |
| Correlation | No exported sensor flow-start/end capture timestamps or stable delivery ID in this payload | Backend receipt time is not original packet time; use independent capture and retain ports/flow IDs |

The intended payload contains the 28 numerical/one-hot model features plus device and endpoint metadata. Matching column count and order is necessary but insufficient: units, direction, windows and unavailable-field treatment must also agree.

For comparison, Zeek defines directional payload bytes separately from IP-layer bytes, and TCP `SF` includes normal establishment and termination. Its connection orientation follows originator/responder semantics. These references help audit Zeek-derived fields; each actual dataset mapping must still be checked rather than assuming all datasets use identical units.

Reference: [Zeek connection record definitions](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html).

## Addendum to give Claude in Antigravity

Copy the following instructions after the earlier training-pipeline task. This supplies the sensor information that was missing from that task.

> Integrate the current Pi sensor into the existing SENTRi-X feature-parity review. The deployed entry point is `/home/raspy3/sentrix_sensor.py`, capturing `eth0`, with the two verified IoT MACs and 5/30-second windows described above. Work from the real plain Python source; the uploaded Markdown lost indentation and contains escaped characters. Do not replace a working Pi file with formatted Markdown.
>
> First preserve the source and document the live feature contract: device-first direction, frame-byte counters, IP-byte counters, callback-time duration, window segmentation, simplified state logic, DNS fields, and zero HTTP/missed-byte fields. Keep device identity separate from any originator/responder orientation used for model features. Include behavior when both monitored endpoints communicate and when capture starts midstream.
>
> Compare every feature against each actual training mapping and deployed preprocessor. Resolve mismatches with a versioned extraction/training/inference contract. Do not silently redefine live values and reuse incompatible model/scaler files. If a feature cannot be measured, document its supported missing-value strategy consistently in training and inference; do not present an unavailable zero as an observed measurement. Keep the 28-feature assumption only if the final verified schema still uses it.
>
> Use small labeled packet fixtures to verify outbound and inbound TCP setup, rejection, reset, normal close, partial captures, UDP/DNS, and an HTTP 200/401 exchange. Compare computed features with an independent reference under the declared definitions. A SYN-only exchange, a reply in each direction, or an HTTP response must not be mislabeled as a richer state the extractor did not actually observe. Verify the precise windowing and byte definitions, not just payload shape.
>
> Preserve the existing live-only behavior, MAC filtering, bounded buffers, independent heartbeats, acknowledgement checks and visible delivery errors. For a lab pilot add only the disposable target's verified capture-side MAC, naming it `lab_target`; do not reclassify it as a physical IoT device. Keep a record of this configuration change.
>
> Preserve sensor/device metadata, protocol, ports, model/mode, inference errors and raw features needed to audit a trial. Consider explicit flow-window timestamps and stable IDs as a versioned contract change; automatic replay requires backend deduplication first. Do not hide queue losses or treat failed posts as confirmed delivery.
>
> Complete the earlier leakage, transformation, fusion and artifact-provenance corrections before final training and scored trials. If training source data cannot support the chosen live feature definitions, report the remaining limitation or implement an explicitly evaluated compatible approach. Do not claim feature parity from successful API calls alone.
>
> Deliver the source diff, feature-contract table, meaningful fixture results and exact Pi deployment steps. Keep pilot results separate from final evaluation. Do not modify thesis results or manufacture successful detections.

## What can proceed now

Local kit checks, network-path verification, target setup, sensor allowlist editing, observer setup, packet/service logging, and explicitly unscored pilots can proceed. Final claims about RF/CNN/Hybrid accuracy, comparative detection, or failed-login recognition need the corrected and frozen pipeline plus reviewed experimental evidence.
