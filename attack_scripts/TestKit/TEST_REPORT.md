# Delivery verification

Kit version: 1.0.0

Verified 29 September 2026 UTC / 30 September 2026 UTC+8.

Environment: isolated Linux workspace, Python 3.12.14. All network requests made during verification stayed on loopback (`127.0.0.1`). No traffic was sent to your Pi, LAN, public hosts, or GitHub deployment.

## Automated result

Command, from the kit folder:

```bash
python3 -m unittest discover -s tests -v
```

**17 tests passed in 12.570 seconds.** No tests were skipped in that run. The initial test run also passed; a test-only unclosed-file warning was then corrected before this final run.

| Area | Verified behavior |
| --- | --- |
| Configuration | Rejects public/invalid/range targets, non-string addresses, excessive rates/counts, duplicate ports, unknown fields, unsafe Trial IDs, and unchanged build-ID placeholders |
| Dry run | Performs no network requests and creates no trial evidence directory |
| Disposable service | Actual loopback HTTP requests return 200 for the correct dummy credential and 401 for the fixed wrong credential; independent service log records both outcomes |
| TCP scanner | Actual connection to a listening socket succeeds; a bound non-listening port is recorded as refused |
| Trial execution | All three cases complete their shortened local intervals with correct counts and spacing; results remain unscored |
| Evidence protection | Existing Trial IDs are rejected; preflight failures and SIGTERM interruptions preserve partial evidence |
| SENTRi-X adapter | Local fake API uses the reviewed response shape; prior alerts are excluded, new alerts are deduplicated, settings mismatches fail, a disjoint 500-row window raises a possible-gap issue |
| Runner + API observer | Full loopback runner observes a deliberately synthetic API fixture and preserves it as a candidate with no invented detection outcome or latency |
| Snort adapter | Fixture-file baseline exclusion, partial JSON-line completion, observation timing, rotation and malformed records are handled explicitly |
| Scope matching | Both endpoint directions are considered; missing ports remain explicitly ambiguous |
| Resource recorder | Test doubles verify CPU priming exclusion, units/means, error preservation and interrupted/null outcomes; missing optional dependency has a clear error |

## Limits of this verification

These are software tests of the kit. The fake API alert and Snort fixture records are not detector results and must not be added to your study's dataset or workbook.

Not executed here:

- Physical SPAN capture or traffic delivery on your LAN.
- Raspberry Pi capture, sensor feature extraction or hardware resource measurements.
- Your trained RF/CNN/Hybrid artifacts or the running SENTRi-X backend.
- A real Snort process, real detection rules, or its packet acquisition/logger buffering.
- Native Windows, WSL networking, or Python versions other than 3.12.
- Real `psutil` measurements; that optional dependency was absent in this workspace. Resource logic was tested with explicit test doubles, and the missing-dependency path was verified.
- Final 60/120-second physical trials, approved repetition counts, expert evaluation or thesis statistics.

The setup guide calls for separate on-site verification and pilot runs. `SENSOR_INTEGRATION.md` documents remaining sensor/model compatibility questions. Passing this test suite does not establish model accuracy or comparative superiority.
