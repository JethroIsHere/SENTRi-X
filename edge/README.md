# SENTRi-X Edge Sensor (Raspberry Pi)

`sentrix_sensor.py` captures live traffic from verified IoT devices on the Pi,
builds 5s/30s flow windows, and POSTs them to the backend (`/api/ingest-flow`)
with heartbeats (`/api/heartbeat`).

Deploy: copy to the Pi (`~/sentrix_sensor.py`) and run `sudo python3 ~/sentrix_sensor.py`.
Requires `scapy`, `requests`, and capture privileges.

## Training-feature parity

The backend maps the posted payload straight onto the 28-feature schema
(`sentrix_ml.preprocessing.build_feature_row`), so the sensor's measurements
must sit on the same scale as the training data. Verified 2026-10-04:

| Payload field | Sensor measures | Training measured | Status |
|---|---|---|---|
| `src/dst_bytes` | IP-layer bytes (`len(ip)`) | L3 (BoT-IoT, CIC-IDS2017) / L4 payload (ToN-IoT) | ✅ matches 2/3 omni domains; documented ~40 B/pkt offset vs ToN-IoT source model |
| `src/dst_ip_bytes` | IP-layer bytes (`len(ip)`) | ToN-IoT 334/434 B, Omni 107/153 B means (Zeek per-flow IP counters); BoT-IoT/CIC 0.0 by policy | ✅ measured = same quantity as training |
| `duration` | seconds (monotonic) | seconds | ✅ |
| `src/dst_pkts` | packet counts | packet counts | ✅ |
| `proto_tcp/proto_udp` | one-hots | one-hots | ✅ |
| `http_*`, `missed_bytes` | `0` | ~zero | ✅ |
| `conn_state_*` | 6/12 states approximated | full 12 Zeek states | ⚠️ documented approximation |
| orientation | IoT-device-first | originator-first (Zeek) | ⚠️ disclosed |
| `dns_*` | last-seen per flow | first query | ⚠️ minor |

## Site-specific values

`BACKEND_URL`, `HEARTBEAT_URL`, `INTERFACE`, and the `IOT_DEVICES` MAC table
are deployment-specific. Review before publishing beyond the project repo.
