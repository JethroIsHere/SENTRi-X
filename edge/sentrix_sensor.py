#!/usr/bin/env python3

"""SENTRi-X Pi sensor, patched from the device-specific sentrix_sensor.py.

Run: sudo python3 ~/sentrix_sensor.py
The device MACs, backend URLs, IoT-first direction, 5/30-second windows and
feature approximations below are retained from the supplied sensor.
Connection states are approximate; HTTP fields and missed_bytes remain zero.

Training-feature parity notes (2026-10-04, verified against sentrix_ml):
- src_bytes/dst_bytes are accumulated at the IP layer (len(ip)), NOT the
  Ethernet frame. Training never measured L2 frames: BoT-IoT sbytes and
  CIC-IDS2017 "total length of fwd packets" are L3, ToN-IoT orig_bytes is L4
  payload. L3 sits exactly on 2 of omni's 3 training domains and inside the
  mixed training distribution. Deploying the ToN-IoT source model instead
  leaves a documented ~40 B/packet upward offset vs its L4-payload training.
- src_ip_bytes/dst_ip_bytes are exported as 0. Training has these ~zero for
  every row (optional features imputed 0.0; the BoT-IoT adapter explicitly
  excludes the per-IP aggregates to prevent cross-flow corruption). Sending
  measured values would make every live flow an outlier on 2/28 features
  after the StandardScaler.
- Flow orientation is IoT-device-first; training used originator-first
  (Zeek). Disclosed approximation; the model trained on mixed orientations.
- conn_state is a live approximation of 6 of 12 Zeek states (see
  finalize_connection_state); SH/S2/S3/SHR/RSTRH/RSTOS0 are never emitted.
- DNS keeps the last-seen query values per flow (training: first query).
"""

import time
import threading
import queue
import signal
import requests

from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR, Ether


INTERFACE = "eth0"
# Site-specific: LAN backend URL and IoT device MACs below. Review before
# publishing this file beyond the project repo.
BACKEND_URL = "http://192.168.254.156:8000/api/ingest-flow"
HEARTBEAT_URL = "http://192.168.254.156:8000/api/heartbeat"
HEARTBEAT_INTERVAL = 3
SENSOR_ID = "rpi3b-edge-01"

# Verified IoT devices
IOT_DEVICES = {
    "20:f1:b2:68:cc:63": "smart_bulb",
    "e4:ae:e4:fb:91:a0": "temp_humidity_sensor",
}

FLOW_IDLE_TIMEOUT = 5.0
FLOW_MAX_AGE = 30.0

# Bounded buffers keep slow/unavailable inference from consuming all Pi RAM.
MAX_ACTIVE_FLOWS = 4096
MAX_PENDING_FLOWS = 1000
FLOW_POST_TIMEOUT = (3.0, 15.0)  # Connect timeout, then read timeout.
HEARTBEAT_POST_TIMEOUT = (2.0, 2.0)
SHUTDOWN_DRAIN_SECONDS = 5.0

flows = {}
lock = threading.Lock()
pending_flows = queue.Queue(maxsize=MAX_PENDING_FLOWS)
stop_event = threading.Event()
expirer_done = threading.Event()
shutdown_deadline = float("inf")
stats_lock = threading.Lock()
stats = {
    "captured_packets": 0,
    "flows_accepted": 0,
    "flows_unconfirmed": 0,
    "flows_dropped": 0,
    "overflow_packets": 0,
    "heartbeats_accepted": 0,
    "heartbeats_failed": 0,
}


def count(name, amount=1):
    with stats_lock:
        stats[name] += amount


def print_stats():
    with stats_lock:
        snapshot = dict(stats)
    with lock:
        active = len(flows)
    print(
        f"[STATS] {snapshot} active_flows={active} "
        f"pending_flows={pending_flows.qsize()}",
        flush=True,
    )


def canonical_flow_key(iot_ip, remote_ip, proto, iot_port, remote_port):
    """
    Always orient the flow from the monitored IoT device toward the remote host.
    """
    return (
        iot_ip,
        remote_ip,
        proto,
        int(iot_port),
        int(remote_port),
    )


def new_flow(
    device_name,
    device_mac,
    iot_ip,
    remote_ip,
    proto,
    iot_port,
    remote_port,
):
    # Only elapsed times use this value; wall-clock corrections cannot expire flows.
    now = time.monotonic()

    return {
        "device_name": device_name,
        "device_mac": device_mac,

        "src_ip": iot_ip,
        "dst_ip": remote_ip,

        "src_port": iot_port,
        "dst_port": remote_port,

        "proto": proto,

        "first_seen": now,
        "last_seen": now,

        "src_bytes": 0,
        "dst_bytes": 0,

        "src_pkts": 0,
        "dst_pkts": 0,

        # Raw L3 measurement, retained for diagnostics. Exported as 0 --
        # see build_payload for the training-parity reason.
        "src_ip_bytes": 0,
        "dst_ip_bytes": 0,

        "missed_bytes": 0,

        "proto_tcp": 1 if proto == "TCP" else 0,
        "proto_udp": 1 if proto == "UDP" else 0,

        "conn_state_REJ": 0,
        "conn_state_RSTO": 0,
        "conn_state_RSTOS0": 0,
        "conn_state_RSTR": 0,
        "conn_state_RSTRH": 0,
        "conn_state_S0": 0,
        "conn_state_S1": 0,
        "conn_state_S2": 0,
        "conn_state_S3": 0,
        "conn_state_SF": 0,
        "conn_state_SH": 0,
        "conn_state_SHR": 0,

        "dns_qclass": 0,
        "dns_qtype": 0,
        "dns_rcode": 0,

        "http_request_body_len": 0,
        "http_response_body_len": 0,
        "http_status_code": 0,

        "_saw_outbound": False,
        "_saw_inbound": False,
        "_saw_syn": False,
        "_saw_synack": False,
        "_rst_from_iot": False,
        "_rst_from_remote": False,
    }


def update_tcp_state(flow, packet, outbound):
    if TCP not in packet:
        return

    flags = int(packet[TCP].flags)

    SYN = 0x02
    ACK = 0x10
    RST = 0x04

    if outbound and (flags & SYN) and not (flags & ACK):
        flow["_saw_syn"] = True

    if (not outbound) and (flags & SYN) and (flags & ACK):
        flow["_saw_synack"] = True

    if flags & RST:
        if outbound:
            flow["_rst_from_iot"] = True
        else:
            flow["_rst_from_remote"] = True


def finalize_connection_state(flow):
    # Simplified live approximation of Zeek-style connection states.
    # This is NOT a full Zeek conn_state implementation.

    # Keep the one-hot state valid even if this function is called more than once.
    for field in flow:
        if field.startswith("conn_state_"):
            flow[field] = 0

    if (
        flow["_saw_syn"]
        and flow["_rst_from_remote"]
        and not flow["_saw_synack"]
    ):
        flow["conn_state_REJ"] = 1

    elif flow["_rst_from_iot"]:
        flow["conn_state_RSTO"] = 1

    elif flow["_rst_from_remote"]:
        flow["conn_state_RSTR"] = 1

    elif flow["_saw_outbound"] and flow["_saw_inbound"]:
        flow["conn_state_SF"] = 1

    elif flow["_saw_outbound"] and not flow["_saw_inbound"]:
        flow["conn_state_S0"] = 1

    else:
        flow["conn_state_S1"] = 1


def parse_dns(flow, packet):
    if DNS not in packet:
        return

    try:
        dns = packet[DNS]

        if DNSQR in packet:
            flow["dns_qtype"] = int(packet[DNSQR].qtype)
            flow["dns_qclass"] = int(packet[DNSQR].qclass)

        flow["dns_rcode"] = int(dns.rcode)

    except Exception:
        pass


def process_packet(packet):
    if Ether not in packet or IP not in packet:
        return

    eth_src = packet[Ether].src.lower()
    eth_dst = packet[Ether].dst.lower()

    src_is_iot = eth_src in IOT_DEVICES
    dst_is_iot = eth_dst in IOT_DEVICES

    if not src_is_iot and not dst_is_iot:
        return

    if src_is_iot:
        device_mac = eth_src
        outbound = True
    else:
        device_mac = eth_dst
        outbound = False

    device_name = IOT_DEVICES[device_mac]

    ip = packet[IP]

    if TCP in packet:
        proto = "TCP"
        packet_src_port = int(packet[TCP].sport)
        packet_dst_port = int(packet[TCP].dport)

    elif UDP in packet:
        proto = "UDP"
        packet_src_port = int(packet[UDP].sport)
        packet_dst_port = int(packet[UDP].dport)

    else:
        return

    count("captured_packets")

    if outbound:
        iot_ip = ip.src
        remote_ip = ip.dst
        iot_port = packet_src_port
        remote_port = packet_dst_port
    else:
        iot_ip = ip.dst
        remote_ip = ip.src
        iot_port = packet_dst_port
        remote_port = packet_src_port

    key = canonical_flow_key(
        iot_ip,
        remote_ip,
        proto,
        iot_port,
        remote_port,
    )

    with lock:
        if key not in flows:
            if len(flows) >= MAX_ACTIVE_FLOWS:
                count("overflow_packets")
                return
            flows[key] = new_flow(
                device_name,
                device_mac,
                iot_ip,
                remote_ip,
                proto,
                iot_port,
                remote_port,
            )

        flow = flows[key]
        flow["last_seen"] = time.monotonic()

        # Parity: accumulate at the IP layer (len(ip)), not the Ethernet
        # frame. Training measured L3 (BoT-IoT, CIC-IDS2017) or L4 payload
        # (ToN-IoT) -- never L2 frames. See module docstring.
        ip_len = len(ip)

        if outbound:
            flow["src_pkts"] += 1
            flow["src_bytes"] += ip_len
            flow["src_ip_bytes"] += ip_len
            flow["_saw_outbound"] = True
        else:
            flow["dst_pkts"] += 1
            flow["dst_bytes"] += ip_len
            flow["dst_ip_bytes"] += ip_len
            flow["_saw_inbound"] = True

        update_tcp_state(flow, packet, outbound)
        parse_dns(flow, packet)


def build_payload(flow):
    finalize_connection_state(flow)

    duration = max(
        0.0,
        flow["last_seen"] - flow["first_seen"]
    )

    payload = {
        "sensor_id": SENSOR_ID,

        "device_name": flow["device_name"],
        "device_mac": flow["device_mac"],

        "src_ip": flow["src_ip"],
        "dst_ip": flow["dst_ip"],

        "src_port": flow["src_port"],
        "dst_port": flow["dst_port"],

        "proto": flow["proto"],

        "duration": round(duration, 6),

        "src_bytes": flow["src_bytes"],
        "dst_bytes": flow["dst_bytes"],

        "src_pkts": flow["src_pkts"],
        "dst_pkts": flow["dst_pkts"],

        # Parity: training has src/dst_ip_bytes ~zero for every row
        # (optional features imputed 0.0; BoT-IoT explicitly excludes the
        # per-IP aggregates). Exporting measured values would make every
        # live flow an outlier on 2/28 features after the scaler.
        "src_ip_bytes": 0,
        "dst_ip_bytes": 0,

        "missed_bytes": flow["missed_bytes"],

        "proto_tcp": flow["proto_tcp"],
        "proto_udp": flow["proto_udp"],

        "dns_qclass": flow["dns_qclass"],
        "dns_qtype": flow["dns_qtype"],
        "dns_rcode": flow["dns_rcode"],

        "http_request_body_len": 0,
        "http_response_body_len": 0,
        "http_status_code": 0,

        "conn_state_REJ": flow["conn_state_REJ"],
        "conn_state_RSTO": flow["conn_state_RSTO"],
        "conn_state_RSTOS0": flow["conn_state_RSTOS0"],
        "conn_state_RSTR": flow["conn_state_RSTR"],
        "conn_state_RSTRH": flow["conn_state_RSTRH"],
        "conn_state_S0": flow["conn_state_S0"],
        "conn_state_S1": flow["conn_state_S1"],
        "conn_state_S2": flow["conn_state_S2"],
        "conn_state_S3": flow["conn_state_S3"],
        "conn_state_SF": flow["conn_state_SF"],
        "conn_state_SH": flow["conn_state_SH"],
        "conn_state_SHR": flow["conn_state_SHR"],
    }

    return payload


def post_json(session, url, payload, timeout, expected_status):
    # No automatic replay: the current backend does not deduplicate flow POSTs.
    with session.post(
        url, json=payload, timeout=timeout, allow_redirects=False,
    ) as response:
        response.raise_for_status()
        if not 200 <= response.status_code < 300:
            raise ValueError(f"Unexpected HTTP {response.status_code}; check the backend URL")

        result = response.json()
        if not isinstance(result, dict) or result.get("status") != expected_status:
            raise ValueError("Backend did not return the expected acknowledgement")
        return result


def send_flow(flow, session):
    payload = build_payload(flow)
    try:
        result = post_json(session, BACKEND_URL, payload, FLOW_POST_TIMEOUT, "success")
        count("flows_accepted")
        print(
            f"[ACCEPTED] "
            f"{flow['device_name']} "
            f"{flow['src_ip']} -> {flow['dst_ip']} "
            f"{flow['proto']} "
            f"pkts={flow['src_pkts'] + flow['dst_pkts']} "
            f"prediction={result.get('prediction')} "
            f"confidence={result.get('confidence')} "
            f"RF={result.get('p_rf')} "
            f"CNN={result.get('p_cnn')}",
            flush=True,
        )
        return True

    except (requests.RequestException, ValueError) as exc:
        count("flows_unconfirmed")
        print(
            f"[ERROR] Flow POST unconfirmed for {flow['device_name']}: {exc}. "
            "Not replayed automatically; a lost response may already have been processed.",
            flush=True,
        )
        return False


def collect_expired_flows(flush_all=False):
    now = time.monotonic()
    expired = []

    with lock:
        for key, flow in list(flows.items()):
            idle = now - flow["last_seen"]
            age = now - flow["first_seen"]
            if flush_all or idle >= FLOW_IDLE_TIMEOUT or age >= FLOW_MAX_AGE:
                expired.append(flows.pop(key))

    dropped = 0
    for flow in expired:
        try:
            pending_flows.put_nowait(flow)
        except queue.Full:
            dropped += 1
    if dropped:
        count("flows_dropped", dropped)
        print(f"[ERROR] Delivery queue full; dropped {dropped} flow windows", flush=True)


def flow_expirer():
    try:
        while not stop_event.wait(1):
            collect_expired_flows()
        collect_expired_flows(flush_all=True)
    finally:
        expirer_done.set()


def flow_sender():
    # Sending may wait for model/XAI work; expiry and heartbeats remain independent.
    with requests.Session() as session:
        while not expirer_done.is_set() or not pending_flows.empty():
            try:
                flow = pending_flows.get(timeout=0.2)
            except queue.Empty:
                continue
            try:
                if time.monotonic() >= shutdown_deadline:
                    count("flows_dropped")
                else:
                    send_flow(flow, session)
            finally:
                pending_flows.task_done()

def heartbeat_worker():
    connected = False
    last_report = time.monotonic()
    with requests.Session() as session:
        while not stop_event.is_set():
            try:
                post_json(
                    session, HEARTBEAT_URL, {"sensor_id": SENSOR_ID},
                    HEARTBEAT_POST_TIMEOUT, "ok",
                )
                count("heartbeats_accepted")
                if not connected:
                    print("[HEARTBEAT] Backend acknowledged sensor connection", flush=True)
                connected = True
            except (requests.RequestException, ValueError) as exc:
                count("heartbeats_failed")
                connected = False
                print(f"[HEARTBEAT] Not acknowledged: {exc}", flush=True)

            if time.monotonic() - last_report >= 10:
                print_stats()
                last_report = time.monotonic()
            if stop_event.wait(HEARTBEAT_INTERVAL):
                break

def main():
    global shutdown_deadline
    print("SENTRi-X Raspberry Pi Edge Sensor")
    print(f"Capture interface : {INTERFACE}")
    print(f"Backend           : {BACKEND_URL}")
    print("Monitoring:")
    for mac, name in IOT_DEVICES.items():
        print(f"  {name}: {mac}")

    # Capture ONLY verified IoT MAC addresses.
    # Prevents SENTRi-X from ingesting its own Wi-Fi/API traffic.
    bpf_filter = " or ".join(f"ether host {mac}" for mac in IOT_DEVICES)
    workers = []

    def start_workers():
        # Scapy calls this only after the capture socket and filter are ready.
        for target in (flow_expirer, flow_sender, heartbeat_worker):
            worker = threading.Thread(target=target, name=target.__name__, daemon=True)
            workers.append(worker)
            worker.start()
        print(f"[CAPTURE] Ready on {INTERFACE}; press Ctrl+C to stop", flush=True)

    def stop_on_signal(_signum, _frame):
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, stop_on_signal)
    # SSH logout can send SIGHUP to a foreground process on the Pi.
    if hasattr(signal, "SIGHUP"):
        signal.signal(signal.SIGHUP, stop_on_signal)

    exit_code = 0
    try:
        sniff(
            iface=INTERFACE,
            filter=bpf_filter,
            prn=process_packet,
            store=False,
            promisc=True,
            started_callback=start_workers,
            chainCC=True,
        )
    except KeyboardInterrupt:
        print("\n[STOP] Stopping sensor and flushing pending flow windows", flush=True)
    except Exception as exc:
        print(
            f"[ERROR] Capture failed: {exc}. Check {INTERFACE}, capture privileges "
            "and libpcap support.",
            flush=True,
        )
        exit_code = 1
    finally:
        shutdown_deadline = time.monotonic() + SHUTDOWN_DRAIN_SECONDS
        stop_event.set()
        join_deadline = shutdown_deadline + sum(FLOW_POST_TIMEOUT) + 1
        for worker in workers:
            worker.join(timeout=max(0.0, join_deadline - time.monotonic()))
        if any(worker.is_alive() for worker in workers):
            print("[ERROR] Shutdown deadline reached; remaining delivery is unconfirmed", flush=True)
            exit_code = 1
        print_stats()
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
