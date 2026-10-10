from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import math
import re
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from . import VERSION

RFC1918 = tuple(ipaddress.ip_network(x) for x in
                ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
APP_ID = "sentrix-disposable-lab-target"
LAB_USER = "sentrix_demo"
LAB_PASSWORD = "demo-correct-0001"
WRONG_PASSWORD = "demo-invalid-0001"
MAX_HTTP_BYTES = 4 * 1024 * 1024
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 123, 135, 139,
                 143, 443, 445, 465, 587, 993, 995, 3306, 8080, 8088,
                 1433, 1521, 2375, 2376, 3000, 5000, 5432, 5601, 5900, 6379,
                 8000, 8001, 8008, 8081, 8089, 8443, 8888, 9000, 9090, 9200,
                 11211, 15672, 27017, 27018, 50000, 50070, 61616, 8082, 8090, 9050]
# Dummy wrong passwords for S2 probing. Obviously fake values for the
# disposable lab service ONLY — not a real wordlist. Never use against
# any real system.
DUMMY_WRONG_PASSWORDS = [
    "wrongpass1",
    "wrongpass2",
    "admin123",
    "letmein",
    "password123",
]


class ConfigError(ValueError):
    pass


def stamp():
    unix_ns = time.time_ns()
    return {
        "utc": datetime.fromtimestamp(unix_ns / 1e9, timezone.utc).isoformat(),
        "unix_ns": unix_ns,
        "monotonic_ns": time.monotonic_ns(),
    }


def fingerprint(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"),
                     allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def safe_ipv4(value, allow_loopback=False):
    if not isinstance(value, str):
        raise ConfigError("Use one literal IPv4 address as a string.")
    try:
        address = ipaddress.IPv4Address(value)
    except (ValueError, TypeError, ipaddress.AddressValueError):
        raise ConfigError("Use one literal IPv4 address, not a hostname, range, or CIDR.")
    if allow_loopback and address == ipaddress.IPv4Address("127.0.0.1"):
        return str(address)
    if not any(address in network for network in RFC1918):
        raise ConfigError("A physical trial requires one RFC1918 lab IPv4 address.")
    return str(address)


def backend_parts(url):
    parts = urlsplit(url)
    if (parts.scheme != "http" or parts.username or parts.password or
            parts.query or parts.fragment or parts.path not in ("", "/")):
        raise ConfigError("backend_url must be http://IPv4:port with no credentials or path.")
    if parts.hostname == "localhost":
        host = "127.0.0.1"
    else:
        host = safe_ipv4(parts.hostname, allow_loopback=True)
    try:
        port = parts.port or 80
    except ValueError as exc:
        raise ConfigError(str(exc)) from exc
    if not 1 <= port <= 65535:
        raise ConfigError("Invalid backend port.")
    return host, port


def number(value, label, low, high, integer=False):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{label} must be numeric.")
    if not math.isfinite(value) or not low <= value <= high:
        raise ConfigError(f"{label} must be between {low} and {high}.")
    if integer and not isinstance(value, int):
        raise ConfigError(f"{label} must be an integer.")
    return value


def validate_config(raw, smoke=False):
    defaults = {
        "protocol_id": "draft2",
        "configuration_id": "unrecorded",
        "target_ip": "",
        "target_mac": "",
        "service_port": 8088,
        "backend_url": "http://192.168.254.156:8000",
        "model_domain": "omni",
        "expected_alert_threshold": 0.87,
        "snort_json_file": "snort_logs/alert_json.txt",
        "warmup_seconds": 60.0,
        "scoring_seconds": 120.0,
        "action_window_seconds": 30.0,
        "interval_seconds": 0.5,
        "timeout_seconds": 0.75,
        "poll_interval_seconds": 0.5,
        "scan_ports": DEFAULT_PORTS,
        "http_attempts": 20,
    }
    if not isinstance(raw, dict):
        raise ConfigError("The configuration must be a JSON object.")
    extra = set(raw) - set(defaults)
    if extra:
        raise ConfigError(f"Unknown configuration fields: {sorted(extra)}")
    cfg = {**defaults, **raw}
    cfg["target_ip"] = safe_ipv4(cfg["target_ip"], allow_loopback=smoke)
    if smoke:
        if cfg["target_ip"] != "127.0.0.1":
            raise ConfigError("--smoke is restricted to 127.0.0.1.")
        cfg.update(warmup_seconds=0.0, scoring_seconds=3.0,
                   action_window_seconds=2.0, interval_seconds=0.5,
                   timeout_seconds=0.35, poll_interval_seconds=0.1,
                   http_attempts=2)
        cfg["scan_ports"] = list(cfg["scan_ports"])[:2]
    else:
        if not isinstance(cfg["target_mac"], str) or not re.fullmatch(
                r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}", cfg["target_mac"]):
            raise ConfigError("Record the lab target's real target_mac in the configuration.")
    for key in ("protocol_id", "configuration_id"):
        if not isinstance(cfg[key], str) or not cfg[key].strip():
            raise ConfigError(f"{key} must be recorded.")
    if cfg["configuration_id"] == "unrecorded" or cfg["configuration_id"].startswith("SET_"):
        raise ConfigError("Set configuration_id to identify the tested build and artifacts.")
    if cfg["model_domain"] not in ("omni", "ton_iot", "bot_iot", "cic_ids2017"):
        raise ConfigError("Unknown model_domain.")
    backend_parts(cfg["backend_url"])
    number(cfg["service_port"], "service_port", 1, 65535, True)
    number(cfg["warmup_seconds"], "warmup_seconds", 0 if smoke else 1, 300)
    number(cfg["scoring_seconds"], "scoring_seconds", 1 if smoke else 30, 600)
    number(cfg["action_window_seconds"], "action_window_seconds", 1, 30)
    number(cfg["interval_seconds"], "interval_seconds", 0.5, 30)
    number(cfg["timeout_seconds"], "timeout_seconds", 0.05, 2)
    number(cfg["poll_interval_seconds"], "poll_interval_seconds", 0.1 if smoke else 0.25, 5)
    number(cfg["http_attempts"], "http_attempts", 1, 30, True)
    number(cfg["expected_alert_threshold"], "expected_alert_threshold", 0.5, 0.99)
    ports = cfg["scan_ports"]
    if not isinstance(ports, list) or not 1 <= len(ports) <= 64:
        raise ConfigError("scan_ports must contain 1 to 64 explicitly chosen ports.")
    for port in ports:
        number(port, "scan port", 1, 65535, True)
    if len(set(ports)) != len(ports):
        raise ConfigError("scan_ports must not contain duplicates.")
    for count in (len(ports), cfg["http_attempts"]):
        maximum = (count - 1) * cfg["interval_seconds"] + cfg["timeout_seconds"]
        if maximum > cfg["action_window_seconds"]:
            raise ConfigError("Actions plus their timeout do not fit inside action_window_seconds.")
    if cfg["action_window_seconds"] >= cfg["scoring_seconds"]:
        raise ConfigError("Reserve an observation tail after action_window_seconds.")
    if not isinstance(cfg["snort_json_file"], str) or not cfg["snort_json_file"]:
        raise ConfigError("snort_json_file must be a path.")
    cfg["target_mac"] = cfg["target_mac"].lower()
    return cfg


class JsonlLog:
    def __init__(self, path, context=None, append=False):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.context = context or {}
        self.lock = threading.Lock()
        self.file = self.path.open("a" if append else "x", encoding="utf-8")

    def write(self, event, **fields):
        row = {**self.context, "event": event, "recorded": stamp(), **fields}
        encoded = json.dumps(row, sort_keys=True, allow_nan=False)
        with self.lock:
            if self.file.closed:
                return
            self.file.write(encoded + "\n")
            self.file.flush()
        return row

    def close(self):
        with self.lock:
            self.file.close()


def write_json(path, value):
    with Path(path).open("x", encoding="utf-8") as file:
        json.dump(value, file, indent=2, sort_keys=True, allow_nan=False)
        file.write("\n")


def http_get(host, port, path, timeout=1, headers=None, max_bytes=MAX_HTTP_BYTES):
    """No redirects, proxies, cookies, DNS target expansion, or automatic retries."""
    began = stamp()
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    source = None
    try:
        conn.connect()
        source = conn.sock.getsockname()
        conn.request("GET", path, headers={"Connection": "close", **(headers or {})})
        response = conn.getresponse()
        data = response.read(max_bytes + 1)
        if len(data) > max_bytes:
            raise ValueError("Response exceeded the configured byte limit.")
        ended = stamp()
        return {
            "status": response.status,
            "body": data.decode("utf-8", errors="replace"),
            "source_ip": source[0], "source_port": source[1],
            "began": began, "ended": ended,
            "elapsed_seconds": (ended["monotonic_ns"] - began["monotonic_ns"]) / 1e9,
        }
    except Exception as exc:
        ended = stamp()
        return {
            "status": None, "body": "",
            "error": f"{type(exc).__name__}: {exc}",
            "source_ip": source[0] if source else None,
            "source_port": source[1] if source else None,
            "began": began, "ended": ended,
            "elapsed_seconds": (ended["monotonic_ns"] - began["monotonic_ns"]) / 1e9,
        }
    finally:
        conn.close()


def get_backend_json(cfg, path):
    host, port = backend_parts(cfg["backend_url"])
    result = http_get(host, port, path, timeout=cfg["timeout_seconds"])
    if result["status"] != 200:
        raise RuntimeError(result.get("error") or f"Backend returned HTTP {result['status']}")
    try:
        body = json.loads(result["body"])
    except json.JSONDecodeError as exc:
        raise RuntimeError("Backend response is not JSON.") from exc
    return body, result


def target_preflight(cfg):
    result = http_get(cfg["target_ip"], cfg["service_port"],
                      "/__sentrix_lab__/health", timeout=cfg["timeout_seconds"])
    if result["status"] != 200:
        raise RuntimeError("The disposable lab target is unavailable: " +
                           (result.get("error") or f"HTTP {result['status']}"))
    try:
        body = json.loads(result["body"])
    except json.JSONDecodeError as exc:
        raise RuntimeError("The target did not return the lab health response.") from exc
    if body.get("application") != APP_ID or body.get("kit_version") != VERSION:
        raise RuntimeError("The endpoint is not this kit's compatible disposable lab target.")
    # The server's view accounts for ordinary source NAT from WSL.
    safe_ipv4(body.get("client_ip"), allow_loopback=True)
    return {**body, "client_local_ip": result["source_ip"], "request": {
        key: value for key, value in result.items() if key != "body"}}


def valid_trial_id(value):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", value):
        raise ConfigError("trial-id must be 1-64 letters/digits/dots/dashes/underscores.")
    return value


def wait_until(deadline, stop=None):
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return True
        if stop is not None:
            if stop.wait(min(remaining, 0.1)):
                return False
        else:
            time.sleep(min(remaining, 0.1))
