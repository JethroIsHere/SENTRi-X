from __future__ import annotations

import json
import math
import threading
import time
from pathlib import Path

from .common import get_backend_json, stamp


def endpoint(value):
    if not isinstance(value, str):
        return None, None
    address, separator, port = value.rpartition(":")
    if separator and port.isdigit():
        return address, int(port)
    return value, None


def scope_hint(raw, source_ip, target_ip, ports, snort=False):
    if snort:
        src, sport = endpoint(raw.get("src_ap"))
        dst, dport = endpoint(raw.get("dst_ap"))
    else:
        src = raw.get("source_ip", raw.get("src_ip"))
        dst = raw.get("dest_ip", raw.get("target_ip", raw.get("dst_ip")))
        sport, dport = raw.get("src_port"), raw.get("dst_port")
    pair = ((src == source_ip and dst == target_ip) or
            (src == target_ip and dst == source_ip))
    target_port = dport if dst == target_ip else sport if src == target_ip else None
    if source_ip == target_ip and pair:  # Local smoke only.
        port_match = sport in ports or dport in ports if sport or dport else None
    else:
        port_match = target_port in ports if target_port is not None else None
    protocol = str(raw.get("proto", "")).upper()
    tcp_or_unspecified = protocol in ("", "TCP", "6")
    return {
        "candidate": pair and port_match is not False and tcp_or_unspecified,
        "ip_pair_match": pair, "target_port_match": port_match,
        "basis": "ip_pair_only" if pair and port_match is None else "endpoints_and_port",
        "manual_scope_review_required": True,
    }


class Observer:
    def __init__(self, cfg, engine, log, source_ip, case):
        self.cfg, self.engine, self.log = cfg, engine, log
        self.source_ip = source_ip
        self.ports = cfg["scan_ports"] if case == "S1" else [cfg["service_port"]]
        self.stop = threading.Event()
        self.thread = None
        self.records = []
        self.issues = []
        self.polls = 0

    def issue(self, kind, message):
        row = {"kind": kind, "message": str(message), "observed": stamp()}
        self.issues.append(row)
        self.log.write("observer_issue", **row)

    def record(self, alert_id, raw, poll_started, poll_finished):
        row = {
            "observer": self.engine, "alert_id": alert_id, "raw": raw,
            "poll_started": poll_started, "first_observed": poll_finished,
            "scope_hint": scope_hint(raw, self.source_ip, self.cfg["target_ip"],
                                     self.ports, self.engine == "snort"),
        }
        self.records.append(row)
        self.log.write("alert_observed", **row)

    def prime(self):
        pass

    def poll(self):
        pass

    def start(self):
        def worker():
            while not self.stop.is_set():
                try:
                    self.poll()
                except Exception as exc:
                    self.issue("poll_failed", f"{type(exc).__name__}: {exc}")
                self.polls += 1
                if self.stop.wait(self.cfg["poll_interval_seconds"]):
                    break
        self.thread = threading.Thread(target=worker, daemon=True)
        self.thread.start()

    def close(self):
        self.stop.set()
        if self.thread:
            self.thread.join(timeout=4 * self.cfg["timeout_seconds"] + 3)
            if self.thread.is_alive():
                self.issue("observer_stop_timeout", "An outstanding read did not finish.")

    def summary(self, scoring_start, scoring_end):
        start = scoring_start["monotonic_ns"] if scoring_start else None
        end = scoring_end["monotonic_ns"] if scoring_end else None
        candidates = []
        if start is not None and end is not None:
            for row in self.records:
                observed = row["first_observed"]["monotonic_ns"]
                if start <= observed <= end and row["scope_hint"]["candidate"]:
                    candidates.append({
                        "alert_id": row["alert_id"],
                        "first_observed_unix_seconds": row["first_observed"]["unix_ns"] / 1e9,
                        "candidate_delay_seconds": (observed - start) / 1e9,
                        "poll_crossed_scoring_start":
                            row["poll_started"]["monotonic_ns"] < start,
                        "scope_hint": row["scope_hint"],
                    })
        return {
            "polls": self.polls, "new_alerts_observed": len(self.records),
            "candidate_alerts_in_scoring_window": candidates,
            "observer_issues": self.issues,
            "complete_recording_without_reported_issue": not self.issues,
            "detection_outcome": None, "detection_latency_seconds": None,
            "review_required": True,
            "note": "Candidates are not confirmed detections. Review scope, ground truth, and timing.",
        }


class SentrixObserver(Observer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.seen = set()
        self.last_status_poll = 0.0
        self.initial_epoch = None
        self.last_ids = set()

    def validate_status(self, status):
        if not isinstance(status, dict) or status.get("api_version") != 2:
            raise RuntimeError("Expected SENTRi-X API version 2.")
        required = {
            "execution_mode": self.engine,
            "current_model": self.cfg["model_domain"],
            "data_source": "live_hardware",
            "simulation_active": False,
            "is_hardware_live": True,
        }
        for key, expected in required.items():
            if status.get(key) != expected:
                raise RuntimeError(f"Status mismatch: {key}={status.get(key)!r}, expected {expected!r}")
        models = ["rf_online"] if self.engine == "rf" else (
            ["cnn_online"] if self.engine == "cnn" else ["rf_online", "cnn_online"])
        if any(status.get(key) is not True for key in models):
            raise RuntimeError("A required model is unavailable.")
        settings = status.get("settings", {})
        threshold = settings.get("alert_threshold")
        if (settings.get("active_alerting") is not True or
                not isinstance(threshold, (int, float)) or
                not math.isclose(threshold, self.cfg["expected_alert_threshold"], abs_tol=1e-9)):
            raise RuntimeError("Persisted alert settings do not match the frozen configuration.")
        if self.initial_epoch is not None and status.get("counter_epoch") != self.initial_epoch:
            raise RuntimeError("Backend counters/restart epoch changed during observation.")

    def fetch_alerts(self):
        began = stamp()
        body, result = get_backend_json(
            self.cfg, "/api/threat-logs?source=live_hardware&limit=500")
        if not isinstance(body, dict) or not isinstance(body.get("logs"), list):
            raise RuntimeError("Unexpected threat-log response schema.")
        rows = body["logs"]
        if any(not isinstance(row, dict) or not row.get("id") for row in rows):
            raise RuntimeError("Every alert must have a stable ID.")
        return rows, began, result["ended"]

    def prime(self):
        status, _ = get_backend_json(self.cfg, "/api/status")
        self.validate_status(status)
        self.initial_epoch = status.get("counter_epoch")
        self.log.write("sentrix_status", phase="preflight", status=status)
        rows, _, _ = self.fetch_alerts()
        self.seen = {str(row["id"]) for row in rows}
        self.last_ids = set(self.seen)
        self.log.write("alert_baseline", count=len(self.seen), alert_ids=sorted(self.seen),
                       source="live_hardware", polling_limit=500)
        self.last_status_poll = time.monotonic()

    def poll(self):
        rows, began, ended = self.fetch_alerts()
        ids = {str(row["id"]) for row in rows}
        if len(rows) >= 500 and not (ids & self.last_ids):
            self.issue("possible_alert_gap", "500-row polling window has no overlap with the previous one.")
        for row in rows:
            identifier = str(row["id"])
            if identifier not in self.seen:
                self.record(identifier, row, began, ended)
        self.seen.update(ids)
        self.last_ids = ids
        self.log.write("alert_poll", returned=len(rows), poll_started=began,
                       poll_finished=ended)
        if time.monotonic() - self.last_status_poll >= 2:
            self.last_status_poll = time.monotonic()
            status, _ = get_backend_json(self.cfg, "/api/status")
            self.log.write("sentrix_status", phase="monitoring", status=status)
            self.validate_status(status)


class SnortObserver(Observer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.path = Path(self.cfg["snort_json_file"])
        self.handle = None
        self.identity = None
        self.pending = b""
        self.pending_offset = 0
        self.discard_partial = False

    def open_file(self, baseline):
        if self.handle:
            self.handle.close()
        self.handle = self.path.open("rb")
        stat = self.path.stat()
        self.identity = (stat.st_dev, stat.st_ino)
        self.pending = b""
        if baseline:
            self.handle.seek(0, 2)
            end = self.handle.tell()
            if end:
                self.handle.seek(end - 1)
                self.discard_partial = self.handle.read(1) != b"\n"
            self.handle.seek(end)
        else:
            self.discard_partial = False
        self.pending_offset = self.handle.tell()

    def prime(self):
        self.open_file(baseline=True)
        self.log.write("snort_baseline", file=str(self.path.resolve()),
                       offset=self.handle.tell(), identity=list(self.identity),
                       note="File readability does not verify Snort capture or enabled rules.")

    def poll(self):
        began = stamp()
        stat = self.path.stat()
        if (stat.st_dev, stat.st_ino) != self.identity or stat.st_size < self.handle.tell():
            self.issue("snort_log_replaced_or_truncated", "Continuity must be checked against preserved logs.")
            self.open_file(baseline=False)
        chunk = self.handle.read(1024 * 1024)
        ended = stamp()
        if not chunk:
            return
        self.pending += chunk
        while b"\n" in self.pending:
            line, self.pending = self.pending.split(b"\n", 1)
            offset = self.pending_offset
            self.pending_offset += len(line) + 1
            if self.discard_partial:
                self.discard_partial = False
                continue
            if not line.strip():
                continue
            try:
                raw = json.loads(line.decode("utf-8"))
                if not isinstance(raw, dict) or not all(k in raw for k in ("src_ap", "dst_ap", "rule")):
                    raise ValueError("Expected a Snort 3 alert_json record with src_ap, dst_ap, and rule.")
            except (ValueError, UnicodeDecodeError) as exc:
                self.issue("unreadable_snort_record", f"Byte offset {offset}: {exc}")
                continue
            identifier = f"snort:{self.identity[0]}:{self.identity[1]}:{offset}"
            self.record(identifier, raw, began, ended)
        if len(self.pending) > 1024 * 1024:
            self.issue("oversized_snort_record", "An unterminated line exceeded 1 MiB.")
            self.pending_offset += len(self.pending)
            self.pending = b""
            self.discard_partial = True

    def close(self):
        super().close()
        if self.pending and not self.discard_partial:
            self.issue("incomplete_snort_record", "The log ended with an incomplete JSON line.")
        if self.handle:
            self.handle.close()


def make_observer(cfg, engine, log, source_ip, case):
    if engine == "none":
        return None
    cls = SnortObserver if engine == "snort" else SentrixObserver
    return cls(cfg, engine, log, source_ip, case)
