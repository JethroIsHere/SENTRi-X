from __future__ import annotations

import contextlib
import csv
import importlib.util
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lab_target import LabServer
from sentrix_lab.common import (
    ConfigError, JsonlLog, fingerprint, safe_ipv4, stamp,
    target_preflight, valid_trial_id, validate_config,
)
from sentrix_lab.observers import SentrixObserver, SnortObserver, scope_hint
from sentrix_lab.traffic import login_attempt, tcp_attempt
import sample_resources


def config(port=8088):
    return validate_config({
        "target_ip": "127.0.0.1", "configuration_id": "unit-test-only",
        "service_port": port, "scan_ports": [port, 9],
        "backend_url": "http://127.0.0.1:8000",
    }, smoke=True)


class QuietBackend(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/api/status":
            body = {
                "api_version": 2, "execution_mode": "hybrid", "current_model": "omni",
                "data_source": "live_hardware", "simulation_active": False,
                "is_hardware_live": True, "rf_online": True, "cnn_online": True,
                "counter_epoch": "test-epoch",
                "settings": {"active_alerting": True, "alert_threshold": 0.87},
            }
        elif self.path.startswith("/api/threat-logs"):
            body = {"logs": self.server.alerts}
        else:
            self.send_error(404)
            return
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@contextlib.contextmanager
def lab_service(directory):
    evidence = JsonlLog(Path(directory) / "service.jsonl", append=True)
    server = LabServer(("127.0.0.1", 0), evidence)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    try:
        yield server, evidence
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
        evidence.close()


class ConfigTests(unittest.TestCase):
    def test_only_one_rfc1918_target_or_explicit_smoke_loopback(self):
        self.assertEqual(safe_ipv4("192.168.254.200"), "192.168.254.200")
        for value in ("8.8.8.8", "example.com", "192.168.1.0/24", "127.0.0.1",
                      "169.254.1.1", "224.0.0.1", "0.0.0.0", "::1", 3232235777):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                safe_ipv4(value)
        self.assertEqual(safe_ipv4("127.0.0.1", True), "127.0.0.1")

    def test_limits_and_unknown_fields(self):
        base = {"target_ip": "192.168.1.20", "target_mac": "02:11:22:33:44:55",
                "configuration_id": "test"}
        validate_config(base)
        for override in ({"http_attempts": 31}, {"interval_seconds": 0.01},
                         {"scan_ports": [80, 80]}, {"timeout_seconds": 20},
                         {"extra_argument": True}, {"interval_seconds": float("nan")},
                         {"service_port": True}, {"scan_ports": list(range(1, 66))},
                         {"configuration_id": "SET_BUILD_MODEL_RULESET_ID"}):
            with self.subTest(override=override), self.assertRaises(ConfigError):
                validate_config({**base, **override})

    def test_path_identifiers_and_fingerprint(self):
        for value in ("../escape", "/tmp/escape", ".", "", "a/b", "x" * 65):
            with self.subTest(value=value), self.assertRaises(ConfigError):
                valid_trial_id(value)
        self.assertEqual(valid_trial_id("PILOT-S1-01"), "PILOT-S1-01")
        self.assertEqual(fingerprint({"a": 1, "b": 2}), fingerprint({"b": 2, "a": 1}))

    def test_dry_run_sends_no_requests_and_writes_no_evidence(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "config.json"
            path.write_text(json.dumps({"target_ip": "127.0.0.1",
                "configuration_id": "test", "scan_ports": [8088, 8089]}))
            result = subprocess.run([sys.executable, str(ROOT / "run_trial.py"),
                "--config", str(path), "--smoke", "--case", "S1", "--engine", "none",
                "--trial-id", "dry", "--output", str(Path(temp) / "evidence")],
                capture_output=True, text=True, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["network_requests_sent"], 0)
            self.assertFalse((Path(temp) / "evidence").exists())


class TargetTests(unittest.TestCase):
    def test_real_success_and_failure_are_independently_logged(self):
        with tempfile.TemporaryDirectory() as temp, lab_service(temp) as (server, _):
            cfg = config(server.server_port)
            health = target_preflight(cfg)
            self.assertEqual(health["client_ip"], "127.0.0.1")
            good = login_attempt(cfg, True, "known-good-id", 0.5)
            bad = login_attempt(cfg, False, "known-bad-id", 0.5)
            self.assertEqual(good["status"], 200)
            self.assertEqual(bad["status"], 401)
            rows = [json.loads(line) for line in (Path(temp) / "service.jsonl").read_text().splitlines()]
            auth = {r["request_id"]: r for r in rows if r["event"] == "request_received"}
            self.assertEqual(auth["known-bad-id"]["authentication_outcome"], "authentication_failed")
            self.assertEqual(auth["known-good-id"]["authentication_outcome"], "authenticated")
            self.assertNotIn("demo-invalid", (Path(temp) / "service.jsonl").read_text())

    def test_scan_reports_actual_open_and_closed_socket_results(self):
        with tempfile.TemporaryDirectory() as temp, lab_service(temp) as (server, _):
            cfg = config(server.server_port)
            self.assertEqual(tcp_attempt(cfg, server.server_port, 0.5)["outcome"], "connected")
            held = socket.socket()
            held.bind(("127.0.0.1", 0))  # Bound but not listening: no competing open service.
            try:
                closed = tcp_attempt(cfg, held.getsockname()[1], 0.5)
                self.assertEqual(closed["outcome"], "refused")
            finally:
                held.close()


class ObserverTests(unittest.TestCase):
    def test_scope_checks_both_directions_and_keeps_port_ambiguity(self):
        raw = {"src_ap": "192.168.1.20:8088", "dst_ap": "192.168.1.30:50000", "proto": "TCP"}
        self.assertTrue(scope_hint(raw, "192.168.1.30", "192.168.1.20", [8088], True)["candidate"])
        self.assertFalse(scope_hint(raw, "192.168.1.31", "192.168.1.20", [8088], True)["candidate"])
        record = {"source_ip": "192.168.1.30", "dest_ip": "192.168.1.20"}
        self.assertEqual(scope_hint(record, "192.168.1.30", "192.168.1.20", [8088])["basis"], "ip_pair_only")

    def test_snort_baseline_partial_line_and_observation_time(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "snort.jsonl"
            old = {"src_ap": "127.0.0.1:50000", "dst_ap": "127.0.0.1:8088", "rule": "1:1:1"}
            path.write_text(json.dumps(old) + "\n")
            cfg = config()
            cfg["snort_json_file"] = str(path)
            log = JsonlLog(Path(temp) / "events.jsonl")
            observer = SnortObserver(cfg, "snort", log, "127.0.0.1", "S2")
            observer.prime()
            start = stamp()
            fresh = {**old, "rule": "1:2:1", "timestamp": "01/01-00:00:00.000001"}
            with path.open("a") as file:
                file.write(json.dumps(fresh))
            observer.poll()
            self.assertEqual(len(observer.records), 0)
            with path.open("a") as file:
                file.write("\n")
            observer.poll()
            end = stamp()
            summary = observer.summary(start, end)
            self.assertEqual(len(observer.records), 1)
            self.assertEqual(observer.records[0]["raw"]["timestamp"], fresh["timestamp"])
            self.assertIsNone(summary["detection_outcome"])
            self.assertIsNone(summary["detection_latency_seconds"])
            self.assertGreaterEqual(summary["candidate_alerts_in_scoring_window"][0]["candidate_delay_seconds"], 0)
            observer.close()
            log.close()

    def test_snort_rotation_and_malformed_data_are_not_silent(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "snort.jsonl"
            path.write_text("")
            cfg = config()
            cfg["snort_json_file"] = str(path)
            log = JsonlLog(Path(temp) / "events.jsonl")
            observer = SnortObserver(cfg, "snort", log, "127.0.0.1", "S1")
            observer.prime()
            path.rename(Path(temp) / "old.jsonl")
            path.write_text("not-json\n")
            observer.poll()
            self.assertEqual(len(observer.issues), 2)
            self.assertFalse(observer.summary(None, None)["complete_recording_without_reported_issue"])
            observer.close()
            log.close()

    def test_sentrix_reads_real_api_shape_and_deduplicates(self):
        with tempfile.TemporaryDirectory() as temp:
            server = ThreadingHTTPServer(("127.0.0.1", 0), QuietBackend)
            server.alerts = [{"id": "old", "source_ip": "127.0.0.1", "dest_ip": "127.0.0.1"}]
            thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
            thread.start()
            log = JsonlLog(Path(temp) / "events.jsonl")
            observer = None
            try:
                cfg = config()
                cfg["backend_url"] = f"http://127.0.0.1:{server.server_port}"
                observer = SentrixObserver(cfg, "hybrid", log, "127.0.0.1", "S2")
                observer.prime()
                server.alerts.insert(0, {"id": "new", "source_ip": "127.0.0.1", "dest_ip": "127.0.0.1"})
                observer.poll()
                observer.poll()
                self.assertEqual([r["alert_id"] for r in observer.records], ["new"])
                bad = {"api_version": 2, "execution_mode": "rf"}
                with self.assertRaises(RuntimeError):
                    observer.validate_status(bad)
                server.alerts = [{"id": f"burst-{i}"} for i in range(500)]
                observer.poll()
                self.assertTrue(any(r["kind"] == "possible_alert_gap" for r in observer.issues))
            finally:
                if observer:
                    observer.close()
                log.close()
                server.shutdown()
                server.server_close()
                thread.join(2)


class RunnerTests(unittest.TestCase):
    def run_cli(self, temp, port, case, trial, extra=()):
        path = Path(temp) / f"{trial}.json"
        path.write_text(json.dumps({
            "configuration_id": "test-only", "target_ip": "127.0.0.1",
            "service_port": port, "scan_ports": [port, 9],
        }))
        command = [sys.executable, str(ROOT / "run_trial.py"), "--config", str(path),
                   "--smoke", "--case", case, "--engine", "none", "--trial-id", trial,
                   "--output", str(Path(temp) / "runs"), "--execute", *extra]
        return subprocess.run(command, capture_output=True, text=True, timeout=12)

    def test_all_three_cases_complete_and_do_not_invent_results(self):
        with tempfile.TemporaryDirectory() as temp, lab_service(temp) as (server, _):
            for case in ("B0", "S1", "S2"):
                trial = f"smoke-{case}"
                result = self.run_cli(temp, server.server_port, case, trial)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                folder = Path(temp) / "runs" / trial
                summary = json.loads((folder / "summary.json").read_text())
                self.assertEqual(summary["run_kind"], "local_smoke")
                self.assertTrue(summary["complete_scoring_window"])
                self.assertEqual(summary["actions"]["attempted"], 2)
                self.assertIsNone(summary["model_accuracy"])
                self.assertIsNone(summary["alerts"]["detection_outcome"])
                with (folder / "review.csv").open(encoding="utf-8") as review_file:
                    rows = list(csv.DictReader(review_file))
                self.assertEqual(rows[0]["relevant_alarm"], "")
                events = [json.loads(line) for line in (folder / "events.jsonl").read_text().splitlines()]
                starts = [r["action_started"]["monotonic_ns"] for r in events if r["event"] == "action_started"]
                self.assertGreaterEqual((starts[1] - starts[0]) / 1e9, 0.49)
            # Existing evidence must never be overwritten.
            repeat = self.run_cli(temp, server.server_port, "B0", "smoke-B0")
            self.assertEqual(repeat.returncode, 2)

    def test_preflight_failure_preserves_evidence_without_sending_actions(self):
        with tempfile.TemporaryDirectory() as temp:
            held = socket.socket()
            held.bind(("127.0.0.1", 0))
            try:
                result = self.run_cli(temp, held.getsockname()[1], "S2", "bad-target")
            finally:
                held.close()
            self.assertEqual(result.returncode, 2)
            summary = json.loads((Path(temp) / "runs/bad-target/summary.json").read_text())
            self.assertEqual(summary["status"], "preflight_failed")
            self.assertEqual(summary["actions"]["attempted"], 0)
            self.assertEqual(summary["trial_validity"], "pending_manual_review")

    def test_runner_with_backend_observer_preserves_raw_candidate_for_review(self):
        with tempfile.TemporaryDirectory() as temp, lab_service(temp) as (server, _):
            backend = ThreadingHTTPServer(("127.0.0.1", 0), QuietBackend)
            backend.alerts = []
            thread = threading.Thread(target=backend.serve_forever,
                                      kwargs={"poll_interval": 0.02}, daemon=True)
            thread.start()
            path = Path(temp) / "observed.json"
            path.write_text(json.dumps({
                "configuration_id": "mock-backend-only", "target_ip": "127.0.0.1",
                "service_port": server.server_port, "scan_ports": [server.server_port, 9],
                "backend_url": f"http://127.0.0.1:{backend.server_port}",
            }))
            command = [sys.executable, str(ROOT / "run_trial.py"), "--config", str(path),
                       "--smoke", "--case", "S2", "--engine", "hybrid",
                       "--trial-id", "observed", "--output", str(Path(temp) / "runs"),
                       "--execute"]
            child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                event_path = Path(temp) / "runs/observed/events.jsonl"
                until = time.monotonic() + 5
                while time.monotonic() < until:
                    if event_path.exists() and '"event": "action_finished"' in event_path.read_text():
                        break
                    time.sleep(0.02)
                backend.alerts = [{"id": "synthetic-api-fixture", "source_ip": "127.0.0.1",
                                   "dest_ip": "127.0.0.1", "flow_id": 42}]
                stdout, stderr = child.communicate(timeout=8)
                self.assertEqual(child.returncode, 0, stdout + stderr)
                summary = json.loads((event_path.parent / "summary.json").read_text())
                candidates = summary["alerts"]["candidate_alerts_in_scoring_window"]
                self.assertEqual([r["alert_id"] for r in candidates], ["synthetic-api-fixture"])
                self.assertIsNone(summary["alerts"]["detection_outcome"])
                self.assertIsNone(summary["alerts"]["detection_latency_seconds"])
                self.assertEqual(candidates[0]["scope_hint"]["basis"], "ip_pair_only")
            finally:
                if child.poll() is None:
                    child.kill()
                    child.communicate()
                backend.shutdown()
                backend.server_close()
                thread.join(2)

    @unittest.skipIf(os.name == "nt", "POSIX signal integration check")
    def test_interruption_writes_partial_evidence(self):
        with tempfile.TemporaryDirectory() as temp, lab_service(temp) as (server, _):
            path = Path(temp) / "config.json"
            path.write_text(json.dumps({"configuration_id": "signal-test",
                "target_ip": "127.0.0.1", "service_port": server.server_port,
                "scan_ports": [server.server_port, 9]}))
            command = [sys.executable, str(ROOT / "run_trial.py"), "--config", str(path),
                       "--smoke", "--case", "S2", "--engine", "none",
                       "--trial-id", "interrupt", "--output", str(Path(temp) / "runs"), "--execute"]
            child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                event_path = Path(temp) / "runs/interrupt/events.jsonl"
                until = time.monotonic() + 5
                while time.monotonic() < until:
                    if event_path.exists() and '"event": "action_finished"' in event_path.read_text():
                        break
                    time.sleep(0.02)
                child.send_signal(signal.SIGTERM)
                stdout, stderr = child.communicate(timeout=5)
                self.assertEqual(child.returncode, 2, stdout + stderr)
                summary = json.loads((Path(temp) / "runs/interrupt/summary.json").read_text())
                self.assertEqual(summary["status"], "interrupted")
                self.assertFalse(summary["complete_scoring_window"])
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()


class ResourceTests(unittest.TestCase):
    def fake_psutil(self, values):
        return types.SimpleNamespace(
            __version__="test-double", Error=OSError,
            cpu_percent=mock.Mock(side_effect=values),
            cpu_count=lambda: 4,
            virtual_memory=lambda: types.SimpleNamespace(used=1024 * 1024),
        )

    def invoke(self, output, fake, interrupt=False):
        argv = ["sample_resources.py", "--scope", "mock_host", "--duration", "1",
                "--interval", "0.25", "--output", str(output)]
        wait = mock.Mock(side_effect=KeyboardInterrupt if interrupt else None)
        with mock.patch.object(sys, "argv", argv), mock.patch.dict(sys.modules, psutil=fake), \
                mock.patch.object(sample_resources, "wait_until", wait), \
                contextlib.redirect_stdout(__import__("io").StringIO()):
            return sample_resources.main()

    def test_priming_value_is_excluded_and_measured_units_are_explicit(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "resources.jsonl"
            self.assertEqual(self.invoke(output, self.fake_psutil([0, 25, 25, 25, 25])), 0)
            summary = json.loads(Path(str(output) + ".summary.json").read_text())
            self.assertEqual(summary["sample_count"], 4)
            self.assertEqual(summary["cpu_mean_percent"], 25)
            self.assertEqual(summary["memory_mean_bytes"], 1024 * 1024)
            events = [json.loads(x) for x in output.read_text().splitlines()]
            self.assertEqual(events[0]["cpu_basis"], "whole_host_0_to_100_percent")

    def test_sampling_error_and_interruption_are_not_zero_successes(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "errors.jsonl"
            fake = self.fake_psutil([0, OSError("sample unavailable"), 25, 25, 25])
            self.assertEqual(self.invoke(output, fake), 3)
            summary = json.loads(Path(str(output) + ".summary.json").read_text())
            self.assertEqual(summary["error_count"], 1)
            self.assertEqual(summary["cpu_mean_percent"], 25)
            output = Path(temp) / "interrupted.jsonl"
            self.assertEqual(self.invoke(output, self.fake_psutil([0]), interrupt=True), 3)
            summary = json.loads(Path(str(output) + ".summary.json").read_text())
            self.assertTrue(summary["interrupted"])
            self.assertIsNone(summary["cpu_mean_percent"])

    def test_missing_optional_dependency_has_clear_error(self):
        with tempfile.TemporaryDirectory() as temp:
            with contextlib.redirect_stderr(__import__("io").StringIO()) as errors, \
                    self.assertRaises(SystemExit) as result:
                self.invoke(Path(temp) / "missing.jsonl", None)
            self.assertEqual(result.exception.code, 2)
            self.assertIn("Optional dependency missing", errors.getvalue())
            self.assertFalse((Path(temp) / "missing.jsonl").exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
