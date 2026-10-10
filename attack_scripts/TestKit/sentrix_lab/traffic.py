from __future__ import annotations

import base64
import errno
import socket
import time
import uuid

from .common import LAB_PASSWORD, LAB_USER, WRONG_PASSWORD, DUMMY_WRONG_PASSWORDS, http_get, stamp, wait_until


def tcp_attempt(cfg, port, timeout):
    began = stamp()
    source = None
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    banner_bytes = 0
    try:
        connection.settimeout(timeout)
        result = connection.connect_ex((cfg["target_ip"], port))
        source = connection.getsockname()
        if result == 0:
            outcome = "connected"
            # Banner grab: read up to 512 bytes (real scanners do this)
            try:
                connection.settimeout(1.0)
                banner = connection.recv(512)
                banner_bytes = len(banner)
            except (OSError, TimeoutError):
                pass
        elif result in (errno.ECONNREFUSED, 10061):
            outcome = "refused"
        elif result in (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK, 10060):
            outcome = "timeout"
        else:
            outcome = "socket_error"
        details = {"outcome": outcome, "errno": result, "banner_bytes": banner_bytes}
    except (OSError, TimeoutError) as exc:
        try:
            source = connection.getsockname()
        except OSError:
            pass
        details = {"outcome": "socket_error", "error": f"{type(exc).__name__}: {exc}", "banner_bytes": 0}
    finally:
        connection.close()
    ended = stamp()
    return {**details, "source_ip": source[0] if source else None,
            "source_port": source[1] if source else None, "target_port": port,
            "began": began, "ended": ended,
            "elapsed_seconds": (ended["monotonic_ns"] - began["monotonic_ns"]) / 1e9}


def login_attempt(cfg, success, request_id, timeout, attempt_index=0):
    if success:
        password = LAB_PASSWORD
    else:
        # Cycle through dummy wrong passwords (lab service only)
        password = DUMMY_WRONG_PASSWORDS[attempt_index % len(DUMMY_WRONG_PASSWORDS)]
    auth = base64.b64encode(f"{LAB_USER}:{password}".encode()).decode()
    result = http_get(
        cfg["target_ip"], cfg["service_port"], "/account", timeout=timeout,
        headers={"Authorization": f"Basic {auth}", "X-Lab-Request-ID": request_id})
    expected = 200 if success else 401
    return {
        key: value for key, value in {
            **result, "target_port": cfg["service_port"],
            "request_id": request_id, "expected_status": expected,
            "expected_response_observed": result["status"] == expected,
        }.items() if key != "body"
    }


def run_actions(case, cfg, scoring_start, stop, log):
    count = len(cfg["scan_ports"]) if case == "S1" else cfg["http_attempts"]
    deadline = scoring_start + cfg["action_window_seconds"]
    results = []
    previous_start = None
    for index in range(count):
        due = scoring_start + index * cfg["interval_seconds"]
        if previous_start is not None:
            # Never catch up a delayed schedule by sending a burst.
            due = max(due, previous_start + cfg["interval_seconds"])
        if not wait_until(due, stop):
            break
        now = time.monotonic()
        if now >= deadline:
            log.write("action_window_exhausted", attempted=len(results), planned=count)
            break
        previous_start = now
        remaining = deadline - now
        timeout = min(cfg["timeout_seconds"], remaining)
        if timeout < 0.01:
            break
        request_id = uuid.uuid4().hex  # Same format in both HTTP cases; no case label on wire.
        began = stamp()
        log.write("action_started", index=index + 1, action_started=began,
                  target_ip=cfg["target_ip"], request_id=request_id,
                  target_port=cfg["scan_ports"][index] if case == "S1" else cfg["service_port"])
        if case == "S1":
            result = tcp_attempt(cfg, cfg["scan_ports"][index], timeout)
        else:
            result = login_attempt(cfg, case == "B0", request_id, timeout, attempt_index=index)
        result.update(index=index + 1, target_ip=cfg["target_ip"])
        log.write("action_finished", **result)
        results.append(result)
    return {"planned": count, "attempted": len(results), "results": results,
            "all_actions_attempted": len(results) == count,
            "expected_http_responses": (
                sum(row.get("expected_response_observed", False) for row in results)
                if case != "S1" else None)}
