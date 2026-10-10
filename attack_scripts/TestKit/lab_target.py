#!/usr/bin/env python3
"""Disposable HTTP authentication target using public dummy credentials."""
from __future__ import annotations

import argparse
import base64
import binascii
import hmac
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from sentrix_lab import VERSION
from sentrix_lab.common import (
    APP_ID, LAB_PASSWORD, LAB_USER, JsonlLog, safe_ipv4, stamp,
)


class LabServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, log):
        self.evidence = log
        super().__init__(address, LabHandler)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(3)
        self.evidence.write("tcp_accepted", client_ip=address[0], client_port=address[1],
                            local_ip=connection.getsockname()[0],
                            local_port=connection.getsockname()[1])
        return connection, address


class LabHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "SENTRiXDisposableLab/1.0"

    def log_message(self, *args):
        pass

    def do_GET(self):
        request_id = self.headers.get("X-Lab-Request-ID", "")[:64]
        accepted = stamp()
        if self.path == "/__sentrix_lab__/health":
            status = 200
            outcome = "health"
            body = {
                "application": APP_ID, "kit_version": VERSION,
                "client_ip": self.client_address[0],
                "local_ip": self.connection.getsockname()[0],
                "service_port": self.server.server_port,
            }
        elif self.path == "/account":
            username = password = ""
            header = self.headers.get("Authorization", "")
            if header.startswith("Basic ") and len(header) <= 1024:
                try:
                    decoded = base64.b64decode(header[6:], validate=True).decode("utf-8")
                    username, password = decoded.split(":", 1)
                except (ValueError, UnicodeDecodeError, binascii.Error):
                    pass
            authenticated = (
                hmac.compare_digest(username.encode(), LAB_USER.encode()) and
                hmac.compare_digest(password.encode(), LAB_PASSWORD.encode()))
            status = 200 if authenticated else 401
            outcome = "authenticated" if authenticated else "authentication_failed"
            body = {"application": APP_ID, "result": outcome}
        else:
            status, outcome, body = 404, "not_found", {"result": "not_found"}
        self.server.evidence.write(
            "request_received", request_received=accepted, request_id=request_id,
            client_ip=self.client_address[0], client_port=self.client_address[1],
            local_ip=self.connection.getsockname()[0], local_port=self.server.server_port,
            path=self.path[:256], intended_status=status, authentication_outcome=outcome)
        data = json.dumps(body, separators=(",", ":")).encode()
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            if status == 401:
                self.send_header("WWW-Authenticate", 'Basic realm="Disposable Lab"')
            self.end_headers()
            self.wfile.write(data)
            self.wfile.flush()
            self.server.evidence.write("response_sent", request_id=request_id,
                                       status=status, client_ip=self.client_address[0],
                                       client_port=self.client_address[1])
        except OSError as exc:
            self.server.evidence.write("response_error", request_id=request_id,
                                       error=f"{type(exc).__name__}: {exc}")
        self.close_connection = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", required=True, help="One LAN IPv4, or 127.0.0.1 for local checks.")
    parser.add_argument("--port", type=int, default=8088)
    parser.add_argument("--log", default="target_evidence/service.jsonl")
    args = parser.parse_args()
    try:
        safe_ipv4(args.bind, allow_loopback=True)
        if not 1 <= args.port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        evidence = JsonlLog(Path(args.log), {"component": "lab_target", "kit_version": VERSION},
                            append=True)
        server = LabServer((args.bind, args.port), evidence)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"Setup error: {exc}\n")
    evidence.write("service_started", bind=args.bind, port=args.port)
    print(f"Disposable lab target: http://{args.bind}:{args.port}", flush=True)
    print(f"Evidence: {Path(args.log).resolve()}; Ctrl+C stops the service.", flush=True)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        evidence.write("service_stopped")
        evidence.close()


if __name__ == "__main__":
    main()
