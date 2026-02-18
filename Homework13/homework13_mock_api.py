"""
Homework 13: Mock AV/FW API interaction

How to run:
1) python homework13_mock_api.py

Optional environment variable:
- MOCK_API_KEY (default: demo-key)

What this script does:
- starts a local mock API server
- sends an authenticated request with API key
- prints JSON response (scan status + firewall rules)
"""

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import request, error

HOST = "127.0.0.1"
PORT = 8089
API_PATH = "/api/v1/security/status"

API_KEY = os.getenv("MOCK_API_KEY", "demo-key")


class MockHandler(BaseHTTPRequestHandler):
    def _send_json(self, status_code, payload):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path != API_PATH:
            self._send_json(404, {"error": "not_found"})
            return

        client_key = self.headers.get("X-API-Key")
        if client_key != API_KEY:
            self._send_json(401, {"error": "unauthorized", "message": "bad api key"})
            return

        payload = {
            "service": "mock-av-fw",
            "timestamp": int(time.time()),
            "scan": {
                "target": "sample.exe",
                "status": "completed",
                "verdict": "clean",
                "engines": {"detected": 0, "total": 68},
            },
            "firewall": {
                "policy": "default-deny-inbound",
                "rules": [
                    {"id": "FW-1001", "action": "allow", "proto": "tcp", "port": 443},
                    {"id": "FW-1002", "action": "allow", "proto": "tcp", "port": 22},
                    {"id": "FW-1003", "action": "deny", "proto": "any", "port": "*"},
                ],
            },
        }
        self._send_json(200, payload)

    def log_message(self, fmt, *args):
        return


def run_mock_server():
    server = HTTPServer((HOST, PORT), MockHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


def call_api():
    url = f"http://{HOST}:{PORT}{API_PATH}"
    req = request.Request(url, method="GET", headers={"X-API-Key": API_KEY})

    # Disable system proxy for local mock endpoint.
    opener = request.build_opener(request.ProxyHandler({}))

    last_err = None
    for _ in range(10):
        try:
            with opener.open(req, timeout=5) as resp:
                raw = resp.read().decode("utf-8")
                data = json.loads(raw)
            print("API response JSON:")
            print(json.dumps(data, ensure_ascii=False, indent=2))
            return
        except (error.URLError, error.HTTPError) as exc:
            last_err = exc
            time.sleep(0.1)

    raise RuntimeError(f"Mock API request failed: {last_err}")


if __name__ == "__main__":
    server = run_mock_server()
    try:
        call_api()
    finally:
        server.shutdown()
        server.server_close()
