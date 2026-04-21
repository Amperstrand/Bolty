#!/usr/bin/env python3
"""Bolty OTA HTTPS server."""

import argparse
import http.server
import json
import os
import socket
import socketserver
import ssl
import sys
from http import HTTPStatus
from pathlib import Path

OTA_DIR = Path(__file__).parent
CERT_DIR = OTA_DIR / "certs"
DEFAULT_CERT = CERT_DIR / "ota_server_cert.pem"
DEFAULT_KEY = CERT_DIR / "ota_server_key.pem"
ENV_FILE = OTA_DIR.parent.parent / "ota.env"


def load_ota_env() -> dict[str, str]:
    loaded: dict[str, str] = {}
    if not ENV_FILE.exists():
        return loaded
    for raw_line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        loaded[key.strip()] = value.strip()
    return loaded


OTA_ENV = load_ota_env()


class OTAHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(OTA_DIR), **kwargs)

    def _is_authorized(self) -> bool:
        expected_token = os.environ.get("OTA_AUTH_TOKEN") or OTA_ENV.get("OTA_AUTH_TOKEN")
        if not expected_token:
            return True
        return self.headers.get("Authorization") == f"Bearer {expected_token}"

    def _require_authorization(self) -> bool:
        if self._is_authorized():
            return True
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("WWW-Authenticate", 'Bearer realm="bolty-ota"')
        self.end_headers()
        self.wfile.write(b"Unauthorized\n")
        return False

    def do_GET(self):
        if not self._require_authorization():
            return
        super().do_GET()

    def do_HEAD(self):
        if not self._require_authorization():
            return
        super().do_HEAD()

    def log_message(self, fmt, *args):
        sys.stdout.write(f"[serve] {self.address_string()} {fmt % args}\n")
        sys.stdout.flush()


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def main():
    parser = argparse.ArgumentParser(description="Bolty OTA manifest server")
    parser.add_argument("--port", type=int, default=8765, help="Listen port (default: 8765)")
    parser.add_argument("--host", default="0.0.0.0", help="Listen address (default: 0.0.0.0)")
    parser.add_argument("--cert", type=Path, default=DEFAULT_CERT, help="TLS certificate path")
    parser.add_argument("--key", type=Path, default=DEFAULT_KEY, help="TLS private key path")
    args = parser.parse_args()

    manifest = OTA_DIR / "manifest.json"
    if not manifest.exists():
        print(f"[serve] ERROR: {manifest} not found")
        print("[serve] Run scripts/ota/publish.sh first to publish a firmware version.")
        sys.exit(1)

    if not args.cert.exists() or not args.key.exists():
        print(f"[serve] ERROR: TLS cert/key missing: {args.cert} / {args.key}")
        print("[serve] Run scripts/ota/generate_https_cert.sh first.")
        sys.exit(1)

    data = json.loads(manifest.read_text())
    print(f"[serve] Manifest loaded:")
    print(f"[serve]   version_code : {data.get('version_code')}")
    print(f"[serve]   url          : {data.get('url')}")
    print(f"[serve]   size         : {data.get('size')} bytes")
    print()

    local_ip = get_local_ip()
    print(f"[serve] Serving OTA from {OTA_DIR}")
    print(f"[serve] Manifest URL  : https://{local_ip}:{args.port}/manifest.json")
    print(f"[serve] Firmware URL  : https://{local_ip}:{args.port}/{Path(data.get('url', '')).name}")
    print(f"[serve] Listening on  : {args.host}:{args.port}")
    print(f"[serve] TLS cert      : {args.cert}")
    if os.environ.get("OTA_AUTH_TOKEN") or OTA_ENV.get("OTA_AUTH_TOKEN"):
        print("[serve] Auth         : bearer token required")
    else:
        print("[serve] Auth         : disabled")
    print(f"[serve] Press Ctrl+C to stop.")
    print()

    with socketserver.TCPServer((args.host, args.port), OTAHandler) as httpd:
        httpd.allow_reuse_address = True
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(args.cert), keyfile=str(args.key))
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[serve] Stopped.")


if __name__ == "__main__":
    main()
