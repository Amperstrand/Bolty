#!/usr/bin/env python3
"""
Bolty LAN OTA manifest server.

Serves manifest.json and firmware binaries from the ota/ directory over HTTP.
Run this on the host machine before powering the ESP32 in OTA mode.

Usage:
    python3 scripts/ota/serve.py [--port 8765] [--host 0.0.0.0]
"""

import argparse
import http.server
import json
import os
import socket
import socketserver
import sys
from pathlib import Path

OTA_DIR = Path(__file__).parent


class OTAHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(OTA_DIR), **kwargs)

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
    args = parser.parse_args()

    manifest = OTA_DIR / "manifest.json"
    if not manifest.exists():
        print(f"[serve] ERROR: {manifest} not found")
        print("[serve] Run scripts/ota/publish.sh first to publish a firmware version.")
        sys.exit(1)

    data = json.loads(manifest.read_text())
    print(f"[serve] Manifest loaded:")
    print(f"[serve]   version_code : {data.get('version_code')}")
    print(f"[serve]   url          : {data.get('url')}")
    print(f"[serve]   size         : {data.get('size')} bytes")
    print()

    local_ip = get_local_ip()
    print(f"[serve] Serving OTA from {OTA_DIR}")
    print(f"[serve] Manifest URL  : http://{local_ip}:{args.port}/manifest.json")
    print(f"[serve] Firmware URL  : http://{local_ip}:{args.port}/{Path(data.get('url', '')).name}")
    print(f"[serve] Listening on  : {args.host}:{args.port}")
    print(f"[serve] Press Ctrl+C to stop.")
    print()

    with socketserver.TCPServer((args.host, args.port), OTAHandler) as httpd:
        httpd.allow_reuse_address = True
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[serve] Stopped.")


if __name__ == "__main__":
    main()
