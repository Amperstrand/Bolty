#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import socket
import ssl
import subprocess
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
BOLTY_DIR = SCRIPT_DIR.parent.parent
ENV_FILE = BOLTY_DIR / "ota.env"
CERT_FILE = SCRIPT_DIR / "certs" / "ota_ca_cert.pem"
SERVER_SCRIPT = SCRIPT_DIR / "serve.py"
MANIFEST_FILE = SCRIPT_DIR / "manifest.json"


def load_ota_env() -> dict[str, str]:
    if not ENV_FILE.exists():
        return {}
    loaded: dict[str, str] = {}
    for raw_line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        loaded[key.strip()] = value.strip()
    return loaded


def reserve_local_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


class TestHttpsOtaServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not SERVER_SCRIPT.exists():
            raise unittest.SkipTest(f"serve.py not found at {SERVER_SCRIPT}")
        if not CERT_FILE.exists():
            raise unittest.SkipTest(
                f"CA certificate not found at {CERT_FILE}. Run scripts/ota/generate_https_cert.sh first."
            )
        if not MANIFEST_FILE.exists():
            raise unittest.SkipTest(
                f"manifest.json not found at {MANIFEST_FILE}. Run scripts/ota/publish.sh first."
            )

        env = load_ota_env()
        cls.token = env.get("OTA_AUTH_TOKEN")
        if not cls.token:
            raise unittest.SkipTest("OTA_AUTH_TOKEN missing from ota.env")

        cls.port = reserve_local_port()
        cls.server = subprocess.Popen(
            [
                "python3",
                str(SERVER_SCRIPT),
                "--host",
                "127.0.0.1",
                "--port",
                str(cls.port),
            ],
            cwd=str(BOLTY_DIR),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        deadline = time.time() + 10.0
        while time.time() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", cls.port), timeout=0.5):
                    return
            except OSError:
                time.sleep(0.1)

        cls.server.kill()
        raise RuntimeError("HTTPS OTA server did not start in time")

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "server") and cls.server.poll() is None:
            cls.server.terminate()
            try:
                cls.server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                cls.server.kill()

    def _fetch_manifest(self, token: str | None) -> tuple[int, str]:
        ctx = ssl.create_default_context(cafile=str(CERT_FILE))
        headers = {}
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(
            f"https://127.0.0.1:{self.port}/manifest.json",
            headers=headers,
        )
        try:
            with urllib.request.urlopen(request, context=ctx, timeout=10) as response:
                return response.status, response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode("utf-8")

    def test_manifest_requires_bearer_token(self):
        status, body = self._fetch_manifest(None)
        self.assertEqual(status, 401)
        self.assertEqual(body.strip(), "Unauthorized")

    def test_manifest_returns_signed_payload_over_https(self):
        status, body = self._fetch_manifest(self.token)
        self.assertEqual(status, 200)
        manifest = json.loads(body)
        self.assertGreater(manifest["version_code"], 0)
        self.assertTrue(str(manifest["url"]).startswith("https://"))
        self.assertEqual(len(manifest["sha256"]), 64)
        self.assertTrue(manifest["signature"])


if __name__ == "__main__":
    unittest.main()
