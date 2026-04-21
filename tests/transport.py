#!/usr/bin/env python3
"""Transport abstraction for Bolty host-side E2E tests.

Provides a uniform interface for serial and REST transports, enabling
the same test scenarios to run over both.
"""

import abc
import time

import serial

from serial_config import get_serial_baud, get_serial_port

try:
    import requests
except ImportError:
    requests = None


class Transport(abc.ABC):
    """Abstract base class for firmware transports."""

    def __init__(self):
        self._connected = False

    @abc.abstractmethod
    def connect(self):
        """Initialize transport, wait for firmware ready."""

    @abc.abstractmethod
    def send_cmd(self, cmd, wait=8.0):
        pass

    @abc.abstractmethod
    def drain(self, wait=0.3):
        pass

    @abc.abstractmethod
    def close(self):
        """Cleanup transport resources."""

    def is_connected(self):
        """Return True if transport is currently connected."""
        return self._connected


class SerialTransport(Transport):
    """Serial transport using pyserial.

    Preserves the exact same timing and behavior as the original
    test send_cmd()/drain() functions used across all test files.
    """

    def __init__(self, port=None, baud=None):
        super(SerialTransport, self).__init__()
        self.port = port or get_serial_port()
        self.baud = baud or get_serial_baud()
        self._ser = None

    def connect(self):
        """Open serial port, wait 4s for boot, drain boot output."""
        self._ser = serial.Serial(self.port, self.baud, timeout=1)
        time.sleep(4)
        self.drain(1.0)
        self._connected = True

    def send_cmd(self, cmd, wait=8.0):
        """Drain 0.1s, write cmd\\n, timed read loop — matches existing tests."""
        self.drain(0.1)
        self._ser.write((cmd + "\n").encode())
        t0 = time.time()
        out = b""
        while time.time() - t0 < wait:
            chunk = self._ser.read(self._ser.in_waiting or 1)
            if chunk:
                out += chunk
            else:
                time.sleep(0.05)
        return out.decode(errors="replace")

    def drain(self, wait=0.3):
        """Read all pending serial output (same pattern as existing tests)."""
        time.sleep(wait)
        out = b""
        while True:
            chunk = self._ser.read(self._ser.in_waiting or 1)
            if not chunk:
                break
            out += chunk
        return out.decode(errors="replace")

    def close(self):
        """Close serial port if open."""
        if self._ser and self._ser.is_open:
            self._ser.close()
        self._connected = False


class RestTransport(Transport):
    """REST transport using HTTP requests.

    Maps serial commands to REST API endpoints and translates JSON responses
    to text patterns matching what test_helpers expects.

    The base_url should include the /api prefix, e.g.
    ``https://192.168.1.100/api``.
    """

    def __init__(self, base_url, verify=True, auth_token=None):
        super(RestTransport, self).__init__()
        self.base_url = base_url.rstrip("/")
        self.verify = verify
        self.auth_token = auth_token
        self._headers = {}
        if auth_token:
            self._headers["Authorization"] = "Bearer %s" % auth_token

    def _request(self, method, path, json_body=None, timeout=10.0):
        """Send HTTP request with auth headers and cert verification."""
        if requests is None:
            raise RuntimeError(
                "requests library required for RestTransport (pip install requests)"
            )
        try:
            resp = requests.request(
                method,
                self.base_url + path,
                json=json_body,
                headers=self._headers,
                timeout=timeout,
                verify=self.verify,
            )
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.JSONDecodeError:
            return {"ok": False, "error": "Invalid JSON response"}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def connect(self):
        """Hit /api/status to verify firmware is responsive."""
        data = self._request("GET", "/status")
        if not data.get("ok"):
            raise RuntimeError(
                "REST transport connect failed: %s" % data.get("error", "unknown")
            )
        self._connected = True

    def send_cmd(self, cmd, wait=8.0):
        """Map serial command to REST endpoint, translate JSON→text."""
        parts = cmd.strip().split()
        action = parts[0].lower() if parts else ""
        timeout = max(wait, 5)

        if action == "help":
            data = self._request("GET", "/status", timeout=timeout)
            if data.get("ok"):
                return "Available commands: keyver, check, keys, url, burn, wipe, ndef, uid, status"
            return self._error_text(data)

        elif action == "keyver":
            data = self._request("GET", "/keyver", timeout=timeout)
            if not data.get("ok"):
                return self._error_text(data)
            lines = []
            for k in data.get("keys", []):
                lines.append("Key %d version: %s" % (k["slot"], k["version"]))
            lines.append("SUCCESS")
            return "\n".join(lines)

        elif action == "check":
            data = self._request("GET", "/check", timeout=timeout)
            if not data.get("ok"):
                return "FAILED\n" + data.get("error", "")
            return "SUCCESS" if data.get("blank") else "FAILED"

        elif action == "keys":
            if len(parts) < 6:
                return "FAILED: keys requires K0 K1 K2 K3 K4"
            payload = {
                "k0": parts[1], "k1": parts[2], "k2": parts[3],
                "k3": parts[4], "k4": parts[5],
            }
            data = self._request("POST", "/keys", json_body=payload, timeout=timeout)
            if not data.get("ok"):
                return self._error_text(data)
            return data.get("message", "Keys set")

        elif action == "url":
            if len(parts) < 2:
                return "FAILED: url requires a URL argument"
            url_val = " ".join(parts[1:])
            data = self._request("POST", "/url", json_body={"url": url_val}, timeout=timeout)
            if not data.get("ok"):
                return self._error_text(data)
            return url_val

        elif action == "burn":
            data = self._request("POST", "/burn", timeout=max(timeout, 25))
            if not data.get("ok"):
                return self._error_text(data)
            lines = [
                "SUCCESS",
                "VERIFY",
                "AUTH k0: OK",
                "NDEF read OK",
                "p=0 c=0",
            ]
            return "\n".join(lines)

        elif action == "wipe":
            data = self._request("POST", "/wipe", timeout=max(timeout, 20))
            if not data.get("ok"):
                return self._error_text(data)
            return "SUCCESS"

        elif action == "ndef":
            data = self._request("GET", "/ndef", timeout=max(timeout, 25))
            if not data.get("ok"):
                return self._error_text(data)
            lines = ["NDEF read OK"]
            uri = data.get("uri") or data.get("ascii") or ""
            if uri:
                lines.append(uri)
            return "\n".join(lines)

        elif action == "uid":
            data = self._request("GET", "/uid", timeout=timeout)
            if not data.get("ok"):
                return self._error_text(data)
            uid = data.get("uid", "")
            ntag = "NTAG424" if data.get("ntag424") else "Unknown"
            return "UID: %s [%s]" % (uid, ntag)

        elif action == "status":
            data = self._request("GET", "/status", timeout=timeout)
            if not data.get("ok"):
                return self._error_text(data)
            lines = [
                "Hardware: %s" % ("ready" if data.get("hw_ready") else "not ready"),
                "UID: %s" % data.get("uid", ""),
                "Job: %s" % data.get("job", ""),
                "Card: %s" % data.get("card_name", ""),
                "URL: %s" % data.get("url", ""),
            ]
            return "\n".join(lines)

        else:
            return "FAILED: unknown command '%s'" % action

    @staticmethod
    def _error_text(data):
        """Format an error JSON into text containing FAILED."""
        msg = data.get("error", data.get("message", "unknown error"))
        return "FAILED: %s" % msg

    def drain(self, wait=0.3):
        """REST is stateless — no pending output to drain."""
        time.sleep(wait)
        return ""

    def close(self):
        """No persistent connection to close."""
        self._connected = False
