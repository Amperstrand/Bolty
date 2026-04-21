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

    Designed for firmware REST API endpoints (being added in parallel).
    Follows the expected API shape::

        GET  /api/status          -> firmware status JSON
        POST /api/cmd  {"cmd": …} -> command response text

    The base_url should include the /api prefix, e.g.
    ``https://192.168.1.100/api``.
    """

    def __init__(self, base_url, verify=True):
        super(RestTransport, self).__init__()
        self.base_url = base_url.rstrip("/")
        self.verify = verify

    def connect(self):
        """Hit /api/status to verify firmware is responsive."""
        if requests is None:
            raise RuntimeError(
                "requests library required for RestTransport (pip install requests)"
            )
        try:
            resp = requests.get(
                self.base_url + "/status", timeout=10, verify=self.verify
            )
            resp.raise_for_status()
        except Exception as e:
            raise RuntimeError("REST transport connect failed: %s" % e)
        self._connected = True

    def send_cmd(self, cmd, wait=8.0):
        """POST command to /api/cmd, return response text."""
        if requests is None:
            raise RuntimeError("requests library required for RestTransport")
        try:
            resp = requests.post(
                self.base_url + "/cmd",
                json={"cmd": cmd},
                timeout=max(wait, 5),
                verify=self.verify,
            )
            resp.raise_for_status()
            return resp.text
        except Exception as e:
            return "ERROR: %s" % e

    def drain(self, wait=0.3):
        """REST is stateless — no pending output to drain."""
        time.sleep(wait)
        return ""

    def close(self):
        """No persistent connection to close."""
        self._connected = False
