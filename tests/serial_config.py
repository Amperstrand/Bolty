#!/usr/bin/env python3
"""Shared serial defaults for Bolty hardware tests."""

from __future__ import annotations

import os


DEFAULT_PORT = "/dev/serial/by-id/usb-M5STACK_Inc._M5_Serial_Converter_9D529068B4-if00-port0"
DEFAULT_BAUD = 115200


def get_serial_port() -> str:
    return os.environ.get("BOLTY_PORT", DEFAULT_PORT)


def get_serial_baud() -> int:
    return int(os.environ.get("BOLTY_BAUD", str(DEFAULT_BAUD)))
