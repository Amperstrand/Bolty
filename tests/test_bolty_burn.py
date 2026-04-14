#!/usr/bin/env python3
"""Bolty controlled burn test — headless serial interface."""

import serial, time, sys

PORT = '/dev/serial/by-id/usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0'
BAUD = 115200
TIMEOUT = 3

# Test keys: each exactly 32 hex chars (16 bytes)
K0 = "11111111111111111111111111111111"
K1 = "22222222222222222222222222222222"
K2 = "33333333333333333333333333333333"
K3 = "44444444444444444444444444444444"
K4 = "55555555555555555555555555555555"

# Test URL
URL = "lnurlw://testcard.local/test?p=00000000000000000000000000000000&c=0000000000000000"


def drain(ser, timeout=0.5):
    """Read all available bytes from serial."""
    time.sleep(timeout)
    out = b""
    while True:
        chunk = ser.read(ser.in_waiting or 1)
        if not chunk:
            break
        out += chunk
    return out.decode(errors="replace")


def send_cmd(ser, cmd, wait=1.0):
    """Send a command and return the response."""
    ser.write((cmd + "\n").encode())
    resp = drain(ser, wait)
    return resp


def main():
    print(f"Connecting to {PORT}...")
    ser = serial.Serial(PORT, BAUD, timeout=TIMEOUT)

    # Hard reset
    print("Hard resetting ESP32...")
    ser.setDTR(False)
    ser.setRTS(True)
    time.sleep(0.1)
    ser.setRTS(False)
    time.sleep(0.1)
    ser.setDTR(True)
    ser.setRTS(True)
    time.sleep(0.1)

    # Wait for boot
    print("Waiting for boot (5s)...")
    time.sleep(5)
    boot_output = drain(ser, 1.0)
    print("=== BOOT OUTPUT ===")
    print(boot_output)
    print("=== END BOOT ===")

    if "Setup done!" not in boot_output:
        print("WARNING: 'Setup done!' not found in boot output")

    # Show current status
    print("\n--- Sending 'help' ---")
    resp = send_cmd(ser, "help")
    print(resp)

    print("\n--- Sending 'status' ---")
    resp = send_cmd(ser, "status")
    print(resp)

    # === PHASE 1: Set keys (CARD OFF READER) ===
    print("\n" + "=" * 60)
    print("PHASE 1: Setting test keys")
    print("MAKE SURE CARD IS OFF THE READER NOW")
    print("=" * 60)
    input("Press ENTER when card is OFF the reader...")

    keys_cmd = f"keys {K0} {K1} {K2} {K3} {K4}"
    print(f"\nSending: keys <k0={K0}> <k1={K1}> <k2={K2}> <k3={K3}> <k4={K4}>")
    resp = send_cmd(ser, keys_cmd, wait=1.0)
    print(resp)

    # Verify keys were set
    print("\n--- Verifying with 'status' ---")
    resp = send_cmd(ser, "status")
    print(resp)

    # === PHASE 2: Set URL (CARD STILL OFF) ===
    print("\n" + "=" * 60)
    print("PHASE 2: Setting test URL")
    print("=" * 60)

    print(f"\nSending: url {URL}")
    resp = send_cmd(ser, f"url {URL}", wait=1.0)
    print(resp)

    # Verify URL
    print("\n--- Verifying with 'status' ---")
    resp = send_cmd(ser, "status")
    print(resp)

    # === PHASE 3: Burn (CARD ON READER) ===
    print("\n" + "=" * 60)
    print("PHASE 3: Burning card")
    print("PLACE THE CARD ON THE READER NOW")
    print("=" * 60)
    input("Press ENTER when card is ON the reader...")

    # First check uid
    print("\n--- Checking UID ---")
    resp = send_cmd(ser, "uid", wait=1.0)
    print(resp)

    # Burn
    print("\n--- Sending 'burn' ---")
    resp = send_cmd(ser, "burn", wait=5.0)
    print(resp)

    # === PHASE 4: Verify ===
    print("\n" + "=" * 60)
    print("PHASE 4: Verifying")
    print("=" * 60)

    print("\n--- Status after burn ---")
    resp = send_cmd(ser, "status", wait=1.0)
    print(resp)

    print("\n--- UID after burn ---")
    resp = send_cmd(ser, "uid", wait=1.0)
    print(resp)

    # === PHASE 5: Wipe ===
    print("\n" + "=" * 60)
    print("PHASE 5: Wiping card (keep card on reader)")
    print("=" * 60)
    input("Press ENTER to wipe...")

    print("\n--- Sending 'wipe' ---")
    resp = send_cmd(ser, "wipe", wait=5.0)
    print(resp)

    print("\n--- Status after wipe ---")
    resp = send_cmd(ser, "status", wait=1.0)
    print(resp)

    print("\n" + "=" * 60)
    print("TEST COMPLETE")
    print("=" * 60)

    ser.close()


if __name__ == "__main__":
    main()
