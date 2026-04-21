#!/usr/bin/env python3
"""Bolty controlled burn test — headless serial interface."""

import time

from test_helpers import STATIC_K0, STATIC_K1, STATIC_K2
from transport import SerialTransport

K3 = "44444444444444444444444444444444"
K4 = "55555555555555555555555555555555"
URL = "lnurlw://testcard.local/test?p=00000000000000000000000000000000&c=0000000000000000"


def main():
    transport = SerialTransport()
    print(f"Connecting to {transport.port}...")
    transport.connect()

    # Hard reset ESP32 via DTR/RTS (needs raw serial access)
    ser = transport._ser
    print("Hard resetting ESP32...")
    ser.setDTR(False)
    ser.setRTS(True)
    time.sleep(0.1)
    ser.setRTS(False)
    time.sleep(0.1)
    ser.setDTR(True)
    ser.setRTS(True)
    time.sleep(0.1)

    # Wait for boot after reset
    print("Waiting for boot (5s)...")
    time.sleep(5)
    boot_output = transport.drain(1.0)
    print("=== BOOT OUTPUT ===")
    print(boot_output)
    print("=== END BOOT ===")

    if "Setup done!" not in boot_output:
        print("WARNING: 'Setup done!' not found in boot output")

    # Show current status
    print("\n--- Sending 'help' ---")
    resp = transport.send_cmd("help", 1.0)
    print(resp)

    print("\n--- Sending 'status' ---")
    resp = transport.send_cmd("status", 1.0)
    print(resp)

    # === PHASE 1: Set keys (CARD OFF READER) ===
    print("\n" + "=" * 60)
    print("PHASE 1: Setting test keys")
    print("MAKE SURE CARD IS OFF THE READER NOW")
    print("=" * 60)
    input("Press ENTER when card is OFF the reader...")

    keys_cmd = f"keys {STATIC_K0} {STATIC_K1} {STATIC_K2} {K3} {K4}"
    print(f"\nSending: keys <k0={STATIC_K0}> <k1={STATIC_K1}> <k2={STATIC_K2}> <k3={K3}> <k4={K4}>")
    resp = transport.send_cmd(keys_cmd, 1.0)
    print(resp)

    # Verify keys were set
    print("\n--- Verifying with 'status' ---")
    resp = transport.send_cmd("status", 1.0)
    print(resp)

    # === PHASE 2: Set URL (CARD STILL OFF) ===
    print("\n" + "=" * 60)
    print("PHASE 2: Setting test URL")
    print("=" * 60)

    print(f"\nSending: url {URL}")
    resp = transport.send_cmd(f"url {URL}", 1.0)
    print(resp)

    # Verify URL
    print("\n--- Verifying with 'status' ---")
    resp = transport.send_cmd("status", 1.0)
    print(resp)

    # === PHASE 3: Burn (CARD ON READER) ===
    print("\n" + "=" * 60)
    print("PHASE 3: Burning card")
    print("PLACE THE CARD ON THE READER NOW")
    print("=" * 60)
    input("Press ENTER when card is ON the reader...")

    # First check uid
    print("\n--- Checking UID ---")
    resp = transport.send_cmd("uid", 1.0)
    print(resp)

    # Burn
    print("\n--- Sending 'burn' ---")
    resp = transport.send_cmd("burn", 5.0)
    print(resp)

    # === PHASE 4: Verify ===
    print("\n" + "=" * 60)
    print("PHASE 4: Verifying")
    print("=" * 60)

    print("\n--- Status after burn ---")
    resp = transport.send_cmd("status", 1.0)
    print(resp)

    print("\n--- UID after burn ---")
    resp = transport.send_cmd("uid", 1.0)
    print(resp)

    # === PHASE 5: Wipe ===
    print("\n" + "=" * 60)
    print("PHASE 5: Wiping card (keep card on reader)")
    print("=" * 60)
    input("Press ENTER to wipe...")

    print("\n--- Sending 'wipe' ---")
    resp = transport.send_cmd("wipe", 5.0)
    print(resp)

    print("\n--- Status after wipe ---")
    resp = transport.send_cmd("status", 1.0)
    print(resp)

    print("\n" + "=" * 60)
    print("TEST COMPLETE")
    print("=" * 60)

    transport.close()


if __name__ == "__main__":
    main()
