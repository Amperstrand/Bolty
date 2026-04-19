#!/usr/bin/env python3
"""Test PICC data decryption on burned card.

Burns card, reads NDEF, then runs picc command to verify
p= decryption and c= verification work on real hardware.
"""

import serial, time, sys, re
from serial_config import get_serial_port, get_serial_baud

PORT = get_serial_port()
BAUD = get_serial_baud()

K0 = "11111111111111111111111111111111"
K1 = "22222222222222222222222222222222"
K2 = "33333333333333333333333333333333"
K3 = K1
K4 = K2
TEST_URL = "https://example.com/bolt"

GREEN = '\033[92m'
RED = '\033[91m'
BOLD = '\033[1m'
RESET_C = '\033[0m'


def drain(ser, wait=0.3):
    time.sleep(wait)
    out = b""
    while True:
        chunk = ser.read(ser.in_waiting or 1)
        if not chunk:
            break
        out += chunk
    return out.decode(errors="replace")


def send_cmd(ser, cmd, wait=8.0):
    drain(ser, 0.1)
    ser.write((cmd + "\n").encode())
    t0 = time.time()
    out = b""
    while time.time() - t0 < wait:
        chunk = ser.read(ser.in_waiting or 1)
        if chunk:
            out += chunk
        else:
            time.sleep(0.05)
    return out.decode(errors="replace")


def step(num, name, condition, detail=""):
    status = f"{GREEN}{BOLD}PASS{RESET_C}" if condition else f"{RED}{BOLD}FAIL{RESET_C}"
    print(f"  [{num}] {status}: {name}")
    if detail and not condition:
        print(f"       {detail}")
    return condition


def main():
    print(f"\n{BOLD}{'='*60}")
    print(f"  PICC DATA DECRYPTION TEST")
    print(f"{'='*60}{RESET_C}\n")

    ser = serial.Serial(PORT, BAUD, timeout=1)
    time.sleep(4)
    drain(ser, 1.0)

    # Verify firmware
    resp = send_cmd(ser, "help", 2.0)
    if "picc" not in resp:
        print(f"{RED}Firmware missing picc command{RESET_C}")
        ser.close()
        sys.exit(1)

    # Phase 1: Burn card
    print(f"\n{BOLD}PHASE 1: Burn card{RESET_C}")
    resp = send_cmd(ser, f"keys {K0} {K1} {K2} {K3} {K4}", 3.0)
    time.sleep(0.3)
    resp = send_cmd(ser, f"url {TEST_URL}", 3.0)
    time.sleep(0.3)
    print(f"  {BOLD}>>> BURNING CARD <<<{RESET_C}")
    resp = send_cmd(ser, "burn", 30.0)
    step("1a", "burn SUCCESS", "SUCCESS" in resp, resp.strip()[-200:])

    # Phase 2: Read NDEF
    print(f"\n{BOLD}PHASE 2: Read NDEF{RESET_C}")
    resp = send_cmd(ser, "ndef", 25.0)
    step("2a", "NDEF read OK", "OK" in resp, resp.strip()[-200:])

    # Extract URL from NDEF for reference
    url_match = re.search(r'https?://[^\s]+', resp)
    if url_match:
        print(f"  URL: {url_match.group(0)}")

    # Phase 3: PICC decrypt + verify
    print(f"\n{BOLD}PHASE 3: PICC decrypt + verify{RESET_C}")
    resp = send_cmd(ser, "picc", 25.0)
    print(f"  Response (last 500 chars):")
    for line in resp.strip().split('\n')[-15:]:
        print(f"    {line.strip()}")

    step("3a", "picc URL found", "URL:" in resp, "No URL in picc output")
    step("3b", "p= decrypted (UID found)", "UID:" in resp, "No UID in picc output")
    step("3c", "c= verified", "UID match:" in resp, "No UID match in picc output")

    # Check if UID match is YES
    uid_match = re.search(r'UID match: (YES|NO)', resp)
    if uid_match:
        step("3d", "UID match YES", uid_match.group(1) == "YES", f"Got: {uid_match.group(1)}")
    else:
        step("3d", "UID match found", False, "No UID match line in output")

    # Phase 4: Wipe
    print(f"\n{BOLD}PHASE 4: Wipe card{RESET_C}")
    resp = send_cmd(ser, f"keys {K0} {K1} {K2} {K3} {K4}", 3.0)
    time.sleep(0.3)
    resp = send_cmd(ser, "wipe", 25.0)
    step("4a", "wipe SUCCESS", "SUCCESS" in resp, resp.strip()[-200:])

    # Summary
    print(f"\n{BOLD}{'='*60}")
    print(f"  PICC DATA DECRYPTION TEST COMPLETE")
    print(f"{'='*60}{RESET_C}\n")

    ser.close()


if __name__ == "__main__":
    main()
