#!/usr/bin/env python3
"""Zero-key safety cycle test — fully automated, no interaction needed.

Card must be on the reader before starting.
Sequence: keyver -> check -> dummyburn -> keyver -> reset -> keyver -> check
Aborts immediately on any failure.
"""

import serial, time, sys, re

from serial_config import get_serial_baud, get_serial_port

PORT = get_serial_port()
BAUD = get_serial_baud()

GREEN = '\033[92m'
RED = '\033[91m'
BOLD = '\033[1m'
DIM = '\033[2m'
RESET = '\033[0m'


def drain(ser, wait=0.3):
    time.sleep(wait)
    out = b""
    while True:
        chunk = ser.read(ser.in_waiting or 1)
        if not chunk:
            break
        out += chunk
    return out.decode(errors="replace")


def send_cmd(ser, cmd, wait=3.0):
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


def step(name, condition, detail=""):
    if condition:
        print(f"  {GREEN}{BOLD}PASS{RESET}: {name}")
    else:
        print(f"  {RED}{BOLD}FAIL{RESET}: {name}")
        if detail:
            print(f"       {detail}")
    return condition


def extract_key_versions(text):
    versions = {}
    for m in re.finditer(r'Key (\d) version: 0x([0-9A-Fa-f]+)', text):
        versions[int(m.group(1))] = int(m.group(2), 16)
    return versions


def main():
    print(f"\n{BOLD}{'='*60}")
    print(f"  ZERO-KEY SAFETY CYCLE TEST (automated)")
    print(f"{'='*60}{RESET}\n")

    ser = serial.Serial(PORT, BAUD, timeout=1)
    time.sleep(4)
    drain(ser, 1.0)

    resp = send_cmd(ser, "help", 1.0)
    if "keyver" not in resp:
        print(f"{RED}keyver command not found{RESET}")
        ser.close()
        sys.exit(1)

    time.sleep(1)

    # Step 0: keyver — determine starting state
    print(f"{BOLD}[0] keyver — determine starting state{RESET}")
    resp = send_cmd(ser, "keyver", 10.0)
    print(f"  {DIM}{resp.strip()}{RESET}")
    versions = extract_key_versions(resp)
    all_factory = all(v == 0x00 for v in versions.values()) and len(versions) == 5
    all_reset = all(v == 0x01 for v in versions.values()) and len(versions) == 5
    if not (all_factory or all_reset):
        print(f"{RED}ABORT: unexpected key versions: {versions}{RESET}")
        ser.close()
        sys.exit(1)
    print(f"  Card state: {'FACTORY BLANK' if all_factory else 'POST-RESET (0x01)'}")

    # If post-reset (0x01), wipe with zero keys to reach factory state
    if all_reset:
        print(f"\n{BOLD}[0a] wipe — return to factory state{RESET}")
        send_cmd(ser, "keys 00000000000000000000000000000000 00000000000000000000000000000000 00000000000000000000000000000000 00000000000000000000000000000000 00000000000000000000000000000000", 3.0)
        resp = send_cmd(ser, "wipe", 20.0)
        print(f"  {DIM}{resp.strip()}{RESET}")
        if not step("wipe SUCCESS", "SUCCESS" in resp):
            ser.close()
            sys.exit(1)
        time.sleep(1)

    time.sleep(1)

    # Step 1: check — auth with zero keys
    print(f"\n{BOLD}[1/6] check (auth with zero keys){RESET}")
    resp = send_cmd(ser, "check", 10.0)
    print(f"  {DIM}{resp.strip()}{RESET}")
    if not step("auth SUCCESS", "SUCCESS" in resp):
        print(f"{RED}ABORT: zero-key auth failed{RESET}")
        ser.close()
        sys.exit(1)

    time.sleep(1)

    # Step 2: dummyburn
    print(f"\n{BOLD}[2/6] dummyburn{RESET}")
    resp = send_cmd(ser, "dummyburn", 15.0)
    print(f"  {DIM}{resp.strip()}{RESET}")
    if not step("burn SUCCESS", "SUCCESS" in resp):
        print(f"{RED}ABORT: dummyburn failed{RESET}")
        ser.close()
        sys.exit(1)

    time.sleep(1)

    # Step 3: keyver — expect PROVISIONED (all changed)
    print(f"\n{BOLD}[3/6] keyver (expect PROVISIONED){RESET}")
    resp = send_cmd(ser, "keyver", 10.0)
    print(f"  {DIM}{resp.strip()}{RESET}")
    versions = extract_key_versions(resp)
    if not step("all keys changed", all(v != 0x00 for v in versions.values()) and len(versions) == 5, f"Got: {versions}"):
        ser.close()
        sys.exit(1)

    time.sleep(1)

    # Step 4: wipe — dummyburn sets key versions to 0x01 (keys are still zeros).
    # resetNdefOnly rejects non-factory versions, so use wipe with zero keys.
    print(f"\n{BOLD}[4/6] wipe (zero keys, to restore factory state){RESET}")
    send_cmd(ser, "keys 00000000000000000000000000000000 00000000000000000000000000000000 00000000000000000000000000000000 00000000000000000000000000000000 00000000000000000000000000000000", 3.0)
    resp = send_cmd(ser, "wipe", 20.0)
    print(f"  {DIM}{resp.strip()}{RESET}")
    if not step("wipe SUCCESS", "SUCCESS" in resp):
        print(f"{RED}ABORT: wipe failed{RESET}")
        ser.close()
        sys.exit(1)

    time.sleep(1)

    # Step 5: keyver — expect 0x00 (factory after wipe)
    print(f"\n{BOLD}[5/6] keyver (expect 0x00 after wipe){RESET}")
    resp = send_cmd(ser, "keyver", 10.0)
    print(f"  {DIM}{resp.strip()}{RESET}")
    versions = extract_key_versions(resp)
    if not step("all keys 0x00", all(v == 0x00 for v in versions.values()) and len(versions) == 5, f"Got: {versions}"):
        ser.close()
        sys.exit(1)

    time.sleep(1)

    # Step 6: check — auth with zero keys after wipe
    print(f"\n{BOLD}[6/6] check (auth after wipe){RESET}")
    resp = send_cmd(ser, "check", 10.0)
    print(f"  {DIM}{resp.strip()}{RESET}")
    if not step("auth SUCCESS after reset", "SUCCESS" in resp):
        ser.close()
        sys.exit(1)

    print(f"\n{BOLD}{'='*60}")
    total_steps = 7 if all_factory else 7
    print(f"  {GREEN}{BOLD}ALL TESTS PASSED{RESET}")
    print(f"{'='*60}{RESET}\n")
    ser.close()


if __name__ == "__main__":
    main()
