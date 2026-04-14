#!/usr/bin/env python3
"""Regression test for NTAG424 ChangeKey payload sizes.

This is a pre-refactor safety test. It verifies that the library emits the
expected ChangeKey payload sizes during real hardware burn/wipe operations:

- non-master keys (1-4): 21 bytes
- master key (0): 17 bytes

The test also verifies the FULL-mode response parsing fix in
`ntag424_ChangeKey()` (library issue #23): burn/wipe must not print a false
"ChangeKey error!" when the overall operation succeeds.

Card must remain on the reader throughout the run.
"""

import re
import serial
import sys
import time


PORT = "/dev/serial/by-id/usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0"
BAUD = 115200

K0 = "11111111111111111111111111111111"
K1 = "22222222222222222222222222222222"
K2 = "33333333333333333333333333333333"
K3 = K1
K4 = K2
TEST_URL = "https://example.com/bolt"

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
BOLD = "\033[1m"
RESET = "\033[0m"


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


def step(name, condition, detail=""):
    status = f"{GREEN}{BOLD}PASS{RESET}" if condition else f"{RED}{BOLD}FAIL{RESET}"
    print(f"  {status}: {name}")
    if detail and not condition:
        print(f"       {detail}")
    return condition


def verbose(resp):
    for line in resp.strip().split("\n"):
        line = line.strip()
        if line:
            print(f"    {line}")


def extract_key_versions(text):
    versions = {}
    for match in re.finditer(r"Key (\d) version: 0x([0-9A-Fa-f]+)", text):
        versions[int(match.group(1))] = int(match.group(2), 16)
    return versions


def extract_lengths(text):
    return [int(match.group(1)) for match in re.finditer(r"CMDDATA Length:(\d+)", text)]


def expect_changekey_lengths(text, phase_name):
    lengths = extract_lengths(text)
    count_21 = lengths.count(21)
    count_17 = lengths.count(17)
    ok_21 = step(f"{phase_name}: 4 non-master ChangeKey payloads at 21 bytes", count_21 == 4, f"Lengths: {lengths}")
    ok_17 = step(f"{phase_name}: 1 master ChangeKey payload at 17 bytes", count_17 == 1, f"Lengths: {lengths}")
    return ok_21 and ok_17


def ensure_blank(ser):
    print(f"\n{BOLD}Ensure blank starting state{RESET}")
    resp = send_cmd(ser, "keyver", 12.0)
    verbose(resp)
    versions = extract_key_versions(resp)
    if len(versions) < 5:
        print(f"{RED}Could not read all key versions{RESET}")
        sys.exit(1)

    all_factory = all(v == 0x00 for v in versions.values())
    all_changed = all(v != 0x00 for v in versions.values())

    if all_factory:
        print(f"  {GREEN}Card is already factory blank{RESET}")
        return

    if all_changed:
        print(f"  {YELLOW}Card is provisioned or wiped-with-nonzero-versions; trying recovery keys{RESET}")
        send_cmd(ser, f"keys {K0} {K1} {K2} {K3} {K4}", 3.0)
        resp = send_cmd(ser, "wipe", 20.0)
        verbose(resp)
        if "SUCCESS" not in resp:
            print(f"{RED}Cannot wipe card with recovery keys{RESET}")
            sys.exit(1)
    else:
        print(f"  {YELLOW}Mixed state detected; trying reset then recovery wipe{RESET}")
        resp = send_cmd(ser, "reset", 20.0)
        if "SUCCESS" not in resp:
            send_cmd(ser, f"keys {K0} {K1} {K2} {K3} {K4}", 3.0)
            resp = send_cmd(ser, "wipe", 20.0)
            if "SUCCESS" not in resp:
                print(f"{RED}Cannot recover mixed-state card{RESET}")
                sys.exit(1)

    time.sleep(1)
    resp = send_cmd(ser, "keyver", 12.0)
    versions = extract_key_versions(resp)
    if not all(v == 0x00 for v in versions.values()):
        print(f"{RED}Card is not blank after recovery: {versions}{RESET}")
        sys.exit(1)
    resp = send_cmd(ser, "check", 12.0)
    if "SUCCESS" not in resp:
        print(f"{RED}Zero-key auth failed after recovery{RESET}")
        sys.exit(1)


def main():
    print(f"\n{BOLD}{'=' * 60}")
    print("  CHANGEKEY PAYLOAD SIZE REGRESSION TEST")
    print(f"{'=' * 60}{RESET}\n")

    ser = serial.Serial(PORT, BAUD, timeout=1)
    time.sleep(4)
    drain(ser, 1.0)

    resp = send_cmd(ser, "help", 2.0)
    if "keyver" not in resp:
        print(f"{RED}Firmware not responding or missing keyver command{RESET}")
        ser.close()
        sys.exit(1)

    ensure_blank(ser)
    time.sleep(1)

    print(f"\n{BOLD}Phase 1: Burn and inspect ChangeKey payload sizes{RESET}")
    send_cmd(ser, f"keys {K0} {K1} {K2} {K3} {K4}", 3.0)
    send_cmd(ser, f"url {TEST_URL}", 3.0)
    burn_resp = send_cmd(ser, "burn", 25.0)
    verbose(burn_resp)
    if not step("burn overall SUCCESS", "SUCCESS" in burn_resp, burn_resp.strip()[-200:]):
        ser.close()
        sys.exit(1)
    if not expect_changekey_lengths(burn_resp, "burn"):
        ser.close()
        sys.exit(1)

    if not step(
        "burn has no false-negative ChangeKey logging",
        "ChangeKey error! Key:" not in burn_resp,
        burn_resp.strip()[-200:],
    ):
        ser.close()
        sys.exit(1)

    time.sleep(1)

    print(f"\n{BOLD}Phase 2: Wipe and inspect ChangeKey payload sizes{RESET}")
    send_cmd(ser, f"keys {K0} {K1} {K2} {K3} {K4}", 3.0)
    wipe_resp = send_cmd(ser, "wipe", 25.0)
    verbose(wipe_resp)
    if not step("wipe overall SUCCESS", "SUCCESS" in wipe_resp, wipe_resp.strip()[-200:]):
        ser.close()
        sys.exit(1)
    if not expect_changekey_lengths(wipe_resp, "wipe"):
        ser.close()
        sys.exit(1)

    if not step(
        "wipe has no false-negative ChangeKey logging",
        "ChangeKey error! Key:" not in wipe_resp,
        wipe_resp.strip()[-200:],
    ):
        ser.close()
        sys.exit(1)

    time.sleep(1)

    print(f"\n{BOLD}Phase 3: Verify factory-identical state after wipe{RESET}")
    keyver_resp = send_cmd(ser, "keyver", 12.0)
    verbose(keyver_resp)
    versions = extract_key_versions(keyver_resp)
    if not step("all keys back at 0x00", all(v == 0x00 for v in versions.values()) and len(versions) == 5, f"Got: {versions}"):
        ser.close()
        sys.exit(1)

    check_resp = send_cmd(ser, "check", 12.0)
    verbose(check_resp)
    if not step("zero-key auth succeeds after wipe", "SUCCESS" in check_resp):
        ser.close()
        sys.exit(1)

    print(f"\n{BOLD}{'=' * 60}")
    print(f"  {GREEN}{BOLD}CHANGEKEY PAYLOAD REGRESSION PASSED{RESET}")
    print(f"{'=' * 60}{RESET}\n")
    ser.close()


if __name__ == "__main__":
    main()
