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
import sys
import time

from test_helpers import (
    STATIC_K0, STATIC_K1, STATIC_K2, STATIC_K3, STATIC_K4, TEST_URL,
    step, verbose, extract_key_versions, check_firmware_responsive,
    GREEN, RED, YELLOW, BOLD, RESET,
)
from transport import SerialTransport


def extract_lengths(text):
    return [int(match.group(1)) for match in re.finditer(r"CMDDATA Length:(\d+)", text)]


def expect_changekey_lengths(text, phase_name):
    lengths = extract_lengths(text)
    count_21 = lengths.count(21)
    count_17 = lengths.count(17)
    ok_21 = step("a", f"{phase_name}: 4 non-master ChangeKey payloads at 21 bytes", count_21 == 4, f"Lengths: {lengths}")
    ok_17 = step("b", f"{phase_name}: 1 master ChangeKey payload at 17 bytes", count_17 == 1, f"Lengths: {lengths}")
    return ok_21 and ok_17


def ensure_blank(transport):
    print(f"\n{BOLD}Ensure blank starting state{RESET}")
    resp = transport.send_cmd("keyver", 12.0)
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
        transport.send_cmd(f"keys {STATIC_K0} {STATIC_K1} {STATIC_K2} {STATIC_K3} {STATIC_K4}", 3.0)
        resp = transport.send_cmd("wipe", 20.0)
        verbose(resp)
        if "SUCCESS" not in resp:
            print(f"{RED}Cannot wipe card with recovery keys{RESET}")
            sys.exit(1)
    else:
        print(f"  {YELLOW}Mixed state detected; trying reset then recovery wipe{RESET}")
        resp = transport.send_cmd("reset", 20.0)
        if "SUCCESS" not in resp:
            transport.send_cmd(f"keys {STATIC_K0} {STATIC_K1} {STATIC_K2} {STATIC_K3} {STATIC_K4}", 3.0)
            resp = transport.send_cmd("wipe", 20.0)
            if "SUCCESS" not in resp:
                print(f"{RED}Cannot recover mixed-state card{RESET}")
                sys.exit(1)

    time.sleep(1)
    resp = transport.send_cmd("keyver", 12.0)
    versions = extract_key_versions(resp)
    if not all(v == 0x00 for v in versions.values()):
        print(f"{RED}Card is not blank after recovery: {versions}{RESET}")
        sys.exit(1)
    resp = transport.send_cmd("check", 12.0)
    if "SUCCESS" not in resp:
        print(f"{RED}Zero-key auth failed after recovery{RESET}")
        sys.exit(1)


def main():
    print(f"\n{BOLD}{'=' * 60}")
    print("  CHANGEKEY PAYLOAD SIZE REGRESSION TEST")
    print(f"{'=' * 60}{RESET}\n")

    transport = SerialTransport()
    transport.connect()

    check_firmware_responsive(transport)
    ensure_blank(transport)
    time.sleep(1)

    print(f"\n{BOLD}Phase 1: Burn and inspect ChangeKey payload sizes{RESET}")
    transport.send_cmd(f"keys {STATIC_K0} {STATIC_K1} {STATIC_K2} {STATIC_K3} {STATIC_K4}", 3.0)
    transport.send_cmd(f"url {TEST_URL}", 3.0)
    burn_resp = transport.send_cmd("burn", 25.0)
    verbose(burn_resp)
    if not step(1, "burn overall SUCCESS", "SUCCESS" in burn_resp, burn_resp.strip()[-200:]):
        transport.close()
        sys.exit(1)
    if not expect_changekey_lengths(burn_resp, "burn"):
        transport.close()
        sys.exit(1)

    if not step(
        2,
        "burn has no false-negative ChangeKey logging",
        "ChangeKey error! Key:" not in burn_resp,
        burn_resp.strip()[-200:],
    ):
        transport.close()
        sys.exit(1)

    time.sleep(1)

    print(f"\n{BOLD}Phase 2: Wipe and inspect ChangeKey payload sizes{RESET}")
    transport.send_cmd(f"keys {STATIC_K0} {STATIC_K1} {STATIC_K2} {STATIC_K3} {STATIC_K4}", 3.0)
    wipe_resp = transport.send_cmd("wipe", 25.0)
    verbose(wipe_resp)
    if not step(3, "wipe overall SUCCESS", "SUCCESS" in wipe_resp, wipe_resp.strip()[-200:]):
        transport.close()
        sys.exit(1)
    if not expect_changekey_lengths(wipe_resp, "wipe"):
        transport.close()
        sys.exit(1)

    if not step(
        4,
        "wipe has no false-negative ChangeKey logging",
        "ChangeKey error! Key:" not in wipe_resp,
        wipe_resp.strip()[-200:],
    ):
        transport.close()
        sys.exit(1)

    time.sleep(1)

    print(f"\n{BOLD}Phase 3: Verify factory-identical state after wipe{RESET}")
    keyver_resp = transport.send_cmd("keyver", 12.0)
    verbose(keyver_resp)
    versions = extract_key_versions(keyver_resp)
    if not step(5, "all keys back at 0x00", all(v == 0x00 for v in versions.values()) and len(versions) == 5, f"Got: {versions}"):
        transport.close()
        sys.exit(1)

    check_resp = transport.send_cmd("check", 12.0)
    verbose(check_resp)
    if not step(6, "zero-key auth succeeds after wipe", "SUCCESS" in check_resp):
        transport.close()
        sys.exit(1)

    print(f"\n{BOLD}{'=' * 60}")
    print(f"  {GREEN}{BOLD}CHANGEKEY PAYLOAD REGRESSION PASSED{RESET}")
    print(f"{'=' * 60}{RESET}\n")
    transport.close()


if __name__ == "__main__":
    main()
