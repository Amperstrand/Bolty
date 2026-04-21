#!/usr/bin/env python3
"""Zero-key safety cycle test — fully automated, no interaction needed.

Card must be on the reader before starting.
Sequence: keyver -> check -> dummyburn -> keyver -> reset -> keyver -> check
Aborts immediately on any failure.
"""

import sys
import time

from test_helpers import (
    step, verbose, extract_key_versions, check_firmware_responsive,
    GREEN, RED, BOLD, DIM, RESET,
)
from transport import SerialTransport

ZERO_KEY = "00000000000000000000000000000000"


def main():
    print(f"\n{BOLD}{'='*60}")
    print(f"  ZERO-KEY SAFETY CYCLE TEST (automated)")
    print(f"{'='*60}{RESET}\n")

    transport = SerialTransport()
    transport.connect()

    check_firmware_responsive(transport)
    time.sleep(1)

    # Step 0: keyver — determine starting state
    print(f"{BOLD}[0] keyver — determine starting state{RESET}")
    resp = transport.send_cmd("keyver", 10.0)
    print(f"  {DIM}{resp.strip()}{RESET}")
    versions = extract_key_versions(resp)
    all_factory = all(v == 0x00 for v in versions.values()) and len(versions) == 5
    all_reset = all(v == 0x01 for v in versions.values()) and len(versions) == 5
    if not (all_factory or all_reset):
        print(f"{RED}ABORT: unexpected key versions: {versions}{RESET}")
        transport.close()
        sys.exit(1)
    print(f"  Card state: {'FACTORY BLANK' if all_factory else 'POST-RESET (0x01)'}")

    # If post-reset (0x01), wipe with zero keys to reach factory state
    if all_reset:
        print(f"\n{BOLD}[0a] wipe — return to factory state{RESET}")
        transport.send_cmd(f"keys {ZERO_KEY} {ZERO_KEY} {ZERO_KEY} {ZERO_KEY} {ZERO_KEY}", 3.0)
        resp = transport.send_cmd("wipe", 20.0)
        print(f"  {DIM}{resp.strip()}{RESET}")
        if not step("0a", "wipe SUCCESS", "SUCCESS" in resp):
            transport.close()
            sys.exit(1)
        time.sleep(1)

    time.sleep(1)

    # Step 1: check — auth with zero keys
    print(f"\n{BOLD}[1/6] check (auth with zero keys){RESET}")
    resp = transport.send_cmd("check", 10.0)
    print(f"  {DIM}{resp.strip()}{RESET}")
    if not step(1, "auth SUCCESS", "SUCCESS" in resp):
        print(f"{RED}ABORT: zero-key auth failed{RESET}")
        transport.close()
        sys.exit(1)

    time.sleep(1)

    # Step 2: dummyburn
    print(f"\n{BOLD}[2/6] dummyburn{RESET}")
    resp = transport.send_cmd("dummyburn", 15.0)
    print(f"  {DIM}{resp.strip()}{RESET}")
    if not step(2, "burn SUCCESS", "SUCCESS" in resp):
        print(f"{RED}ABORT: dummyburn failed{RESET}")
        transport.close()
        sys.exit(1)

    time.sleep(1)

    # Step 3: keyver — expect PROVISIONED (all changed)
    print(f"\n{BOLD}[3/6] keyver (expect PROVISIONED){RESET}")
    resp = transport.send_cmd("keyver", 10.0)
    print(f"  {DIM}{resp.strip()}{RESET}")
    versions = extract_key_versions(resp)
    if not step(3, "all keys changed", all(v != 0x00 for v in versions.values()) and len(versions) == 5, f"Got: {versions}"):
        transport.close()
        sys.exit(1)

    time.sleep(1)

    # Step 4: wipe — dummyburn sets key versions to 0x01 (keys are still zeros).
    # resetNdefOnly rejects non-factory versions, so use wipe with zero keys.
    print(f"\n{BOLD}[4/6] wipe (zero keys, to restore factory state){RESET}")
    transport.send_cmd(f"keys {ZERO_KEY} {ZERO_KEY} {ZERO_KEY} {ZERO_KEY} {ZERO_KEY}", 3.0)
    resp = transport.send_cmd("wipe", 20.0)
    print(f"  {DIM}{resp.strip()}{RESET}")
    if not step(4, "wipe SUCCESS", "SUCCESS" in resp):
        print(f"{RED}ABORT: wipe failed{RESET}")
        transport.close()
        sys.exit(1)

    time.sleep(1)

    # Step 5: keyver — expect 0x00 (factory after wipe)
    print(f"\n{BOLD}[5/6] keyver (expect 0x00 after wipe){RESET}")
    resp = transport.send_cmd("keyver", 10.0)
    print(f"  {DIM}{resp.strip()}{RESET}")
    versions = extract_key_versions(resp)
    if not step(5, "all keys 0x00", all(v == 0x00 for v in versions.values()) and len(versions) == 5, f"Got: {versions}"):
        transport.close()
        sys.exit(1)

    time.sleep(1)

    # Step 6: check — auth with zero keys after wipe
    print(f"\n{BOLD}[6/6] check (auth after wipe){RESET}")
    resp = transport.send_cmd("check", 10.0)
    print(f"  {DIM}{resp.strip()}{RESET}")
    if not step(6, "auth SUCCESS after reset", "SUCCESS" in resp):
        transport.close()
        sys.exit(1)

    print(f"\n{BOLD}{'='*60}")
    total_steps = 7 if all_factory else 7
    print(f"  {GREEN}{BOLD}ALL TESTS PASSED{RESET}")
    print(f"{'='*60}{RESET}\n")
    transport.close()


if __name__ == "__main__":
    main()
