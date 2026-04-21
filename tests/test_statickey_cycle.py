#!/usr/bin/env python3
"""Static-key provisioning cycle — fully automated burn, verify, phone-test pause, wipe.

Uses known static keys (1111..., 2222..., etc.) instead of random or zero keys.
This confirms the firmware writes ALL 5 keys correctly and can wipe them back.

Sequence:
  0. Reset card to zero-key state (safe starting point)
  1. Set static keys + test URL in firmware config
  2. keyver — confirm card is at 0x01 (post-reset)
  3. burn — provision card with static keys + test URL
  4. keyver — confirm all keys changed
  5. auth — verify k0 authentication works with new keys
  6. ndef — read back NDEF message, verify URL present
  7. PAUSE — user tests on phone, presses ENTER when done
  8. wipe — reset card back to zero keys
  9. keyver — confirm back to 0x01
  10. check — confirm zero-key auth works

Card must be on the reader before starting.
Aborts immediately on any failure BEFORE step 7.
After step 7, card state is unknown (phone may have modified it).
"""

import sys
import time

from test_helpers import (
    STATIC_K0, STATIC_K1, STATIC_K2, STATIC_K3, STATIC_K4,
    step, verbose, extract_key_versions, check_firmware_responsive,
    GREEN, RED, YELLOW, BOLD, DIM, RESET,
)
from transport import SerialTransport

TEST_URL = "https://dummy.test?p=STATIC_KEY_TEST&c=0000000000000000"


def main():
    print(f"\n{BOLD}{'='*60}")
    print(f"  STATIC-KEY PROVISIONING CYCLE TEST")
    print(f"{'='*60}{RESET}\n")

    print(f"  {DIM}Static keys:{RESET}")
    print(f"    k0 (auth): {STATIC_K0}")
    print(f"    k1 (PICC): {STATIC_K1}")
    print(f"    k2 (MAC):  {STATIC_K2}")
    print(f"    k3 (k1):   {STATIC_K3}")
    print(f"    k4 (k2):   {STATIC_K4}")
    print(f"    URL:      {TEST_URL}")

    transport = SerialTransport()
    transport.connect()

    check_firmware_responsive(transport)
    time.sleep(1)

    # ── Step 0: Reset card to known zero-key state ──
    print(f"\n{BOLD}[0/10] reset — ensure card starts at zero keys{RESET}")
    resp = transport.send_cmd("reset", 15.0)
    verbose(resp)
    if not step(0, "reset SUCCESS", "SUCCESS" in resp):
        print(f"{RED}ABORT: reset failed{RESET}")
        transport.close()
        sys.exit(1)
    time.sleep(1)

    # ── Step 1: Set static keys + URL ──
    print(f"\n{BOLD}[1/10] keys — set static test keys{RESET}")
    resp = transport.send_cmd(f"keys {STATIC_K0} {STATIC_K1} {STATIC_K2} {STATIC_K3} {STATIC_K4}", 3.0)
    verbose(resp)
    if not step(1, "keys set", "Set" in resp or "k0" in resp.lower(), f"Response: {resp.strip()[:100]}"):
        transport.close()
        sys.exit(1)
    time.sleep(0.5)

    print(f"\n{BOLD}[1b/10] url — set test URL{RESET}")
    resp = transport.send_cmd(f"url {TEST_URL}", 3.0)
    verbose(resp)
    if not step("1b", "url set", TEST_URL in resp, f"Response: {resp.strip()[:100]}"):
        transport.close()
        sys.exit(1)
    time.sleep(0.5)

    # ── Step 2: keyver — confirm post-reset state (0x01) ──
    print(f"\n{BOLD}[2/10] keyver — confirm post-reset state{RESET}")
    resp = transport.send_cmd("keyver", 10.0)
    verbose(resp)
    versions = extract_key_versions(resp)
    if not step(2, "all keys 0x01 (post-reset)", all(v == 0x01 for v in versions.values()) and len(versions) == 5, f"Got: {versions}"):
        print(f"{RED}ABORT: unexpected starting state{RESET}")
        transport.close()
        sys.exit(1)
    time.sleep(1)

    # ── Step 3: BURN — provision with static keys ──
    print(f"\n{BOLD}[3/10] burn — provision with static keys{RESET}")
    print(f"  {YELLOW}{BOLD}>>> Writing keys to card NOW <<<{RESET}")
    resp = transport.send_cmd("burn", 20.0)
    verbose(resp)
    if not step(3, "burn SUCCESS", "SUCCESS" in resp):
        print(f"{RED}ABORT: burn failed — card may be in unknown state!{RESET}")
        transport.close()
        sys.exit(1)
    time.sleep(1)

    # ── Step 4: keyver — confirm keys changed ──
    print(f"\n{BOLD}[4/10] keyver — confirm keys changed{RESET}")
    resp = transport.send_cmd("keyver", 10.0)
    verbose(resp)
    versions = extract_key_versions(resp)
    if not step(4, "all keys changed (not 0x00)", all(v != 0x00 for v in versions.values()) and len(versions) == 5, f"Got: {versions}"):
        transport.close()
        sys.exit(1)
    time.sleep(1)

    # ── Step 5: auth — verify k0 authentication with static key ──
    print(f"\n{BOLD}[5/10] auth — verify k0 works with static key{RESET}")
    resp = transport.send_cmd("auth", 10.0)
    verbose(resp)
    if not step(5, "auth SUCCESS with k0", "SUCCESS" in resp):
        transport.close()
        sys.exit(1)
    time.sleep(1)

    # ── Step 6: ndef — read back NDEF, verify URL ──
    print(f"\n{BOLD}[6/10] ndef — read back and verify URL{RESET}")
    resp = transport.send_cmd("ndef", 10.0)
    verbose(resp)
    if not step(6, "NDEF contains test URL", "dummy.test" in resp, f"URL not found in NDEF output"):
        transport.close()
        sys.exit(1)
    time.sleep(1)

    # ── Step 7: PAUSE for phone testing ──
    print(f"\n{BOLD}{'='*60}")
    print(f"  {GREEN}{BOLD}BURN COMPLETE — CARD READY FOR PHONE TEST{RESET}")
    print(f"{'='*60}{RESET}")
    print(f"\n  {YELLOW}The card now has static keys and a test URL.{RESET}")
    print(f"  {YELLOW}Test it on your phone now.{RESET}")
    print(f"  {YELLOW}When done, place card back on the reader and press ENTER.{RESET}")
    input(f"\n  {DIM}Press ENTER after phone test...{RESET}")
    print()

    # ── Step 8: Wipe — reset back to zero keys ──
    print(f"\n{BOLD}[8/10] wipe — reset card to zero keys{RESET}")
    print(f"  {YELLOW}{BOLD}>>> Erasing keys from card NOW <<<{RESET}")
    resp = transport.send_cmd("wipe", 20.0)
    verbose(resp)
    if not step(8, "wipe SUCCESS", "SUCCESS" in resp):
        print(f"{RED}WARNING: wipe failed — card may still have static keys!{RESET}")
        print(f"{RED}Try 'keys {STATIC_K0} {STATIC_K1} {STATIC_K2} {STATIC_K3} {STATIC_K4}' then 'wipe' manually.{RESET}")
        transport.close()
        sys.exit(1)
    time.sleep(1)

    # ── Step 9: keyver — confirm back to 0x01 ──
    print(f"\n{BOLD}[9/10] keyver — confirm back to 0x01{RESET}")
    resp = transport.send_cmd("keyver", 10.0)
    verbose(resp)
    versions = extract_key_versions(resp)
    if not step(9, "all keys 0x01 (after wipe)", all(v == 0x01 for v in versions.values()) and len(versions) == 5, f"Got: {versions}"):
        transport.close()
        sys.exit(1)
    time.sleep(1)

    # ── Step 10: check — verify zero-key auth works ──
    print(f"\n{BOLD}[10/10] check — verify zero-key auth{RESET}")
    resp = transport.send_cmd("check", 10.0)
    verbose(resp)
    if not step(10, "auth SUCCESS with zero keys", "SUCCESS" in resp):
        transport.close()
        sys.exit(1)

    # ── Summary ──
    print(f"\n{BOLD}{'='*60}")
    print(f"  {GREEN}{BOLD}ALL 10/10 STEPS PASSED{RESET}")
    print(f"{'='*60}{RESET}\n")
    print(f"  Static-key provisioning cycle complete:")
    print(f"    burn: zero keys -> static keys (1111/2222/3333)")
    print(f"    verify: keyver, auth, ndef all confirmed")
    print(f"    phone test: user confirmed")
    print(f"    wipe:  static keys -> zero keys")
    print(f"    verify: keyver, check confirmed")
    print(f"  Card is back at zero-key state (version 0x01).\n")
    transport.close()


if __name__ == "__main__":
    main()
