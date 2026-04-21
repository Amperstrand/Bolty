#!/usr/bin/env python3
"""Shared assertion, parsing, and test-scenario utilities for Bolty E2E tests."""

import re
import sys
import time

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BOLD = '\033[1m'
DIM = '\033[2m'
RESET = '\033[0m'

STATIC_K0 = "11111111111111111111111111111111"
STATIC_K1 = "22222222222222222222222222222222"
STATIC_K2 = "33333333333333333333333333333333"
STATIC_K3 = STATIC_K1
STATIC_K4 = STATIC_K2

TEST_URL = "https://example.com/bolt"


def step(num, name, condition, detail=""):
    """Colored PASS/FAIL assertion — extracted from test_full_cycle.py."""
    status = f"{GREEN}{BOLD}PASS{RESET}" if condition else f"{RED}{BOLD}FAIL{RESET}"
    print(f"  [{num}] {status}: {name}")
    if detail and not condition:
        print(f"       {detail}")
    return condition


def verbose(resp):
    for line in resp.strip().split('\n'):
        line = line.strip()
        if line:
            print(f"    {line}")


def extract_key_versions(text):
    """Parse 'Key N version: 0xNN' from firmware output."""
    versions = {}
    for m in re.finditer(r'Key (\d) version: 0x([0-9A-Fa-f]+)', text):
        versions[int(m.group(1))] = int(m.group(2), 16)
    return versions


def check_firmware_responsive(transport):
    """Send 'help', verify response contains 'keyver'."""
    resp = transport.send_cmd("help", 2.0)
    if "keyver" not in resp:
        print(f"{RED}Firmware not responding or missing keyver command{RESET}")
        transport.close()
        sys.exit(1)
    return True


def run_full_cycle_scenario(transport, keys, url):
    """Full provisioning cycle: blank -> burn -> verify -> ndef -> wipe -> verify blank.

    Args:
        transport: Connected Transport instance
        keys: (k0, k1, k2, k3, k4) tuple of 32-char hex key strings
        url: LNURL payment URL string
    Returns:
        True on overall pass
    """
    k0, k1, k2, k3, k4 = keys

    print(f"\n{BOLD}{'='*60}")
    print(f"  FULL PROVISIONING CYCLE TEST")
    print(f"{'='*60}{RESET}\n")

    check_firmware_responsive(transport)

    # Phase 1: Detect card state
    print(f"\n{BOLD}PHASE 1: Detect card state{RESET}")
    resp = transport.send_cmd("keyver", 12.0)
    verbose(resp)
    versions = extract_key_versions(resp)

    if len(versions) < 5:
        print(f"{RED}Could not read all key versions — card not detected?{RESET}")
        transport.close()
        sys.exit(1)

    all_factory = all(v == 0x00 for v in versions.values())
    all_changed = all(v != 0x00 for v in versions.values())

    if all_factory:
        print(f"  {GREEN}Card is FACTORY BLANK (version 0x00){RESET}")
        card_state = "blank"
    elif all_changed:
        print(f"  Key versions are 0x01 — checking if keys are actually zeros...")
        time.sleep(0.5)
        resp = transport.send_cmd("check", 12.0)
        if "SUCCESS" in resp:
            print(f"  {GREEN}Card has ZERO keys (wiped state, version 0x01){RESET}")
            card_state = "blank"
        else:
            print(f"  {YELLOW}Card is PROVISIONED (non-zero keys){RESET}")
            card_state = "provisioned"
    else:
        print(f"  {RED}Card is in MIXED state: {versions}{RESET}")
        card_state = "mixed"

    time.sleep(1)

    # Phase 2: Wipe to blank if needed
    print(f"\n{BOLD}PHASE 2: Ensure card is blank{RESET}")
    if card_state == "blank":
        print(f"  {GREEN}Already blank — skipping wipe{RESET}")
    elif card_state == "provisioned":
        print(f"  Setting current keys to static keys...")
        resp = transport.send_cmd(f"keys {k0} {k1} {k2} {k3} {k4}", 3.0)
        verbose(resp)
        time.sleep(0.5)
        print(f"  Wiping with static keys...")
        resp = transport.send_cmd("wipe", 20.0)
        verbose(resp)
        if not step("2a", "wipe SUCCESS", "SUCCESS" in resp, resp.strip()[-100:]):
            print(f"{RED}ABORT: Cannot wipe card{RESET}")
            transport.close()
            sys.exit(1)
        time.sleep(1)
        resp = transport.send_cmd("check", 12.0)
        if not step("2b", "zero-key auth after wipe", "SUCCESS" in resp,
                     resp.strip()[-100:]):
            transport.close()
            sys.exit(1)
    else:
        print(f"  {RED}Mixed state — trying reset (factory zero keys)...{RESET}")
        resp = transport.send_cmd("reset", 20.0)
        verbose(resp)
        if "SUCCESS" not in resp:
            print(f"  {RED}Reset failed — trying with static keys...{RESET}")
            transport.send_cmd(f"keys {k0} {k1} {k2} {k3} {k4}", 3.0)
            resp = transport.send_cmd("wipe", 20.0)
            verbose(resp)
            if "SUCCESS" not in resp:
                print(f"{RED}ABORT: Cannot restore card{RESET}")
                transport.close()
                sys.exit(1)

    time.sleep(1)

    # Phase 3: Burn with static keys
    print(f"\n{BOLD}PHASE 3: Burn card with static keys{RESET}")
    resp = transport.send_cmd(f"keys {k0} {k1} {k2} {k3} {k4}", 3.0)
    verbose(resp)
    time.sleep(0.3)
    resp = transport.send_cmd(f"url {url}", 3.0)
    verbose(resp)
    time.sleep(0.3)

    print(f"  {YELLOW}{BOLD}>>> BURNING CARD <<<{RESET}")
    resp = transport.send_cmd("burn", 25.0)
    verbose(resp)
    if not step("3a", "burn SUCCESS", "SUCCESS" in resp, resp.strip()[-200:]):
        print(f"{RED}ABORT: Burn failed{RESET}")
        transport.close()
        sys.exit(1)

    verify_ok = "VERIFY" in resp and "AUTH k0: OK" in resp
    step("3b", "post-burn K0 auth verify", verify_ok, "No VERIFY — AUTH k0 output in burn response")

    ndef_verify_ok = "NDEF read OK" in resp
    step("3c", "post-burn NDEF read verify", ndef_verify_ok, "No NDEF read OK in burn response")

    has_p_and_c = "p=" in resp and "c=" in resp
    step("3d", "NDEF contains p= and c=", has_p_and_c, "No p=/c= in burn verify output")

    time.sleep(1)

    # Phase 4: Verify provisioned state
    print(f"\n{BOLD}PHASE 4: Verify provisioned state{RESET}")
    resp = transport.send_cmd("keyver", 12.0)
    verbose(resp)
    versions = extract_key_versions(resp)
    step("4a", "all keys changed",
         all(v != 0x00 for v in versions.values()) and len(versions) == 5,
         f"Got: {versions}")

    time.sleep(2)

    # Phase 5: Read NDEF
    print(f"\n{BOLD}PHASE 5: Read NDEF data{RESET}")
    resp = transport.send_cmd("ndef", 25.0)
    verbose(resp)
    ndef_ok = "example.com" in resp or "OK" in resp
    step("5a", "NDEF read succeeded", "OK" in resp)
    step("5b", "NDEF contains URL domain", "example.com" in resp, f"Response: {resp.strip()[-200:]}")

    time.sleep(1)

    # Phase 6: Wipe back to factory
    print(f"\n{BOLD}PHASE 6: Wipe card back to factory{RESET}")
    resp = transport.send_cmd(f"keys {k0} {k1} {k2} {k3} {k4}", 3.0)
    time.sleep(0.3)
    print(f"  {YELLOW}{BOLD}>>> WIPING CARD <<<{RESET}")
    resp = transport.send_cmd("wipe", 20.0)
    verbose(resp)
    if not step("6a", "wipe SUCCESS", "SUCCESS" in resp, resp.strip()[-200:]):
        print(f"{RED}WARNING: Wipe failed — card still has static keys!{RESET}")
        transport.close()
        sys.exit(1)

    time.sleep(1)

    # Phase 7: Verify blank state
    print(f"\n{BOLD}PHASE 7: Verify card is blank{RESET}")
    resp = transport.send_cmd("keyver", 12.0)
    verbose(resp)
    versions = extract_key_versions(resp)
    step("7a", "all keys at 0x00 (factory-identical after wipe with keyversion=0x00)",
          all(v == 0x00 for v in versions.values()) and len(versions) == 5,
          f"Got: {versions}")

    resp = transport.send_cmd("check", 12.0)
    verbose(resp)
    step("7b", "check passes (zero-key auth)", "SUCCESS" in resp)

    print(f"\n{BOLD}{'='*60}")
    print(f"  {GREEN}{BOLD}FULL CYCLE COMPLETE{RESET}")
    print(f"{'='*60}{RESET}")
    print(f"  blank → burn → verify → ndef → wipe → verify blank")
    print(f"  Card is back at factory state.\n")

    return True
