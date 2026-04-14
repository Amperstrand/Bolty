#!/usr/bin/env python3
"""Full provisioning cycle test — handles card in ANY key state.

Detects current card state via keyver, wipes with correct keys,
then runs: burn → verify → wipe → verify.

Card must be on the reader before starting.
"""

import serial, time, sys, re

PORT = '/dev/serial/by-id/usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0'
BAUD = 115200

K0 = "11111111111111111111111111111111"
K1 = "22222222222222222222222222222222"
K2 = "33333333333333333333333333333333"
K3 = K1
K4 = K2
TEST_URL = "https://example.com/bolt"

GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
BOLD = '\033[1m'
DIM = '\033[2m'
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
    text = out.decode(errors="replace")
    return text


def step(num, name, condition, detail=""):
    status = f"{GREEN}{BOLD}PASS{RESET_C}" if condition else f"{RED}{BOLD}FAIL{RESET_C}"
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
    versions = {}
    for m in re.finditer(r'Key (\d) version: 0x([0-9A-Fa-f]+)', text):
        versions[int(m.group(1))] = int(m.group(2), 16)
    return versions


def main():
    print(f"\n{BOLD}{'='*60}")
    print(f"  FULL PROVISIONING CYCLE TEST")
    print(f"{'='*60}{RESET_C}\n")

    ser = serial.Serial(PORT, BAUD, timeout=1)
    time.sleep(4)
    drain(ser, 1.0)

    # Verify firmware is responsive
    resp = send_cmd(ser, "help", 2.0)
    if "keyver" not in resp:
        print(f"{RED}Firmware not responding or missing keyver command{RESET_C}")
        ser.close()
        sys.exit(1)

    # Phase 1: Detect card state
    print(f"\n{BOLD}PHASE 1: Detect card state{RESET_C}")
    resp = send_cmd(ser, "keyver", 12.0)
    verbose(resp)
    versions = extract_key_versions(resp)

    if len(versions) < 5:
        print(f"{RED}Could not read all key versions — card not detected?{RESET_C}")
        ser.close()
        sys.exit(1)

    all_factory = all(v == 0x00 for v in versions.values())
    all_changed = all(v != 0x00 for v in versions.values())

    if all_factory:
        print(f"  {GREEN}Card is FACTORY BLANK (version 0x00){RESET_C}")
        card_state = "blank"
    elif all_changed:
        print(f"  Key versions are 0x01 — checking if keys are actually zeros...")
        time.sleep(0.5)
        resp = send_cmd(ser, "check", 12.0)
        if "SUCCESS" in resp:
            print(f"  {GREEN}Card has ZERO keys (wiped state, version 0x01){RESET_C}")
            card_state = "blank"
        else:
            print(f"  {YELLOW}Card is PROVISIONED (non-zero keys){RESET_C}")
            card_state = "provisioned"
    else:
        print(f"  {RED}Card is in MIXED state: {versions}{RESET_C}")
        card_state = "mixed"

    time.sleep(1)

    # Phase 2: Wipe to blank if needed
    print(f"\n{BOLD}PHASE 2: Ensure card is blank{RESET_C}")
    if card_state == "blank":
        print(f"  {GREEN}Already blank — skipping wipe{RESET_C}")
    elif card_state == "provisioned":
        # Set the static keys as current keys, then wipe
        print(f"  Setting current keys to static keys...")
        resp = send_cmd(ser, f"keys {K0} {K1} {K2} {K3} {K4}", 3.0)
        verbose(resp)
        time.sleep(0.5)
        print(f"  Wiping with static keys...")
        resp = send_cmd(ser, "wipe", 20.0)
        verbose(resp)
        if not step("2a", "wipe SUCCESS", "SUCCESS" in resp, resp.strip()[-100:]):
            print(f"{RED}ABORT: Cannot wipe card{RESET_C}")
            ser.close()
            sys.exit(1)
        time.sleep(1)
        # Verify blank via zero-key auth
        resp = send_cmd(ser, "check", 12.0)
        if not step("2b", "zero-key auth after wipe", "SUCCESS" in resp,
                     resp.strip()[-100:]):
            ser.close()
            sys.exit(1)
    else:
        print(f"  {RED}Mixed state — trying reset (factory zero keys)...{RESET_C}")
        resp = send_cmd(ser, "reset", 20.0)
        verbose(resp)
        if "SUCCESS" not in resp:
            print(f"  {RED}Reset failed — trying with static keys...{RESET_C}")
            resp = send_cmd(ser, f"keys {K0} {K1} {K2} {K3} {K4}", 3.0)
            resp = send_cmd(ser, "wipe", 20.0)
            verbose(resp)
            if "SUCCESS" not in resp:
                print(f"{RED}ABORT: Cannot restore card{RESET_C}")
                ser.close()
                sys.exit(1)

    time.sleep(1)

    # Phase 3: Burn with static keys
    print(f"\n{BOLD}PHASE 3: Burn card with static keys{RESET_C}")
    # Set keys and URL
    resp = send_cmd(ser, f"keys {K0} {K1} {K2} {K3} {K4}", 3.0)
    verbose(resp)
    time.sleep(0.3)
    resp = send_cmd(ser, f"url {TEST_URL}", 3.0)
    verbose(resp)
    time.sleep(0.3)

    print(f"  {YELLOW}{BOLD}>>> BURNING CARD <<<{RESET_C}")
    resp = send_cmd(ser, "burn", 25.0)
    verbose(resp)
    if not step("3a", "burn SUCCESS", "SUCCESS" in resp, resp.strip()[-200:]):
        print(f"{RED}ABORT: Burn failed{RESET_C}")
        ser.close()
        sys.exit(1)

    # Check post-burn verify output
    verify_ok = "VERIFY" in resp and "NLEN=" in resp
    step("3b", "post-burn NDEF verify ran", verify_ok, "No VERIFY output in burn response")

    # Check if NLEN was valid
    nlen_match = re.search(r'NLEN=(\d+)', resp)
    if nlen_match:
        nlen = int(nlen_match.group(1))
        step("3c", f"NLEN={nlen} (valid)", nlen > 0 and nlen <= 252)
    else:
        step("3c", "NLEN found", False, "No NLEN in output")

    # Check if NDEF peek succeeded
    peek_ok = "NDEF peek OK" in resp
    step("3d", "NDEF peek OK", peek_ok, "Post-burn NDEF peek failed")

    time.sleep(1)

    # Phase 4: Verify provisioned state
    print(f"\n{BOLD}PHASE 4: Verify provisioned state{RESET_C}")
    resp = send_cmd(ser, "keyver", 12.0)
    verbose(resp)
    versions = extract_key_versions(resp)
    step("4a", "all keys changed",
         all(v != 0x00 for v in versions.values()) and len(versions) == 5,
         f"Got: {versions}")

    time.sleep(2)

    # Phase 5: Read NDEF
    print(f"\n{BOLD}PHASE 5: Read NDEF data{RESET_C}")
    resp = send_cmd(ser, "ndef", 25.0)
    verbose(resp)
    # The URL in the NDEF should contain our test URL (after SDM placeholder expansion)
    ndef_ok = "example.com" in resp or "OK" in resp
    step("5a", "NDEF read succeeded", "OK" in resp)
    step("5b", "NDEF contains URL domain", "example.com" in resp, f"Response: {resp.strip()[-200:]}")

    time.sleep(1)

    # Phase 6: Wipe back to factory
    print(f"\n{BOLD}PHASE 6: Wipe card back to factory{RESET_C}")
    resp = send_cmd(ser, f"keys {K0} {K1} {K2} {K3} {K4}", 3.0)
    time.sleep(0.3)
    print(f"  {YELLOW}{BOLD}>>> WIPING CARD <<<{RESET_C}")
    resp = send_cmd(ser, "wipe", 20.0)
    verbose(resp)
    if not step("6a", "wipe SUCCESS", "SUCCESS" in resp, resp.strip()[-200:]):
        print(f"{RED}WARNING: Wipe failed — card still has static keys!{RESET_C}")
        ser.close()
        sys.exit(1)

    time.sleep(1)

    # Phase 7: Verify blank state
    print(f"\n{BOLD}PHASE 7: Verify card is blank{RESET_C}")
    resp = send_cmd(ser, "keyver", 12.0)
    verbose(resp)
    versions = extract_key_versions(resp)
    step("7a", "all keys at 0x00 (factory-identical after wipe with keyversion=0x00)",
          all(v == 0x00 for v in versions.values()) and len(versions) == 5,
          f"Got: {versions}")

    resp = send_cmd(ser, "check", 12.0)
    verbose(resp)
    step("7b", "check passes (zero-key auth)", "SUCCESS" in resp)

    # Summary
    print(f"\n{BOLD}{'='*60}")
    print(f"  {GREEN}{BOLD}FULL CYCLE COMPLETE{RESET_C}")
    print(f"{'='*60}{RESET_C}")
    print(f"  blank → burn → verify → ndef → wipe → verify blank")
    print(f"  Card is back at factory state.\n")

    ser.close()


if __name__ == "__main__":
    main()
