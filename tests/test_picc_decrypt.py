#!/usr/bin/env python3
"""Test PICC data decryption on burned card.

Burns card, reads NDEF, then runs picc command to verify
p= decryption and c= verification work on real hardware.
"""

import re
import sys
import time

from test_helpers import (
    STATIC_K0, STATIC_K1, STATIC_K2, STATIC_K3, STATIC_K4, TEST_URL,
    step, verbose,
    GREEN, RED, BOLD, RESET,
)
from transport import SerialTransport


def main():
    print(f"\n{BOLD}{'='*60}")
    print(f"  PICC DATA DECRYPTION TEST")
    print(f"{'='*60}{RESET}\n")

    transport = SerialTransport()
    transport.connect()

    # Verify firmware
    resp = transport.send_cmd("help", 2.0)
    if "picc" not in resp:
        print(f"{RED}Firmware missing picc command{RESET}")
        transport.close()
        sys.exit(1)

    # Phase 1: Burn card
    print(f"\n{BOLD}PHASE 1: Burn card{RESET}")
    resp = transport.send_cmd(f"keys {STATIC_K0} {STATIC_K1} {STATIC_K2} {STATIC_K3} {STATIC_K4}", 3.0)
    time.sleep(0.3)
    resp = transport.send_cmd(f"url {TEST_URL}", 3.0)
    time.sleep(0.3)
    print(f"  {BOLD}>>> BURNING CARD <<<{RESET}")
    resp = transport.send_cmd("burn", 30.0)
    step("1a", "burn SUCCESS", "SUCCESS" in resp, resp.strip()[-200:])

    # Phase 2: Read NDEF
    print(f"\n{BOLD}PHASE 2: Read NDEF{RESET}")
    resp = transport.send_cmd("ndef", 25.0)
    step("2a", "NDEF read OK", "OK" in resp, resp.strip()[-200:])

    # Extract URL from NDEF for reference
    url_match = re.search(r'https?://[^\s]+', resp)
    if url_match:
        print(f"  URL: {url_match.group(0)}")

    # Phase 3: PICC decrypt + verify
    print(f"\n{BOLD}PHASE 3: PICC decrypt + verify{RESET}")
    resp = transport.send_cmd("picc", 25.0)
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
    print(f"\n{BOLD}PHASE 4: Wipe card{RESET}")
    resp = transport.send_cmd(f"keys {STATIC_K0} {STATIC_K1} {STATIC_K2} {STATIC_K3} {STATIC_K4}", 3.0)
    time.sleep(0.3)
    resp = transport.send_cmd("wipe", 25.0)
    step("4a", "wipe SUCCESS", "SUCCESS" in resp, resp.strip()[-200:])

    # Summary
    print(f"\n{BOLD}{'='*60}")
    print(f"  PICC DATA DECRYPTION TEST COMPLETE")
    print(f"{'='*60}{RESET}\n")

    transport.close()


if __name__ == "__main__":
    main()
