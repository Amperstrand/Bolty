#!/usr/bin/env python3
"""Automated Bolty card provisioning test with filtered output."""

import re

from test_helpers import STATIC_K0, STATIC_K1, STATIC_K2
from transport import SerialTransport

K3 = "44444444444444444444444444444444"
K4 = "55555555555555555555555555555555"
URL = "lnurlw://testcard.local/test?p=00000000000000000000000000000000&c=0000000000000000"


def filtered_send(transport, cmd, wait=1.5):
    raw = transport.send_cmd(cmd, wait)
    lines = raw.strip().split('\n')
    filtered = [
        l for l in lines
        if re.search(r'^(\[|Headless|  )', l.strip())
        or l.strip().startswith('Job')
        or l.strip().startswith('LNURL')
        or 'SUCCESS' in l
        or 'FAILED' in l
        or 'error' in l.lower()
    ]
    return '\n'.join(filtered) if filtered else '(no filtered output)'


def main():
    transport = SerialTransport()
    transport.connect()
    try:
        print("=" * 60)
        print("BOLTY CARD PROVISIONING TEST")
        print("=" * 60)

        print("\n>>> REMOVE card from reader if present")
        input("Press ENTER when card is OFF the reader...")

        print("\n=== Setting keys ===")
        print(filtered_send(transport, f"keys {STATIC_K0} {STATIC_K1} {STATIC_K2} {K3} {K4}", 2.0))

        print("\n=== Setting URL ===")
        print(filtered_send(transport, f"url {URL}", 2.0))

        print("\n=== Verifying config ===")
        print(filtered_send(transport, "status"))

        print("\n" + "=" * 60)
        print(">>> PLACE card on reader now")
        print("=" * 60)
        input("Press ENTER when card is ON the reader...")

        print("\n=== Burning card ===")
        print(filtered_send(transport, "burn", 10.0))

        print("\n=== Status after burn ===")
        print(filtered_send(transport, "status"))

        print("\n" + "=" * 60)
        print(">>> Keep card on reader for wipe")
        print("=" * 60)
        input("Press ENTER to wipe card...")

        print("\n=== Wiping card ===")
        print(filtered_send(transport, "wipe", 10.0))

        print("\n=== Status after wipe ===")
        print(filtered_send(transport, "status"))
    finally:
        transport.close()

    print("\n" + "=" * 60)
    print("TEST COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
