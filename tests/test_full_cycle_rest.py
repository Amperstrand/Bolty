#!/usr/bin/env python3
"""Full provisioning cycle test via REST transport."""

import argparse
import os

import urllib3

import requests

from transport import RestTransport
from test_helpers import (
    STATIC_K0, STATIC_K1, STATIC_K2, STATIC_K3, STATIC_K4, TEST_URL,
    run_full_cycle_scenario,
)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def main():
    parser = argparse.ArgumentParser(description="Bolty REST full cycle test")
    parser.add_argument("--url", default=os.environ.get("BOLTY_REST_URL", ""),
                        help="REST base URL e.g. https://192.168.1.100/api")
    parser.add_argument("--token", default=os.environ.get("BOLTY_REST_TOKEN", ""),
                        help="Bearer auth token")
    args = parser.parse_args()

    if not args.url:
        print("ERROR: --url or BOLTY_REST_URL required")
        return

    transport = RestTransport(
        base_url=args.url,
        verify=False,
        auth_token=args.token or None,
    )
    transport.connect()
    try:
        run_full_cycle_scenario(
            transport,
            keys=(STATIC_K0, STATIC_K1, STATIC_K2, STATIC_K3, STATIC_K4),
            url=TEST_URL,
        )
    finally:
        transport.close()


if __name__ == "__main__":
    main()
