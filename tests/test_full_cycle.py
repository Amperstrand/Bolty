#!/usr/bin/env python3
"""Full provisioning cycle test — handles card in ANY key state.

Detects current card state via keyver, wipes with correct keys,
then runs: burn -> verify -> wipe -> verify.

Card must be on the reader before starting.
"""

from transport import SerialTransport
from test_helpers import (
    STATIC_K0, STATIC_K1, STATIC_K2, STATIC_K3, STATIC_K4, TEST_URL,
    run_full_cycle_scenario,
)


def main():
    transport = SerialTransport()
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
