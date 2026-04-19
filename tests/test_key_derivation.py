#!/usr/bin/env python3
"""Verify deterministic key derivation against boltcard DETERMINISTIC.md test vectors.

Test vectors from:
  https://github.com/boltcard/boltcard/blob/main/docs/DETERMINISTIC.md

Input:
  UID:         04a39493cc8680
  Issuer Key:  00000000000000000000000000000001
  Version:     1

Expected:
  CardKey: ebff5a4e6da5ee14cbfe720ae06fbed9
  K0:      a29119fcb48e737d1591d3489557e49b
  K1:      55da174c9608993dc27bb3f30a4a7314
  K2:      f4b404be700ab285e333e32348fa3d3b
  K3:      73610ba4afe45b55319691cb9489142f
  K4:      addd03e52964369be7f2967736b7bdb5
  ID:      e07ce1279d980ecb892a81924b67bf18
"""

import sys

try:
    from cryptography.hazmat.primitives.cmac import CMAC
    from cryptography.hazmat.primitives.ciphers import algorithms
except ImportError:
    print("pip install cryptography")
    sys.exit(1)


def aes_cmac(key: bytes, data: bytes) -> bytes:
    c = CMAC(algorithms.AES(key))
    c.update(data)
    return c.finalize()


def derive_card_key(issuer_key: bytes, uid: bytes, version: int) -> bytes:
    msg = bytes([0x2D, 0x00, 0x3F, 0x75]) + uid + version.to_bytes(4, "little")
    return aes_cmac(issuer_key, msg)


def derive_boltcard_keys(issuer_key: bytes, uid: bytes, version: int) -> list[bytes]:
    card_key = derive_card_key(issuer_key, uid, version)
    k0 = aes_cmac(card_key, bytes([0x2D, 0x00, 0x3F, 0x76]))
    k1 = aes_cmac(issuer_key, bytes([0x2D, 0x00, 0x3F, 0x77]))
    k2 = aes_cmac(card_key, bytes([0x2D, 0x00, 0x3F, 0x78]))
    k3 = aes_cmac(card_key, bytes([0x2D, 0x00, 0x3F, 0x79]))
    k4 = aes_cmac(card_key, bytes([0x2D, 0x00, 0x3F, 0x7A]))
    return [k0, k1, k2, k3, k4]


def derive_card_id(issuer_key: bytes, uid: bytes) -> bytes:
    msg = bytes([0x2D, 0x00, 0x3F, 0x7B]) + uid
    return aes_cmac(issuer_key, msg)


def main():
    uid = bytes.fromhex("04a39493cc8680")
    issuer_key = bytes.fromhex("00000000000000000000000000000001")
    version = 1

    expected = {
        "CardKey": "ebff5a4e6da5ee14cbfe720ae06fbed9",
        "K0": "a29119fcb48e737d1591d3489557e49b",
        "K1": "55da174c9608993dc27bb3f30a4a7314",
        "K2": "f4b404be700ab285e333e32348fa3d3b",
        "K3": "73610ba4afe45b55319691cb9489142f",
        "K4": "addd03e52964369be7f2967736b7bdb5",
        "ID": "e07ce1279d980ecb892a81924b67bf18",
    }

    card_key = derive_card_key(issuer_key, uid, version)
    keys = derive_boltcard_keys(issuer_key, uid, version)
    card_id = derive_card_id(issuer_key, uid)

    actual = {
        "CardKey": card_key.hex(),
        "K0": keys[0].hex(),
        "K1": keys[1].hex(),
        "K2": keys[2].hex(),
        "K3": keys[3].hex(),
        "K4": keys[4].hex(),
        "ID": card_id.hex(),
    }

    passed = 0
    failed = 0
    for name, exp in expected.items():
        act = actual[name]
        if act == exp:
            print(f"PASS: {name}")
            passed += 1
        else:
            print(f"FAIL: {name}")
            print(f"  expected: {exp}")
            print(f"  actual:   {act}")
            failed += 1

    print(f"\n{passed} passed, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
