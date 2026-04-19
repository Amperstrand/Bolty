#!/usr/bin/env python3
"""Verify BOLT11 invoice decoder against canonical spec test vectors.

Test vectors from BOLT #11:
  https://github.com/lightning/bolts/blob/master/11-payment-encoding.md

All invoices are signed with priv_key e126f68f7eafcc8b74f54d269fe206be715000f94dac067d1c04a8ca3b2db734
and contain payment_secret 1111111111111111111111111111111111111111111111111111111111111111.

This Python implementation mirrors the C++ Bolt11Decode.h logic exactly:
  - bech32 character → 5-bit value conversion
  - 5-bit → 8-bit conversion
  - timestamp from first 7 five-bit values (35 bits)
  - tagged field parsing: p=payment_hash, d=description, x=expiry
  - amount parsing with m/u/n/p multipliers
"""

import sys

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def bech32_char_to_value(c):
    c = c.lower()
    for i in range(32):
        if BECH32_CHARSET[i] == c:
            return i
    return -1


def convert_5to8(five_bit):
    acc = 0
    bits = 0
    out = bytearray()
    for v in five_bit:
        acc = (acc << 5) | v
        bits += 5
        while bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    return bytes(out)


def bolt11_parse_amount(s):
    if not s:
        return 0
    raw = 0
    i = 0
    while i < len(s) and s[i].isdigit():
        raw = raw * 10 + int(s[i])
        i += 1
    if i < len(s):
        mult = s[i].lower()
        if mult == 'm':
            raw = raw * 100000000 // 1000
        elif mult == 'u':
            raw = raw * 100000000 // 1000000
        elif mult == 'n':
            raw = raw * 100000000 // 1000000000
        elif mult == 'p':
            raw = raw // 10000
    return raw


def bolt11_decode(invoice):
    info = {
        "valid": False,
        "amount_sat": 0,
        "has_amount": False,
        "timestamp": 0,
        "description": "",
        "payment_hash": b"",
        "has_payment_hash": False,
        "expiry": 3600,
    }

    if not invoice:
        return info

    p = invoice
    if p.startswith("lightning:"):
        p = p[10:]

    if not p.startswith("ln"):
        return info
    p = p[2:]

    # Find bech32 separator: LAST '1' in the string (CLN approach).
    # Everything before = HRP (ln + network + amount), after = data.
    sep_pos = p.rfind('1')
    if sep_pos < 2 or sep_pos + 7 > len(p):
        return info

    hrp_part = p[:sep_pos]
    data_start = p[sep_pos + 1:]

    # Extract amount from HRP: skip "ln" prefix (already done) + network identifier
    hrp_after_ln = hrp_part[2:]
    i = 0
    while i < len(hrp_after_ln) and hrp_after_ln[i].isalpha():
        i += 1
    amount_str = hrp_after_ln[i:]

    if amount_str:
        info["amount_sat"] = bolt11_parse_amount(amount_str)
        info["has_amount"] = True
    data_len = len(data_start)
    if data_len < 7 + 6:  # timestamp(7) + checksum(6) minimum
        return info
    data_len -= 6

    # Signature is always last 105 five-bit values (104 signature + 1 recovery flag)
    sig_len = 105
    five_bit = []
    for i in range(data_len):
        val = bech32_char_to_value(data_start[i])
        if val < 0:
            return info
        five_bit.append(val)

    # Timestamp: first 7 values (35 bits)
    if len(five_bit) < 7:
        return info
    ts = 0
    for i in range(7):
        ts = (ts << 5) | five_bit[i]
    info["timestamp"] = ts

    # Signature is always last 105 five-bit values (104 signature + 1 recovery flag)
    sig_len = 105
    usable_len = len(five_bit)
    if usable_len >= sig_len + 7:
        field_end = usable_len - sig_len
    else:
        field_end = usable_len

    pos = 7
    while pos + 3 <= field_end:
        field_type = five_bit[pos]
        field_len = (five_bit[pos + 1] << 5) | five_bit[pos + 2]
        pos += 3

        if pos + field_len > field_end:
            break

        if field_type == 1:  # 'p' = payment_hash
            if field_len >= 52:
                hash_bytes = convert_5to8(five_bit[pos:pos + 52])
                info["payment_hash"] = hash_bytes[:32]
                info["has_payment_hash"] = True
        elif field_type == 13:  # 'd' = description
            desc_bytes = convert_5to8(five_bit[pos:pos + field_len])
            info["description"] = desc_bytes.decode("utf-8", errors="replace")
        elif field_type == 6:  # 'x' = expiry
            # Direct 5-bit concatenation (per CLN pull_uint):
            # 5-bit values ARE the integer, no byte conversion needed.
            expiry = 0
            for i in range(field_len):
                expiry = (expiry << 5) | five_bit[pos + i]
            info["expiry"] = expiry

        pos += field_len

    info["valid"] = True
    return info


# BOLT #11 canonical test vectors
TEST_VECTORS = [
    {
        "name": "Donation of any amount",
        "invoice": "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmmwwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93dj32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyetp5h2tztugp9lfyql",
        "expected": {
            "valid": True,
            "has_amount": False,
            "amount_sat": 0,
            "timestamp": 1496314658,
            "has_payment_hash": True,
            "payment_hash": bytes.fromhex("0001020304050607080900010203040506070809000102030405060708090102"),
            "description": "Please consider supporting this project",
            "expiry": 3600,
        },
    },
    {
        "name": "2500u for a cup of coffee, 60s expiry",
        "invoice": "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh",
        "expected": {
            "valid": True,
            "has_amount": True,
            "amount_sat": 2500 * 100000000 // 1000000,  # 250000 sat
            "timestamp": 1496314658,
            "has_payment_hash": True,
            "payment_hash": bytes.fromhex("0001020304050607080900010203040506070809000102030405060708090102"),
            "description": "1 cup coffee",
            "expiry": 60,
        },
    },
    {
        "name": "2500u for nonsense (UTF-8), 60s expiry",
        "invoice": "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpquwpc4curk03c9wlrswe78q4eyqc7d8d0xqzpu9qrsgqhtjpauu9ur7fw2thcl4y9vfvh4m9wlfyz2gem29g5ghe2aak2pm3ps8fdhtceqsaagty2vph7utlgj48u0ged6a337aewvraedendscp573dxr",
        "expected": {
            "valid": True,
            "has_amount": True,
            "amount_sat": 2500 * 100000000 // 1000000,
            "timestamp": 1496314658,
            "has_payment_hash": True,
            "payment_hash": bytes.fromhex("0001020304050607080900010203040506070809000102030405060708090102"),
            "description": "\u30ca\u30f3\u30bb\u30f3\u30b9 1\u676f",
            "expiry": 60,
        },
    },
    {
        "name": "20m with hashed description",
        "invoice": "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqs9qrsgq7ea976txfraylvgzuxs8kgcw23ezlrszfnh8r6qtfpr6cxga50aj6txm9rxrydzd06dfeawfk6swupvz4erwnyutnjq7x39ymw6j38gp7ynn44",
        "expected": {
            "valid": True,
            "has_amount": True,
            "amount_sat": 20 * 100000000 // 1000,  # 2000000 sat
            "timestamp": 1496314658,
            "has_payment_hash": True,
            "payment_hash": bytes.fromhex("0001020304050607080900010203040506070809000102030405060708090102"),
            "description": "",
            "expiry": 3600,
        },
    },
    {
        "name": "20m testnet with P2PKH fallback",
        "invoice": "lntb20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e20v6pu37c5d9vax37wxq72un989qrsgqdj545axuxtnfemtpwkc45hx9d2ft7x04mt8q7y6t0k2dge9e7h8kpy9p34ytyslj3yu569aalz2xdk8xkd7ltxqld94u8h2esmsmacgpghe9k8",
        "expected": {
            "valid": True,
            "has_amount": True,
            "amount_sat": 20 * 100000000 // 1000,
            "timestamp": 1496314658,
            "has_payment_hash": True,
            "payment_hash": bytes.fromhex("0001020304050607080900010203040506070809000102030405060708090102"),
            "description": "",
            "expiry": 3600,
        },
    },
    {
        "name": "20m mainnet with P2SH fallback + routing info",
        "invoice": "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqhp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqsfpp3qjmp7lwpagxun9pygexvgpjdc4jdj85fr9yq20q82gphp2nflc7jtzrcazrra7wwgzxqc8u7754cdlpfrmccae92qgzqvzq2ps8pqqqqqqpqqqqq9qqqvpeuqafqxu92d8lr6fvg0r5gv0heeeqgcrqlnm6jhphu9y00rrhy4grqszsvpcgpy9qqqqqqgqqqqq7qqzq9qrsgqdfjcdk6w3ak5pca9hwfwfh63zrrz06wwfya0ydlzpgzxkn5xagsqz7x9j4jwe7yj7vaf2k9lqsdk45kts2fd0fkr28am0u4w95tt2nsq76cqw0",
        "expected": {
            "valid": True,
            "has_amount": True,
            "amount_sat": 20 * 100000000 // 1000,
            "timestamp": 1496314658,
            "has_payment_hash": True,
            "payment_hash": bytes.fromhex("0001020304050607080900010203040506070809000102030405060708090102"),
            "description": "",
            "expiry": 3600,
        },
    },
    {
        "name": "20m with P2WPKH fallback",
        "invoice": "lnbc20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfppqw508d6qejxtdg4y5r3zarvary0c5xw7k9qrsgqt29a0wturnys2hhxpner2e3plp6jyj8qx7548zr2z7ptgjjc7hljm98xhjym0dg52sdrvqamxdezkmqg4gdrvwwnf0kv2jdfnl4xatsqmrnsse",
        "expected": {
            "valid": True,
            "has_amount": True,
            "amount_sat": 20 * 100000000 // 1000,
            "timestamp": 1496314658,
            "has_payment_hash": True,
            "payment_hash": bytes.fromhex("0001020304050607080900010203040506070809000102030405060708090102"),
            "description": "",
            "expiry": 3600,
        },
    },
    {
        "name": "9678785340p amount with long description",
        "invoice": "lnbc9678785340p1pwmna7lpp5gc3xfm08u9qy06djf8dfflhugl6p7lgza6dsjxq454gxhj9t7a0sd8dgfkx7cmtwd68yetpd5s9xar0wfjn5gpc8qhrsdfq24f5ggrxdaezqsnvda3kkum5wfjkzmfqf3jkgem9wgsyuctwdus9xgrcyqcjcgpzgfskx6eqf9hzqnteypzxz7fzypfhg6trddjhygrcyqezcgpzfysywmm5ypxxjemgw3hxjmn8yptk7untd9hxwg3q2d6xjcmtv4ezq7pqxgsxzmnyyqcjqmt0wfjjq6t5v4khxsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsxqyjw5qcqp2rzjq0gxwkzc8w6323m55m4jyxcjwmy7stt9hwkwe2qxmy8zpsgg7jcuwz87fcqqeuqqqyqqqqlgqqqqn3qq9q9qrsgqrvgkpnmps664wgkp43l22qsgdw4ve24aca4nymnxddlnp8vh9v2sdxlu5ywdxefsfvm0fq3sesf08uf6q9a2ke0hc9j6z6wlxg5z5kqpu2v9wz",
        "expected": {
            "valid": True,
            "has_amount": True,
            "amount_sat": 967878,  # 9678785340 pico-BTC → 9678785340 // 10000 = 967878 sat
            "timestamp": 1572468703,
            "has_payment_hash": True,
            "payment_hash": bytes.fromhex("462264ede7e14047e9b249da94fefc47f41f7d02ee9b091815a5506bc8abf75f"),
            "description": "Blockstream Store: 88.85 USD for Blockstream Ledger Nano S x 1, \"Back In My Day\" Sticker x 2, \"I Got Lightning Working\" Sticker x 2 and 1 more items",
            "expiry": 604800,
        },
    },
]


def check_field(name, actual, expected):
    if actual == expected:
        print(f"  PASS: {name}")
        return True
    else:
        print(f"  FAIL: {name}")
        print(f"    expected: {expected!r}")
        print(f"    actual:   {actual!r}")
        return False


def run_test(tv):
    name = tv["name"]
    invoice = tv["invoice"]
    expected = tv["expected"]

    print(f"\nTest: {name}")
    print(f"  Invoice: {invoice[:50]}...")

    actual = bolt11_decode(invoice)
    passed = 0
    failed = 0

    for field in ("valid", "has_amount", "amount_sat", "timestamp", "expiry", "description"):
        if field in expected:
            if check_field(field, actual[field], expected[field]):
                passed += 1
            else:
                failed += 1

    if expected.get("has_payment_hash"):
        if actual["has_payment_hash"] and actual["payment_hash"] == expected["payment_hash"]:
            print(f"  PASS: payment_hash")
            passed += 1
        else:
            exp_hex = expected["payment_hash"].hex()
            act_hex = actual["payment_hash"].hex() if actual["has_payment_hash"] else "(none)"
            print(f"  FAIL: payment_hash")
            print(f"    expected: {exp_hex}")
            print(f"    actual:   {act_hex}")
            failed += 1

    return passed, failed


def main():
    total_passed = 0
    total_failed = 0

    for tv in TEST_VECTORS:
        p, f = run_test(tv)
        total_passed += p
        total_failed += f

    print(f"\n{'='*60}")
    print(f"  {total_passed} passed, {total_failed} failed")
    print(f"{'='*60}")
    return 0 if total_failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
