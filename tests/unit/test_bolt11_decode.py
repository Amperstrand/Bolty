from __future__ import annotations

from dataclasses import dataclass, field

import pytest


BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
PAYMENT_HASH = bytes.fromhex(
    "0001020304050607080900010203040506070809000102030405060708090102"
)

MAINNET_COFFEE_INVOICE = (
    "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs"
    "pp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enx"
    "v4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53u"
    "t353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh"
)
TESTNET_INVOICE = (
    "lntb20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygsh"
    "p58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqf"
    "qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e20v6pu37c5d9vax37wxq72un989q"
    "rsgqdj545axuxtnfemtpwkc45hx9d2ft7x04mt8q7y6t0k2dge9e7h8kpy9p34ytyslj3yu569"
    "aalz2xdk8xkd7ltxqld94u8h2esmsmacgpghe9k8"
)
ZERO_AMOUNT_INVOICE = (
    "lnbc1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygs"
    "pp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdpl2pkx2ctnv5sxxmm"
    "wwd5kgetjypeh2ursdae8g6twvus8g6rfwvs8qun0dfjkxaq9qrsgq357wnc5r2ueh7ck6q93d"
    "j32dlqnls087fxdwk8qakdyafkq3yap9us6v52vjjsrvywa6rt52cm9r9zqt8r2t7mlcwspyet"
    "p5h2tztugp9lfyql"
)
PREFIXED_INVOICE = f"lightning:{MAINNET_COFFEE_INVOICE}"
CHECKSUM_IGNORED_EXAMPLE = (
    "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqd"
    "q5xysxxatsyp3k7enxv4jsxqzpuaztrnwngzn3kdzw5hydlzf03qdgm2hdq27cqv3agm2awhz5"
    "se903vruatfhed77fql676eexamples"
)
INVALID_BECH32_INVOICE = "lnbc2500u1bzzzzz"


@dataclass
class Bolt11Info:
    valid: bool = False
    amount_sat: int = 0
    has_amount: bool = False
    timestamp: int = 0
    description: str = ""
    payment_hash: bytes = field(default_factory=lambda: bytes(32))
    has_payment_hash: bool = False
    expiry: int = 0


def bech32_char_to_value(char: str) -> int:
    if "A" <= char <= "Z":
        char = chr(ord(char) - ord("A") + ord("a"))
    for index, candidate in enumerate(BECH32_CHARSET):
        if candidate == char:
            return index
    return -1


def bolt11_parse_amount(amount: str) -> int:
    if not amount:
        return 0

    raw = 0
    index = 0
    while index < len(amount) and "0" <= amount[index] <= "9":
        raw = raw * 10 + (ord(amount[index]) - ord("0"))
        index += 1

    if index < len(amount):
        multiplier = chr(ord(amount[index]) | 0x20)
        if multiplier == "m":
            raw = raw * 100_000_000 // 1_000
        elif multiplier == "u":
            raw = raw * 100_000_000 // 1_000_000
        elif multiplier == "n":
            raw = raw * 100_000_000 // 1_000_000_000
        elif multiplier == "p":
            raw = raw // 10_000

    return raw


def convert_5to8(five_bit: list[int] | tuple[int, ...], eight_max: int) -> bytes:
    acc = 0
    bits = 0
    out = bytearray()

    for value in five_bit:
        acc = (acc << 5) | value
        bits += 5
        while bits >= 8:
            if len(out) >= eight_max:
                return bytes(out)
            bits -= 8
            out.append((acc >> bits) & 0xFF)

    return bytes(out)


def bolt11_parse_fields_5bit(five_bit: list[int] | tuple[int, ...], info: Bolt11Info) -> None:
    five_len = len(five_bit)
    if five_len < 7:
        return

    timestamp = 0
    for value in five_bit[:7]:
        timestamp = (timestamp << 5) | value
    info.timestamp = timestamp

    pos = 7
    while five_len - pos > 104:
        field_type = five_bit[pos]
        field_len = (five_bit[pos + 1] << 5) | five_bit[pos + 2]
        pos += 3

        if pos + field_len > five_len:
            break

        if field_type == 1 and field_len >= 52:
            hash_bytes = convert_5to8(five_bit[pos : pos + 52], 33)
            info.payment_hash = hash_bytes[:32]
            info.has_payment_hash = True
        elif field_type == 13:
            desc_bytes = convert_5to8(five_bit[pos : pos + field_len], 256)
            desc_bytes = desc_bytes[:128]
            info.description = desc_bytes.decode("utf-8", errors="replace")
        elif field_type == 6:
            expiry = 0
            for value in five_bit[pos : pos + min(field_len, 8)]:
                expiry = (expiry << 5) | value
            info.expiry = expiry

        pos += field_len


def bolt11_decode(invoice: str | None) -> Bolt11Info:
    info = Bolt11Info(expiry=3600)
    if invoice is None:
        return info

    text = invoice
    if text.startswith("lightning:"):
        text = text[10:]

    if len(text) < 2 or text[0] != "l" or text[1] != "n":
        return info
    text = text[2:]

    separator = text.rfind("1")
    if separator < 2 or len(text) - separator < 7:
        return info

    hrp = text[:separator]
    index = 0
    while index < len(hrp) and hrp[index].isalpha():
        index += 1

    amount = hrp[index:]
    if amount:
        info.amount_sat = bolt11_parse_amount(amount)
        info.has_amount = True

    data = text[separator + 1 :]
    data_len = len(data)
    if data_len < 13:
        return info
    data_len -= 6
    if data_len > 512:
        return info

    five_bit = []
    for char in data[:data_len]:
        value = bech32_char_to_value(char)
        if value < 0:
            return info
        five_bit.append(value)

    bolt11_parse_fields_5bit(five_bit, info)
    info.valid = True
    return info


def invoice_to_5bit(invoice: str) -> list[int]:
    text = invoice.removeprefix("lightning:")
    if text.startswith("ln"):
        text = text[2:]
    separator = text.rfind("1")
    data = text[separator + 1 : -6]
    return [bech32_char_to_value(char) for char in data]


@pytest.mark.parametrize("index,char", list(enumerate(BECH32_CHARSET)))
def test_bech32_char_to_value_all_chars(index: int, char: str) -> None:
    assert bech32_char_to_value(char) == index


@pytest.mark.parametrize("index,char", list(enumerate(BECH32_CHARSET)))
def test_bech32_char_to_value_case_insensitive(index: int, char: str) -> None:
    assert bech32_char_to_value(char.upper()) == index


@pytest.mark.parametrize("char", ["1", "b", "i", "o", "!", "_"])
def test_bech32_char_to_value_invalid_chars(char: str) -> None:
    assert bech32_char_to_value(char) == -1


@pytest.mark.parametrize(
    ("amount", "expected"),
    [
        ("", 0),
        ("0", 0),
        ("123", 123),
        ("2500m", 250_000_000),
        ("2500u", 250_000),
        ("1000n", 100),
        ("9678785340p", 967_878),
        ("2500U", 250_000),
    ],
)
def test_bolt11_parse_amount(amount: str, expected: int) -> None:
    assert bolt11_parse_amount(amount) == expected


@pytest.mark.parametrize(
    ("five_bit", "eight_max", "expected"),
    [
        ([], 10, b""),
        ([0], 10, b""),
        ([1, 2], 10, bytes([0x08])),
        ([31, 28], 10, bytes([0xFF])),
        ([0, 0, 0, 0, 0, 0, 0, 0], 10, bytes([0, 0, 0, 0, 0])),
        ([31, 31, 31, 31, 31, 31, 31, 31], 10, bytes([0xFF] * 5)),
        ([31, 31, 31, 31, 31, 31, 31, 31], 2, bytes([0xFF, 0xFF])),
    ],
)
def test_convert_5to8_known_conversions(
    five_bit: list[int], eight_max: int, expected: bytes
) -> None:
    assert convert_5to8(five_bit, eight_max) == expected


def test_bolt11_parse_fields_5bit_extracts_timestamp_payment_hash_description_and_expiry() -> None:
    info = Bolt11Info()
    bolt11_parse_fields_5bit(invoice_to_5bit(MAINNET_COFFEE_INVOICE), info)

    assert info.timestamp == 1_496_314_658
    assert info.has_payment_hash is True
    assert info.payment_hash == PAYMENT_HASH
    assert info.description == "1 cup coffee"
    assert info.expiry == 60


def test_bolt11_parse_fields_5bit_ignores_too_short_stream() -> None:
    info = Bolt11Info()
    bolt11_parse_fields_5bit([1, 2, 3, 4, 5, 6], info)

    assert info.timestamp == 0
    assert info.has_payment_hash is False
    assert info.description == ""
    assert info.expiry == 0


def test_bolt11_decode_mainnet_invoice() -> None:
    info = bolt11_decode(MAINNET_COFFEE_INVOICE)

    assert info.valid is True
    assert info.has_amount is True
    assert info.amount_sat == 250_000
    assert info.timestamp == 1_496_314_658
    assert info.has_payment_hash is True
    assert info.payment_hash == PAYMENT_HASH
    assert info.description == "1 cup coffee"
    assert info.expiry == 60


def test_bolt11_decode_testnet_invoice() -> None:
    info = bolt11_decode(TESTNET_INVOICE)

    assert info.valid is True
    assert info.has_amount is True
    assert info.amount_sat == 2_000_000
    assert info.timestamp == 1_496_314_658
    assert info.has_payment_hash is True
    assert info.payment_hash == PAYMENT_HASH
    assert info.description == ""
    assert info.expiry == 3600


def test_bolt11_decode_zero_amount_invoice() -> None:
    info = bolt11_decode(ZERO_AMOUNT_INVOICE)

    assert info.valid is True
    assert info.has_amount is False
    assert info.amount_sat == 0
    assert info.timestamp == 1_496_314_658
    assert info.has_payment_hash is True
    assert info.payment_hash == PAYMENT_HASH
    assert info.description == "Please consider supporting this project"
    assert info.expiry == 3600


def test_bolt11_decode_accepts_lightning_prefix() -> None:
    prefixed = bolt11_decode(PREFIXED_INVOICE)
    plain = bolt11_decode(MAINNET_COFFEE_INVOICE)
    assert prefixed == plain


def test_bolt11_decode_ignores_checksum_bytes_like_firmware() -> None:
    info = bolt11_decode(CHECKSUM_IGNORED_EXAMPLE)

    assert info.valid is True
    assert info.has_amount is True
    assert info.amount_sat == 250_000
    assert info.timestamp == 1_496_314_658
    assert info.has_payment_hash is True
    assert info.expiry == 3600


@pytest.mark.parametrize(
    ("invoice", "expected_has_amount"),
    [(None, False), ("", False), ("garbage", False), (INVALID_BECH32_INVOICE, True)],
)
def test_bolt11_decode_invalid_inputs(
    invoice: str | None, expected_has_amount: bool
) -> None:
    info = bolt11_decode(invoice)

    assert info.valid is False
    assert info.has_amount is expected_has_amount
    assert info.amount_sat == (250_000 if expected_has_amount else 0)
    assert info.timestamp == 0
    assert info.description == ""
    assert info.has_payment_hash is False
    assert info.expiry == 3600
