from __future__ import annotations

from dataclasses import dataclass

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC


ZERO_IV = bytes(16)
P_HEX_LEN = 32
C_HEX_LEN = 16


@dataclass(slots=True)
class PiccData:
    valid: bool = False
    uid: bytes = bytes(7)
    counter: int = 0
    has_uid: bool = False
    has_counter: bool = False


@dataclass(frozen=True, slots=True)
class PiccVector:
    k1: bytes
    k2: bytes
    uid: bytes
    counter: int
    plaintext: bytes
    p_hex: str
    sv2: bytes
    derived_key: bytes
    full_mac: bytes
    short_mac: bytes
    c_hex: str


def aes_128_cbc_encrypt(key: bytes, plaintext: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.CBC(ZERO_IV)).encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()


def aes_128_cbc_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CBC(ZERO_IV)).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def aes_128_cmac(key: bytes, data: bytes) -> bytes:
    cmac = CMAC(algorithms.AES(key))
    cmac.update(data)
    return cmac.finalize()


def ntag424_cmac_short(full_cmac: bytes) -> bytes:
    return full_cmac[1::2]


def picc_hex_nibble(char: str) -> int:
    if "0" <= char <= "9":
        return ord(char) - ord("0")
    if "a" <= char <= "f":
        return ord(char) - ord("a") + 10
    if "A" <= char <= "F":
        return ord(char) - ord("A") + 10
    return 0xFF


def picc_hex_to_bytes(hex_string: str, max_bytes: int) -> bytes | None:
    if len(hex_string) != max_bytes * 2:
        return None

    out = bytearray()
    for index in range(max_bytes):
        hi = picc_hex_nibble(hex_string[index * 2])
        lo = picc_hex_nibble(hex_string[index * 2 + 1])
        if hi == 0xFF or lo == 0xFF:
            return None
        out.append((hi << 4) | lo)
    return bytes(out)


def picc_is_hex(value: str | None, expected_len: int) -> bool:
    if value is None or len(value) != expected_len:
        return False
    return all(picc_hex_nibble(char) != 0xFF for char in value)


def _extract_last_hex_param(url: str, name: str) -> str | None:
    marker = f"{name}="
    start = -1
    for index in range(len(url) - 1):
        if url[index : index + 2] == marker:
            start = index + 2

    if start < 0:
        return None

    end = start
    while end < len(url) and picc_hex_nibble(url[end]) != 0xFF:
        end += 1
    return url[start:end]


def extract_p_and_c(url: str | None) -> tuple[str, str] | None:
    if not url:
        return None

    p_hex = _extract_last_hex_param(url, "p")
    c_hex = _extract_last_hex_param(url, "c")
    if p_hex is None or c_hex is None:
        return None
    if not picc_is_hex(p_hex, P_HEX_LEN) or not picc_is_hex(c_hex, C_HEX_LEN):
        return None
    return p_hex, c_hex


def picc_decrypt_p(k1: bytes, p_hex: str) -> PiccData | None:
    ciphertext = picc_hex_to_bytes(p_hex, 16)
    if ciphertext is None:
        return None

    decrypted = aes_128_cbc_decrypt(k1, ciphertext)
    header = decrypted[0]
    if header != 0xC7:
        return None

    result = PiccData()
    offset = 1
    has_uid = (header & 0x80) != 0
    has_counter = (header & 0x40) != 0

    if has_uid:
        if (header & 0x07) != 0x07:
            return None
        result.uid = decrypted[offset : offset + 7]
        result.has_uid = True
        offset += 7

    if has_counter:
        result.counter = int.from_bytes(decrypted[offset : offset + 3], "little")
        result.has_counter = True

    return result if has_uid else None


def build_sv2(uid: bytes, counter: int) -> bytes:
    return bytes([0x3C, 0xC3, 0x00, 0x01, 0x00, 0x80]) + uid + counter.to_bytes(3, "little")


def picc_verify_c(k2: bytes, picc: PiccData, c_hex: str) -> bool:
    if not picc.has_uid or not picc.has_counter or not picc_is_hex(c_hex, C_HEX_LEN):
        return False

    sv2 = build_sv2(picc.uid, picc.counter)
    derived_key = aes_128_cmac(k2, sv2)
    computed_mac = ntag424_cmac_short(aes_128_cmac(derived_key, b""))
    expected_mac = picc_hex_to_bytes(c_hex, 8)
    return expected_mac == computed_mac


def picc_decrypt_and_verify(k1: bytes, k2: bytes, p_hex: str, c_hex: str) -> PiccData:
    result = picc_decrypt_p(k1, p_hex)
    if result is None or not picc_verify_c(k2, result, c_hex):
        return PiccData()
    result.valid = True
    return result


def picc_parse_url(k1: bytes, k2: bytes, url: str) -> PiccData:
    extracted = extract_p_and_c(url)
    if extracted is None:
        return PiccData()
    p_hex, c_hex = extracted
    return picc_decrypt_and_verify(k1, k2, p_hex, c_hex)


def make_picc_vector(k1: bytes, k2: bytes, uid: bytes, counter: int) -> PiccVector:
    assert len(k1) == 16
    assert len(k2) == 16
    assert len(uid) == 7
    assert 0 <= counter <= 0xFFFFFF

    # Firmware expects byte 0 itself to be 0xC7, which already encodes
    # UID present, counter present, and UID length = 7. The chosen UID starts
    # with 0x87 so the plaintext literally begins C7 87 ... as requested.
    plaintext = bytes([0xC7]) + uid + counter.to_bytes(3, "little") + bytes(5)
    ciphertext = aes_128_cbc_encrypt(k1, plaintext)
    sv2 = build_sv2(uid, counter)
    derived_key = aes_128_cmac(k2, sv2)
    full_mac = aes_128_cmac(derived_key, b"")
    short_mac = ntag424_cmac_short(full_mac)
    return PiccVector(
        k1=k1,
        k2=k2,
        uid=uid,
        counter=counter,
        plaintext=plaintext,
        p_hex=ciphertext.hex(),
        sv2=sv2,
        derived_key=derived_key,
        full_mac=full_mac,
        short_mac=short_mac,
        c_hex=short_mac.hex(),
    )


@pytest.fixture(scope="module")
def known_vector() -> PiccVector:
    return make_picc_vector(
        k1=bytes.fromhex("00112233445566778899aabbccddeeff"),
        k2=bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0"),
        uid=bytes.fromhex("87112233445566"),
        counter=0x010203,
    )


@pytest.mark.parametrize(
    ("char", "expected"),
    [
        *[(str(value), value) for value in range(10)],
        ("a", 10),
        ("f", 15),
        ("A", 10),
        ("F", 15),
    ],
)
def test_picc_hex_nibble_valid_inputs(char: str, expected: int) -> None:
    assert picc_hex_nibble(char) == expected


@pytest.mark.parametrize("char", ["g", "G", "x", "-", " ", "?"])
def test_picc_hex_nibble_invalid_inputs(char: str) -> None:
    assert picc_hex_nibble(char) == 0xFF


def test_picc_hex_to_bytes_round_trip_and_invalid_chars() -> None:
    original = bytes.fromhex("00ab12cd34ef5678")
    assert picc_hex_to_bytes(original.hex(), len(original)) == original
    assert picc_hex_to_bytes(original.hex().upper(), len(original)) == original
    assert picc_hex_to_bytes("001122GG", 4) is None
    assert picc_hex_to_bytes("001122", 4) is None


def test_picc_is_hex_validates_exact_length() -> None:
    assert picc_is_hex("A1b2C3d4", 8) is True
    assert picc_is_hex("A1b2C3d", 8) is False
    assert picc_is_hex("A1b2C3d40", 8) is False
    assert picc_is_hex("A1b2C3dZ", 8) is False
    assert picc_is_hex(None, 8) is False


@pytest.mark.parametrize(
    ("url_template", "expect_success"),
    [
        ("https://example.com/bolt?p={p}&c={c}", True),
        ("p={p}&c={c}", True),
        ("https://example.com/bolt?x=1&p={p}&y=2&c={c}", True),
        ("https://example.com/bolt?c={c}", False),
        ("https://example.com/bolt?p={p}", False),
        ("https://example.com/bolt?p={short_p}&c={c}", False),
        ("https://example.com/bolt?p={p}&c={short_c}", False),
    ],
)
def test_extract_p_and_c_handles_expected_url_shapes(
    known_vector: PiccVector, url_template: str, expect_success: bool
) -> None:
    url = url_template.format(
        p=known_vector.p_hex.upper(),
        c=known_vector.c_hex.upper(),
        short_p=known_vector.p_hex[:-2],
        short_c=known_vector.c_hex[:-2],
    )

    extracted = extract_p_and_c(url)
    if expect_success:
        assert extracted == (known_vector.p_hex.upper(), known_vector.c_hex.upper())
    else:
        assert extracted is None


def test_extract_p_and_c_prefers_last_occurrence_like_firmware(known_vector: PiccVector) -> None:
    url = (
        f"https://example.com/bolt?p={'00' * 16}&c={'11' * 8}"
        f"&p={known_vector.p_hex}&c={known_vector.c_hex}"
    )
    assert extract_p_and_c(url) == (known_vector.p_hex, known_vector.c_hex)


def test_picc_decrypt_p_decrypts_valid_p_and_extracts_uid_and_counter(
    known_vector: PiccVector,
) -> None:
    picc = picc_decrypt_p(known_vector.k1, known_vector.p_hex)

    assert picc is not None
    assert picc.valid is False
    assert picc.has_uid is True
    assert picc.has_counter is True
    assert picc.uid == known_vector.uid
    assert picc.counter == known_vector.counter
    assert known_vector.plaintext[0] == 0xC7
    assert known_vector.plaintext[1] == 0x87


def test_picc_decrypt_p_rejects_non_c7_header(known_vector: PiccVector) -> None:
    invalid_plaintext = bytes([0x00]) + known_vector.uid + known_vector.counter.to_bytes(3, "little") + bytes(5)
    invalid_p_hex = aes_128_cbc_encrypt(known_vector.k1, invalid_plaintext).hex()
    assert picc_decrypt_p(known_vector.k1, invalid_p_hex) is None


def test_picc_verify_c_builds_expected_sv2_and_accepts_known_mac(known_vector: PiccVector) -> None:
    picc = picc_decrypt_p(known_vector.k1, known_vector.p_hex)
    assert picc is not None

    assert known_vector.sv2 == bytes.fromhex("3cc30001008087112233445566030201")
    assert len(known_vector.derived_key) == 16
    assert len(known_vector.full_mac) == 16
    assert known_vector.short_mac == known_vector.full_mac[1::2]
    assert picc_verify_c(known_vector.k2, picc, known_vector.c_hex) is True
    assert picc_verify_c(known_vector.k2, picc, known_vector.c_hex.upper()) is True


def test_picc_verify_c_rejects_wrong_mac(known_vector: PiccVector) -> None:
    picc = picc_decrypt_p(known_vector.k1, known_vector.p_hex)
    assert picc is not None

    wrong_mac = (bytes.fromhex(known_vector.c_hex)[:-1] + b"\x00").hex()
    assert picc_verify_c(known_vector.k2, picc, wrong_mac) is False


def test_picc_decrypt_and_verify_returns_valid_picc_data(known_vector: PiccVector) -> None:
    picc = picc_decrypt_and_verify(
        known_vector.k1,
        known_vector.k2,
        known_vector.p_hex,
        known_vector.c_hex,
    )

    assert picc.valid is True
    assert picc.uid == known_vector.uid
    assert picc.counter == known_vector.counter
    assert picc.has_uid is True
    assert picc.has_counter is True


def test_picc_parse_url_parses_full_url_into_picc_data(known_vector: PiccVector) -> None:
    url = f"https://example.com/bolt?foo=1&p={known_vector.p_hex}&bar=2&c={known_vector.c_hex}"
    picc = picc_parse_url(known_vector.k1, known_vector.k2, url)

    assert picc.valid is True
    assert picc.uid == known_vector.uid
    assert picc.counter == known_vector.counter


def test_picc_parse_url_returns_invalid_for_missing_or_malformed_values(
    known_vector: PiccVector,
) -> None:
    missing = picc_parse_url(known_vector.k1, known_vector.k2, "https://example.com/bolt?p=abcd")
    malformed = picc_parse_url(
        known_vector.k1,
        known_vector.k2,
        f"https://example.com/bolt?p={known_vector.p_hex}&c=XYZ12345",
    )

    assert missing.valid is False
    assert malformed.valid is False


def test_all_zero_keys_are_supported_end_to_end() -> None:
    zero_vector = make_picc_vector(
        k1=bytes(16),
        k2=bytes(16),
        uid=bytes.fromhex("87010203040506"),
        counter=0x0A0B0C,
    )

    picc = picc_decrypt_and_verify(
        zero_vector.k1,
        zero_vector.k2,
        zero_vector.p_hex,
        zero_vector.c_hex,
    )

    assert picc.valid is True
    assert picc.uid == zero_vector.uid
    assert picc.counter == zero_vector.counter
