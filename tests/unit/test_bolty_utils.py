import pytest


def ntag424_error_name(sw1: int, sw2: int) -> str:
    if sw1 == 0x91:
        return {
            0x00: "OK",
            0xAE: "AUTHENTICATION_ERROR",
            0xBE: "BOUNDARY_ERROR",
            0xEE: "MEMORY_ERROR",
            0x1E: "INTEGRITY_ERROR",
            0x7E: "LENGTH_ERROR",
            0x9D: "PERMISSION_DENIED",
            0xCA: "COMMAND_ABORTED",
            0x9E: "PARAMETER_ERROR",
            0x40: "NO_SUCH_KEY",
            0xAD: "AUTHENTICATION_DELAY",
            0xF0: "FILE_NOT_FOUND",
        }.get(sw2, "UNKNOWN_ERROR")
    if sw1 == 0x69:
        return {
            0x82: "SECURITY_STATUS_NOT_SATISFIED",
            0x85: "CONDITIONS_NOT_SATISFIED",
            0x88: "REF_DATA_INVALID",
        }.get(sw2, "UNKNOWN_ERROR")
    if sw1 == 0x6A and sw2 == 0x82:
        return "FILE_NOT_FOUND"
    if sw1 == 0x6A and sw2 == 0x86:
        return "INCORRECT_P1_P2"
    return "UNKNOWN_ERROR"


def hex_nibble(ch: str) -> tuple[bool, int]:
    if "0" <= ch <= "9":
        return True, ord(ch) - ord("0")
    if "a" <= ch <= "f":
        return True, ord(ch) - ord("a") + 10
    if "A" <= ch <= "F":
        return True, ord(ch) - ord("A") + 10
    return False, 0


def parse_hex_fixed(hex_string: str, expected_len: int) -> bytes | None:
    if len(hex_string) != expected_len * 2:
        return None

    out = bytearray()
    for index in range(expected_len):
        ok_upper, upper = hex_nibble(hex_string[index * 2])
        ok_lower, lower = hex_nibble(hex_string[index * 2 + 1])
        if not ok_upper or not ok_lower:
            return None
        out.append((upper << 4) | lower)

    return bytes(out)


def write_u32_le(value: int) -> bytes:
    return bytes(
        [
            value & 0xFF,
            (value >> 8) & 0xFF,
            (value >> 16) & 0xFF,
            (value >> 24) & 0xFF,
        ]
    )


def bcd_to_decimal(value: int) -> int:
    return ((value >> 4) & 0x0F) * 10 + (value & 0x0F)


def decode_u24_le(buf: bytes | bytearray | list[int] | tuple[int, int, int]) -> int:
    return buf[0] | (buf[1] << 8) | (buf[2] << 16)


@pytest.mark.parametrize(
    ("sw1", "sw2", "expected"),
    [
        (0x91, 0x00, "OK"),
        (0x91, 0xAE, "AUTHENTICATION_ERROR"),
        (0x91, 0xBE, "BOUNDARY_ERROR"),
        (0x91, 0xEE, "MEMORY_ERROR"),
        (0x91, 0x1E, "INTEGRITY_ERROR"),
        (0x91, 0x7E, "LENGTH_ERROR"),
        (0x91, 0x9D, "PERMISSION_DENIED"),
        (0x91, 0xCA, "COMMAND_ABORTED"),
        (0x91, 0x9E, "PARAMETER_ERROR"),
        (0x91, 0x40, "NO_SUCH_KEY"),
        (0x91, 0xAD, "AUTHENTICATION_DELAY"),
        (0x91, 0xF0, "FILE_NOT_FOUND"),
        (0x69, 0x82, "SECURITY_STATUS_NOT_SATISFIED"),
        (0x69, 0x85, "CONDITIONS_NOT_SATISFIED"),
        (0x69, 0x88, "REF_DATA_INVALID"),
        (0x6A, 0x82, "FILE_NOT_FOUND"),
        (0x6A, 0x86, "INCORRECT_P1_P2"),
    ],
)
def test_ntag424_error_name_known_codes(sw1: int, sw2: int, expected: str) -> None:
    assert ntag424_error_name(sw1, sw2) == expected


@pytest.mark.parametrize("sw1, sw2", [(0x91, 0x01), (0x69, 0x00), (0x6B, 0x82)])
def test_ntag424_error_name_unknown_codes(sw1: int, sw2: int) -> None:
    assert ntag424_error_name(sw1, sw2) == "UNKNOWN_ERROR"


@pytest.mark.parametrize("ch, expected", [(str(i), i) for i in range(10)])
def test_hex_nibble_digits(ch: str, expected: int) -> None:
    assert hex_nibble(ch) == (True, expected)


@pytest.mark.parametrize(
    "ch, expected",
    [("a", 10), ("b", 11), ("c", 12), ("d", 13), ("e", 14), ("f", 15)],
)
def test_hex_nibble_lowercase(ch: str, expected: int) -> None:
    assert hex_nibble(ch) == (True, expected)


@pytest.mark.parametrize(
    "ch, expected",
    [("A", 10), ("B", 11), ("C", 12), ("D", 13), ("E", 14), ("F", 15)],
)
def test_hex_nibble_uppercase(ch: str, expected: int) -> None:
    assert hex_nibble(ch) == (True, expected)


@pytest.mark.parametrize("ch", ["g", "z", "!", " "])
def test_hex_nibble_invalid_chars(ch: str) -> None:
    ok, _ = hex_nibble(ch)
    assert ok is False


@pytest.mark.parametrize(
    "hex_string, expected_len, expected_bytes",
    [
        ("", 0, b""),
        ("00", 1, b"\x00"),
        ("0a1B", 2, bytes([0x0A, 0x1B])),
        ("12345678", 4, bytes([0x12, 0x34, 0x56, 0x78])),
        ("DEADBEEF", 4, bytes([0xDE, 0xAD, 0xBE, 0xEF])),
    ],
)
def test_parse_hex_fixed_valid_inputs(
    hex_string: str, expected_len: int, expected_bytes: bytes
) -> None:
    assert parse_hex_fixed(hex_string, expected_len) == expected_bytes


@pytest.mark.parametrize(
    "hex_string, expected_len",
    [("0", 1), ("0011", 1), ("AA", 2), ("abc", 2)],
)
def test_parse_hex_fixed_wrong_length_returns_none(
    hex_string: str, expected_len: int
) -> None:
    assert parse_hex_fixed(hex_string, expected_len) is None


@pytest.mark.parametrize("hex_string", ["GG", "0x", "12!4", "zz"])
def test_parse_hex_fixed_invalid_chars_return_none(hex_string: str) -> None:
    assert parse_hex_fixed(hex_string, len(hex_string) // 2) is None


def test_parse_hex_fixed_round_trip_known_bytes() -> None:
    original = bytes([0x00, 0x01, 0xAB, 0xCD, 0xEF])
    hex_string = original.hex()
    assert parse_hex_fixed(hex_string, len(original)) == original


@pytest.mark.parametrize(
    "value, expected",
    [
        (0, bytes([0, 0, 0, 0])),
        (1, bytes([1, 0, 0, 0])),
        (256, bytes([0, 1, 0, 0])),
        (0x12345678, bytes([0x78, 0x56, 0x34, 0x12])),
        (0xFFFFFFFF, bytes([0xFF, 0xFF, 0xFF, 0xFF])),
    ],
)
def test_write_u32_le(value: int, expected: bytes) -> None:
    assert write_u32_le(value) == expected


@pytest.mark.parametrize(
    "value, expected",
    [(0x00, 0), (0x12, 12), (0x99, 99), (0x10, 10)],
)
def test_bcd_to_decimal(value: int, expected: int) -> None:
    assert bcd_to_decimal(value) == expected


@pytest.mark.parametrize(
    "buf, expected",
    [
        ([0, 0, 0], 0),
        ([1, 0, 0], 1),
        ([0, 1, 0], 256),
        ([0xFF, 0xFF, 0xFF], 0xFFFFFF),
    ],
)
def test_decode_u24_le(buf: list[int], expected: int) -> None:
    assert decode_u24_le(buf) == expected


class TestWriteHexToBuf:
    """Tests for write_hex_to_buf — buffer-based hex conversion replacing convertIntToHex."""

    def _write_hex_to_buf(self, buf, data):
        """Python reimplementation of C++ write_hex_to_buf."""
        hex_chars = "0123456789ABCDEF"
        for i, b in enumerate(data):
            buf[i * 2] = hex_chars[b >> 4]
            buf[i * 2 + 1] = hex_chars[b & 0x0F]
        buf[len(data) * 2] = '\0'
        return ''.join(buf[:len(data) * 2])

    def test_single_byte(self):
        buf = ['\0'] * 10
        result = self._write_hex_to_buf(buf, [0xAB])
        assert result == "AB"

    def test_zero_byte(self):
        buf = ['\0'] * 10
        result = self._write_hex_to_buf(buf, [0x00])
        assert result == "00"

    def test_empty_input(self):
        buf = ['\0'] * 10
        result = self._write_hex_to_buf(buf, [])
        assert result == ""

    def test_full_uid_7bytes(self):
        uid = [0x04, 0x10, 0x65, 0xFA, 0x96, 0x73, 0x80]
        buf = ['\0'] * 20
        result = self._write_hex_to_buf(buf, uid)
        assert result == "041065FA967380"

    def test_full_uid_4bytes(self):
        uid = [0xDE, 0xAD, 0xBE, 0xEF]
        buf = ['\0'] * 10
        result = self._write_hex_to_buf(buf, uid)
        assert result == "DEADBEEF"

    def test_all_zeros(self):
        uid = [0x00, 0x00, 0x00, 0x00]
        buf = ['\0'] * 10
        result = self._write_hex_to_buf(buf, uid)
        assert result == "00000000"

    def test_all_ff(self):
        uid = [0xFF, 0xFF, 0xFF, 0xFF]
        buf = ['\0'] * 10
        result = self._write_hex_to_buf(buf, uid)
        assert result == "FFFFFFFF"

    def test_16_byte_key(self):
        key = [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
               0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11]
        buf = ['\0'] * 34
        result = self._write_hex_to_buf(buf, key)
        assert result == "11111111111111111111111111111111"

    def test_mixed_nibbles(self):
        """Each nibble value 0-F appears."""
        data = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]
        buf = ['\0'] * 20
        result = self._write_hex_to_buf(buf, data)
        assert result == "0123456789ABCDEF"
