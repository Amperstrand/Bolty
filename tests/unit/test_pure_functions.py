import pytest


# --- convertIntToHex (from bolt.h) ---

def convert_int_to_hex(data: bytes) -> str:
    return "".join(f"{b:02X}" for b in data)


class TestConvertIntToHex:
    def test_empty_input(self) -> None:
        assert convert_int_to_hex(b"") == ""

    def test_single_byte(self) -> None:
        assert convert_int_to_hex(b"\x00") == "00"
        assert convert_int_to_hex(b"\xFF") == "FF"
        assert convert_int_to_hex(b"\xAB") == "AB"

    def test_multi_byte(self) -> None:
        assert convert_int_to_hex(b"\x01\x23\x45\x67") == "01234567"

    def test_aes_key_16_bytes(self) -> None:
        key = bytes([0x11] * 16)
        assert convert_int_to_hex(key) == "11111111111111111111111111111111"

    def test_all_zeros(self) -> None:
        assert convert_int_to_hex(bytes(4)) == "00000000"

    def test_uppercase_output(self) -> None:
        assert convert_int_to_hex(b"\x0a\x0b\x0c") == "0A0B0C"


# --- convertCharToHex (from bolt.h) ---

def convert_char_to_hex(ch: str) -> int:
    upper = ch.upper()
    if "0" <= upper <= "9":
        return ord(upper) - ord("0")
    if "A" <= upper <= "F":
        return ord(upper) - ord("A") + 10
    return 0


class TestConvertCharToHex:
    @pytest.mark.parametrize("ch,expected", [
        ("0", 0), ("1", 1), ("2", 2), ("3", 3), ("4", 4),
        ("5", 5), ("6", 6), ("7", 7), ("8", 8), ("9", 9),
    ])
    def test_digits(self, ch: str, expected: int) -> None:
        assert convert_char_to_hex(ch) == expected

    @pytest.mark.parametrize("ch,expected", [
        ("A", 10), ("B", 11), ("C", 12), ("D", 13), ("E", 14), ("F", 15),
    ])
    def test_uppercase_hex(self, ch: str, expected: int) -> None:
        assert convert_char_to_hex(ch) == expected

    @pytest.mark.parametrize("ch,expected", [
        ("a", 10), ("b", 11), ("c", 12), ("d", 13), ("e", 14), ("f", 15),
    ])
    def test_lowercase_hex(self, ch: str, expected: int) -> None:
        assert convert_char_to_hex(ch) == expected

    @pytest.mark.parametrize("ch", ["g", "z", "G", "Z", " ", "!", "\x00", "\xff"])
    def test_invalid_returns_zero(self, ch: str) -> None:
        assert convert_char_to_hex(ch) == 0


# --- ndef_extract_uri (from bolty_utils.h) ---

NDEF_HTTPS_PREFIX = 0x04


def build_ndef_record(payload: str, prefix: int = NDEF_HTTPS_PREFIX) -> bytes:
    payload_bytes = bytes([prefix]) + payload.encode("ascii")
    payload_len = len(payload_bytes)
    header = bytes([
        0xD1,
        0x01,
        payload_len,
        0x55,
    ])
    return header + payload_bytes


def ndef_extract_uri(ndef: bytes) -> str | None:
    if len(ndef) < 5:
        return None
    for i in range(len(ndef) - 4):
        if ndef[i] == 0xD1 and ndef[i + 1] == 0x01 and ndef[i + 3] == 0x55:
            payload_len = ndef[i + 2]
            if payload_len < 1 or i + 4 + payload_len > len(ndef):
                return None
            prefix = ndef[i + 4]
            prefix_map = {
                0x00: "",
                0x01: "http://www.",
                0x02: "https://www.",
                0x03: "http://",
                0x04: "https://",
            }
            base = prefix_map.get(prefix, "")
            for j in range(payload_len - 1):
                ch = ndef[i + 5 + j]
                base += chr(ch) if 0x20 <= ch < 0x7F else "."
            return base
    return None


class TestNdefExtractUri:
    def test_https_uri(self) -> None:
        ndef = build_ndef_record("example.com/ln", 0x04)
        result = ndef_extract_uri(ndef)
        assert result == "https://example.com/ln"

    def test_http_uri(self) -> None:
        ndef = build_ndef_record("example.com/bolt", 0x03)
        result = ndef_extract_uri(ndef)
        assert result == "http://example.com/bolt"

    def test_http_www_prefix(self) -> None:
        ndef = build_ndef_record("example.com", 0x01)
        result = ndef_extract_uri(ndef)
        assert result == "http://www.example.com"

    def test_https_www_prefix(self) -> None:
        ndef = build_ndef_record("example.com", 0x02)
        result = ndef_extract_uri(ndef)
        assert result == "https://www.example.com"

    def test_no_prefix(self) -> None:
        ndef = build_ndef_record("example.com", 0x00)
        result = ndef_extract_uri(ndef)
        assert result == "example.com"

    def test_unknown_prefix_returns_empty_base(self) -> None:
        ndef = build_ndef_record("example.com", 0x05)
        result = ndef_extract_uri(ndef)
        assert result == "example.com"

    def test_too_short_input(self) -> None:
        assert ndef_extract_uri(bytes(4)) is None
        assert ndef_extract_uri(bytes(0)) is None
        assert ndef_extract_uri(bytes(3)) is None

    def test_no_ndef_header_found(self) -> None:
        assert ndef_extract_uri(b"\x00\x00\x00\x00\x00") is None

    def test_payload_exceeds_buffer(self) -> None:
        ndef = bytes([0xD1, 0x01, 0x20, 0x55, 0x04])
        assert ndef_extract_uri(ndef) is None

    def test_non_printable_chars_replaced(self) -> None:
        payload = bytes([0x04, 0x41, 0x00, 0x42])
        ndef = bytes([0xD1, 0x01, len(payload), 0x55]) + payload
        result = ndef_extract_uri(ndef)
        assert result == "https://A.B"

    def test_ndef_record_at_offset(self) -> None:
        padding = bytes([0x00, 0x00, 0x00])
        ndef = padding + build_ndef_record("test.com", 0x04)
        result = ndef_extract_uri(ndef)
        assert result == "https://test.com"

    def test_full_boltcard_url(self) -> None:
        url = "lnurlw.example.com/bolt?p=ABCDEF0123456789ABCDEF0123456789&c=0123456789ABCDEF"
        ndef = build_ndef_record(url, 0x04)
        result = ndef_extract_uri(ndef)
        assert result == "https://" + url


# --- store_hex_string (from bolty_utils.h) ---

def store_hex_string(data: bytes, out_size: int) -> str:
    hex_str = convert_int_to_hex(data)
    result = hex_str[:out_size - 1] if out_size > 0 else ""
    return result


class TestStoreHexString:
    def test_exact_fit(self) -> None:
        result = store_hex_string(b"\xAB\xCD", 5)
        assert result == "ABCD"

    def test_truncated(self) -> None:
        result = store_hex_string(b"\xAB\xCD\xEF", 5)
        assert result == "ABCD"

    def test_extra_space(self) -> None:
        result = store_hex_string(b"\xAB", 5)
        assert result == "AB"

    def test_zero_size(self) -> None:
        result = store_hex_string(b"\xAB", 0)
        assert result == ""

    def test_single_byte_output(self) -> None:
        result = store_hex_string(b"\xFF", 1)
        assert result == ""
