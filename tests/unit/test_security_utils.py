import pytest


# --- crypto_memcmp (from bolty_utils.h) ---

def crypto_memcmp(a: bytes, b: bytes, length: int) -> bool:
    diff = 0
    for i in range(length):
        diff |= a[i] ^ b[i]
    return diff == 0


class TestCryptoMemcmp:
    def test_equal_empty(self) -> None:
        assert crypto_memcmp(b"", b"", 0) is True

    def test_equal_single_byte(self) -> None:
        assert crypto_memcmp(b"\x42", b"\x42", 1) is True

    def test_equal_16_bytes(self) -> None:
        data = bytes(range(16))
        assert crypto_memcmp(data, data, 16) is True

    def test_unequal_first_byte(self) -> None:
        assert crypto_memcmp(b"\x01\x02\x03", b"\x00\x02\x03", 3) is False

    def test_unequal_last_byte(self) -> None:
        assert crypto_memcmp(b"\x01\x02\x03", b"\x01\x02\x04", 3) is False

    def test_unequal_single_bit(self) -> None:
        assert crypto_memcmp(b"\b", b"\t", 1) is False

    def test_all_zeros_equal(self) -> None:
        zeros = bytes(16)
        assert crypto_memcmp(zeros, zeros, 16) is True

    def test_all_ff_equal(self) -> None:
        data = bytes([0xFF] * 16)
        assert crypto_memcmp(data, data, 16) is True

    def test_zero_length(self) -> None:
        assert crypto_memcmp(b"abc", b"xyz", 0) is True

    def test_partial_compare(self) -> None:
        assert crypto_memcmp(b"prefix-match-A", b"prefix-match-B", 12) is True

    def test_partial_compare_detects_difference_within_range(self) -> None:
        assert crypto_memcmp(b"abc123", b"abc023", 6) is False

    def test_multiple_mismatches_still_false(self) -> None:
        assert crypto_memcmp(b"\x00\x11\x22\x33", b"\xFF\x11\x00\x33", 4) is False


# --- safe_strcpy (from bolty_utils.h) ---

def safe_strcpy(src: str, dst_size: int) -> str:
    if dst_size == 0:
        return ""
    result = src[: dst_size - 1]
    return result


class TestSafeStrcpy:
    def test_normal_copy(self) -> None:
        assert safe_strcpy("hello", 10) == "hello"

    def test_exact_fit(self) -> None:
        assert safe_strcpy("hello", 6) == "hello"

    def test_truncation(self) -> None:
        assert safe_strcpy("helloworld", 5) == "hell"

    def test_zero_size(self) -> None:
        assert safe_strcpy("ignored", 0) == ""

    def test_size_one(self) -> None:
        assert safe_strcpy("ignored", 1) == ""

    def test_empty_src(self) -> None:
        assert safe_strcpy("", 10) == ""

    def test_long_string(self) -> None:
        src = "x" * 100
        assert safe_strcpy(src, 33) == "x" * 32

    @pytest.mark.parametrize(
        ("src", "dst_size", "expected"),
        [
            ("hello", 10, "hello"),
            ("hello", 6, "hello"),
            ("helloworld", 5, "hell"),
            ("A", 2, "A"),
            ("AB", 2, "A"),
            ("", 1, ""),
        ],
    )
    def test_null_terminator_position(self, src: str, dst_size: int, expected: str) -> None:
        result = safe_strcpy(src, dst_size)
        assert result == expected
        assert len(result) <= max(dst_size - 1, 0)

    def test_single_char(self) -> None:
        assert safe_strcpy("A", 2) == "A"

    def test_single_char_truncation(self) -> None:
        assert safe_strcpy("AB", 2) == "A"

    def test_unicode_copy_preserves_characters(self) -> None:
        assert safe_strcpy("héllo", 10) == "héllo"

    def test_large_dst_size_keeps_full_source(self) -> None:
        assert safe_strcpy("short", 100) == "short"


# --- secure_memzero (from bolty_utils.h) ---

def secure_memzero(data: bytearray | None, length: int) -> bytearray | None:
    if data is None:
        return data
    for i in range(min(length, len(data))):
        data[i] = 0
    return data


class TestSecureMemzero:
    def test_normal_zeroing(self) -> None:
        data = bytearray(b"secret\x00\x00\x00")
        result = secure_memzero(data, 6)
        assert result is not None
        assert result[:6] == bytearray(b"\x00" * 6)
        assert result[6:] == bytearray(b"\x00\x00\x00")

    def test_zero_length(self) -> None:
        data = bytearray(b"secret")
        result = secure_memzero(data, 0)
        assert result == bytearray(b"secret")

    def test_full_buffer(self) -> None:
        data = bytearray(b"12345678")
        assert secure_memzero(data, len(data)) == bytearray(b"\x00" * 8)

    def test_partial_zeroing(self) -> None:
        data = bytearray(b"abcdefgh")
        result = secure_memzero(data, 4)
        assert result == bytearray(b"\x00\x00\x00\x00efgh")

    def test_single_byte(self) -> None:
        data = bytearray(b"Z")
        assert secure_memzero(data, 1) == bytearray(b"\x00")

    def test_already_zero(self) -> None:
        data = bytearray(b"\x00" * 4)
        assert secure_memzero(data, 4) == bytearray(b"\x00" * 4)

    def test_length_larger_than_buffer(self) -> None:
        data = bytearray(b"abc")
        assert secure_memzero(data, 10) == bytearray(b"\x00\x00\x00")

    def test_none_input(self) -> None:
        assert secure_memzero(None, 4) is None

    def test_returns_same_object(self) -> None:
        data = bytearray(b"token")
        result = secure_memzero(data, 3)
        assert result is data
        assert data == bytearray(b"\x00\x00\x00en")
