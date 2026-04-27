import pytest

from test_picc_data import (
    aes_128_cbc_decrypt,
    aes_128_cbc_encrypt,
    aes_128_cmac,
    ntag424_cmac_short,
    build_sv2,
    make_picc_vector,
)


TEST_K1 = bytes.fromhex("00112233445566778899aabbccddeeff")
TEST_K2 = bytes.fromhex("0f1e2d3c4b5a69788796a5b4c3d2e1f0")
TEST_UID = bytes.fromhex("87112233445566")
ALT_K1 = bytes.fromhex("ffeeddccbbaa99887766554433221100")
ALT_K2 = bytes.fromhex("f0e1d2c3b4a5968778695a4b3c2d1e0f")
ALT_UID = bytes.fromhex("87010203040506")


def deterministic_decrypt_p(k1: bytes, p_bytes: bytes, uid: bytes) -> tuple[bool, bytes | None, int]:
    """
    Decrypt p= parameter with K1, validate PICC format (0xC7) and UID match.
    Returns (success, decrypted_bytes, counter).
    """
    decrypted = aes_128_cbc_decrypt(k1, p_bytes)
    if decrypted[0] != 0xC7:
        return False, None, 0
    if decrypted[1:8] != uid:
        return False, None, 0
    counter = decrypted[8] | (decrypted[9] << 8) | (decrypted[10] << 16)
    return True, decrypted, counter


def deterministic_verify_cmac(k2: bytes, uid: bytes, counter: int, expected_c: bytes) -> bool:
    """
    Build SV2 from uid+counter, derive session key via CMAC(K2, SV2),
    compute CMAC(session_key, empty), extract odd bytes, compare with expected_c.
    """
    sv2 = build_sv2(uid, counter)
    session_key = aes_128_cmac(k2, sv2)
    full_cmac = aes_128_cmac(session_key, b"")
    computed_c = ntag424_cmac_short(full_cmac)
    return computed_c == expected_c


@pytest.fixture
def known_vector():
    return make_picc_vector(TEST_K1, TEST_K2, TEST_UID, 0x010203)


class TestDeterministicDecryptP:
    def test_valid_decryption(self, known_vector) -> None:
        success, decrypted, counter = deterministic_decrypt_p(
            known_vector.k1,
            bytes.fromhex(known_vector.p_hex),
            known_vector.uid,
        )

        assert success is True
        assert decrypted is not None
        assert decrypted == known_vector.plaintext
        assert decrypted[1:8] == known_vector.uid
        assert counter == known_vector.counter

    def test_wrong_key(self, known_vector) -> None:
        success, decrypted, counter = deterministic_decrypt_p(
            ALT_K1,
            bytes.fromhex(known_vector.p_hex),
            known_vector.uid,
        )

        assert success is False
        assert decrypted is None
        assert counter == 0

    def test_wrong_uid(self, known_vector) -> None:
        success, decrypted, counter = deterministic_decrypt_p(
            known_vector.k1,
            bytes.fromhex(known_vector.p_hex),
            ALT_UID,
        )

        assert success is False
        assert decrypted is None
        assert counter == 0

    def test_invalid_format_byte(self) -> None:
        counter = 0x010203
        plaintext = bytes([0x00]) + TEST_UID + counter.to_bytes(3, "little") + bytes(5)
        p_bytes = aes_128_cbc_encrypt(TEST_K1, plaintext)

        success, decrypted, extracted_counter = deterministic_decrypt_p(TEST_K1, p_bytes, TEST_UID)

        assert success is False
        assert decrypted is None
        assert extracted_counter == 0

    @pytest.mark.parametrize("counter", [0, 255, 0xFFFFFF])
    def test_counter_extraction(self, counter: int) -> None:
        vector = make_picc_vector(TEST_K1, TEST_K2, TEST_UID, counter)

        success, decrypted, extracted_counter = deterministic_decrypt_p(
            vector.k1,
            bytes.fromhex(vector.p_hex),
            vector.uid,
        )

        assert success is True
        assert decrypted == vector.plaintext
        assert extracted_counter == counter

    def test_zero_counter(self) -> None:
        vector = make_picc_vector(TEST_K1, TEST_K2, TEST_UID, 0)

        success, decrypted, counter = deterministic_decrypt_p(
            vector.k1,
            bytes.fromhex(vector.p_hex),
            vector.uid,
        )

        assert success is True
        assert decrypted is not None
        assert counter == 0

    def test_max_counter(self) -> None:
        vector = make_picc_vector(TEST_K1, TEST_K2, TEST_UID, 0xFFFFFF)

        success, decrypted, counter = deterministic_decrypt_p(
            vector.k1,
            bytes.fromhex(vector.p_hex),
            vector.uid,
        )

        assert success is True
        assert decrypted is not None
        assert counter == 0xFFFFFF

    def test_different_keys_different_ciphertexts(self) -> None:
        vector_one = make_picc_vector(TEST_K1, TEST_K2, TEST_UID, 0x010203)
        vector_two = make_picc_vector(ALT_K1, TEST_K2, TEST_UID, 0x010203)

        assert vector_one.plaintext == vector_two.plaintext
        assert vector_one.p_hex != vector_two.p_hex


class TestDeterministicVerifyCmac:
    def test_valid_cmac(self, known_vector) -> None:
        assert deterministic_verify_cmac(
            known_vector.k2,
            known_vector.uid,
            known_vector.counter,
            bytes.fromhex(known_vector.c_hex),
        ) is True

    def test_wrong_k2(self, known_vector) -> None:
        assert deterministic_verify_cmac(
            ALT_K2,
            known_vector.uid,
            known_vector.counter,
            bytes.fromhex(known_vector.c_hex),
        ) is False

    def test_wrong_uid(self, known_vector) -> None:
        assert deterministic_verify_cmac(
            known_vector.k2,
            ALT_UID,
            known_vector.counter,
            bytes.fromhex(known_vector.c_hex),
        ) is False

    def test_wrong_counter(self, known_vector) -> None:
        assert deterministic_verify_cmac(
            known_vector.k2,
            known_vector.uid,
            known_vector.counter + 1,
            bytes.fromhex(known_vector.c_hex),
        ) is False

    def test_tampered_mac(self, known_vector) -> None:
        tampered_mac = bytearray.fromhex(known_vector.c_hex)
        tampered_mac[0] ^= 0x01

        assert deterministic_verify_cmac(
            known_vector.k2,
            known_vector.uid,
            known_vector.counter,
            bytes(tampered_mac),
        ) is False

    def test_all_zero_mac(self, known_vector) -> None:
        zero_mac = bytes(8)

        assert bytes.fromhex(known_vector.c_hex) != zero_mac
        assert deterministic_verify_cmac(
            known_vector.k2,
            known_vector.uid,
            known_vector.counter,
            zero_mac,
        ) is False

    def test_consistency(self, known_vector) -> None:
        expected_c = bytes.fromhex(known_vector.c_hex)

        first = deterministic_verify_cmac(
            known_vector.k2,
            known_vector.uid,
            known_vector.counter,
            expected_c,
        )
        second = deterministic_verify_cmac(
            known_vector.k2,
            known_vector.uid,
            known_vector.counter,
            expected_c,
        )

        assert first is True
        assert second is True

    @pytest.mark.parametrize("counter", [0, 1, 0x010203, 0xFFFFFF])
    def test_matches_make_picc_vector_outputs(self, counter: int) -> None:
        vector = make_picc_vector(TEST_K1, TEST_K2, TEST_UID, counter)

        assert deterministic_verify_cmac(
            vector.k2,
            vector.uid,
            vector.counter,
            vector.short_mac,
        ) is True
