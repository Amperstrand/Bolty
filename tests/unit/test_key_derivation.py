from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.cmac import CMAC


TAG_CARDKEY = bytes.fromhex("2d003f75")
TAG_K0 = bytes.fromhex("2d003f76")
TAG_K1 = bytes.fromhex("2d003f77")
TAG_K2 = bytes.fromhex("2d003f78")
TAG_K3 = bytes.fromhex("2d003f79")
TAG_K4 = bytes.fromhex("2d003f7a")
TAG_CARDID = bytes.fromhex("2d003f7b")

KNOWN_ISSUER_KEY = bytes.fromhex("00112233445566778899aabbccddeeff")
KNOWN_UID = bytes.fromhex("04968caa5c5e80")
ALT_UID = bytes.fromhex("04968caa5c5e81")

KNOWN_CARD_KEY_V1 = bytes.fromhex("81a5e268b98451b9f737c074d3069fc4")
KNOWN_KEYS_V1 = [
    bytes.fromhex("9f3dd6be582beabc7ac91bd8d228620c"),
    bytes.fromhex("ad7de883fc0d04ed6532edfd1bf275d7"),
    bytes.fromhex("97a6328dd5456bca8a1956be46c7dc6c"),
    bytes.fromhex("0310a0478b575c6e7abf5dca71e2e078"),
    bytes.fromhex("70ac842eab652599451ea93e44105ff4"),
]
KNOWN_CARD_ID = bytes.fromhex("b0698008195a6350d0d56b57fa20a7cf")

ZERO_ISSUER_KEY = bytes(16)
ZERO_UID = bytes(7)
ZERO_CARD_KEY = bytes.fromhex("ae1bd8498ea8ebc891001b8240635427")
ZERO_KEYS = [
    bytes.fromhex("cd949bc7c6a05885c12373b8ff7be9c9"),
    bytes.fromhex("dfea2649f9ce19d0556d0c04cef56fa2"),
    bytes.fromhex("aef75941e95e637847e547db89d70678"),
    bytes.fromhex("0185b206f9fe53bd1666d6726eb869de"),
    bytes.fromhex("115b9c0f6e29188a13a988b8d04f11a6"),
]
ZERO_CARD_ID = bytes.fromhex("83f73b2fb71b4e137b7edbc1c5b467a9")


def aes_128_cmac(key: bytes, message: bytes) -> bytes:
    assert len(key) == 16
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    assert cipher.algorithm.key_size == 128
    cmac = CMAC(algorithms.AES(key))
    cmac.update(message)
    return cmac.finalize()


def le32(value: int) -> bytes:
    return value.to_bytes(4, "little")


def derive_card_key(issuer_key: bytes, uid: bytes, version: int) -> bytes:
    assert len(uid) == 7
    return aes_128_cmac(issuer_key, TAG_CARDKEY + uid + le32(version))


def derive_boltcard_keys(issuer_key: bytes, uid: bytes, version: int) -> list[bytes]:
    card_key = derive_card_key(issuer_key, uid, version)
    return [
        aes_128_cmac(card_key, TAG_K0),
        aes_128_cmac(issuer_key, TAG_K1),
        aes_128_cmac(card_key, TAG_K2),
        aes_128_cmac(card_key, TAG_K3),
        aes_128_cmac(card_key, TAG_K4),
    ]


def derive_card_id(issuer_key: bytes, uid: bytes) -> bytes:
    assert len(uid) == 7
    return aes_128_cmac(issuer_key, TAG_CARDID + uid)


def test_keyderivation_card_key_known_vector_is_16_bytes_and_deterministic() -> None:
    card_key = derive_card_key(KNOWN_ISSUER_KEY, KNOWN_UID, version=1)
    repeat = derive_card_key(KNOWN_ISSUER_KEY, KNOWN_UID, version=1)

    assert len(card_key) == 16
    assert card_key == repeat
    assert card_key == KNOWN_CARD_KEY_V1


def test_keyderivation_boltcard_keys_follow_exact_chain_and_are_all_unique() -> None:
    keys = derive_boltcard_keys(KNOWN_ISSUER_KEY, KNOWN_UID, version=1)
    card_key = derive_card_key(KNOWN_ISSUER_KEY, KNOWN_UID, version=1)

    assert keys == KNOWN_KEYS_V1
    assert len(keys) == 5
    assert all(len(key) == 16 for key in keys)
    assert len(set(keys)) == 5
    assert keys[1] == aes_128_cmac(KNOWN_ISSUER_KEY, TAG_K1)
    assert keys[1] != aes_128_cmac(card_key, TAG_K1)
    assert keys[0] != keys[1] != keys[2] != keys[3] != keys[4]


def test_keyderivation_card_id_is_16_bytes_and_changes_with_uid() -> None:
    card_id = derive_card_id(KNOWN_ISSUER_KEY, KNOWN_UID)
    different_uid_card_id = derive_card_id(KNOWN_ISSUER_KEY, ALT_UID)

    assert len(card_id) == 16
    assert card_id == KNOWN_CARD_ID
    assert different_uid_card_id != card_id


def test_keyderivation_with_all_zero_issuer_key_matches_known_vectors() -> None:
    card_key = derive_card_key(ZERO_ISSUER_KEY, ZERO_UID, version=0)
    keys = derive_boltcard_keys(ZERO_ISSUER_KEY, ZERO_UID, version=0)
    card_id = derive_card_id(ZERO_ISSUER_KEY, ZERO_UID)

    assert card_key == ZERO_CARD_KEY
    assert keys == ZERO_KEYS
    assert card_id == ZERO_CARD_ID
    assert len(set(keys)) == 5


def test_known_inputs_are_fully_deterministic_across_entire_derivation_chain() -> None:
    first = (
        derive_card_key(KNOWN_ISSUER_KEY, KNOWN_UID, version=1),
        derive_boltcard_keys(KNOWN_ISSUER_KEY, KNOWN_UID, version=1),
        derive_card_id(KNOWN_ISSUER_KEY, KNOWN_UID),
    )
    second = (
        derive_card_key(KNOWN_ISSUER_KEY, KNOWN_UID, version=1),
        derive_boltcard_keys(KNOWN_ISSUER_KEY, KNOWN_UID, version=1),
        derive_card_id(KNOWN_ISSUER_KEY, KNOWN_UID),
    )

    assert first == second


def test_version_zero_and_one_produce_different_card_keys_and_derived_keys() -> None:
    card_key_v0 = derive_card_key(KNOWN_ISSUER_KEY, KNOWN_UID, version=0)
    card_key_v1 = derive_card_key(KNOWN_ISSUER_KEY, KNOWN_UID, version=1)
    keys_v0 = derive_boltcard_keys(KNOWN_ISSUER_KEY, KNOWN_UID, version=0)
    keys_v1 = derive_boltcard_keys(KNOWN_ISSUER_KEY, KNOWN_UID, version=1)

    assert card_key_v0 != card_key_v1
    assert keys_v0[0] != keys_v1[0]
    assert keys_v0[2] != keys_v1[2]
    assert keys_v0[3] != keys_v1[3]
    assert keys_v0[4] != keys_v1[4]
    assert keys_v0[1] == keys_v1[1]
