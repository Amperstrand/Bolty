import pytest


class IdleCardKind:
    NONE = 0
    BLANK = 1
    UNKNOWN = 2
    PROGRAMMED = 3


class KeyConfidence:
    UNKNOWN = 0
    PARTIAL = 1
    HIGH = 2


class CardAssessment:
    def __init__(self):
        self.present = False
        self.is_ntag424 = False
        self.uid = bytearray(12)
        self.uid_len = 0
        self.kind = IdleCardKind.NONE
        self.key_versions = [0xFF] * 5
        self.key_confidence = [KeyConfidence.UNKNOWN] * 5
        self.zero_key_auth_ok = False
        self.has_ndef = False
        self.has_uri = False
        self.looks_like_boltcard = False
        self.deterministic_k1_match = False
        self.deterministic_full_match = False
        self.reset_eligible = False


def reset_card_assessment(a: CardAssessment) -> None:
    a.present = False
    a.is_ntag424 = False
    a.uid = bytearray(12)
    a.uid_len = 0
    a.kind = IdleCardKind.NONE
    a.key_versions = [0xFF] * 5
    a.key_confidence = [KeyConfidence.UNKNOWN] * 5
    a.zero_key_auth_ok = False
    a.has_ndef = False
    a.has_uri = False
    a.looks_like_boltcard = False
    a.deterministic_k1_match = False
    a.deterministic_full_match = False
    a.reset_eligible = False


def crypto_memcmp(a: bytes, b: bytes, length: int) -> bool:
    diff = 0
    for i in range(length):
        diff |= a[i] ^ b[i]
    return diff == 0


def same_uid(assessment: CardAssessment, uid: bytes, uid_len: int) -> bool:
    return (
        assessment.present
        and assessment.uid_len == uid_len
        and crypto_memcmp(bytes(assessment.uid), uid, uid_len)
    )


def make_dirty_assessment() -> CardAssessment:
    assessment = CardAssessment()
    assessment.present = True
    assessment.is_ntag424 = True
    assessment.uid = bytearray([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
    assessment.uid_len = 7
    assessment.kind = IdleCardKind.PROGRAMMED
    assessment.key_versions = [0, 1, 2, 3, 4]
    assessment.key_confidence = [
        KeyConfidence.HIGH,
        KeyConfidence.PARTIAL,
        KeyConfidence.HIGH,
        KeyConfidence.PARTIAL,
        KeyConfidence.HIGH,
    ]
    assessment.zero_key_auth_ok = True
    assessment.has_ndef = True
    assessment.has_uri = True
    assessment.looks_like_boltcard = True
    assessment.deterministic_k1_match = True
    assessment.deterministic_full_match = True
    assessment.reset_eligible = True
    return assessment


class TestResetCardAssessment:
    def test_defaults_after_reset(self) -> None:
        assessment = CardAssessment()
        reset_card_assessment(assessment)

        assert assessment.present is False
        assert assessment.is_ntag424 is False
        assert assessment.uid == bytearray(12)
        assert assessment.uid_len == 0
        assert assessment.kind == IdleCardKind.NONE
        assert assessment.key_versions == [0xFF] * 5
        assert assessment.key_confidence == [KeyConfidence.UNKNOWN] * 5
        assert assessment.zero_key_auth_ok is False
        assert assessment.has_ndef is False
        assert assessment.has_uri is False
        assert assessment.looks_like_boltcard is False
        assert assessment.deterministic_k1_match is False
        assert assessment.deterministic_full_match is False
        assert assessment.reset_eligible is False

    def test_key_versions_are_0xFF(self) -> None:
        assessment = make_dirty_assessment()
        reset_card_assessment(assessment)

        assert assessment.key_versions == [0xFF, 0xFF, 0xFF, 0xFF, 0xFF]

    def test_key_confidence_unknown(self) -> None:
        assessment = make_dirty_assessment()
        reset_card_assessment(assessment)

        assert assessment.key_confidence == [KeyConfidence.UNKNOWN] * 5

    def test_kind_is_none(self) -> None:
        assessment = make_dirty_assessment()
        reset_card_assessment(assessment)

        assert assessment.kind == IdleCardKind.NONE

    def test_uid_zeroed(self) -> None:
        assessment = make_dirty_assessment()
        reset_card_assessment(assessment)

        assert assessment.uid == bytearray(12)
        assert list(assessment.uid) == [0] * 12

    def test_boolean_fields_false(self) -> None:
        assessment = make_dirty_assessment()
        reset_card_assessment(assessment)

        assert assessment.present is False
        assert assessment.is_ntag424 is False
        assert assessment.zero_key_auth_ok is False
        assert assessment.has_ndef is False
        assert assessment.has_uri is False
        assert assessment.looks_like_boltcard is False
        assert assessment.deterministic_k1_match is False
        assert assessment.deterministic_full_match is False
        assert assessment.reset_eligible is False

    def test_reset_after_modification(self) -> None:
        assessment = make_dirty_assessment()

        reset_card_assessment(assessment)

        assert assessment.uid_len == 0
        assert assessment.kind == IdleCardKind.NONE
        assert assessment.key_versions == [0xFF] * 5
        assert assessment.key_confidence == [KeyConfidence.UNKNOWN] * 5
        assert assessment.reset_eligible is False

    def test_reset_idempotent(self) -> None:
        assessment = make_dirty_assessment()

        reset_card_assessment(assessment)
        first_state = assessment.__dict__.copy()
        reset_card_assessment(assessment)

        assert assessment.__dict__ == first_state


class TestSameUid:
    def test_same_uid_returns_true(self) -> None:
        assessment = CardAssessment()
        uid = bytes([0x04, 0x10, 0x65, 0xAA, 0xBB, 0xCC, 0xDD])
        assessment.present = True
        assessment.uid[: len(uid)] = uid
        assessment.uid_len = len(uid)

        assert same_uid(assessment, uid, len(uid)) is True

    def test_different_uid_returns_false(self) -> None:
        assessment = CardAssessment()
        assessment.present = True
        assessment.uid[:7] = bytes([0x04, 0x10, 0x65, 0xAA, 0xBB, 0xCC, 0xDD])
        assessment.uid_len = 7

        assert same_uid(assessment, bytes([0x04, 0x10, 0x65, 0xAA, 0xBB, 0xCC, 0xDE]), 7) is False

    def test_not_present_returns_false(self) -> None:
        assessment = CardAssessment()
        uid = bytes([0x04, 0x10, 0x65, 0xAA, 0xBB, 0xCC, 0xDD])
        assessment.uid[: len(uid)] = uid
        assessment.uid_len = len(uid)

        assert same_uid(assessment, uid, len(uid)) is False

    def test_wrong_length_returns_false(self) -> None:
        assessment = CardAssessment()
        uid = bytes([0x04, 0x10, 0x65, 0xAA, 0xBB, 0xCC, 0xDD])
        assessment.present = True
        assessment.uid[: len(uid)] = uid
        assessment.uid_len = len(uid)

        assert same_uid(assessment, uid[:-1], len(uid) - 1) is False

    def test_empty_uid(self) -> None:
        assessment = CardAssessment()
        assessment.present = True
        assessment.uid_len = 0

        assert same_uid(assessment, b"", 0) is True

    def test_partial_match(self) -> None:
        assessment = CardAssessment()
        assessment.present = True
        assessment.uid[:7] = bytes([0x04, 0x10, 0x65, 0xAA, 0xBB, 0xCC, 0xDD])
        assessment.uid_len = 7

        assert same_uid(assessment, bytes([0x04, 0x10, 0x65, 0xAA, 0x01, 0x02, 0x03]), 7) is False

    def test_single_byte_uid(self) -> None:
        assessment = CardAssessment()
        assessment.present = True
        assessment.uid[0] = 0xAB
        assessment.uid_len = 1

        assert same_uid(assessment, bytes([0xAB]), 1) is True
