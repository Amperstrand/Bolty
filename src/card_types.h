#pragma once
#include "bolty_utils.h"  // for crypto_memcmp

// ============================================================
// Card Type Definitions and Assessment Helpers
// ============================================================
// Extracted from bolty.ino for modularity. Contains card classification
// enums, the CardAssessment struct, and pure-logic helper functions
// that don't depend on NFC hardware or peripherals.

enum class IdleCardKind : uint8_t {
  none = 0,
  blank,
  unknown,
  programmed,
};

enum class KeyConfidence : uint8_t {
  unknown = 0,
  partial,
  high,
};

struct CardAssessment {
  bool present;
  bool is_ntag424;
  uint8_t uid[12];
  uint8_t uid_len;
  IdleCardKind kind;
  uint8_t key_versions[5];
  KeyConfidence key_confidence[5];
  bool zero_key_auth_ok;
  bool has_ndef;
  bool has_uri;
  bool looks_like_boltcard;
  bool deterministic_k1_match;
  bool deterministic_full_match;
  String uri;
  uint8_t derived_keys[5][16];
  bool reset_eligible;
};

// Zero-initialize a CardAssessment struct, setting default confidence levels and card classification.
// Called before each card scan to start with a clean state.
static void reset_card_assessment(CardAssessment &assessment) {
  memset(&assessment, 0, sizeof(assessment));
  assessment.kind = IdleCardKind::none;
  for (int i = 0; i < 5; i++) {
    assessment.key_versions[i] = 0xFF;
    assessment.key_confidence[i] = KeyConfidence::unknown;
  }
}

// Compare a scanned UID against a stored assessment using constant-time comparison.
// Ref: bolty_utils.h (crypto_memcmp for timing-safe comparison)
static bool same_uid(const CardAssessment &assessment, const uint8_t *uid, uint8_t uid_len) {
  return assessment.present && assessment.uid_len == uid_len && crypto_memcmp(assessment.uid, uid, uid_len);
}
