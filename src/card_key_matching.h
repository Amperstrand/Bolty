#pragma once
#include "bolt.h"
#include "bolty_utils.h"
#include "KeyDerivation.h"
#include "PiccData.h"

extern BoltDevice bolt;
extern sBoltConfig mBoltConfig;
extern volatile bool serial_cmd_active;
extern bool bolty_hw_ready;
extern bool has_issuer_key;
extern CardAssessment g_last_assessment;

static const uint8_t BOLTCARD_ISSUER_KEY_ZERO[AES_KEY_LEN] = {0};
static const uint8_t BOLTCARD_ISSUER_KEY_DEV[AES_KEY_LEN] = {
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x01,
};
static const uint8_t BOLTCARD_ISSUER_KEY_BOLTPOC[AES_KEY_LEN] = {
  0xB0, 0x73, 0x39, 0x59,
  0x68, 0x6C, 0x5D, 0xA2,
  0x74, 0x12, 0x30, 0x84,
  0xB5, 0xC0, 0x78, 0x20,
};
static const uint8_t BOLTCARD_ISSUER_KEY_BOLTPOC2[AES_KEY_LEN] = {
  0x0A, 0x27, 0x62, 0x06,
  0xCC, 0xAE, 0x41, 0x73,
  0x9B, 0x35, 0x41, 0xE2,
  0x85, 0x22, 0x3E, 0xEE,
};
static const uint8_t BOLTCARD_ISSUER_KEY_PROXY[AES_KEY_LEN] = {
  0x55, 0x73, 0x45, 0x71,
  0xCE, 0x72, 0xED, 0x36,
  0x49, 0x94, 0xCF, 0x2F,
  0x20, 0x91, 0x40, 0x92,
};
static const uint8_t BOLTCARD_ISSUER_KEY_PROXY2[AES_KEY_LEN] = {
  0x43, 0x71, 0xF0, 0x15,
  0x9A, 0x98, 0xA8, 0x50,
  0x09, 0xFF, 0x2B, 0xCF,
  0x21, 0xC5, 0xB3, 0x01,
};
static const uint8_t BOLTCARD_ISSUER_KEY_PROXY3[AES_KEY_LEN] = {
  0xCE, 0x20, 0xDA, 0x28,
  0x08, 0x11, 0x14, 0x4B,
  0x0A, 0xAD, 0x13, 0xFD,
  0x87, 0x4E, 0xAE, 0xCA,
};
static const uint32_t BOLTCARD_VERSION_CANDIDATES[4] = {1, 0, 2, 3};
static const uint8_t * const BOLTCARD_ISSUER_KEYS[7] = {
  BOLTCARD_ISSUER_KEY_ZERO,
  BOLTCARD_ISSUER_KEY_DEV,
  BOLTCARD_ISSUER_KEY_BOLTPOC,
  BOLTCARD_ISSUER_KEY_BOLTPOC2,
  BOLTCARD_ISSUER_KEY_PROXY,
  BOLTCARD_ISSUER_KEY_PROXY2,
  BOLTCARD_ISSUER_KEY_PROXY3,
};
static const __FlashStringHelper * const BOLTCARD_ISSUER_KEY_LABELS[7] = {
  F("00000000000000000000000000000000"),
  F("00000000000000000000000000000001"),
  F("b0733959686c5da274123084b5c07820"),
  F("0a276206ccae41739b3541e285223eee"),
  F("55734571ce72ed364994cf2f20914092"),
  F("4371f0159a98a85009ff2bcf21c5b301"),
  F("ce20da280811144b0aad13fd874eaeca"),
};

struct CardTapResult {
  uint8_t uid[MAX_UID_LEN] = {0};
  uint8_t uid_len = 0;
  bool found = false;
};

static CardTapResult wait_for_card(const __FlashStringHelper *timeout_msg,
                                   const __FlashStringHelper *uid_prefix = nullptr,
                                   unsigned long timeout_ms = CARD_TAP_TIMEOUT_MS,
                                   bool settle_after_detect = false) {
  CardTapResult tap;
  const unsigned long t0 = millis();
  do {
    tap.found = bolty_read_passive_target(bolt.nfc, tap.uid, &tap.uid_len);
    if (tap.found) {
      if (uid_prefix != nullptr) {
        Serial.print(uid_prefix);
        bolty_print_hex(bolt.nfc, tap.uid, tap.uid_len);
      }
      if (settle_after_detect) {
        delay(50);
      }
      return tap;
    }
    if (millis() - t0 > timeout_ms) {
      if (timeout_msg != nullptr) {
        Serial.println(timeout_msg);
      }
      serial_cmd_active = false;
      led_blink(5, 100);
      return tap;
    }
  } while (!tap.found);
  return tap;
}

static bool begin_card_command(const __FlashStringHelper *tag) {
  if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return false; }
  Serial.print(tag);
  Serial.println(F(" Tap card now..."));
  serial_cmd_active = true;
  led_on();
  return true;
}

template <typename Fn>
static uint8_t wait_for_card(const __FlashStringHelper *timeout_msg,
                             unsigned long timeout_ms,
                             Fn run_job) {
  const unsigned long t0 = millis();
  uint8_t result = JOBSTATUS_WAITING;
  do {
    while (Serial.available()) Serial.read();
    result = run_job();
    if (millis() - t0 > timeout_ms) {
      if (timeout_msg != nullptr) {
        Serial.println(timeout_msg);
      }
      serial_cmd_active = false;
      return JOBSTATUS_WAITING;
    }
  } while (result == JOBSTATUS_WAITING);
  return result;
}

struct DeterministicBoltcardMatch {
  bool saw_k1_match;
  bool full_match;
  uint32_t counter;
  uint32_t version;
  uint8_t issuer_key[AES_KEY_LEN];
  uint8_t decrypted[AES_KEY_LEN];
  uint8_t keys[5][AES_KEY_LEN];
};

static void derive_deterministic_card_key(BoltyNfcReader *nfc,
                                          const uint8_t issuer_key[AES_KEY_LEN],
                                          const uint8_t uid[7],
                                          uint32_t version,
                                          uint8_t out_card_key[AES_KEY_LEN]) {
  (void)nfc;
  keyderivation_card_key(issuer_key, uid, version, out_card_key);
}

static void derive_deterministic_boltcard_keys(BoltyNfcReader *nfc,
                                               const uint8_t issuer_key[AES_KEY_LEN],
                                               const uint8_t uid[7],
                                               uint32_t version,
                                               uint8_t out_keys[5][AES_KEY_LEN]) {
  (void)nfc;
  keyderivation_boltcard_keys(issuer_key, uid, version, out_keys);
}

// Decrypt SDM PICC data (p= parameter) using derived K1 (encryption key).
// Validates PICC format byte (0xC7) and UID match. Extracts read counter.
// Returns false if decryption fails or UID doesn't match.
// Ref: AN12196 §4.7 (SDM for Metro), NT4H2421Gx datasheet §8.7.2 (PICC data),
//      PiccData.h (PICC_FORMAT_BOLTCARD, PICC_FLAG_* constants)
static bool deterministic_decrypt_p(BoltyNfcReader *nfc,
                                    const uint8_t k1[AES_KEY_LEN],
                                    const uint8_t p[AES_KEY_LEN],
                                    const uint8_t uid[7],
                                    uint8_t decrypted[AES_KEY_LEN],
                                    uint32_t &counter_out) {
  if (!nfc->ntag424_decrypt((uint8_t *)k1, AES_KEY_LEN, (uint8_t *)p,
                            decrypted)) {
    return false;
  }
  if (decrypted[0] != PICC_FORMAT_BOLTCARD) return false;
  if (!crypto_memcmp(decrypted + 1, uid, PICC_UID_BYTE_LEN)) return false;
  counter_out = decode_u24_le(decrypted + 8);
  return true;
}

// Verify SDM MAC (c= parameter) using derived K2 (authentication key).
// Derives session key via SV2 (AES-CMAC of K2 with UID+counter), then computes
// CMAC of empty data and compares odd bytes with the expected 8-byte MAC.
// Ref: AN12196 §4.7 (SDM MAC verification), NT4H2421Gx datasheet §8.7.2,
//      PiccData.h (sdm_build_sv2 helper, SV2_HEADER constants)
static bool deterministic_verify_cmac(BoltyNfcReader *nfc,
                                      const uint8_t k2[AES_KEY_LEN],
                                      const uint8_t uid[7],
                                      uint32_t counter,
                                      const uint8_t expected_c[8]) {
  (void)nfc;
  uint8_t sv2[AES_KEY_LEN] = {};
  sdm_build_sv2(uid, counter, sv2);

  uint8_t session_key[AES_KEY_LEN] = {0};
  AES128_CMAC(k2, sv2, sizeof(sv2), session_key);

  uint8_t full_cmac[AES_KEY_LEN] = {0};
  AES128_CMAC(session_key, nullptr, 0, full_cmac);

  uint8_t computed_c[8] = {0};
  for (int i = 0; i < 8; i++) {
    computed_c[i] = full_cmac[(i * 2) + 1];
  }
  return crypto_memcmp(computed_c, expected_c, sizeof(computed_c));
}

// Try all known issuer keys against card's SDM p=/c= parameters.
// For each issuer key: derives K0-K4, attempts K1 decryption of p=, then K2
// CMAC verification of c=. Tests version candidates 0 and 1. Returns full
// match with derived keys if both K1 and K2 checks pass.
// Ref: boltcard SPEC (deterministic key derivation),
//      KeyDerivation.h (derivation constants KEYDET_TAG_*),
//      AN12196 §6 (CMAC verification)
static bool deterministic_try_known_matches(BoltyNfcReader *nfc,
                                            const uint8_t *uid,
                                            uint8_t uid_len,
                                            const String &uri,
                                            DeterministicBoltcardMatch &match) {
  memset(&match, 0, sizeof(match));
  if (uid == nullptr || uid_len != PICC_UID_BYTE_LEN || uri.length() == 0) return false;

  String p_hex;
  if (!uri_get_query_param(uri, "p", p_hex)) return false;

  uint8_t p_bytes[AES_KEY_LEN] = {0};
  if (!parse_hex_fixed(p_hex, p_bytes, sizeof(p_bytes))) return false;

  String c_hex;
  const bool has_c = uri_get_query_param(uri, "c", c_hex);
  uint8_t c_bytes[8] = {0};
  const bool c_parse_ok = has_c && parse_hex_fixed(c_hex, c_bytes, sizeof(c_bytes));

  for (int candidate = 0; candidate < 7; candidate++) {
    const uint8_t *issuer_key = BOLTCARD_ISSUER_KEYS[candidate];

    uint8_t keys_v1[5][AES_KEY_LEN] = {{0}};
    derive_deterministic_boltcard_keys(nfc, issuer_key, uid, 1, keys_v1);

    uint8_t decrypted[AES_KEY_LEN] = {0};
    uint32_t counter = 0;
    const bool k1_match = deterministic_decrypt_p(nfc, keys_v1[1], p_bytes, uid, decrypted, counter);
    if (!k1_match) continue;

    match.saw_k1_match = true;
    memcpy(match.issuer_key, issuer_key, sizeof(match.issuer_key));
    memcpy(match.decrypted, decrypted, sizeof(match.decrypted));
    match.counter = counter;

    if (!c_parse_ok) {
      return false;
    }

    for (int version_idx = 0; version_idx < 2; version_idx++) {
      const uint32_t version = BOLTCARD_VERSION_CANDIDATES[version_idx];
      uint8_t derived_keys[5][AES_KEY_LEN] = {{0}};
      derive_deterministic_boltcard_keys(nfc, issuer_key, uid, version, derived_keys);
      if (!deterministic_verify_cmac(nfc, derived_keys[2], uid, counter, c_bytes)) continue;

      match.full_match = true;
      match.version = version;
      memcpy(match.keys, derived_keys, sizeof(match.keys));
      return true;
    }

    return false;
  }

  return false;
}
