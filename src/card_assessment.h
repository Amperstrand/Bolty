#pragma once
#include "bolt.h"
#include "bolty_utils.h"
#include "KeyDerivation.h"
#include "PiccData.h"
#include "hardware_config.h"

extern BoltDevice bolt;
extern sBoltConfig mBoltConfig;
extern volatile bool serial_cmd_active;
extern bool bolty_hw_ready;
extern bool has_issuer_key;
extern CardAssessment g_last_assessment;

// Test all hardcoded issuer keys against card's SDM p=/c= parameters.
//
// Iterates through known issuer keys (BOLTCARD_ISSUER_KEYS[]), derives K0-K4
// for each, and attempts K1 decryption + K2 CMAC verification. Reports
// matches with key version, decrypted UID, and read counter.
//
// Ref: boltcard SPEC (deterministic key derivation from issuer key + UID),
//      NT4H2421Gx datasheet §8.7 (SDM), AN12196 §6 (CMAC verification)
static void print_deterministic_boltcard_check(BoltyNfcReader *nfc,
                                               const uint8_t *uid,
                                               uint8_t uid_len,
                                               const String &uri) {
  Serial.println(F("[inspect] --- Deterministic Key Derivation Check ---"));

  if (uid_len != 7) {
    Serial.println(F("[inspect] SKIPPED — deterministic Bolt Card derivation expects a 7-byte UID."));
    return;
  }
  if (uri.length() == 0) {
    Serial.println(F("[inspect] SKIPPED — no URI available for read-only deterministic verification."));
    return;
  }

  String p_hex;
  if (!uri_get_query_param(uri, "p", p_hex)) {
    Serial.println(F("[inspect] SKIPPED — URI has no p= parameter to decrypt."));
    return;
  }

  uint8_t p_bytes[AES_KEY_LEN] = {0};
  if (!parse_hex_fixed(p_hex, p_bytes, sizeof(p_bytes))) {
    Serial.println(F("[inspect] FAIL — p= is not valid 16-byte hex."));
    return;
  }

  String c_hex;
  const bool has_c = uri_get_query_param(uri, "c", c_hex);
  uint8_t c_bytes[8] = {0};
  const bool c_parse_ok = has_c && parse_hex_fixed(c_hex, c_bytes, sizeof(c_bytes));

  bool any_match = false;
  bool any_full_match = false;

  for (int candidate = 0; candidate < 7; candidate++) {
    const uint8_t *issuer_key = BOLTCARD_ISSUER_KEYS[candidate];
    const __FlashStringHelper *issuer_label = BOLTCARD_ISSUER_KEY_LABELS[candidate];

    // K1 is derived from issuer_key only (version-independent), but try all versions anyway
  uint8_t decrypted[AES_KEY_LEN] = {0};
    uint32_t counter = 0;
    bool k1_match = false;
    uint32_t k1_matched_version = 0;

    for (int vi = 0; vi < 4 && !k1_match; vi++) {
      uint32_t try_version = BOLTCARD_VERSION_CANDIDATES[vi];
      uint8_t keys_try[5][AES_KEY_LEN] = {{0}};
      derive_deterministic_boltcard_keys(nfc, issuer_key, uid, try_version, keys_try);
      k1_match = deterministic_decrypt_p(nfc, keys_try[1], p_bytes, uid, decrypted, counter);
      if (k1_match) k1_matched_version = try_version;
    }

    Serial.print(F("[inspect] Issuer key "));
    Serial.print(issuer_label);
    Serial.print(F(" -> deterministic K1 read-only decrypt: "));
    Serial.println(k1_match ? F("MATCH") : F("NO MATCH"));

    if (!k1_match) {
      continue;
    }

    any_match = true;
    Serial.print(F("[inspect]   PICCData header: 0x"));
    print_hex_byte_prefixed(decrypted[0]);
    Serial.println();
    Serial.print(F("[inspect]   Decrypted UID: "));
    print_hex_bytes_spaced(decrypted + 1, 7);
    Serial.println();
    Serial.print(F("[inspect]   Read counter: "));
    Serial.println(counter);
    Serial.println(F("[inspect]   This card was decrypted with a deterministic K1 derived from the UID using the Bolt Card spec."));

    if (!has_c) {
      Serial.println(F("[inspect]   c= missing — cannot read-only verify deterministic K2/K0/K3/K4."));
      Serial.println(F("[inspect]   This is a strong indicator only; it does not guarantee auth or wipe will succeed."));
      continue;
    }
    if (!c_parse_ok) {
      Serial.println(F("[inspect]   c= is malformed — cannot read-only verify deterministic K2/K0/K3/K4."));
      Serial.println(F("[inspect]   This is a strong indicator only; it does not guarantee auth or wipe will succeed."));
      continue;
    }

    int matched_version = -1;
    uint8_t matched_keys[5][AES_KEY_LEN] = {{0}};
    for (int version_idx = 0; version_idx < 4; version_idx++) {
      const uint32_t version = BOLTCARD_VERSION_CANDIDATES[version_idx];
      uint8_t derived_keys[5][AES_KEY_LEN] = {{0}};
      derive_deterministic_boltcard_keys(nfc, issuer_key, uid, version, derived_keys);
      const bool cmac_match = deterministic_verify_cmac(nfc, derived_keys[2], uid, counter, c_bytes);
      Serial.print(F("[inspect]   Deterministic K2/c= check (version "));
      Serial.print(version);
      Serial.print(F("): "));
      Serial.println(cmac_match ? F("MATCH") : F("NO MATCH"));
      if (cmac_match && matched_version < 0) {
        matched_version = (int)version;
        memcpy(matched_keys, derived_keys, sizeof(matched_keys));
      }
    }

    if (matched_version >= 0) {
      any_full_match = true;
      Serial.print(F("[inspect]   Full read-only deterministic match: issuer key "));
      Serial.print(issuer_label);
      Serial.print(F(", version "));
      Serial.println(matched_version);
      Serial.println(F("[inspect]   This strongly indicates the deterministic K0-K4 set for this issuer/version is correct."));
      Serial.println(F("[inspect]   It is still not a guarantee that authenticate or wipe will succeed on this tag."));
      DBG_PRINTLN(F("[inspect]   Suggested keys command:"));
      DBG_PRINT(F("[inspect]   keys "));
      DBG_PRINT(convertIntToHex(matched_keys[0], AES_KEY_LEN));
      DBG_PRINT(F(" "));
      DBG_PRINT(convertIntToHex(matched_keys[1], AES_KEY_LEN));
      DBG_PRINT(F(" "));
      DBG_PRINT(convertIntToHex(matched_keys[2], AES_KEY_LEN));
      DBG_PRINT(F(" "));
      DBG_PRINT(convertIntToHex(matched_keys[3], AES_KEY_LEN));
      DBG_PRINT(F(" "));
      DBG_PRINTLN(convertIntToHex(matched_keys[4], AES_KEY_LEN));
    } else {
      Serial.println(F("[inspect]   K1 matched, but tested deterministic K2 versions did not validate c=."));
      Serial.println(F("[inspect]   This is still a strong indicator that we probably know the issuer key and can likely recover the card more easily."));
    }
  }

  if (!any_match) {
    Serial.println(F("[inspect] No tested deterministic issuer key produced valid PICCData for this UID."));
  } else if (!any_full_match) {
    Serial.println(F("[inspect] Deterministic read-only verification found a K1 match, but no full K2/c= match for the tested versions."));
  }
}

// Perform full read-only card state assessment.
//
// Multi-phase assessment: detect card type (NTAG424 check) → read key versions
// (factory vs provisioned) → authenticate K0 with zero key → read NDEF content →
// attempt deterministic key matching → attempt web key lookup. Populates
// CardAssessment struct with all findings. No destructive operations performed.
//
// Ref: NT4H2421Gx datasheet §7.1 (GetVersion), §7.3.1 (Authenticate),
//      §7.3.3 (GetKeyVersion), §7.6.1 (GetFileSettings), §8.7 (SDM),
//      boltcard SPEC (deterministic key derivation), AN12196 §6 (CMAC)
static bool assess_current_card(CardAssessment &assessment) {
  reset_card_assessment(assessment);
  if (!bolty_hw_ready) return false;

  uint8_t uid[MAX_UID_LEN] = {0};
  uint8_t uid_len = 0;
  unsigned long t0 = millis();
  bool found = false;
  do {
    found = bolty_read_passive_target(bolt.nfc, uid, &uid_len);
    if (millis() - t0 > ASSESSMENT_TIMEOUT_MS) {
      return false;
    }
  } while (!found);

  assessment.present = true;
  assessment.uid_len = uid_len;
  memcpy(assessment.uid, uid, uid_len);
  assessment.is_ntag424 = (((uid_len == 7) || (uid_len == 4)) && bolt.nfc->ntag424_isNTAG424());
  if (!assessment.is_ntag424) {
    assessment.kind = IdleCardKind::unknown;
    return true;
  }

  bool all_zero = true;
  bool all_key_versions_read = true;
  for (int k = 0; k < 5; k++) {
    const uint8_t kv = bolty_get_key_version(bolt.nfc, k);
    assessment.key_versions[k] = kv;
    if (kv == KEY_VER_READ_FAILED) {
      all_key_versions_read = false;
      assessment.key_confidence[k] = KeyConfidence::unknown;
    } else if (kv == KEY_VER_FACTORY) {
      assessment.key_confidence[k] = KeyConfidence::high;
    } else {
      assessment.key_confidence[k] = KeyConfidence::unknown;
      all_zero = false;
    }
  }

  if (all_key_versions_read && all_zero) {
    bolt.selectNtagApplicationFiles();
    assessment.zero_key_auth_ok =
        (bolt.nfc->ntag424_Authenticate((uint8_t *)ZERO_KEY, 0, AUTH_CMD_EV2_FIRST) == 1);
  }

  uint8_t ndef[NDEF_MAX_LEN] = {0};
  const int ndef_len = bolt.nfc->ntag424_ReadNDEFMessage(ndef, sizeof(ndef));
  assessment.has_ndef = ndef_len > 0;
  if (ndef_len > 0) {
    Serial.print(F("[assess] NDEF ASCII: "));
    print_ndef_ascii(ndef, ndef_len);
    if (ndef_extract_uri(ndef, ndef_len, assessment.uri)) {
      assessment.has_uri = true;
      const bool has_lnurlw = assessment.uri.startsWith("lnurlw://") || assessment.uri.indexOf("lnurlw://") >= 0;
      const bool has_lnurlp = assessment.uri.startsWith("lnurlp://") || assessment.uri.indexOf("lnurlp://") >= 0;
      String p_hex;
      String c_hex;
      const bool has_p = uri_get_query_param(assessment.uri, "p", p_hex);
      const bool has_c = uri_get_query_param(assessment.uri, "c", c_hex);
      assessment.looks_like_boltcard = has_lnurlw || has_lnurlp || (has_p && has_c);

      // Try current issuer key first (if set)
      bool issuer_matched = false;
      if (has_issuer_key && uid_len == 7 && has_p) {
        uint8_t p_bytes[AES_KEY_LEN] = {0};
        if (parse_hex_fixed(p_hex, p_bytes, AES_KEY_LEN)) {
          for (int vi = 0; vi < 4 && !issuer_matched; vi++) {
            uint32_t try_ver = BOLTCARD_VERSION_CANDIDATES[vi];
            uint8_t try_keys[5][AES_KEY_LEN] = {{0}};
            derive_deterministic_boltcard_keys(bolt.nfc, current_issuer_key, uid, try_ver, try_keys);
            uint8_t dec[AES_KEY_LEN] = {0};
            uint32_t ctr = 0;
            if (deterministic_decrypt_p(bolt.nfc, try_keys[1], p_bytes, uid, dec, ctr)) {
              // K1 matched — check CMAC if available
              bool cmac_ok = false;
              if (has_c && c_hex.length() >= 16) {
                uint8_t c_bytes[8] = {0};
                if (parse_hex_fixed(c_hex, c_bytes, 8)) {
                  cmac_ok = deterministic_verify_cmac(bolt.nfc, try_keys[2], uid, ctr, c_bytes);
                }
              }
              if (cmac_ok || !has_c) {
                issuer_matched = true;
                memcpy(assessment.derived_keys, try_keys, sizeof(assessment.derived_keys));
                for (int i = 0; i < 5; i++) {
                  assessment.key_confidence[i] = KeyConfidence::high;
                }
                assessment.deterministic_k1_match = true;
                assessment.deterministic_full_match = true;
                led_signal_key_local();
              }
            }
          }
        }
      }

      // Try web lookup if no issuer match and WiFi connected
      #if HAS_WEB_LOOKUP
      if (!issuer_matched && wifi_connected && uid_len == 7 && has_p) {
        uint8_t p_bytes[AES_KEY_LEN] = {0};
        if (parse_hex_fixed(p_hex, p_bytes, AES_KEY_LEN)) {
          char uid_hex[15] = {0};
          for (int i = 0; i < uid_len; i++) {
            snprintf(uid_hex + i*2, 3, "%02X", uid[i]);
          }
          uint8_t web_keys[5][AES_KEY_LEN] = {{0}};
          uint32_t web_counter = 0;
          uint8_t web_decrypted[AES_KEY_LEN] = {0};
          if (web_lookup_and_match(bolt.nfc, uid_hex, p_bytes, uid, web_keys, web_counter, web_decrypted)) {
            // K1 matched from web — check CMAC
            bool cmac_ok = false;
            if (has_c && c_hex.length() >= 16) {
              uint8_t c_bytes[8] = {0};
              if (parse_hex_fixed(c_hex, c_bytes, 8)) {
                cmac_ok = deterministic_verify_cmac(bolt.nfc, web_keys[2], uid, web_counter, c_bytes);
              }
            }
            if (cmac_ok || !has_c) {
              issuer_matched = true;
              memcpy(assessment.derived_keys, web_keys, sizeof(assessment.derived_keys));
              for (int i = 0; i < 5; i++) {
                assessment.key_confidence[i] = KeyConfidence::high;
              }
              assessment.deterministic_k1_match = true;
              assessment.deterministic_full_match = true;
              led_signal_key_online();
              Serial.println(F("[assess] Web key lookup match!"));
              // Auto-load into mBoltConfig for wipe/burn
              store_bolt_config_keys_from_bytes(mBoltConfig, web_keys);
            }
          }
        }
      }
      #endif

      // Fall through to hardcoded issuer keys if no match from current issuer
      if (!issuer_matched) {
        DeterministicBoltcardMatch match;
        const bool full_match = deterministic_try_known_matches(bolt.nfc, uid, uid_len, assessment.uri, match);
        assessment.deterministic_k1_match = match.saw_k1_match;
        assessment.deterministic_full_match = full_match;
        if (full_match) {
          memcpy(assessment.derived_keys, match.keys, sizeof(assessment.derived_keys));
        }
        if (match.saw_k1_match) {
          assessment.key_confidence[1] = KeyConfidence::high;
        }
        if (full_match) {
          for (int i = 0; i < 5; i++) {
            assessment.key_confidence[i] = KeyConfidence::high;
          }
        } else if (match.saw_k1_match) {
          assessment.key_confidence[0] = KeyConfidence::partial;
          assessment.key_confidence[2] = KeyConfidence::partial;
          assessment.key_confidence[3] = KeyConfidence::partial;
          assessment.key_confidence[4] = KeyConfidence::partial;
        }
      }
    }
  }

  if (all_zero && assessment.zero_key_auth_ok) {
    assessment.kind = IdleCardKind::blank;
  } else if (assessment.looks_like_boltcard || assessment.deterministic_k1_match) {
    assessment.kind = IdleCardKind::programmed;
  } else {
    assessment.kind = IdleCardKind::unknown;
  }

  assessment.reset_eligible = assessment.key_confidence[0] == KeyConfidence::high ||
                              assessment.kind == IdleCardKind::blank;
  return true;
}
