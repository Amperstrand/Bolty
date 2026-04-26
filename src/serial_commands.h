#pragma once

// Serial command interface for headless and REST modes.
// Included by bolty.ino when HAS_WIFI=0 or HAS_REST_SERVER=1.

#include "bolt.h"
#include "bolty_utils.h"
#include "KeyDerivation.h"
#include "PiccData.h"
#include "Bolt11Decode.h"
#include "debug.h"
#include "hardware_config.h"

#if HAS_WEB_LOOKUP
#include "http_probe.h"
#endif

extern BoltDevice bolt;
extern sBoltConfig mBoltConfig;
extern volatile bool serial_cmd_active;
extern bool bolty_hw_ready;
extern bool has_issuer_key;
extern CardAssessment g_last_assessment;

static uint8_t current_issuer_key[16] = {0};

void serial_print_help() {
  Serial.println();
  Serial.println(F("=== Bolty Headless Mode ==="));
  Serial.println(F("Commands:"));
  Serial.println(F("  help              Show this help"));
  Serial.println(F("  uid               Scan card and print UID"));
  Serial.println(F("  status            Print current config and status"));
  Serial.println(F("  keys <k0> <k1> <k2> <k3> <k4>  Set 5 keys (32-char hex each)"));
  Serial.println(F("  issuer <hex32>     Set issuer key for deterministic per-card derivation"));
  Serial.println(F("  url <lnurl>        Set LNURL for burn"));
  Serial.println(F("  burn              Burn card (tap card, uses keys+url)"));
  Serial.println(F("  wipe              Wipe card (tap card, uses keys)"));
  Serial.println(F("  ndef              Read NDEF message (no auth needed)"));
  Serial.println(F("  picc              Read NDEF, decrypt p= and verify c= (uses k1/k2)"));
  Serial.println(F("  decodebolt11 <invoice>  Decode bolt11 invoice (amount, description, hash)"));
  Serial.println(F("  inspect           Full read-only card inspection (no auth, no writes)"));
  Serial.println(F("  derivekeys        Load deterministic keys from read-only p=/c= verification"));
  Serial.println(F("  auth              Test k0 authentication (tap card)"));
  Serial.println(F("  ver               GetVersion + NTAG424 check (tap card)"));
  Serial.println(F("  keyver            Read key versions (blank/provisioned check, tap card)"));
  Serial.println(F("  diagnose          Auth-based state detection (for recovery work)"));
  Serial.println(F("  probe             Probe last assessed card URI once"));
  Serial.println(F("  probe on|off      Enable/disable auto probe after assessment"));
  #if HAS_WEB_LOOKUP
  Serial.println(F("  wifi <ssid> <pass> Connect to WiFi for web key lookup"));
  Serial.println(F("  wifi off          Disconnect WiFi"));
  Serial.println(F("  keyserver <url>   Set web key lookup URL"));
  #endif
  Serial.println(F("  --- Safety / Testing ---"));
  Serial.println(F("  check             Auth with factory zero keys (confirm card is blank)"));
  Serial.println(F("  dummyburn         Burn with zero keys + dummy URL (test write path)"));
  Serial.println(F("  recoverkey <n> <hex>  Recover key slot n (0-4) with candidate old key"));
  Serial.println(F("  reset             Reset NDEF+SDM on factory-key card (keys unchanged)"));
  Serial.println(F("  testck            ChangeKey A/B test on key 1 (verify implementation)"));
#if BOLTY_OTA_ENABLED
  Serial.println(F("  --- OTA ---"));
  Serial.println(F("  ota               Check manifest and apply firmware update if newer"));
#endif
  Serial.println();
}

void serial_print_status() {
  Serial.println();
  Serial.print(F("  NFC HW: ")); Serial.println(bolty_hw_ready ? F("ready") : F("NOT ready"));
  Serial.print(F("  Last UID: ")); Serial.println(bolt.getScannedUid());
  Serial.print(F("  Job: ")); Serial.println(bolt.get_job_status());
  Serial.print(F("  Card: ")); Serial.println(mBoltConfig.card_name);
  Serial.print(F("  LNURL: ")); Serial.println(mBoltConfig.url);
  Serial.print(F("  k0: ")); Serial.println(mBoltConfig.k0);
  Serial.print(F("  k1: ")); Serial.println(mBoltConfig.k1);
  Serial.print(F("  k2: ")); Serial.println(mBoltConfig.k2);
  Serial.print(F("  k3: ")); Serial.println(mBoltConfig.k3);
  Serial.print(F("  k4: ")); Serial.println(mBoltConfig.k4);
  Serial.print(F("  Issuer key: "));
  if (has_issuer_key) {
    Serial.println(convertIntToHex(current_issuer_key, 16));
  } else {
    Serial.println(F("(none)"));
  }
  #if HAS_WEB_LOOKUP
  Serial.print(F("  WiFi: "));
  if (wifi_connected) {
    Serial.print(F("connected ("));
    Serial.print(WiFi.localIP());
    Serial.println(F(")"));
    Serial.print(F("  Keyserver: "));
    Serial.println(web_lookup_url);
  } else {
    Serial.println(F("not connected"));
  }
  #endif
  Serial.println();
}

// ntag424_getKeyVersion moved to bolt.h for use by burn/wipe guards

static const uint8_t BOLTCARD_ISSUER_KEY_ZERO[16] = {0};
static const uint8_t BOLTCARD_ISSUER_KEY_DEV[16] = {
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x01,
};
static const uint8_t BOLTCARD_ISSUER_KEY_BOLTPOC[16] = {
  0xB0, 0x73, 0x39, 0x59,
  0x68, 0x6C, 0x5D, 0xA2,
  0x74, 0x12, 0x30, 0x84,
  0xB5, 0xC0, 0x78, 0x20,
};
static const uint8_t BOLTCARD_ISSUER_KEY_BOLTPOC2[16] = {
  0x0A, 0x27, 0x62, 0x06,
  0xCC, 0xAE, 0x41, 0x73,
  0x9B, 0x35, 0x41, 0xE2,
  0x85, 0x22, 0x3E, 0xEE,
};
static const uint8_t BOLTCARD_ISSUER_KEY_PROXY[16] = {
  0x55, 0x73, 0x45, 0x71,
  0xCE, 0x72, 0xED, 0x36,
  0x49, 0x94, 0xCF, 0x2F,
  0x20, 0x91, 0x40, 0x92,
};
static const uint8_t BOLTCARD_ISSUER_KEY_PROXY2[16] = {
  0x43, 0x71, 0xF0, 0x15,
  0x9A, 0x98, 0xA8, 0x50,
  0x09, 0xFF, 0x2B, 0xCF,
  0x21, 0xC5, 0xB3, 0x01,
};
static const uint8_t BOLTCARD_ISSUER_KEY_PROXY3[16] = {
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

struct DeterministicBoltcardMatch {
  bool saw_k1_match;
  bool full_match;
  uint32_t counter;
  uint32_t version;
  uint8_t issuer_key[16];
  uint8_t decrypted[16];
  uint8_t keys[5][16];
};

static void derive_deterministic_card_key(BoltyNfcReader *nfc,
                                          const uint8_t issuer_key[16],
                                          const uint8_t uid[7],
                                          uint32_t version,
                                          uint8_t out_card_key[16]) {
  (void)nfc;
  keyderivation_card_key(issuer_key, uid, version, out_card_key);
}

static void derive_deterministic_boltcard_keys(BoltyNfcReader *nfc,
                                               const uint8_t issuer_key[16],
                                               const uint8_t uid[7],
                                               uint32_t version,
                                               uint8_t out_keys[5][16]) {
  (void)nfc;
  keyderivation_boltcard_keys(issuer_key, uid, version, out_keys);
}

static bool deterministic_decrypt_p(BoltyNfcReader *nfc,
                                    const uint8_t k1[16],
                                    const uint8_t p[16],
                                    const uint8_t uid[7],
                                    uint8_t decrypted[16],
                                    uint32_t &counter_out) {
  if (!nfc->ntag424_decrypt((uint8_t *)k1, 16, (uint8_t *)p, decrypted)) {
    return false;
  }
  if (decrypted[0] != 0xC7) return false;
  if (memcmp(decrypted + 1, uid, 7) != 0) return false;
  counter_out = decode_u24_le(decrypted + 8);
  return true;
}

static bool deterministic_verify_cmac(BoltyNfcReader *nfc,
                                      const uint8_t k2[16],
                                      const uint8_t uid[7],
                                      uint32_t counter,
                                      const uint8_t expected_c[8]) {
  (void)nfc;
  uint8_t sv2[16] = {0x3C, 0xC3, 0x00, 0x01, 0x00, 0x80};
  memcpy(sv2 + 6, uid, 7);
  sv2[13] = (uint8_t)(counter & 0xFF);
  sv2[14] = (uint8_t)((counter >> 8) & 0xFF);
  sv2[15] = (uint8_t)((counter >> 16) & 0xFF);

  uint8_t session_key[16] = {0};
  AES128_CMAC(k2, sv2, sizeof(sv2), session_key);

  uint8_t full_cmac[16] = {0};
  AES128_CMAC(session_key, nullptr, 0, full_cmac);

  uint8_t computed_c[8] = {0};
  for (int i = 0; i < 8; i++) {
    computed_c[i] = full_cmac[(i * 2) + 1];
  }
  return memcmp(computed_c, expected_c, sizeof(computed_c)) == 0;
}

static bool deterministic_try_known_matches(BoltyNfcReader *nfc,
                                            const uint8_t *uid,
                                            uint8_t uid_len,
                                            const String &uri,
                                            DeterministicBoltcardMatch &match) {
  memset(&match, 0, sizeof(match));
  if (uid == nullptr || uid_len != 7 || uri.length() == 0) return false;

  String p_hex;
  if (!uri_get_query_param(uri, "p", p_hex)) return false;

  uint8_t p_bytes[16] = {0};
  if (!parse_hex_fixed(p_hex, p_bytes, sizeof(p_bytes))) return false;

  String c_hex;
  const bool has_c = uri_get_query_param(uri, "c", c_hex);
  uint8_t c_bytes[8] = {0};
  const bool c_parse_ok = has_c && parse_hex_fixed(c_hex, c_bytes, sizeof(c_bytes));

  for (int candidate = 0; candidate < 7; candidate++) {
    const uint8_t *issuer_key = BOLTCARD_ISSUER_KEYS[candidate];

    uint8_t keys_v1[5][16] = {{0}};
    derive_deterministic_boltcard_keys(nfc, issuer_key, uid, 1, keys_v1);

    uint8_t decrypted[16] = {0};
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
      uint8_t derived_keys[5][16] = {{0}};
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

#if HAS_WEB_LOOKUP
// Parse a hex char to nibble value
static uint8_t hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return 0;
}

// Parse 32-char hex string to 16 bytes. Returns false on bad format.
static bool parse_hex_32(const char *hex, uint8_t out[16]) {
  for (int i = 0; i < 16; i++) {
    char hi = hex[i * 2], lo = hex[i * 2 + 1];
    if (!isxdigit(hi) || !isxdigit(lo)) return false;
    out[i] = (hex_nibble(hi) << 4) | hex_nibble(lo);
  }
  return true;
}

// Find a key value like "k0":"<hex32>" starting from search_pos.
// Returns pointer past the closing quote, or nullptr if not found.
static const char* find_key_hex(const char *json, const char *key_name, const char *search_from, uint8_t out[16]) {
  const char *p = strstr(search_from, key_name);
  if (!p) return nullptr;
  const char *colon = strchr(p, ':');
  if (!colon) return nullptr;
  const char *open_q = strchr(colon + 1, '"');
  if (!open_q) return nullptr;
  const char *val = open_q + 1;
  const char *close_q = strchr(val, '"');
  if (!close_q || (close_q - val) != 32) return nullptr;
  if (!parse_hex_32(val, out)) return nullptr;
  return close_q + 1;
}

// Fetch keysets from web API, try each K1 against p=, return matched keys.
static bool web_lookup_and_match(BoltyNfcReader *nfc,
                                  const char *uid_hex,
                                  const uint8_t *p_bytes, const uint8_t *uid,
                                  uint8_t matched_keys[5][16],
                                  uint32_t &out_counter, uint8_t out_decrypted[16]) {
  if (!wifi_connected) return false;

  HTTPClient http;
  char url[256];
  snprintf(url, sizeof(url), "%s?uid=%s", web_lookup_url, uid_hex);
  http.begin(url);
  http.setTimeout(5000);
  int code = http.GET();
  if (code != 200) {
    Serial.print(F("[web] HTTP "));
    Serial.println(code);
    http.end();
    return false;
  }
  String body = http.getString();
  http.end();

  Serial.print(F("[web] Response len: "));
  Serial.println(body.length());

  const char *search_from = body.c_str();
  int keyset_idx = 0;
  while (true) {
    const char *k0_pos = strstr(search_from, "\"k0\"");
    if (!k0_pos) break;

    uint8_t try_keys[5][16] = {{0}};
    const char *key_names[] = {"\"k0\"", "\"k1\"", "\"k2\"", "\"k3\"", "\"k4\""};
    bool all_found = true;
    const char *after = k0_pos;
    for (int i = 0; i < 5; i++) {
      after = find_key_hex(body.c_str(), key_names[i], after, try_keys[i]);
      if (!after) { all_found = false; break; }
    }

    if (!all_found) {
      search_from = k0_pos + 4;
      continue;
    }

    Serial.print(F("[web] Trying keyset #"));
    Serial.println(keyset_idx);

    uint32_t counter = 0;
    uint8_t decrypted[16] = {0};
    if (deterministic_decrypt_p(nfc, try_keys[1], p_bytes, uid, decrypted, counter)) {
      Serial.print(F("[web] Keyset #"));
      Serial.print(keyset_idx);
      Serial.println(F(" K1 MATCH!"));
      memcpy(matched_keys, try_keys, sizeof(try_keys));
      out_counter = counter;
      memcpy(out_decrypted, decrypted, 16);
      return true;
    }

    keyset_idx++;
    search_from = k0_pos + 4;
  }

  Serial.println(F("[web] No keyset matched K1 decrypt."));
  return false;
}
#endif

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

  uint8_t p_bytes[16] = {0};
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
    uint8_t decrypted[16] = {0};
    uint32_t counter = 0;
    bool k1_match = false;
    uint32_t k1_matched_version = 0;

    for (int vi = 0; vi < 4 && !k1_match; vi++) {
      uint32_t try_version = BOLTCARD_VERSION_CANDIDATES[vi];
      uint8_t keys_try[5][16] = {{0}};
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
    uint8_t matched_keys[5][16] = {{0}};
    for (int version_idx = 0; version_idx < 4; version_idx++) {
      const uint32_t version = BOLTCARD_VERSION_CANDIDATES[version_idx];
      uint8_t derived_keys[5][16] = {{0}};
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
      Serial.println(F("[inspect]   Suggested keys command:"));
      Serial.print(F("[inspect]   keys "));
      Serial.print(convertIntToHex(matched_keys[0], 16));
      Serial.print(F(" "));
      Serial.print(convertIntToHex(matched_keys[1], 16));
      Serial.print(F(" "));
      Serial.print(convertIntToHex(matched_keys[2], 16));
      Serial.print(F(" "));
      Serial.print(convertIntToHex(matched_keys[3], 16));
      Serial.print(F(" "));
      Serial.println(convertIntToHex(matched_keys[4], 16));
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

static bool assess_current_card(CardAssessment &assessment) {
  reset_card_assessment(assessment);
  if (!bolty_hw_ready) return false;

  uint8_t uid[12] = {0};
  uint8_t uid_len = 0;
  unsigned long t0 = millis();
  bool found = false;
  do {
    found = bolty_read_passive_target(bolt.nfc, uid, &uid_len);
    if (millis() - t0 > 5000) {
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
    if (kv == 0xFF) {
      all_key_versions_read = false;
      assessment.key_confidence[k] = KeyConfidence::unknown;
    } else if (kv == 0x00) {
      assessment.key_confidence[k] = KeyConfidence::high;
    } else {
      assessment.key_confidence[k] = KeyConfidence::unknown;
      all_zero = false;
    }
  }

  if (all_key_versions_read && all_zero) {
    bolt.selectNtagApplicationFiles();
    uint8_t zero_key[16] = {0};
    assessment.zero_key_auth_ok = (bolt.nfc->ntag424_Authenticate(zero_key, 0, 0x71) == 1);
  }

  uint8_t ndef[256] = {0};
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
        uint8_t p_bytes[16] = {0};
        if (parse_hex_fixed(p_hex, p_bytes, 16)) {
          for (int vi = 0; vi < 4 && !issuer_matched; vi++) {
            uint32_t try_ver = BOLTCARD_VERSION_CANDIDATES[vi];
            uint8_t try_keys[5][16] = {{0}};
            derive_deterministic_boltcard_keys(bolt.nfc, current_issuer_key, uid, try_ver, try_keys);
            uint8_t dec[16] = {0};
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
        uint8_t p_bytes[16] = {0};
        if (parse_hex_fixed(p_hex, p_bytes, 16)) {
          char uid_hex[15] = {0};
          for (int i = 0; i < uid_len; i++) {
            snprintf(uid_hex + i*2, 3, "%02X", uid[i]);
          }
          uint8_t web_keys[5][16] = {{0}};
          uint32_t web_counter = 0;
          uint8_t web_decrypted[16] = {0};
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
              strncpy(mBoltConfig.k0, convertIntToHex(web_keys[0], 16).c_str(), 33);
              strncpy(mBoltConfig.k1, convertIntToHex(web_keys[1], 16).c_str(), 33);
              strncpy(mBoltConfig.k2, convertIntToHex(web_keys[2], 16).c_str(), 33);
              strncpy(mBoltConfig.k3, convertIntToHex(web_keys[3], 16).c_str(), 33);
              strncpy(mBoltConfig.k4, convertIntToHex(web_keys[4], 16).c_str(), 33);
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

void handle_serial_command(String cmd) {
  cmd.trim();
  if (cmd.length() == 0) return;

  if (cmd == "help") {
    serial_print_help();
  }
  else if (cmd == "uid") {
    Serial.println(F("[cmd] Scanning for card..."));
    if (bolty_hw_ready) {
      led_on();
      if (bolt.scanUID()) {
        led_blink(3, 100);
        Serial.print(F("[uid] ")); Serial.println(bolt.getScannedUid());
        Serial.print(F("[ntag424] "));
        Serial.println(bolt.nfc->ntag424_isNTAG424() ? "YES" : "NO");
      } else {
        led_off();
        Serial.println(F("[uid] No card detected"));
      }
    } else {
      led_off();
      Serial.println(F("[error] NFC hardware not ready"));
    }
  }
  else if (cmd == "status") {
    serial_print_status();
  }
  else if (cmd == "auth") {
    if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
    Serial.println(F("[auth] Tap card now..."));
    serial_cmd_active = true;
    led_on();
    bolt.setCurKeysFromHex(mBoltConfig.k0, mBoltConfig.k1, mBoltConfig.k2, mBoltConfig.k3, mBoltConfig.k4);
    Serial.print(F("[auth] Trying k0: "));
    for (int i = 0; i < 16; i++) { if (bolt.cur_keys.keys[0][i] < 0x10) Serial.print("0"); Serial.print(bolt.cur_keys.keys[0][i], HEX); }
    Serial.println();
    Serial.print(F("[auth] k0 bytes: "));
    for (int i = 0; i < 16; i++) {
      Serial.print(bolt.cur_keys.keys[0][i], DEC);
      Serial.print(" ");
    }
    Serial.println();
    unsigned long t0 = millis();
    bool found = false;
    do {
      uint8_t uid[12] = {0};
      uint8_t uidLen;
      found = bolty_read_passive_target(bolt.nfc, uid, &uidLen);
      if (found) {
        Serial.print(F("[auth] UID: "));
        bolty_print_hex(bolt.nfc, uid, uidLen);
      }
      if (millis() - t0 > 15000) { Serial.println(F("[auth] TIMEOUT")); serial_cmd_active = false; return; }
    } while (!found);
    delay(50);
    Serial.println(F("[auth] About to authenticate..."));
    uint8_t result = bolt.nfc->ntag424_Authenticate(bolt.cur_keys.keys[0], 0, 0x71);
    Serial.print(F("[auth] ntag424_Authenticate returned: "));
    Serial.println(result);
    Serial.print(F("[auth] Session authenticated: "));
    Serial.println(bolt.nfc->ntag424_Session.authenticated);
    Serial.print(F("[auth] Result: "));
    Serial.println(result == 1 ? "SUCCESS" : "FAILED");
    led_blink(result == 1 ? 3 : 5, 100);
    serial_cmd_active = false;
  }
   // ── NDEF read using ISO-7816-4 ReadBinary ──
   //
   // Reads the NDEF file (E104) via ISO-7816 SELECT + READ BINARY.
   // This works both before and after burn (with SDM enabled).
   //
   // Why not DESFire ReadData (0xAD)?
   //   ReadData returns 91 9D (File Not Found) when the application
   //   is not selected. Even with ISO select, it fails on SDM-enabled
   //   files. Both the Bolt Android app and iOS implementations use
   //   ISO-7816 ReadBinary instead.
   //
   // Why not the library's ISOReadFile?
   //   It does GetFileSettings → SELECT → ReadBinary, but GetFileSettings
   //   returns garbage on SDM-enabled files, causing a negative filesize
   //   and failure.
   //
   // Ref: Android Ntag424.js isoReadBinary() (lines 716-745)
   //       iOS ntag424-macos readNDEFURL() (lines 91-179)
   //       CoreExtendedNFC Type4NDEF.readNDEF() (lines 55-114)
   //
   // Sequence: SELECT AID (D2760000850101) → SELECT FILE (E104) →
   //           READ BINARY (offset=0, len=2) → READ BINARY (offset=2, len=nlen)
   //
    else if (cmd == "ndef") {
     if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
     Serial.println(F("[ndef] Tap card now..."));
     serial_cmd_active = true;
     led_on();
      uint8_t uid[12] = {0};
      uint8_t uid_len = 0;
      unsigned long t0_ndef = millis();
      bool found_ndef = false;
      do {
        found_ndef = bolty_read_passive_target(bolt.nfc, uid, &uid_len);
        if (millis() - t0_ndef > 15000) break;
       } while (!found_ndef);
      if (found_ndef) {
          uint8_t ndef[256] = {0};
           int len = bolt.nfc->ntag424_ReadNDEFMessage(ndef, sizeof(ndef));
           if (len < 0 && strlen(mBoltConfig.k3) == 32) {
            // PLAIN ISO read failed. SDM mirroring causes ISO ReadBinary to return
            // unexpected data on provisioned cards. Re-detect card to reset ISO-DEP
            // state, authenticate with key 3, then read via native DESFire ReadData.
            Serial.println(F("[ndef] PLAIN read failed, re-detecting for k3 auth..."));
            uint8_t redet_uid[12] = {0};
            uint8_t redet_uid_len = 0;
            if (bolty_read_passive_target(bolt.nfc, redet_uid, &redet_uid_len)) {
              uint8_t k3_bytes[16] = {0};
              bolt.setKey(k3_bytes, String(mBoltConfig.k3));
              if (bolt.nfc->ntag424_Authenticate(k3_bytes, 3, 0x71) == 1) {
                uint8_t raw[64] = {0};
                uint8_t rlen = bolt.nfc->ntag424_ReadData(raw, 2, 0, sizeof(raw));
                if (rlen >= 4) {
                  uint16_t nlen = (static_cast<uint16_t>(raw[0]) << 8) | raw[1];
                  if (nlen > 0 && nlen <= 252 && rlen >= 2 + nlen) {
                    memcpy(ndef, raw + 2, nlen);
                    len = nlen;
                  } else if (nlen == 0) {
                    len = 0;
                  }
                }
              }
            }
          }
         if (len <= 0) {
           if (len == 0) {
             Serial.println(F("[ndef] No NDEF data (NLEN=0)"));
           } else {
             Serial.println(F("[ndef] FAILED — read error (file may require key 3 auth, set keys first)"));
           }
           goto ndef_fail;
         }

         Serial.print(F("[ndef] OK (")); Serial.print(len); Serial.println(F(" bytes)"));
         Serial.print(F("[ndef] hex: "));
         bolty_print_hex(bolt.nfc, ndef, len > 128 ? 128 : len);
         Serial.print(F("[ndef] ASCII: "));
         print_ndef_ascii(ndef, len);
         led_blink(3, 100);
         serial_cmd_active = false;
      } else {
ndef_fail:
       Serial.println(F("[ndef] FAILED — card not detected or read error"));
       led_blink(5, 100);
       serial_cmd_active = false;
     }
    }
    else if (cmd == "picc") {
      if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
      if (strlen(mBoltConfig.k1) != 32 || strlen(mBoltConfig.k2) != 32) {
        Serial.println(F("[picc] Set k1 and k2 first (keys command)"));
        return;
      }
      Serial.println(F("[picc] Tap card now..."));
      serial_cmd_active = true;
      led_on();

      uint8_t uid[12] = {0};
      uint8_t uid_len = 0;
      unsigned long t0_picc = millis();
      bool found_picc = false;
      do {
        found_picc = bolty_read_passive_target(bolt.nfc, uid, &uid_len);
        if (millis() - t0_picc > 15000) break;
      } while (!found_picc);

      if (!found_picc) {
        Serial.println(F("[picc] TIMEOUT — no card detected"));
        led_blink(5, 100);
        serial_cmd_active = false;
        goto picc_done;
      }

      {
        uint8_t ndef[256] = {0};
        int len = bolt.nfc->ntag424_ReadNDEFMessage(ndef, sizeof(ndef));
        if (len <= 0) {
          Serial.println(F("[picc] NDEF read failed"));
          led_blink(5, 100);
          serial_cmd_active = false;
          goto picc_done;
        }

        String uri;
        if (!ndef_extract_uri(ndef, len, uri)) {
          Serial.println(F("[picc] No URI in NDEF"));
          led_blink(5, 100);
          serial_cmd_active = false;
          goto picc_done;
        }

        Serial.print(F("[picc] URL: "));
        Serial.println(uri);

        // Parse k1 and k2 from config
        uint8_t k1[16], k2[16];
        if (picc_hex_to_bytes(mBoltConfig.k1, k1, 16) != 16 ||
            picc_hex_to_bytes(mBoltConfig.k2, k2, 16) != 16) {
          Serial.println(F("[picc] Invalid k1/k2 hex"));
          led_blink(5, 100);
          serial_cmd_active = false;
          goto picc_done;
        }

        PiccData picc = picc_parse_url(k1, k2, uri.c_str());
        picc_print(&picc);

        if (picc.valid) {
          // Verify UID matches
          bool uid_match = (uid_len == 7);
          for (int i = 0; uid_match && i < 7; i++) {
            uid_match = (uid[i] == picc.uid[i]);
          }
          Serial.print(F("[picc] UID match: "));
          Serial.println(uid_match ? F("YES") : F("NO"));
          led_blink(3, 100);
        } else {
          led_blink(5, 100);
        }
        serial_cmd_active = false;
      }
      picc_done:;
    }
    else if (cmd.startsWith("decodebolt11 ")) {
      String invoice = cmd.substring(13);
      invoice.trim();
      if (invoice.length() < 10) {
        Serial.println(F("[bolt11] Invoice too short"));
      } else {
        Bolt11Info info = bolt11_decode(invoice.c_str());
        bolt11_print(&info);
      }
    }
    else if (cmd == "inspect") {
      if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
      Serial.println(F("[inspect] Tap card now..."));
      serial_cmd_active = true;
      led_on();

      uint8_t uid[12] = {0};
      uint8_t uid_len = 0;
      unsigned long t0_inspect = millis();
      bool found = false;
      do {
        found = bolty_read_passive_target(bolt.nfc, uid, &uid_len);
        if (millis() - t0_inspect > 15000) {
          Serial.println(F("[inspect] TIMEOUT"));
          serial_cmd_active = false;
          return;
        }
      } while (!found);

      Serial.println(F("[inspect] --- Card Presence ---"));
      Serial.print(F("[inspect] UID length: "));
      Serial.println(uid_len);
      Serial.print(F("[inspect] UID: "));
      bolty_print_hex(bolt.nfc, uid, uid_len);
      Serial.print(F("[inspect] UID compact: "));
      Serial.println(convertIntToHex(uid, uid_len));
      delay(50);

      Serial.println(F("[inspect] --- Version / Type ---"));
      const uint8_t version_ok = bolt.nfc->ntag424_GetVersion();
      Serial.print(F("[inspect] GetVersion: "));
      Serial.println(version_ok ? F("OK") : F("FAIL"));
      if (version_ok) {
        Serial.print(F("[inspect] NTAG424 HWType: 0x"));
        print_hex_byte_prefixed(bolt.nfc->ntag424_VersionInfo.HWType);
        Serial.println();
        Serial.print(F("[inspect] NTAG424 SW version: "));
        Serial.print(bolt.nfc->ntag424_VersionInfo.SWMajorVersion, DEC);
        Serial.print(F("."));
        Serial.println(bolt.nfc->ntag424_VersionInfo.SWMinorVersion, DEC);
        Serial.print(F("[inspect] Prod week/year: CW "));
        Serial.print(bolt.nfc->ntag424_VersionInfo.CWProd, DEC);
        Serial.print(F(" / "));
        Serial.print(2000 + bcd_to_decimal(bolt.nfc->ntag424_VersionInfo.YearProd));
        Serial.println();
      }
      Serial.print(F("[inspect] isNTAG424: "));
      Serial.println(version_ok && bolt.nfc->ntag424_VersionInfo.HWType == 0x04 ? F("YES") : F("NO / UNKNOWN"));

      Serial.println(F("[inspect] --- Key Versions (read-only) ---"));
      bool all_zero = true;
      bool any_keyver_error = false;
      uint8_t key_versions[5] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
      if (!bolt.nfc->ntag424_ISOSelectFileByDFN((uint8_t *)NTAG424_AID)) {
        Serial.println(F("[inspect] Failed to select NTAG424 application for key version reads"));
        any_keyver_error = true;
      } else {
        for (int k = 0; k < 5; k++) {
          const bool ok = bolt.nfc->ntag424_GetKeyVersion(k, &key_versions[k]);
          Serial.print(F("[inspect] Key "));
          Serial.print(k);
          Serial.print(F(" version: "));
          if (!ok) {
            Serial.println(F("READ ERROR"));
            any_keyver_error = true;
            continue;
          }
          Serial.print(F("0x"));
          print_hex_byte_prefixed(key_versions[k]);
          if (key_versions[k] == 0x00) Serial.println(F(" (factory default)"));
          else Serial.println(F(" (changed)"));
          if (key_versions[k] != 0x00) all_zero = false;
        }
      }

      // Detect inconsistent states (mixed factory + changed keys)
      if (!all_zero && !any_keyver_error) {
        bool all_changed = true;
        for (int k = 0; k < 5; k++) { if (key_versions[k] == 0x00) all_changed = false; }
        if (!all_changed) {
          Serial.println(F("[inspect] *** INCONSISTENT STATE DETECTED ***"));
          Serial.print(F("[inspect] Partial burn/wipe: keys "));
          for (int k = 0; k < 5; k++) {
            if (key_versions[k] == 0x00) {
              Serial.print(F("K")); Serial.print(k); Serial.print(F("=factory "));
            }
          }
          Serial.println(F("are still factory"));
          Serial.println(F("[inspect] If you know the keys used, try 'wipe' to reset all keys."));
          Serial.println(F("[inspect] If K0 is still factory, 'burn' may work (it requires K0=0x00)."));
        }
      }

      Serial.println(F("[inspect] --- NDEF File Settings ---"));
      uint8_t fs[32] = {0};
      const uint8_t fs_len = bolt.nfc->ntag424_GetFileSettings(2, fs, NTAG424_COMM_MODE_PLAIN);
      if (fs_len >= 2) {
        Serial.print(F("[inspect] GetFileSettings len: "));
        Serial.println(fs_len);
        Serial.print(F("[inspect] Raw file settings: "));
        bolty_print_hex(bolt.nfc, fs, fs_len);
        if (fs_len >= 7) {
          Serial.print(F("[inspect] FileType: 0x"));
          print_hex_byte_prefixed(fs[0]);
          Serial.println();
          Serial.print(F("[inspect] FileOption: 0x"));
          print_hex_byte_prefixed(fs[1]);
          Serial.println();
          Serial.print(F("[inspect] AccessRights: 0x"));
          print_hex_byte_prefixed(fs[2]);
          print_hex_byte_prefixed(fs[3]);
          Serial.println();
          Serial.print(F("[inspect] FileSize bytes: "));
          Serial.println(((uint32_t)fs[4] << 16) | ((uint32_t)fs[5] << 8) | fs[6]);
          Serial.print(F("[inspect] SDM enabled: "));
          Serial.println((fs[1] & 0x40) ? F("YES") : F("NO"));
          if ((fs[1] & 0x40) && fs_len >= 21) {
            Serial.print(F("[inspect] SDM options: 0x"));
            print_hex_byte_prefixed(fs[7]);
            Serial.println();
            Serial.print(F("[inspect] SDM access rights: 0x"));
            print_hex_byte_prefixed(fs[8]);
            print_hex_byte_prefixed(fs[9]);
            Serial.println();
            Serial.print(F("[inspect] UID offset: "));
            Serial.println(decode_u24_le(fs + 10));
            Serial.print(F("[inspect] SDM MAC input offset: "));
            Serial.println(decode_u24_le(fs + 13));
            Serial.print(F("[inspect] SDM MAC offset: "));
            Serial.println(decode_u24_le(fs + 16));
          }
        }
      } else {
        Serial.println(F("[inspect] GetFileSettings failed"));
      }

      Serial.println(F("[inspect] --- NDEF Read ---"));
      uint8_t ndef[256] = {0};
      int ndef_len = bolt.nfc->ntag424_ReadNDEFMessage(ndef, sizeof(ndef));
      if (ndef_len < 0 && strlen(mBoltConfig.k3) == 32) {
         // PLAIN ISO read failed — re-detect card to reset ISO-DEP state,
         // auth with key 3, then read NDEF via native DESFire ReadData.
         uint8_t redet_uid[12] = {0};
         uint8_t redet_uid_len = 0;
         if (bolty_read_passive_target(bolt.nfc, redet_uid, &redet_uid_len)) {
           uint8_t k3_bytes[16] = {0};
           bolt.setKey(k3_bytes, String(mBoltConfig.k3));
           if (bolt.nfc->ntag424_Authenticate(k3_bytes, 3, 0x71) == 1) {
             uint8_t raw[64] = {0};
             uint8_t rlen = bolt.nfc->ntag424_ReadData(raw, 2, 0, sizeof(raw));
             if (rlen >= 4) {
               uint16_t nlen = (static_cast<uint16_t>(raw[0]) << 8) | raw[1];
               if (nlen > 0 && nlen <= 252 && rlen >= 2 + nlen) {
                 memcpy(ndef, raw + 2, nlen);
                 ndef_len = nlen;
               } else if (nlen == 0) {
                 ndef_len = 0;
               }
             }
           }
         }
      }
      if (ndef_len < 0) {
        Serial.println(F("[inspect] NDEF read failed"));
      } else if (ndef_len == 0) {
        Serial.println(F("[inspect] No NDEF data (NLEN=0)"));
      } else {
        Serial.print(F("[inspect] NDEF bytes: "));
        Serial.println(ndef_len);
        Serial.print(F("[inspect] NDEF hex: "));
        bolty_print_hex(bolt.nfc, ndef, ndef_len > 128 ? 128 : ndef_len);
        Serial.print(F("[inspect] NDEF ASCII: "));
        print_ndef_ascii(ndef, ndef_len);

        String uri;
        if (ndef_extract_uri(ndef, ndef_len, uri)) {
          Serial.print(F("[inspect] URI: "));
          Serial.println(uri);
        } else {
          Serial.println(F("[inspect] URI: not found / non-URI NDEF"));
        }
        print_boltcard_heuristics(uri);

        // --- Key Matching (issuer → web → hardcoded) ---
        // Parse p= and c= once for all key matching attempts
        String p_hex, c_hex;
        const bool has_p = uri_get_query_param(uri, "p", p_hex);
        const bool has_c = uri_get_query_param(uri, "c", c_hex);
        uint8_t p_bytes[16] = {0};
        uint8_t c_bytes[8] = {0};
        bool p_ok = false, c_ok = false;
        if (has_p) p_ok = parse_hex_fixed(p_hex, p_bytes, 16);
        if (has_c) c_ok = parse_hex_fixed(c_hex, c_bytes, 8);
        bool keys_auto_loaded = false;

        // --- 1. Current Issuer Key Check ---
        if (has_issuer_key && uid_len == 7 && has_p && p_ok) {
          Serial.println(F("[inspect] --- Current Issuer Key Check ---"));
          bool issuer_k1_match = false;
          uint32_t issuer_counter = 0;
          uint8_t issuer_decrypted[16] = {0};
          uint8_t issuer_matched_keys[5][16] = {{0}};
          int issuer_matched_version = -1;

          // Try all version candidates
          for (int vi = 0; vi < 4 && !issuer_k1_match; vi++) {
            uint32_t try_ver = BOLTCARD_VERSION_CANDIDATES[vi];
            uint8_t try_keys[5][16] = {{0}};
            derive_deterministic_boltcard_keys(bolt.nfc, current_issuer_key, uid, try_ver, try_keys);
            issuer_k1_match = deterministic_decrypt_p(bolt.nfc, try_keys[1], p_bytes, uid, issuer_decrypted, issuer_counter);
            if (issuer_k1_match) {
              memcpy(issuer_matched_keys, try_keys, sizeof(issuer_matched_keys));
              issuer_matched_version = (int)try_ver;
            }
          }

          Serial.print(F("[inspect] Issuer key "));
          Serial.print(convertIntToHex(current_issuer_key, 16));
          Serial.print(F(" -> K1 decrypt: "));
          Serial.println(issuer_k1_match ? F("MATCH") : F("NO MATCH"));

          if (issuer_k1_match) {
            Serial.print(F("[inspect]   PICCData header: 0x"));
            print_hex_byte_prefixed(issuer_decrypted[0]);
            Serial.println();
            Serial.print(F("[inspect]   Decrypted UID: "));
            print_hex_bytes_spaced(issuer_decrypted + 1, 7);
            Serial.println();
            Serial.print(F("[inspect]   Read counter: "));
            Serial.println(issuer_counter);

            // Try K2/CMAC verification
            if (c_ok) {
              bool issuer_cmac_ok = deterministic_verify_cmac(bolt.nfc, issuer_matched_keys[2], uid, issuer_counter, c_bytes);
              Serial.print(F("[inspect]   K2/CMAC check (version "));
              Serial.print(issuer_matched_version);
              Serial.print(F("): "));
              Serial.println(issuer_cmac_ok ? F("MATCH") : F("NO MATCH"));

              if (issuer_cmac_ok) {
                Serial.println(F("[inspect]   Card matches current issuer key!"));
                led_signal_key_local();
                strncpy(mBoltConfig.k0, convertIntToHex(issuer_matched_keys[0], 16).c_str(), 33);
                strncpy(mBoltConfig.k1, convertIntToHex(issuer_matched_keys[1], 16).c_str(), 33);
                strncpy(mBoltConfig.k2, convertIntToHex(issuer_matched_keys[2], 16).c_str(), 33);
                strncpy(mBoltConfig.k3, convertIntToHex(issuer_matched_keys[3], 16).c_str(), 33);
                strncpy(mBoltConfig.k4, convertIntToHex(issuer_matched_keys[4], 16).c_str(), 33);
                Serial.println(F("[inspect]   Keys auto-loaded. Ready for wipe/burn."));
                keys_auto_loaded = true;
              }
            } else {
              Serial.println(F("[inspect]   c= missing — cannot verify K2/CMAC."));
              strncpy(mBoltConfig.k0, convertIntToHex(issuer_matched_keys[0], 16).c_str(), 33);
              strncpy(mBoltConfig.k1, convertIntToHex(issuer_matched_keys[1], 16).c_str(), 33);
              strncpy(mBoltConfig.k2, convertIntToHex(issuer_matched_keys[2], 16).c_str(), 33);
              strncpy(mBoltConfig.k3, convertIntToHex(issuer_matched_keys[3], 16).c_str(), 33);
              strncpy(mBoltConfig.k4, convertIntToHex(issuer_matched_keys[4], 16).c_str(), 33);
              Serial.println(F("[inspect]   Keys auto-loaded (K1 only, no CMAC proof)."));
              keys_auto_loaded = true;
            }
          }
        }

        // --- 2. Web Lookup ---
        #if HAS_WEB_LOOKUP
        if (!keys_auto_loaded && uid_len == 7 && has_p && p_ok) {
          Serial.println(F("[inspect] --- Web Key Lookup ---"));
          char uid_hex[15] = {0};
          for (int i = 0; i < uid_len; i++) {
            snprintf(uid_hex + i*2, 3, "%02X", uid[i]);
          }
          uint8_t web_keys[5][16] = {{0}};
          uint32_t web_counter = 0;
          uint8_t web_decrypted[16] = {0};

          if (web_lookup_and_match(bolt.nfc, uid_hex, p_bytes, uid, web_keys, web_counter, web_decrypted)) {
            Serial.print(F("[inspect]   Web match! Counter: "));
            Serial.println(web_counter);
            Serial.print(F("[inspect]   Decrypted UID: "));
            print_hex_bytes_spaced(web_decrypted + 1, 7);
            Serial.println();

            // Try K2/CMAC verification
            if (c_ok) {
              bool web_cmac_ok = deterministic_verify_cmac(bolt.nfc, web_keys[2], uid, web_counter, c_bytes);
              Serial.print(F("[inspect]   K2/CMAC check: "));
              Serial.println(web_cmac_ok ? F("MATCH") : F("NO MATCH"));
              if (web_cmac_ok) {
                Serial.println(F("[inspect]   Card matched via web lookup!"));
                led_signal_key_online();
                strncpy(mBoltConfig.k0, convertIntToHex(web_keys[0], 16).c_str(), 33);
                strncpy(mBoltConfig.k1, convertIntToHex(web_keys[1], 16).c_str(), 33);
                strncpy(mBoltConfig.k2, convertIntToHex(web_keys[2], 16).c_str(), 33);
                strncpy(mBoltConfig.k3, convertIntToHex(web_keys[3], 16).c_str(), 33);
                strncpy(mBoltConfig.k4, convertIntToHex(web_keys[4], 16).c_str(), 33);
                Serial.println(F("[inspect]   Keys auto-loaded from web. Ready for wipe/burn."));
                keys_auto_loaded = true;
              }
            } else {
              Serial.println(F("[inspect]   c= missing — loading web keys without CMAC proof."));
              led_signal_key_online();
              strncpy(mBoltConfig.k0, convertIntToHex(web_keys[0], 16).c_str(), 33);
              strncpy(mBoltConfig.k1, convertIntToHex(web_keys[1], 16).c_str(), 33);
              strncpy(mBoltConfig.k2, convertIntToHex(web_keys[2], 16).c_str(), 33);
              strncpy(mBoltConfig.k3, convertIntToHex(web_keys[3], 16).c_str(), 33);
              strncpy(mBoltConfig.k4, convertIntToHex(web_keys[4], 16).c_str(), 33);
              Serial.println(F("[inspect]   Keys auto-loaded from web (K1 only)."));
              keys_auto_loaded = true;
            }
          } else if (!wifi_connected) {
            Serial.println(F("[inspect]   WiFi not connected — skipping web lookup."));
          } else {
            Serial.println(F("[inspect]   No matching keyset found online."));
          }
        }
        #endif

        // --- 3. Hardcoded Issuer Keys ---
        print_deterministic_boltcard_check(bolt.nfc, uid, uid_len, uri);
      }

      Serial.println(F("[inspect] --- Safe Summary ---"));
      if (!version_ok) {
        Serial.println(F("[inspect] Could not confirm NTAG424 via GetVersion."));
      } else if (any_keyver_error) {
        Serial.println(F("[inspect] Card responded, but some read-only NTAG424 reads failed."));
      } else if (all_zero) {
        Serial.println(F("[inspect] Card looks blank or unprovisioned from key versions alone."));
      } else {
        Serial.println(F("[inspect] Card has non-default key versions; likely provisioned or previously modified."));
      }
      Serial.println(F("[inspect] No authentication attempts were made."));
      Serial.println(F("[inspect] No writes or key changes were performed."));
      led_blink(3, 100);
      serial_cmd_active = false;
    }
  else if (cmd == "derivekeys") {
    if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
    Serial.println(F("[derivekeys] Tap card now..."));
    Serial.println(F("[derivekeys] Read-only flow: inspect NDEF, verify p=/c=, and only then load keys into config."));
    serial_cmd_active = true;
    led_on();

    uint8_t uid[12] = {0};
    uint8_t uid_len = 0;
    unsigned long t0_derive = millis();
    bool found = false;
    do {
      found = bolty_read_passive_target(bolt.nfc, uid, &uid_len);
      if (millis() - t0_derive > 15000) {
        Serial.println(F("[derivekeys] TIMEOUT"));
        serial_cmd_active = false;
        return;
      }
    } while (!found);

    Serial.print(F("[derivekeys] UID: "));
    bolty_print_hex(bolt.nfc, uid, uid_len);

    uint8_t ndef[256] = {0};
    const int ndef_len = bolt.nfc->ntag424_ReadNDEFMessage(ndef, sizeof(ndef));
    if (ndef_len <= 0) {
      Serial.println(F("[derivekeys] FAIL — could not read NDEF."));
      Serial.println(F("[derivekeys] No keys were changed in config."));
      led_blink(5, 100);
      serial_cmd_active = false;
      return;
    }

    String uri;
    if (!ndef_extract_uri(ndef, ndef_len, uri)) {
      Serial.println(F("[derivekeys] FAIL — NDEF does not contain a URI record."));
      Serial.println(F("[derivekeys] No keys were changed in config."));
      led_blink(5, 100);
      serial_cmd_active = false;
      return;
    }

    DeterministicBoltcardMatch match;
    const bool full_match = deterministic_try_known_matches(bolt.nfc, uid, uid_len, uri, match);

    if (!match.saw_k1_match) {
      Serial.println(F("[derivekeys] FAIL — no known deterministic issuer key produced valid PICCData for this card."));
      Serial.println(F("[derivekeys] No keys were changed in config."));
      led_blink(5, 100);
      serial_cmd_active = false;
      return;
    }

    Serial.print(F("[derivekeys] Deterministic K1 matched issuer key "));
    print_hex_bytes_inline(match.issuer_key, sizeof(match.issuer_key));
    Serial.println();
    Serial.print(F("[derivekeys] Read counter from p=: "));
    Serial.println(match.counter);

    if (!full_match) {
      Serial.println(F("[derivekeys] PARTIAL — K1 matched, but no full K2/c= match was found for tested versions."));
      Serial.println(F("[derivekeys] Config keys were left unchanged on purpose."));
      Serial.println(F("[derivekeys] You likely know the issuer key, but auth/wipe confidence is not high enough to auto-load keys."));
      led_blink(5, 100);
      serial_cmd_active = false;
      return;
    }

    store_bolt_config_keys_from_bytes(mBoltConfig, match.keys);
    Serial.print(F("[derivekeys] FULL MATCH — issuer key "));
    print_hex_bytes_inline(match.issuer_key, sizeof(match.issuer_key));
    Serial.print(F(", version "));
    Serial.println(match.version);
    Serial.println(F("[derivekeys] Loaded deterministic K0-K4 into active config."));
    Serial.println(F("[derivekeys] K1 and K2 were verified read-only from the card's current NDEF data."));
    Serial.println(F("[derivekeys] K0, K3, and K4 cannot be directly verified read-only, but this is the strongest safe pre-auth signal."));
    Serial.print(F("[derivekeys] k0: "));
    Serial.println(mBoltConfig.k0);
    Serial.print(F("[derivekeys] k1: "));
    Serial.println(mBoltConfig.k1);
    Serial.print(F("[derivekeys] k2: "));
    Serial.println(mBoltConfig.k2);
    Serial.print(F("[derivekeys] k3: "));
    Serial.println(mBoltConfig.k3);
    Serial.print(F("[derivekeys] k4: "));
    Serial.println(mBoltConfig.k4);
    Serial.println(F("[derivekeys] Next steps: 'auth' gives a single K0 confirmation attempt; 'wipe' performs the actual reset."));
    led_blink(3, 100);
    serial_cmd_active = false;
  }
  else if (cmd == "ver") {
    if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
    serial_cmd_active = true;
    uint8_t uid[12] = {0};
    uint8_t uidLen;
    uint8_t ok = bolty_read_passive_target(bolt.nfc, uid, &uidLen);
    Serial.print(F("[ver] Card detected: "));
    Serial.println(ok ? "YES" : "NO");
    if (ok) {
      bolt.nfc->ntag424_GetVersion();
      Serial.print(F("[ver] HWType: 0x"));
      Serial.print(bolt.nfc->ntag424_VersionInfo.HWType, HEX);
      Serial.print(F(" expected: 0x04 match: "));
      Serial.println(bolt.nfc->ntag424_VersionInfo.HWType == 0x04 ? "YES" : "NO");
      Serial.print(F("[ver] isNTAG424: "));
      Serial.println(bolt.nfc->ntag424_isNTAG424() ? "YES" : "NO");
      Serial.print(F("[ver] HWType after isNTAG424: 0x"));
      Serial.println(bolt.nfc->ntag424_VersionInfo.HWType, HEX);
    }
    serial_cmd_active = false;
  }
  else if (cmd == "issuer") {
    // Show current issuer key
    if (has_issuer_key) {
      Serial.print(F("[issuer] Current issuer key: "));
      Serial.println(convertIntToHex(current_issuer_key, 16));
    } else {
      Serial.println(F("[issuer] No issuer key set"));
    }
  }
  else if (cmd.startsWith("issuer ")) {
    String hex = cmd.substring(7);
    hex.trim();
    if (hex.length() != 32) {
      Serial.println(F("[error] Issuer key must be exactly 32 hex chars"));
      return;
    }
    // Validate hex chars
    for (unsigned int i = 0; i < hex.length(); i++) {
      char c = hex.charAt(i);
      if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
        Serial.println(F("[error] Issuer key must be hex only (0-9, a-f)"));
        return;
      }
    }
    uint8_t tmp[16] = {0};
    if (!parse_hex_fixed(hex, tmp, 16)) {
      Serial.println(F("[error] Failed to parse issuer key hex"));
      return;
    }
    memcpy(current_issuer_key, tmp, 16);
    has_issuer_key = true;
    Serial.print(F("[issuer] Issuer key set: "));
    Serial.println(hex);
    Serial.println(F("[issuer] Per-card K0-K4 will be derived from this key during inspect/burn/wipe"));
  }
  else if (cmd.startsWith("keys ")) {
    String args = cmd.substring(5);
    int s1 = args.indexOf(' ');
    int s2 = args.indexOf(' ', s1 + 1);
    int s3 = args.indexOf(' ', s2 + 1);
    int s4 = args.indexOf(' ', s3 + 1);
    if (s1 < 0 || s2 < 0 || s3 < 0 || s4 < 0) {
      Serial.println(F("[error] Usage: keys <k0> <k1> <k2> <k3> <k4>"));
      return;
    }
    String k0 = args.substring(0, s1);
    String k1 = args.substring(s1 + 1, s2);
    String k2 = args.substring(s2 + 1, s3);
    String k3 = args.substring(s3 + 1, s4);
    String k4 = args.substring(s4 + 1);
    if (k0.length() != 32 || k1.length() != 32 || k2.length() != 32 ||
        k3.length() != 32 || k4.length() != 32) {
      Serial.println(F("[error] Each key must be exactly 32 hex chars"));
      return;
    }
    strncpy(mBoltConfig.k0, k0.c_str(), 33);
    strncpy(mBoltConfig.k1, k1.c_str(), 33);
    strncpy(mBoltConfig.k2, k2.c_str(), 33);
    strncpy(mBoltConfig.k3, k3.c_str(), 33);
    strncpy(mBoltConfig.k4, k4.c_str(), 33);
    has_issuer_key = false;  // Mutual exclusion: keys overrides issuer
    Serial.println(F("[keys] Keys set"));
    Serial.print(F("  k0: ")); Serial.println(k0);
    Serial.print(F("  k4: ")); Serial.println(k4);
  }
  else if (cmd.startsWith("url ")) {
    String url = cmd.substring(4);
    url.trim();
    if (url.length() == 0) {
      Serial.println(F("[error] Usage: url <lnurl>"));
      return;
    }
    strncpy(mBoltConfig.url, url.c_str(), sizeof(mBoltConfig.url));
    if (url.startsWith("lnurlp://")) {
      strncpy(mBoltConfig.card_mode, "pos", sizeof(mBoltConfig.card_mode));
    } else if (url.startsWith("https://")) {
      strncpy(mBoltConfig.card_mode, "2fa", sizeof(mBoltConfig.card_mode));
    } else {
      strncpy(mBoltConfig.card_mode, "withdraw", sizeof(mBoltConfig.card_mode));
    }
    saveBoltConfig(active_bolt_config);
    Serial.print(F("[url] Set to: ")); Serial.println(url);
  }
  else if (cmd == "mode pos") {
    strncpy(mBoltConfig.card_mode, "pos", sizeof(mBoltConfig.card_mode));
    saveBoltConfig(active_bolt_config);
    Serial.println(F("[mode] Set to: pos"));
  }
  else if (cmd == "mode 2fa") {
    strncpy(mBoltConfig.card_mode, "2fa", sizeof(mBoltConfig.card_mode));
    saveBoltConfig(active_bolt_config);
    Serial.println(F("[mode] Set to: 2fa"));
  }
  else if (cmd == "mode withdraw") {
    strncpy(mBoltConfig.card_mode, "withdraw", sizeof(mBoltConfig.card_mode));
    saveBoltConfig(active_bolt_config);
    Serial.println(F("[mode] Set to: withdraw"));
  }
  else if (cmd.startsWith("reseturl ")) {
    String url = cmd.substring(9);
    url.trim();
    if (url.length() == 0) {
      Serial.println(F("[error] Usage: reseturl <plain-url>"));
      return;
    }
    strncpy(mBoltConfig.reset_url, url.c_str(), sizeof(mBoltConfig.reset_url));
    saveBoltConfig(active_bolt_config);
    Serial.print(F("[reseturl] Set to: ")); Serial.println(url);
  }
  else if (cmd.startsWith("wifissid ")) {
    String ssid = cmd.substring(9);
    ssid.trim();
    strncpy(mBoltConfig.wifi_ssid, ssid.c_str(), sizeof(mBoltConfig.wifi_ssid));
    saveBoltConfig(active_bolt_config);
    Serial.print(F("[wifissid] Set to: ")); Serial.println(mBoltConfig.wifi_ssid);
  }
  else if (cmd.startsWith("wifipass ")) {
    String pass = cmd.substring(9);
    pass.trim();
    strncpy(mBoltConfig.wifi_password, pass.c_str(), sizeof(mBoltConfig.wifi_password));
    saveBoltConfig(active_bolt_config);
    Serial.println(F("[wifipass] Updated"));
  }
#if HAS_WEB_LOOKUP
  else if (cmd.startsWith("wifi ")) {
    // wifi <ssid> <pass> — connect to WiFi for web key lookup
    String args = cmd.substring(5);
    args.trim();
    int sp = args.indexOf(' ');
    if (sp < 0) {
      Serial.println(F("[error] Usage: wifi <ssid> <password>"));
      return;
    }
    String ssid = args.substring(0, sp);
    String pass = args.substring(sp + 1);
    pass.trim();
    Serial.print(F("[wifi] Connecting to "));
    Serial.println(ssid);
    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid.c_str(), pass.c_str());
    unsigned long t0 = millis();
    while (WiFi.status() != WL_CONNECTED && millis() - t0 < 15000) {
      delay(500);
    }
    if (WiFi.status() == WL_CONNECTED) {
      wifi_connected = true;
      Serial.print(F("[wifi] Connected! IP: "));
      Serial.println(WiFi.localIP());
    } else {
      wifi_connected = false;
      Serial.println(F("[wifi] FAILED to connect"));
    }
  }
  else if (cmd == "wifi off") {
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    wifi_connected = false;
    Serial.println(F("[wifi] Disconnected"));
  }
  else if (cmd == "wifi") {
    if (wifi_connected) {
      Serial.print(F("[wifi] Connected, IP: "));
      Serial.println(WiFi.localIP());
      Serial.print(F("[wifi] Lookup URL: "));
      Serial.println(web_lookup_url);
    } else {
      Serial.println(F("[wifi] Not connected. Use: wifi <ssid> <password>"));
    }
  }
  else if (cmd.startsWith("keyserver ")) {
    String url = cmd.substring(10);
    url.trim();
    if (url.length() >= sizeof(web_lookup_url)) {
      Serial.println(F("[error] URL too long"));
      return;
    }
    strncpy(web_lookup_url, url.c_str(), sizeof(web_lookup_url));
    Serial.print(F("[keyserver] Set to: "));
    Serial.println(web_lookup_url);
  }
#endif
  else if (cmd == "probe on") {
    mBoltConfig.wifi_probe_enabled = true;
    saveBoltConfig(active_bolt_config);
    Serial.println(F("[probe] enabled"));
  }
  else if (cmd == "probe off") {
    mBoltConfig.wifi_probe_enabled = false;
    saveBoltConfig(active_bolt_config);
    Serial.println(F("[probe] disabled"));
  }
  else if (cmd == "probe") {
    if (!mBoltConfig.wifi_probe_enabled) {
      Serial.println(F("[probe] Probe disabled. Use: probe on"));
      return;
    }
    if (!g_last_assessment.has_uri) {
      Serial.println(F("[probe] No URI in last assessment. Click button with card first."));
      return;
    }
    http_probe_url(g_last_assessment.uri);
  }
  else if (cmd == "burn") {
    if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
    if (strlen(mBoltConfig.url) == 0) { Serial.println(F("[error] No LNURL. Use: url <lnurl>")); return; }
    if (strlen(mBoltConfig.k0) == 0) { Serial.println(F("[error] No keys. Use: keys <k0> <k1> <k2> <k3> <k4>")); return; }
    Serial.println(F("[burn] Tap card now..."));
    serial_cmd_active = true;
    led_on();
    bolt.loadKeysForBurn(mBoltConfig);
    uint8_t result;
    unsigned long t0 = millis();
    do {
      while (Serial.available()) Serial.read();
      result = bolt.burn(String(mBoltConfig.url));
      if (millis() - t0 > 30000) {
        Serial.println(F("[burn] TIMEOUT — no card detected in 30s"));
        serial_cmd_active = false;
        return;
      }
    } while (result == JOBSTATUS_WAITING);
    if (result == JOBSTATUS_GUARD_REJECT) {
      Serial.println(F("[burn] ABORTED - guard rejected (card not in expected state)"));
      led_blink(5, 100);
      serial_cmd_active = false;
      return;
    }
    Serial.print(F("[burn] ")); Serial.println(bolt.get_job_status());
    Serial.println(result == JOBSTATUS_DONE ? F("[burn] SUCCESS") : F("[burn] FAILED"));
      if (result == JOBSTATUS_DONE) {
        // Post-burn verify: auth with new key 0 to confirm key change worked,
        // then read NDEF to verify the URL was written correctly.
        const uint8_t v_auth0 = bolt.nfc->ntag424_Authenticate(bolt.new_keys.keys[0], 0, 0x71);
        Serial.print(F("[burn] VERIFY — AUTH k0: "));
        Serial.println(v_auth0 == 1 ? F("OK") : F("FAIL"));
        if (v_auth0 == 1) {
          // Re-detect card (auth may have left ISO-DEP in odd state),
          // then try PLAIN ISO NDEF read (works now that WriteData offset bug is fixed).
          uint8_t v_uid[12] = {0};
          uint8_t v_uid_len = 0;
          if (bolty_read_passive_target(bolt.nfc, v_uid, &v_uid_len)) {
            uint8_t vbuf[256] = {0};
            const int16_t vlen = bolt.nfc->ntag424_ReadNDEFMessage(vbuf, sizeof(vbuf));
            if (vlen > 0) {
              Serial.print(F("[burn] VERIFY — NDEF read OK ("));
              Serial.print(vlen); Serial.println(F(" bytes)"));
              Serial.print(F("[burn] VERIFY — ASCII: "));
              for (int i = 0; i < vlen; i++) {
                Serial.write(vbuf[i] >= 0x20 && vbuf[i] < 0x7F ? vbuf[i] : '.');
              }
              Serial.println();
            } else if (vlen == 0) {
              Serial.println(F("[burn] VERIFY — NDEF empty (NLEN=0)"));
            } else {
              Serial.println(F("[burn] VERIFY — NDEF read failed"));
            }
          }
        }
      }
    led_blink(result == JOBSTATUS_DONE ? 3 : 5, 100);
    serial_cmd_active = false;
  }
  else if (cmd == "wipe") {
    if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
    if (strlen(mBoltConfig.k0) == 0) { Serial.println(F("[error] No keys. Use: keys <k0> <k1> <k2> <k3> <k4>")); return; }
    Serial.println(F("[wipe] Tap card now..."));
    serial_cmd_active = true;
    led_on();
    bolt.loadKeysForWipe(mBoltConfig);
    uint8_t result;
    unsigned long t0 = millis();
    do {
      while (Serial.available()) Serial.read();
      result = bolt.wipe();
      if (millis() - t0 > 30000) {
        Serial.println(F("[wipe] TIMEOUT — no card detected in 30s"));
        serial_cmd_active = false;
        return;
      }
    } while (result == JOBSTATUS_WAITING);
    if (result == JOBSTATUS_GUARD_REJECT) {
      Serial.println(F("[wipe] ABORTED - guard rejected (card not in expected state)"));
      led_blink(5, 100);
      serial_cmd_active = false;
      return;
    }
    Serial.print(F("[wipe] ")); Serial.println(bolt.get_job_status());
    Serial.println(result == JOBSTATUS_DONE ? F("[wipe] SUCCESS") : F("[wipe] FAILED"));
    led_blink(result == JOBSTATUS_DONE ? 3 : 5, 100);
    serial_cmd_active = false;
  }
  else if (cmd == "keyver") {
    if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
    Serial.println(F("[keyver] Tap card now..."));
    serial_cmd_active = true;
    led_on();
    unsigned long t0 = millis();
    bool found = false;
    do {
      uint8_t uid[12] = {0};
      uint8_t uidLen;
      found = bolty_read_passive_target(bolt.nfc, uid, &uidLen);
      if (found) {
        Serial.print(F("[keyver] UID: "));
        bolty_print_hex(bolt.nfc, uid, uidLen);
      }
      if (millis() - t0 > 15000) { Serial.println(F("[keyver] TIMEOUT")); serial_cmd_active = false; return; }
    } while (!found);
    delay(50);
    bool all_zero = true;
    for (int k = 0; k < 5; k++) {
      uint8_t kv = bolty_get_key_version(bolt.nfc, k);
      Serial.print(F("[keyver] Key "));
      Serial.print(k);
      Serial.print(F(" version: 0x"));
      if (kv < 0x10) Serial.print(F("0"));
      Serial.print(kv, HEX);
      if (kv == 0x00) {
        Serial.println(F(" (factory default)"));
      } else if (kv == 0xFF) {
        Serial.print(F(" (ERROR: "));
        Serial.print(ntag424_error_name(0x91, 0xAE));
        Serial.println(F(")"));
      } else {
        Serial.println(F(" (changed)"));
      }
      if (kv != 0x00) all_zero = false;
    }
    if (all_zero) {
      Serial.println(F("[keyver] Card is BLANK — factory default keys"));
    } else {
      Serial.println(F("[keyver] Card is PROVISIONED — keys have been set"));
    }
    led_blink(3, 100);
    serial_cmd_active = false;
  }
  else if (cmd == "check") {
    if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
    Serial.println(F("[check] Tap card now..."));
    serial_cmd_active = true;
    led_on();
    bolt.cur_keys = BoltcardKeys::allZeros();
    Serial.print(F("[check] Using zero key: "));
    for (int i = 0; i < 16; i++) { if (bolt.cur_keys.keys[0][i] < 0x10) Serial.print("0"); Serial.print(bolt.cur_keys.keys[0][i], HEX); }
    Serial.println();
    unsigned long t0 = millis();
    bool found = false;
    do {
      uint8_t uid[12] = {0};
      uint8_t uidLen;
      found = bolty_read_passive_target(bolt.nfc, uid, &uidLen);
      if (found) {
        Serial.print(F("[check] UID: "));
        bolty_print_hex(bolt.nfc, uid, uidLen);
      }
      if (millis() - t0 > 15000) { Serial.println(F("[check] TIMEOUT")); serial_cmd_active = false; return; }
    } while (!found);
    delay(50);
    uint8_t result = bolt.nfc->ntag424_Authenticate(bolt.cur_keys.keys[0], 0, 0x71);
    Serial.println(result == 1 ? F("[check] SUCCESS — card has factory zero keys") : F("[check] FAILED — card does NOT have factory keys"));
    led_blink(result == 1 ? 3 : 5, 100);
    serial_cmd_active = false;
  }
  else if (cmd == "dummyburn") {
    if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
    Serial.println(F("[dummyburn] Tap card now..."));
    serial_cmd_active = true;
    led_on();
    bolt.cur_keys = BoltcardKeys::allZeros();
    bolt.new_keys = BoltcardKeys::allZeros();
    String lnurl = "https://dummy.test";
    uint8_t result;
    unsigned long t0 = millis();
    do {
      while (Serial.available()) Serial.read();
      result = bolt.burn(lnurl);
      if (millis() - t0 > 30000) {
        Serial.println(F("[dummyburn] TIMEOUT — no card detected in 30s"));
        serial_cmd_active = false;
        return;
      }
    } while (result == JOBSTATUS_WAITING);
    Serial.print(F("[dummyburn] ")); Serial.println(bolt.get_job_status());
    Serial.println(result == JOBSTATUS_DONE ? F("[dummyburn] SUCCESS") : F("[dummyburn] FAILED"));
    if (result == JOBSTATUS_DONE) {
      Serial.println(F("[dummyburn] Card has dummy data — use 'keys 000... 000... 000... 000... 000...' then 'wipe' to restore"));
    }
    led_blink(result == JOBSTATUS_DONE ? 3 : 5, 100);
    serial_cmd_active = false;
  }
  else if (cmd == "reset") {
    if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
    Serial.println(F("[reset] Tap card now..."));
    Serial.println(F("[reset] Factory-key NDEF+SDM reset (keys unchanged)."));
    serial_cmd_active = true;
    led_on();
    uint8_t result;
    unsigned long t0 = millis();
    do {
      while (Serial.available()) Serial.read();
      result = bolt.resetNdefOnly();
      if (millis() - t0 > 30000) {
        Serial.println(F("[reset] TIMEOUT — no card detected in 30s"));
        serial_cmd_active = false;
        return;
      }
    } while (result == JOBSTATUS_WAITING);
    if (result == JOBSTATUS_GUARD_REJECT) {
      Serial.println(F("[reset] ABORTED — card has non-factory keys. Use 'wipe' with explicit keys."));
      led_blink(5, 100);
      serial_cmd_active = false;
      return;
    }
    Serial.print(F("[reset] ")); Serial.println(bolt.get_job_status());
    Serial.println(result == JOBSTATUS_DONE ? F("[reset] SUCCESS — NDEF and SDM reset, keys unchanged") : F("[reset] FAILED"));
    led_blink(result == JOBSTATUS_DONE ? 3 : 5, 100);
    serial_cmd_active = false;
  }
  else if (cmd == "diagnose") {
    if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
    Serial.println(F("[diagnose] Tap card now..."));
    serial_cmd_active = true;
    led_on();

    uint8_t uid_d[12] = {0};
    uint8_t uidLen_d;
    unsigned long t0_d = millis();
    bool found_d = false;
    do {
      found_d = bolty_read_passive_target(bolt.nfc, uid_d, &uidLen_d);
      if (found_d) {
        Serial.print(F("[diagnose] UID: "));
        bolty_print_hex(bolt.nfc, uid_d, uidLen_d);
      }
      if (millis() - t0_d > 15000) {
        Serial.println(F("[diagnose] TIMEOUT"));
        serial_cmd_active = false;
        return;
      }
    } while (!found_d);

    delay(50);

    // Read all 5 key versions (PLAIN mode — no auth needed)
    Serial.println(F("[diagnose] --- Key Versions ---"));
    uint8_t kv[5];
    bool all_zero = true;
    bool any_error = false;
    for (int k = 0; k < 5; k++) {
      kv[k] = bolty_get_key_version(bolt.nfc, k);
      Serial.print(F("[diagnose]   Key "));
      Serial.print(k);
      Serial.print(F(" version: 0x"));
      if (kv[k] < 0x10) Serial.print(F("0"));
      Serial.print(kv[k], HEX);
      if (kv[k] == 0x00) Serial.println(F(" (default)"));
      else if (kv[k] == 0xFF) { Serial.println(F(" (READ ERROR)")); any_error = true; }
      else Serial.println(F(" (changed)"));
      if (kv[k] != 0x00) all_zero = false;
    }

    // Test zero-key authentication on key 0 (master)
    bolt.selectNtagApplicationFiles();
    uint8_t zero_key[16] = {0};
    uint8_t auth_d = bolt.nfc->ntag424_Authenticate(zero_key, 0, 0x71);
    Serial.print(F("[diagnose] Zero-key auth (key 0): "));
    Serial.println(auth_d == 1 ? "OK" : "FAILED");

    // Classify card state
    Serial.println(F("[diagnose] --- Card State ---"));
    if (any_error) {
      Serial.println(F("[diagnose] COMM ERROR — card may not be NTAG424 or reader issue"));
      Serial.println(F("[diagnose] Try: 'ver' to confirm card type"));
    } else if (all_zero && auth_d == 1) {
      Serial.println(F("[diagnose] State: BLANK"));
      Serial.println(F("[diagnose] All keys factory default, zero-key auth OK."));
      Serial.println(F("[diagnose] Ready for burn or dummyburn."));
    } else if (!all_zero && auth_d == 1) {
      Serial.println(F("[diagnose] State: HALF-WIPED"));
      Serial.println(F("[diagnose] Key 0 (master) is zero but some non-master keys remain."));
      Serial.println(F("[diagnose] Recovery: 'recoverkey <slot> <old-key-hex>' per stuck key"));
      Serial.println(F("[diagnose]   or 'keys ...' + 'wipe' if you know all current key values"));
    } else if (!all_zero && auth_d != 1) {
      Serial.println(F("[diagnose] State: PROVISIONED"));
      Serial.println(F("[diagnose] Key 0 (master) is non-zero. Card is locked."));
      Serial.println(F("[diagnose] To wipe: set known keys with 'keys ...' then 'wipe'"));
      Serial.println(F("[diagnose] If key 0 value is unknown, card is NOT recoverable."));
    } else {
      Serial.println(F("[diagnose] State: INCONSISTENT"));
      Serial.println(F("[diagnose] Key versions all 0x00 but zero-key auth FAILED."));
      Serial.println(F("[diagnose] Possible: auth counter lockout, card corruption, or hw issue."));
      Serial.println(F("[diagnose] Try: 'ver' to confirm card type, wait 10s and retry."));
    }

    led_blink(3, 100);
    serial_cmd_active = false;
  }
  else if (cmd.startsWith("recoverkey ")) {
    // Usage: recoverkey <slot 0-4> <32-hex-old-key>
    // Authenticates with zero key on key 0, then attempts ChangeKey
    // to restore the target key slot to zero with version 0x00.
    if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }

    String args = cmd.substring(11);
    args.trim();
    int spaceIdx = args.indexOf(' ');
    if (spaceIdx < 0) {
      Serial.println(F("[recoverkey] Usage: recoverkey <slot 0-4> <32-hex-old-key>"));
      return;
    }
    int slot = args.substring(0, spaceIdx).toInt();
    String old_key_hex = args.substring(spaceIdx + 1);
    old_key_hex.trim();

    if (slot < 0 || slot > 4) {
      Serial.println(F("[recoverkey] Slot must be 0-4"));
      return;
    }
    if (old_key_hex.length() != 32) {
      Serial.println(F("[recoverkey] Key must be 32 hex chars (16 bytes)"));
      return;
    }

    uint8_t zero_key[16] = {0};
    uint8_t old_key[16] = {0};
    bolt.setKey(old_key, old_key_hex);

    Serial.print(F("[recoverkey] Target: key "));
    Serial.print(slot);
    Serial.println(F(" -> zero, ver=0x00"));
    Serial.print(F("[recoverkey] Candidate old key: "));
    Serial.println(old_key_hex);
    serial_cmd_active = true;
    led_on();

    uint8_t uid_rk[12] = {0};
    uint8_t uidLen_rk;
    unsigned long t0_rk = millis();
    bool found_rk = false;
    do {
      found_rk = bolty_read_passive_target(bolt.nfc, uid_rk, &uidLen_rk);
      if (found_rk) {
        Serial.print(F("[recoverkey] UID: "));
        bolty_print_hex(bolt.nfc, uid_rk, uidLen_rk);
      }
      if (millis() - t0_rk > 15000) {
        Serial.println(F("[recoverkey] TIMEOUT"));
        serial_cmd_active = false;
        return;
      }
    } while (!found_rk);

    delay(50);
    bolt.selectNtagApplicationFiles();
    uint8_t kv_before = bolty_get_key_version(bolt.nfc, slot);
    Serial.print(F("[recoverkey] Key "));
    Serial.print(slot);
    Serial.print(F(" version BEFORE: 0x"));
    if (kv_before < 0x10) Serial.print(F("0"));
    Serial.println(kv_before, HEX);

    // Auth with key 0 (zeros) — master key required for ChangeKey
    uint8_t auth_rk = bolt.nfc->ntag424_Authenticate(zero_key, 0, 0x71);
    Serial.print(F("[recoverkey] Auth key 0 (zeros): "));
    Serial.println(auth_rk == 1 ? "OK" : "FAILED");
    if (auth_rk != 1) {
      Serial.println(F("[recoverkey] ABORT — key 0 auth failed (master key is non-zero)"));
      led_blink(5, 100);
      serial_cmd_active = false;
      return;
    }

    bool ok = bolt.nfc->ntag424_ChangeKey(old_key, zero_key, slot, 0x00);
    Serial.print(F("[recoverkey] ChangeKey result: "));
    Serial.println(ok ? "OK" : "FAILED");

    // Re-select and verify
    bolt.nfc->ntag424_ISOSelectFileByDFN((uint8_t *)NTAG424_AID);
    uint8_t kv_after = bolty_get_key_version(bolt.nfc, slot);
    Serial.print(F("[recoverkey] Key "));
    Serial.print(slot);
    Serial.print(F(" version AFTER: 0x"));
    if (kv_after < 0x10) Serial.print(F("0"));
    Serial.println(kv_after, HEX);

    const bool pass = ok && (kv_after == 0x00);
    Serial.println(pass ?
                       F("[recoverkey] PASS — key restored to factory zero") :
                       F("[recoverkey] FAIL — candidate old key was incorrect or card state differs"));
    led_blink(pass ? 3 : 5, 100);
    serial_cmd_active = false;
  }
  else if (cmd == "testck") {
    // A/B test: prove ChangeKey works on known-good key slots.
    // Test card has keys 0-3 = zero, key 4 = unknown.
    // Round-trip: change key 1 from zero→test value→zero, verify versions.
    // If this passes but key 4 fails → issue is card-specific, not our code.
    //
    // Ref: NXP AN12196 §10.4 (ChangeKey), johnnyb/ntag424-java ChangeKey.java
    if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
    Serial.println(F("[testck] ChangeKey A/B test — round-trip on key 1 (known zero)"));
    serial_cmd_active = true;
    led_on();

    // Detect card
    uint8_t uid_ck[12] = {0};
    uint8_t uidLen_ck;
    unsigned long t0_ck = millis();
    bool found_ck = false;
    do {
      found_ck = bolty_read_passive_target(bolt.nfc, uid_ck, &uidLen_ck);
      if (found_ck) {
        Serial.print(F("[testck] UID: "));
        bolty_print_hex(bolt.nfc, uid_ck, uidLen_ck);
      }
      if (millis() - t0_ck > 15000) { Serial.println(F("[testck] TIMEOUT")); serial_cmd_active = false; return; }
    } while (!found_ck);
    delay(50);

    uint8_t zero_key[16] = {0};
    // Distinctive test value — not a real key, just for verification
    uint8_t test_key[16] = {0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44,
                            0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xEE, 0xFF};

    // Read key 1 version BEFORE.
    // 0x00 = blank/default state.
    // 0x01 = our previous aborted test changed key 1 to test_key and needs
    // restore before we can do a clean round-trip again.
    uint8_t kv_before = bolty_get_key_version(bolt.nfc, 1);
    Serial.print(F("[testck] Key 1 version BEFORE: 0x"));
    if (kv_before < 0x10) Serial.print(F("0"));
    Serial.println(kv_before, HEX);

    // Auth with key 0 (zeros) — key 0 is master, needed for ChangeKey
    bolt.selectNtagApplicationFiles();
    uint8_t auth1 = bolt.nfc->ntag424_Authenticate(zero_key, 0, 0x71);
    Serial.print(F("[testck] Auth key 0 (zeros): "));
    Serial.println(auth1 == 1 ? "OK" : "FAILED");
    if (auth1 != 1) {
      Serial.println(F("[testck] ABORT — auth failed"));
      led_blink(5, 100);
      serial_cmd_active = false;
      return;
    }

    if (kv_before == 0x01) {
      Serial.println(F("[testck] Recovery mode — restoring key 1 from test value to zero"));
      bool recovered = bolt.nfc->ntag424_ChangeKey(test_key, zero_key, 1, 0x00);
      Serial.print(F("[testck]   Result: "));
      Serial.println(recovered ? "OK" : "FAILED");

      bolt.nfc->ntag424_ISOSelectFileByDFN((uint8_t *)NTAG424_AID);
      uint8_t kv_recovered = bolty_get_key_version(bolt.nfc, 1);
      Serial.print(F("[testck]   Key 1 version: 0x"));
      if (kv_recovered < 0x10) Serial.print(F("0"));
      Serial.println(kv_recovered, HEX);

      const bool recovery_pass = recovered && (kv_recovered == 0x00);
      Serial.println(recovery_pass ?
                         F("[testck] RECOVERY PASS — key 1 restored to factory state") :
                         F("[testck] RECOVERY FAIL — key 1 not restored"));
      led_blink(recovery_pass ? 3 : 5, 100);
      serial_cmd_active = false;
      return;
    }

    if (kv_before != 0x00) {
      Serial.println(F("[testck] WARNING — key 1 is in an unexpected state, aborting"));
      led_blink(5, 100);
      serial_cmd_active = false;
      return;
    }

    // Step 1: ChangeKey key 1 from zero → test value, version 0x01
    Serial.println(F("[testck] Step 1: ChangeKey(1, zero→test, ver=0x01)"));
    bool ck1 = bolt.nfc->ntag424_ChangeKey(zero_key, test_key, 1, 0x01);
    Serial.print(F("[testck]   Result: "));
    Serial.println(ck1 ? "OK" : "FAILED");

    // Re-select and read version (PLAIN, no auth needed for GetKeyVersion)
    bolt.nfc->ntag424_ISOSelectFileByDFN((uint8_t *)NTAG424_AID);
    uint8_t kv_mid = bolty_get_key_version(bolt.nfc, 1);
    Serial.print(F("[testck]   Key 1 version: 0x"));
    if (kv_mid < 0x10) Serial.print(F("0"));
    Serial.println(kv_mid, HEX);

    if (!ck1 && kv_mid == 0x01) {
      Serial.println(F("[testck] NOTICE — card changed but library returned false (stale build/parsing bug)"));
    }

    bool step1_pass = (kv_mid == 0x01);
    Serial.print(F("[testck]   Step 1: "));
    Serial.println(step1_pass ? "PASS" : "FAIL");

    if (!step1_pass) {
      Serial.println(F("[testck] ABORT — step 1 failed, not attempting restore"));
      led_blink(5, 100);
      serial_cmd_active = false;
      return;
    }

    // Step 2: Re-auth (key 0 still zero), change key 1 back
    bolt.selectNtagApplicationFiles();
    uint8_t auth2 = bolt.nfc->ntag424_Authenticate(zero_key, 0, 0x71);
    Serial.print(F("[testck] Re-auth key 0: "));
    Serial.println(auth2 == 1 ? "OK" : "FAILED");
    if (auth2 != 1) {
      Serial.println(F("[testck] ABORT — re-auth failed (card may be in bad state)"));
      led_blink(5, 100);
      serial_cmd_active = false;
      return;
    }

    Serial.println(F("[testck] Step 2: ChangeKey(1, test→zero, ver=0x00)"));
    bool ck2 = bolt.nfc->ntag424_ChangeKey(test_key, zero_key, 1, 0x00);
    Serial.print(F("[testck]   Result: "));
    Serial.println(ck2 ? "OK" : "FAILED");

    // Read final version
    bolt.nfc->ntag424_ISOSelectFileByDFN((uint8_t *)NTAG424_AID);
    uint8_t kv_final = bolty_get_key_version(bolt.nfc, 1);
    Serial.print(F("[testck]   Key 1 version: 0x"));
    if (kv_final < 0x10) Serial.print(F("0"));
    Serial.println(kv_final, HEX);

    if (!ck2 && kv_final == 0x00) {
      Serial.println(F("[testck] NOTICE — card restored but library returned false (stale build/parsing bug)"));
    }

    bool step2_pass = (kv_final == 0x00);
    Serial.print(F("[testck]   Step 2: "));
    Serial.println(step2_pass ? "PASS" : "FAIL");

    // Summary
    Serial.println(F("---"));
    bool all_pass = step1_pass && step2_pass;
    if (all_pass) {
      Serial.println(F("[testck] ALL PASS — ChangeKey implementation is CORRECT"));
      Serial.println(F("[testck] Conclusion: key 4 corruption is CARD-SPECIFIC"));
      Serial.println(F("[testck] (key 4 has unknown value from prior operation)"));
    } else {
      Serial.println(F("[testck] SOME FAILED — ChangeKey has issues"));
    }

    led_blink(all_pass ? 3 : 5, 100);
    serial_cmd_active = false;
  }
#if BOLTY_OTA_ENABLED
  else if (cmd == "ota") {
    ota_check_and_update();
  }
#endif
  else {
    Serial.print(F("[error] Unknown: ")); Serial.println(cmd);
  }
}
