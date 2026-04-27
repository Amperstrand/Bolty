#pragma once
#include "bolt.h"
#include "bolty_utils.h"
#include "KeyDerivation.h"
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

#if HAS_WEB_LOOKUP
// Parse 32-char hex string to 16 bytes. Returns false on bad format.
static bool parse_hex_32(const char *hex, uint8_t out[AES_KEY_LEN]) {
  for (int i = 0; i < AES_KEY_LEN; i++) {
    char hi = hex[i * 2], lo = hex[i * 2 + 1];
    if (!isxdigit(hi) || !isxdigit(lo)) return false;
    out[i] = (convertCharToHex(hi) << 4) | convertCharToHex(lo);
  }
  return true;
}

// Find a key value like "k0":"<hex32>" starting from search_pos.
// Returns pointer past the closing quote, or nullptr if not found.
static const char* find_key_hex(const char *json, const char *key_name,
                                const char *search_from,
                                uint8_t out[AES_KEY_LEN]) {
  const char *p = strstr(search_from, key_name);
  if (!p) return nullptr;
  const char *colon = strchr(p, ':');
  if (!colon) return nullptr;
  const char *open_q = strchr(colon + 1, '"');
  if (!open_q) return nullptr;
  const char *val = open_q + 1;
  const char *close_q = strchr(val, '"');
  if (!close_q || (close_q - val) != HEX_KEY_LEN) return nullptr;
  if (!parse_hex_32(val, out)) return nullptr;
  return close_q + 1;
}

// Fetch card keys from a web key server and match against card's SDM data.
//
// Queries the configured key server with the card's UID, receives JSON keysets
// containing K0-K4 hex values, and tests each K1 against the card's SDM-encrypted
// PICC data (p= parameter) using deterministic_decrypt_p(). Returns the first
// matching keyset with the decrypted data and read counter.
//
// Ref: boltcard SPEC (web key lookup protocol), NT4H2421Gx datasheet §8.7 (SDM),
//      card_key_matching.h (deterministic_decrypt_p for K1 decryption)
static bool web_lookup_and_match(BoltyNfcReader *nfc,
                                  const char *uid_hex,
                                  const uint8_t *p_bytes, const uint8_t *uid,
                                  uint8_t matched_keys[5][AES_KEY_LEN],
                                  uint32_t &out_counter,
                                  uint8_t out_decrypted[AES_KEY_LEN]) {
  if (!wifi_connected) return false;

  HTTPClient http;
  char url[NDEF_MAX_LEN];
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

    uint8_t try_keys[5][AES_KEY_LEN] = {{0}};
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
    uint8_t decrypted[AES_KEY_LEN] = {0};
    if (deterministic_decrypt_p(nfc, try_keys[1], p_bytes, uid, decrypted, counter)) {
      Serial.print(F("[web] Keyset #"));
      Serial.print(keyset_idx);
      Serial.println(F(" K1 MATCH!"));
      memcpy(matched_keys, try_keys, sizeof(try_keys));
      out_counter = counter;
      memcpy(out_decrypted, decrypted, AES_KEY_LEN);
      return true;
    }

    keyset_idx++;
    search_from = k0_pos + 4;
  }

  Serial.println(F("[web] No keyset matched K1 decrypt."));
  return false;
}
#endif
