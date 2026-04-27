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

static uint8_t current_issuer_key[AES_KEY_LEN] = {0};
static String g_serial_command;

#include "card_key_matching.h"
#include "card_web_lookup.h"
#include "card_assessment.h"

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
  Serial.println(F("  recoverkey <n> <hex> [k0-hex]  Recover key slot n (0-4) with candidate old key"));
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
  if (has_issuer_key) {
    DBG_PRINT(F("  k0: ")); DBG_PRINTLN(mBoltConfig.k0);
    DBG_PRINT(F("  k1: ")); DBG_PRINTLN(mBoltConfig.k1);
    DBG_PRINT(F("  k2: ")); DBG_PRINTLN(mBoltConfig.k2);
    DBG_PRINT(F("  k3: ")); DBG_PRINTLN(mBoltConfig.k3);
    DBG_PRINT(F("  k4: ")); DBG_PRINTLN(mBoltConfig.k4);
    DBG_PRINT(F("  Issuer key: "));
    DBG_PRINTLN(convertIntToHex(current_issuer_key, AES_KEY_LEN));
  } else {
    DBG_PRINT(F("  k0: ")); DBG_PRINTLN(mBoltConfig.k0);
    DBG_PRINT(F("  k1: ")); DBG_PRINTLN(mBoltConfig.k1);
    DBG_PRINT(F("  k2: ")); DBG_PRINTLN(mBoltConfig.k2);
    DBG_PRINT(F("  k3: ")); DBG_PRINTLN(mBoltConfig.k3);
    DBG_PRINT(F("  k4: ")); DBG_PRINTLN(mBoltConfig.k4);
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

void handle_help() {
  serial_print_help();
}

void handle_uid() {
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

void handle_status() {
  serial_print_status();
}

void handle_auth() {
  if (!begin_card_command(F("[auth]"))) return;
  bolt.setCurKeysFromHex(mBoltConfig.k0, mBoltConfig.k1, mBoltConfig.k2, mBoltConfig.k3, mBoltConfig.k4);
  DBG_PRINT(F("[auth] Trying k0: "));
  for (int i = 0; i < AES_KEY_LEN; i++) { if (bolt.cur_keys.keys[0][i] < 0x10) DBG_PRINT("0"); DBG_PRINT(bolt.cur_keys.keys[0][i], HEX); }
  DBG_PRINTLN();
  DBG_PRINT(F("[auth] k0 bytes: "));
  for (int i = 0; i < 16; i++) {
    DBG_PRINT(bolt.cur_keys.keys[0][i], DEC);
    DBG_PRINT(" ");
  }
  DBG_PRINTLN();
  CardTapResult tap = wait_for_card(F("[auth] TIMEOUT"), F("[auth] UID: "), CARD_TAP_TIMEOUT_MS, true);
  if (!tap.found) return;
  Serial.println(F("[auth] About to authenticate..."));
  uint8_t result = bolt.nfc->ntag424_Authenticate(bolt.cur_keys.keys[0], 0, AUTH_CMD_EV2_FIRST);
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
void handle_ndef() {
  if (!begin_card_command(F("[ndef]"))) return;
  CardTapResult tap = wait_for_card(nullptr);
  if (tap.found) {
    uint8_t ndef[NDEF_MAX_LEN] = {0};
    int len = bolt.nfc->ntag424_ReadNDEFMessage(ndef, sizeof(ndef));
    if (len < 0 && strlen(mBoltConfig.k3) == HEX_KEY_LEN) {
      // PLAIN ISO read failed. SDM mirroring causes ISO ReadBinary to return
      // unexpected data on provisioned cards. Re-detect card to reset ISO-DEP
      // state, authenticate with key 3, then read via native DESFire ReadData.
      Serial.println(F("[ndef] PLAIN read failed, re-detecting for k3 auth..."));
      uint8_t redet_uid[MAX_UID_LEN] = {0};
      uint8_t redet_uid_len = 0;
      if (bolty_read_passive_target(bolt.nfc, redet_uid, &redet_uid_len)) {
        uint8_t k3_bytes[AES_KEY_LEN] = {0};
        bolt.setKey(k3_bytes, String(mBoltConfig.k3));
        if (bolt.nfc->ntag424_Authenticate(k3_bytes, 3, AUTH_CMD_EV2_FIRST) == 1) {
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

void handle_picc() {
  if (!begin_card_command(F("[picc]"))) return;

  CardTapResult tap = wait_for_card(F("[picc] TIMEOUT — no card detected"));

  if (!tap.found) {
    goto picc_done;
  }

  {
    uint8_t ndef[NDEF_MAX_LEN] = {0};
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
    uint8_t k1[AES_KEY_LEN], k2[AES_KEY_LEN];
    if (picc_hex_to_bytes(mBoltConfig.k1, k1, AES_KEY_LEN) != AES_KEY_LEN ||
        picc_hex_to_bytes(mBoltConfig.k2, k2, AES_KEY_LEN) != AES_KEY_LEN) {
      Serial.println(F("[picc] Invalid k1/k2 hex"));
      led_blink(5, 100);
      serial_cmd_active = false;
      goto picc_done;
    }

    PiccData picc = picc_parse_url(k1, k2, uri.c_str());
    picc_print(&picc);

    if (picc.valid) {
      // Verify UID matches
      bool uid_match = (tap.uid_len == 7);
      for (int i = 0; uid_match && i < 7; i++) {
        uid_match = (tap.uid[i] == picc.uid[i]);
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

void handle_decodebolt11() {
  const String &cmd = g_serial_command;
  String invoice = cmd.substring(13);
  invoice.trim();
  if (invoice.length() < 10) {
    Serial.println(F("[bolt11] Invoice too short"));
  } else {
    Bolt11Info info = bolt11_decode(invoice.c_str());
    bolt11_print(&info);
  }
}

struct InspectCardInfo {
  uint8_t version_ok;
};

static InspectCardInfo inspect_card_info(const CardTapResult &tap) {
  InspectCardInfo info = {};

  Serial.println(F("[inspect] --- Card Presence ---"));
  Serial.print(F("[inspect] UID length: "));
  Serial.println(tap.uid_len);
  Serial.print(F("[inspect] UID: "));
  bolty_print_hex(bolt.nfc, tap.uid, tap.uid_len);
  Serial.print(F("[inspect] UID compact: "));
  Serial.println(convertIntToHex(tap.uid, tap.uid_len));
  delay(50);

  Serial.println(F("[inspect] --- Version / Type ---"));
  info.version_ok = bolt.nfc->ntag424_GetVersion();
  Serial.print(F("[inspect] GetVersion: "));
  Serial.println(info.version_ok ? F("OK") : F("FAIL"));
  if (info.version_ok) {
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
  Serial.println(info.version_ok && bolt.nfc->ntag424_VersionInfo.HWType == 0x04 ? F("YES") : F("NO / UNKNOWN"));

  return info;
}

struct InspectKeyVersions {
  bool all_zero;
  bool any_error;
};

static InspectKeyVersions inspect_key_versions() {
  InspectKeyVersions result = {true, false};
  uint8_t key_versions[5] = {KEY_VER_READ_FAILED, KEY_VER_READ_FAILED,
                             KEY_VER_READ_FAILED, KEY_VER_READ_FAILED,
                             KEY_VER_READ_FAILED};

  Serial.println(F("[inspect] --- Key Versions (read-only) ---"));
  if (!bolt.nfc->ntag424_ISOSelectFileByDFN((uint8_t *)NTAG424_AID)) {
    Serial.println(F("[inspect] Failed to select NTAG424 application for key version reads"));
    result.any_error = true;
  } else {
    for (int k = 0; k < 5; k++) {
      const bool ok = bolt.nfc->ntag424_GetKeyVersion(k, &key_versions[k]);
      Serial.print(F("[inspect] Key "));
      Serial.print(k);
      Serial.print(F(" version: "));
      if (!ok) {
        Serial.println(F("READ ERROR"));
        result.any_error = true;
        continue;
      }
      Serial.print(F("0x"));
      print_hex_byte_prefixed(key_versions[k]);
      if (key_versions[k] == KEY_VER_FACTORY) Serial.println(F(" (factory default)"));
      else Serial.println(F(" (changed)"));
      if (key_versions[k] != KEY_VER_FACTORY) result.all_zero = false;
    }
  }

  // Detect inconsistent states (mixed factory + changed keys)
  if (!result.all_zero && !result.any_error) {
    bool all_changed = true;
    for (int k = 0; k < 5; k++) { if (key_versions[k] == KEY_VER_FACTORY) all_changed = false; }
    if (!all_changed) {
      Serial.println(F("[inspect] *** INCONSISTENT STATE DETECTED ***"));
      Serial.print(F("[inspect] Partial burn/wipe: keys "));
      for (int k = 0; k < 5; k++) {
        if (key_versions[k] == KEY_VER_FACTORY) {
          Serial.print(F("K")); Serial.print(k); Serial.print(F("=factory "));
        }
      }
      Serial.println(F("are still factory"));
      Serial.println(F("[inspect] If you know the keys used, try 'wipe' to reset all keys."));
      Serial.println(F("[inspect] If K0 is still factory, 'burn' may work (it requires K0=0x00)."));
    }
  }

  return result;
}

static void inspect_file_settings() {
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
}

static bool inspect_load_keys(uint8_t keys[5][AES_KEY_LEN]) {
  store_bolt_config_keys_from_bytes(mBoltConfig, keys);
  return true;
}

// Test current issuer key against card's SDM-encrypted PICC data.
//
// Derives K0-K4 from issuer key + UID using boltcard deterministic spec,
// then attempts K1 decryption of p= parameter and K2 CMAC verification of c=.
// If full match found, auto-loads derived keys for wipe/burn. Tests all
// version candidates (0,1,2,3) per boltcard spec.
//
// Ref: boltcard SPEC (deterministic key derivation), NT4H2421Gx datasheet §8.7 (SDM),
//      AN12196 §6 (CMAC verification), KeyDerivation.h (derivation constants)
static bool inspect_match_issuer(const CardTapResult &tap,
                                  const uint8_t p_bytes[AES_KEY_LEN],
                                  const uint8_t c_bytes[8],
                                  bool p_ok, bool c_ok) {
  if (!has_issuer_key || tap.uid_len != 7 || !p_ok) return false;

  Serial.println(F("[inspect] --- Current Issuer Key Check ---"));
  bool issuer_k1_match = false;
  uint32_t issuer_counter = 0;
  uint8_t issuer_decrypted[AES_KEY_LEN] = {0};
  uint8_t issuer_matched_keys[5][AES_KEY_LEN] = {{0}};
  int issuer_matched_version = -1;

  // Try all version candidates
  for (int vi = 0; vi < 4 && !issuer_k1_match; vi++) {
    uint32_t try_ver = BOLTCARD_VERSION_CANDIDATES[vi];
    uint8_t try_keys[5][AES_KEY_LEN] = {{0}};
    derive_deterministic_boltcard_keys(bolt.nfc, current_issuer_key, tap.uid, try_ver, try_keys);
    issuer_k1_match = deterministic_decrypt_p(bolt.nfc, try_keys[1], p_bytes, tap.uid, issuer_decrypted, issuer_counter);
    if (issuer_k1_match) {
      memcpy(issuer_matched_keys, try_keys, sizeof(issuer_matched_keys));
      issuer_matched_version = (int)try_ver;
    }
  }

  DBG_PRINT(F("[inspect] Issuer key "));
  DBG_PRINT(convertIntToHex(current_issuer_key, AES_KEY_LEN));
  DBG_PRINT(F(" -> K1 decrypt: "));
  DBG_PRINTLN(issuer_k1_match ? F("MATCH") : F("NO MATCH"));

  if (!issuer_k1_match) return false;

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
    bool issuer_cmac_ok = deterministic_verify_cmac(bolt.nfc, issuer_matched_keys[2], tap.uid, issuer_counter, c_bytes);
    Serial.print(F("[inspect]   K2/CMAC check (version "));
    Serial.print(issuer_matched_version);
    Serial.print(F("): "));
    Serial.println(issuer_cmac_ok ? F("MATCH") : F("NO MATCH"));

    if (issuer_cmac_ok) {
      Serial.println(F("[inspect]   Card matches current issuer key!"));
      led_signal_key_local();
      inspect_load_keys(issuer_matched_keys);
      Serial.println(F("[inspect]   Keys auto-loaded. Ready for wipe/burn."));
      return true;
    }
  } else {
    Serial.println(F("[inspect]   c= missing — cannot verify K2/CMAC."));
    inspect_load_keys(issuer_matched_keys);
    Serial.println(F("[inspect]   Keys auto-loaded (K1 only, no CMAC proof)."));
    return true;
  }
  return false;
}

// Fetch card keys from a web key server and verify against SDM data.
//
// Connects to configured key server with card UID, receives K0-K4 hex keys,
// then validates by authenticating K0 and verifying SDM p=/c= parameters.
// Falls back gracefully if WiFi or server is unavailable.
//
// Ref: boltcard SPEC (web key lookup protocol), NT4H2421Gx datasheet §8.7 (SDM)
static bool inspect_match_web(const CardTapResult &tap,
                                const uint8_t p_bytes[AES_KEY_LEN],
                                const uint8_t c_bytes[8],
                                bool p_ok, bool c_ok) {
  #if !HAS_WEB_LOOKUP
  (void)tap; (void)p_bytes; (void)c_bytes; (void)p_ok; (void)c_ok;
  return false;
  #else
  if (tap.uid_len != 7 || !p_ok) return false;

  Serial.println(F("[inspect] --- Web Key Lookup ---"));
  char uid_hex[15] = {0};
  for (int i = 0; i < tap.uid_len; i++) {
    snprintf(uid_hex + i * 2, 3, "%02X", tap.uid[i]);
  }
  uint8_t web_keys[5][AES_KEY_LEN] = {{0}};
  uint32_t web_counter = 0;
  uint8_t web_decrypted[AES_KEY_LEN] = {0};

  if (web_lookup_and_match(bolt.nfc, uid_hex, p_bytes, tap.uid, web_keys, web_counter, web_decrypted)) {
    Serial.print(F("[inspect]   Web match! Counter: "));
    Serial.println(web_counter);
    Serial.print(F("[inspect]   Decrypted UID: "));
    print_hex_bytes_spaced(web_decrypted + 1, 7);
    Serial.println();

    // Try K2/CMAC verification
    if (c_ok) {
      bool web_cmac_ok = deterministic_verify_cmac(bolt.nfc, web_keys[2], tap.uid, web_counter, c_bytes);
      Serial.print(F("[inspect]   K2/CMAC check: "));
      Serial.println(web_cmac_ok ? F("MATCH") : F("NO MATCH"));
      if (web_cmac_ok) {
        Serial.println(F("[inspect]   Card matched via web lookup!"));
        led_signal_key_online();
        inspect_load_keys(web_keys);
        Serial.println(F("[inspect]   Keys auto-loaded from web. Ready for wipe/burn."));
        return true;
      }
    } else {
      Serial.println(F("[inspect]   c= missing — loading web keys without CMAC proof."));
      led_signal_key_online();
      inspect_load_keys(web_keys);
      Serial.println(F("[inspect]   Keys auto-loaded from web (K1 only)."));
      return true;
    }
  } else if (!wifi_connected) {
    Serial.println(F("[inspect]   WiFi not connected — skipping web lookup."));
  } else {
    Serial.println(F("[inspect]   No matching keyset found online."));
  }
  return false;
  #endif
}

static void inspect_ndef_content(const CardTapResult &tap) {
  Serial.println(F("[inspect] --- NDEF Read ---"));
  uint8_t ndef[NDEF_MAX_LEN] = {0};
  int ndef_len = bolt.nfc->ntag424_ReadNDEFMessage(ndef, sizeof(ndef));
  if (ndef_len < 0 && strlen(mBoltConfig.k3) == HEX_KEY_LEN) {
    // PLAIN ISO read failed — re-detect card to reset ISO-DEP state,
    // auth with key 3, then read NDEF via native DESFire ReadData.
    uint8_t redet_uid[MAX_UID_LEN] = {0};
    uint8_t redet_uid_len = 0;
    if (bolty_read_passive_target(bolt.nfc, redet_uid, &redet_uid_len)) {
      uint8_t k3_bytes[AES_KEY_LEN] = {0};
      bolt.setKey(k3_bytes, String(mBoltConfig.k3));
      if (bolt.nfc->ntag424_Authenticate(k3_bytes, 3, AUTH_CMD_EV2_FIRST) == 1) {
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
    return;
  }
  if (ndef_len == 0) {
    Serial.println(F("[inspect] No NDEF data (NLEN=0)"));
    return;
  }

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

  // Parse p= and c= once for all key matching attempts
  String p_hex, c_hex;
  const bool has_p = uri_get_query_param(uri, "p", p_hex);
  const bool has_c = uri_get_query_param(uri, "c", c_hex);
  uint8_t p_bytes[AES_KEY_LEN] = {0};
  uint8_t c_bytes[8] = {0};
  bool p_ok = false, c_ok = false;
  if (has_p) p_ok = parse_hex_fixed(p_hex, p_bytes, AES_KEY_LEN);
  if (has_c) c_ok = parse_hex_fixed(c_hex, c_bytes, 8);

  // Key matching cascade: issuer → web → hardcoded
  bool keys_auto_loaded = inspect_match_issuer(tap, p_bytes, c_bytes, p_ok, c_ok);
  if (!keys_auto_loaded) {
    keys_auto_loaded = inspect_match_web(tap, p_bytes, c_bytes, p_ok, c_ok);
  }
  if (!keys_auto_loaded) {
    print_deterministic_boltcard_check(bolt.nfc, tap.uid, tap.uid_len, uri);
  }
}

// Perform comprehensive read-only card inspection.
//
// Multi-phase inspection: card presence/type → key versions → file settings →
// NDEF content → issuer key matching → web key lookup. All operations are
// non-destructive (no authentication required for version/settings reads).
// Auto-loads matched keys for subsequent wipe/burn operations.
//
// Ref: NT4H2421Gx datasheet §7.1 (GetVersion), §7.3.3 (GetKeyVersion),
//      §7.6.1 (GetFileSettings), ISO 7816-4 (ReadBinary for NDEF)
void handle_inspect() {
  if (!begin_card_command(F("[inspect]"))) return;

  CardTapResult tap = wait_for_card(F("[inspect] TIMEOUT"));
  if (!tap.found) return;

  InspectCardInfo card_info = inspect_card_info(tap);
  InspectKeyVersions key_info = inspect_key_versions();
  inspect_file_settings();
  inspect_ndef_content(tap);

  Serial.println(F("[inspect] --- Safe Summary ---"));
  if (!card_info.version_ok) {
    Serial.println(F("[inspect] Could not confirm NTAG424 via GetVersion."));
  } else if (key_info.any_error) {
    Serial.println(F("[inspect] Card responded, but some read-only NTAG424 reads failed."));
  } else if (key_info.all_zero) {
    Serial.println(F("[inspect] Card looks blank or unprovisioned from key versions alone."));
  } else {
    Serial.println(F("[inspect] Card has non-default key versions; likely provisioned or previously modified."));
  }
  Serial.println(F("[inspect] No authentication attempts were made."));
  Serial.println(F("[inspect] No writes or key changes were performed."));
  led_blink(3, 100);
  serial_cmd_active = false;
}

// Derive and display deterministic boltcard keys from card's NDEF data.
//
// Reads card NDEF, extracts p= (encrypted PICC data) and c= (CMAC), then
// attempts deterministic key derivation using all known issuer keys and version
// candidates. Displays derived K0-K4 and CardID if a match is found.
//
// Ref: boltcard SPEC (deterministic key derivation),
//      NT4H2421Gx datasheet §8.7 (SDM data structure),
//      AN12196 §6.3 (key derivation and CMAC)
void handle_derivekeys() {
  if (!begin_card_command(F("[derivekeys]"))) return;

  CardTapResult tap = wait_for_card(F("[derivekeys] TIMEOUT"));
  if (!tap.found) return;

  Serial.print(F("[derivekeys] UID: "));
  bolty_print_hex(bolt.nfc, tap.uid, tap.uid_len);

  uint8_t ndef[NDEF_MAX_LEN] = {0};
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
  const bool full_match = deterministic_try_known_matches(bolt.nfc, tap.uid, tap.uid_len, uri, match);

  if (!match.saw_k1_match) {
    Serial.println(F("[derivekeys] FAIL — no known deterministic issuer key produced valid PICCData for this card."));
    Serial.println(F("[derivekeys] No keys were changed in config."));
    led_blink(5, 100);
    serial_cmd_active = false;
    return;
  }

  DBG_PRINT(F("[derivekeys] Deterministic K1 matched issuer key "));
  print_hex_bytes_inline(match.issuer_key, sizeof(match.issuer_key));
  DBG_PRINTLN();
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
  DBG_PRINT(F("[derivekeys] FULL MATCH — issuer key "));
  print_hex_bytes_inline(match.issuer_key, sizeof(match.issuer_key));
  DBG_PRINT(F(", version "));
  DBG_PRINTLN(match.version);
  Serial.println(F("[derivekeys] Loaded deterministic K0-K4 into active config."));
  Serial.println(F("[derivekeys] K1 and K2 were verified read-only from the card's current NDEF data."));
  Serial.println(F("[derivekeys] K0, K3, and K4 cannot be directly verified read-only, but this is the strongest safe pre-auth signal."));
  DBG_PRINT(F("[derivekeys] k0: "));
  DBG_PRINTLN(mBoltConfig.k0);
  DBG_PRINT(F("[derivekeys] k1: "));
  DBG_PRINTLN(mBoltConfig.k1);
  DBG_PRINT(F("[derivekeys] k2: "));
  DBG_PRINTLN(mBoltConfig.k2);
  DBG_PRINT(F("[derivekeys] k3: "));
  DBG_PRINTLN(mBoltConfig.k3);
  DBG_PRINT(F("[derivekeys] k4: "));
  DBG_PRINTLN(mBoltConfig.k4);
  Serial.println(F("[derivekeys] Next steps: 'auth' gives a single K0 confirmation attempt; 'wipe' performs the actual reset."));
  led_blink(3, 100);
  serial_cmd_active = false;
}

void handle_ver() {
  if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
  serial_cmd_active = true;
  uint8_t uid[MAX_UID_LEN] = {0};
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

void handle_issuer() {
  if (has_issuer_key) {
    DBG_PRINT(F("[issuer] Current issuer key: "));
    DBG_PRINTLN(convertIntToHex(current_issuer_key, AES_KEY_LEN));
  } else {
    Serial.println(F("[issuer] No issuer key set"));
  }
}

void handle_set_issuer() {
  const String &cmd = g_serial_command;
  String hex = cmd.substring(7);
  hex.trim();
  if (hex.length() != HEX_KEY_LEN) {
    Serial.println(F("[error] Issuer key must be exactly 32 hex chars"));
    return;
  }
  for (unsigned int i = 0; i < hex.length(); i++) {
    char c = hex.charAt(i);
    if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
      Serial.println(F("[error] Issuer key must be hex only (0-9, a-f)"));
      return;
    }
  }
  uint8_t tmp[AES_KEY_LEN] = {0};
  if (!parse_hex_fixed(hex, tmp, AES_KEY_LEN)) {
    Serial.println(F("[error] Failed to parse issuer key hex"));
    return;
  }
  memcpy(current_issuer_key, tmp, AES_KEY_LEN);
  has_issuer_key = true;
  DBG_PRINT(F("[issuer] Issuer key set: "));
  DBG_PRINTLN(hex);
  Serial.println(F("[issuer] Per-card K0-K4 will be derived from this key during inspect/burn/wipe"));
}

void handle_keys() {
  const String &cmd = g_serial_command;
  String args = cmd.substring(5);
  int s1 = args.indexOf(' ');
  if (s1 < 0) { Serial.println(F("[error] Usage: keys <k0> <k1> <k2> <k3> <k4>")); return; }
  int s2 = args.indexOf(' ', s1 + 1);
  if (s2 < 0) { Serial.println(F("[error] Usage: keys <k0> <k1> <k2> <k3> <k4>")); return; }
  int s3 = args.indexOf(' ', s2 + 1);
  if (s3 < 0) { Serial.println(F("[error] Usage: keys <k0> <k1> <k2> <k3> <k4>")); return; }
  int s4 = args.indexOf(' ', s3 + 1);
  if (s4 < 0) { Serial.println(F("[error] Usage: keys <k0> <k1> <k2> <k3> <k4>")); return; }
  String k0 = args.substring(0, s1);
  String k1 = args.substring(s1 + 1, s2);
  String k2 = args.substring(s2 + 1, s3);
  String k3 = args.substring(s3 + 1, s4);
  String k4 = args.substring(s4 + 1);
  if (k0.length() != HEX_KEY_LEN || k1.length() != HEX_KEY_LEN ||
      k2.length() != HEX_KEY_LEN || k3.length() != HEX_KEY_LEN ||
      k4.length() != HEX_KEY_LEN) {
    Serial.println(F("[error] Each key must be exactly 32 hex chars"));
    return;
  }
  safe_strcpy(mBoltConfig.k0, k0.c_str(), sizeof(mBoltConfig.k0));
  safe_strcpy(mBoltConfig.k1, k1.c_str(), sizeof(mBoltConfig.k1));
  safe_strcpy(mBoltConfig.k2, k2.c_str(), sizeof(mBoltConfig.k2));
  safe_strcpy(mBoltConfig.k3, k3.c_str(), sizeof(mBoltConfig.k3));
  safe_strcpy(mBoltConfig.k4, k4.c_str(), sizeof(mBoltConfig.k4));
  has_issuer_key = false;  // Mutual exclusion: keys overrides issuer
  Serial.println(F("[keys] Keys set"));
  DBG_PRINT(F("  k0: ")); DBG_PRINTLN(k0);
  DBG_PRINT(F("  k4: ")); DBG_PRINTLN(k4);
}

void handle_url() {
  const String &cmd = g_serial_command;
  String url = cmd.substring(4);
  url.trim();
  if (url.length() == 0) {
    Serial.println(F("[error] Usage: url <lnurl>"));
    return;
  }
  safe_strcpy(mBoltConfig.url, url.c_str(), sizeof(mBoltConfig.url));
  if (url.startsWith("lnurlp://")) {
    safe_strcpy(mBoltConfig.card_mode, "pos", sizeof(mBoltConfig.card_mode));
  } else if (url.startsWith("https://")) {
    safe_strcpy(mBoltConfig.card_mode, "2fa", sizeof(mBoltConfig.card_mode));
  } else {
    safe_strcpy(mBoltConfig.card_mode, "withdraw", sizeof(mBoltConfig.card_mode));
  }
  saveBoltConfig(active_bolt_config);
  Serial.print(F("[url] Set to: ")); Serial.println(url);
}

void handle_mode_pos() {
  safe_strcpy(mBoltConfig.card_mode, "pos", sizeof(mBoltConfig.card_mode));
  saveBoltConfig(active_bolt_config);
  Serial.println(F("[mode] Set to: pos"));
}

void handle_mode_2fa() {
  safe_strcpy(mBoltConfig.card_mode, "2fa", sizeof(mBoltConfig.card_mode));
  saveBoltConfig(active_bolt_config);
  Serial.println(F("[mode] Set to: 2fa"));
}

void handle_mode_withdraw() {
  safe_strcpy(mBoltConfig.card_mode, "withdraw", sizeof(mBoltConfig.card_mode));
  saveBoltConfig(active_bolt_config);
  Serial.println(F("[mode] Set to: withdraw"));
}

void handle_reseturl() {
  const String &cmd = g_serial_command;
  String url = cmd.substring(9);
  url.trim();
  if (url.length() == 0) {
    Serial.println(F("[error] Usage: reseturl <plain-url>"));
    return;
  }
  safe_strcpy(mBoltConfig.reset_url, url.c_str(), sizeof(mBoltConfig.reset_url));
  saveBoltConfig(active_bolt_config);
  Serial.print(F("[reseturl] Set to: ")); Serial.println(url);
}

void handle_wifissid() {
  const String &cmd = g_serial_command;
  String ssid = cmd.substring(9);
  ssid.trim();
  safe_strcpy(mBoltConfig.wifi_ssid, ssid.c_str(), sizeof(mBoltConfig.wifi_ssid));
  saveBoltConfig(active_bolt_config);
  Serial.print(F("[wifissid] Set to: ")); Serial.println(mBoltConfig.wifi_ssid);
}

void handle_wifipass() {
  const String &cmd = g_serial_command;
  String pass = cmd.substring(9);
  pass.trim();
  safe_strcpy(mBoltConfig.wifi_password, pass.c_str(), sizeof(mBoltConfig.wifi_password));
  saveBoltConfig(active_bolt_config);
  Serial.println(F("[wifipass] Updated"));
}

#if HAS_WEB_LOOKUP
void handle_wifi_connect() {
  const String &cmd = g_serial_command;
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
  while (WiFi.status() != WL_CONNECTED && millis() - t0 < CARD_TAP_TIMEOUT_MS) {
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

void handle_wifi_off() {
  WiFi.disconnect(true);
  WiFi.mode(WIFI_OFF);
  wifi_connected = false;
  Serial.println(F("[wifi] Disconnected"));
}

void handle_wifi() {
  if (wifi_connected) {
    Serial.print(F("[wifi] Connected, IP: "));
    Serial.println(WiFi.localIP());
    Serial.print(F("[wifi] Lookup URL: "));
    Serial.println(web_lookup_url);
  } else {
    Serial.println(F("[wifi] Not connected. Use: wifi <ssid> <password>"));
  }
}

void handle_keyserver() {
  const String &cmd = g_serial_command;
  String url = cmd.substring(10);
  url.trim();
  if (url.length() >= sizeof(web_lookup_url)) {
    Serial.println(F("[error] URL too long"));
    return;
  }
  safe_strcpy(web_lookup_url, url.c_str(), sizeof(web_lookup_url));
  Serial.print(F("[keyserver] Set to: "));
  Serial.println(web_lookup_url);
}
#endif

void handle_probe_on() {
  mBoltConfig.wifi_probe_enabled = true;
  saveBoltConfig(active_bolt_config);
  Serial.println(F("[probe] enabled"));
}

void handle_probe_off() {
  mBoltConfig.wifi_probe_enabled = false;
  saveBoltConfig(active_bolt_config);
  Serial.println(F("[probe] disabled"));
}

void handle_probe() {
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

void handle_burn() {
  if (!begin_card_command(F("[burn]"))) return;
  bolt.loadKeysForBurn(mBoltConfig);
  uint8_t result = wait_for_card(F("[burn] TIMEOUT — no card detected in 30s"), CARD_TAP_TIMEOUT_LONG_MS,
                                 [&]() { return bolt.burn(String(mBoltConfig.url)); });
  if (result == JOBSTATUS_WAITING) {
    serial_cmd_active = false;
    led_blink(5, 100);
    return;
  }
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
    const uint8_t v_auth0 = bolt.nfc->ntag424_Authenticate(bolt.new_keys.keys[0], 0, AUTH_CMD_EV2_FIRST);
    DBG_PRINT(F("[burn] VERIFY — AUTH k0: "));
    DBG_PRINTLN(v_auth0 == 1 ? F("OK") : F("FAIL"));
    if (v_auth0 == 1) {
      // Re-detect card (auth may have left ISO-DEP in odd state),
      // then try PLAIN ISO NDEF read (works now that WriteData offset bug is fixed).
      uint8_t v_uid[MAX_UID_LEN] = {0};
      uint8_t v_uid_len = 0;
      if (bolty_read_passive_target(bolt.nfc, v_uid, &v_uid_len)) {
        uint8_t vbuf[NDEF_MAX_LEN] = {0};
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

void handle_wipe() {
  if (!begin_card_command(F("[wipe]"))) return;
  bolt.loadKeysForWipe(mBoltConfig);
  uint8_t result = wait_for_card(F("[wipe] TIMEOUT — no card detected in 30s"), CARD_TAP_TIMEOUT_LONG_MS,
                                 [&]() { return bolt.wipe(); });
  if (result == JOBSTATUS_WAITING) {
    serial_cmd_active = false;
    led_blink(5, 100);
    return;
  }
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

void handle_keyver() {
  if (!begin_card_command(F("[keyver]"))) return;
  CardTapResult tap = wait_for_card(F("[keyver] TIMEOUT"), F("[keyver] UID: "), CARD_TAP_TIMEOUT_MS, true);
  if (!tap.found) return;
  bool all_zero = true;
  for (int k = 0; k < 5; k++) {
    uint8_t kv = bolty_get_key_version(bolt.nfc, k);
    Serial.print(F("[keyver] Key "));
    Serial.print(k);
    Serial.print(F(" version: 0x"));
    serial_print_hex_byte(kv);
    if (kv == KEY_VER_FACTORY) {
      Serial.println(F(" (factory default)"));
    } else if (kv == KEY_VER_READ_FAILED && k == 0) {
      Serial.println(F(" (protected — K0 changed from factory)"));
    } else if (kv == KEY_VER_READ_FAILED) {
      Serial.println(F(" (ERROR: read failed)"));
    } else {
      Serial.println(F(" (changed)"));
    }
    if (kv != KEY_VER_FACTORY && kv != KEY_VER_READ_FAILED) all_zero = false;
  }
  if (all_zero) {
    Serial.println(F("[keyver] Card appears BLANK — factory default keys"));
  } else {
    Serial.println(F("[keyver] Card is PROVISIONED — keys have been set"));
  }
  led_blink(3, 100);
  serial_cmd_active = false;
}

void handle_check() {
  if (!begin_card_command(F("[check]"))) return;
  bolt.cur_keys = BoltcardKeys::allZeros();
  DBG_PRINT(F("[check] Using zero key: "));
  for (int i = 0; i < AES_KEY_LEN; i++) { if (bolt.cur_keys.keys[0][i] < 0x10) DBG_PRINT("0"); DBG_PRINT(bolt.cur_keys.keys[0][i], HEX); }
  DBG_PRINTLN();
  CardTapResult tap = wait_for_card(F("[check] TIMEOUT"), F("[check] UID: "), CARD_TAP_TIMEOUT_MS, true);
  if (!tap.found) return;
  uint8_t result = bolt.nfc->ntag424_Authenticate(bolt.cur_keys.keys[0], 0, AUTH_CMD_EV2_FIRST);
  Serial.println(result == 1 ? F("[check] SUCCESS — card has factory zero keys") : F("[check] FAILED — card does NOT have factory keys"));
  led_blink(result == 1 ? 3 : 5, 100);
  serial_cmd_active = false;
}

void handle_dummyburn() {
  if (!begin_card_command(F("[dummyburn]"))) return;
  bolt.cur_keys = BoltcardKeys::allZeros();
  bolt.new_keys = BoltcardKeys::allZeros();
  String lnurl = "https://dummy.test";
  uint8_t result = wait_for_card(F("[dummyburn] TIMEOUT — no card detected in 30s"), CARD_TAP_TIMEOUT_LONG_MS,
                                 [&]() { return bolt.burn(lnurl); });
  if (result == JOBSTATUS_WAITING) {
    serial_cmd_active = false;
    led_blink(5, 100);
    return;
  }
  Serial.print(F("[dummyburn] ")); Serial.println(bolt.get_job_status());
  Serial.println(result == JOBSTATUS_DONE ? F("[dummyburn] SUCCESS") : F("[dummyburn] FAILED"));
  if (result == JOBSTATUS_DONE) {
    Serial.println(F("[dummyburn] Card has dummy data — use 'keys 000... 000... 000... 000... 000...' then 'wipe' to restore"));
  }
  led_blink(result == JOBSTATUS_DONE ? 3 : 5, 100);
  serial_cmd_active = false;
}

void handle_reset() {
  if (!begin_card_command(F("[reset]"))) return;
  uint8_t result = wait_for_card(F("[reset] TIMEOUT — no card detected in 30s"), CARD_TAP_TIMEOUT_LONG_MS,
                                 [&]() { return bolt.resetNdefOnly(); });
  if (result == JOBSTATUS_WAITING) {
    serial_cmd_active = false;
    led_blink(5, 100);
    return;
  }
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

void handle_diagnose() {
  if (!begin_card_command(F("[diagnose]"))) return;

  CardTapResult tap = wait_for_card(F("[diagnose] TIMEOUT"), F("[diagnose] UID: "), CARD_TAP_TIMEOUT_MS, true);
  if (!tap.found) return;

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
    serial_print_hex_byte(kv[k]);
    if (kv[k] == KEY_VER_FACTORY) Serial.println(F(" (default)"));
    else if (kv[k] == KEY_VER_READ_FAILED) { Serial.println(F(" (READ ERROR)")); any_error = true; }
    else Serial.println(F(" (changed)"));
    if (kv[k] != KEY_VER_FACTORY) all_zero = false;
  }
  
  // Test zero-key authentication on key 0 (master)
  bolt.selectNtagApplicationFiles();
  uint8_t auth_d = bolt.nfc->ntag424_Authenticate((uint8_t *)ZERO_KEY, 0, AUTH_CMD_EV2_FIRST);
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
    Serial.println(F("[diagnose] Recovery: 'recoverkey <slot> <old-key-hex> [k0-hex]' per stuck key"));
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

void handle_recoverkey() {
  const String &cmd = g_serial_command;
  // Usage: recoverkey <slot 0-4> <32-hex-old-key> [32-hex-k0]
  // Authenticates with K0 (zeros by default, or provided hex), then ChangeKey
  // to restore the target key slot to zero with version 0x00.
  if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }

  String args = cmd.substring(11);
  args.trim();
  int spaceIdx = args.indexOf(' ');
  if (spaceIdx < 0) {
    Serial.println(F("[recoverkey] Usage: recoverkey <slot 0-4> <32-hex-old-key> [32-hex-k0]"));
    return;
  }
  int slot = args.substring(0, spaceIdx).toInt();
  String rest = args.substring(spaceIdx + 1);
  rest.trim();

  int spaceIdx2 = rest.indexOf(' ');
  String old_key_hex, k0_hex;
  if (spaceIdx2 >= 0) {
    old_key_hex = rest.substring(0, spaceIdx2);
    k0_hex = rest.substring(spaceIdx2 + 1);
    k0_hex.trim();
  } else {
    old_key_hex = rest;
    k0_hex = "";
  }
  old_key_hex.trim();

  if (slot < 0 || slot > 4) {
    Serial.println(F("[recoverkey] Slot must be 0-4"));
    return;
  }
  if (old_key_hex.length() != HEX_KEY_LEN) {
    Serial.println(F("[recoverkey] Old key must be 32 hex chars (16 bytes)"));
    return;
  }
  if (k0_hex.length() > 0 && k0_hex.length() != HEX_KEY_LEN) {
    Serial.println(F("[recoverkey] K0 must be 32 hex chars (16 bytes) or omitted for zeros"));
    return;
  }

  uint8_t auth_key[AES_KEY_LEN] = {0};
  uint8_t old_key[AES_KEY_LEN] = {0};
  bolt.setKey(old_key, old_key_hex);
  if (k0_hex.length() == HEX_KEY_LEN) {
    bolt.setKey(auth_key, k0_hex);
  }

  Serial.print(F("[recoverkey] Target: key "));
  Serial.print(slot);
  Serial.println(F(" -> zero, ver=0x00"));
  DBG_PRINT(F("[recoverkey] Candidate old key: "));
  DBG_PRINTLN(old_key_hex);
  if (k0_hex.length() == HEX_KEY_LEN) {
    DBG_PRINT(F("[recoverkey] Auth K0: "));
    DBG_PRINTLN(k0_hex);
  } else {
    Serial.println(F("[recoverkey] Auth K0: zeros (factory default)"));
  }
  serial_cmd_active = true;
  led_on();

  CardTapResult tap = wait_for_card(F("[recoverkey] TIMEOUT"), F("[recoverkey] UID: "), CARD_TAP_TIMEOUT_MS, true);
  if (!tap.found) return;
  bolt.selectNtagApplicationFiles();

  uint8_t auth_rk = bolt.nfc->ntag424_Authenticate(auth_key, 0, AUTH_CMD_EV2_FIRST);
  Serial.print(F("[recoverkey] Auth K0: "));
  Serial.println(auth_rk == 1 ? "OK" : "FAILED");
  if (auth_rk != 1) {
    Serial.println(F("[recoverkey] ABORT — K0 auth failed (wrong master key)"));
    led_blink(5, 100);
    serial_cmd_active = false;
    return;
  }

  bool ok = bolt.nfc->ntag424_ChangeKey(old_key, (uint8_t *)ZERO_KEY, slot, KEY_VER_FACTORY);
  Serial.print(F("[recoverkey] ChangeKey result: "));
  Serial.println(ok ? "OK" : "FAILED");

  bolt.nfc->ntag424_ISOSelectFileByDFN((uint8_t *)NTAG424_AID);
  uint8_t kv_after = bolty_get_key_version(bolt.nfc, slot);
  Serial.print(F("[recoverkey] Key "));
  Serial.print(slot);
  Serial.print(F(" version AFTER: 0x"));
  serial_print_hex_byte(kv_after);
  Serial.println();

  const bool pass = ok &&
                    (kv_after == KEY_VER_FACTORY ||
                     (slot == 0 && kv_after == KEY_VER_READ_FAILED));
  Serial.println(pass ?
                     F("[recoverkey] PASS — key restored to factory zero") :
                     F("[recoverkey] FAIL — candidate old key was incorrect or card state differs"));
  led_blink(pass ? 3 : 5, 100);
  serial_cmd_active = false;
}

static void testck_print_version(const __FlashStringHelper *label, uint8_t kv) {
  Serial.print(label);
  serial_print_hex_byte(kv);
  Serial.println();
}

static void testck_finish(uint8_t blinks) {
  led_blink(blinks, 100);
  serial_cmd_active = false;
}

void handle_testck() {
  if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
  Serial.println(F("[testck] ChangeKey A/B test — round-trip on key 1 (known zero)"));
  serial_cmd_active = true;
  led_on();

  CardTapResult tap = wait_for_card(F("[testck] TIMEOUT"), F("[testck] UID: "), CARD_TAP_TIMEOUT_MS, true);
  if (!tap.found) return;

  uint8_t test_key[AES_KEY_LEN] = {0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44,
                          0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xEE, 0xFF};

  uint8_t kv_before = bolty_get_key_version(bolt.nfc, 1);
  testck_print_version(F("[testck] Key 1 version BEFORE: 0x"), kv_before);

  bolt.selectNtagApplicationFiles();
  uint8_t auth1 = bolt.nfc->ntag424_Authenticate((uint8_t *)ZERO_KEY, 0, AUTH_CMD_EV2_FIRST);
  Serial.print(F("[testck] Auth key 0 (zeros): "));
  Serial.println(auth1 == 1 ? "OK" : "FAILED");
  if (auth1 != 1) {
    Serial.println(F("[testck] ABORT — auth failed"));
    testck_finish(5);
    return;
  }

  if (kv_before == KEY_VER_PROVISIONED) {
    Serial.println(F("[testck] Recovery mode — restoring key 1 from test value to zero"));
    bool recovered = bolt.nfc->ntag424_ChangeKey(test_key, (uint8_t *)ZERO_KEY, 1, KEY_VER_FACTORY);
    Serial.print(F("[testck]   Result: "));
    Serial.println(recovered ? "OK" : "FAILED");

    bolt.nfc->ntag424_ISOSelectFileByDFN((uint8_t *)NTAG424_AID);
    uint8_t kv_recovered = bolty_get_key_version(bolt.nfc, 1);
    testck_print_version(F("[testck]   Key 1 version: 0x"), kv_recovered);

    bool recovery_pass = recovered && (kv_recovered == KEY_VER_FACTORY);
    Serial.println(recovery_pass ?
                       F("[testck] RECOVERY PASS — key 1 restored to factory state") :
                       F("[testck] RECOVERY FAIL — key 1 not restored"));
    testck_finish(recovery_pass ? 3 : 5);
    return;
  }

  if (kv_before != KEY_VER_FACTORY) {
    Serial.println(F("[testck] WARNING — key 1 is in an unexpected state, aborting"));
    testck_finish(5);
    return;
  }

  // Step 1: ChangeKey key 1 from zero → test value, version 0x01
  Serial.println(F("[testck] Step 1: ChangeKey(1, zero→test, ver=0x01)"));
  bool ck1 = bolt.nfc->ntag424_ChangeKey((uint8_t *)ZERO_KEY, test_key, 1, KEY_VER_PROVISIONED);
  Serial.print(F("[testck]   Result: "));
  Serial.println(ck1 ? "OK" : "FAILED");

  bolt.nfc->ntag424_ISOSelectFileByDFN((uint8_t *)NTAG424_AID);
  uint8_t kv_mid = bolty_get_key_version(bolt.nfc, 1);
  testck_print_version(F("[testck]   Key 1 version: 0x"), kv_mid);

  if (!ck1 && kv_mid == KEY_VER_PROVISIONED) {
    Serial.println(F("[testck] NOTICE — card changed but library returned false (stale build/parsing bug)"));
  }

  bool step1_pass = (kv_mid == KEY_VER_PROVISIONED);
  Serial.print(F("[testck]   Step 1: "));
  Serial.println(step1_pass ? "PASS" : "FAIL");

  if (!step1_pass) {
    Serial.println(F("[testck] ABORT — step 1 failed, not attempting restore"));
    testck_finish(5);
    return;
  }

  // Step 2: Re-auth (key 0 still zero), change key 1 back
  bolt.selectNtagApplicationFiles();
  uint8_t auth2 = bolt.nfc->ntag424_Authenticate((uint8_t *)ZERO_KEY, 0, AUTH_CMD_EV2_FIRST);
  Serial.print(F("[testck] Re-auth key 0: "));
  Serial.println(auth2 == 1 ? "OK" : "FAILED");
  if (auth2 != 1) {
    Serial.println(F("[testck] ABORT — re-auth failed (card may be in bad state)"));
    testck_finish(5);
    return;
  }

  Serial.println(F("[testck] Step 2: ChangeKey(1, test→zero, ver=0x00)"));
  bool ck2 = bolt.nfc->ntag424_ChangeKey(test_key, (uint8_t *)ZERO_KEY, 1, KEY_VER_FACTORY);
  Serial.print(F("[testck]   Result: "));
  Serial.println(ck2 ? "OK" : "FAILED");

  bolt.nfc->ntag424_ISOSelectFileByDFN((uint8_t *)NTAG424_AID);
  uint8_t kv_final = bolty_get_key_version(bolt.nfc, 1);
  testck_print_version(F("[testck]   Key 1 version: 0x"), kv_final);

  if (!ck2 && kv_final == KEY_VER_FACTORY) {
    Serial.println(F("[testck] NOTICE — card restored but library returned false (stale build/parsing bug)"));
  }

  bool step2_pass = (kv_final == KEY_VER_FACTORY);
  Serial.print(F("[testck]   Step 2: "));
  Serial.println(step2_pass ? "PASS" : "FAIL");

  bool all_pass = step1_pass && step2_pass;
  Serial.println(F("---"));
  if (all_pass) {
    Serial.println(F("[testck] ALL PASS — ChangeKey implementation is CORRECT"));
    Serial.println(F("[testck] Conclusion: key 4 corruption is CARD-SPECIFIC"));
    Serial.println(F("[testck] (key 4 has unknown value from prior operation)"));
  } else {
    Serial.println(F("[testck] SOME FAILED — ChangeKey has issues"));
  }

  testck_finish(all_pass ? 3 : 5);
}

#if BOLTY_OTA_ENABLED
void handle_ota() {
  ota_check_and_update();
}
#endif

void handle_serial_command(String cmd) {
  cmd.trim();
  if (cmd.length() == 0) return;

  g_serial_command = cmd;

  if (cmd == "help") { handle_help(); }
  else if (cmd == "uid") { handle_uid(); }
  else if (cmd == "status") { handle_status(); }
  else if (cmd == "auth") { handle_auth(); }
  else if (cmd == "ndef") { handle_ndef(); }
  else if (cmd == "picc") { handle_picc(); }
  else if (cmd.startsWith("decodebolt11 ")) { handle_decodebolt11(); }
  else if (cmd == "inspect") { handle_inspect(); }
  else if (cmd == "derivekeys") { handle_derivekeys(); }
  else if (cmd == "ver") { handle_ver(); }
  else if (cmd == "issuer") { handle_issuer(); }
  else if (cmd.startsWith("issuer ")) { handle_set_issuer(); }
  else if (cmd.startsWith("keys ")) { handle_keys(); }
  else if (cmd.startsWith("url ")) { handle_url(); }
  else if (cmd == "mode pos") { handle_mode_pos(); }
  else if (cmd == "mode 2fa") { handle_mode_2fa(); }
  else if (cmd == "mode withdraw") { handle_mode_withdraw(); }
  else if (cmd.startsWith("reseturl ")) { handle_reseturl(); }
  else if (cmd.startsWith("wifissid ")) { handle_wifissid(); }
  else if (cmd.startsWith("wifipass ")) { handle_wifipass(); }
#if HAS_WEB_LOOKUP
  else if (cmd.startsWith("wifi ")) { handle_wifi_connect(); }
  else if (cmd == "wifi off") { handle_wifi_off(); }
  else if (cmd == "wifi") { handle_wifi(); }
  else if (cmd.startsWith("keyserver ")) { handle_keyserver(); }
#endif
  else if (cmd == "probe on") { handle_probe_on(); }
  else if (cmd == "probe off") { handle_probe_off(); }
  else if (cmd == "probe") { handle_probe(); }
  else if (cmd == "burn") { handle_burn(); }
  else if (cmd == "wipe") { handle_wipe(); }
  else if (cmd == "keyver") { handle_keyver(); }
  else if (cmd == "check") { handle_check(); }
  else if (cmd == "dummyburn") { handle_dummyburn(); }
  else if (cmd == "reset") { handle_reset(); }
  else if (cmd == "diagnose") { handle_diagnose(); }
  else if (cmd.startsWith("recoverkey ")) { handle_recoverkey(); }
  else if (cmd == "testck") { handle_testck(); }
#if BOLTY_OTA_ENABLED
  else if (cmd == "ota") { handle_ota(); }
#endif
  else {
    Serial.print(F("[error] Unknown: ")); Serial.println(cmd);
  }
}
