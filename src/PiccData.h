// PICC data parsing for NTAG424 DNA bolt cards.
// Decrypts p= parameter (SDM encrypted PICC data) and verifies c= (SDM MAC).
//
// Algorithm reference:
//   - NXP NTAG 424 DNA AN12196 §4.7 "SDM for Metro"
//   - BTCPayServer.NTag424/PICCData.cs + AESKey.cs
//   - BTCPayServer.NTag424/Ntag424.cs (SesSDMFileReadMACKey)
//
// p= decryption:
//   AES-128-CBC decrypt first 16 hex chars of p= using K1 (encryption key), zero IV.
//   Decrypted[0] must be 0xC7 for boltcard PICC data format.
//   Bit 7 of byte 0 = UID present (7 bytes at offset 1).
//   Bit 6 of byte 0 = counter present (3 bytes LE after UID).
//
// c= verification:
//   1. Build SV2 = {0x3C, 0xC3, 0x00, 0x01, 0x00, 0x80, UID[0..6], Counter[0..2]}
//      padded to 16 bytes with zeros.
//   2. Derive key = AES-CMAC(K2, SV2).
//   3. Compute MAC = AES-CMAC(derived_key, empty_data) truncated to odd bytes (8 bytes).
//   4. Compare MAC with c= parameter.

#ifndef PICC_DATA_H
#define PICC_DATA_H

#include <stdint.h>
#include <string.h>
#include "debug.h"
#include "ntag424_crypto.h"

// --- PICC Data Format Constants ---
// Ref: AN12196 §4.7 "SDM for Metro", NT4H2421Gx datasheet §8.7.2
//
// Decrypted p= byte 0 (PICC data format byte):
//   Bit 7 (0x80): UID present (7 bytes following)
//   Bit 6 (0x40): Read counter present (3 bytes LE)
//   Bits 2-0:      UID length / type indicator (0x07 = 7-byte UID)
//   Standard boltcard format: 0xC7 = CMAC(1) + UID(1) + Counter(1) + UID_len(7)
static const uint8_t PICC_FORMAT_BOLTCARD = 0xC7;
static const uint8_t PICC_FLAG_HAS_UID = 0x80;
static const uint8_t PICC_FLAG_HAS_COUNTER = 0x40;
static const uint8_t PICC_UID_LEN_MASK = 0x07;
static const uint8_t PICC_UID_BYTE_LEN = 7;    // NTAG424 DNA UID is always 7 bytes
static const uint8_t PICC_COUNTER_LEN = 3;     // Read counter is 24-bit LE

// --- SV2 Derivation Vector ---
// Ref: AN12196 §4.7, NT4H2421Gx datasheet §8.7.2
// SV2 is the "SesSDMFileReadMACKey" derivation input:
//   Bytes 0-1: 0x3C, 0xC3 (SDM MAC derivation constant)
//   Byte 2:    0x00 (RFU)
//   Byte 3:    0x01 (SDM variant)
//   Byte 4:    0x00 (RFU)
//   Byte 5:    0x80 (CMAC output length indicator)
//   Bytes 6-12:  UID[0..6]
//   Bytes 13-15: ReadCounter[0..2] (LE)
static const uint8_t SV2_HEADER[] = {0x3C, 0xC3, 0x00, 0x01, 0x00, 0x80};
static const uint8_t SV2_UID_OFFSET = 6;
static const uint8_t SV2_COUNTER_OFFSET = 13;

// Build SV2 derivation vector for SDM MAC verification.
// Ref: AN12196 §4.7, BTCPayServer.NTag424/Ntag424.cs (SesSDMFileReadMACKey)
static inline void sdm_build_sv2(const uint8_t uid[7], uint32_t counter, uint8_t sv2_out[16]) {
  memset(sv2_out, 0, 16);
  memcpy(sv2_out, SV2_HEADER, sizeof(SV2_HEADER));
  memcpy(sv2_out + SV2_UID_OFFSET, uid, PICC_UID_BYTE_LEN);
  sv2_out[SV2_COUNTER_OFFSET] = (uint8_t)(counter & 0xFF);
  sv2_out[SV2_COUNTER_OFFSET + 1] = (uint8_t)((counter >> 8) & 0xFF);
  sv2_out[SV2_COUNTER_OFFSET + 2] = (uint8_t)((counter >> 16) & 0xFF);
}

struct PiccData {
  bool valid;
  uint8_t uid[7];
  uint32_t counter;
  bool has_uid;
  bool has_counter;
};

static inline uint8_t picc_hex_nibble(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return 0xFF;
}

static inline uint8_t picc_hex_to_bytes(const char* hex, uint8_t* out, uint8_t max_bytes) {
  for (uint8_t i = 0; i < max_bytes; i++) {
    uint8_t hi = picc_hex_nibble(hex[i * 2]);
    uint8_t lo = picc_hex_nibble(hex[i * 2 + 1]);
    if (hi == 0xFF || lo == 0xFF) return 0;
    out[i] = (hi << 4) | lo;
  }
  return max_bytes;
}

static inline bool picc_is_hex(const char* s, uint8_t expected_len) {
  if (!s) return false;
  for (uint8_t i = 0; i < expected_len; i++) {
    if (picc_hex_nibble(s[i]) == 0xFF) return false;
  }
  return true;
}

static inline bool extract_p_and_c(const char* url, char* p_out, char* c_out) {
  if (!url) return false;

  const char* p_start = nullptr;
  const char* c_start = nullptr;

  const char* s = url;
  while (*s) {
    if (s[0] == 'p' && s[1] == '=') {
      p_start = s + 2;
    } else if (s[0] == 'c' && s[1] == '=') {
      c_start = s + 2;
    }
    s++;
  }

  if (!p_start || !c_start) return false;
  if (!picc_is_hex(p_start, 32) || !picc_is_hex(c_start, 16)) return false;

  memcpy(p_out, p_start, 32);
  memcpy(c_out, c_start, 16);
  p_out[32] = '\0';
  c_out[16] = '\0';
  return true;
}

static inline bool picc_decrypt_p(const uint8_t k1[16], const char* p_hex, PiccData* out) {
  if (!picc_is_hex(p_hex, 32)) return false;

  uint8_t ciphertext[16];
  if (picc_hex_to_bytes(p_hex, ciphertext, 16) != 16) return false;

  uint8_t decrypted[16];
  if (!ntag424_decrypt((uint8_t*)k1, 16, ciphertext, decrypted)) return false;

  if (decrypted[0] != PICC_FORMAT_BOLTCARD) return false;

  memset(out, 0, sizeof(PiccData));

  uint8_t offset = 1;
  bool has_uid = (decrypted[0] & PICC_FLAG_HAS_UID) != 0;
  bool has_counter = (decrypted[0] & PICC_FLAG_HAS_COUNTER) != 0;

  if (has_uid) {
    if ((decrypted[0] & PICC_UID_LEN_MASK) != PICC_UID_BYTE_LEN) return false;
    memcpy(out->uid, decrypted + offset, PICC_UID_BYTE_LEN);
    out->has_uid = true;
    offset += PICC_UID_BYTE_LEN;
  }

  if (has_counter) {
    out->counter = (uint32_t)decrypted[offset]
                 | ((uint32_t)decrypted[offset + 1] << 8)
                 | ((uint32_t)decrypted[offset + 2] << 16);
    out->has_counter = true;
  }

  return has_uid;
}

static inline bool picc_verify_c(const uint8_t k2[16], const PiccData* picc, const char* c_hex) {
  if (!picc->has_uid || !picc->has_counter) return false;
  if (!picc_is_hex(c_hex, 16)) return false;

  // SesSDMFileReadMACKey: SV2 derivation vector
  uint8_t sv2[16];
  sdm_build_sv2(picc->uid, picc->counter, sv2);

  uint8_t derived_key[16];
  ntag424_cmac((uint8_t*)k2, sv2, 16, derived_key);

  // CMAC of empty payload, truncated to odd bytes (8 bytes)
  uint8_t computed_mac[8];
  uint8_t dummy_empty = 0;
  ntag424_cmac_short(derived_key, &dummy_empty, 0, computed_mac);

  uint8_t expected_mac[8];
  if (picc_hex_to_bytes(c_hex, expected_mac, 8) != 8) return false;

  return crypto_memcmp(computed_mac, expected_mac, 8);
}

static inline PiccData picc_decrypt_and_verify(const uint8_t k1[16], const uint8_t k2[16],
                                                const char* p_hex, const char* c_hex) {
  PiccData result = {};
  if (!picc_decrypt_p(k1, p_hex, &result)) return result;
  if (!picc_verify_c(k2, &result, c_hex)) return result;
  result.valid = true;
  return result;
}

static inline PiccData picc_parse_url(const uint8_t k1[16], const uint8_t k2[16],
                                       const char* url) {
  char p_hex[33];
  char c_hex[17];
  if (!extract_p_and_c(url, p_hex, c_hex)) {
    PiccData empty = {};
    return empty;
  }
  return picc_decrypt_and_verify(k1, k2, p_hex, c_hex);
}

static inline void picc_print(const PiccData* picc) {
  if (!picc->valid) {
    DBG_PRINTLN(F("[picc] INVALID"));
    return;
  }
  DBG_PRINT(F("[picc] UID: "));
  for (int i = 0; i < PICC_UID_BYTE_LEN; i++) {
    if (picc->uid[i] < 0x10) DBG_PRINT('0');
    DBG_PRINT(picc->uid[i], HEX);
    if (i < PICC_UID_BYTE_LEN - 1) DBG_PRINT(':');
  }
  DBG_PRINT(F("  Counter: "));
  DBG_PRINTLN(picc->counter);
}

#endif // PICC_DATA_H
