#ifndef BOLTY_UTILS_H
#define BOLTY_UTILS_H

#include <Arduino.h>
#include "debug.h"

#include "bolt.h"

// --- NTAG424 APDU Status Codes ---
// Ref: NT4H2421Gx datasheet §9, Table 94-95 (Status and Error Codes)
static const uint8_t SW1_NTAG_SUCCESS = 0x91;
static const uint8_t SW1_ISO_69 = 0x69;

static const uint8_t SW2_OK = 0x00;
static const uint8_t SW2_AUTH_ERROR = 0xAE;
static const uint8_t SW2_BOUNDARY_ERROR = 0xBE;
static const uint8_t SW2_MEMORY_ERROR = 0xEE;
static const uint8_t SW2_INTEGRITY_ERROR = 0x1E;
static const uint8_t SW2_LENGTH_ERROR = 0x7E;
static const uint8_t SW2_PERMISSION_DENIED = 0x9D;
static const uint8_t SW2_COMMAND_ABORTED = 0xCA;
static const uint8_t SW2_PARAMETER_ERROR = 0x9E;
static const uint8_t SW2_NO_SUCH_KEY = 0x40;
static const uint8_t SW2_AUTH_DELAY = 0xAD;
static const uint8_t SW2_FILE_NOT_FOUND = 0xF0;

static const uint8_t SW2_82_SECURITY_STATUS = 0x82;
static const uint8_t SW2_85_CONDITIONS = 0x85;
static const uint8_t SW2_88_REF_DATA_INVALID = 0x88;

static const uint8_t SW1_6A_WRONG_PARAMS = 0x6A;
static const uint8_t SW2_82_FILE_NOT_FOUND_ISO = 0x82;
static const uint8_t SW2_86_INCORRECT_P1P2 = 0x86;

// Constant-time comparison for secrets (MAC, UID, tokens).
// Always compares all bytes regardless of mismatches to prevent timing attacks.
inline bool crypto_memcmp(const void *a, const void *b, size_t len) {
  const uint8_t *pa = (const uint8_t *)a;
  const uint8_t *pb = (const uint8_t *)b;
  uint8_t diff = 0;
  for (size_t i = 0; i < len; i++) {
    diff |= pa[i] ^ pb[i];
  }
  return diff == 0;
}

// Always-null-terminating string copy. Use instead of strncpy/strcpy.
inline void safe_strcpy(char *dst, const char *src, size_t dst_size) {
  if (dst_size == 0) return;
  strncpy(dst, src, dst_size - 1);
  dst[dst_size - 1] = '\0';
}

// Secure memory zeroing — compiler cannot optimize this away.
// Use for key material, decrypted data, and other secrets on the stack.
inline void secure_memzero(void *ptr, size_t len) {
  if (ptr == nullptr) return;
  volatile uint8_t *p = (volatile uint8_t *)ptr;
  while (len--) *p++ = 0;
}

inline const char *ntag424_error_name(uint8_t sw1, uint8_t sw2) {
  if (sw1 == SW1_NTAG_SUCCESS) {
    switch (sw2) {
    case SW2_OK:
      return "OK";
    case SW2_AUTH_ERROR:
      return "AUTHENTICATION_ERROR";
    case SW2_BOUNDARY_ERROR:
      return "BOUNDARY_ERROR";
    case SW2_MEMORY_ERROR:
      return "MEMORY_ERROR";
    case SW2_INTEGRITY_ERROR:
      return "INTEGRITY_ERROR";
    case SW2_LENGTH_ERROR:
      return "LENGTH_ERROR";
    case SW2_PERMISSION_DENIED:
      return "PERMISSION_DENIED";
    case SW2_COMMAND_ABORTED:
      return "COMMAND_ABORTED";
    case SW2_PARAMETER_ERROR:
      return "PARAMETER_ERROR";
    case SW2_NO_SUCH_KEY:
      return "NO_SUCH_KEY";
    case SW2_AUTH_DELAY:
      return "AUTHENTICATION_DELAY";
    case SW2_FILE_NOT_FOUND:
      return "FILE_NOT_FOUND";
    default:
      return "UNKNOWN_ERROR";
    }
  }
  if (sw1 == SW1_ISO_69) {
    switch (sw2) {
    case SW2_82_SECURITY_STATUS:
      return "SECURITY_STATUS_NOT_SATISFIED";
    case SW2_85_CONDITIONS:
      return "CONDITIONS_NOT_SATISFIED";
    case SW2_88_REF_DATA_INVALID:
      return "REF_DATA_INVALID";
    default:
      return "UNKNOWN_ERROR";
    }
  }
  if (sw1 == SW1_6A_WRONG_PARAMS && sw2 == SW2_82_FILE_NOT_FOUND_ISO) {
    return "FILE_NOT_FOUND";
  }
  if (sw1 == SW1_6A_WRONG_PARAMS && sw2 == SW2_86_INCORRECT_P1P2) {
    return "INCORRECT_P1_P2";
  }
  return "UNKNOWN_ERROR";
}

inline void print_hex_byte_prefixed(uint8_t value) {
  if (value < 0x10) {
    DBG_PRINT(F("0"));
  }
  DBG_PRINT(value, HEX);
}

inline uint8_t bcd_to_decimal(uint8_t value) {
  return (uint8_t)(((value >> 4) & 0x0F) * 10 + (value & 0x0F));
}

inline uint32_t decode_u24_le(const uint8_t *buf) {
  return (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) |
         ((uint32_t)buf[2] << 16);
}

inline bool ndef_extract_uri(const uint8_t *ndef, int len, String &uri) {
  if (ndef == nullptr || len < 5) {
    return false;
  }

  for (int i = 0; i <= len - 5; i++) {
    if (ndef[i] == NDEF_HEADER_SHORT && ndef[i + 1] == 0x01 &&
        ndef[i + 3] == NDEF_TYPE_URI) {
      const int payload_len = ndef[i + 2];
      if (payload_len < 1 || i + 4 + payload_len > len) {
        return false;
      }

      const uint8_t prefix = ndef[i + 4];
      // NFC Forum URI Identifier Codes, Ref: NFC Forum NDEF §3.2.2 Table 7
      switch (prefix) {
      case 0x00:
        uri = "";
        break;
      case 0x01:
        uri = "http://www.";
        break;
      case 0x02:
        uri = "https://www.";
        break;
      case 0x03:
        uri = "http://";
        break;
      case 0x04:
        uri = "https://";
        break;
      default:
        uri = "";
        break;
      }

      for (int j = 0; j < payload_len - 1; j++) {
        const uint8_t ch = ndef[i + 5 + j];
        uri += (ch >= 0x20 && ch < 0x7F) ? (char)ch : '.';
      }
      return true;
    }
  }

  return false;
}

inline void print_ndef_ascii(const uint8_t *ndef, int len) {
  for (int i = 0; i < len; i++) {
    Serial.write(ndef[i] >= 0x20 && ndef[i] < 0x7F ? ndef[i] : '.');
  }
  DBG_PRINTLN();
}

inline void print_boltcard_heuristics(const String &uri) {
  DBG_PRINTLN(F("[inspect] --- Boltcard Heuristics ---"));
  if (uri.length() == 0) {
    DBG_PRINTLN(F("[inspect] No URI record found in NDEF."));
    return;
  }

  const bool has_lnurlw =
      uri.startsWith("lnurlw://") || uri.indexOf("lnurlw://") >= 0;
  const bool has_lnurlp =
      uri.startsWith("lnurlp://") || uri.indexOf("lnurlp://") >= 0;
  const bool has_https =
      uri.startsWith("https://") || uri.indexOf("https://") >= 0;
  const int p_idx = uri.indexOf("p=");
  const int c_idx = uri.indexOf("c=");
  const bool has_p = p_idx >= 0;
  const bool has_c = c_idx >= 0;

  DBG_PRINT(F("[inspect] URI has lnurlw scheme: "));
  DBG_PRINTLN(has_lnurlw ? F("YES") : F("NO"));
  DBG_PRINT(F("[inspect] URI has lnurlp scheme: "));
  DBG_PRINTLN(has_lnurlp ? F("YES") : F("NO"));
  DBG_PRINT(F("[inspect] URI has https scheme: "));
  DBG_PRINTLN(has_https ? F("YES") : F("NO"));
  DBG_PRINT(F("[inspect] URI has p= param: "));
  DBG_PRINTLN(has_p ? F("YES") : F("NO"));
  DBG_PRINT(F("[inspect] URI has c= param: "));
  DBG_PRINTLN(has_c ? F("YES") : F("NO"));

  if (has_p) {
    DBG_PRINT(F("[inspect] p= offset in URI: "));
    DBG_PRINTLN(p_idx);
  }
  if (has_c) {
    DBG_PRINT(F("[inspect] c= offset in URI: "));
    DBG_PRINTLN(c_idx);
  }

  const bool looks_boltcard = has_lnurlw || has_lnurlp || (has_p && has_c);
  DBG_PRINT(F("[inspect] Looks like Bolt Card: "));
  DBG_PRINTLN(looks_boltcard ? F("YES") : F("NO / UNKNOWN"));
}

inline bool hex_nibble(char ch, uint8_t &value) {
  if (ch >= '0' && ch <= '9') {
    value = (uint8_t)(ch - '0');
    return true;
  }
  if (ch >= 'a' && ch <= 'f') {
    value = (uint8_t)(ch - 'a' + 10);
    return true;
  }
  if (ch >= 'A' && ch <= 'F') {
    value = (uint8_t)(ch - 'A' + 10);
    return true;
  }
  return false;
}

inline bool parse_hex_fixed(const String &hex, uint8_t *out, size_t out_len) {
  if (hex.length() != (int)(out_len * 2)) {
    return false;
  }
  for (size_t i = 0; i < out_len; i++) {
    uint8_t upper = 0;
    uint8_t lower = 0;
    if (!hex_nibble(hex[(int)(i * 2)], upper) ||
        !hex_nibble(hex[(int)(i * 2 + 1)], lower)) {
      return false;
    }
    out[i] = (uint8_t)((upper << 4) | lower);
  }
  return true;
}

inline bool uri_get_query_param(const String &uri, const char *name,
                                String &value) {
  value = "";
  const int query_idx = uri.indexOf('?');
  if (query_idx < 0) {
    return false;
  }

  const String needle = String(name) + "=";
  const int start = uri.indexOf(needle, query_idx + 1);
  if (start < 0) {
    return false;
  }

  const int value_start = start + needle.length();
  int value_end = uri.indexOf('&', value_start);
  if (value_end < 0) {
    value_end = uri.length();
  }
  value = uri.substring(value_start, value_end);
  return value.length() > 0;
}

inline void print_hex_bytes_inline(const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (data[i] < 0x10) {
      DBG_PRINT(F("0"));
    }
    DBG_PRINT(data[i], HEX);
  }
}

inline void print_hex_bytes_spaced(const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (i > 0) {
      DBG_PRINT(F(" "));
    }
    if (data[i] < 0x10) {
      DBG_PRINT(F("0"));
    }
    DBG_PRINT(data[i], HEX);
  }
}

inline void store_hex_string(char *out, size_t out_size, const uint8_t *data,
                             uint8_t len) {
  if (out == nullptr || out_size == 0 || data == nullptr) {
    return;
  }
  String hex = convertIntToHex(data, len);
  strncpy(out, hex.c_str(), out_size - 1);
  out[out_size - 1] = '\0';
}

inline void store_bolt_config_keys_from_bytes(sBoltConfig &config,
                                              const uint8_t keys[5][16]) {
  store_hex_string(config.k0, sizeof(config.k0), keys[0], 16);
  store_hex_string(config.k1, sizeof(config.k1), keys[1], 16);
  store_hex_string(config.k2, sizeof(config.k2), keys[2], 16);
  store_hex_string(config.k3, sizeof(config.k3), keys[3], 16);
  store_hex_string(config.k4, sizeof(config.k4), keys[4], 16);
}

inline void write_u32_le(uint32_t value, uint8_t out[4]) {
  out[0] = (uint8_t)(value & 0xFF);
  out[1] = (uint8_t)((value >> 8) & 0xFF);
  out[2] = (uint8_t)((value >> 16) & 0xFF);
  out[3] = (uint8_t)((value >> 24) & 0xFF);
}

// Print a single hex byte to Serial with leading-zero prefix.
// Used for user-facing key version and status output (NOT debug output).
// For debug output, use print_hex_byte_prefixed() above instead.
inline void serial_print_hex_byte(uint8_t value) {
  if (value < 0x10) Serial.print(F("0"));
  Serial.print(value, HEX);
}

#endif
