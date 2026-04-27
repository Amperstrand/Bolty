#ifndef BOLTY_UTILS_H
#define BOLTY_UTILS_H

#include <Arduino.h>
#include "debug.h"

#include "bolt.h"

inline const char *ntag424_error_name(uint8_t sw1, uint8_t sw2) {
  if (sw1 == 0x91) {
    switch (sw2) {
    case 0x00:
      return "OK";
    case 0xAE:
      return "AUTHENTICATION_ERROR";
    case 0xBE:
      return "BOUNDARY_ERROR";
    case 0xEE:
      return "MEMORY_ERROR";
    case 0x1E:
      return "INTEGRITY_ERROR";
    case 0x7E:
      return "LENGTH_ERROR";
    case 0x9D:
      return "PERMISSION_DENIED";
    case 0xCA:
      return "COMMAND_ABORTED";
    case 0x9E:
      return "PARAMETER_ERROR";
    case 0x40:
      return "NO_SUCH_KEY";
    case 0xAD:
      return "AUTHENTICATION_DELAY";
    case 0xF0:
      return "FILE_NOT_FOUND";
    default:
      return "UNKNOWN_ERROR";
    }
  }
  if (sw1 == 0x69) {
    switch (sw2) {
    case 0x82:
      return "SECURITY_STATUS_NOT_SATISFIED";
    case 0x85:
      return "CONDITIONS_NOT_SATISFIED";
    case 0x88:
      return "REF_DATA_INVALID";
    default:
      return "UNKNOWN_ERROR";
    }
  }
  if (sw1 == 0x6A && sw2 == 0x82) {
    return "FILE_NOT_FOUND";
  }
  if (sw1 == 0x6A && sw2 == 0x86) {
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
    if (ndef[i] == 0xD1 && ndef[i + 1] == 0x01 && ndef[i + 3] == 0x55) {
      const int payload_len = ndef[i + 2];
      if (payload_len < 1 || i + 4 + payload_len > len) {
        return false;
      }

      const uint8_t prefix = ndef[i + 4];
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

#endif
