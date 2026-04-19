// Minimal bolt11 (BOLT11) lightning invoice decoder for embedded use.
// Parses lnbc/lntb invoices to extract amount, description, payment hash,
// and timestamp. No checksum verification (embedded-friendly).
//
// Format reference: BOLT11 spec
//   https://github.com/lightning/bolts/blob/master/11-payment-encoding.md
//
// Invoice structure:
//   human-readable: ln<net><amount><multiplier>1<bech32-data>
//   bech32-data (5-bit values):
//     - timestamp: 35 bits (7 values)
//     - tagged fields: <type(5bit)><length(10bit)><data(length*5bit)>
//     - signature: 104 values + 1 recovery flag

#ifndef BOLT11_DECODE_H
#define BOLT11_DECODE_H

#include <stdint.h>
#include <string.h>
#include <Arduino.h>

struct Bolt11Info {
  bool valid;
  uint64_t amount_sat;
  bool has_amount;
  uint32_t timestamp;
  char description[129];
  uint8_t payment_hash[32];
  bool has_payment_hash;
  uint32_t expiry;
};

static const char BECH32_CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

static inline int8_t bech32_char_to_value(char c) {
  if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
  for (int8_t i = 0; i < 32; i++) {
    if (BECH32_CHARSET[i] == c) return i;
  }
  return -1;
}

// BOLT11 amount: decimal + optional multiplier in BTC units.
// m=milli-BTC (0.001 BTC), u=micro-BTC, n=nano-BTC, p=pico-BTC.
// 1 BTC = 100,000,000 sat. No multiplier = satoshis directly.
static inline uint64_t bolt11_parse_amount(const char* s, uint8_t len) {
  if (len == 0) return 0;

  uint64_t raw = 0;
  uint8_t i = 0;
  while (i < len && s[i] >= '0' && s[i] <= '9') {
    raw = raw * 10 + (s[i] - '0');
    i++;
  }

  if (i < len) {
    char mult = s[i] | 0x20;
    // Convert from BTC-denominated units to satoshis (1 BTC = 100000000 sat)
    switch (mult) {
      case 'm': raw = raw * 100000000ULL / 1000; break;   // milli-BTC → sat
      case 'u': raw = raw * 100000000ULL / 1000000; break; // micro-BTC → sat
      case 'n': raw = raw * 100000000ULL / 1000000000ULL; break; // nano-BTC → sat
      case 'p': raw = raw / 10000; break; // pico-BTC → sat (raw * 1e-12 * 1e8 = raw * 1e-4)
    }
  }

  return raw;
}

// Convert 5-bit values to 8-bit bytes.
static inline uint16_t convert_5to8(const uint8_t* five_bit, uint16_t five_len,
                                     uint8_t* eight_bit, uint16_t eight_max) {
  uint64_t acc = 0;
  uint8_t bits = 0;
  uint16_t out_pos = 0;

  for (uint16_t i = 0; i < five_len; i++) {
    acc = (acc << 5) | five_bit[i];
    bits += 5;
    while (bits >= 8) {
      if (out_pos >= eight_max) return out_pos;
      bits -= 8;
      eight_bit[out_pos++] = (acc >> bits) & 0xFF;
    }
  }

  return out_pos;
}

// Parse tagged fields from the 5-bit data stream.
// Type codes map to BECH32_CHARSET index: p=1, d=13, x=6, h=23, n=19, s=16, etc.
static inline void bolt11_parse_fields_5bit(const uint8_t* five_bit, uint16_t five_len,
                                             Bolt11Info* info) {
  // Timestamp: first 7 values (35 bits)
  if (five_len < 7) return;
  uint32_t ts = 0;
  for (int i = 0; i < 7; i++) {
    ts = (ts << 5) | five_bit[i];
  }
  info->timestamp = ts;

  uint16_t pos = 7;
  while (pos + 3 <= five_len) {
    uint8_t type = five_bit[pos];
    // Length is 10 bits: next two 5-bit values
    uint16_t field_len = ((uint16_t)five_bit[pos + 1] << 5) | five_bit[pos + 2];
    pos += 3;

    if (pos + field_len > five_len) break;

    // Signature is 104 values + 1 recovery flag = 105 values at the end
    // Don't try to parse past it
    if (pos + field_len + 105 > five_len && type != 1 && type != 13 && type != 6 && type != 23) {
      // Likely hit signature territory
      pos += field_len;
      continue;
    }

    switch (type) {
      case 1: { // 'p' = payment_hash (52 five-bit values → 32 bytes + padding)
        if (field_len >= 52) {
          uint8_t hash_bytes[33];
          convert_5to8(five_bit + pos, 52, hash_bytes, 33);
          memcpy(info->payment_hash, hash_bytes, 32);
          info->has_payment_hash = true;
        }
        break;
      }
      case 13: { // 'd' = description
        uint8_t desc_bytes[256];
        uint16_t desc_len = convert_5to8(five_bit + pos, field_len, desc_bytes, sizeof(desc_bytes));
        uint16_t copy_len = desc_len;
        if (copy_len > sizeof(info->description) - 1) copy_len = sizeof(info->description) - 1;
        memcpy(info->description, desc_bytes, copy_len);
        info->description[copy_len] = '\0';
        break;
      }
      case 6: { // 'x' = expiry
        uint8_t exp_bytes[4];
        uint16_t exp_len = convert_5to8(five_bit + pos, field_len, exp_bytes, sizeof(exp_bytes));
        uint32_t expiry = 0;
        for (uint16_t i = 0; i < exp_len && i < 4; i++) {
          expiry = (expiry << 8) | exp_bytes[i];
        }
        info->expiry = expiry;
        break;
      }
      case 23:   // 'h' = description_hash
      case 19:   // 'n' = payee node key
      case 16:   // 's' = payment secret
      case 24:   // 'c' = min final CLTV
      case 9:    // 'f' = fallback address
      case 3:    // 'r' = route hints
      case 5:    // '9' = feature bits
      case 27:   // 'm' = metadata
        break;
    }

    pos += field_len;
  }
}

static inline Bolt11Info bolt11_decode(const char* invoice) {
  Bolt11Info info = {};
  info.expiry = 3600;

  if (!invoice) return info;

  const char* p = invoice;
  if (strncmp(p, "lightning:", 10) == 0) p += 10;

  if (p[0] != 'l' || p[1] != 'n') return info;
  p += 2;

  // Skip network identifier (alpha only: bc, tb, bcrt)
  while (*p && ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z'))) p++;

  // Amount: decimal digits + optional multiplier char (m/u/n/p)
  const char* amount_start = p;
  while (*p && *p >= '0' && *p <= '9') p++;
  if (*p) {
    char lower = *p | 0x20;
    if (lower == 'm' || lower == 'u' || lower == 'n' || lower == 'p') p++;
  }

  // Separator must be '1'
  if (*p != '1' || !p[1]) return info;
  const char* separator = p;

  uint8_t amount_len = p - amount_start;
  if (amount_len > 0) {
    info.amount_sat = bolt11_parse_amount(amount_start, amount_len);
    info.has_amount = true;
  }

  // Decode bech32 data part (after separator, minus 6 checksum chars)
  const char* data_start = separator + 1;
  uint16_t data_len = strlen(data_start);
  if (data_len < 112) return info;
  data_len -= 6;

  uint8_t five_bit[512];
  if (data_len > sizeof(five_bit)) return info;

  for (uint16_t i = 0; i < data_len; i++) {
    int8_t val = bech32_char_to_value(data_start[i]);
    if (val < 0) return info;
    five_bit[i] = val;
  }

  // Parse fields directly from 5-bit stream
  bolt11_parse_fields_5bit(five_bit, data_len, &info);

  info.valid = true;
  return info;
}

static inline void bolt11_print(const Bolt11Info* info) {
  if (!info->valid) {
    Serial.println(F("[bolt11] INVALID invoice"));
    return;
  }
  Serial.print(F("[bolt11] Amount: "));
  if (info->has_amount) {
    Serial.print(info->amount_sat);
    Serial.println(F(" sat"));
  } else {
    Serial.println(F("(any amount)"));
  }
  Serial.print(F("[bolt11] Timestamp: "));
  Serial.println(info->timestamp);
  if (info->description[0]) {
    Serial.print(F("[bolt11] Description: "));
    Serial.println(info->description);
  }
  if (info->has_payment_hash) {
    Serial.print(F("[bolt11] Payment hash: "));
    for (int i = 0; i < 32; i++) {
      if (info->payment_hash[i] < 0x10) Serial.print('0');
      Serial.print(info->payment_hash[i], HEX);
    }
    Serial.println();
  }
  Serial.print(F("[bolt11] Expiry: "));
  Serial.print(info->expiry);
  Serial.println(F(" seconds"));
}

#endif // BOLT11_DECODE_H
