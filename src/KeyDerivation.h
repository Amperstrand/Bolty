// Deterministic key derivation for NTAG424 DNA bolt cards.
// Implements the boltcard DETERMINISTIC.md spec:
//   https://github.com/boltcard/boltcard/blob/main/docs/DETERMINISTIC.md
//
// Derivation chain:
//   IssuerKey (16 bytes) → CardKey → K0,K1,K2,K3,K4 + CardID
//   PRF = AES-128-CMAC (NIST SP 800-38B)
//
// Key derivation constants (from spec):
//   CardKey = CMAC(IssuerKey, 0x2d003f75 || UID[7] || Version_LE[4])
//   K0      = CMAC(CardKey,  0x2d003f76)
//   K1      = CMAC(IssuerKey, 0x2d003f77)  ← derived from ISSUER key, not card key
//   K2      = CMAC(CardKey,  0x2d003f78)
//   K3      = CMAC(CardKey,  0x2d003f79)
//   K4      = CMAC(CardKey,  0x2d003f7a)
//   CardID  = CMAC(IssuerKey, 0x2d003f7b || UID[7])

#ifndef KEY_DERIVATION_H
#define KEY_DERIVATION_H

#include <stdint.h>
#include <string.h>

#if __has_include("aescmac.h")
#include "aescmac.h"
#elif __has_include("Arduino.h")
#include "Arduino.h"
#endif

#include "bolty_utils.h"

static const uint8_t KEYDET_TAG_CARDKEY[4] = {0x2D, 0x00, 0x3F, 0x75};
static const uint8_t KEYDET_TAG_K0[4]      = {0x2D, 0x00, 0x3F, 0x76};
static const uint8_t KEYDET_TAG_K1[4]      = {0x2D, 0x00, 0x3F, 0x77};
static const uint8_t KEYDET_TAG_K2[4]      = {0x2D, 0x00, 0x3F, 0x78};
static const uint8_t KEYDET_TAG_K3[4]      = {0x2D, 0x00, 0x3F, 0x79};
static const uint8_t KEYDET_TAG_K4[4]      = {0x2D, 0x00, 0x3F, 0x7A};
static const uint8_t KEYDET_TAG_CARDID[4]  = {0x2D, 0x00, 0x3F, 0x7B};

static inline void keyderivation_card_key(const uint8_t issuer_key[16],
                                          const uint8_t uid[7],
                                          uint32_t version,
                                          uint8_t out_card_key[16]) {
  uint8_t msg[4 + 7 + 4] = {};
  memcpy(msg, KEYDET_TAG_CARDKEY, 4);
  memcpy(msg + 4, uid, 7);
  write_u32_le(version, msg + 11);
  AES128_CMAC(issuer_key, msg, sizeof(msg), out_card_key);
}

static inline void keyderivation_boltcard_keys(const uint8_t issuer_key[16],
                                               const uint8_t uid[7],
                                               uint32_t version,
                                               uint8_t out_keys[5][16]) {
  uint8_t card_key[16] = {};
  keyderivation_card_key(issuer_key, uid, version, card_key);

  AES128_CMAC(card_key,    KEYDET_TAG_K0, 4, out_keys[0]);
  AES128_CMAC(issuer_key,  KEYDET_TAG_K1, 4, out_keys[1]);
  AES128_CMAC(card_key,    KEYDET_TAG_K2, 4, out_keys[2]);
  AES128_CMAC(card_key,    KEYDET_TAG_K3, 4, out_keys[3]);
  AES128_CMAC(card_key,    KEYDET_TAG_K4, 4, out_keys[4]);
}

static inline void keyderivation_card_id(const uint8_t issuer_key[16],
                                         const uint8_t uid[7],
                                         uint8_t out_id[16]) {
  uint8_t msg[4 + 7] = {};
  memcpy(msg, KEYDET_TAG_CARDID, 4);
  memcpy(msg + 4, uid, 7);
  AES128_CMAC(issuer_key, msg, sizeof(msg), out_id);
}

#endif // KEY_DERIVATION_H
