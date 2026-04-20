#ifndef BOLT_H
#define BOLT_H

#include "gui.h"
#include "hardware_config.h"
#include "led.h"

#if BOLTY_NFC_BACKEND_MFRC522
#include <MFRC522_NTAG424.h>
using BoltyNfcReader = MFRC522_NTAG424;
#else
#include <Adafruit_PN532_NTAG424.h>
using BoltyNfcReader = Adafruit_PN532;
#endif

#include <SPI.h>
#include <Wire.h>
#include "debug.h"

#define JOBSTATUS_IDLE 0
#define JOBSTATUS_WAITING 1
#define JOBSTATUS_PROVISIONING 2
#define JOBSTATUS_WIPING 3
#define JOBSTATUS_DONE 4
#define JOBSTATUS_ERROR 5
#define JOBSTATUS_GUARD_REJECT 6

// NTAG424 DNA Application Identifier — AN12196 §3.1, NT4H2421Gx datasheet §6.4
static const uint8_t NTAG424_AID[7] = {0xD2, 0x76, 0x00, 0x00,
                                       0x85, 0x01, 0x01};
// NDEF File ID: 0xE104 — NT4H2421Gx datasheet §8.6.4
static const uint16_t NTAG424_NDEF_FILE_ID = 0xE104;

static String boltstatustext[7] = {
    "idle",          "waiting for nfc-tag..",  "provisioning data..",
    "wiping data..", "done - remove the card", "error",
    "guard rejected - card not in expected state",
};

struct sBoltConfig {
  char card_name[50];
  char wallet_host[50];
  char wallet_name[256];
  char wallet_url[256];
  char url[256];
  char card_mode[16];
  char reset_url[256];
  char uid[17];
  char k0[33];
  char k1[33];
  char k2[33];
  char k3[33];
  char k4[33];
  char wifi_ssid[33];
  char wifi_password[65];
  bool wifi_probe_enabled;
};

inline String convertIntToHex(uint8_t *input, uint8_t len) {
  String ret = "";
  for (uint8_t i = 0; i < len; i++) {
    char hexChar[3];
    sprintf(hexChar, "%02X", input[i]);
    ret += hexChar;
  }
  return ret;
}

inline uint8_t convertCharToHex(char ch) {
  const char upper = toupper(ch);
  if (upper >= '0' && upper <= '9') {
    return upper - '0';
  }
  if (upper >= 'A' && upper <= 'F') {
    return upper - 'A' + 10;
  }
  return 0;
}

inline bool bolty_read_passive_target(BoltyNfcReader *nfc, uint8_t *uid,
                                      uint8_t *uidLength) {
#if BOLTY_NFC_BACKEND_MFRC522
  const bool found = nfc->readPassiveTargetID(uid, uidLength);
#else
  const bool found =
      nfc->readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, uidLength, 100);
#endif
  if (found) {
    led_notify_card_present();
  }
  return found;
}

inline void bolty_print_hex(BoltyNfcReader *nfc, const uint8_t *data,
                            uint8_t length) {
#if BOLTY_NFC_BACKEND_MFRC522
  for (uint8_t i = 0; i < length; ++i) {
    if (data[i] < 0x10) {
      DBG_PRINT(F("0x0"));
    } else {
      DBG_PRINT(F("0x"));
    }
    DBG_PRINT(data[i], HEX);
    if (i + 1 < length) {
      DBG_PRINT(F(" "));
    }
  }
  DBG_PRINTLN();
#else
  nfc->PrintHex(data, length);
#endif
}

// ISO SELECT before GetKeyVersion is needed when NOT authenticated (the card
// may not have the NTAG424 app selected). But during authenticated sessions,
// ISO SELECT (CLA=0x00) desyncs cmd_counter — the card doesn't count ISO
// commands but our process_response() does. Solution: only ISO SELECT when
// the session is not yet authenticated. See issue #8.
inline uint8_t bolty_get_key_version(BoltyNfcReader *nfc, uint8_t keyno) {
  if (!nfc->ntag424_Session.authenticated) {
    if (!nfc->ntag424_ISOSelectFileByDFN((uint8_t *)NTAG424_AID)) {
      return 0xFF;
    }
  }
  uint8_t version = 0xFF;
  if (nfc->ntag424_GetKeyVersion(keyno, &version)) {
    return version;
  }
  return 0xFF;
}

inline bool bolty_iso_authenticate(BoltyNfcReader *nfc, uint8_t *key,
                                   uint8_t keyno) {
  return nfc->ntag424_ISOAuthenticate(key, keyno) == 1;
}

inline bool bolty_iso_write_ndef_file(BoltyNfcReader *nfc, uint8_t *data,
                                      size_t length) {
  if (data == nullptr || length == 0 || length > 0xFF) {
    return false;
  }
  return nfc->ntag424_ISOUpdateBinary(data, static_cast<uint8_t>(length));
}

// Pre-wipe key verification result.
struct KeyVerifyResult {
  uint8_t key_versions[5]; // 0xFF=read fail, 0x00=factory, 0x01+=provisioned
  bool verified[5];        // true = key ownership proven
  bool all_verified;       // all 5 keys verified
  bool all_factory;        // all 5 keys at version 0x00
};

struct BoltcardKeys {
  uint8_t keys[5][16] = {{0}};

  enum Slot : uint8_t {
    MasterKey     = 0,
    EncryptionKey = 1,
    AuthenticationKey = 2,
    MacReadKey    = 3,
    MacWriteKey   = 4
  };

  static BoltcardKeys allZeros() {
    BoltcardKeys k;
    memset(k.keys, 0, sizeof(k.keys));
    return k;
  }

  static BoltcardKeys fromHexStrings(const char* k0, const char* k1,
                                      const char* k2, const char* k3,
                                      const char* k4) {
    BoltcardKeys k;
    k.setSlotFromHex(MasterKey, k0);
    k.setSlotFromHex(EncryptionKey, k1);
    k.setSlotFromHex(AuthenticationKey, k2);

    // LNbits fallback: k3→k1 if empty/all-zeros, k4→k2 if empty/all-zeros
    if (k3 == nullptr || strlen(k3) == 0 || isAllZerosHex(k3)) {
      k.setSlotFromHex(MacReadKey, k1);
    } else {
      k.setSlotFromHex(MacReadKey, k3);
    }
    if (k4 == nullptr || strlen(k4) == 0 || isAllZerosHex(k4)) {
      k.setSlotFromHex(MacWriteKey, k2);
    } else {
      k.setSlotFromHex(MacWriteKey, k4);
    }
    return k;
  }

  bool isSlotFactoryDefault(uint8_t slot) const {
    for (int i = 0; i < 16; i++) {
      if (keys[slot][i] != 0) return false;
    }
    return true;
  }

  bool allSlotsFactoryDefault() const {
    for (int s = 0; s < 5; s++) {
      if (!isSlotFactoryDefault(s)) return false;
    }
    return true;
  }

  void copySlotTo(uint8_t slot, uint8_t dest[16]) const {
    memcpy(dest, keys[slot], 16);
  }

  void copyAllTo(uint8_t dest[5][16]) const {
    memcpy(dest, keys, sizeof(keys));
  }

private:
  void setSlotFromHex(uint8_t slot, const char* hex) {
    if (hex == nullptr) return;
    size_t len = strlen(hex);
    for (size_t i = 0; i + 1 < len && (i / 2) < 16; i += 2) {
      uint8_t upper = convertCharToHex(hex[i]);
      uint8_t lower = (i + 1 < len) ? convertCharToHex(hex[i + 1]) : 0;
      keys[slot][i / 2] = (upper << 4) | lower;
    }
  }

  static bool isAllZerosHex(const char* hex) {
    if (hex == nullptr) return true;
    for (size_t i = 0; i < strlen(hex); i++) {
      if (hex[i] != '0') return false;
    }
    return true;
  }

  static uint8_t convertCharToHex(char ch) {
    const char upper = toupper(ch);
    if (upper >= '0' && upper <= '9') return upper - '0';
    if (upper >= 'A' && upper <= 'F') return upper - 'A' + 10;
    return 0;
  }
};

class BoltDevice {
public:
  BoltyNfcReader *nfc = nullptr;
  BoltcardKeys cur_keys = BoltcardKeys::allZeros();
  BoltcardKeys new_keys = BoltcardKeys::allZeros();

  uint8_t job_status = JOBSTATUS_IDLE;
  uint8_t job_perc = 0;
  uint8_t job_ok = 0;
  uint8_t _consecutive_scan_failures = 0;
  static const uint8_t MAX_SCAN_FAILURES = 5;
  static const unsigned long REINIT_BACKOFF_MS = 30000;
  unsigned long _last_reader_reinit_ms = 0;
  String last_scanned_uid;
  long lastscan = 0;

#if BOLTY_NFC_BACKEND_MFRC522
  BoltDevice(uint8_t i2cAddress, TwoWire *wire = &Wire) {
    nfc = new MFRC522_NTAG424(i2cAddress, wire);
  }
#elif BOLTY_NFC_BACKEND_PN532_UART
  BoltDevice(uint8_t reset, HardwareSerial *ser) {
    nfc = new Adafruit_PN532(reset, ser);
  }
#else
  BoltDevice(uint8_t SCK, uint8_t MISO, uint8_t MOSI, uint8_t SS) {
    nfc = new Adafruit_PN532(SCK, MISO, MOSI, SS);
  }
#endif

  void loadKeysForBurn(const sBoltConfig &config) {
    cur_keys = BoltcardKeys::allZeros();
    new_keys = BoltcardKeys::fromHexStrings(config.k0, config.k1, config.k2, config.k3, config.k4);
  }

  void loadKeysForWipe(const sBoltConfig &config) {
    cur_keys = BoltcardKeys::fromHexStrings(config.k0, config.k1, config.k2, config.k3, config.k4);
    new_keys = BoltcardKeys::allZeros();
  }

  void setCurKeysFromHex(const char* k0, const char* k1, const char* k2, const char* k3, const char* k4) {
    cur_keys = BoltcardKeys::fromHexStrings(k0, k1, k2, k3, k4);
  }

  bool selectNtagApplicationFiles() {
    return nfc->ntag424_ISOSelectFileByDFN((uint8_t *)NTAG424_AID) &&
           nfc->ntag424_ISOSelectCCFile() &&
           nfc->ntag424_ISOSelectFileById(NTAG424_NDEF_FILE_ID);
  }

  bool selectNdefFileOnly() { return nfc->ntag424_ISOSelectNDEFFile(); }

  // Change all 5 application keys in reverse order (4→0) so the auth key
  // (K0) is changed last. Continues through individual failures to avoid
  // leaving the card in a partial-wipe state.
  // Ref: NT4H2421Gx datasheet §7.3.2, AN12196 §6.3
  // Abort changeAllKeys immediately on first failure.
  // Since keys are changed 4→0, if K3 fails, K0 is still original —
  // recovery is possible with old K0. Continuing would leave mixed state.
  bool changeAllKeys(uint8_t target_key_version) {
    DBG_PRINT(F("[changeAllKeys] Changing keys 4→3→2→1→0, target version=0x"));
    if (target_key_version < 0x10) DBG_PRINT('0');
    DBG_PRINTLN(target_key_version, HEX);
    for (int i = 0; i < 5; i++) {
      const uint8_t key_index = 4 - i;
      DBG_PRINT(F("[changeAllKeys] Key "));
      DBG_PRINT(key_index);
      DBG_PRINT(F(": cur="));
      for (int b = 0; b < 16; b++) { if (cur_keys.keys[key_index][b] < 0x10) DBG_PRINT('0'); DBG_PRINT(cur_keys.keys[key_index][b], HEX); }
      DBG_PRINT(F(" new="));
      for (int b = 0; b < 16; b++) { if (new_keys.keys[key_index][b] < 0x10) DBG_PRINT('0'); DBG_PRINT(new_keys.keys[key_index][b], HEX); }
      DBG_PRINTLN();
      if (!nfc->ntag424_ChangeKey(cur_keys.keys[key_index], new_keys.keys[key_index],
                                  key_index, target_key_version)) {
        DBG_PRINT(F("[changeAllKeys] ABORT: FAILED on key "));
        DBG_PRINT(key_index);
        DBG_PRINTLN(F(" — stopping immediately to avoid inconsistent card state"));
        // Report which keys succeeded before failure (all keys > key_index are done)
        if (i > 0) {
          DBG_PRINT(F("[changeAllKeys] Keys already changed successfully: "));
          for (int j = 0; j < i; j++) {
            DBG_PRINT(F("K"));
            DBG_PRINT(4 - j);
            if (j < i - 1) DBG_PRINT(F(", "));
          }
          DBG_PRINTLN();
        }
        return false;
      }
      DBG_PRINT(F("[changeAllKeys] Key "));
      DBG_PRINT(key_index);
      DBG_PRINTLN(F(" -> OK"));
    }
    DBG_PRINTLN(F("[changeAllKeys] All 5 keys changed successfully"));
    return true;
  }

  void setKey(uint8_t keys[16], String key) {
    for (int i = 0; i < key.length(); i += 2) {
      uint8_t ki = (i / 2);
      uint8_t upper = (convertCharToHex(key[i]) << 4);
      uint8_t lower = (convertCharToHex(key[i + 1]));
      keys[ki] = (upper | lower);
    }
  }

  bool begin() {
#if BOLTY_NFC_BACKEND_MFRC522
    delay(1000);
    bool init_ok = false;
    for (uint8_t attempt = 1; attempt <= 3; ++attempt) {
      if (nfc->begin(MFRC522_SDA, MFRC522_SCL, MFRC522_I2C_FREQUENCY)) {
        init_ok = true;
        break;
      }
      DBG_PRINT("MFRC522 begin attempt ");
      DBG_PRINT(attempt);
      DBG_PRINTLN(" failed");
      delay(200);
    }
    if (!init_ok) {
      DBG_PRINTLN("MFRC522 begin failed");
      return false;
    }
    const uint8_t version = nfc->PCD_ReadRegister(MFRC522_I2C::VersionReg);
    DBG_PRINT("Found MFRC522 version 0x");
    DBG_PRINTLN(version, HEX);
#elif BOLTY_NFC_BACKEND_PN532_UART
#if NFC_RESET_PIN >= 0
    pinMode(NFC_RESET_PIN, OUTPUT);
    digitalWrite(NFC_RESET_PIN, LOW);
    delay(100);
    digitalWrite(NFC_RESET_PIN, HIGH);
    delay(10);
#endif
    DBG_PRINTLN("PN532 UART mode (Serial2)");
    extern HardwareSerial PN532Serial;
    PN532Serial.begin(115200, SERIAL_8N1, PN532_UART_RX, PN532_UART_TX);
    while (PN532Serial.available()) PN532Serial.read();
    nfc->begin();
    uint32_t versiondata = nfc->getFirmwareVersion();
    if (!versiondata) {
      DBG_PRINT("Didn't find PN53x board (UART)");
      return false;
    }
    DBG_PRINT("Found chip PN53x");
    DBG_PRINTLN((versiondata >> 24) & 0xFF, HEX);
    DBG_PRINT("Firmware ver. ");
    DBG_PRINT((versiondata >> 16) & 0xFF, DEC);
    DBG_PRINT('.');
    DBG_PRINTLN((versiondata >> 8) & 0xFF, DEC);
    nfc->SAMConfig();
#else
    pinMode(PN532_SS, OUTPUT);
    digitalWrite(PN532_SS, HIGH);
#if NFC_RESET_PIN >= 0
    pinMode(NFC_RESET_PIN, OUTPUT);
    digitalWrite(NFC_RESET_PIN, LOW);
    delay(100);
    digitalWrite(NFC_RESET_PIN, HIGH);
    delay(10);
#endif
    nfc->begin();
    uint32_t versiondata = nfc->getFirmwareVersion();
    if (!versiondata) {
      DBG_PRINT("Didn't find PN53x board");
      return false;
    }
    DBG_PRINT("Found chip PN53x");
    DBG_PRINTLN((versiondata >> 24) & 0xFF, HEX);
    DBG_PRINT("Firmware ver. ");
    DBG_PRINT((versiondata >> 16) & 0xFF, DEC);
    DBG_PRINT('.');
    DBG_PRINTLN((versiondata >> 8) & 0xFF, DEC);
    nfc->SAMConfig();
#endif

    _consecutive_scan_failures = 0;
    _last_reader_reinit_ms = 0;
    DBG_PRINTLN("NFC Ready...");
    return true;
  }

  bool reinitReader() {
    _last_reader_reinit_ms = millis();
#if BOLTY_NFC_BACKEND_MFRC522
    bool ok = false;
    for (uint8_t attempt = 1; attempt <= 3; ++attempt) {
      if (nfc->begin(MFRC522_SDA, MFRC522_SCL, MFRC522_I2C_FREQUENCY)) {
        ok = true;
        break;
      }
      DBG_PRINT("MFRC522 reinit attempt ");
      DBG_PRINT(attempt);
      DBG_PRINTLN(" failed");
      delay(100);
    }
    if (!ok) {
      DBG_PRINTLN("MFRC522 reinit failed");
      return false;
    }
    DBG_PRINTLN("MFRC522 reinit complete");
    return true;
#else
    pinMode(NFC_RESET_PIN, OUTPUT);
    digitalWrite(NFC_RESET_PIN, LOW);
    delay(100);
    digitalWrite(NFC_RESET_PIN, HIGH);
    delay(10);

    nfc->begin();

    uint32_t versiondata = nfc->getFirmwareVersion();
    if (!versiondata) {
      DBG_PRINTLN("PN532 reinit failed: firmware query returned no data");
      return false;
    }

    nfc->SAMConfig();
    _last_reader_reinit_ms = millis();
    DBG_PRINTLN("PN532 reinit complete");
    return true;
#endif
  }

  String get_job_status() { return boltstatustext[job_status]; }
  uint8_t get_job_perc() { return job_perc; }
  uint8_t get_job_status_id() { return job_status; }

  void set_job_status_id(uint8_t new_status) {
    job_status = new_status;
    led_set_job_status(job_status);
#if HAS_DISPLAY
    uint16_t statcolor = APPBLACK;
    if (job_status == JOBSTATUS_ERROR) {
      statcolor = APPRED;
    } else if (job_status == JOBSTATUS_WIPING ||
               job_status == JOBSTATUS_PROVISIONING) {
      statcolor = APPORANGE;
    } else if (job_status == JOBSTATUS_DONE) {
      statcolor = APPGREEN;
    }
    tft.setFreeFont(&FreeSans9pt7b);
    tft.setTextColor(APPWHITE);
    tft.fillRect(0, -3 + (3 * 23), tft.width(), 21, statcolor);
    displayTextCentered(-3 + (4 * 21), get_job_status());
    tft.setTextColor(APPBLACK);
#else
    DBG_PRINT("[status] ");
    DBG_PRINTLN(get_job_status());
#endif
  }

  bool scanUID() {
    uint8_t uid[12] = {0};
    uint8_t uidLength = 0;
    if ((millis() - lastscan) > 2000) {
      last_scanned_uid = "";
    }

    const bool success = bolty_read_passive_target(nfc, uid, &uidLength);
    if (success) {
      _consecutive_scan_failures = 0;
      bolty_print_hex(nfc, uid, uidLength);
      if (((uidLength == 7) || (uidLength == 4)) && nfc->ntag424_isNTAG424()) {
        lastscan = millis();
        last_scanned_uid = convertIntToHex(uid, uidLength);
        return true;
      }
    } else {
      _consecutive_scan_failures++;
      if (_consecutive_scan_failures >= MAX_SCAN_FAILURES &&
          (_last_reader_reinit_ms == 0 ||
           (millis() - _last_reader_reinit_ms) >= REINIT_BACKOFF_MS)) {
        DBG_PRINTLN("NFC scan failures exceeded threshold, reinitializing");
        if (reinitReader()) {
          _consecutive_scan_failures = 0;
        }
      }
    }
    return false;
  }

  String getScannedUid() { return last_scanned_uid; }

  // Max URL length: NDEF file = 256 bytes. Total message = 7 (header) + url_len
  // + 61 (SDM "?p=32hex&c=16hex"). Plus 2 for NLEN. Max url_len = 256 - 70 = 186.
  static const int MAX_URL_LENGTH = 186;

  uint8_t burn(String lnurl) {
    if ((int)lnurl.length() > MAX_URL_LENGTH) {
      DBG_PRINT(F("[burn] URL too long: "));
      DBG_PRINT(lnurl.length());
      DBG_PRINT(F(" bytes (max "));
      DBG_PRINT(MAX_URL_LENGTH);
      DBG_PRINTLN(F(")"));
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }

    uint8_t uid[12] = {0};
    uint8_t uidLength = 0;
    job_status = JOBSTATUS_WAITING;
    set_job_status_id(JOBSTATUS_WAITING);

    if (!bolty_read_passive_target(nfc, uid, &uidLength)) {
      return job_status;
    }

    set_job_status_id(JOBSTATUS_PROVISIONING);
    DBG_PRINTLN("Found an ISO14443A tag");
    DBG_PRINT("  UID Length: ");
    DBG_PRINT(uidLength, DEC);
    DBG_PRINTLN(" bytes");
    DBG_PRINT("  UID Value: ");
    bolty_print_hex(nfc, uid, uidLength);
    DBG_PRINTLN("");

    if (!(((uidLength == 7) || (uidLength == 4)) && nfc->ntag424_isNTAG424())) {
      DBG_PRINTLN("This doesn't seem to be an NTAG424 tag. (UUID length != 7 bytes and UUID length != 4)!");
      return job_status;
    }

    uint8_t kv = bolty_get_key_version(nfc, 1);
    if (kv != 0x00) {
      DBG_PRINT(F("ABORT: Card key 1 version is 0x"));
      if (kv < 0x10) {
        DBG_PRINT(F("0"));
      }
      DBG_PRINT(kv, HEX);
      DBG_PRINTLN(F(" - card appears provisioned. Wipe first."));
      set_job_status_id(JOBSTATUS_GUARD_REJECT);
      return job_status;
    }

    DBG_PRINTLN(F("Pre-burn check OK - card has factory keys"));

    if (!selectNtagApplicationFiles()) {
      DBG_PRINTLN(F("Failed to select NTAG application files."));
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }

    // Native AuthenticateEV2First: cmd=0x71 (NT4H2421Gx §7.3.1.1).
    // Using cur_keys.keys[0] (factory zero key) with key number 0.
    const uint8_t auth_result = nfc->ntag424_Authenticate(cur_keys.keys[0], 0, 0x71);
    if (auth_result != 1) {
      uint8_t chk_uid[12] = {0};
      uint8_t chk_uid_len = 0;
      if (bolty_read_passive_target(nfc, chk_uid, &chk_uid_len)) {
        DBG_PRINTLN(F("Auth FAILED — card is present but key was rejected (wrong key?)"));
      } else {
        DBG_PRINTLN(F("Auth FAILED — card no longer detected (removed during operation?)"));
      }
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }
    DBG_PRINTLN(F("Auth OK."));

    const uint8_t uriIdentifier = 0;
    // PICC data offset: 7 (NDEF header) + lnurl_length + "?p=" (2) + 16*2 hex digits
    // This tells the tag where to inject the UID+read counter during SDM.
    // Ref: NT4H2421Gx datasheet §8.7.2, SDM PICCDataOffset
    const int piccDataOffset = lnurl.length() + 10;
    // SDM MAC offset: piccDataOffset + UID_hex(14) + read_ctr_hex(6)
    // = lnurl_length + 10 + 14 + 6 + "&c="(3) = lnurl_length + 33
    // But we account for the full "?p=..." + "&c=..." structure:
    // lnurl + "?p=" (2) + 32 hex chars + "&c=" (3) + 16 hex chars
    // The MAC is appended at the end of the 16 hex c= placeholder.
    // Net: lnurl_length + 45
    const int sdmMacOffset = lnurl.length() + 45;
    // Bolt card LNURL placeholder: p=32-hex-char PICC data placeholder,
    // c=16-hex-char MAC placeholder. These get replaced by the tag's
    // Secure Dynamic Messaging (SDM) during read.
    // Ref: bolt-card specification, NT4H2421Gx §8.7
    lnurl += "?p=00000000000000000000000000000000&c=0000000000000000";
    const uint8_t len = lnurl.length();
    // NDEF Record Header — NFC Forum NDEF specification §3.2
    // Byte 0: 0x00 = MB=0, ME=0 (more records follow; actually this IS the
    //         only record but we set MB/ME in byte 2's TNF)
    // Byte 1: len + 5 = total payload after this byte (record payload size)
    // Byte 2: 0xD1 = MB=1, ME=1, CF=0, SR=1, IL=0, TNF=0x01 (NFC Well-Known)
    // Byte 3: 0x01 = type length = 1 byte ("U")
    // Byte 4: len + 1 = payload length (type "U" + URL string)
    // Byte 5: 0x55 = 'U' — NFC Well-Known Type "U" (URI record)
    // Byte 6: 0x00 = URI Identifier Code = "No prepending" (raw URL)
    // Ref: NFC Forum NDEF Technical Specification §3.2.1
    uint8_t ndefheader[7] = {
        0x0,
        static_cast<uint8_t>(len + 5),
        0xD1,
        0x01,
        static_cast<uint8_t>(len + 1),
        0x55,
        uriIdentifier,
    };
    uint8_t *filedata = (uint8_t *)malloc(len + sizeof(ndefheader));
    if (filedata == nullptr) {
      DBG_PRINTLN(F("Failed to allocate NDEF buffer."));
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }
    memcpy(filedata, ndefheader, sizeof(ndefheader));
    memcpy(filedata + sizeof(ndefheader), lnurl.c_str(), len);
    const size_t ndef_file_length = len + sizeof(ndefheader);

    bool ndef_write_ok = true;
    // MFRC522 FIFO-safe chunk size: 47 bytes.
    // MFRC522 has a 64-byte FIFO (MFRC522 datasheet §8.6.1).
    // WriteData APDU: CLA(1)+INS(1)+P1(1)+P2(1)+Lc(1)+header(7)+data(N)+Le(1)
    // = 12 + N. ISO-DEP adds PCB(1)+CID(1)+CRC(2)=4 bytes overhead.
    // Total: 4 + 12 + N ≤ 64 → N ≤ 48. Use 47 for safety margin.
    // Matches the chunk size used by ntag424_FormatNDEF() in ntag424_core.cpp.
    // Confirmed by reference: Obsttube/MFRC522_NTAG424DNA line 1598.
    const uint8_t kWriteChunkSize = 47;
    size_t write_offset = 0;
    while (write_offset < ndef_file_length) {
      const uint8_t chunk_len =
          (ndef_file_length - write_offset > kWriteChunkSize)
              ? kWriteChunkSize
              : static_cast<uint8_t>(ndef_file_length - write_offset);
      if (!nfc->ntag424_WriteData(2, filedata + write_offset, chunk_len,
                                   static_cast<int>(write_offset))) {
        ndef_write_ok = false;
        break;
      }
      write_offset += chunk_len;
    }
    free(filedata);

    if (!ndef_write_ok) {
      DBG_PRINTLN(F("NDEF write failed via native WriteData."));
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }
    DBG_PRINTLN(F("NDEF written successfully."));
    // ChangeFileSettings for file 2 (NDEF) — NT4H2421Gx datasheet §7.6.2,
    // Table 49, and §8.7.2 Table 71 for SDM configuration.
    //
    // Byte layout (after FileNo):
    //   [0]  0x40 = FileOption: SDM enabled (bit 6), Plain read/write
    //   [1]  0x00 = Access Rights: free read (0x0), free write (0x0)
    //   [2]  0xE0 = Write access key=0xE (key 0 for write), Read=0x0 (free)
    //   [3]  0xC1 = SDMOptions: UID mirror + ReadCnt mirror + MAC + encrypt
    //   [4]  0xFF = SDMAccessRights: SDMReadRetr key=0xF (free)
    //   [5]  0x12 = SDMCounterRetr: retrieve read counter
    //   [6-8]   PICCDataOffset (3 bytes, LE) — where SDM injects UID+counter
    //   [9-11]  SDMMACInputOffset (3 bytes, LE) — MAC input location
    //   [12-14] SDMMACOffset (3 bytes, LE) — where SDM writes the CMAC
    // Ref: NT4H2421Gx datasheet §8.7.2 Table 71, bolt-card specification
    uint8_t fileSettings[] = {0x40,
                              0x00,
                              0xE0,
                              0xC1,
                              0xFF,
                              0x12,
                              static_cast<uint8_t>(piccDataOffset & 0xff),
                              static_cast<uint8_t>((piccDataOffset >> 8) & 0xff),
                              static_cast<uint8_t>((piccDataOffset >> 16) & 0xff),
                              static_cast<uint8_t>(sdmMacOffset & 0xff),
                              static_cast<uint8_t>((sdmMacOffset >> 8) & 0xff),
                              static_cast<uint8_t>((sdmMacOffset >> 16) & 0xff),
                              static_cast<uint8_t>(sdmMacOffset & 0xff),
                              static_cast<uint8_t>((sdmMacOffset >> 8) & 0xff),
                              static_cast<uint8_t>((sdmMacOffset >> 16) & 0xff)};
    if (!nfc->ntag424_ChangeFileSettings((uint8_t)2, fileSettings,
                                    (uint8_t)sizeof(fileSettings),
                                    (uint8_t)NTAG424_COMM_MODE_FULL)) {
      DBG_PRINTLN(F("ChangeFileSettings (SDM enable) FAILED — aborting burn before key change"));
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }

    // EC-5 card presence: the MFRC522 adapter checks isTagPresent() before
    // every transceive, so ChangeKey will naturally fail if the card is gone.
    // Combined with abort-on-first-failure, this is sufficient protection.
    // GetKeyVersion cannot be used here — it returns 91 7E during auth sessions.
    // Ref: GitHub issue #8

    // Change all 5 application keys. Key version 0x01 marks the card as
    // provisioned (factory = 0x00). Keys changed in reverse order (4→0)
    // to avoid losing access mid-operation.
    // Ref: NT4H2421Gx datasheet §7.3.2, AN12196 §6.3
    if (!changeAllKeys(0x01)) {
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }

    // Verify new keys work: AuthenticateEV2First with new key 0, then
    // probe all key versions to confirm the burn succeeded.
    selectNtagApplicationFiles();
    DBG_PRINTLN(F("[burn] Post-burn verification..."));
    const uint8_t authed = nfc->ntag424_Authenticate(new_keys.keys[0], 0, 0x71);
    if (authed != 1) {
      DBG_PRINTLN(F("[burn] VERIFY FAIL: new-key auth failed"));
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }
    DBG_PRINTLN(F("[burn] New-key auth OK"));

    bool burn_verified = true;
    for (int i = 1; i < 5; i++) {
      uint8_t v = bolty_get_key_version(nfc, i);
      if (v != 0x01) {
        DBG_PRINT(F("[burn] VERIFY FAIL: Key "));
        DBG_PRINT(i);
        DBG_PRINT(F(" version=0x"));
        if (v < 0x10) DBG_PRINT('0');
        DBG_PRINT(v, HEX);
        DBG_PRINTLN(F(" — expected 0x01"));
        burn_verified = false;
      }
    }

    if (burn_verified) {
      DBG_PRINTLN(F("[burn] VERIFY OK: All keys confirmed at target version 0x01"));
      set_job_status_id(JOBSTATUS_DONE);
    } else {
      DBG_PRINTLN(F("[burn] VERIFY FAIL: Some keys not at target version"));
      set_job_status_id(JOBSTATUS_ERROR);
    }
    return job_status;
  }

  uint8_t resetNdefOnly() {
    uint8_t uid[12] = {0};
    uint8_t uidLength = 0;

    set_job_status_id(JOBSTATUS_WAITING);
    if (!bolty_read_passive_target(nfc, uid, &uidLength)) {
      return job_status;
    }

    set_job_status_id(JOBSTATUS_WIPING);
    DBG_PRINTLN(F("Found an ISO14443A tag"));
    DBG_PRINT(F("  UID Length: "));
    DBG_PRINT(uidLength, DEC);
    DBG_PRINTLN(F(" bytes"));
    DBG_PRINT(F("  UID Value: "));
    bolty_print_hex(nfc, uid, uidLength);
    DBG_PRINTLN();

    if (!(((uidLength == 7) || (uidLength == 4)) && nfc->ntag424_isNTAG424())) {
      DBG_PRINTLN(F("This doesn't seem to be an NTAG424 tag."));
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }

    const uint8_t kv = bolty_get_key_version(nfc, 0);
    if (kv != 0x00) {
      DBG_PRINT(F("ABORT: Key 0 version is 0x"));
      if (kv < 0x10) {
        DBG_PRINT(F("0"));
      }
      DBG_PRINT(kv, HEX);
      DBG_PRINTLN(F(" — resetNdefOnly requires factory keys. Use 'wipe' instead."));
      set_job_status_id(JOBSTATUS_GUARD_REJECT);
      return job_status;
    }

    DBG_PRINTLN(F("Pre-reset check OK — key 0 is factory default"));
    selectNtagApplicationFiles();

    uint8_t zero_key[16] = {0};
    if (nfc->ntag424_Authenticate(zero_key, 0, 0x71) != 1) {
      DBG_PRINTLN(F("Authentication with zero key FAILED."));
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }
    DBG_PRINTLN(F("Authentication successful (factory zero key)."));

    DBG_PRINTLN(F("Disabling SDM and resetting file settings..."));
    // Reset file 2 settings: disable SDM, keep Plain read/write access.
    // {0x00, 0x00, 0xE0} = no SDM mirroring, free access, standard file.
    // Ref: NT4H2421Gx datasheet §7.6.2 Table 49
    uint8_t fileSettings[] = {0x00, 0x00, 0xE0};
    nfc->ntag424_ChangeFileSettings((uint8_t)2, fileSettings,
                                    (uint8_t)sizeof(fileSettings),
                                    (uint8_t)NTAG424_COMM_MODE_FULL);

    selectNtagApplicationFiles();
    nfc->ntag424_Authenticate(zero_key, 0, 0x71);
    if (nfc->ntag424_FormatNDEF()) {
      DBG_PRINTLN(F("NDEF formatted OK."));
    } else {
      DBG_PRINTLN(F("NDEF format skipped (already blank)."));
    }
    job_perc = 100;

    selectNtagApplicationFiles();
    const uint8_t verify_auth = nfc->ntag424_Authenticate(zero_key, 0, 0x71);
    if (verify_auth == 1) {
      DBG_PRINTLN(F("Verify auth OK — keys unchanged."));
    } else {
      DBG_PRINTLN(F("WARNING: Verify auth failed (unexpected)."));
    }

    set_job_status_id(JOBSTATUS_DONE);
    return job_status;
  }

  // Authenticate every key slot to prove we know all keys before wiping.
  // For K3/K4, if the explicit key fails, probes K3=K1 (LNBits) and zeros.
  // Updates cur_keys.keys[] if probing finds a working key.
  KeyVerifyResult verify_all_keys() {
    KeyVerifyResult vr = {};
    memset(vr.key_versions, 0xFF, 5);
    uint8_t zero_key[16] = {0};

    DBG_PRINTLN(F("[verify] Reading key versions..."));
    for (int i = 0; i < 5; i++) {
      vr.key_versions[i] = bolty_get_key_version(nfc, i);
    }

    vr.all_factory = true;
    for (int i = 0; i < 5; i++) {
      if (vr.key_versions[i] != 0x00) { vr.all_factory = false; break; }
    }

    if (vr.all_factory) {
      DBG_PRINTLN(F("[verify] All keys at factory (0x00) — card is blank."));
      for (int i = 0; i < 5; i++) vr.verified[i] = true;
      vr.all_verified = true;
      return vr;
    }

    DBG_PRINTLN(F("[verify] Authenticating all keys..."));
    for (int i = 0; i < 5; i++) {
      selectNtagApplicationFiles();
      DBG_PRINT(F("[verify]   K"));
      DBG_PRINT(i);
      DBG_PRINT(F(": ver=0x"));
      if (vr.key_versions[i] < 0x10) DBG_PRINT(F("0"));
      DBG_PRINT(vr.key_versions[i], HEX);

      if (vr.key_versions[i] == 0x00) {
        if (nfc->ntag424_Authenticate(zero_key, i, 0x71) == 1) {
          vr.verified[i] = true;
          DBG_PRINTLN(F(" FACTORY-OK"));
        } else {
          vr.verified[i] = false;
          DBG_PRINTLN(F(" FACTORY-FAIL (desync!)"));
        }
        continue;
      }

      // Provisioned slot — try explicit key first.
      if (nfc->ntag424_Authenticate(cur_keys.keys[i], i, 0x71) == 1) {
        vr.verified[i] = true;
        DBG_PRINTLN(F(" AUTHENTICATED"));
        continue;
      }

      // Explicit key failed. Probe K3=K1 or K4=K2 (LNBits), then zeros.
      if (i == 3 || i == 4) {
        const uint8_t lnbits_src = (i == 3) ? 1 : 2;
        DBG_PRINT(F(" probing..."));
        selectNtagApplicationFiles();
        if (nfc->ntag424_Authenticate(cur_keys.keys[lnbits_src], i, 0x71) == 1) {
          DBG_PRINT(F(" K"));
          DBG_PRINT(i);
          DBG_PRINT(F("=K"));
          DBG_PRINT(lnbits_src);
          DBG_PRINTLN(F(" (LNBits) OK"));
          memcpy(cur_keys.keys[i], cur_keys.keys[lnbits_src], 16);
          vr.verified[i] = true;
          continue;
        }
        selectNtagApplicationFiles();
        if (nfc->ntag424_Authenticate(zero_key, i, 0x71) == 1) {
          DBG_PRINTLN(F(" zeros OK"));
          memset(cur_keys.keys[i], 0, 16);
          vr.verified[i] = true;
          continue;
        }
        DBG_PRINTLN(F(" PROBE-FAIL"));
        vr.verified[i] = false;
      } else {
        DBG_PRINTLN(F(" FAILED (no probe for K0/K1/K2)"));
        vr.verified[i] = false;
      }
    }

    uint8_t ok_count = 0;
    for (int i = 0; i < 5; i++) { if (vr.verified[i]) ok_count++; }
    vr.all_verified = (ok_count == 5);

    if (vr.all_verified) {
      DBG_PRINTLN(F("[verify] All 5 keys verified — safe to wipe."));
    } else {
      DBG_PRINT(F("[verify] ABORT: "));
      DBG_PRINT(5 - ok_count);
      DBG_PRINT(F(" key(s) UNVERIFIED:"));
      for (int i = 0; i < 5; i++) {
        if (!vr.verified[i]) { DBG_PRINT(F(" K")); DBG_PRINT(i); }
      }
      DBG_PRINTLN();
    }
    return vr;
  }

  uint8_t wipe() {
    uint8_t uid[12] = {0};
    uint8_t uidLength = 0;
    set_job_status_id(JOBSTATUS_WAITING);

    if (!bolty_read_passive_target(nfc, uid, &uidLength)) {
      return job_status;
    }

    set_job_status_id(JOBSTATUS_WIPING);
    DBG_PRINTLN("Found an ISO14443A tag");
    DBG_PRINT("  UID Length: ");
    DBG_PRINT(uidLength, DEC);
    DBG_PRINTLN(" bytes");
    DBG_PRINT("  UID Value: ");
    bolty_print_hex(nfc, uid, uidLength);
    DBG_PRINTLN("");

    if (!(((uidLength == 7) || (uidLength == 4)) && nfc->ntag424_isNTAG424())) {
      DBG_PRINTLN("This doesn't seem to be an NTAG424 tag. (UUID length != 7 bytes and UUID length != 4)!");
      return job_status;
    }

    KeyVerifyResult vr = verify_all_keys();

    if (vr.all_factory) {
      set_job_status_id(JOBSTATUS_GUARD_REJECT);
      return job_status;
    }

    if (!vr.all_verified) {
      set_job_status_id(JOBSTATUS_GUARD_REJECT);
      return job_status;
    }

    // Re-auth K0 for wipe ops (verify cycle may have left non-K0 session active).
    selectNtagApplicationFiles();
    if (nfc->ntag424_Authenticate(cur_keys.keys[0], 0, 0x71) != 1) {
      uint8_t chk_uid[12] = {0};
      uint8_t chk_uid_len = 0;
      if (bolty_read_passive_target(nfc, chk_uid, &chk_uid_len)) {
        DBG_PRINTLN(F("Post-verify K0 re-auth FAILED — card present but key rejected"));
      } else {
        DBG_PRINTLN(F("Post-verify K0 re-auth FAILED — card removed during verify"));
      }
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }
    DBG_PRINTLN("Disable Mirroring and SDM.");
    // Reset file 2 settings: disable SDM, keep Plain read/write access.
    // {0x00, 0x00, 0xE0} = no SDM mirroring, free access, standard file.
    // Ref: NT4H2421Gx datasheet §7.6.2 Table 49
    uint8_t fileSettings[] = {0x00, 0x00, 0xE0};
    if (!nfc->ntag424_ChangeFileSettings((uint8_t)2, fileSettings,
                                    (uint8_t)sizeof(fileSettings),
                                    (uint8_t)NTAG424_COMM_MODE_FULL)) {
      DBG_PRINTLN(F("ChangeFileSettings (SDM disable) FAILED — aborting wipe before key change"));
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }

    // EC-5: Not checked here — GetKeyVersion returns 91 7E during auth.
    // MFRC522 adapter's isTagPresent() per-transceive check is sufficient.
    // Ref: GitHub issue #8

    // Reset all keys to factory defaults (key version 0x00 = factory state).
    // Ref: NT4H2421Gx datasheet §7.3.2
    if (!changeAllKeys(0x00)) {
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }

    // Re-authenticate with the new (factory zero) key. Changing key 0
    // invalidates the old auth session, but FormatNDEF needs an active
    // session because the NDEF file access rights require key 0 for write.
    // Ref: NT4H2421Gx datasheet §7.3.2 — "If the key that was used for
    //   the active authentication is changed, the PICC terminates the
    //   transaction (SDM state is reset)."
    selectNtagApplicationFiles();
    if (nfc->ntag424_Authenticate(new_keys.keys[0], 0, 0x71) != 1) {
      DBG_PRINTLN("Re-authentication after key change failed.");
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }

    if (nfc->ntag424_FormatNDEF()) {
      job_perc = 100;
    } else {
      DBG_PRINTLN(F("FormatNDEF FAILED — card keys are reset but NDEF may be stale"));
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }

    // Post-wipe verification: confirm all keys are at factory version 0x00.
    selectNtagApplicationFiles();
    DBG_PRINTLN(F("[wipe] Post-wipe verification..."));
    uint8_t zero_key[16] = {0};
    const uint8_t authed = nfc->ntag424_Authenticate(zero_key, 0, 0x71);
    if (authed != 1) {
      DBG_PRINTLN(F("[wipe] VERIFY FAIL: zero-key auth failed — wipe did not succeed"));
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }

    bool all_verified = true;
    for (int i = 0; i < 5; i++) {
      uint8_t v = bolty_get_key_version(nfc, i);
      if (v != 0x00) {
        DBG_PRINT(F("[wipe] VERIFY FAIL: Key "));
        DBG_PRINT(i);
        DBG_PRINT(F(" version=0x"));
        if (v < 0x10) DBG_PRINT('0');
        DBG_PRINT(v, HEX);
        DBG_PRINTLN(F(" — expected 0x00"));
        all_verified = false;
      }
    }

    if (all_verified) {
      DBG_PRINTLN(F("[wipe] VERIFY OK: All 5 keys confirmed factory (version 0x00)"));
      set_job_status_id(JOBSTATUS_DONE);
    } else {
      DBG_PRINTLN(F("[wipe] VERIFY FAIL: Some keys not at factory state"));
      set_job_status_id(JOBSTATUS_ERROR);
    }
    return job_status;
  }
};

#endif
