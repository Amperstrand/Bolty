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

#define JOBSTATUS_IDLE 0
#define JOBSTATUS_WAITING 1
#define JOBSTATUS_PROVISIONING 2
#define JOBSTATUS_WIPING 3
#define JOBSTATUS_DONE 4
#define JOBSTATUS_ERROR 5
#define JOBSTATUS_GUARD_REJECT 6

static const uint8_t NTAG424_AID[7] = {0xD2, 0x76, 0x00, 0x00,
                                       0x85, 0x01, 0x01};
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
      Serial.print(F("0x0"));
    } else {
      Serial.print(F("0x"));
    }
    Serial.print(data[i], HEX);
    if (i + 1 < length) {
      Serial.print(F(" "));
    }
  }
  Serial.println();
#else
  nfc->PrintHex(data, length);
#endif
}

inline uint8_t bolty_get_key_version(BoltyNfcReader *nfc, uint8_t keyno) {
  if (!nfc->ntag424_ISOSelectFileByDFN((uint8_t *)NTAG424_AID)) {
    return 0xFF;
  }
  uint8_t version = 0xFF;
  if (nfc->ntag424_GetKeyVersion(keyno, &version)) {
    return version;
  }
  return 0xFF;
}

class BoltDevice {
public:
  BoltyNfcReader *nfc = nullptr;
  uint8_t key_cur[5][16] = {{0}};
  uint8_t key_new[5][16] = {{0}};

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
#else
  BoltDevice(uint8_t SCK, uint8_t MISO, uint8_t MOSI, uint8_t SS) {
    nfc = new Adafruit_PN532(SCK, MISO, MOSI, SS);
  }
#endif

  void setDefautKeys(uint8_t keys[5][16]) {
    for (int i = 0; i < 5; i++) {
      memset((void *)(keys[i]), 0, 16);
    }
  }

  void setDefautKeysNew() { setDefautKeys(key_new); }
  void setDefautKeysCur() { setDefautKeys(key_cur); }

  void loadKeysForBurn(const sBoltConfig &config) {
    setDefautKeysCur();
    setNewKey(config.k0, 0);
    setNewKey(config.k1, 1);
    setNewKey(config.k2, 2);
    setNewKey(config.k3, 3);
    setNewKey(config.k4, 4);
  }

  void loadKeysForWipe(const sBoltConfig &config) {
    setDefautKeysNew();
    setCurKey(config.k0, 0);
    setCurKey(config.k1, 1);
    setCurKey(config.k2, 2);
    setCurKey(config.k3, 3);
    setCurKey(config.k4, 4);
  }

  bool selectNtagApplicationFiles() {
    return nfc->ntag424_ISOSelectFileByDFN((uint8_t *)NTAG424_AID) &&
           nfc->ntag424_ISOSelectCCFile() &&
           nfc->ntag424_ISOSelectFileById(NTAG424_NDEF_FILE_ID);
  }

  bool selectNdefFileOnly() { return nfc->ntag424_ISOSelectNDEFFile(); }

  bool changeAllKeys(uint8_t target_key_version) {
    for (int i = 0; i < 5; i++) {
      const uint8_t key_index = 4 - i;
      if (!nfc->ntag424_ChangeKey(key_cur[key_index], key_new[key_index],
                                  key_index, target_key_version)) {
        Serial.print("ChangeKey error! Key: ");
        Serial.println(key_index);
        return false;
      }
    }
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

  void setNewKey(String key, uint8_t keyno) { setKey(key_new[keyno], key); }
  void setCurKey(String key, uint8_t keyno) { setKey(key_cur[keyno], key); }

  bool begin() {
#if BOLTY_NFC_BACKEND_MFRC522
    delay(1000);
    bool init_ok = false;
    for (uint8_t attempt = 1; attempt <= 3; ++attempt) {
      if (nfc->begin(MFRC522_SDA, MFRC522_SCL, MFRC522_I2C_FREQUENCY)) {
        init_ok = true;
        break;
      }
      Serial.print("MFRC522 begin attempt ");
      Serial.print(attempt);
      Serial.println(" failed");
      delay(200);
    }
    if (!init_ok) {
      Serial.println("MFRC522 begin failed");
      return false;
    }
    const uint8_t version = nfc->PCD_ReadRegister(MFRC522_I2C::VersionReg);
    Serial.print("Found MFRC522 version 0x");
    Serial.println(version, HEX);
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
      Serial.print("Didn't find PN53x board");
      return false;
    }
    Serial.print("Found chip PN53x");
    Serial.println((versiondata >> 24) & 0xFF, HEX);
    Serial.print("Firmware ver. ");
    Serial.print((versiondata >> 16) & 0xFF, DEC);
    Serial.print('.');
    Serial.println((versiondata >> 8) & 0xFF, DEC);
    nfc->SAMConfig();
#endif

    _consecutive_scan_failures = 0;
    _last_reader_reinit_ms = 0;
    Serial.println("NFC Ready...");
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
      Serial.print("MFRC522 reinit attempt ");
      Serial.print(attempt);
      Serial.println(" failed");
      delay(100);
    }
    if (!ok) {
      Serial.println("MFRC522 reinit failed");
      return false;
    }
    Serial.println("MFRC522 reinit complete");
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
      Serial.println("PN532 reinit failed: firmware query returned no data");
      return false;
    }

    nfc->SAMConfig();
    _last_reader_reinit_ms = millis();
    Serial.println("PN532 reinit complete");
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
    Serial.print("[status] ");
    Serial.println(get_job_status());
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
        Serial.println("NFC scan failures exceeded threshold, reinitializing");
        if (reinitReader()) {
          _consecutive_scan_failures = 0;
        }
      }
    }
    return false;
  }

  String getScannedUid() { return last_scanned_uid; }

  uint8_t burn(String lnurl) {
    uint8_t uid[12] = {0};
    uint8_t uidLength = 0;
    job_status = JOBSTATUS_WAITING;
    set_job_status_id(JOBSTATUS_WAITING);

    if (!bolty_read_passive_target(nfc, uid, &uidLength)) {
      return job_status;
    }

    set_job_status_id(JOBSTATUS_PROVISIONING);
    Serial.println("Found an ISO14443A tag");
    Serial.print("  UID Length: ");
    Serial.print(uidLength, DEC);
    Serial.println(" bytes");
    Serial.print("  UID Value: ");
    bolty_print_hex(nfc, uid, uidLength);
    Serial.println("");

    if (!(((uidLength == 7) || (uidLength == 4)) && nfc->ntag424_isNTAG424())) {
      Serial.println("This doesn't seem to be an NTAG424 tag. (UUID length != 7 bytes and UUID length != 4)!");
      return job_status;
    }

    uint8_t kv = bolty_get_key_version(nfc, 1);
    if (kv != 0x00) {
      Serial.print(F("ABORT: Card key 1 version is 0x"));
      if (kv < 0x10) {
        Serial.print(F("0"));
      }
      Serial.print(kv, HEX);
      Serial.println(F(" - card appears provisioned. Wipe first."));
      set_job_status_id(JOBSTATUS_GUARD_REJECT);
      return job_status;
    }

    Serial.println(F("Pre-burn check OK - card has factory keys"));
    // NTAG424 personalization flow writes NDEF only after selecting the NDEF
    // application/file first (AN12196 Rev. 2.0, Sections 5.3 and 5.8.1). Keep
    // this guard explicit so transport failures are not confused with select
    // state mistakes on the MFRC522 path.
    if (!selectNtagApplicationFiles()) {
      Serial.println(F("Failed to select NTAG application files before NDEF write."));
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }
    const uint8_t uriIdentifier = 0;
    const int piccDataOffset = lnurl.length() + 10;
    const int sdmMacOffset = lnurl.length() + 45;
    lnurl += "?p=00000000000000000000000000000000&c=0000000000000000";
    const uint8_t len = lnurl.length();
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
    memcpy(filedata, ndefheader, sizeof(ndefheader));
    memcpy(filedata + sizeof(ndefheader), lnurl.c_str(), lnurl.length());
    const bool ndef_write_ok =
        nfc->ntag424_ISOUpdateBinary(filedata, len + sizeof(ndefheader));
    free(filedata);

    if (!ndef_write_ok) {
      Serial.println(F("NDEF write failed before SDM/key changes."));
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }

    const uint8_t authenticated = nfc->ntag424_Authenticate(key_cur[0], 0, 0x71);
    if (authenticated != 1) {
      Serial.println("Authentication 1 failed.");
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }

    Serial.println("Authentication successful.");
    Serial.println("Enable Mirroring and SDM.");
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
    nfc->ntag424_ChangeFileSettings((uint8_t)2, fileSettings,
                                    (uint8_t)sizeof(fileSettings),
                                    (uint8_t)NTAG424_COMM_MODE_FULL);

    if (!changeAllKeys(0x01)) {
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }

    const uint8_t authenticated_after = nfc->ntag424_Authenticate(key_new[0], 0, 0x71);
    if (authenticated_after == 1) {
      Serial.println("Authentication 2 Success.");
      set_job_status_id(JOBSTATUS_DONE);
    } else {
      Serial.println("Authentication 2 failed.");
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
    Serial.println(F("Found an ISO14443A tag"));
    Serial.print(F("  UID Length: "));
    Serial.print(uidLength, DEC);
    Serial.println(F(" bytes"));
    Serial.print(F("  UID Value: "));
    bolty_print_hex(nfc, uid, uidLength);
    Serial.println();

    if (!(((uidLength == 7) || (uidLength == 4)) && nfc->ntag424_isNTAG424())) {
      Serial.println(F("This doesn't seem to be an NTAG424 tag."));
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }

    const uint8_t kv = bolty_get_key_version(nfc, 0);
    if (kv != 0x00) {
      Serial.print(F("ABORT: Key 0 version is 0x"));
      if (kv < 0x10) {
        Serial.print(F("0"));
      }
      Serial.print(kv, HEX);
      Serial.println(F(" — resetNdefOnly requires factory keys. Use 'wipe' instead."));
      set_job_status_id(JOBSTATUS_GUARD_REJECT);
      return job_status;
    }

    Serial.println(F("Pre-reset check OK — key 0 is factory default"));
    selectNtagApplicationFiles();

    uint8_t zero_key[16] = {0};
    if (nfc->ntag424_Authenticate(zero_key, 0, 0x71) != 1) {
      Serial.println(F("Authentication with zero key FAILED."));
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }
    Serial.println(F("Authentication successful (factory zero key)."));

    Serial.println(F("Disabling SDM and resetting file settings..."));
    uint8_t fileSettings[] = {0x00, 0x00, 0xE0};
    nfc->ntag424_ChangeFileSettings((uint8_t)2, fileSettings,
                                    (uint8_t)sizeof(fileSettings),
                                    (uint8_t)NTAG424_COMM_MODE_FULL);

    selectNtagApplicationFiles();
    nfc->ntag424_Authenticate(zero_key, 0, 0x71);
    if (nfc->ntag424_FormatNDEF()) {
      Serial.println(F("NDEF formatted OK."));
    } else {
      Serial.println(F("NDEF format skipped (already blank)."));
    }
    job_perc = 100;

    selectNtagApplicationFiles();
    const uint8_t verify_auth = nfc->ntag424_Authenticate(zero_key, 0, 0x71);
    if (verify_auth == 1) {
      Serial.println(F("Verify auth OK — keys unchanged."));
    } else {
      Serial.println(F("WARNING: Verify auth failed (unexpected)."));
    }

    set_job_status_id(JOBSTATUS_DONE);
    return job_status;
  }

  uint8_t wipe() {
    uint8_t uid[12] = {0};
    uint8_t uidLength = 0;
    set_job_status_id(JOBSTATUS_WAITING);

    if (!bolty_read_passive_target(nfc, uid, &uidLength)) {
      return job_status;
    }

    set_job_status_id(JOBSTATUS_WIPING);
    Serial.println("Found an ISO14443A tag");
    Serial.print("  UID Length: ");
    Serial.print(uidLength, DEC);
    Serial.println(" bytes");
    Serial.print("  UID Value: ");
    bolty_print_hex(nfc, uid, uidLength);
    Serial.println("");

    if (!(((uidLength == 7) || (uidLength == 4)) && nfc->ntag424_isNTAG424())) {
      Serial.println("This doesn't seem to be an NTAG424 tag. (UUID length != 7 bytes and UUID length != 4)!");
      return job_status;
    }

    uint8_t kv = bolty_get_key_version(nfc, 1);
    if (kv == 0x00) {
      Serial.println(F("ABORT: Card key 1 version is 0x00 - card already has factory keys."));
      set_job_status_id(JOBSTATUS_GUARD_REJECT);
      return job_status;
    }

    Serial.print(F("Pre-wipe check OK - card key 1 version: 0x"));
    if (kv < 0x10) {
      Serial.print(F("0"));
    }
    Serial.println(kv, HEX);
    selectNtagApplicationFiles();

    if (nfc->ntag424_Authenticate(key_cur[0], 0, 0x71) != 1) {
      Serial.println("Authentication failed.");
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }

    Serial.println("Authentication successful.");
    Serial.println("Disable Mirroring and SDM.");
    uint8_t fileSettings[] = {0x00, 0x00, 0xE0};
    nfc->ntag424_ChangeFileSettings((uint8_t)2, fileSettings,
                                    (uint8_t)sizeof(fileSettings),
                                    (uint8_t)NTAG424_COMM_MODE_FULL);

    if (!changeAllKeys(0x00)) {
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }

    selectNtagApplicationFiles();
    if (nfc->ntag424_FormatNDEF()) {
      job_perc = 100;
    }

    const uint8_t authenticated = nfc->ntag424_Authenticate(key_new[0], 0, 0x71);
    if (authenticated == 1) {
      Serial.println("Authentication 2 Success.");
      set_job_status_id(JOBSTATUS_DONE);
    } else {
      Serial.println("Authentication 2 failed.");
      set_job_status_id(JOBSTATUS_ERROR);
    }
    return job_status;
  }
};

#endif
