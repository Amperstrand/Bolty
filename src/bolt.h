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

    if (!selectNtagApplicationFiles()) {
      Serial.println(F("Failed to select NTAG application files."));
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }

    // Native AuthenticateEV2First: cmd=0x71 (NT4H2421Gx §7.3.1.1).
    // Using key_cur[0] (factory zero key) with key number 0.
    const uint8_t auth_result = nfc->ntag424_Authenticate(key_cur[0], 0, 0x71);
    if (auth_result != 1) {
      Serial.println(F("Native auth with factory key failed."));
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }
    Serial.println(F("Auth OK."));

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
      Serial.println(F("Failed to allocate NDEF buffer."));
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
      Serial.println(F("NDEF write failed via native WriteData."));
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }
    Serial.println(F("NDEF written successfully."));
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
    nfc->ntag424_ChangeFileSettings((uint8_t)2, fileSettings,
                                    (uint8_t)sizeof(fileSettings),
                                    // NTAG424_COMM_MODE_FULL: AES-128 encrypt +
                                    // CMAC on command and response.
                                    // Ref: NT4H2421Gx datasheet §7.6.2
                                    (uint8_t)NTAG424_COMM_MODE_FULL);

    // Change all 5 application keys. Key version 0x01 marks the card as
    // provisioned (factory = 0x00). Keys changed in reverse order (4→0)
    // to avoid losing access mid-operation.
    // Ref: NT4H2421Gx datasheet §7.3.2, AN12196 §6.3
    if (!changeAllKeys(0x01)) {
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }

    // Verify new keys work: AuthenticateEV2First with new key 0
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
    // Reset file 2 settings: disable SDM, keep Plain read/write access.
    // {0x00, 0x00, 0xE0} = no SDM mirroring, free access, standard file.
    // Ref: NT4H2421Gx datasheet §7.6.2 Table 49
    uint8_t fileSettings[] = {0x00, 0x00, 0xE0};
    nfc->ntag424_ChangeFileSettings((uint8_t)2, fileSettings,
                                    (uint8_t)sizeof(fileSettings),
                                    (uint8_t)NTAG424_COMM_MODE_FULL);

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
    if (nfc->ntag424_Authenticate(key_new[0], 0, 0x71) != 1) {
      Serial.println("Re-authentication after key change failed.");
      set_job_status_id(JOBSTATUS_ERROR);
      return job_status;
    }

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
