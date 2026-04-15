#ifndef BOLT_H
#define BOLT_H

//#define NTAG424DEBUG
//#define PN532DEBUG

#include "gui.h"
#include "hardware_config.h"
#include <Adafruit_PN532_NTAG424.h>
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
static const uint16_t NTAG424_CC_FILE_ID = 0xE103;
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
  char uid[17];
  char k0[33];
  char k1[33];
  char k2[33];
  char k3[33];
  char k4[33];
};

String convertIntToHex(uint8_t *input, uint8_t len) {
  String ret = "";
  for (uint8_t i = 0; i < len; i++) {
    char hexChar[3];
    sprintf(hexChar, "%02X", input[i]);
    ret += hexChar;
  }
  return ret;
}

uint8_t convertCharToHex(char ch) {
  const char upper = toupper(ch);
  if (upper >= '0' && upper <= '9') {
    return upper - '0';
  }
  if (upper >= 'A' && upper <= 'F') {
    return upper - 'A' + 10;
  }
  return 0;
}

uint8_t ntag424_getKeyVersion(Adafruit_PN532 *nfc, uint8_t keyno) {
  if (!nfc->ntag424_ISOSelectFileByDFN((uint8_t *)NTAG424_AID)) return 0xFF;
  uint8_t version = 0xFF;
  if (nfc->ntag424_GetKeyVersion(keyno, &version)) return version;
  return 0xFF;
}

class BoltDevice {

public: // Access specifier
  Adafruit_PN532 *nfc = NULL;
  uint8_t key_cur[5][16] = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};
  uint8_t key_new[5][16] = {{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
                            {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}};

  uint8_t job_status; // 0=idle; 1=wait for tag; 2=busy provisioning;3=busy wipe
  uint8_t job_perc;
  uint8_t job_ok;
  uint8_t _consecutive_scan_failures = 0;
  static const uint8_t MAX_SCAN_FAILURES = 5;
  static const unsigned long REINIT_BACKOFF_MS = 30000;
  unsigned long _last_pn532_reinit_ms = 0;
  String last_scanned_uid;

  BoltDevice(uint8_t SCK, uint8_t MISO, uint8_t MOSI,
             uint8_t SS) { // Constructor
    nfc = new Adafruit_PN532(SCK, MISO, MOSI, SS);
  }

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

  bool selectNdefFileOnly() {
    return nfc->ntag424_ISOSelectNDEFFile();
  }

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
    // Serial.print("Key Set: ");
    // Serial.println(key);
  }

  void setNewKey(String key, uint8_t keyno) { setKey(key_new[keyno], key); }

  void setCurKey(String key, uint8_t keyno) { setKey(key_cur[keyno], key); }

  bool begin() {

    nfc->begin();

    uint32_t versiondata = nfc->getFirmwareVersion();
    if (!versiondata) {
      Serial.print("Didn't find PN53x board");
      return false;
        ; // halt
    }
    // Got ok data, print it out!
    Serial.print("Found chip PN53x");
    Serial.println((versiondata >> 24) & 0xFF, HEX);
    Serial.print("Firmware ver. ");
    Serial.print((versiondata >> 16) & 0xFF, DEC);
    Serial.print('.');
    Serial.println((versiondata >> 8) & 0xFF, DEC);

    // configure board to read RFID tags
    nfc->SAMConfig();
    _consecutive_scan_failures = 0;
    _last_pn532_reinit_ms = 0;

    Serial.println("NFC Ready...");
    return true;
  }

  bool reinitPN532() {
    // Issue #7: this SPI build passes no reset pin to Adafruit_PN532, so the
    // library reset path is a no-op and recovery must drive RSTPD_N directly.
    _last_pn532_reinit_ms = millis();
    pinMode(PN532_RSTPD_N, OUTPUT);
    digitalWrite(PN532_RSTPD_N, LOW);
    delay(100);
    digitalWrite(PN532_RSTPD_N, HIGH);
    delay(10);

    nfc->begin();

    uint32_t versiondata = nfc->getFirmwareVersion();
    if (!versiondata) {
      Serial.println("PN532 reinit failed: firmware query returned no data");
      return false;
    }

    nfc->SAMConfig();
    _last_pn532_reinit_ms = millis();
    Serial.println("PN532 reinit complete");
    return true;
  }

  String get_job_status() { return boltstatustext[job_status]; }

  uint8_t get_job_perc() { return job_perc; }

  uint8_t get_job_status_id() { return job_status; }

  void set_job_status_id(uint8_t new_status) {
    job_status = new_status;
#if HAS_DISPLAY
    uint16_t statcolor = APPBLACK;
    if (job_status == JOBSTATUS_ERROR) {
      statcolor = APPRED;

    } else if (job_status == JOBSTATUS_WIPING) {
      statcolor = APPORANGE;
    } else if (job_status == JOBSTATUS_PROVISIONING) {
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

  long lastscan = 0;

  bool scanUID() {
    uint8_t success;
    uint8_t uid[] = {0, 0, 0, 0, 0, 0,
                     0, 0, 0, 0, 0, 0}; // Buffer to store the returned UID
    uint8_t uidLength; // Length of the UID (4 or 7 bytes depending on ISO14443A
                       // card type)
    if ((millis() - lastscan) > 2000) {
      last_scanned_uid = "";
    };
    // Wait for an NTAG203 card.  When one is found 'uid' will be populated with
    // the UID, and uidLength will indicate the size of the UUID (normally 7)
    success =
        nfc->readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength, 100);
    if (success) {
      _consecutive_scan_failures = 0;
      nfc->PrintHex(uid, uidLength);
      if (((uidLength == 7) || (uidLength == 4)) &&
          (nfc->ntag424_isNTAG424())) {
        lastscan = millis();
        last_scanned_uid = convertIntToHex(uid, uidLength);
        return true;
      }
    } else {
      _consecutive_scan_failures++;
      // Issue #7 / ESPEasy pattern: repeated passive-read failures can mean the
      // RF field is stuck, but normal idle polling also returns false, so keep a
      // cooldown to avoid reset loops while no card is present.
      if (_consecutive_scan_failures >= MAX_SCAN_FAILURES &&
          (_last_pn532_reinit_ms == 0 ||
           (millis() - _last_pn532_reinit_ms) >= REINIT_BACKOFF_MS)) {
        Serial.println("PN532 scan failures exceeded threshold, reinitializing");
        if (reinitPN532()) {
          _consecutive_scan_failures = 0;
        }
      }
    }
    return false;
  }

  String getScannedUid() { return last_scanned_uid; }

  uint8_t burn(String lnurl) {
    uint8_t success = true;
    uint8_t uid[] = {0, 0, 0, 0, 0, 0, 0}; // Buffer to store the returned UID
    uint8_t uidLength; // Length of the UID (4 or 7 bytes depending on ISO14443A
                       // card type)
    job_status = JOBSTATUS_WAITING;
    set_job_status_id(JOBSTATUS_WAITING);
    // Wait for an NTAG203 card.  When one is found 'uid' will be populated with
    // the UID, and uidLength will indicate the size of the UUID (normally 7)
    success =
        nfc->readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength, 100);
    if (success) {
      set_job_status_id(JOBSTATUS_PROVISIONING);
      // Display some basic information about the card
      Serial.println("Found an ISO14443A tag");
      Serial.print("  UID Length: ");
      Serial.print(uidLength, DEC);
      Serial.println(" bytes");
      Serial.print("  UID Value: ");
      nfc->PrintHex(uid, uidLength);
      Serial.println("");

      //&& (nfc->ntag424_isNTAG424())
      if (((uidLength == 7) || (uidLength == 4)) &&
          (nfc->ntag424_isNTAG424())) {
        // Pre-burn guard: reject if card is already provisioned
        uint8_t kv = ntag424_getKeyVersion(nfc, 1);
        if (kv != 0x00) {
          Serial.print(F("ABORT: Card key 1 version is 0x"));
          if (kv < 0x10) Serial.print(F("0"));
          Serial.print(kv, HEX);
          Serial.println(F(" - card appears provisioned. Wipe first."));
          set_job_status_id(JOBSTATUS_GUARD_REJECT);
          return job_status;
        }
        Serial.println(F("Pre-burn check OK - card has factory keys"));
        selectNtagApplicationFiles();
        uint8_t uriIdentifier = 0;
        int piccDataOffset = lnurl.length() + 10;
        int sdmMacOffset = lnurl.length() + 45;
        lnurl += "?p=00000000000000000000000000000000&c=0000000000000000";
        uint8_t len = lnurl.length();
        uint8_t ndefheader[7] = {
            0x0,     /* Tag Field (0x03 = NDEF Message) */
            static_cast<uint8_t>(len + 5), /* Payload Length (not including 0xFE trailer) */
            0xD1, /* NDEF Record Header (TNF=0x1:Well known record + SR + ME +
                     MB) */
            0x01, /* Type Length for the record type indicator */
            (uint8_t)(len + 1), /* Payload len */
            0x55,         /* Record Type Indicator (0x55 or 'U' = URI Record) */
            uriIdentifier /* URI Prefix (ex. 0x01 = "http://www.") */
        };
        uint8_t *filedata = (uint8_t *)malloc(len + sizeof(ndefheader));
        memcpy(filedata, ndefheader, sizeof(ndefheader));
        memcpy(filedata + sizeof(ndefheader), lnurl.c_str(), lnurl.length());
        nfc->ntag424_ISOUpdateBinary(filedata, len + sizeof(ndefheader));
        free(filedata);
        uint8_t keyno = 0;
        uint8_t authenticated =
            nfc->ntag424_Authenticate(key_cur[keyno], keyno, 0x71);

        if (authenticated == 1) {
          Serial.println("Authentication successful.");
          Serial.println("Enable Mirroring and SDM.");
          // int piccDataOffset = 81;
          // int sdmMacOffset = 116;
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

           success &= changeAllKeys(0x01);
           if (!success) {
             set_job_status_id(JOBSTATUS_ERROR);
             return job_status;
           }
          } else {
          Serial.println("Authentication 1 failed.");
          set_job_status_id(JOBSTATUS_ERROR);
          return job_status;
        }
        authenticated = 0;
        authenticated = nfc->ntag424_Authenticate(key_new[0], 0, 0x71);
        // Display the current page number
        Serial.print("Response ");
        // Display the results, depending on 'success'
        if (authenticated == 1) {
          Serial.println("Authentication 2 Success.");
          set_job_status_id(JOBSTATUS_DONE);
        } else {
          Serial.println("Authentication 2 failed.");
          set_job_status_id(JOBSTATUS_ERROR);
        }
      } else {
        Serial.println("This doesn't seem to be an NTAG424 tag. (UUID length "
                       "!= 7 bytes and UUID length != 4)!");
      }
    }
    return job_status;
  }

  uint8_t resetNdefOnly() {
    uint8_t success;
    uint8_t uid[] = {0, 0, 0, 0, 0, 0, 0};
    uint8_t uidLength;

    set_job_status_id(JOBSTATUS_WAITING);
    success = nfc->readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength, 100);
    if (!success) {
      return job_status;
    }

    set_job_status_id(JOBSTATUS_WIPING);
    Serial.println(F("Found an ISO14443A tag"));
    Serial.print(F("  UID Length: "));
    Serial.print(uidLength, DEC);
    Serial.println(F(" bytes"));
    Serial.print(F("  UID Value: "));
    nfc->PrintHex(uid, uidLength);
    Serial.println();

    if (((uidLength == 7) || (uidLength == 4)) && (nfc->ntag424_isNTAG424())) {
      uint8_t kv = ntag424_getKeyVersion(nfc, 0);
      if (kv != 0x00) {
        Serial.print(F("ABORT: Key 0 version is 0x"));
        if (kv < 0x10) Serial.print(F("0"));
        Serial.print(kv, HEX);
        Serial.println(F(" — resetNdefOnly requires factory keys. Use 'wipe' instead."));
        set_job_status_id(JOBSTATUS_GUARD_REJECT);
        return job_status;
      }
      Serial.println(F("Pre-reset check OK — key 0 is factory default"));

      selectNtagApplicationFiles();

      uint8_t zero_key[16] = {0};
      uint8_t authenticated = nfc->ntag424_Authenticate(zero_key, 0, 0x71);
      if (authenticated != 1) {
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
      uint8_t verify_auth = nfc->ntag424_Authenticate(zero_key, 0, 0x71);
      if (verify_auth == 1) {
        Serial.println(F("Verify auth OK — keys unchanged."));
      } else {
        Serial.println(F("WARNING: Verify auth failed (unexpected)."));
      }

      set_job_status_id(JOBSTATUS_DONE);
    } else {
      Serial.println(F("This doesn't seem to be an NTAG424 tag."));
      set_job_status_id(JOBSTATUS_ERROR);
    }
    return job_status;
  }

  uint8_t wipe() {
    uint8_t success = true;
    uint8_t uid[] = {0, 0, 0, 0, 0, 0, 0}; // Buffer to store the returned UID
    uint8_t uidLength; // Length of the UID (4 or 7 bytes depending on ISO14443A
                       // card type)

    // Wait for an NTAG203 card.  When one is found 'uid' will be populated with
    // the UID, and uidLength will indicate the size of the UUID (normally 7)

    set_job_status_id(JOBSTATUS_WAITING);
    // Wait for an NTAG203 card.  When one is found 'uid' will be populated with
    // the UID, and uidLength will indicate the size of the UUID (normally 7)
    success =
        nfc->readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength, 100);
    if (success) {
      set_job_status_id(JOBSTATUS_WIPING);
      // Display some basic information about the card
      Serial.println("Found an ISO14443A tag");
      Serial.print("  UID Length: ");
      Serial.print(uidLength, DEC);
      Serial.println(" bytes");
      Serial.print("  UID Value: ");
      nfc->PrintHex(uid, uidLength);
      Serial.println("");

      //&& (nfc->ntag424_isNTAG424())
      if (((uidLength == 7) || (uidLength == 4)) &&
          (nfc->ntag424_isNTAG424())) {
        // Pre-wipe guard: reject if card already has factory keys
        uint8_t kv = ntag424_getKeyVersion(nfc, 1);
        if (kv == 0x00) {
          Serial.println(F("ABORT: Card key 1 version is 0x00 - card already has factory keys."));
          set_job_status_id(JOBSTATUS_GUARD_REJECT);
          return job_status;
        }
        Serial.print(F("Pre-wipe check OK - card key 1 version: 0x"));
        if (kv < 0x10) Serial.print(F("0"));
        Serial.println(kv, HEX);
        selectNtagApplicationFiles();
        uint8_t keyno = 0;
        uint8_t authenticated =
            nfc->ntag424_Authenticate(key_cur[keyno], keyno, 0x71);

        // Display the current page number
        Serial.print("Response ");
        // Display the results, depending on 'success'
        if (authenticated == 1) {
          Serial.println("Authentication successful.");
          Serial.println("Disable Mirroring and SDM.");
          uint8_t fileSettings[] = {0x00, 0x00, 0xE0};

          nfc->ntag424_ChangeFileSettings((uint8_t)2, fileSettings,
                                          (uint8_t)sizeof(fileSettings),
                                          (uint8_t)NTAG424_COMM_MODE_FULL);

          success &= changeAllKeys(0x00);
          if (!success) {
            set_job_status_id(JOBSTATUS_ERROR);
            return job_status;
          }

          selectNtagApplicationFiles();

          if (nfc->ntag424_FormatNDEF()) {
            job_perc = 100;
          }
        } else {
          Serial.println("Authentication failed.");
          success = false;
          set_job_status_id(JOBSTATUS_ERROR);
          return job_status;
        }
        // try authenticating with the new key
        authenticated = 0;
        authenticated = nfc->ntag424_Authenticate(key_new[0], 0, 0x71);
        if (authenticated == 1) {
          Serial.println("Authentication 2 Success.");
          set_job_status_id(JOBSTATUS_DONE);
        } else {
          Serial.println("Authentication 2 failed.");
          set_job_status_id(JOBSTATUS_ERROR);
        }
      } else {
        Serial.println("This doesn't seem to be an NTAG424 tag. (UUID length "
                       "!= 7 bytes and UUID length != 4)!");
      }
    }
    return job_status;
  }
};
#endif
