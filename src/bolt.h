#ifndef BOLT_H
#define BOLT_H

//#define NTAG424DEBUG
//#define PN532DEBUG

#include "gui.h"
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
    char hexChar[2];
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

// GetKeyVersion — plain commode, requires ISOSelectFileByDFN first.
// Returns the version byte for the given key (0-4), or 0xFF on error.
//
// Key version semantics (NXP NTAG424 DNA, AN12195):
//   - Per-key version byte stored on the card (keys 0-4 each have their own)
//   - Factory default: 0x00 for all keys
//   - Set by the ChangeKey APDU — the card stores whatever byte is sent
//   - Does NOT auto-increment; it's a write-once-per-change value
//   - Used to detect if keys have been changed from factory defaults
//   - Official apps (bolt-nfc-android-app) pass keyVersion as a parameter
//     and use it to detect provisioning state: 0x00 = blank, != 0x00 = provisioned
//   - APDU: `90 64 00 00 01 {keyNo} 00` -- PLAIN commode, no auth needed
//
  // Practical implications for our firmware:
  //   - After factory reset: all keys at 0x00
  //   - keyver command checks these versions to determine card state
  //   - Pre-burn guard rejects if key 1 version != 0x00
uint8_t ntag424_getKeyVersion(Adafruit_PN532 *nfc, uint8_t keyno) {
  nfc->ntag424_ISOSelectFileByDFN((uint8_t *)NTAG424_AID);
  uint8_t cla[] = {0x90};
  uint8_t ins[] = {0x64};
  uint8_t p1[] = {0x00};
  uint8_t p2[] = {0x00};
  uint8_t cmd_header[] = {keyno};
  uint8_t result[16];
  int len = nfc->ntag424_apdu_send(cla, ins, p1, p2,
      cmd_header, sizeof(cmd_header), NULL, 0, 0,
      NTAG424_COMM_MODE_PLAIN, result, sizeof(result));
  if (len >= 1) return result[0];
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
           nfc->ntag424_ISOSelectFileById(NTAG424_CC_FILE_ID) &&
           nfc->ntag424_ISOSelectFileById(NTAG424_NDEF_FILE_ID);
  }

  bool selectNdefFileOnly() {
    return nfc->ntag424_ISOSelectFileByDFN((uint8_t *)NTAG424_AID) &&
           nfc->ntag424_ISOSelectFileById(NTAG424_NDEF_FILE_ID);
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

    Serial.println("NFC Ready...");
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
      nfc->PrintHex(uid, uidLength);
      if (((uidLength == 7) || (uidLength == 4)) &&
          (nfc->ntag424_isNTAG424())) {
        lastscan = millis();
        last_scanned_uid = convertIntToHex(uid, uidLength);
        return true;
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
          uint8_t fileSettings[] = {0x40, 0xE0, 0xEE, 0x01, 0xFF, 0xFF};

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
