/**************************************************************************/
/*!
    @file     bolty.ino
    @author   Thilo
    https://github.com/bitcoin-ring/Bolty
    This sketch will start a wifi in AP or STA mode (WIFIMODE_*). If you want to
   use STA mode you have to enter the WIFI credentials of your existing network.
    A webserver allows to import keydata  in form of the raw json of the lnbits
   "Card key credentials" link. The keydata is saved on the eepom and should
   therefore be availabe after reboot/powerdown. The saved keydata can be used
   to provision/burn or wipe/delete ntag424 tags i.E. BoltCard, BoltRing.
    Button1:
    - śhort press: Load next boltconfiguration/keyset
    - long press: toggle wifi on/off
    Button2:
    - śhort press: Toggle between burn and wipe
    - long press: sleepmode

*/
/**************************************************************************/
#include <Arduino.h>
#include "bolt.h"
#include "bolty_utils.h"
#include "PiccData.h"
#include "Bolt11Decode.h"
#include "KeyDerivation.h"
#include "build_metadata.h"
#if HAS_WIFI
#include "gui.h"
#endif
#include "led.h"
#include "http_probe.h"
#include <SPI.h>
#include "FS.h"
#include "SPIFFS.h"

#if HAS_WEB_LOOKUP
#include <WiFi.h>
#include <HTTPClient.h>
#endif

#if HAS_WIFI
#include <WiFi.h>
#include <Wire.h>
#include <esp_wifi.h>
#if HAS_DISPLAY
#include <qrcode_rep.h>
#endif
#define DYNAMIC_JSON_DOCUMENT_SIZE 1024
#include "ArduinoJson.h"
#include "AsyncJson.h"
#include "ESPAsyncWebServer.h"
#include <WiFiAP.h>
#define DEST_FS_USES_SPIFFS
#include <ESP32-targz.h>
#include "tarstream.h"
#include "tardata.h"
#endif

#if BOLTY_OTA_ENABLED
#include "ota.h"
#endif

#if HAS_REST_SERVER
#include <esp_wifi.h>
#include <WiFi.h>
#include "bolty_rest_server.h"
#endif

#if HAS_WIFI
#define WIFIMODE_AP 0
#define WIFIMODE_STA 1

#define CONFIGVERSION 1
#endif

#define WIFI_AP_PASSWORD_LENGTH 8

// uncommment the next line for static wifi password
//#define WIFI_AP_PASSWORD_STATIC "wango123"

#if HAS_WIFI
#define HTTP_CREDENTIAL_SIZE 16
const char* http_default_username = "bolty";
const char* http_default_password = "bolty";
#define MAX_BOLT_DEVICES 5
char charpool[] = {
    "qweertzunopaasdfghjkyxcvbnm-?234567890QWEERTYUOPAASDFGHJKLZXCVBNM"};
#endif

#if HAS_WIFI
char *ap_ssid = "Bolty";
#ifdef WIFI_AP_PASSWORD_STATIC
char ap_password[] = WIFI_AP_PASSWORD_STATIC;
#else
char ap_password[WIFI_AP_PASSWORD_LENGTH];
#endif

AsyncWebServer server(80);
const char *PARAM_CONFIG = "config";
#endif

// Hardware pin configuration — see hardware_config.h for board presets
#include "hardware_config.h"
// For RSTPD_N to work on TTGO, the author had to desolder a 10k pull-up
// between RSTPD_N and VCC. This is not needed on DevKitC.

#if HAS_WIFI
#define APPS (3)
#define APP_KEYSETUP (0)
#define APP_BOLTBURN (1)
#define APP_BOLTWIPE (2)

#define APP_STATUS_START (0)
#define APP_STATUS_LOOP (1)
#define APP_STATUS_END (2)
#endif

#if BOLTY_NFC_BACKEND_MFRC522
BoltDevice bolt(MFRC522_I2C_ADDRESS);
#elif BOLTY_NFC_BACKEND_PN532_UART
HardwareSerial PN532Serial(2);
BoltDevice bolt(PN532_RSTPD_N, &PN532Serial);
#else
BoltDevice bolt(PN532_SCK, PN532_MISO, PN532_MOSI, PN532_SS);
#endif

// Forward declarations (needed for PlatformIO — Arduino IDE auto-generates these)
void dumpconfig();
void dumpsettings();

#if HAS_WIFI
bool SendQR(String input, AsyncResponseStream *response);
void checkparams(AsyncWebServerRequest *request);
void handleUpload(AsyncWebServerRequest *request, String filename, size_t index,
                  uint8_t *data, size_t len, bool final);
#endif

struct DeterministicBoltcardMatch;
static bool deterministic_try_known_matches(BoltyNfcReader *nfc,
                                            const uint8_t *uid,
                                            uint8_t uid_len,
                                            const String &uri,
                                            DeterministicBoltcardMatch &match);

#if HAS_WIFI
struct sSettings {
  char essid[33];
  char password[65];
  uint8_t wifimode;
  bool wifi_enabled;
  char http_username[HTTP_CREDENTIAL_SIZE];
  char http_password[HTTP_CREDENTIAL_SIZE];
};
sSettings mSettings;

uint8_t app_active;
int8_t app_next;
uint8_t app_status;
String SIpAddress = "Waiting for ip..";
IPAddress myIP;
#endif

uint8_t active_bolt_config;
sBoltConfig mBoltConfig;

bool signal_update_screen = false;
volatile bool serial_cmd_active = false;
int signal_restart_delayed = 0;

bool bolty_hw_ready = false;
static bool atom_hold_action_fired = false;

bool has_issuer_key = false;

#if HAS_WEB_LOOKUP
static bool wifi_connected = false;
static char web_lookup_url[128] = "https://boltcardpoc.psbt.me/api/keys";
#endif

enum class IdleCardKind : uint8_t {
  none = 0,
  blank,
  unknown,
  programmed,
};

enum class KeyConfidence : uint8_t {
  unknown = 0,
  partial,
  high,
};

struct CardAssessment {
  bool present;
  bool is_ntag424;
  uint8_t uid[12];
  uint8_t uid_len;
  IdleCardKind kind;
  uint8_t key_versions[5];
  KeyConfidence key_confidence[5];
  bool zero_key_auth_ok;
  bool has_ndef;
  bool has_uri;
  bool looks_like_boltcard;
  bool deterministic_k1_match;
  bool deterministic_full_match;
  String uri;
  uint8_t derived_keys[5][16];
  bool reset_eligible;
};

static CardAssessment g_last_assessment = {};

static void reset_card_assessment(CardAssessment &assessment) {
  memset(&assessment, 0, sizeof(assessment));
  assessment.kind = IdleCardKind::none;
  for (int i = 0; i < 5; i++) {
    assessment.key_versions[i] = 0xFF;
    assessment.key_confidence[i] = KeyConfidence::unknown;
  }
}

static bool same_uid(const CardAssessment &assessment, const uint8_t *uid, uint8_t uid_len) {
  return assessment.present && assessment.uid_len == uid_len && crypto_memcmp(assessment.uid, uid, uid_len);
}

static IdleCardKind classify_idle_card(const uint8_t *uid, uint8_t uid_len) {
  if (!(((uid_len == 7) || (uid_len == 4)) && bolt.nfc->ntag424_isNTAG424())) {
    return IdleCardKind::unknown;
  }

  const uint8_t kv1 = bolty_get_key_version(bolt.nfc, 1);
  if (kv1 == 0x00) {
    return IdleCardKind::blank;
  }

  uint8_t ndef[256] = {0};
  const int ndef_len = bolt.nfc->ntag424_ReadNDEFMessage(ndef, sizeof(ndef));
  if (ndef_len > 0) {
    String uri;
    if (ndef_extract_uri(ndef, ndef_len, uri)) {
      const bool has_lnurlw = uri.startsWith("lnurlw://") || uri.indexOf("lnurlw://") >= 0;
      String p_hex;
      String c_hex;
      const bool has_p = uri_get_query_param(uri, "p", p_hex);
      const bool has_c = uri_get_query_param(uri, "c", c_hex);
      if (has_lnurlw || (has_p && has_c)) {
        return IdleCardKind::programmed;
      }
    }
  }

  return IdleCardKind::unknown;
}

static void signal_idle_card_kind(IdleCardKind kind) {
  switch (kind) {
    case IdleCardKind::blank:
      Serial.println("[nfc] classified: blank/factory");
      led_signal_card_blank();
      break;
    case IdleCardKind::programmed:
      Serial.println("[nfc] classified: programmed bolt card");
      led_signal_card_programmed();
      break;
    case IdleCardKind::unknown:
      Serial.println("[nfc] classified: unknown");
      led_signal_card_unknown();
      break;
    default:
      break;
  }
}

static void assessment_to_led_rows(const CardAssessment &assessment, uint8_t rows[5]) {
  for (int i = 0; i < 5; i++) {
    switch (assessment.key_confidence[i]) {
      case KeyConfidence::high:
        rows[i] = 2;
        break;
      case KeyConfidence::partial:
        rows[i] = 1;
        break;
      default:
        rows[i] = 0;
        break;
    }
  }
}

static void print_card_assessment(const CardAssessment &assessment) {
  Serial.println(F("[assess] --- Card Assessment ---"));
  Serial.print(F("[assess] UID: "));
  bolty_print_hex(bolt.nfc, assessment.uid, assessment.uid_len);
  Serial.print(F("[assess] NTAG424: "));
  Serial.println(assessment.is_ntag424 ? F("YES") : F("NO"));
  Serial.print(F("[assess] Class: "));
  switch (assessment.kind) {
    case IdleCardKind::blank: Serial.println(F("blank")); break;
    case IdleCardKind::programmed: Serial.println(F("programmed")); break;
    case IdleCardKind::unknown: Serial.println(F("unknown")); break;
    default: Serial.println(F("none")); break;
  }
  for (int i = 0; i < 5; i++) {
    Serial.print(F("[assess] Key "));
    Serial.print(i);
    Serial.print(F(" ver=0x"));
    if (assessment.key_versions[i] < 0x10) Serial.print(F("0"));
    Serial.print(assessment.key_versions[i], HEX);
    Serial.print(F(" confidence="));
    switch (assessment.key_confidence[i]) {
      case KeyConfidence::high: Serial.println(F("high")); break;
      case KeyConfidence::partial: Serial.println(F("partial")); break;
      default: Serial.println(F("unknown")); break;
    }
  }
  Serial.print(F("[assess] Zero-key auth: "));
  Serial.println(assessment.zero_key_auth_ok ? F("YES") : F("NO"));
  Serial.print(F("[assess] Has NDEF: "));
  Serial.println(assessment.has_ndef ? F("YES") : F("NO"));
  Serial.print(F("[assess] Looks like Bolt Card: "));
  Serial.println(assessment.looks_like_boltcard ? F("YES") : F("NO"));
  if (assessment.uri.length() > 0) {
    Serial.print(F("[assess] URI: "));
    Serial.println(assessment.uri);
  }
  Serial.print(F("[assess] Reset eligible: "));
  Serial.println(assessment.reset_eligible ? F("YES") : F("NO"));
}

static bool assess_current_card(CardAssessment &assessment);

static void handle_atom_button_feedback() {
#if HAS_LED_MATRIX
  if (sharedvars.appbuttons[0] == 1) {
    Serial.println("[button] Atom BtnA click — assessing card");
    CardAssessment assessment;
    if (!assess_current_card(assessment)) {
      Serial.println("[assess] No card detected for click assessment");
      led_signal_card_unknown();
      led_tick();
      return;
    }
    g_last_assessment = assessment;
    print_card_assessment(assessment);
    uint8_t rows[5] = {0};
    assessment_to_led_rows(assessment, rows);
    switch (assessment.kind) {
      case IdleCardKind::blank: led_signal_card_blank(); break;
      case IdleCardKind::programmed: led_signal_card_programmed(); break;
      default: led_signal_card_unknown(); break;
    }
    led_show_key_assessment(rows, 2500);
    led_tick();
#if HAS_HTTP_PROBE
    if (mBoltConfig.wifi_probe_enabled && assessment.has_uri && assessment.uri.length() > 0) {
      http_probe_url(assessment.uri);
    }
#endif
  } else if (sharedvars.appbuttons[0] == 2) {
    Serial.println("[button] Atom BtnA hold event");
  }
#endif
}

static void handle_atom_hold_reset() {
#if HAS_LED_MATRIX
  if (!button_is_held()) {
    atom_hold_action_fired = false;
    return;
  }

  if (atom_hold_action_fired) {
    return;
  }

  uint8_t rows = 0;
  if (button_pressed_for(400)) rows = 1;
  if (button_pressed_for(800)) rows = 2;
  if (button_pressed_for(1200)) rows = 3;
  if (button_pressed_for(1600)) rows = 4;
  if (button_pressed_for(2000)) rows = 5;
  if (rows > 0) {
    led_show_hold_countdown(rows, 120);
  }

  if (!button_pressed_for(2000)) {
    return;
  }

  atom_hold_action_fired = true;
  Serial.println("[button] Atom BtnA long hold — validating reset");

  CardAssessment fresh;
  if (!assess_current_card(fresh)) {
    Serial.println("[button] Reset refused — no card present");
    led_signal_result(false);
    led_tick();
    return;
  }

  g_last_assessment = fresh;
  print_card_assessment(fresh);
  if (!fresh.reset_eligible) {
    Serial.println("[button] Reset refused — insufficient confidence");
    led_signal_result(false);
    led_tick();
    return;
  }

  if (fresh.kind == IdleCardKind::blank) {
    Serial.println("[button] Blank card detected — using factory reset path");
    const uint8_t result = bolt.resetNdefOnly();
    Serial.print("[button] resetNdefOnly -> ");
    Serial.println(result == JOBSTATUS_DONE ? "SUCCESS" : "FAILED");
    led_signal_result(result == JOBSTATUS_DONE);
    led_tick();
    return;
  }

  if (fresh.deterministic_full_match) {
    Serial.println(F("[button] Deterministic full match — loading derived keys"));
    Serial.print(F("[button] Derived K0: "));
    for (int b = 0; b < 16; b++) { if (fresh.derived_keys[0][b] < 0x10) Serial.print('0'); Serial.print(fresh.derived_keys[0][b], HEX); }
    Serial.println();
    Serial.print(F("[button] Derived K1: "));
    for (int b = 0; b < 16; b++) { if (fresh.derived_keys[1][b] < 0x10) Serial.print('0'); Serial.print(fresh.derived_keys[1][b], HEX); }
    Serial.println();
    store_bolt_config_keys_from_bytes(mBoltConfig, fresh.derived_keys);
    saveBoltConfig(active_bolt_config);
    bolt.loadKeysForWipe(mBoltConfig);
    Serial.println(F("[button] Keys loaded for wipe, starting wipe()..."));
    const uint8_t result = bolt.wipe();
    Serial.print("[button] wipe -> ");
    Serial.println(result == JOBSTATUS_DONE ? "SUCCESS" : "FAILED");
    led_signal_result(result == JOBSTATUS_DONE);
    led_tick();
    return;
  }

  Serial.println("[button] Reset refused — no safe reset path for this card");
  led_signal_result(false);
  led_tick();
#endif
}

#if HAS_WIFI
typedef void (*tAppHandler)();
typedef void (*tEvtHandler)(uint8_t btn, uint8_t evt);

struct sAppHandler {
  String app_title;
  String app_desc;
  tAppHandler app_start; // function pointer start lifecycle
  tAppHandler app_end;   // function pointer end lifecycle
  tAppHandler app_loop;  // function pointer mainloop
  uint16_t app_fgcolor;
  uint16_t app_bgcolor;
};

sAppHandler mAppHandler[APPS];
#endif

#if HAS_WIFI
void saveSettings() {
  char path[20];
  sprintf(path, "/settings.dat");
  fs::File myFile = SPIFFS.open(path, FILE_WRITE);
  if (!myFile) { Serial.println(F("[error] Failed to open settings for write")); return; }
  myFile.write((byte *)&mSettings, sizeof(sSettings));
  myFile.close();
}

//Extract files needed by the webserver from the data in tardata.h
void extractfiles(){
    Serial.println("Extracting files");
    Stream *HTMLTarStream = new TarStream(data_tar, (size_t) data_tar_len);
    TarGzUnpacker *TARGZUnpacker = new TarGzUnpacker();
    TARGZUnpacker->haltOnError( true );
    TARGZUnpacker->setTarVerify( true );
    TARGZUnpacker->setupFSCallbacks( targzTotalBytesFn, targzFreeBytesFn );
    TARGZUnpacker->setGzProgressCallback( BaseUnpacker::defaultProgressCallback );
    TARGZUnpacker->setLoggerCallback( BaseUnpacker::targzPrintLoggerCallback  );
    TARGZUnpacker->setTarProgressCallback( BaseUnpacker::defaultProgressCallback );
    TARGZUnpacker->setTarStatusProgressCallback( BaseUnpacker::defaultTarStatusProgressCallback );
    TARGZUnpacker->setTarMessageCallback( BaseUnpacker::targzPrintLoggerCallback );
    if( !TARGZUnpacker->tarGzStreamExpander( HTMLTarStream, tarGzFS ) ) {
      Serial.println("Error while unpacking the webserver files");
      delete TARGZUnpacker;
      delete HTMLTarStream;
      return;
    }
    delete TARGZUnpacker;
    delete HTMLTarStream;

    fs::File myFile = SPIFFS.open("/fsversion.dat", FILE_WRITE);
    if (myFile) {
      myFile.write((byte *) &fsversion, sizeof(fsversion));
      myFile.close();
    }

    Serial.println("done!");
    
}

int checkFsVersion(){
  int myversion = -1;
  fs::File myFile = SPIFFS.open("/fsversion.dat", FILE_READ);
  if (!myFile) return -1;
  myFile.read((byte *) &myversion, sizeof(myversion));
  myFile.close();
  Serial.println(myversion);
  return myversion;
}

void loadSettings() {
  char path[20];
  sprintf(path, "/settings.dat");
  Serial.print(path);
  if (SPIFFS.exists(path) == 1) {
    Serial.println(" found");
    fs::File myFile = SPIFFS.open(path, FILE_READ);
    if (!myFile) { Serial.println(F("[error] Failed to open settings for read")); return; }
    myFile.read((byte *)&mSettings, sizeof(sSettings));
    myFile.close();
  } else {
    Serial.println(" not found");
    mSettings.essid[0] = 0;
    mSettings.password[0] = 0;
    mSettings.wifimode = WIFIMODE_AP;
    mSettings.wifi_enabled = 1;
    memcpy(mSettings.http_username, http_default_username, HTTP_CREDENTIAL_SIZE);
    memcpy(mSettings.http_password, http_default_password, HTTP_CREDENTIAL_SIZE);
  }
  dumpsettings();
}
#else
void saveSettings() {}

void loadSettings() {}
#endif

void saveBoltConfig(uint8_t slot) {
  char path[20];
  sprintf(path, "/config%02x.dat", slot);
  SPIFFS.begin(true);
  // Never persist keys to flash — write a sanitized copy with zeroed key fields.
  sBoltConfig sanitized = mBoltConfig;
  memset(sanitized.k0, 0, sizeof(sanitized.k0));
  memset(sanitized.k1, 0, sizeof(sanitized.k1));
  memset(sanitized.k2, 0, sizeof(sanitized.k2));
  memset(sanitized.k3, 0, sizeof(sanitized.k3));
  memset(sanitized.k4, 0, sizeof(sanitized.k4));
  fs::File myFile = SPIFFS.open(path, FILE_WRITE);
  if (!myFile) { Serial.println(F("[error] Failed to open config for write")); return; }
  myFile.write((byte *)&sanitized, sizeof(sBoltConfig));
  myFile.close();
}

/*
uint8_t boltconfig_key[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}; uint8_t newlen =
bolt.nfc->ntag424_addpadding(strlen(mBoltConfig.url), 16,  (uint8_t *)
&mBoltConfig.url); Serial.println(bolt.nfc->ntag424_encrypt(boltconfig_key,
newlen, (uint8_t *) &mBoltConfig.url, testurl_enc));
Serial.println(bolt.nfc->ntag424_decrypt(boltconfig_key, newlen, testurl_enc,
testurl)); bolt.nfc->PrintHexChar(testurl, 56);
*/

void loadBoltConfig(uint8_t slot) {
  char path[20];
  sprintf(path, "/config%02x.dat", slot);
  SPIFFS.begin(true);
  Serial.print(path);
  Serial.println(sizeof(((sBoltConfig *)0)->url));
  memset(&mBoltConfig, 0, sizeof(sBoltConfig));
  uint8_t testurl_enc[sizeof(((sBoltConfig *)0)->url)];
  uint8_t testurl[sizeof(((sBoltConfig *)0)->url)];
  if (SPIFFS.exists(path) == 1) {
    Serial.println(" found");
    fs::File myFile = SPIFFS.open(path, FILE_READ);
    if (!myFile) { Serial.println(F("[error] Failed to open config for read")); return; }
    myFile.read((byte *)&mBoltConfig, sizeof(sBoltConfig));
    myFile.close();
  } else {
    Serial.println(" not found");
    strcpy(mBoltConfig.card_name, "*new*");
    mBoltConfig.url[0] = 0;
    strcpy(mBoltConfig.card_mode, "withdraw");
    mBoltConfig.uid[0] = 0;
    mBoltConfig.k0[0] = 0;
    mBoltConfig.k1[0] = 0;
    mBoltConfig.k2[0] = 0;
    mBoltConfig.k3[0] = 0;
    mBoltConfig.k4[0] = 0;
    mBoltConfig.wallet_name[0] = 0;
    mBoltConfig.wallet_url[0] = 0;
    mBoltConfig.wallet_host[0] = 0;
    mBoltConfig.reset_url[0] = 0;
    strcpy(mBoltConfig.wifi_ssid, "Tollgate");
    mBoltConfig.wifi_password[0] = 0;
    mBoltConfig.wifi_probe_enabled = false;
  }
  if (mBoltConfig.card_mode[0] == '\0') {
    strcpy(mBoltConfig.card_mode, "withdraw");
  }
  dumpconfig();
}

#if HAS_WIFI
String exportBoltConfig() {
  String path = "/backup.dat";
  SPIFFS.remove(path);
  fs::File myFile = SPIFFS.open(path, FILE_APPEND);
  if (!myFile) { Serial.println(F("[error] Failed to open backup for write")); return path; }
  for (uint8_t i = 0; i < MAX_BOLT_DEVICES; i++) {
    loadBoltConfig(i);
    myFile.write((byte *)&mBoltConfig, sizeof(sBoltConfig));
  }
  myFile.close();
  loadBoltConfig(active_bolt_config);
  return path;
}

void importBoltConfig() {
  String path = "/backup.dat";
  fs::File myFile = SPIFFS.open(path, FILE_READ);
  if (!myFile) { Serial.println(F("[error] Failed to open backup for read")); return; }
  for (uint8_t i = 0; i < MAX_BOLT_DEVICES; i++) {
    myFile.seek(i * sizeof(sBoltConfig));
    myFile.readBytes((char *)&mBoltConfig, sizeof(sBoltConfig));
    // loadBoltConfig(i);
    saveBoltConfig(i);
    dumpconfig();
  }
  myFile.close();
  loadBoltConfig(active_bolt_config);
}
#endif

#if LED_PIN >= 0
void led_on() { digitalWrite(LED_PIN, LOW); }
void led_off() { digitalWrite(LED_PIN, HIGH); }
void led_blink(int count, int ms) {
  for (int i = 0; i < count; i++) {
    led_on(); delay(ms); led_off();
    if (i < count - 1) delay(ms);
  }
}
#else
void led_on() {
  led_set_busy(true);
  led_notify_activity();
  led_tick();
}
void led_off() {
  led_set_busy(false);
  led_tick();
}
void led_blink(int count, int) {
  led_signal_result(count <= 3);
  led_tick();
}
#endif

// Button event handler — used in both serial and WiFi builds
void handle_events() {
#if HAS_WIFI && HAS_BUTTONS
  handle_atom_button_feedback();
  // Button 0 short clicky = next keyset
  if ((sharedvars.appbuttons[0] == 1) && (app_active != APP_KEYSETUP)) {
    active_bolt_config += 1;
    if (active_bolt_config >= MAX_BOLT_DEVICES) {
      active_bolt_config = 0;
    }
    loadBoltConfig(active_bolt_config);
    signal_update_screen = true;
  }
  // Button 1 short clicky = next app
  if ((sharedvars.appbuttons[1] == 1) && (app_active != APP_KEYSETUP)) {
    app_next = app_active + 1;
    if (app_next > APPS - 1) {
      app_next = 1;
    }
  }
  // Button 0 long clicky = toggle WiFi
  if (sharedvars.appbuttons[0] == 2) {
    wifi_toogle();
    signal_update_screen = true;
  }
  // Button 1 long clicky = deep sleep
  if (sharedvars.appbuttons[1] == 2) {
    nfc_stop();
    esp_sleep_enable_ext0_wakeup(GPIO_NUM_35, 0); // 1 = High, 0 = Low
    esp_deep_sleep_start();
  }
  // Button 0 double clicky
  if (sharedvars.appbuttons[0] == 3) {
    Serial.println("double click btn0");
    String wurl =
        String(mBoltConfig.wallet_host) + "?" + String(mBoltConfig.wallet_url);
    Serial.println(wurl);
  }
  // Button 1 double clicky
  if (sharedvars.appbuttons[1] == 3) {
    Serial.println("double click btn1");
  }
  sharedvars.appbuttons[0] = 0;
  sharedvars.appbuttons[1] = 0;
#else
  sharedvars.appbuttons[0] = 0;
  sharedvars.appbuttons[1] = 0;
#endif
}

// Keysetup
#if HAS_WIFI
void app_keysetup_start() { Serial.println("app_KEYSETUP_start"); }

long lasttime = 0;
String default_app_message = "* Buttons are locked! *";
String app_message = default_app_message;
void app_keysetup_loop() {
  if (!serial_cmd_active && (millis() - lasttime) > 200) {
    lasttime = millis();
    if (bolty_hw_ready) {
      bolt.scanUID();
      app_message = bolt.getScannedUid();
    }
    if (app_message == "") {
      app_message = default_app_message;
    }
#if HAS_DISPLAY
    tft.setFreeFont(&FreeSans9pt7b);
    tft.setTextColor(APPRED);
    tft.fillRect(0, -3 + (3 * 23), tft.width(), 21, APPWHITE);
#endif
    displayTextCentered(-3 + (4 * 21), app_message);
  }
#if HAS_WIFI
  if (!mSettings.wifi_enabled) {
    app_next = APP_BOLTBURN;
  }
#else
  // Auto-advance disabled for headless serial testing
  // if (app_message != default_app_message) {
  //   app_next = APP_BOLTBURN;
  // }
#endif
  delay(50);
}

#if HAS_WIFI
String web_keysetup_processor(const String &var) {
  if (var == "wallet_name")
    return mBoltConfig.wallet_name;
  if (var == "wallet_host")
    return mBoltConfig.wallet_host;
  if (var == "wallet_url")
    return mBoltConfig.wallet_url;
  if (var == "wallet_link")
    return mBoltConfig.wallet_url;
  if (var == "uid")
    return mBoltConfig.uid;
  if (var == "card_mode")
    return strlen(mBoltConfig.card_mode) ? mBoltConfig.card_mode : "withdraw";
  return processor_default(var);
}
#endif

void app_keysetup_end() { Serial.println("app_KEYSETUP_end"); }

// Ringsetup
void APP_BOLTBURN_start() { Serial.println("APP_BOLTBURN_start"); }

uint32_t previousMillis;
uint32_t Interval = 100;

void APP_BOLTBURN_loop() {
  // set the keys
  if (millis() - previousMillis < Interval) {
    return;
  }
  previousMillis = millis();
  Interval = 100;
  if (bolty_hw_ready) {
    bolt.loadKeysForBurn(mBoltConfig);
    String lnurl = String(mBoltConfig.url);
    uint8_t burn_result = bolt.burn(lnurl);
    if (burn_result != JOBSTATUS_WAITING) {
      led_set_job_status(bolt.get_job_status_id());
      previousMillis = millis();
      Interval = 3000;
      dumpconfig();
    }
  } else {
#if HAS_DISPLAY
    tft.setFreeFont(&FreeSans9pt7b);
    tft.setTextColor(APPRED);
    tft.fillRect(0, -3 + (3 * 23), tft.width(), 21, APPWHITE);
#endif
    displayTextCentered(-3 + (4 * 21), "nfc hw not ready");
  }
}


String shortenkeys(const String &var){
  return var.substring(0,3) + "*************";
}

String processor_default(const String &var){
  if (var == "cnn")
    return String(active_bolt_config + 1).c_str();
  if (var == "cn")
    return mBoltConfig.card_name;
  if (var == "url")
    return mBoltConfig.url;
  if (var == "card_mode")
    return strlen(mBoltConfig.card_mode) ? mBoltConfig.card_mode : "withdraw";
  if (var == "ks0")
    return shortenkeys(mBoltConfig.k0);
  if (var == "ks1")
    return shortenkeys(mBoltConfig.k1);
  if (var == "ks2")
    return shortenkeys(mBoltConfig.k2);
  if (var == "ks3")
    return shortenkeys(mBoltConfig.k3);
  if (var == "ks4")
    return shortenkeys(mBoltConfig.k4);
  if (var == "k0")
    return mBoltConfig.k0;
  if (var == "k1")
    return mBoltConfig.k1;
  if (var == "k2")
    return mBoltConfig.k2;
  if (var == "k3")
    return mBoltConfig.k3;
  if (var == "k4")
    return mBoltConfig.k4;
#if HAS_WIFI
  if (var == "wifista")
        return String(mSettings.wifimode);
  if (var == "essid")
        if (mSettings.wifimode == WIFIMODE_STA)
                return String(mSettings.essid);
#endif
  return String();
}

#if HAS_WIFI
String web_burn_processor(const String &var) {
  Serial.println("web_ringsetup_loop");
  if (var == "job")
    return "Burn";
  return processor_default(var);
}
#endif
void APP_BOLTBURN_end() { Serial.println("APP_BOLTBURN_end"); }
// Ringsetup
void APP_BOLTWIPE_start() { Serial.println("APP_BOLTWIPE_start"); }

void APP_BOLTWIPE_loop() {
  if (millis() - previousMillis < Interval) {
    return;
  }
  previousMillis = millis();
  Interval = 100;
  if (bolty_hw_ready) {
    bolt.loadKeysForWipe(mBoltConfig);
    uint8_t wipe_result = bolt.wipe();
    if (wipe_result != JOBSTATUS_WAITING) {
      led_set_job_status(bolt.get_job_status_id());
      previousMillis = millis();
      Interval = 3000;
      dumpconfig();
    }
  } else {
#if HAS_DISPLAY
    tft.setFreeFont(&FreeSans9pt7b);
    tft.setTextColor(APPRED);
    tft.fillRect(0, -3 + (3 * 23), tft.width(), 21, APPWHITE);
#endif
    displayTextCentered(-3 + (4 * 21), "nfc hw not ready");
  }
}

#if HAS_WIFI
String web_ringwipe_processor(const String &var) {
  Serial.println("web_ringwipe_loop");
  if (var == "job")
    return "Wipe";
  return processor_default(var);
}
#endif
void APP_BOLTWIPE_end() { Serial.println("APP_BOLTWIPE_end"); }

#if HAS_WIFI
bool SendQR(String input, AsyncResponseStream *response) {
  int qrSize = 10;
  int ec_lvl = 0;
  int const sizes[18][4] = {
      {17, 14, 11, 7},   {32, 26, 20, 14},  {53, 42, 32, 24},
      {78, 62, 46, 34},  {106, 84, 60, 44}, {134, 106, 74, 58},
      {154, 122, 86, 64}, {192, 152, 108, 84}, {230, 180, 130, 98},
      {271, 213, 151, 119}, {321, 251, 177, 137}, {367, 287, 203, 155},
      {425, 331, 241, 177}, {458, 362, 258, 194}, {520, 412, 292, 220},
      {586, 450, 322, 250}, {644, 504, 364, 280},
  };

  int len = input.length();
  for (int ii = 0; ii < 17; ii++) {
    qrSize = ii + 1;
    if (sizes[ii][ec_lvl] > len) {
      break;
    }
  }

  Serial.printf("len = %d, ec_lvl = %d, qrSize = %d\n", len, ec_lvl, qrSize);

  QRCode qrcode;
  uint8_t qrcodeData[qrcode_getBufferSize(qrSize)];
  qrcode_initText(&qrcode, qrcodeData, qrSize, ec_lvl, input.c_str());

  Serial.printf("saw qr mode = %d\n", qrcode.mode);

  for (uint8_t y = 0; y < qrcode.size; y++) {
    for (uint8_t x = 0; x < qrcode.size; x++) {
      response->print(qrcode_getModule(&qrcode, x, y) ? "\u2588\u2588" : "  ");
    }
    response->print("<br/>");
  }
  return true;
}
#endif

uint8_t lineh = 21;

#if HAS_DISPLAY
void update_screen() {
  tft.fillScreen(fromrgb(0xed, 0xef, 0xf2));
  int8_t ofs = -3;
  tft.fillRect(0, 0, tft.width(), 23, mAppHandler[app_active].app_bgcolor);
#if HAS_BATTERY
  draw_battery(true);
#endif
#if HAS_WIFI
  draw_wifi(mSettings.wifi_enabled);
#else
  draw_wifi(false);
#endif

  tft.setFreeFont(&FreeSans9pt7b);
  tft.setTextColor(APPWHITE);
  displayTextCentered(ofs + (1 * lineh), mAppHandler[app_active].app_title);
  tft.setTextColor(mAppHandler[app_active].app_fgcolor);
  displayTextCentered(ofs + (2 * lineh), String(active_bolt_config + 1) + ". " +
                                             mBoltConfig.card_name);
  displayTextCentered(ofs + (3 * lineh), mAppHandler[app_active].app_desc);
#if HAS_WIFI
  if (mSettings.wifi_enabled) {
    if (mSettings.wifimode == WIFIMODE_AP) {
      displayTextLeft(ofs + (5 * lineh),
                      "WiFi " + String(ap_ssid) + ":" + String(ap_password));
    }
    SIpAddress = getIpAddress();
    displayTextLeft(ofs + (6 * lineh), SIpAddress);
  }
#endif
  signal_update_screen = false;
}
#else
void update_screen() {
  signal_update_screen = false;
}
#endif

void app_stateengine() {
  handle_events();
#if HAS_DISPLAY
  if (signal_update_screen){
      update_screen();
  }
#endif
  if (signal_restart_delayed > 0){
    delay(3000);
    ESP.restart();
  }
  if (app_next >= APPS)
    app_next = 0;
  // do not switch to keysetup using buttons
  if (app_next < 0)
    app_next = APPS - 1;

  if (app_active != app_next) {
    Serial.print("start: current app:");
    Serial.println(app_active);
    Serial.print("switching to app:");
    Serial.println(app_next);
    app_status = APP_STATUS_END;
  }
  if (app_status == APP_STATUS_START) {
    (*mAppHandler[app_active].app_start)();
    app_status = APP_STATUS_LOOP;
#if HAS_DISPLAY
    update_screen();
#endif
  }
  if (app_status == APP_STATUS_LOOP) {
#if HAS_BATTERY
    draw_battery();
#endif
#if HAS_WIFI
    draw_wifi(mSettings.wifi_enabled);
#elif HAS_DISPLAY
    draw_wifi(false);
#endif
    (*mAppHandler[app_active].app_loop)();
  }
  if (app_status == APP_STATUS_END) {
    Serial.print("end: ending app:");
    Serial.println(app_active);
    Serial.print("end: activating app:");
    Serial.println(app_next);
    (*mAppHandler[app_active].app_end)();
    app_active = app_next;
    app_status = APP_STATUS_START;
  }
}
#endif // HAS_WIFI — end of web UI app lifecycle

void dumpconfig() {
  Serial.println(mBoltConfig.wallet_name);
  Serial.println(mBoltConfig.wallet_host);
  Serial.println(mBoltConfig.wallet_url);
  Serial.println(mBoltConfig.uid);
  Serial.println(mBoltConfig.card_name);
  Serial.println(mBoltConfig.url);
  Serial.println(mBoltConfig.reset_url);
  Serial.println(mBoltConfig.k0);
  Serial.println(mBoltConfig.k1);
  Serial.println(mBoltConfig.k2);
  Serial.println(mBoltConfig.k3);
  Serial.println(mBoltConfig.k4);
  Serial.println(mBoltConfig.wifi_ssid);
  Serial.println(mBoltConfig.wifi_password);
  Serial.println(mBoltConfig.wifi_probe_enabled ? "probe=1" : "probe=0");
}

void dumpsettings() {
#if HAS_WIFI
  Serial.println(mSettings.wifimode);
  Serial.println(mSettings.essid);
  Serial.println(mSettings.password);
  Serial.println(mSettings.wifi_enabled);
  Serial.println(mSettings.http_username);
  Serial.println(mSettings.http_password);
#endif
}

#if HAS_WIFI
void checkparams(AsyncWebServerRequest *request) {
  if (request->hasParam("d")) {
    AsyncWebParameter *p = request->getParam("d");
    Serial.println("got d param");
    Serial.println(p->value().c_str());
    if (p->value() == "p") {
      active_bolt_config =
          constrain((active_bolt_config - 1), 0, MAX_BOLT_DEVICES - 1);
    }
    if (p->value() == "n") {
      active_bolt_config =
          constrain((active_bolt_config + 1), 0, MAX_BOLT_DEVICES - 1);
    }
    loadBoltConfig(active_bolt_config);
    signal_update_screen = true;
  }
  Serial.println(active_bolt_config);
}
#endif

void empty() {
  //
}

#if HAS_WIFI
void randomchar(char *outbuf, uint8_t count) {
  for (uint8_t i = 0; i < count; i++) {
    Serial.print(i);
    Serial.print(":");
    outbuf[i] = charpool[esp_random() % 63];
    Serial.println(outbuf[i]);
  }
  outbuf[count] = 0;
}
#endif

#if HAS_WIFI
String getIpAddress() {
  if (mSettings.wifimode == WIFIMODE_AP)
    myIP = WiFi.softAPIP();
  if (mSettings.wifimode == WIFIMODE_STA)
    myIP = WiFi.localIP();
  return myIP.toString();
}

void wifi_start() {
  // if we have credentials try connecting. WIFIMODE_STA will fallback to
  // mSettings.wifimode == WIFIMODE_AP
  if ((mSettings.essid != "") && (mSettings.password != "")) {
    mSettings.wifimode = WIFIMODE_STA;
  }
  if (mSettings.wifimode == WIFIMODE_AP) {
#ifndef WIFI_AP_PASSWORD_STATIC
    randomchar(ap_password, sizeof(ap_password));
#endif
    WiFi.softAP(ap_ssid, ap_password);
    myIP = WiFi.softAPIP();
  }

  uint8_t connect_count = 0;
  if (mSettings.wifimode == WIFIMODE_STA) {
    WiFi.begin(mSettings.essid, mSettings.password);
    while (WiFi.status() != WL_CONNECTED) {
      delay(500);
      connect_count++;
      Serial.println("Connecting to WiFi..");
      // fall back to AP mode if we cannot connect for 10 seconds
      if (connect_count > 10) {
        Serial.println("Cannot connect to Network. Fallback to AP-Mode.");
        wifi_stop();
        delay(50);
        mSettings.wifimode = WIFIMODE_AP;
#ifndef WIFI_AP_PASSWORD_STATIC
        randomchar(ap_password, sizeof(ap_password));
#endif
        WiFi.softAP(ap_ssid, ap_password);
        myIP = WiFi.softAPIP();
        break;
      }
    }
    // still STA mode? then we should be connected by now!
    if (mSettings.wifimode == WIFIMODE_STA) {
      myIP = WiFi.localIP();
    }
  }
  if (!mSettings.wifi_enabled) {
    mSettings.wifi_enabled = true;
    saveSettings();
    //set wifimode  after savesettings. we dont want to persist it if we fallback to apmode.
    if ((mSettings.wifimode == WIFIMODE_STA) && (connect_count <= 10)) {
      mSettings.wifimode = WIFIMODE_AP;
    }
  }
  server.begin();
}

void wifi_stop() {
  server.end();
  WiFi.mode(WIFI_STA);
  WiFi.disconnect();
  esp_wifi_stop();
  Serial.println("WIFI: Disconnected");
  delay(100);
  WiFi.mode(WIFI_OFF);
  delay(100);
  if (mSettings.wifi_enabled) {
    mSettings.wifi_enabled = false;
    saveSettings();
  }
}

void wifi_toogle() {
  if (mSettings.wifi_enabled) {
    wifi_stop();
  } else {
    wifi_start();
  }
}
#else
String getIpAddress() {
  return String("WiFi disabled");
}

void wifi_start() { Serial.println("WiFi disabled (headless mode)"); }

void wifi_stop() {}

void wifi_toogle() {}
#endif

void nfc_start() {
  Serial.println("switching nfc on");
#if NFC_RESET_PIN >= 0
  digitalWrite(NFC_RESET_PIN, HIGH);
#endif
}

void nfc_stop() {
  Serial.println("switching nfc off");
#if NFC_RESET_PIN >= 0
  digitalWrite(NFC_RESET_PIN, LOW);
#endif
}

// handles uploads
#if HAS_WIFI
void handleUpload(AsyncWebServerRequest *request, String filename, size_t index,
                  uint8_t *data, size_t len, bool final) {
  String logmessage = "Client:" + request->client()->remoteIP().toString() +
                      " " + request->url();
  Serial.println(logmessage);

  if (!index) {
    logmessage = "Upload Start: " + String(filename);
    // open the file on first call and store the file handle in the request
    // object
    request->_tempFile = SPIFFS.open("/backup.dat", "w");
    Serial.println(logmessage);
  }

  if (len) {
    // stream the incoming chunk to the opened file
    request->_tempFile.write(data, len);
    logmessage = "Writing file: " + String(filename) +
                 " index=" + String(index) + " len=" + String(len);
    Serial.println(logmessage);
  }

  if (final) {
    logmessage = "Upload Complete: " + String(filename) +
                 ",size: " + String(index + len);
    // close the file handle as the upload is now done
    request->_tempFile.close();
    Serial.println(logmessage);
    importBoltConfig();
    request->redirect("/");
  }
}
#endif

void setup(void) {
  Serial.begin(115200);
  while (!Serial)
    delay(10); // for Leonardo/Micro/Zero

  Serial.println("=== Bolty Build Info ===");
  Serial.print("Board: ");
  Serial.println(BOLTY_BOARD_NAME);
  Serial.print("NFC backend: ");
#if BOLTY_NFC_BACKEND_MFRC522
  Serial.println("MFRC522");
#else
  Serial.println("PN532");
#endif
  Serial.print("Bolty commit: ");
  Serial.println(BOLTY_GIT_COMMIT);
  Serial.print("NFC lib commit: ");
  Serial.println(PN532_LIB_GIT_COMMIT);
  Serial.println("========================");

#if BOLTY_OTA_ENABLED
  ota_check_and_update();
#endif

  setup_display();
  led_setup();

#if !HAS_DISPLAY
  Serial.println("=== Bolty Headless Mode ===");
#endif

#if HAS_WIFI
  // Initialize SPIFFS
  if (!tarGzFS.begin()) {
    Serial.println("An Error has occurred while mounting SPIFFS");
    #if defined DEST_FS_USES_SPIFFS || defined DEST_FS_USES_LITTLEFS
        Serial.println("Initializing flash!");
        displayMessage("init flash...", 0);
        tarGzFS.format();
    #endif
    if (!tarGzFS.begin()){
      Serial.println("Failed to mount filesystem!");
      while (true)
        delay(1000);
    }
    displayMessage("extract files...", 0);
    extractfiles();
  }

  if ((!SPIFFS.exists("/wipe.html")) || (!SPIFFS.exists("/fsversion.dat"))) {
    Serial.println("Could not find files!");
    displayMessage("extract files", 0);
    extractfiles();
  }
  else if (checkFsVersion() < fsversion) {
    Serial.println("updating");
    displayMessage("updating...", 0);
    extractfiles();
  }
#endif

  displayMessage("setup nfc", 0);
#if NFC_RESET_PIN >= 0
  pinMode(NFC_RESET_PIN, OUTPUT);
#endif
#if LED_PIN >= 0
  pinMode(LED_PIN, OUTPUT);
  led_off();
#endif
  // Backends with a reset pin benefit from a hard reset before startup.
  // This is especially important for PN532 recovery after transport errors.
#if NFC_RESET_PIN >= 0
  digitalWrite(NFC_RESET_PIN, LOW);
  delay(100);
  digitalWrite(NFC_RESET_PIN, HIGH);
  delay(10);
#endif
  nfc_start();
  bolty_hw_ready = bolt.begin();
  led_set_hardware_ready(bolty_hw_ready);
  led_boot_animation(bolty_hw_ready);
  Serial.println("Setup done!");
#if HAS_WIFI
  app_active = APP_KEYSETUP;
  app_next = APP_BOLTBURN;
  app_status = APP_STATUS_START;
  led_set_app_mode(app_active);
  led_set_job_status(bolt.get_job_status_id());
  mAppHandler[APP_KEYSETUP].app_title = "Key-Setup";
  mAppHandler[APP_KEYSETUP].app_desc = "Use a webbrowser";
  mAppHandler[APP_KEYSETUP].app_start = app_keysetup_start;
  mAppHandler[APP_KEYSETUP].app_end = app_keysetup_end;
  mAppHandler[APP_KEYSETUP].app_loop = app_keysetup_loop;
  mAppHandler[APP_KEYSETUP].app_fgcolor = APPBLACK;
  mAppHandler[APP_KEYSETUP].app_bgcolor = fromrgb(0x3e, 0xaf, 0x7c);

  mAppHandler[APP_BOLTBURN].app_title = "Burn";
  mAppHandler[APP_BOLTBURN].app_desc = "Burn a Bolt Card";
  mAppHandler[APP_BOLTBURN].app_start = APP_BOLTBURN_start;
  mAppHandler[APP_BOLTBURN].app_end = APP_BOLTBURN_end;
  mAppHandler[APP_BOLTBURN].app_loop = APP_BOLTBURN_loop;
  mAppHandler[APP_BOLTBURN].app_fgcolor = APPBLACK;
  mAppHandler[APP_BOLTBURN].app_bgcolor = fromrgb(0xff, 0xad, 0x33);

  mAppHandler[APP_BOLTWIPE].app_title = "Wipe";
  mAppHandler[APP_BOLTWIPE].app_desc = "Wipe a Bolt Card";
  mAppHandler[APP_BOLTWIPE].app_start = APP_BOLTWIPE_start;
  mAppHandler[APP_BOLTWIPE].app_end = APP_BOLTWIPE_end;
  mAppHandler[APP_BOLTWIPE].app_loop = APP_BOLTWIPE_loop;
  mAppHandler[APP_BOLTWIPE].app_fgcolor = APPBLACK;
  mAppHandler[APP_BOLTWIPE].app_bgcolor = fromrgb(0xee, 0xa0, 0xa0);
#else
  led_set_job_status(bolt.get_job_status_id());
#endif

  // initialize the bolt configurations
  active_bolt_config = 0;
  loadBoltConfig(active_bolt_config);

#if HAS_WIFI
  Serial.println("Loading settings...");
  displayMessage("load settings", 0);
  loadSettings();
  // Route for root / web page
  server.on("/", HTTP_GET, [](AsyncWebServerRequest *request) {
    app_next = APP_BOLTBURN;
    checkparams(request);
    request->send(SPIFFS, "/burn.html", String(), false, web_burn_processor);
  });
  // Route for root / web page
  server.on("/favicon.ico", HTTP_GET, [](AsyncWebServerRequest *request) {
    request->send(SPIFFS, "/favicon.ico", "image/png");
  });
  // Export Config
  server.on("/export", HTTP_GET, [](AsyncWebServerRequest *request) {
    String exportfile = exportBoltConfig();
    request->send(SPIFFS, exportfile, "application/octet-stream");
  });

  // Route for keys / web page
  server.on("/setup", HTTP_GET, [](AsyncWebServerRequest *request) {
    if(!request->authenticate(mSettings.http_username, mSettings.http_password))
        return request->requestAuthentication();
    app_next = APP_KEYSETUP;
    checkparams(request);
    AsyncWebServerResponse *response = request->beginResponse(
        SPIFFS, "/setup.html", String(), false,
        web_keysetup_processor); // Sends File with cross-origin-header
    response->addHeader("Access-Control-Allow-Origin", "*");
    request->send(response);
  });
  // Route for root / web page
  server.on("/wipe", HTTP_GET, [](AsyncWebServerRequest *request) {
    app_next = APP_BOLTWIPE;
    checkparams(request);
    request->send(SPIFFS, "/wipe.html", String(), false,
                  web_ringwipe_processor);
  });
  server.on("/style.css", HTTP_GET, [](AsyncWebServerRequest *request) {
    AsyncWebServerResponse *response = request->beginResponse(
        SPIFFS, "/style.css", String());
    response->addHeader("last-modified", "Mon, 13 Jun 2022 11:05:21 GMT");
    response->addHeader("expires", "Sun, 13 Jun 2032 11:05:21 GMT");
    response->addHeader("cache-control", "max-age=86400");
    request->send(response);
  });
  server.on("/setup.js", HTTP_GET, [](AsyncWebServerRequest *request) {
    if(!request->authenticate(mSettings.http_username, mSettings.http_password))
        return request->requestAuthentication();
    AsyncWebServerResponse *response = request->beginResponse(
        SPIFFS, "/setup.js", String());
    response->addHeader("last-modified", "Mon, 13 Jun 2022 11:05:21 GMT");
    response->addHeader("expires", "Sun, 13 Jun 2032 11:05:21 GMT");
    response->addHeader("cache-control", "max-age=86400");
    request->send(response);
  });
  server.on("/bolty.js", HTTP_GET, [](AsyncWebServerRequest *request) {
    AsyncWebServerResponse *response = request->beginResponse(
        SPIFFS, "/bolty.js", String());
    response->addHeader("last-modified", "Mon, 13 Jun 2022 11:05:21 GMT");
    response->addHeader("expires", "Sun, 13 Jun 2032 11:05:21 GMT");
    response->addHeader("cache-control", "max-age=86400");
    request->send(response);
  });
  server.on("/qr", HTTP_GET, [](AsyncWebServerRequest *request) {
    AsyncResponseStream *response =
        request->beginResponseStream("text/html; charset=utf-8");
    response->print(
        "<html><head><link rel='stylesheet' media='screen' "
        "href='https://fontlibrary.org/face/dejavu-sans-mono' "
        "type='text/css'></head><body><pre style='font-family: "
        "DejaVuSansMonoBold,monospace;font-size: 0.2em;'>"); // font-size: 1vw;
    String walurl = web_keysetup_processor("wallet_link");
    SendQR(walurl, response);
    response->print("</pre></body></html>");
    request->send(response);
  });

  AsyncCallbackJsonWebHandler *handler = new AsyncCallbackJsonWebHandler(
      "/status", [](AsyncWebServerRequest *request, JsonVariant &json) {
        request->send(200, "application/json",
                      "{\"status\":\"" + bolt.get_job_status() +
                          "\",\"app\":\"" + app_active + "\",\"cnn\":\"" +
                          (active_bolt_config + 1) + "\"}");
      });

  server.addHandler(handler);

  AsyncCallbackJsonWebHandler *handler_uid = new AsyncCallbackJsonWebHandler(
      "/uid", [](AsyncWebServerRequest *request, JsonVariant &json) {
        request->send(200, "application/json",
                      "{\"uid\":\"" + bolt.getScannedUid() + "\"}");
      });

  server.addHandler(handler_uid);

  AsyncCallbackJsonWebHandler *handler2 = new AsyncCallbackJsonWebHandler(
      "/keys", [](AsyncWebServerRequest *request, JsonVariant &json) {
      if(!request->authenticate(mSettings.http_username, mSettings.http_password))
          return request->requestAuthentication();
        Serial.println("received keys");
        StaticJsonDocument<200> data;
        if (json.is<JsonArray>()) {
          data = json.as<JsonArray>();
        } else if (json.is<JsonObject>()) {
          data = json.as<JsonObject>();
        }
        if (data.containsKey("card_name"))
          safe_strcpy(mBoltConfig.card_name, data["card_name"], sizeof(mBoltConfig.card_name));
        if (data.containsKey("card_mode"))
          safe_strcpy(mBoltConfig.card_mode, data["card_mode"], sizeof(mBoltConfig.card_mode));
        if (data.containsKey("lnurlp_base"))
          safe_strcpy(mBoltConfig.url, data["lnurlp_base"], sizeof(mBoltConfig.url));
        else if (data.containsKey("lnurlw_base"))
          safe_strcpy(mBoltConfig.url, data["lnurlw_base"], sizeof(mBoltConfig.url));
        if (data.containsKey("wallet_name"))
          safe_strcpy(mBoltConfig.wallet_name, data["wallet_name"], sizeof(mBoltConfig.wallet_name));
        if (data.containsKey("wallet_url"))
          safe_strcpy(mBoltConfig.wallet_url, data["wallet_url"], sizeof(mBoltConfig.wallet_url));
        if (data.containsKey("wallet_host"))
          safe_strcpy(mBoltConfig.wallet_host, data["wallet_host"], sizeof(mBoltConfig.wallet_host));
        if (data.containsKey("uid"))
          safe_strcpy(mBoltConfig.uid, data["uid"], sizeof(mBoltConfig.uid));
        if (data.containsKey("k0"))
          safe_strcpy(mBoltConfig.k0, data["k0"], sizeof(mBoltConfig.k0));
        if (data.containsKey("k1"))
          safe_strcpy(mBoltConfig.k1, data["k1"], sizeof(mBoltConfig.k1));
        if (data.containsKey("k2"))
          safe_strcpy(mBoltConfig.k2, data["k2"], sizeof(mBoltConfig.k2));
        if (data.containsKey("k3"))
          safe_strcpy(mBoltConfig.k3, data["k3"], sizeof(mBoltConfig.k3));
        if (data.containsKey("k4"))
          safe_strcpy(mBoltConfig.k4, data["k4"], sizeof(mBoltConfig.k4));
        saveBoltConfig(active_bolt_config);
        Serial.println(mBoltConfig.card_name);
        request->send(200, "application/json",
                      "{\"status\":\"received_keys\"}");
      });
  server.addHandler(handler2);

  AsyncCallbackJsonWebHandler *handlerwifi = new AsyncCallbackJsonWebHandler(
      "/wifi", [](AsyncWebServerRequest *request, JsonVariant &json) {
      if(!request->authenticate(mSettings.http_username, mSettings.http_password))
        return request->requestAuthentication();
        Serial.println("received wifi-settings");
        StaticJsonDocument<200> data;
        if (json.is<JsonArray>()) {
          data = json.as<JsonArray>();
        } else if (json.is<JsonObject>()) {
          data = json.as<JsonObject>();
        }
        if (data["essid"] != "") {
          safe_strcpy(mSettings.essid, data["essid"], sizeof(mSettings.essid));
        }
        if ((data["password"] != "*123--keep-my-current-password--321*")) {
          safe_strcpy(mSettings.password, data["password"], sizeof(mSettings.password));
        }
        if (data["wifimode"] == "sta") {
          mSettings.wifimode = WIFIMODE_STA;
        } else {
          mSettings.wifimode = WIFIMODE_AP;
        }
        saveSettings();
        request->send(200, "application/json",
                      "{\"status\":\"received_keys\"}");
        signal_restart_delayed = 2000;
      });
  server.addHandler(handlerwifi);
  
  AsyncCallbackJsonWebHandler *handlerac = new AsyncCallbackJsonWebHandler(
      "/ac", [](AsyncWebServerRequest *request, JsonVariant &json) {
      if(!request->authenticate(mSettings.http_username, mSettings.http_password))
        return request->requestAuthentication();
        Serial.println("received credential-settings");
        StaticJsonDocument<200> data;
        if (json.is<JsonArray>()) {
          data = json.as<JsonArray>();
        } else if (json.is<JsonObject>()) {
          data = json.as<JsonObject>();
        }
        if ((strlen(data["http_u"]) >= HTTP_CREDENTIAL_SIZE) || (strlen(data["http_p"]) >= HTTP_CREDENTIAL_SIZE)){
          request->send(505, "application/json",
                      "{\"status\":\"credentials too long\"}");
          return;
        }
        if (data["http_u"] != "") {
          safe_strcpy(mSettings.http_username, data["http_u"], sizeof(mSettings.http_username));
        }
        if (data["http_p"] != "") {
          safe_strcpy(mSettings.http_password, data["http_p"], sizeof(mSettings.http_password));
        }
        saveSettings();
        request->send(200, "application/json",
                      "{\"status\":\"received_credentials\"}");
        ESP.restart();
      });
  server.addHandler(handlerac);

  // run handleUpload function when any file is uploaded
  server.on(
      "/upload", HTTP_POST,
      [](AsyncWebServerRequest *request) { request->send(200); }, handleUpload);

  Serial.println("Wifi setup...");
  displayMessage("Wifi setup", 0);
  if (mSettings.wifi_enabled) {
    wifi_start();
    IPAddress myIP;
    SIpAddress = getIpAddress();
    Serial.println(SIpAddress);
  }
  Serial.println("Server started");
#else
  Serial.println("Headless mode ready. Type 'help' for commands.");
#endif

#if HAS_REST_SERVER
  Serial.println("REST mode: connecting WiFi for HTTPS provisioning...");
  WiFi.mode(WIFI_STA);
  WiFi.setSleep(WIFI_PS_NONE);       // disable modem sleep — critical for TLS stability
  WiFi.setTxPower(WIFI_POWER_19_5dBm);
  WiFi.setAutoReconnect(true);

  // Register disconnect handler for immediate reconnect
  WiFi.onEvent([](WiFiEvent_t event) {
    Serial.println("[rest] WiFi disconnected — auto-reconnecting...");
  }, WiFiEvent_t::ARDUINO_EVENT_WIFI_STA_DISCONNECTED);

  #ifndef OTA_SSID
  #error "OTA_SSID must be defined for REST server mode. Add ota.env and load_env.py to extra_scripts."
  #endif
  WiFi.begin(OTA_SSID, OTA_PASSWORD);
  uint8_t rest_tries = 0;
  while (WiFi.status() != WL_CONNECTED && rest_tries < 40) {
    delay(500);
    Serial.print(".");
    rest_tries++;
  }
  if (WiFi.status() == WL_CONNECTED) {
    Serial.println();
    Serial.print("[rest] WiFi connected, IP: ");
    Serial.println(WiFi.localIP());
    configTime(0, 0, "pool.ntp.org");
    uint32_t ntp_start = millis();
    while (time(nullptr) < 1700000000 && millis() - ntp_start < 15000) {
      delay(500);
      Serial.print(".");
    }
    if (time(nullptr) >= 1700000000) {
      Serial.println(" NTP OK");
      bolty_rest_server_start();
    } else {
      Serial.println(" NTP failed - HTTPS server NOT started");
    }
  } else {
    Serial.println(" WiFi failed");
  }
  Serial.println("REST mode ready. Type 'help' for serial commands.");
#endif
}

#if !HAS_WIFI || HAS_REST_SERVER
#include "serial_commands.h"
#endif
void loop(void) {

#if HAS_LED_MATRIX
  M5.update();
#endif

#if !HAS_WIFI
  button_loop();
  handle_events();
#endif

#if HAS_LED_MATRIX
  {
    static bool prev_held = false;
    bool held = button_is_held();
    if (held != prev_held) {
      if (!held) {
        atom_hold_action_fired = false;
      }
      prev_held = held;
    }
    led_set_held(held);
  }
  handle_atom_hold_reset();
#endif

#if HAS_LED_MATRIX && !HAS_WIFI
  if (!serial_cmd_active && bolty_hw_ready && !bolty_led_internal::animating) {
    static unsigned long last_card_poll = 0;
    static bool prev_card = false;
    if (millis() - last_card_poll > 200) {
      last_card_poll = millis();
      uint8_t poll_uid[12] = {0};
      uint8_t poll_len = 0;
      bool found = bolty_read_passive_target(bolt.nfc, poll_uid, &poll_len);
      if (found != prev_card) {
        if (found) {
          Serial.print("[nfc] card detected: ");
          for (uint8_t i = 0; i < poll_len; i++) {
            if (poll_uid[i] < 0x10) Serial.print("0");
            Serial.print(poll_uid[i], HEX);
          }
          Serial.println();
          signal_idle_card_kind(classify_idle_card(poll_uid, poll_len));
        } else {
          Serial.println("[nfc] card removed");
        }
        prev_card = found;
      }
    }
  }
#endif

  led_set_busy(serial_cmd_active);
#if HAS_WIFI
  led_set_app_mode(app_active);
#endif
  led_tick();

#if !HAS_WIFI
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    handle_serial_command(cmd);
  }
#elif HAS_REST_SERVER
  // REST mode: handle serial + WiFi health
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    handle_serial_command(cmd);
  }
  // Reconnect WiFi if dropped (critical for REST availability)
  if (WiFi.status() != WL_CONNECTED) {
    static unsigned long _last_wifi_attempt = 0;
    if (millis() - _last_wifi_attempt > 10000) {  // retry every 10s
      _last_wifi_attempt = millis();
      Serial.println("[rest] WiFi lost, reconnecting...");
      WiFi.disconnect();
      WiFi.begin(OTA_SSID, OTA_PASSWORD);
    }
  }
#else
  app_stateengine();
#endif

  delay(10);
}
