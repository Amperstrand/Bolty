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
#include "gui.h"
#include <SPI.h>

#if HAS_WIFI
#include <WiFi.h>
#include <Wire.h>
#include <esp_wifi.h>
#include <qrcode_rep.h>
#define DYNAMIC_JSON_DOCUMENT_SIZE 1024
#include "ArduinoJson.h"
#include "AsyncJson.h"
#include "ESPAsyncWebSrv.h"
#include "FS.h"
#include "SPIFFS.h"
#include <WiFiAP.h>
#define DEST_FS_USES_SPIFFS
#include <ESP32-targz.h>
#include "tarstream.h"
#include "tardata.h"
#endif

#if HAS_WIFI
#define WIFIMODE_AP 0
#define WIFIMODE_STA 1

#define CONFIGVERSION 1
#endif

#define WIFI_AP_PASSWORD_LENGTH 8

// uncommment the next line for static wifi password
//#define WIFI_AP_PASSWORD_STATIC "wango123"

#define HTTP_CREDENTIAL_SIZE 16

//if you change this do not exceed HTTP_CREDENTIAL_SIZE-1 chars!
const char* http_default_username = "bolty";
const char* http_default_password = "bolty";

#define MAX_BOLT_DEVICES 5
char charpool[] = {
    "qweertzunopaasdfghjkyxcvbnm-?234567890QWEERTYUOPAASDFGHJKLZXCVBNM"};

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

#define APPS (3)
#define APP_KEYSETUP (0)
#define APP_BOLTBURN (1)
#define APP_BOLTWIPE (2)

#define APP_STATUS_START (0)
#define APP_STATUS_LOOP (1)
#define APP_STATUS_END (2)

BoltDevice bolt(PN532_SCK, PN532_MISO, PN532_MOSI, PN532_SS);

// Forward declarations (needed for PlatformIO — Arduino IDE auto-generates these)
void dumpconfig();
void dumpsettings();

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
#if HAS_WIFI
IPAddress myIP;
#endif

uint8_t active_bolt_config;
sBoltConfig mBoltConfig;

bool signal_update_screen = false;
volatile bool serial_cmd_active = false;
int signal_restart_delayed = 0;

bool bolty_hw_ready = false;

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

#if HAS_WIFI
void saveSettings() {
  char path[20];
  sprintf(path, "/settings.dat");
  fs::File myFile = SPIFFS.open(path, FILE_WRITE);
  myFile.write((byte *)&mSettings, sizeof(sSettings));
  myFile.close();
}

//Extract files needed by the webserver from the data in tardata.h
void extractfiles(){
    Serial.println("Extracting files");
    Stream *HTMLTarStream = new TarStream(data_tar, (size_t) data_tar_len);
    //TarUnpacker *TARUnpacker = new TarUnpacker();
    //TARUnpacker->haltOnError(true);                                                            // stop on fail (manual restart/reset required)
    //TARUnpacker->setTarVerify(true);                                                           // true = enables health checks but slows down the overall process
    //TARUnpacker->setupFSCallbacks(targzTotalBytesFn, targzFreeBytesFn);                        // prevent the partition from exploding, recommended
    //TARGZUnpacker->setGzProgressCallback(BaseUnpacker::defaultProgressCallback ); // targzNullProgressCallback or defaultProgressCallback
    //TARUnpacker->setLoggerCallback(BaseUnpacker::targzPrintLoggerCallback);                    // gz log verbosity
    //TARUnpacker->setTarProgressCallback(BaseUnpacker::defaultProgressCallback);                // prints the untarring progress for each individual file
    //TARUnpacker->setTarStatusProgressCallback(BaseUnpacker::defaultTarStatusProgressCallback); // print the filenames as they're expanded
    //TARUnpacker->setTarMessageCallback(BaseUnpacker::targzPrintLoggerCallback);                // tar log verbosity  
    //if (!TARUnpacker->tarStreamExpander(HTMLTarStream, data_tar_len, tarGzFS, "/")){
    TarGzUnpacker *TARGZUnpacker = new TarGzUnpacker();
    TARGZUnpacker->haltOnError( true ); // stop on fail (manual restart/reset required)
    TARGZUnpacker->setTarVerify( true ); // true = enables health checks but slows down the overall process
    TARGZUnpacker->setupFSCallbacks( targzTotalBytesFn, targzFreeBytesFn ); // prevent the partition from exploding, recommended
    TARGZUnpacker->setGzProgressCallback( BaseUnpacker::defaultProgressCallback ); // targzNullProgressCallback or defaultProgressCallback
    TARGZUnpacker->setLoggerCallback( BaseUnpacker::targzPrintLoggerCallback  );    // gz log verbosity
    TARGZUnpacker->setTarProgressCallback( BaseUnpacker::defaultProgressCallback ); // prints the untarring progress for each individual file
    TARGZUnpacker->setTarStatusProgressCallback( BaseUnpacker::defaultTarStatusProgressCallback ); // print the filenames as they're expanded
    TARGZUnpacker->setTarMessageCallback( BaseUnpacker::targzPrintLoggerCallback ); // tar log verbosity
    if( !TARGZUnpacker->tarGzStreamExpander( HTMLTarStream, tarGzFS ) ) {
      Serial.println("Error while unpacking the webserver files");
      return;
    }
    //write version info
    fs::File myFile = SPIFFS.open("/fsversion.dat", FILE_WRITE);
    myFile.write((byte *) &fsversion, sizeof(fsversion));
    myFile.close();

    Serial.println("done!");
    
}

int checkFsVersion(){
  int myversion = -1;
  fs::File myFile = SPIFFS.open("/fsversion.dat", FILE_READ);
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

void loadSettings() {
  memset(&mSettings, 0, sizeof(sSettings));
}
#endif

#if HAS_WIFI
void saveBoltConfig(uint8_t slot) {
  char path[20];
  sprintf(path, "/config%02x.dat", slot);
  fs::File myFile = SPIFFS.open(path, FILE_WRITE);
  myFile.write((byte *)&mBoltConfig, sizeof(sBoltConfig));
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
  Serial.print(path);
  Serial.println(sizeof(((sBoltConfig *)0)->url));
  memset(&mBoltConfig, 0, sizeof(sBoltConfig));
  uint8_t testurl_enc[sizeof(((sBoltConfig *)0)->url)];
  uint8_t testurl[sizeof(((sBoltConfig *)0)->url)];
  if (SPIFFS.exists(path) == 1) {
    Serial.println(" found");
    fs::File myFile = SPIFFS.open(path, FILE_READ);
    myFile.read((byte *)&mBoltConfig, sizeof(sBoltConfig));
    myFile.close();
  } else {
    Serial.println(" not found");
    strcpy(mBoltConfig.card_name, "*new*");
    mBoltConfig.url[0] = 0;
    mBoltConfig.uid[0] = 0;
    mBoltConfig.k0[0] = 0;
    mBoltConfig.k1[0] = 0;
    mBoltConfig.k2[0] = 0;
    mBoltConfig.k3[0] = 0;
    mBoltConfig.k4[0] = 0;
    mBoltConfig.wallet_name[0] = 0;
    mBoltConfig.wallet_url[0] = 0;
    mBoltConfig.wallet_host[0] = 0;
  }
  dumpconfig();
}

String exportBoltConfig() {
  String path = "/backup.dat";
  SPIFFS.remove(path);
  fs::File myFile = SPIFFS.open(path, FILE_APPEND);
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
#else
void saveBoltConfig(uint8_t slot) {
  (void)slot;
}

void loadBoltConfig(uint8_t slot) {
  (void)slot;
  memset(&mBoltConfig, 0, sizeof(sBoltConfig));
  strcpy(mBoltConfig.card_name, "*new*");
}

String exportBoltConfig() {
  return String();
}

void importBoltConfig() {}
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
void led_on() {}
void led_off() {}
void led_blink(int, int) {}
#endif

// Keysetup
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
  // Serial.println("web_keysetup_loop");
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
  return processor_default(var);
}
#endif

void app_keysetup_end() { Serial.println("app_KEYSETUP_end"); }

// Ringsetup
void APP_BOLTBURN_start() { Serial.println("APP_BOLTBURN_start"); }

uint32_t previousMillis;
uint32_t Interval = 100;

void APP_BOLTBURN_loop() {
  // Serial.println("APP_BOLTBURN_loop");
  // set the keys
  if (millis() - previousMillis < Interval) {
    return;
  }
  previousMillis = millis();
  Interval = 100;
  if (bolty_hw_ready) {
    bolt.setDefautKeysCur();
    bolt.setNewKey(mBoltConfig.k0, 0);
    bolt.setNewKey(mBoltConfig.k1, 1);
    bolt.setNewKey(mBoltConfig.k2, 2);
    bolt.setNewKey(mBoltConfig.k3, 3);
    bolt.setNewKey(mBoltConfig.k4, 4);
    String lnurl = String(mBoltConfig.url);
    uint8_t burn_result = bolt.burn(lnurl);
    if (burn_result != JOBSTATUS_WAITING) {
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
  /*if (var == "essid")
    //if (mSettings.wifimode == WIFIMODE_STA)
    return String(mSettings.essid);
   */
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
  // Serial.println("APP_BOLTWIPE_loop");
  if (millis() - previousMillis < Interval) {
    return;
  }
  previousMillis = millis();
  Interval = 100;
  if (bolty_hw_ready) {
    bolt.setDefautKeysNew();
    bolt.setCurKey(mBoltConfig.k0, 0);
    bolt.setCurKey(mBoltConfig.k1, 1);
    bolt.setCurKey(mBoltConfig.k2, 2);
    bolt.setCurKey(mBoltConfig.k3, 3);
    bolt.setCurKey(mBoltConfig.k4, 4);
    uint8_t wipe_result = bolt.wipe();
    if (wipe_result != JOBSTATUS_WAITING) {
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

void handle_events() {
#if HAS_BUTTONS
  // Button 0 short clicky = next keyset
  if ((sharedvars.appbuttons[0] == 1) && (app_active != APP_KEYSETUP)) {
    // we dont want to interrupt anything done with keyysetup
    active_bolt_config += 1;
    if (active_bolt_config >= MAX_BOLT_DEVICES) {
      active_bolt_config = 0;
    }
    loadBoltConfig(active_bolt_config);
    signal_update_screen = true;
  }
  // Button 1 short clicky = next app
  if ((sharedvars.appbuttons[1] == 1) && (app_active != APP_KEYSETUP)) {
    // we dont want to interrupt anything done with keyysetup
    app_next = app_active + 1;
    if (app_next > APPS - 1) {
      app_next = 1;
    }
  }
  // Button 0 long clicky =
  if (sharedvars.appbuttons[0] == 2) {
    wifi_toogle();
    signal_update_screen = true;
  }
  // Button 1 long clicky =
  if (sharedvars.appbuttons[1] == 2) {
    nfc_stop();
    esp_sleep_enable_ext0_wakeup(GPIO_NUM_35, 0); // 1 = High, 0 = Low
    esp_deep_sleep_start();
  }
  // Button 0 double clicky =
  if (sharedvars.appbuttons[0] == 3) {
    Serial.println("double click btn0");
    String wurl =
        String(mBoltConfig.wallet_host) + "?" + String(mBoltConfig.wallet_url);
    Serial.println(wurl);
    // displayQR(wurl);
  }
  // Button 1 duoble clicky =
  if (sharedvars.appbuttons[1] == 3) {
    Serial.println("double click btn1");
  }
  // reset button events
  sharedvars.appbuttons[0] = 0;
  sharedvars.appbuttons[1] = 0;
#else
  sharedvars.appbuttons[0] = 0;
  sharedvars.appbuttons[1] = 0;
#endif
}

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

void dumpconfig() {
  Serial.println(mBoltConfig.wallet_name);
  Serial.println(mBoltConfig.wallet_host);
  Serial.println(mBoltConfig.wallet_url);
  Serial.println(mBoltConfig.uid);
  Serial.println(mBoltConfig.card_name);
  Serial.println(mBoltConfig.url);
  Serial.println(mBoltConfig.k0);
  Serial.println(mBoltConfig.k1);
  Serial.println(mBoltConfig.k2);
  Serial.println(mBoltConfig.k3);
  Serial.println(mBoltConfig.k4);
}

void dumpsettings() {
  Serial.println(mSettings.wifimode);
  Serial.println(mSettings.essid);
  Serial.println(mSettings.password);
  Serial.println(mSettings.wifi_enabled);
  Serial.println(mSettings.http_username);
  Serial.println(mSettings.http_password);
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

void randomchar(char *outbuf, uint8_t count) {
  for (uint8_t i = 0; i < count; i++) {
    Serial.print(i);
    Serial.print(":");
    outbuf[i] = charpool[random(0, 63)];
    Serial.println(outbuf[i]);
  }
  outbuf[count] = 0;
}

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
  digitalWrite(PN532_RSTPD_N, HIGH);
}

void nfc_stop() {
  Serial.println("switching nfc off");
  digitalWrite(PN532_RSTPD_N, LOW);
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

  setup_display();

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
  pinMode(PN532_RSTPD_N, OUTPUT);
#if LED_PIN >= 0
  pinMode(LED_PIN, OUTPUT);
  led_off();
#endif
  nfc_start();
  bolty_hw_ready = bolt.begin();
  Serial.println("Setup done!");
  app_active = APP_KEYSETUP;
#if HAS_WIFI
  app_next = APP_BOLTBURN;
#else
  app_next = APP_KEYSETUP;
#endif
  app_status = APP_STATUS_START;
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
    // request->send(SPIFFS, "/setup.html", String(), false,
    // web_keysetup_processor);
  });
  // Route for root / web page
  server.on("/wipe", HTTP_GET, [](AsyncWebServerRequest *request) {
    // Serial.println("request wipe");
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
        // Serial.println(bolt.get_job_status());
        request->send(200, "application/json",
                      "{\"status\":\"" + bolt.get_job_status() +
                          "\",\"app\":\"" + app_active + "\",\"cnn\":\"" +
                          (active_bolt_config + 1) + "\"}");
      });

  server.addHandler(handler);

  AsyncCallbackJsonWebHandler *handler_uid = new AsyncCallbackJsonWebHandler(
      "/uid", [](AsyncWebServerRequest *request, JsonVariant &json) {
        // Serial.println(bolt.get_job_status());
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
          strcpy(mBoltConfig.card_name, data["card_name"]);
        if (data.containsKey("lnurlw_base"))
          strcpy(mBoltConfig.url, data["lnurlw_base"]);
        if (data.containsKey("wallet_name"))
          strcpy(mBoltConfig.wallet_name, data["wallet_name"]);
        if (data.containsKey("wallet_url"))
          strcpy(mBoltConfig.wallet_url, data["wallet_url"]);
        if (data.containsKey("wallet_host"))
          strcpy(mBoltConfig.wallet_host, data["wallet_host"]);
        if (data.containsKey("uid"))
          strcpy(mBoltConfig.uid, data["uid"]);
        if (data.containsKey("k0"))
          strcpy(mBoltConfig.k0, data["k0"]);
        if (data.containsKey("k1"))
          strcpy(mBoltConfig.k1, data["k1"]);
        if (data.containsKey("k2"))
          strcpy(mBoltConfig.k2, data["k2"]);
        if (data.containsKey("k3"))
          strcpy(mBoltConfig.k3, data["k3"]);
        if (data.containsKey("k4"))
          strcpy(mBoltConfig.k4, data["k4"]);
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
          strcpy(mSettings.essid, data["essid"]);
        }
        if ((data["password"] != "*123--keep-my-current-password--321*")) {
          strcpy(mSettings.password, data["password"]);
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
          strcpy(mSettings.http_username, data["http_u"]);
        }
        if (data["http_p"] != "") {
          strcpy(mSettings.http_password, data["http_p"]);
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
  led_blink(bolty_hw_ready ? 2 : 5, 100);
#endif
}

#if !HAS_WIFI

void serial_print_help() {
  Serial.println();
  Serial.println(F("=== Bolty Headless Mode ==="));
  Serial.println(F("Commands:"));
  Serial.println(F("  help              Show this help"));
  Serial.println(F("  uid               Scan card and print UID"));
  Serial.println(F("  status            Print current config and status"));
  Serial.println(F("  keys <k0> <k1> <k2> <k3> <k4>  Set 5 keys (32-char hex each)"));
  Serial.println(F("  url <lnurl>        Set LNURL for burn"));
  Serial.println(F("  burn              Burn card (tap card, uses keys+url)"));
  Serial.println(F("  wipe              Wipe card (tap card, uses keys)"));
  Serial.println(F("  ndef              Read NDEF message (no auth needed)"));
  Serial.println(F("  auth              Test k0 authentication (tap card)"));
  Serial.println(F("  ver               GetVersion + NTAG424 check (tap card)"));
  Serial.println();
}

void serial_print_status() {
  Serial.println();
  Serial.print(F("  NFC HW: ")); Serial.println(bolty_hw_ready ? F("ready") : F("NOT ready"));
  Serial.print(F("  Last UID: ")); Serial.println(bolt.getScannedUid());
  Serial.print(F("  Job: ")); Serial.println(bolt.get_job_status());
  Serial.print(F("  Card: ")); Serial.println(mBoltConfig.card_name);
  Serial.print(F("  LNURL: ")); Serial.println(mBoltConfig.url);
  Serial.print(F("  k0: ")); Serial.println(mBoltConfig.k0);
  Serial.print(F("  k1: ")); Serial.println(mBoltConfig.k1);
  Serial.print(F("  k2: ")); Serial.println(mBoltConfig.k2);
  Serial.print(F("  k3: ")); Serial.println(mBoltConfig.k3);
  Serial.print(F("  k4: ")); Serial.println(mBoltConfig.k4);
  Serial.println();
}

void handle_serial_command(String cmd) {
  cmd.trim();
  if (cmd.length() == 0) return;

  if (cmd == "help") {
    serial_print_help();
  }
  else if (cmd == "uid") {
    Serial.println(F("[cmd] Scanning for card..."));
    if (bolty_hw_ready) {
      led_on();
      if (bolt.scanUID()) {
        led_blink(3, 100);
        Serial.print(F("[uid] ")); Serial.println(bolt.getScannedUid());
        Serial.print(F("[ntag424] "));
        Serial.println(bolt.nfc->ntag424_isNTAG424() ? "YES" : "NO");
      } else {
        led_off();
        Serial.println(F("[uid] No card detected"));
      }
    } else {
      led_off();
      Serial.println(F("[error] NFC hardware not ready"));
    }
  }
  else if (cmd == "status") {
    serial_print_status();
  }
  else if (cmd == "auth") {
    if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
    Serial.println(F("[auth] Tap card now..."));
    serial_cmd_active = true;
    led_on();
    bolt.setCurKey(String(mBoltConfig.k0), 0);
    Serial.print(F("[auth] Trying k0: "));
    for (int i = 0; i < 16; i++) { if (bolt.key_cur[0][i] < 0x10) Serial.print("0"); Serial.print(bolt.key_cur[0][i], HEX); }
    Serial.println();
    Serial.print(F("[auth] k0 bytes: "));
    for (int i = 0; i < 16; i++) {
      Serial.print(bolt.key_cur[0][i], DEC);
      Serial.print(" ");
    }
    Serial.println();
    unsigned long t0 = millis();
    bool found = false;
    do {
      uint8_t uid[7] = {0};
      uint8_t uidLen;
      found = bolt.nfc->readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLen, 100);
      if (found) {
        Serial.print(F("[auth] UID: "));
        bolt.nfc->PrintHex(uid, uidLen);
      }
      if (millis() - t0 > 15000) { Serial.println(F("[auth] TIMEOUT")); serial_cmd_active = false; return; }
    } while (!found);
    delay(50);
    Serial.println(F("[auth] About to authenticate..."));
    uint8_t result = bolt.nfc->ntag424_Authenticate(bolt.key_cur[0], 0, 0x71);
    Serial.print(F("[auth] ntag424_Authenticate returned: "));
    Serial.println(result);
    Serial.print(F("[auth] Session authenticated: "));
    Serial.println(bolt.nfc->ntag424_Session.authenticated);
    Serial.print(F("[auth] Result: "));
    Serial.println(result == 1 ? "SUCCESS" : "FAILED");
    led_blink(result == 1 ? 3 : 5, 100);
    serial_cmd_active = false;
  }
  else if (cmd == "ndef") {
    if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
    Serial.println(F("[ndef] Tap card now..."));
    serial_cmd_active = true;
    led_on();
    uint8_t uid[7] = {0};
    uint8_t uid_len = 0;
    if (bolt.nfc->readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uid_len, 2000)) {
      uint8_t ndef[256] = {0};
      uint8_t len = bolt.nfc->ntag424_ISOReadFile(ndef, 256);
      if (len > 0) {
        Serial.print(F("[ndef] HEX ("));
        Serial.print(len);
        Serial.print(F(" bytes): "));
        bolt.nfc->PrintHex(ndef, len > 128 ? 128 : len);
        Serial.print(F("[ndef] ASCII: "));
        for (int i = 0; i < len && i < 256; i++) {
          Serial.write(ndef[i] >= 0x20 && ndef[i] < 0x7F ? ndef[i] : '.');
        }
        Serial.println();
        led_blink(3, 100);
      } else {
        Serial.println(F("[ndef] No NDEF data (card may not be NTAG424)"));
        led_blink(5, 100);
      }
    } else {
      Serial.println(F("[ndef] No card detected"));
      led_blink(5, 100);
    }
    serial_cmd_active = false;
  }
  else if (cmd == "ver") {
    if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
    serial_cmd_active = true;
    uint8_t uid[7] = {0};
    uint8_t uidLen;
    uint8_t ok = bolt.nfc->readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLen, 100);
    Serial.print(F("[ver] Card detected: "));
    Serial.println(ok ? "YES" : "NO");
    if (ok) {
      bolt.nfc->ntag424_GetVersion();
      Serial.print(F("[ver] HWType: 0x"));
      Serial.print(bolt.nfc->ntag424_VersionInfo.HWType, HEX);
      Serial.print(F(" expected: 0x04 match: "));
      Serial.println(bolt.nfc->ntag424_VersionInfo.HWType == 0x04 ? "YES" : "NO");
      Serial.print(F("[ver] isNTAG424: "));
      Serial.println(bolt.nfc->ntag424_isNTAG424() ? "YES" : "NO");
      Serial.print(F("[ver] HWType after isNTAG424: 0x"));
      Serial.println(bolt.nfc->ntag424_VersionInfo.HWType, HEX);
    }
    serial_cmd_active = false;
  }
  else if (cmd.startsWith("keys ")) {
    String args = cmd.substring(5);
    int s1 = args.indexOf(' ');
    int s2 = args.indexOf(' ', s1 + 1);
    int s3 = args.indexOf(' ', s2 + 1);
    int s4 = args.indexOf(' ', s3 + 1);
    if (s1 < 0 || s2 < 0 || s3 < 0 || s4 < 0) {
      Serial.println(F("[error] Usage: keys <k0> <k1> <k2> <k3> <k4>"));
      return;
    }
    String k0 = args.substring(0, s1);
    String k1 = args.substring(s1 + 1, s2);
    String k2 = args.substring(s2 + 1, s3);
    String k3 = args.substring(s3 + 1, s4);
    String k4 = args.substring(s4 + 1);
    if (k0.length() != 32 || k1.length() != 32 || k2.length() != 32 ||
        k3.length() != 32 || k4.length() != 32) {
      Serial.println(F("[error] Each key must be exactly 32 hex chars"));
      return;
    }
    strncpy(mBoltConfig.k0, k0.c_str(), 33);
    strncpy(mBoltConfig.k1, k1.c_str(), 33);
    strncpy(mBoltConfig.k2, k2.c_str(), 33);
    strncpy(mBoltConfig.k3, k3.c_str(), 33);
    strncpy(mBoltConfig.k4, k4.c_str(), 33);
    Serial.println(F("[keys] Keys set"));
    Serial.print(F("  k0: ")); Serial.println(k0);
    Serial.print(F("  k4: ")); Serial.println(k4);
  }
  else if (cmd.startsWith("url ")) {
    String url = cmd.substring(4);
    url.trim();
    if (url.length() == 0) {
      Serial.println(F("[error] Usage: url <lnurl>"));
      return;
    }
    strncpy(mBoltConfig.url, url.c_str(), sizeof(mBoltConfig.url));
    Serial.print(F("[url] Set to: ")); Serial.println(url);
  }
  else if (cmd == "burn") {
    if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
    if (strlen(mBoltConfig.url) == 0) { Serial.println(F("[error] No LNURL. Use: url <lnurl>")); return; }
    if (strlen(mBoltConfig.k0) == 0) { Serial.println(F("[error] No keys. Use: keys <k0> <k1> <k2> <k3> <k4>")); return; }
    Serial.println(F("[burn] Tap card now..."));
    serial_cmd_active = true;
    led_on();
    bolt.setDefautKeysCur();
    bolt.setNewKey(mBoltConfig.k0, 0);
    bolt.setNewKey(mBoltConfig.k1, 1);
    bolt.setNewKey(mBoltConfig.k2, 2);
    bolt.setNewKey(mBoltConfig.k3, 3);
    bolt.setNewKey(mBoltConfig.k4, 4);
    uint8_t result;
    unsigned long t0 = millis();
    do {
      while (Serial.available()) Serial.read();
      String lnurl = String(mBoltConfig.url);
      result = bolt.burn(lnurl);
      if (millis() - t0 > 30000) {
        Serial.println(F("[burn] TIMEOUT — no card detected in 30s"));
        serial_cmd_active = false;
        return;
      }
    } while (result == JOBSTATUS_WAITING);
    Serial.print(F("[burn] ")); Serial.println(bolt.get_job_status());
    Serial.println(result == JOBSTATUS_DONE ? F("[burn] SUCCESS") : F("[burn] FAILED"));
    led_blink(result == JOBSTATUS_DONE ? 3 : 5, 100);
    serial_cmd_active = false;
  }
  else if (cmd == "wipe") {
    if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
    if (strlen(mBoltConfig.k0) == 0) { Serial.println(F("[error] No keys. Use: keys <k0> <k1> <k2> <k3> <k4>")); return; }
    Serial.println(F("[wipe] Tap card now..."));
    serial_cmd_active = true;
    led_on();
    bolt.setDefautKeysNew();
    bolt.setCurKey(mBoltConfig.k0, 0);
    bolt.setCurKey(mBoltConfig.k1, 1);
    bolt.setCurKey(mBoltConfig.k2, 2);
    bolt.setCurKey(mBoltConfig.k3, 3);
    bolt.setCurKey(mBoltConfig.k4, 4);
    uint8_t result;
    unsigned long t0 = millis();
    do {
      while (Serial.available()) Serial.read();
      result = bolt.wipe();
      if (millis() - t0 > 30000) {
        Serial.println(F("[wipe] TIMEOUT — no card detected in 30s"));
        serial_cmd_active = false;
        return;
      }
    } while (result == JOBSTATUS_WAITING);
    Serial.print(F("[wipe] ")); Serial.println(bolt.get_job_status());
    Serial.println(result == JOBSTATUS_DONE ? F("[wipe] SUCCESS") : F("[wipe] FAILED"));
    led_blink(result == JOBSTATUS_DONE ? 3 : 5, 100);
    serial_cmd_active = false;
  }
  else {
    Serial.print(F("[error] Unknown: ")); Serial.println(cmd);
  }
}

#endif

void loop(void) {

#if !HAS_WIFI
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    handle_serial_command(cmd);
  }
#else
  app_stateengine();
#endif

  delay(10);
}
