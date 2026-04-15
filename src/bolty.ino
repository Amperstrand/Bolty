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
#include "build_metadata.h"
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
    bolt.loadKeysForBurn(mBoltConfig);
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
    bolt.loadKeysForWipe(mBoltConfig);
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

  Serial.println("=== Bolty Build Info ===");
  Serial.print("Bolty commit: ");
  Serial.println(BOLTY_GIT_COMMIT);
  Serial.print("PN532 lib commit: ");
  Serial.println(PN532_LIB_GIT_COMMIT);
  Serial.println("========================");

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
  // Issue #7: force a real PN532 hardware reset before startup. RIOT-OS keeps
  // RSTPD_N low for 400 ms, and ESPEasy also relies on reinit when the reader
  // stops responding after repeated errors.
  digitalWrite(PN532_RSTPD_N, LOW);
  delay(100);
  digitalWrite(PN532_RSTPD_N, HIGH);
  delay(10);
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
  Serial.println(F("  inspect           Full read-only card inspection (no auth, no writes)"));
  Serial.println(F("  derivekeys        Load deterministic keys from read-only p=/c= verification"));
  Serial.println(F("  auth              Test k0 authentication (tap card)"));
  Serial.println(F("  ver               GetVersion + NTAG424 check (tap card)"));
  Serial.println(F("  keyver            Read key versions (blank/provisioned check, tap card)"));
  Serial.println(F("  diagnose          Auth-based state detection (for recovery work)"));
  Serial.println(F("  --- Safety / Testing ---"));
  Serial.println(F("  check             Auth with factory zero keys (confirm card is blank)"));
  Serial.println(F("  dummyburn         Burn with zero keys + dummy URL (test write path)"));
  Serial.println(F("  recoverkey <n> <hex>  Recover key slot n (0-4) with candidate old key"));
  Serial.println(F("  reset             Reset NDEF+SDM on factory-key card (keys unchanged)"));
  Serial.println(F("  testck            ChangeKey A/B test on key 1 (verify implementation)"));
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

// ntag424_getKeyVersion moved to bolt.h for use by burn/wipe guards

const char* ntag424_error_name(uint8_t sw1, uint8_t sw2) {
  if (sw1 == 0x91) {
    switch (sw2) {
      case 0x00: return "OK";
      case 0xAE: return "AUTHENTICATION_ERROR";
      case 0xBE: return "BOUNDARY_ERROR";
      case 0xEE: return "MEMORY_ERROR";
      case 0x1E: return "INTEGRITY_ERROR";
      case 0x7E: return "LENGTH_ERROR";
      case 0x9D: return "PERMISSION_DENIED";
      case 0xCA: return "COMMAND_ABORTED";
      case 0x9E: return "PARAMETER_ERROR";
      case 0x40: return "NO_SUCH_KEY";
      case 0xAD: return "AUTHENTICATION_DELAY";
      case 0xF0: return "FILE_NOT_FOUND";
      default:   return "UNKNOWN_ERROR";
    }
  }
  if (sw1 == 0x69) {
    switch (sw2) {
      case 0x82: return "SECURITY_STATUS_NOT_SATISFIED";
      case 0x85: return "CONDITIONS_NOT_SATISFIED";
      case 0x88: return "REF_DATA_INVALID";
      default:   return "UNKNOWN_ERROR";
    }
  }
  if (sw1 == 0x6A && sw2 == 0x82) return "FILE_NOT_FOUND";
  if (sw1 == 0x6A && sw2 == 0x86) return "INCORRECT_P1_P2";
  return "UNKNOWN_ERROR";
}

static void print_hex_byte_prefixed(uint8_t value) {
  if (value < 0x10) Serial.print(F("0"));
  Serial.print(value, HEX);
}

static uint8_t bcd_to_decimal(uint8_t value) {
  return (uint8_t)(((value >> 4) & 0x0F) * 10 + (value & 0x0F));
}

static uint32_t decode_u24_le(const uint8_t *buf) {
  return (uint32_t)buf[0] | ((uint32_t)buf[1] << 8) | ((uint32_t)buf[2] << 16);
}

static bool ndef_extract_uri(const uint8_t *ndef, int len, String &uri) {
  if (ndef == nullptr || len < 5) return false;

  for (int i = 0; i <= len - 5; i++) {
    if (ndef[i] == 0xD1 && ndef[i + 1] == 0x01 && ndef[i + 3] == 0x55) {
      const int payload_len = ndef[i + 2];
      if (payload_len < 1 || i + 4 + payload_len > len) return false;

      const uint8_t prefix = ndef[i + 4];
      switch (prefix) {
        case 0x00: uri = ""; break;
        case 0x01: uri = "http://www."; break;
        case 0x02: uri = "https://www."; break;
        case 0x03: uri = "http://"; break;
        case 0x04: uri = "https://"; break;
        default: uri = ""; break;
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

static void print_ndef_ascii(const uint8_t *ndef, int len) {
  for (int i = 0; i < len; i++) {
    Serial.write(ndef[i] >= 0x20 && ndef[i] < 0x7F ? ndef[i] : '.');
  }
  Serial.println();
}

static void print_boltcard_heuristics(const String &uri) {
  Serial.println(F("[inspect] --- Boltcard Heuristics ---"));
  if (uri.length() == 0) {
    Serial.println(F("[inspect] No URI record found in NDEF."));
    return;
  }

  const bool has_lnurlw = uri.startsWith("lnurlw://") || uri.indexOf("lnurlw://") >= 0;
  const int p_idx = uri.indexOf("p=");
  const int c_idx = uri.indexOf("c=");
  const bool has_p = p_idx >= 0;
  const bool has_c = c_idx >= 0;

  Serial.print(F("[inspect] URI has lnurlw scheme: "));
  Serial.println(has_lnurlw ? F("YES") : F("NO"));
  Serial.print(F("[inspect] URI has p= param: "));
  Serial.println(has_p ? F("YES") : F("NO"));
  Serial.print(F("[inspect] URI has c= param: "));
  Serial.println(has_c ? F("YES") : F("NO"));

  if (has_p) {
    Serial.print(F("[inspect] p= offset in URI: "));
    Serial.println(p_idx);
  }
  if (has_c) {
    Serial.print(F("[inspect] c= offset in URI: "));
    Serial.println(c_idx);
  }

  const bool looks_boltcard = has_lnurlw || (has_p && has_c);
  Serial.print(F("[inspect] Looks like Bolt Card: "));
  Serial.println(looks_boltcard ? F("YES") : F("NO / UNKNOWN"));
}

static bool hex_nibble(char ch, uint8_t &value) {
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

static bool parse_hex_fixed(const String &hex, uint8_t *out, size_t out_len) {
  if (hex.length() != (int)(out_len * 2)) return false;
  for (size_t i = 0; i < out_len; i++) {
    uint8_t upper = 0;
    uint8_t lower = 0;
    if (!hex_nibble(hex[(int)(i * 2)], upper) || !hex_nibble(hex[(int)(i * 2 + 1)], lower)) {
      return false;
    }
    out[i] = (uint8_t)((upper << 4) | lower);
  }
  return true;
}

static bool uri_get_query_param(const String &uri, const char *name, String &value) {
  value = "";
  const int query_idx = uri.indexOf('?');
  if (query_idx < 0) return false;

  const String needle = String(name) + "=";
  const int start = uri.indexOf(needle, query_idx + 1);
  if (start < 0) return false;

  const int value_start = start + needle.length();
  int value_end = uri.indexOf('&', value_start);
  if (value_end < 0) value_end = uri.length();
  value = uri.substring(value_start, value_end);
  return value.length() > 0;
}

static void print_hex_bytes_inline(const uint8_t *data, size_t len) {
  for (size_t i = 0; i < len; i++) {
    if (data[i] < 0x10) Serial.print(F("0"));
    Serial.print(data[i], HEX);
  }
}

static void store_hex_string(char *out, size_t out_size, const uint8_t *data, uint8_t len) {
  if (out == nullptr || out_size == 0 || data == nullptr) return;
  String hex = convertIntToHex((uint8_t *)data, len);
  strncpy(out, hex.c_str(), out_size - 1);
  out[out_size - 1] = '\0';
}

static void store_bolt_config_keys_from_bytes(sBoltConfig &config, const uint8_t keys[5][16]) {
  store_hex_string(config.k0, sizeof(config.k0), keys[0], 16);
  store_hex_string(config.k1, sizeof(config.k1), keys[1], 16);
  store_hex_string(config.k2, sizeof(config.k2), keys[2], 16);
  store_hex_string(config.k3, sizeof(config.k3), keys[3], 16);
  store_hex_string(config.k4, sizeof(config.k4), keys[4], 16);
}

static void write_u32_le(uint32_t value, uint8_t out[4]) {
  out[0] = (uint8_t)(value & 0xFF);
  out[1] = (uint8_t)((value >> 8) & 0xFF);
  out[2] = (uint8_t)((value >> 16) & 0xFF);
  out[3] = (uint8_t)((value >> 24) & 0xFF);
}

static const uint8_t BOLTCARD_DET_TAG_CARDKEY[4] = {0x2D, 0x00, 0x3F, 0x75};
static const uint8_t BOLTCARD_DET_TAG_K0[4] = {0x2D, 0x00, 0x3F, 0x76};
static const uint8_t BOLTCARD_DET_TAG_K1[4] = {0x2D, 0x00, 0x3F, 0x77};
static const uint8_t BOLTCARD_DET_TAG_K2[4] = {0x2D, 0x00, 0x3F, 0x78};
static const uint8_t BOLTCARD_DET_TAG_K3[4] = {0x2D, 0x00, 0x3F, 0x79};
static const uint8_t BOLTCARD_DET_TAG_K4[4] = {0x2D, 0x00, 0x3F, 0x7A};
static const uint8_t BOLTCARD_ISSUER_KEY_ZERO[16] = {0};
static const uint8_t BOLTCARD_ISSUER_KEY_DEV[16] = {
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x01,
};
static const uint32_t BOLTCARD_VERSION_CANDIDATES[2] = {1, 0};

struct DeterministicBoltcardMatch {
  bool saw_k1_match;
  bool full_match;
  uint32_t counter;
  uint32_t version;
  uint8_t issuer_key[16];
  uint8_t decrypted[16];
  uint8_t keys[5][16];
};

static void derive_deterministic_card_key(Adafruit_PN532 *nfc,
                                          const uint8_t issuer_key[16],
                                          const uint8_t uid[7],
                                          uint32_t version,
                                          uint8_t out_card_key[16]) {
  (void)nfc;
  uint8_t msg[15] = {0};
  memcpy(msg, BOLTCARD_DET_TAG_CARDKEY, 4);
  memcpy(msg + 4, uid, 7);
  write_u32_le(version, msg + 11);
  AES128_CMAC(issuer_key, msg, sizeof(msg), out_card_key);
}

static void derive_deterministic_boltcard_keys(Adafruit_PN532 *nfc,
                                               const uint8_t issuer_key[16],
                                               const uint8_t uid[7],
                                               uint32_t version,
                                               uint8_t out_keys[5][16]) {
  (void)nfc;
  uint8_t card_key[16] = {0};
  derive_deterministic_card_key(nfc, issuer_key, uid, version, card_key);
  AES128_CMAC(card_key, BOLTCARD_DET_TAG_K0, sizeof(BOLTCARD_DET_TAG_K0), out_keys[0]);
  AES128_CMAC(issuer_key, BOLTCARD_DET_TAG_K1, sizeof(BOLTCARD_DET_TAG_K1), out_keys[1]);
  AES128_CMAC(card_key, BOLTCARD_DET_TAG_K2, sizeof(BOLTCARD_DET_TAG_K2), out_keys[2]);
  AES128_CMAC(card_key, BOLTCARD_DET_TAG_K3, sizeof(BOLTCARD_DET_TAG_K3), out_keys[3]);
  AES128_CMAC(card_key, BOLTCARD_DET_TAG_K4, sizeof(BOLTCARD_DET_TAG_K4), out_keys[4]);
}

static bool deterministic_decrypt_p(Adafruit_PN532 *nfc,
                                    const uint8_t k1[16],
                                    const uint8_t p[16],
                                    const uint8_t uid[7],
                                    uint8_t decrypted[16],
                                    uint32_t &counter_out) {
  if (!nfc->ntag424_decrypt((uint8_t *)k1, 16, (uint8_t *)p, decrypted)) {
    return false;
  }
  if (decrypted[0] != 0xC7) return false;
  if (memcmp(decrypted + 1, uid, 7) != 0) return false;
  counter_out = decode_u24_le(decrypted + 8);
  return true;
}

static bool deterministic_verify_cmac(Adafruit_PN532 *nfc,
                                      const uint8_t k2[16],
                                      const uint8_t uid[7],
                                      uint32_t counter,
                                      const uint8_t expected_c[8]) {
  (void)nfc;
  uint8_t sv2[16] = {0x3C, 0xC3, 0x00, 0x01, 0x00, 0x80};
  memcpy(sv2 + 6, uid, 7);
  sv2[13] = (uint8_t)(counter & 0xFF);
  sv2[14] = (uint8_t)((counter >> 8) & 0xFF);
  sv2[15] = (uint8_t)((counter >> 16) & 0xFF);

  uint8_t session_key[16] = {0};
  AES128_CMAC(k2, sv2, sizeof(sv2), session_key);

  uint8_t full_cmac[16] = {0};
  AES128_CMAC(session_key, nullptr, 0, full_cmac);

  uint8_t computed_c[8] = {0};
  for (int i = 0; i < 8; i++) {
    computed_c[i] = full_cmac[(i * 2) + 1];
  }
  return memcmp(computed_c, expected_c, sizeof(computed_c)) == 0;
}

static bool deterministic_try_known_matches(Adafruit_PN532 *nfc,
                                            const uint8_t *uid,
                                            uint8_t uid_len,
                                            const String &uri,
                                            DeterministicBoltcardMatch &match) {
  memset(&match, 0, sizeof(match));
  if (uid == nullptr || uid_len != 7 || uri.length() == 0) return false;

  String p_hex;
  if (!uri_get_query_param(uri, "p", p_hex)) return false;

  uint8_t p_bytes[16] = {0};
  if (!parse_hex_fixed(p_hex, p_bytes, sizeof(p_bytes))) return false;

  String c_hex;
  const bool has_c = uri_get_query_param(uri, "c", c_hex);
  uint8_t c_bytes[8] = {0};
  const bool c_parse_ok = has_c && parse_hex_fixed(c_hex, c_bytes, sizeof(c_bytes));

  for (int candidate = 0; candidate < 2; candidate++) {
    const uint8_t *issuer_key = (candidate == 0) ? BOLTCARD_ISSUER_KEY_ZERO : BOLTCARD_ISSUER_KEY_DEV;

    uint8_t keys_v1[5][16] = {{0}};
    derive_deterministic_boltcard_keys(nfc, issuer_key, uid, 1, keys_v1);

    uint8_t decrypted[16] = {0};
    uint32_t counter = 0;
    const bool k1_match = deterministic_decrypt_p(nfc, keys_v1[1], p_bytes, uid, decrypted, counter);
    if (!k1_match) continue;

    match.saw_k1_match = true;
    memcpy(match.issuer_key, issuer_key, sizeof(match.issuer_key));
    memcpy(match.decrypted, decrypted, sizeof(match.decrypted));
    match.counter = counter;

    if (!c_parse_ok) {
      return false;
    }

    for (int version_idx = 0; version_idx < 2; version_idx++) {
      const uint32_t version = BOLTCARD_VERSION_CANDIDATES[version_idx];
      uint8_t derived_keys[5][16] = {{0}};
      derive_deterministic_boltcard_keys(nfc, issuer_key, uid, version, derived_keys);
      if (!deterministic_verify_cmac(nfc, derived_keys[2], uid, counter, c_bytes)) continue;

      match.full_match = true;
      match.version = version;
      memcpy(match.keys, derived_keys, sizeof(match.keys));
      return true;
    }

    return false;
  }

  return false;
}

static void print_deterministic_boltcard_check(Adafruit_PN532 *nfc,
                                               const uint8_t *uid,
                                               uint8_t uid_len,
                                               const String &uri) {
  Serial.println(F("[inspect] --- Deterministic Key Derivation Check ---"));

  if (uid_len != 7) {
    Serial.println(F("[inspect] SKIPPED — deterministic Bolt Card derivation expects a 7-byte UID."));
    return;
  }
  if (uri.length() == 0) {
    Serial.println(F("[inspect] SKIPPED — no URI available for read-only deterministic verification."));
    return;
  }

  String p_hex;
  if (!uri_get_query_param(uri, "p", p_hex)) {
    Serial.println(F("[inspect] SKIPPED — URI has no p= parameter to decrypt."));
    return;
  }

  uint8_t p_bytes[16] = {0};
  if (!parse_hex_fixed(p_hex, p_bytes, sizeof(p_bytes))) {
    Serial.println(F("[inspect] FAIL — p= is not valid 16-byte hex."));
    return;
  }

  String c_hex;
  const bool has_c = uri_get_query_param(uri, "c", c_hex);
  uint8_t c_bytes[8] = {0};
  const bool c_parse_ok = has_c && parse_hex_fixed(c_hex, c_bytes, sizeof(c_bytes));

  bool any_match = false;
  bool any_full_match = false;

  for (int candidate = 0; candidate < 2; candidate++) {
    const uint8_t *issuer_key = (candidate == 0) ? BOLTCARD_ISSUER_KEY_ZERO : BOLTCARD_ISSUER_KEY_DEV;
    const __FlashStringHelper *issuer_label =
        (candidate == 0) ? F("00000000000000000000000000000000")
                         : F("00000000000000000000000000000001");

    uint8_t keys_v1[5][16] = {{0}};
    derive_deterministic_boltcard_keys(nfc, issuer_key, uid, 1, keys_v1);

    uint8_t decrypted[16] = {0};
    uint32_t counter = 0;
    const bool k1_match = deterministic_decrypt_p(nfc, keys_v1[1], p_bytes, uid, decrypted, counter);

    Serial.print(F("[inspect] Issuer key "));
    Serial.print(issuer_label);
    Serial.print(F(" -> deterministic K1 read-only decrypt: "));
    Serial.println(k1_match ? F("MATCH") : F("NO MATCH"));

    if (!k1_match) {
      continue;
    }

    any_match = true;
    Serial.print(F("[inspect]   PICCData header: 0x"));
    print_hex_byte_prefixed(decrypted[0]);
    Serial.println();
    Serial.print(F("[inspect]   Decrypted UID: "));
    bolt.nfc->PrintHex(decrypted + 1, 7);
    Serial.print(F("[inspect]   Read counter: "));
    Serial.println(counter);
    Serial.println(F("[inspect]   This card was decrypted with a deterministic K1 derived from the UID using the Bolt Card spec."));

    if (!has_c) {
      Serial.println(F("[inspect]   c= missing — cannot read-only verify deterministic K2/K0/K3/K4."));
      Serial.println(F("[inspect]   This is a strong indicator only; it does not guarantee auth or wipe will succeed."));
      continue;
    }
    if (!c_parse_ok) {
      Serial.println(F("[inspect]   c= is malformed — cannot read-only verify deterministic K2/K0/K3/K4."));
      Serial.println(F("[inspect]   This is a strong indicator only; it does not guarantee auth or wipe will succeed."));
      continue;
    }

    int matched_version = -1;
    uint8_t matched_keys[5][16] = {{0}};
    for (int version_idx = 0; version_idx < 2; version_idx++) {
      const uint32_t version = BOLTCARD_VERSION_CANDIDATES[version_idx];
      uint8_t derived_keys[5][16] = {{0}};
      derive_deterministic_boltcard_keys(nfc, issuer_key, uid, version, derived_keys);
      const bool cmac_match = deterministic_verify_cmac(nfc, derived_keys[2], uid, counter, c_bytes);
      Serial.print(F("[inspect]   Deterministic K2/c= check (version "));
      Serial.print(version);
      Serial.print(F("): "));
      Serial.println(cmac_match ? F("MATCH") : F("NO MATCH"));
      if (cmac_match && matched_version < 0) {
        matched_version = (int)version;
        memcpy(matched_keys, derived_keys, sizeof(matched_keys));
      }
    }

    if (matched_version >= 0) {
      any_full_match = true;
      Serial.print(F("[inspect]   Full read-only deterministic match: issuer key "));
      Serial.print(issuer_label);
      Serial.print(F(", version "));
      Serial.println(matched_version);
      Serial.println(F("[inspect]   This strongly indicates the deterministic K0-K4 set for this issuer/version is correct."));
      Serial.println(F("[inspect]   It is still not a guarantee that authenticate or wipe will succeed on this tag."));
      Serial.println(F("[inspect]   Suggested keys command:"));
      Serial.print(F("[inspect]   keys "));
      Serial.print(convertIntToHex(matched_keys[0], 16));
      Serial.print(F(" "));
      Serial.print(convertIntToHex(matched_keys[1], 16));
      Serial.print(F(" "));
      Serial.print(convertIntToHex(matched_keys[2], 16));
      Serial.print(F(" "));
      Serial.print(convertIntToHex(matched_keys[3], 16));
      Serial.print(F(" "));
      Serial.println(convertIntToHex(matched_keys[4], 16));
    } else {
      Serial.println(F("[inspect]   K1 matched, but tested deterministic K2 versions did not validate c=."));
      Serial.println(F("[inspect]   This is still a strong indicator that we probably know the issuer key and can likely recover the card more easily."));
    }
  }

  if (!any_match) {
    Serial.println(F("[inspect] No tested deterministic issuer key produced valid PICCData for this UID."));
  } else if (!any_full_match) {
    Serial.println(F("[inspect] Deterministic read-only verification found a K1 match, but no full K2/c= match for the tested versions."));
  }
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
   // ── NDEF read using ISO-7816-4 ReadBinary ──
   //
   // Reads the NDEF file (E104) via ISO-7816 SELECT + READ BINARY.
   // This works both before and after burn (with SDM enabled).
   //
   // Why not DESFire ReadData (0xAD)?
   //   ReadData returns 91 9D (File Not Found) when the application
   //   is not selected. Even with ISO select, it fails on SDM-enabled
   //   files. Both the Bolt Android app and iOS implementations use
   //   ISO-7816 ReadBinary instead.
   //
   // Why not the library's ISOReadFile?
   //   It does GetFileSettings → SELECT → ReadBinary, but GetFileSettings
   //   returns garbage on SDM-enabled files, causing a negative filesize
   //   and failure.
   //
   // Ref: Android Ntag424.js isoReadBinary() (lines 716-745)
   //       iOS ntag424-macos readNDEFURL() (lines 91-179)
   //       CoreExtendedNFC Type4NDEF.readNDEF() (lines 55-114)
   //
   // Sequence: SELECT AID (D2760000850101) → SELECT FILE (E104) →
   //           READ BINARY (offset=0, len=2) → READ BINARY (offset=2, len=nlen)
   //
    else if (cmd == "ndef") {
     if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
     Serial.println(F("[ndef] Tap card now..."));
     serial_cmd_active = true;
     led_on();
     uint8_t uid[7] = {0};
     uint8_t uid_len = 0;
     unsigned long t0_ndef = millis();
     bool found_ndef = false;
     do {
       found_ndef = bolt.nfc->readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uid_len, 100);
       if (millis() - t0_ndef > 15000) break;
      } while (!found_ndef);
      if (found_ndef) {
        uint8_t ndef[256] = {0};
        int len = bolt.nfc->ntag424_ReadNDEFMessage(ndef, sizeof(ndef));
        if (len <= 0) {
          if (len == 0) {
            Serial.println(F("[ndef] No NDEF data (NLEN=0)"));
          }
          goto ndef_fail;
        }

        Serial.print(F("[ndef] OK (")); Serial.print(len); Serial.println(F(" bytes)"));
        Serial.print(F("[ndef] hex: "));
        bolt.nfc->PrintHex(ndef, len > 128 ? 128 : len);
        Serial.print(F("[ndef] ASCII: "));
        print_ndef_ascii(ndef, len);
        led_blink(3, 100);
        serial_cmd_active = false;
      } else {
ndef_fail:
       Serial.println(F("[ndef] FAILED — card not detected or read error"));
       led_blink(5, 100);
       serial_cmd_active = false;
     }
    }
    else if (cmd == "inspect") {
      if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
      Serial.println(F("[inspect] Tap card now..."));
      serial_cmd_active = true;
      led_on();

      uint8_t uid[7] = {0};
      uint8_t uid_len = 0;
      unsigned long t0_inspect = millis();
      bool found = false;
      do {
        found = bolt.nfc->readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uid_len, 100);
        if (millis() - t0_inspect > 15000) {
          Serial.println(F("[inspect] TIMEOUT"));
          serial_cmd_active = false;
          return;
        }
      } while (!found);

      Serial.println(F("[inspect] --- Card Presence ---"));
      Serial.print(F("[inspect] UID length: "));
      Serial.println(uid_len);
      Serial.print(F("[inspect] UID: "));
      bolt.nfc->PrintHex(uid, uid_len);
      Serial.print(F("[inspect] UID compact: "));
      Serial.println(convertIntToHex(uid, uid_len));
      delay(50);

      Serial.println(F("[inspect] --- Version / Type ---"));
      const uint8_t version_ok = bolt.nfc->ntag424_GetVersion();
      Serial.print(F("[inspect] GetVersion: "));
      Serial.println(version_ok ? F("OK") : F("FAIL"));
      if (version_ok) {
        Serial.print(F("[inspect] NTAG424 HWType: 0x"));
        print_hex_byte_prefixed(bolt.nfc->ntag424_VersionInfo.HWType);
        Serial.println();
        Serial.print(F("[inspect] NTAG424 SW version: "));
        Serial.print(bolt.nfc->ntag424_VersionInfo.SWMajorVersion, DEC);
        Serial.print(F("."));
        Serial.println(bolt.nfc->ntag424_VersionInfo.SWMinorVersion, DEC);
        Serial.print(F("[inspect] Prod week/year: CW "));
        Serial.print(bolt.nfc->ntag424_VersionInfo.CWProd, DEC);
        Serial.print(F(" / "));
        Serial.print(2000 + bcd_to_decimal(bolt.nfc->ntag424_VersionInfo.YearProd));
        Serial.println();
      }
      Serial.print(F("[inspect] isNTAG424: "));
      Serial.println(version_ok && bolt.nfc->ntag424_VersionInfo.HWType == 0x04 ? F("YES") : F("NO / UNKNOWN"));

      Serial.println(F("[inspect] --- Key Versions (read-only) ---"));
      bool all_zero = true;
      bool any_keyver_error = false;
      if (!bolt.nfc->ntag424_ISOSelectFileByDFN((uint8_t *)NTAG424_AID)) {
        Serial.println(F("[inspect] Failed to select NTAG424 application for key version reads"));
        any_keyver_error = true;
      } else {
        for (int k = 0; k < 5; k++) {
          uint8_t kv = 0xFF;
          const bool ok = bolt.nfc->ntag424_GetKeyVersion(k, &kv);
          Serial.print(F("[inspect] Key "));
          Serial.print(k);
          Serial.print(F(" version: "));
          if (!ok) {
            Serial.println(F("READ ERROR"));
            any_keyver_error = true;
            continue;
          }
          Serial.print(F("0x"));
          print_hex_byte_prefixed(kv);
          if (kv == 0x00) Serial.println(F(" (factory default)"));
          else Serial.println(F(" (changed)"));
          if (kv != 0x00) all_zero = false;
        }
      }

      Serial.println(F("[inspect] --- NDEF File Settings ---"));
      uint8_t fs[32] = {0};
      const uint8_t fs_len = bolt.nfc->ntag424_GetFileSettings(2, fs, NTAG424_COMM_MODE_PLAIN);
      if (fs_len >= 2) {
        Serial.print(F("[inspect] GetFileSettings len: "));
        Serial.println(fs_len);
        Serial.print(F("[inspect] Raw file settings: "));
        bolt.nfc->PrintHex(fs, fs_len);
        if (fs_len >= 7) {
          Serial.print(F("[inspect] FileType: 0x"));
          print_hex_byte_prefixed(fs[0]);
          Serial.println();
          Serial.print(F("[inspect] FileOption: 0x"));
          print_hex_byte_prefixed(fs[1]);
          Serial.println();
          Serial.print(F("[inspect] AccessRights: 0x"));
          print_hex_byte_prefixed(fs[2]);
          print_hex_byte_prefixed(fs[3]);
          Serial.println();
          Serial.print(F("[inspect] FileSize bytes: "));
          Serial.println(((uint32_t)fs[4] << 16) | ((uint32_t)fs[5] << 8) | fs[6]);
          Serial.print(F("[inspect] SDM enabled: "));
          Serial.println((fs[1] & 0x40) ? F("YES") : F("NO"));
          if ((fs[1] & 0x40) && fs_len >= 21) {
            Serial.print(F("[inspect] SDM options: 0x"));
            print_hex_byte_prefixed(fs[7]);
            Serial.println();
            Serial.print(F("[inspect] SDM access rights: 0x"));
            print_hex_byte_prefixed(fs[8]);
            print_hex_byte_prefixed(fs[9]);
            Serial.println();
            Serial.print(F("[inspect] UID offset: "));
            Serial.println(decode_u24_le(fs + 10));
            Serial.print(F("[inspect] SDM MAC input offset: "));
            Serial.println(decode_u24_le(fs + 13));
            Serial.print(F("[inspect] SDM MAC offset: "));
            Serial.println(decode_u24_le(fs + 16));
          }
        }
      } else {
        Serial.println(F("[inspect] GetFileSettings failed"));
      }

      Serial.println(F("[inspect] --- NDEF Read ---"));
      uint8_t ndef[256] = {0};
      const int ndef_len = bolt.nfc->ntag424_ReadNDEFMessage(ndef, sizeof(ndef));
      if (ndef_len < 0) {
        Serial.println(F("[inspect] NDEF read failed"));
      } else if (ndef_len == 0) {
        Serial.println(F("[inspect] No NDEF data (NLEN=0)"));
      } else {
        Serial.print(F("[inspect] NDEF bytes: "));
        Serial.println(ndef_len);
        Serial.print(F("[inspect] NDEF hex: "));
        bolt.nfc->PrintHex(ndef, ndef_len > 128 ? 128 : ndef_len);
        Serial.print(F("[inspect] NDEF ASCII: "));
        print_ndef_ascii(ndef, ndef_len);

        String uri;
        if (ndef_extract_uri(ndef, ndef_len, uri)) {
          Serial.print(F("[inspect] URI: "));
          Serial.println(uri);
        } else {
          Serial.println(F("[inspect] URI: not found / non-URI NDEF"));
        }
        print_boltcard_heuristics(uri);
        print_deterministic_boltcard_check(bolt.nfc, uid, uid_len, uri);
      }

      Serial.println(F("[inspect] --- Safe Summary ---"));
      if (!version_ok) {
        Serial.println(F("[inspect] Could not confirm NTAG424 via GetVersion."));
      } else if (any_keyver_error) {
        Serial.println(F("[inspect] Card responded, but some read-only NTAG424 reads failed."));
      } else if (all_zero) {
        Serial.println(F("[inspect] Card looks blank or unprovisioned from key versions alone."));
      } else {
        Serial.println(F("[inspect] Card has non-default key versions; likely provisioned or previously modified."));
      }
      Serial.println(F("[inspect] No authentication attempts were made."));
      Serial.println(F("[inspect] No writes or key changes were performed."));
      led_blink(3, 100);
      serial_cmd_active = false;
    }
  else if (cmd == "derivekeys") {
    if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
    Serial.println(F("[derivekeys] Tap card now..."));
    Serial.println(F("[derivekeys] Read-only flow: inspect NDEF, verify p=/c=, and only then load keys into config."));
    serial_cmd_active = true;
    led_on();

    uint8_t uid[7] = {0};
    uint8_t uid_len = 0;
    unsigned long t0_derive = millis();
    bool found = false;
    do {
      found = bolt.nfc->readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uid_len, 100);
      if (millis() - t0_derive > 15000) {
        Serial.println(F("[derivekeys] TIMEOUT"));
        serial_cmd_active = false;
        return;
      }
    } while (!found);

    Serial.print(F("[derivekeys] UID: "));
    bolt.nfc->PrintHex(uid, uid_len);

    uint8_t ndef[256] = {0};
    const int ndef_len = bolt.nfc->ntag424_ReadNDEFMessage(ndef, sizeof(ndef));
    if (ndef_len <= 0) {
      Serial.println(F("[derivekeys] FAIL — could not read NDEF."));
      Serial.println(F("[derivekeys] No keys were changed in config."));
      led_blink(5, 100);
      serial_cmd_active = false;
      return;
    }

    String uri;
    if (!ndef_extract_uri(ndef, ndef_len, uri)) {
      Serial.println(F("[derivekeys] FAIL — NDEF does not contain a URI record."));
      Serial.println(F("[derivekeys] No keys were changed in config."));
      led_blink(5, 100);
      serial_cmd_active = false;
      return;
    }

    DeterministicBoltcardMatch match;
    const bool full_match = deterministic_try_known_matches(bolt.nfc, uid, uid_len, uri, match);

    if (!match.saw_k1_match) {
      Serial.println(F("[derivekeys] FAIL — no known deterministic issuer key produced valid PICCData for this card."));
      Serial.println(F("[derivekeys] No keys were changed in config."));
      led_blink(5, 100);
      serial_cmd_active = false;
      return;
    }

    Serial.print(F("[derivekeys] Deterministic K1 matched issuer key "));
    print_hex_bytes_inline(match.issuer_key, sizeof(match.issuer_key));
    Serial.println();
    Serial.print(F("[derivekeys] Read counter from p=: "));
    Serial.println(match.counter);

    if (!full_match) {
      Serial.println(F("[derivekeys] PARTIAL — K1 matched, but no full K2/c= match was found for tested versions."));
      Serial.println(F("[derivekeys] Config keys were left unchanged on purpose."));
      Serial.println(F("[derivekeys] You likely know the issuer key, but auth/wipe confidence is not high enough to auto-load keys."));
      led_blink(5, 100);
      serial_cmd_active = false;
      return;
    }

    store_bolt_config_keys_from_bytes(mBoltConfig, match.keys);
    Serial.print(F("[derivekeys] FULL MATCH — issuer key "));
    print_hex_bytes_inline(match.issuer_key, sizeof(match.issuer_key));
    Serial.print(F(", version "));
    Serial.println(match.version);
    Serial.println(F("[derivekeys] Loaded deterministic K0-K4 into active config."));
    Serial.println(F("[derivekeys] K1 and K2 were verified read-only from the card's current NDEF data."));
    Serial.println(F("[derivekeys] K0, K3, and K4 cannot be directly verified read-only, but this is the strongest safe pre-auth signal."));
    Serial.print(F("[derivekeys] k0: "));
    Serial.println(mBoltConfig.k0);
    Serial.print(F("[derivekeys] k1: "));
    Serial.println(mBoltConfig.k1);
    Serial.print(F("[derivekeys] k2: "));
    Serial.println(mBoltConfig.k2);
    Serial.print(F("[derivekeys] k3: "));
    Serial.println(mBoltConfig.k3);
    Serial.print(F("[derivekeys] k4: "));
    Serial.println(mBoltConfig.k4);
    Serial.println(F("[derivekeys] Next steps: 'auth' gives a single K0 confirmation attempt; 'wipe' performs the actual reset."));
    led_blink(3, 100);
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
    bolt.loadKeysForBurn(mBoltConfig);
    uint8_t result;
    unsigned long t0 = millis();
    do {
      while (Serial.available()) Serial.read();
      result = bolt.burn(String(mBoltConfig.url));
      if (millis() - t0 > 30000) {
        Serial.println(F("[burn] TIMEOUT — no card detected in 30s"));
        serial_cmd_active = false;
        return;
      }
    } while (result == JOBSTATUS_WAITING);
    if (result == JOBSTATUS_GUARD_REJECT) {
      Serial.println(F("[burn] ABORTED - guard rejected (card not in expected state)"));
      led_blink(5, 100);
      serial_cmd_active = false;
      return;
    }
    Serial.print(F("[burn] ")); Serial.println(bolt.get_job_status());
    Serial.println(result == JOBSTATUS_DONE ? F("[burn] SUCCESS") : F("[burn] FAILED"));
      if (result == JOBSTATUS_DONE) {
        // Post-burn NDEF verification: confirm NLEN is valid and peek at first bytes.
        // After burn, auth session changes card state — must re-select AID + file.
        // Ref: Android bolt-nfc-android-app isoReadBinary always does
        //      SELECT AID → SELECT FILE before ReadBinary.
        //
        // Note: PN532 pn532_packetbuffer is only 64 bytes, so max card data per
        // read is ~54 bytes (64 - 8 header - 2 SW). Full NDEF readback needs
        // pagination — use the 'ndef' command for that. Here we just sanity-check.
        bool v_sel1 = bolt.selectNdefFileOnly();
        bool v_sel2 = v_sel1;
        Serial.print(F("[burn] VERIFY — SELECT AID: "));
        Serial.println(v_sel1 ? F("OK") : F("FAIL"));
        Serial.print(F("[burn] VERIFY — SELECT E104: "));
        Serial.println(v_sel2 ? F("OK") : F("FAIL"));
        if (v_sel1 && v_sel2) {
          // Read NLEN (2 bytes) + 1 extra = 3 bytes at offset 0
          uint8_t nlen_buf[8] = {0};
          uint8_t nlen_rl = bolt.nfc->ntag424_ISOReadBinary(0, 3, nlen_buf, sizeof(nlen_buf));
          if (nlen_rl >= 3 && nlen_buf[nlen_rl-2] == 0x90 && nlen_buf[nlen_rl-1] == 0x00) {
            int nlen = (nlen_buf[0] << 8) | nlen_buf[1];
            Serial.print(F("[burn] VERIFY — NLEN=")); Serial.println(nlen);
            if (nlen > 0 && nlen <= 252) {
              // Read first chunk (max 48 bytes to stay within 64-byte SPI buffer)
              uint8_t peek_len = (nlen + 3 > 48) ? 48 : (nlen + 3);
              uint8_t body_buf[52] = {0};
              uint8_t body_rl = bolt.nfc->ntag424_ISOReadBinary(2, peek_len, body_buf, sizeof(body_buf));
              if (body_rl >= 4 && body_buf[body_rl-2] == 0x90 && body_buf[body_rl-1] == 0x00) {
                int dlen = body_rl - 2;
                Serial.print(F("[burn] VERIFY — NDEF peek OK ("));
                Serial.print(dlen); Serial.print(F(" of ")); Serial.print(nlen);
                Serial.println(F(" bytes)"));
                Serial.print(F("[burn] VERIFY — ASCII: "));
                for (int i = 0; i < dlen; i++) {
                  Serial.write(body_buf[i] >= 0x20 && body_buf[i] < 0x7F ? body_buf[i] : '.');
                }
                Serial.println();
              } else {
                Serial.print(F("[burn] VERIFY — NDEF body read failed SW="));
                if (body_rl >= 2) {
                  Serial.print(body_buf[body_rl-2], HEX); Serial.print(F(" "));
                  Serial.print(body_buf[body_rl-1], HEX);
                }
                Serial.println();
              }
            } else {
              Serial.println(F("[burn] VERIFY — NLEN invalid or zero"));
            }
          } else {
            Serial.print(F("[burn] VERIFY — NLEN read failed SW="));
            if (nlen_rl >= 2) {
              Serial.print(nlen_buf[nlen_rl-2], HEX); Serial.print(F(" "));
              Serial.print(nlen_buf[nlen_rl-1], HEX);
            }
            Serial.println();
          }
        }
      }
    led_blink(result == JOBSTATUS_DONE ? 3 : 5, 100);
    serial_cmd_active = false;
  }
  else if (cmd == "wipe") {
    if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
    if (strlen(mBoltConfig.k0) == 0) { Serial.println(F("[error] No keys. Use: keys <k0> <k1> <k2> <k3> <k4>")); return; }
    Serial.println(F("[wipe] Tap card now..."));
    serial_cmd_active = true;
    led_on();
    bolt.loadKeysForWipe(mBoltConfig);
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
    if (result == JOBSTATUS_GUARD_REJECT) {
      Serial.println(F("[wipe] ABORTED - guard rejected (card not in expected state)"));
      led_blink(5, 100);
      serial_cmd_active = false;
      return;
    }
    Serial.print(F("[wipe] ")); Serial.println(bolt.get_job_status());
    Serial.println(result == JOBSTATUS_DONE ? F("[wipe] SUCCESS") : F("[wipe] FAILED"));
    led_blink(result == JOBSTATUS_DONE ? 3 : 5, 100);
    serial_cmd_active = false;
  }
  else if (cmd == "keyver") {
    if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
    Serial.println(F("[keyver] Tap card now..."));
    serial_cmd_active = true;
    led_on();
    unsigned long t0 = millis();
    bool found = false;
    do {
      uint8_t uid[7] = {0};
      uint8_t uidLen;
      found = bolt.nfc->readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLen, 100);
      if (found) {
        Serial.print(F("[keyver] UID: "));
        bolt.nfc->PrintHex(uid, uidLen);
      }
      if (millis() - t0 > 15000) { Serial.println(F("[keyver] TIMEOUT")); serial_cmd_active = false; return; }
    } while (!found);
    delay(50);
    bool all_zero = true;
    for (int k = 0; k < 5; k++) {
      uint8_t kv = ntag424_getKeyVersion(bolt.nfc, k);
      Serial.print(F("[keyver] Key "));
      Serial.print(k);
      Serial.print(F(" version: 0x"));
      if (kv < 0x10) Serial.print(F("0"));
      Serial.print(kv, HEX);
      if (kv == 0x00) {
        Serial.println(F(" (factory default)"));
      } else if (kv == 0xFF) {
        Serial.print(F(" (ERROR: "));
        Serial.print(ntag424_error_name(0x91, 0xAE));
        Serial.println(F(")"));
      } else {
        Serial.println(F(" (changed)"));
      }
      if (kv != 0x00) all_zero = false;
    }
    if (all_zero) {
      Serial.println(F("[keyver] Card is BLANK — factory default keys"));
    } else {
      Serial.println(F("[keyver] Card is PROVISIONED — keys have been set"));
    }
    led_blink(3, 100);
    serial_cmd_active = false;
  }
  else if (cmd == "check") {
    if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
    Serial.println(F("[check] Tap card now..."));
    serial_cmd_active = true;
    led_on();
    bolt.setDefautKeysCur();
    Serial.print(F("[check] Using zero key: "));
    for (int i = 0; i < 16; i++) { if (bolt.key_cur[0][i] < 0x10) Serial.print("0"); Serial.print(bolt.key_cur[0][i], HEX); }
    Serial.println();
    unsigned long t0 = millis();
    bool found = false;
    do {
      uint8_t uid[7] = {0};
      uint8_t uidLen;
      found = bolt.nfc->readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLen, 100);
      if (found) {
        Serial.print(F("[check] UID: "));
        bolt.nfc->PrintHex(uid, uidLen);
      }
      if (millis() - t0 > 15000) { Serial.println(F("[check] TIMEOUT")); serial_cmd_active = false; return; }
    } while (!found);
    delay(50);
    uint8_t result = bolt.nfc->ntag424_Authenticate(bolt.key_cur[0], 0, 0x71);
    Serial.println(result == 1 ? F("[check] SUCCESS — card has factory zero keys") : F("[check] FAILED — card does NOT have factory keys"));
    led_blink(result == 1 ? 3 : 5, 100);
    serial_cmd_active = false;
  }
  else if (cmd == "dummyburn") {
    if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
    Serial.println(F("[dummyburn] Tap card now..."));
    serial_cmd_active = true;
    led_on();
    bolt.setDefautKeysCur();
    bolt.setDefautKeysNew();
    String lnurl = "https://dummy.test";
    uint8_t result;
    unsigned long t0 = millis();
    do {
      while (Serial.available()) Serial.read();
      result = bolt.burn(lnurl);
      if (millis() - t0 > 30000) {
        Serial.println(F("[dummyburn] TIMEOUT — no card detected in 30s"));
        serial_cmd_active = false;
        return;
      }
    } while (result == JOBSTATUS_WAITING);
    Serial.print(F("[dummyburn] ")); Serial.println(bolt.get_job_status());
    Serial.println(result == JOBSTATUS_DONE ? F("[dummyburn] SUCCESS") : F("[dummyburn] FAILED"));
    if (result == JOBSTATUS_DONE) {
      Serial.println(F("[dummyburn] Card has dummy data — use 'keys 000... 000... 000... 000... 000...' then 'wipe' to restore"));
    }
    led_blink(result == JOBSTATUS_DONE ? 3 : 5, 100);
    serial_cmd_active = false;
  }
  else if (cmd == "reset") {
    if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
    Serial.println(F("[reset] Tap card now..."));
    Serial.println(F("[reset] Factory-key NDEF+SDM reset (keys unchanged)."));
    serial_cmd_active = true;
    led_on();
    uint8_t result;
    unsigned long t0 = millis();
    do {
      while (Serial.available()) Serial.read();
      result = bolt.resetNdefOnly();
      if (millis() - t0 > 30000) {
        Serial.println(F("[reset] TIMEOUT — no card detected in 30s"));
        serial_cmd_active = false;
        return;
      }
    } while (result == JOBSTATUS_WAITING);
    if (result == JOBSTATUS_GUARD_REJECT) {
      Serial.println(F("[reset] ABORTED — card has non-factory keys. Use 'wipe' with explicit keys."));
      led_blink(5, 100);
      serial_cmd_active = false;
      return;
    }
    Serial.print(F("[reset] ")); Serial.println(bolt.get_job_status());
    Serial.println(result == JOBSTATUS_DONE ? F("[reset] SUCCESS — NDEF and SDM reset, keys unchanged") : F("[reset] FAILED"));
    led_blink(result == JOBSTATUS_DONE ? 3 : 5, 100);
    serial_cmd_active = false;
  }
  else if (cmd == "diagnose") {
    if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
    Serial.println(F("[diagnose] Tap card now..."));
    serial_cmd_active = true;
    led_on();

    uint8_t uid_d[7] = {0};
    uint8_t uidLen_d;
    unsigned long t0_d = millis();
    bool found_d = false;
    do {
      found_d = bolt.nfc->readPassiveTargetID(PN532_MIFARE_ISO14443A, uid_d, &uidLen_d, 100);
      if (found_d) {
        Serial.print(F("[diagnose] UID: "));
        bolt.nfc->PrintHex(uid_d, uidLen_d);
      }
      if (millis() - t0_d > 15000) {
        Serial.println(F("[diagnose] TIMEOUT"));
        serial_cmd_active = false;
        return;
      }
    } while (!found_d);

    delay(50);

    // Read all 5 key versions (PLAIN mode — no auth needed)
    Serial.println(F("[diagnose] --- Key Versions ---"));
    uint8_t kv[5];
    bool all_zero = true;
    bool any_error = false;
    for (int k = 0; k < 5; k++) {
      kv[k] = ntag424_getKeyVersion(bolt.nfc, k);
      Serial.print(F("[diagnose]   Key "));
      Serial.print(k);
      Serial.print(F(" version: 0x"));
      if (kv[k] < 0x10) Serial.print(F("0"));
      Serial.print(kv[k], HEX);
      if (kv[k] == 0x00) Serial.println(F(" (default)"));
      else if (kv[k] == 0xFF) { Serial.println(F(" (READ ERROR)")); any_error = true; }
      else Serial.println(F(" (changed)"));
      if (kv[k] != 0x00) all_zero = false;
    }

    // Test zero-key authentication on key 0 (master)
    bolt.selectNtagApplicationFiles();
    uint8_t zero_key[16] = {0};
    uint8_t auth_d = bolt.nfc->ntag424_Authenticate(zero_key, 0, 0x71);
    Serial.print(F("[diagnose] Zero-key auth (key 0): "));
    Serial.println(auth_d == 1 ? "OK" : "FAILED");

    // Classify card state
    Serial.println(F("[diagnose] --- Card State ---"));
    if (any_error) {
      Serial.println(F("[diagnose] COMM ERROR — card may not be NTAG424 or reader issue"));
      Serial.println(F("[diagnose] Try: 'ver' to confirm card type"));
    } else if (all_zero && auth_d == 1) {
      Serial.println(F("[diagnose] State: BLANK"));
      Serial.println(F("[diagnose] All keys factory default, zero-key auth OK."));
      Serial.println(F("[diagnose] Ready for burn or dummyburn."));
    } else if (!all_zero && auth_d == 1) {
      Serial.println(F("[diagnose] State: HALF-WIPED"));
      Serial.println(F("[diagnose] Key 0 (master) is zero but some non-master keys remain."));
      Serial.println(F("[diagnose] Recovery: 'recoverkey <slot> <old-key-hex>' per stuck key"));
      Serial.println(F("[diagnose]   or 'keys ...' + 'wipe' if you know all current key values"));
    } else if (!all_zero && auth_d != 1) {
      Serial.println(F("[diagnose] State: PROVISIONED"));
      Serial.println(F("[diagnose] Key 0 (master) is non-zero. Card is locked."));
      Serial.println(F("[diagnose] To wipe: set known keys with 'keys ...' then 'wipe'"));
      Serial.println(F("[diagnose] If key 0 value is unknown, card is NOT recoverable."));
    } else {
      Serial.println(F("[diagnose] State: INCONSISTENT"));
      Serial.println(F("[diagnose] Key versions all 0x00 but zero-key auth FAILED."));
      Serial.println(F("[diagnose] Possible: auth counter lockout, card corruption, or hw issue."));
      Serial.println(F("[diagnose] Try: 'ver' to confirm card type, wait 10s and retry."));
    }

    led_blink(3, 100);
    serial_cmd_active = false;
  }
  else if (cmd.startsWith("recoverkey ")) {
    // Usage: recoverkey <slot 0-4> <32-hex-old-key>
    // Authenticates with zero key on key 0, then attempts ChangeKey
    // to restore the target key slot to zero with version 0x00.
    if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }

    String args = cmd.substring(11);
    args.trim();
    int spaceIdx = args.indexOf(' ');
    if (spaceIdx < 0) {
      Serial.println(F("[recoverkey] Usage: recoverkey <slot 0-4> <32-hex-old-key>"));
      return;
    }
    int slot = args.substring(0, spaceIdx).toInt();
    String old_key_hex = args.substring(spaceIdx + 1);
    old_key_hex.trim();

    if (slot < 0 || slot > 4) {
      Serial.println(F("[recoverkey] Slot must be 0-4"));
      return;
    }
    if (old_key_hex.length() != 32) {
      Serial.println(F("[recoverkey] Key must be 32 hex chars (16 bytes)"));
      return;
    }

    uint8_t zero_key[16] = {0};
    uint8_t old_key[16] = {0};
    bolt.setKey(old_key, old_key_hex);

    Serial.print(F("[recoverkey] Target: key "));
    Serial.print(slot);
    Serial.println(F(" -> zero, ver=0x00"));
    Serial.print(F("[recoverkey] Candidate old key: "));
    Serial.println(old_key_hex);
    serial_cmd_active = true;
    led_on();

    uint8_t uid_rk[7] = {0};
    uint8_t uidLen_rk;
    unsigned long t0_rk = millis();
    bool found_rk = false;
    do {
      found_rk = bolt.nfc->readPassiveTargetID(PN532_MIFARE_ISO14443A, uid_rk, &uidLen_rk, 100);
      if (found_rk) {
        Serial.print(F("[recoverkey] UID: "));
        bolt.nfc->PrintHex(uid_rk, uidLen_rk);
      }
      if (millis() - t0_rk > 15000) {
        Serial.println(F("[recoverkey] TIMEOUT"));
        serial_cmd_active = false;
        return;
      }
    } while (!found_rk);

    delay(50);
    bolt.selectNtagApplicationFiles();
    uint8_t kv_before = ntag424_getKeyVersion(bolt.nfc, slot);
    Serial.print(F("[recoverkey] Key "));
    Serial.print(slot);
    Serial.print(F(" version BEFORE: 0x"));
    if (kv_before < 0x10) Serial.print(F("0"));
    Serial.println(kv_before, HEX);

    // Auth with key 0 (zeros) — master key required for ChangeKey
    uint8_t auth_rk = bolt.nfc->ntag424_Authenticate(zero_key, 0, 0x71);
    Serial.print(F("[recoverkey] Auth key 0 (zeros): "));
    Serial.println(auth_rk == 1 ? "OK" : "FAILED");
    if (auth_rk != 1) {
      Serial.println(F("[recoverkey] ABORT — key 0 auth failed (master key is non-zero)"));
      led_blink(5, 100);
      serial_cmd_active = false;
      return;
    }

    bool ok = bolt.nfc->ntag424_ChangeKey(old_key, zero_key, slot, 0x00);
    Serial.print(F("[recoverkey] ChangeKey result: "));
    Serial.println(ok ? "OK" : "FAILED");

    // Re-select and verify
    bolt.nfc->ntag424_ISOSelectFileByDFN((uint8_t *)NTAG424_AID);
    uint8_t kv_after = ntag424_getKeyVersion(bolt.nfc, slot);
    Serial.print(F("[recoverkey] Key "));
    Serial.print(slot);
    Serial.print(F(" version AFTER: 0x"));
    if (kv_after < 0x10) Serial.print(F("0"));
    Serial.println(kv_after, HEX);

    const bool pass = ok && (kv_after == 0x00);
    Serial.println(pass ?
                       F("[recoverkey] PASS — key restored to factory zero") :
                       F("[recoverkey] FAIL — candidate old key was incorrect or card state differs"));
    led_blink(pass ? 3 : 5, 100);
    serial_cmd_active = false;
  }
  else if (cmd == "testck") {
    // A/B test: prove ChangeKey works on known-good key slots.
    // Test card has keys 0-3 = zero, key 4 = unknown.
    // Round-trip: change key 1 from zero→test value→zero, verify versions.
    // If this passes but key 4 fails → issue is card-specific, not our code.
    //
    // Ref: NXP AN12196 §10.4 (ChangeKey), johnnyb/ntag424-java ChangeKey.java
    if (!bolty_hw_ready) { Serial.println(F("[error] NFC not ready")); return; }
    Serial.println(F("[testck] ChangeKey A/B test — round-trip on key 1 (known zero)"));
    serial_cmd_active = true;
    led_on();

    // Detect card
    uint8_t uid_ck[7] = {0};
    uint8_t uidLen_ck;
    unsigned long t0_ck = millis();
    bool found_ck = false;
    do {
      found_ck = bolt.nfc->readPassiveTargetID(PN532_MIFARE_ISO14443A, uid_ck, &uidLen_ck, 100);
      if (found_ck) {
        Serial.print(F("[testck] UID: "));
        bolt.nfc->PrintHex(uid_ck, uidLen_ck);
      }
      if (millis() - t0_ck > 15000) { Serial.println(F("[testck] TIMEOUT")); serial_cmd_active = false; return; }
    } while (!found_ck);
    delay(50);

    uint8_t zero_key[16] = {0};
    // Distinctive test value — not a real key, just for verification
    uint8_t test_key[16] = {0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44,
                            0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xEE, 0xFF};

    // Read key 1 version BEFORE.
    // 0x00 = blank/default state.
    // 0x01 = our previous aborted test changed key 1 to test_key and needs
    // restore before we can do a clean round-trip again.
    uint8_t kv_before = ntag424_getKeyVersion(bolt.nfc, 1);
    Serial.print(F("[testck] Key 1 version BEFORE: 0x"));
    if (kv_before < 0x10) Serial.print(F("0"));
    Serial.println(kv_before, HEX);

    // Auth with key 0 (zeros) — key 0 is master, needed for ChangeKey
    bolt.selectNtagApplicationFiles();
    uint8_t auth1 = bolt.nfc->ntag424_Authenticate(zero_key, 0, 0x71);
    Serial.print(F("[testck] Auth key 0 (zeros): "));
    Serial.println(auth1 == 1 ? "OK" : "FAILED");
    if (auth1 != 1) {
      Serial.println(F("[testck] ABORT — auth failed"));
      led_blink(5, 100);
      serial_cmd_active = false;
      return;
    }

    if (kv_before == 0x01) {
      Serial.println(F("[testck] Recovery mode — restoring key 1 from test value to zero"));
      bool recovered = bolt.nfc->ntag424_ChangeKey(test_key, zero_key, 1, 0x00);
      Serial.print(F("[testck]   Result: "));
      Serial.println(recovered ? "OK" : "FAILED");

      bolt.nfc->ntag424_ISOSelectFileByDFN((uint8_t *)NTAG424_AID);
      uint8_t kv_recovered = ntag424_getKeyVersion(bolt.nfc, 1);
      Serial.print(F("[testck]   Key 1 version: 0x"));
      if (kv_recovered < 0x10) Serial.print(F("0"));
      Serial.println(kv_recovered, HEX);

      const bool recovery_pass = recovered && (kv_recovered == 0x00);
      Serial.println(recovery_pass ?
                         F("[testck] RECOVERY PASS — key 1 restored to factory state") :
                         F("[testck] RECOVERY FAIL — key 1 not restored"));
      led_blink(recovery_pass ? 3 : 5, 100);
      serial_cmd_active = false;
      return;
    }

    if (kv_before != 0x00) {
      Serial.println(F("[testck] WARNING — key 1 is in an unexpected state, aborting"));
      led_blink(5, 100);
      serial_cmd_active = false;
      return;
    }

    // Step 1: ChangeKey key 1 from zero → test value, version 0x01
    Serial.println(F("[testck] Step 1: ChangeKey(1, zero→test, ver=0x01)"));
    bool ck1 = bolt.nfc->ntag424_ChangeKey(zero_key, test_key, 1, 0x01);
    Serial.print(F("[testck]   Result: "));
    Serial.println(ck1 ? "OK" : "FAILED");

    // Re-select and read version (PLAIN, no auth needed for GetKeyVersion)
    bolt.nfc->ntag424_ISOSelectFileByDFN((uint8_t *)NTAG424_AID);
    uint8_t kv_mid = ntag424_getKeyVersion(bolt.nfc, 1);
    Serial.print(F("[testck]   Key 1 version: 0x"));
    if (kv_mid < 0x10) Serial.print(F("0"));
    Serial.println(kv_mid, HEX);

    if (!ck1 && kv_mid == 0x01) {
      Serial.println(F("[testck] NOTICE — card changed but library returned false (stale build/parsing bug)"));
    }

    bool step1_pass = (kv_mid == 0x01);
    Serial.print(F("[testck]   Step 1: "));
    Serial.println(step1_pass ? "PASS" : "FAIL");

    if (!step1_pass) {
      Serial.println(F("[testck] ABORT — step 1 failed, not attempting restore"));
      led_blink(5, 100);
      serial_cmd_active = false;
      return;
    }

    // Step 2: Re-auth (key 0 still zero), change key 1 back
    bolt.selectNtagApplicationFiles();
    uint8_t auth2 = bolt.nfc->ntag424_Authenticate(zero_key, 0, 0x71);
    Serial.print(F("[testck] Re-auth key 0: "));
    Serial.println(auth2 == 1 ? "OK" : "FAILED");
    if (auth2 != 1) {
      Serial.println(F("[testck] ABORT — re-auth failed (card may be in bad state)"));
      led_blink(5, 100);
      serial_cmd_active = false;
      return;
    }

    Serial.println(F("[testck] Step 2: ChangeKey(1, test→zero, ver=0x00)"));
    bool ck2 = bolt.nfc->ntag424_ChangeKey(test_key, zero_key, 1, 0x00);
    Serial.print(F("[testck]   Result: "));
    Serial.println(ck2 ? "OK" : "FAILED");

    // Read final version
    bolt.nfc->ntag424_ISOSelectFileByDFN((uint8_t *)NTAG424_AID);
    uint8_t kv_final = ntag424_getKeyVersion(bolt.nfc, 1);
    Serial.print(F("[testck]   Key 1 version: 0x"));
    if (kv_final < 0x10) Serial.print(F("0"));
    Serial.println(kv_final, HEX);

    if (!ck2 && kv_final == 0x00) {
      Serial.println(F("[testck] NOTICE — card restored but library returned false (stale build/parsing bug)"));
    }

    bool step2_pass = (kv_final == 0x00);
    Serial.print(F("[testck]   Step 2: "));
    Serial.println(step2_pass ? "PASS" : "FAIL");

    // Summary
    Serial.println(F("---"));
    bool all_pass = step1_pass && step2_pass;
    if (all_pass) {
      Serial.println(F("[testck] ALL PASS — ChangeKey implementation is CORRECT"));
      Serial.println(F("[testck] Conclusion: key 4 corruption is CARD-SPECIFIC"));
      Serial.println(F("[testck] (key 4 has unknown value from prior operation)"));
    } else {
      Serial.println(F("[testck] SOME FAILED — ChangeKey has issues"));
    }

    led_blink(all_pass ? 3 : 5, 100);
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
