#pragma once
#if BOLTY_OTA_ENABLED

#include <WiFi.h>
#include <HTTPClient.h>
#include <Update.h>
#include <ArduinoJson.h>
#include <esp_wifi.h>
#include "build_metadata.h"

#ifndef OTA_SSID
#error "OTA_SSID must be defined. Set it in platformio.ini build_flags."
#endif
#ifndef OTA_PASSWORD
#error "OTA_PASSWORD must be defined. Set it in platformio.ini build_flags."
#endif
#ifndef OTA_HOST
#error "OTA_HOST must be defined. Set it in platformio.ini build_flags."
#endif
#ifndef OTA_PORT
#define OTA_PORT 8765
#endif

#define BOLTY_OTA_STRINGIFY_(x) #x
#define BOLTY_OTA_STRINGIFY(x)  BOLTY_OTA_STRINGIFY_(x)

#define OTA_MANIFEST_URL \
  "http://" OTA_HOST ":" BOLTY_OTA_STRINGIFY(OTA_PORT) "/manifest.json"

static void ota_check_and_update() {
  Serial.println(F("[ota] Checking for firmware update..."));
  Serial.print(F("[ota] Manifest: ")); Serial.println(F(OTA_MANIFEST_URL));
  Serial.print(F("[ota] Current version: ")); Serial.println((unsigned long)FW_VERSION_CODE);

  WiFi.mode(WIFI_STA);
  esp_wifi_set_country_code("EU", true);
  WiFi.setTxPower(WIFI_POWER_19_5dBm);

  wifi_scan_config_t scan_cfg;
  memset(&scan_cfg, 0, sizeof(scan_cfg));
  scan_cfg.channel_bitmap.ghz_2_channels = 0x3FFE;  // channels 1-13
  esp_wifi_scan_start(&scan_cfg, true);

  uint16_t ap_count = 0;
  esp_wifi_scan_get_ap_num(&ap_count);

  bool ssid_found = false;
  if (ap_count > 0) {
    wifi_ap_record_t *ap_list = (wifi_ap_record_t *)malloc(ap_count * sizeof(wifi_ap_record_t));
    if (ap_list && esp_wifi_scan_get_ap_records(&ap_count, ap_list) == ESP_OK) {
      for (int i = 0; i < (int)ap_count; i++) {
        if (strcmp((char *)ap_list[i].ssid, OTA_SSID) == 0) {
          Serial.print(F("[ota] Found AP, RSSI: ")); Serial.println(ap_list[i].rssi);
          ssid_found = true;
        }
      }
    }
    free(ap_list);
  }

  if (!ssid_found) {
    Serial.println(F("[ota] AP not in range - skipping OTA, continuing normal boot"));
    WiFi.mode(WIFI_OFF);
    return;
  }

  WiFi.begin(OTA_SSID, OTA_PASSWORD);

  Serial.print(F("[ota] Connecting to WiFi"));
  uint8_t tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 40) {
    delay(500);
    Serial.print(F("."));
    tries++;
  }
  Serial.println();

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println(F("[ota] WiFi connect failed - skipping OTA, continuing normal boot"));
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    return;
  }

  Serial.print(F("[ota] Connected, IP: ")); Serial.println(WiFi.localIP());

  HTTPClient http;
  WiFiClient client;
  http.begin(client, OTA_MANIFEST_URL);
  http.useHTTP10(true);
  int code = http.GET();

  if (code != 200) {
    Serial.print(F("[ota] Manifest fetch failed, HTTP ")); Serial.println(code);
    http.end();
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    return;
  }

  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, http.getStream());
  http.end();

  if (err) {
    Serial.print(F("[ota] Manifest JSON parse error: ")); Serial.println(err.c_str());
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    return;
  }

  unsigned long remote_version = doc["version_code"].as<unsigned long>();
  String        fw_url         = doc["url"].as<String>();
  int           fw_size        = doc["size"].as<int>();

  Serial.print(F("[ota] Remote version: ")); Serial.println(remote_version);

  if (remote_version == 0 || fw_url.length() == 0) {
    Serial.println(F("[ota] Manifest missing version_code or url - skipping"));
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    return;
  }

  if (remote_version <= (unsigned long)FW_VERSION_CODE) {
    Serial.println(F("[ota] Firmware is up to date - no update needed"));
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    return;
  }

  Serial.print(F("[ota] Update available! Downloading ")); Serial.println(fw_url);

  HTTPClient http2;
  WiFiClient client2;
  http2.begin(client2, fw_url);
  http2.useHTTP10(true);
  int fw_code = http2.GET();

  if (fw_code != 200) {
    Serial.print(F("[ota] Firmware fetch failed, HTTP ")); Serial.println(fw_code);
    http2.end();
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    return;
  }

  int content_len = http2.getSize();
  if (content_len <= 0 && fw_size > 0) {
    content_len = fw_size;
  }

  Serial.print(F("[ota] Firmware size: ")); Serial.println(content_len);

  if (!Update.begin(content_len > 0 ? content_len : UPDATE_SIZE_UNKNOWN, U_FLASH)) {
    Serial.print(F("[ota] Update.begin failed: ")); Serial.println(Update.errorString());
    http2.end();
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    return;
  }

  Update.onProgress([](size_t done, size_t total) {
    if (total > 0) {
      Serial.print(F("[ota] Progress: "));
      Serial.print((done * 100) / total);
      Serial.println(F("%"));
    }
  });

  size_t written = Update.writeStream(*http2.getStreamPtr());
  http2.end();

  if (written != (size_t)(content_len > 0 ? content_len : written)) {
    Serial.print(F("[ota] Write incomplete: "));
    Serial.print(written);
    Serial.print(F(" / "));
    Serial.println(content_len);
  }

  if (!Update.end()) {
    Serial.print(F("[ota] Update.end failed: ")); Serial.println(Update.errorString());
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    return;
  }

  if (!Update.isFinished()) {
    Serial.println(F("[ota] Update not finished unexpectedly"));
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    return;
  }

  Serial.println(F("[ota] Update complete! Rebooting..."));
  WiFi.disconnect(true);
  WiFi.mode(WIFI_OFF);
  delay(200);
  ESP.restart();
}

#endif
