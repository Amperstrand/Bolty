#pragma once
#if BOLTY_OTA_ENABLED

#include <ArduinoJson.h>
#include <HTTPClient.h>
#include <Update.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <esp_wifi.h>
#include <mbedtls/base64.h>
#include <mbedtls/pk.h>
#include <mbedtls/sha256.h>
#include <time.h>

#include "build_metadata.h"
#include "ota_ca_cert.h"
#include "ota_signing_key.h"

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
#ifndef OTA_AUTH_TOKEN
#define OTA_AUTH_TOKEN ""
#endif
#ifndef OTA_NTP_SERVER
#define OTA_NTP_SERVER "pool.ntp.org"
#endif

#define BOLTY_OTA_STRINGIFY_(x) #x
#define BOLTY_OTA_STRINGIFY(x)  BOLTY_OTA_STRINGIFY_(x)

#define OTA_MANIFEST_URL \
  "https://" OTA_HOST ":" BOLTY_OTA_STRINGIFY(OTA_PORT) "/manifest.json"

static bool ota_verify_manifest_signature(unsigned long version_code, const String &sha256_hex, const String &signature_b64) {
  if (sha256_hex.length() != 64 || signature_b64.length() == 0) {
    Serial.println(F("[ota] Manifest missing sha256 or signature"));
    return false;
  }

  const String payload = String(version_code) + sha256_hex;
  unsigned char payload_hash[32];
  mbedtls_sha256(reinterpret_cast<const unsigned char *>(payload.c_str()), payload.length(), payload_hash, 0);

  const size_t signature_b64_len = signature_b64.length();
  size_t decoded_len = 0;
  unsigned char *decoded_sig = static_cast<unsigned char *>(malloc(signature_b64_len));
  if (!decoded_sig) {
    Serial.println(F("[ota] Failed to allocate signature buffer"));
    return false;
  }

  int rc = mbedtls_base64_decode(decoded_sig, signature_b64_len, &decoded_len,
                             reinterpret_cast<const unsigned char *>(signature_b64.c_str()),
                             signature_b64_len);
  if (rc != 0 || decoded_len == 0) {
    Serial.print(F("[ota] Signature base64 decode failed: "));
    Serial.println(rc);
    free(decoded_sig);
    return false;
  }

  mbedtls_pk_context pk;
  mbedtls_pk_init(&pk);

  rc = mbedtls_pk_parse_public_key(
      &pk,
      reinterpret_cast<const unsigned char *>(OTA_SIGNING_PUBLIC_KEY_PEM),
      strlen(OTA_SIGNING_PUBLIC_KEY_PEM) + 1);
  if (rc != 0) {
    Serial.print(F("[ota] Public key parse failed: "));
    Serial.println(rc);
    mbedtls_pk_free(&pk);
    free(decoded_sig);
    return false;
  }

  rc = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256, payload_hash, sizeof(payload_hash), decoded_sig, decoded_len);
  mbedtls_pk_free(&pk);
  free(decoded_sig);

  if (rc != 0) {
    Serial.print(F("[ota] Manifest signature verify failed: "));
    Serial.println(rc);
    return false;
  }

  return true;
}

static bool ota_wait_for_ntp_time() {
  time_t now = time(nullptr);
  if (now >= 1700000000) {
    return true;
  }

  Serial.print(F("[ota] Syncing time via NTP"));
  configTime(0, 0, OTA_NTP_SERVER);

  const unsigned long started = millis();
  while (millis() - started < 30000UL) {
    delay(500);
    Serial.print(F("."));
    now = time(nullptr);
    if (now >= 1700000000) {
      Serial.println();
      Serial.print(F("[ota] Time synced: "));
      Serial.println(static_cast<unsigned long>(now));
      return true;
    }
  }

  Serial.println();
  Serial.println(F("[ota] NTP sync failed - aborting HTTPS OTA"));
  return false;
}

static void ota_configure_tls_client(WiFiClientSecure &client) {
  client.setCACert(OTA_CA_CERT_PEM);
  client.setHandshakeTimeout(15);
}

static bool ota_stream_matches_sha256(Client &client, size_t expected_size, const String &expected_sha256_hex) {
  if (!Update.begin(expected_size > 0 ? expected_size : UPDATE_SIZE_UNKNOWN, U_FLASH)) {
    Serial.print(F("[ota] Update.begin failed: "));
    Serial.println(Update.errorString());
    return false;
  }

  Update.onProgress([](size_t done, size_t total) {
    if (total > 0) {
      Serial.print(F("[ota] Progress: "));
      Serial.print((done * 100) / total);
      Serial.println(F("%"));
    }
  });

  mbedtls_sha256_context sha_ctx;
  mbedtls_sha256_init(&sha_ctx);
  int sha_rc = mbedtls_sha256_starts(&sha_ctx, 0);
  if (sha_rc != 0) {
    Serial.print(F("[ota] SHA-256 init failed: "));
    Serial.println(sha_rc);
    mbedtls_sha256_free(&sha_ctx);
    Update.abort();
    return false;
  }

  uint8_t buffer[4096];
  size_t total_written = 0;
  unsigned long last_data_ms = millis();

  while (client.connected() || client.available()) {
    const size_t available = client.available();
    if (available == 0) {
      if (millis() - last_data_ms > 10000UL) {
        Serial.println(F("[ota] Firmware download timed out"));
        mbedtls_sha256_free(&sha_ctx);
        Update.abort();
        return false;
      }
      delay(1);
      continue;
    }

    const size_t to_read = available > sizeof(buffer) ? sizeof(buffer) : available;
    const int bytes_read = client.readBytes(reinterpret_cast<char *>(buffer), to_read);
    if (bytes_read <= 0) {
      Serial.println(F("[ota] Firmware stream read failed"));
      mbedtls_sha256_free(&sha_ctx);
      Update.abort();
      return false;
    }

    last_data_ms = millis();

    sha_rc = mbedtls_sha256_update(&sha_ctx, buffer, static_cast<size_t>(bytes_read));
    if (sha_rc != 0) {
      Serial.print(F("[ota] SHA-256 update failed: "));
      Serial.println(sha_rc);
      mbedtls_sha256_free(&sha_ctx);
      Update.abort();
      return false;
    }

    const size_t just_written = Update.write(buffer, static_cast<size_t>(bytes_read));
    if (just_written != static_cast<size_t>(bytes_read)) {
      Serial.print(F("[ota] Update write failed: "));
      Serial.println(Update.errorString());
      mbedtls_sha256_free(&sha_ctx);
      Update.abort();
      return false;
    }

    total_written += just_written;
  }

  unsigned char digest[32];
  sha_rc = mbedtls_sha256_finish(&sha_ctx, digest);
  mbedtls_sha256_free(&sha_ctx);
  if (sha_rc != 0) {
    Serial.print(F("[ota] SHA-256 finish failed: "));
    Serial.println(sha_rc);
    Update.abort();
    return false;
  }

  char digest_hex[65];
  for (size_t i = 0; i < sizeof(digest); ++i) {
    snprintf(&digest_hex[i * 2], 3, "%02x", digest[i]);
  }
  digest_hex[64] = '\0';

  Serial.print(F("[ota] Downloaded bytes: "));
  Serial.println(total_written);

  if (expected_size > 0 && total_written != expected_size) {
    Serial.print(F("[ota] Download size mismatch: "));
    Serial.print(total_written);
    Serial.print(F(" / "));
    Serial.println(expected_size);
    Update.abort();
    return false;
  }

  if (!expected_sha256_hex.equalsIgnoreCase(String(digest_hex))) {
    Serial.println(F("[ota] Firmware SHA-256 mismatch - skipping OTA"));
    Serial.print(F("[ota] Expected: "));
    Serial.println(expected_sha256_hex);
    Serial.print(F("[ota] Actual  : "));
    Serial.println(digest_hex);
    Update.abort();
    return false;
  }

  if (!Update.end()) {
    Serial.print(F("[ota] Update.end failed: "));
    Serial.println(Update.errorString());
    return false;
  }

  if (!Update.isFinished()) {
    Serial.println(F("[ota] Update not finished unexpectedly"));
    return false;
  }

  return true;
}

static void ota_add_auth_header(HTTPClient &http) {
  if (strlen(OTA_AUTH_TOKEN) > 0) {
    http.addHeader("Authorization", String("Bearer ") + OTA_AUTH_TOKEN);
  }
}

static void ota_disconnect_wifi() {
  WiFi.disconnect(true);
  WiFi.mode(WIFI_OFF);
}

static void ota_check_and_update_impl() {
  Serial.println(F("[ota] Checking for firmware update..."));
  Serial.print(F("[ota] Manifest: "));
  Serial.println(F(OTA_MANIFEST_URL));
  Serial.print(F("[ota] Current version: "));
  Serial.println((unsigned long)FW_VERSION_CODE);

  WiFi.mode(WIFI_STA);
  esp_wifi_set_country_code("EU", true);
  WiFi.setTxPower(WIFI_POWER_19_5dBm);

  wifi_scan_config_t scan_cfg;
  memset(&scan_cfg, 0, sizeof(scan_cfg));
  scan_cfg.channel_bitmap.ghz_2_channels = 0x3FFE;
  esp_wifi_scan_start(&scan_cfg, true);

  uint16_t ap_count = 0;
  esp_wifi_scan_get_ap_num(&ap_count);

  bool ssid_found = false;
  if (ap_count > 0) {
    wifi_ap_record_t *ap_list = (wifi_ap_record_t *)malloc(ap_count * sizeof(wifi_ap_record_t));
    if (ap_list && esp_wifi_scan_get_ap_records(&ap_count, ap_list) == ESP_OK) {
      for (int i = 0; i < (int)ap_count; i++) {
        if (strcmp((char *)ap_list[i].ssid, OTA_SSID) == 0) {
          Serial.print(F("[ota] Found AP, RSSI: "));
          Serial.println(ap_list[i].rssi);
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

  Serial.print(F("[ota] Connected, IP: "));
  Serial.println(WiFi.localIP());

  if (!ota_wait_for_ntp_time()) {
    ota_disconnect_wifi();
    return;
  }

  HTTPClient http;
  WiFiClientSecure client;
  ota_configure_tls_client(client);
  if (!http.begin(client, OTA_MANIFEST_URL)) {
    Serial.println(F("[ota] HTTPS manifest client init failed"));
    ota_disconnect_wifi();
    return;
  }
  http.useHTTP10(true);
  http.setConnectTimeout(15000);
  http.setTimeout(15000);
  ota_add_auth_header(http);
  const int code = http.GET();

  if (code != 200) {
    Serial.print(F("[ota] Manifest fetch failed, HTTP "));
    Serial.println(code);
    http.end();
    ota_disconnect_wifi();
    return;
  }

  JsonDocument doc;
  DeserializationError err = deserializeJson(doc, http.getStream());
  http.end();

  if (err) {
    Serial.print(F("[ota] Manifest JSON parse error: "));
    Serial.println(err.c_str());
    ota_disconnect_wifi();
    return;
  }

  const unsigned long remote_version = doc["version_code"].as<unsigned long>();
  const String fw_url = doc["url"].as<String>();
  const size_t fw_size = doc["size"].as<size_t>();
  const String fw_sha256 = doc["sha256"].as<String>();
  const String fw_signature = doc["signature"].as<String>();

  Serial.print(F("[ota] Remote version: "));
  Serial.println(remote_version);

  if (remote_version == 0 || fw_url.length() == 0) {
    Serial.println(F("[ota] Manifest missing version_code or url - skipping"));
    ota_disconnect_wifi();
    return;
  }

  if (remote_version <= (unsigned long)FW_VERSION_CODE) {
    Serial.println(F("[ota] Firmware is up to date - no update needed"));
    WiFi.disconnect(true);
    WiFi.mode(WIFI_OFF);
    return;
  }

  if (!ota_verify_manifest_signature(remote_version, fw_sha256, fw_signature)) {
    Serial.println(F("[ota] Manifest signature invalid - skipping OTA"));
    ota_disconnect_wifi();
    return;
  }

  Serial.print(F("[ota] Update available! Downloading "));
  Serial.println(fw_url);

  HTTPClient http2;
  WiFiClientSecure client2;
  ota_configure_tls_client(client2);
  if (!http2.begin(client2, fw_url)) {
    Serial.println(F("[ota] HTTPS firmware client init failed"));
    ota_disconnect_wifi();
    return;
  }
  http2.useHTTP10(true);
  http2.setConnectTimeout(15000);
  http2.setTimeout(15000);
  ota_add_auth_header(http2);
  const int fw_code = http2.GET();

  if (fw_code != 200) {
    Serial.print(F("[ota] Firmware fetch failed, HTTP "));
    Serial.println(fw_code);
    http2.end();
    ota_disconnect_wifi();
    return;
  }

  int content_len = http2.getSize();
  if (content_len <= 0 && fw_size > 0) {
    content_len = static_cast<int>(fw_size);
  }

  Serial.print(F("[ota] Firmware size: "));
  Serial.println(content_len);

  const size_t expected_download_size = content_len > 0 ? static_cast<size_t>(content_len) : fw_size;
  bool ok = ota_stream_matches_sha256(client2, expected_download_size, fw_sha256);
  http2.end();

  if (!ok) {
    ota_disconnect_wifi();
    return;
  }

  Serial.println(F("[ota] Update complete! Rebooting..."));
  ota_disconnect_wifi();
  delay(200);
  ESP.restart();
}

static void ota_task_fn(void *param) {
  ota_check_and_update_impl();
  vTaskDelete(NULL);
}

// Run OTA check in a FreeRTOS task with a larger stack (16KB).
// The default Arduino loopTask stack (8KB) is too small for
// WiFi + HTTPClient + ArduinoJson + mbedTLS ECDSA combined.
static void ota_check_and_update() {
  xTaskCreate(ota_task_fn, "ota_check", 16384, NULL, 1, NULL);
}

#endif
