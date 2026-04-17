#ifndef HTTP_PROBE_H
#define HTTP_PROBE_H

#include <Arduino.h>
#include "bolt.h"

#if HAS_HTTP_PROBE
#include <HTTPClient.h>
#include <WiFi.h>

extern sBoltConfig mBoltConfig;

static inline void http_probe_disconnect_wifi() {
  WiFi.disconnect(true);
  WiFi.mode(WIFI_OFF);
}

static inline size_t http_probe_read_body_preview(HTTPClient &http,
                                                  char *preview,
                                                  size_t preview_size,
                                                  bool &truncated) {
  WiFiClient *stream = http.getStreamPtr();
  size_t preview_len = 0;
  truncated = false;
  unsigned long last_data_ms = millis();

  while (http.connected() && (millis() - last_data_ms) < 10000UL) {
    led_notify_activity();
    led_tick();

    int available = stream->available();
    if (available <= 0) {
      delay(10);
      continue;
    }

    while (available-- > 0) {
      const int ch = stream->read();
      if (ch < 0) {
        break;
      }
      last_data_ms = millis();
      if ((preview_len + 1) < preview_size) {
        preview[preview_len++] = static_cast<char>(ch);
      } else {
        truncated = true;
      }
    }
  }

  if (http.getSize() > 0 && static_cast<int>(preview_len) < http.getSize()) {
    truncated = true;
  }

  preview[preview_len] = '\0';
  return preview_len;
}
#endif

static inline bool http_probe_url(const String &url) {
#if HAS_HTTP_PROBE
  if (url.length() == 0) return false;

  String http_url = url;
  if (http_url.startsWith("lnurlw://")) {
    http_url = "https://" + http_url.substring(10);
  }

  if (!http_url.startsWith("http://") && !http_url.startsWith("https://")) {
    Serial.println(F("[probe] URL is not HTTP, skipping"));
    return false;
  }

  if (mBoltConfig.wifi_ssid[0] == '\0') {
    Serial.println(F("[probe] WiFi SSID is empty, skipping"));
    return false;
  }

  Serial.print(F("[probe] URL: "));
  Serial.println(http_url);
  Serial.print(F("[probe] Connecting WiFi to SSID: "));
  Serial.println(mBoltConfig.wifi_ssid);

  WiFi.persistent(false);
  WiFi.setAutoReconnect(false);
  WiFi.mode(WIFI_STA);
  WiFi.begin(mBoltConfig.wifi_ssid, mBoltConfig.wifi_password);

  const unsigned long wifi_start_ms = millis();
  while (WiFi.status() != WL_CONNECTED && (millis() - wifi_start_ms) < 10000UL) {
    led_notify_activity();
    led_tick();
    delay(100);
  }

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println(F("[probe] WiFi connect timeout"));
    http_probe_disconnect_wifi();
    led_tick();
    return true;
  }

  Serial.print(F("[probe] WiFi connected, IP: "));
  Serial.println(WiFi.localIP());

  HTTPClient http;
  http.useHTTP10(true);
  http.setConnectTimeout(10000);
  http.setTimeout(10000);
  http.setFollowRedirects(HTTPC_FORCE_FOLLOW_REDIRECTS);

  if (!http.begin(http_url)) {
    Serial.println(F("[probe] HTTP begin failed"));
    http_probe_disconnect_wifi();
    led_tick();
    return true;
  }

  led_notify_activity();
  led_tick();
  const int http_code = http.GET();
  Serial.print(F("[probe] HTTP status: "));
  Serial.println(http_code);

  if (http_code > 0) {
    char body_preview[513] = {0};
    bool truncated = false;
    const size_t preview_len =
        http_probe_read_body_preview(http, body_preview, sizeof(body_preview), truncated);
    Serial.print(F("[probe] Body preview ("));
    Serial.print(preview_len);
    Serial.println(F(" bytes):"));
    if (preview_len > 0) {
      Serial.println(body_preview);
      if (truncated) {
        Serial.println(F("[probe] Body truncated to 512 chars"));
      }
    } else {
      Serial.println(F("[probe] <empty body>"));
    }
  } else {
    Serial.print(F("[probe] HTTP GET failed: "));
    Serial.println(http.errorToString(http_code));
  }

  http.end();
  http_probe_disconnect_wifi();
  Serial.println(F("[probe] WiFi disconnected"));
  led_tick();
  return true;
#else
  (void)url;
  return false;
#endif
}

#endif
