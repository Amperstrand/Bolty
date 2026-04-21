#pragma once
#if HAS_REST_SERVER

#include <esp_https_server.h>
#include <ArduinoJson.h>
#include <ESPmDNS.h>
#include "rest_server_cert.h"

// Forward declarations for globals defined in bolty.ino
extern BoltDevice bolt;
extern sBoltConfig mBoltConfig;
extern volatile bool serial_cmd_active;
extern bool bolty_hw_ready;
extern bool has_issuer_key;

// Auth tokens — separate read and write access.
// Set via build flags: -DREST_READ_TOKEN='"..."' -DREST_WRITE_TOKEN='"..."'.
// Empty string = no auth required for that level.
// If only REST_AUTH_TOKEN is defined (legacy), it grants full access.
#ifndef REST_READ_TOKEN
  #ifdef REST_AUTH_TOKEN
    #define REST_READ_TOKEN REST_AUTH_TOKEN
  #else
    #define REST_READ_TOKEN ""
  #endif
#endif

#ifndef REST_WRITE_TOKEN
  #ifdef REST_AUTH_TOKEN
    #define REST_WRITE_TOKEN REST_AUTH_TOKEN
  #else
    #define REST_WRITE_TOKEN ""
  #endif
#endif

static httpd_handle_t _rest_server = NULL;

static bool _rest_check_token(httpd_req_t *req, const char *expected_token) {
  if (strlen(expected_token) == 0) return true;
  size_t hdr_len = httpd_req_get_hdr_value_len(req, "Authorization") + 1;
  if (hdr_len <= 1) {
    httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Missing Authorization header");
    return false;
  }
  char *hdr = (char *)malloc(hdr_len);
  if (!hdr) { httpd_resp_send_500(req); return false; }
  httpd_req_get_hdr_value_str(req, "Authorization", hdr, hdr_len);
  bool ok = (strncmp(hdr, "Bearer ", 7) == 0 && strcmp(hdr + 7, expected_token) == 0);
  free(hdr);
  if (!ok) { httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Invalid token"); }
  return ok;
}

// Read endpoints: status, uid, keyver, check, ndef, job
static bool _rest_check_read_auth(httpd_req_t *req) {
  return _rest_check_token(req, REST_READ_TOKEN);
}

// Write endpoints: keys, url, burn, wipe
static bool _rest_check_write_auth(httpd_req_t *req) {
  return _rest_check_token(req, REST_WRITE_TOKEN);
}

static esp_err_t _rest_json(httpd_req_t *req, const char *json) {
  httpd_resp_set_type(req, "application/json");
  httpd_resp_set_hdr(req, "Connection", "close");
  return httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
}

static esp_err_t _rest_error(httpd_req_t *req, const char *msg) {
  char json[192];
  snprintf(json, sizeof(json), "{\"ok\":false,\"error\":\"%s\"}", msg);
  return _rest_json(req, json);
}

static bool _rest_read_body(httpd_req_t *req, char *buf, size_t buf_size) {
  int remaining = req->content_len;
  int total = 0;
  while (remaining > 0 && total < (int)buf_size - 1) {
    int recv = httpd_req_recv(req, buf + total, remaining > 256 ? 256 : remaining);
    if (recv == HTTPD_SOCK_ERR_TIMEOUT) continue;
    if (recv <= 0) return false;
    remaining -= recv;
    total += recv;
  }
  buf[total] = '\0';
  return true;
}

static bool _rest_wait_card(uint8_t *uid, uint8_t *uid_len, uint32_t timeout_ms) {
  uint32_t t0 = millis();
  do {
    if (bolty_read_passive_target(bolt.nfc, uid, uid_len)) return true;
    if (millis() - t0 > timeout_ms) return false;
    delay(50);
  } while (true);
}

// ── GET /api/status ──

static esp_err_t rest_get_status(httpd_req_t *req) {
  if (!_rest_check_read_auth(req)) return ESP_FAIL;
  char json[384];
  snprintf(json, sizeof(json),
    "{\"ok\":true,\"hw_ready\":%s,\"uid\":\"%s\",\"job\":\"%s\","
    "\"card_name\":\"%s\",\"url\":\"%s\"}",
    bolty_hw_ready ? "true" : "false",
    bolt.getScannedUid().c_str(),
    bolt.get_job_status().c_str(),
    mBoltConfig.card_name,
    mBoltConfig.url);
  return _rest_json(req, json);
}

// ── GET /api/uid ──

static esp_err_t rest_get_uid(httpd_req_t *req) {
  if (!_rest_check_read_auth(req)) return ESP_FAIL;
  if (!bolty_hw_ready) return _rest_error(req, "NFC not ready");
  if (serial_cmd_active) return _rest_error(req, "Device busy");
  serial_cmd_active = true;
  uint8_t uid[12] = {0};
  uint8_t uid_len = 0;
  bool found = _rest_wait_card(uid, &uid_len, 10000);
  if (!found) {
    serial_cmd_active = false;
    return _rest_error(req, "No card detected (10s timeout)");
  }
  String uid_hex = convertIntToHex(uid, uid_len);
  bool is_ntag = (uid_len == 7 || uid_len == 4) && bolt.nfc->ntag424_isNTAG424();
  char json[192];
  snprintf(json, sizeof(json), "{\"ok\":true,\"uid\":\"%s\",\"ntag424\":%s}",
    uid_hex.c_str(), is_ntag ? "true" : "false");
  serial_cmd_active = false;
  return _rest_json(req, json);
}

// ── POST /api/keys ──

static esp_err_t rest_post_keys(httpd_req_t *req) {
  if (!_rest_check_write_auth(req)) return ESP_FAIL;
  if (serial_cmd_active) return _rest_error(req, "Device busy");
  char body[512] = {0};
  if (!_rest_read_body(req, body, sizeof(body))) return _rest_error(req, "Failed to read body");

  JsonDocument doc;
  if (deserializeJson(doc, body)) return _rest_error(req, "Invalid JSON");

  const char *k0 = doc["k0"] | "";
  const char *k1 = doc["k1"] | "";
  const char *k2 = doc["k2"] | "";
  const char *k3 = doc["k3"] | "";
  const char *k4 = doc["k4"] | "";
  if (strlen(k0) != 32 || strlen(k1) != 32 || strlen(k2) != 32 ||
      strlen(k3) != 32 || strlen(k4) != 32)
    return _rest_error(req, "Each key must be 32 hex chars");

  strncpy(mBoltConfig.k0, k0, 33);
  strncpy(mBoltConfig.k1, k1, 33);
  strncpy(mBoltConfig.k2, k2, 33);
  strncpy(mBoltConfig.k3, k3, 33);
  strncpy(mBoltConfig.k4, k4, 33);
  has_issuer_key = false;
  return _rest_json(req, "{\"ok\":true,\"message\":\"Keys set\"}");
}

// ── POST /api/url ──

static esp_err_t rest_post_url(httpd_req_t *req) {
  if (!_rest_check_write_auth(req)) return ESP_FAIL;
  if (serial_cmd_active) return _rest_error(req, "Device busy");
  char body[512] = {0};
  if (!_rest_read_body(req, body, sizeof(body))) return _rest_error(req, "Failed to read body");

  JsonDocument doc;
  if (deserializeJson(doc, body)) return _rest_error(req, "Invalid JSON");
  const char *url = doc["url"] | "";
  if (strlen(url) == 0) return _rest_error(req, "Missing 'url' field");

  strncpy(mBoltConfig.url, url, sizeof(mBoltConfig.url));
  if (strncmp(url, "lnurlp://", 9) == 0) {
    strncpy(mBoltConfig.card_mode, "pos", sizeof(mBoltConfig.card_mode));
  } else if (strncmp(url, "https://", 8) == 0) {
    strncpy(mBoltConfig.card_mode, "2fa", sizeof(mBoltConfig.card_mode));
  } else {
    strncpy(mBoltConfig.card_mode, "withdraw", sizeof(mBoltConfig.card_mode));
  }
  return _rest_json(req, "{\"ok\":true,\"message\":\"URL set\"}");
}

// ── GET /api/keyver ──

static esp_err_t rest_get_keyver(httpd_req_t *req) {
  if (!_rest_check_read_auth(req)) return ESP_FAIL;
  if (!bolty_hw_ready) return _rest_error(req, "NFC not ready");
  if (serial_cmd_active) return _rest_error(req, "Device busy");
  serial_cmd_active = true;

  uint8_t uid[12] = {0};
  uint8_t uid_len = 0;
  if (!_rest_wait_card(uid, &uid_len, 10000)) {
    serial_cmd_active = false;
    return _rest_error(req, "No card detected");
  }
  String uid_hex = convertIntToHex(uid, uid_len);
  bolt.nfc->ntag424_ISOSelectFileByDFN((uint8_t *)NTAG424_AID);

  char json[320];
  int pos = snprintf(json, sizeof(json),
    "{\"ok\":true,\"uid\":\"%s\",\"keys\":[", uid_hex.c_str());
  bool all_zero = true;
  for (int k = 0; k < 5; k++) {
    uint8_t kv = bolty_get_key_version(bolt.nfc, k);
    if (kv != 0x00) all_zero = false;
    pos += snprintf(json + pos, sizeof(json) - pos,
      "%s{\"slot\":%d,\"version\":\"0x%02X\",\"factory\":%s}",
      k > 0 ? "," : "", k, kv, kv == 0x00 ? "true" : "false");
  }
  pos += snprintf(json + pos, sizeof(json) - pos,
    "],\"state\":\"%s\"}", all_zero ? "blank" : "provisioned");

  serial_cmd_active = false;
  return _rest_json(req, json);
}

// ── GET /api/check ──

static esp_err_t rest_get_check(httpd_req_t *req) {
  if (!_rest_check_read_auth(req)) return ESP_FAIL;
  if (!bolty_hw_ready) return _rest_error(req, "NFC not ready");
  if (serial_cmd_active) return _rest_error(req, "Device busy");
  serial_cmd_active = true;

  uint8_t uid[12] = {0};
  uint8_t uid_len = 0;
  if (!_rest_wait_card(uid, &uid_len, 10000)) {
    serial_cmd_active = false;
    return _rest_error(req, "No card detected");
  }

  uint8_t zero_key[16] = {0};
  uint8_t result = bolt.nfc->ntag424_Authenticate(zero_key, 0, 0x71);
  serial_cmd_active = false;

  char json[128];
  snprintf(json, sizeof(json), "{\"ok\":true,\"blank\":%s}",
    result == 1 ? "true" : "false");
  return _rest_json(req, json);
}

// ── POST /api/burn ──

static esp_err_t rest_post_burn(httpd_req_t *req) {
  if (!_rest_check_write_auth(req)) return ESP_FAIL;
  if (!bolty_hw_ready) return _rest_error(req, "NFC not ready");
  if (serial_cmd_active) return _rest_error(req, "Device busy");
  if (strlen(mBoltConfig.url) == 0) return _rest_error(req, "No URL set");
  if (strlen(mBoltConfig.k0) == 0) return _rest_error(req, "No keys set");

  serial_cmd_active = true;
  bolt.loadKeysForBurn(mBoltConfig);
  uint8_t result;
  uint32_t t0 = millis();
  do {
    result = bolt.burn(String(mBoltConfig.url));
    if (millis() - t0 > 30000) {
      serial_cmd_active = false;
      return _rest_error(req, "Timeout (30s)");
    }
  } while (result == JOBSTATUS_WAITING);

  char json[192];
  snprintf(json, sizeof(json),
    "{\"ok\":%s,\"status\":\"%s\",\"job_id\":%u}",
    result == JOBSTATUS_DONE ? "true" : "false",
    result == JOBSTATUS_DONE ? "done" :
      result == JOBSTATUS_GUARD_REJECT ? "guard_rejected" : "error",
    result);
  serial_cmd_active = false;
  return _rest_json(req, json);
}

// ── POST /api/wipe ──

static esp_err_t rest_post_wipe(httpd_req_t *req) {
  if (!_rest_check_write_auth(req)) return ESP_FAIL;
  if (!bolty_hw_ready) return _rest_error(req, "NFC not ready");
  if (serial_cmd_active) return _rest_error(req, "Device busy");
  if (strlen(mBoltConfig.k0) == 0) return _rest_error(req, "No keys set");

  serial_cmd_active = true;
  bolt.loadKeysForWipe(mBoltConfig);
  uint8_t result;
  uint32_t t0 = millis();
  do {
    result = bolt.wipe();
    if (millis() - t0 > 30000) {
      serial_cmd_active = false;
      return _rest_error(req, "Timeout (30s)");
    }
  } while (result == JOBSTATUS_WAITING);

  char json[192];
  snprintf(json, sizeof(json),
    "{\"ok\":%s,\"status\":\"%s\",\"job_id\":%u}",
    result == JOBSTATUS_DONE ? "true" : "false",
    result == JOBSTATUS_DONE ? "done" :
      result == JOBSTATUS_GUARD_REJECT ? "guard_rejected" : "error",
    result);
  serial_cmd_active = false;
  return _rest_json(req, json);
}

// ── GET /api/ndef ──

static esp_err_t rest_get_ndef(httpd_req_t *req) {
  if (!_rest_check_read_auth(req)) return ESP_FAIL;
  if (!bolty_hw_ready) return _rest_error(req, "NFC not ready");
  if (serial_cmd_active) return _rest_error(req, "Device busy");
  serial_cmd_active = true;

  uint8_t uid[12] = {0};
  uint8_t uid_len = 0;
  if (!_rest_wait_card(uid, &uid_len, 10000)) {
    serial_cmd_active = false;
    return _rest_error(req, "No card detected");
  }

  uint8_t ndef[256] = {0};
  int len = bolt.nfc->ntag424_ReadNDEFMessage(ndef, sizeof(ndef));
  serial_cmd_active = false;

  if (len <= 0) return _rest_error(req, "NDEF read failed");

  String uri;
  bool has_uri = ndef_extract_uri(ndef, len, uri);
  char ascii[257] = {0};
  for (int i = 0; i < len && i < 256; i++)
    ascii[i] = (ndef[i] >= 0x20 && ndef[i] < 0x7F) ? ndef[i] : '.';

  // Build JSON manually since the URI might contain special chars
  char json[512];
  int pos = snprintf(json, sizeof(json),
    "{\"ok\":true,\"length\":%d,\"ascii\":\"", len);
  for (int i = 0; i < len && pos < 480; i++) {
    char c = ascii[i];
    if (c == '"' || c == '\\') json[pos++] = '\\';
    json[pos++] = c;
  }
  pos += snprintf(json + pos, sizeof(json) - pos,
    "\",\"uri\":\"");
  if (has_uri) {
    for (unsigned int i = 0; i < uri.length() && pos < 480; i++) {
      char c = uri.charAt(i);
      if (c == '"' || c == '\\') json[pos++] = '\\';
      json[pos++] = c;
    }
  }
  pos += snprintf(json + pos, sizeof(json) - pos, "\"}");
  json[pos] = '\0';
  return _rest_json(req, json);
}

// ── GET /api/job ──

static esp_err_t rest_get_job(httpd_req_t *req) {
  if (!_rest_check_read_auth(req)) return ESP_FAIL;
  char json[128];
  snprintf(json, sizeof(json),
    "{\"ok\":true,\"status\":\"%s\",\"id\":%u,\"busy\":%s}",
    bolt.get_job_status().c_str(),
    bolt.get_job_status_id(),
    serial_cmd_active ? "true" : "false");
  return _rest_json(req, json);
}

// ── URI registrations ──

static const httpd_uri_t _rest_uris[] = {
  { .uri = "/api/status", .method = HTTP_GET,  .handler = rest_get_status },
  { .uri = "/api/uid",    .method = HTTP_GET,  .handler = rest_get_uid },
  { .uri = "/api/keys",   .method = HTTP_POST, .handler = rest_post_keys },
  { .uri = "/api/url",    .method = HTTP_POST, .handler = rest_post_url },
  { .uri = "/api/keyver", .method = HTTP_GET,  .handler = rest_get_keyver },
  { .uri = "/api/check",  .method = HTTP_GET,  .handler = rest_get_check },
  { .uri = "/api/burn",   .method = HTTP_POST, .handler = rest_post_burn },
  { .uri = "/api/wipe",   .method = HTTP_POST, .handler = rest_post_wipe },
  { .uri = "/api/ndef",   .method = HTTP_GET,  .handler = rest_get_ndef },
  { .uri = "/api/job",    .method = HTTP_GET,  .handler = rest_get_job },
};
static const int _rest_uri_count = sizeof(_rest_uris) / sizeof(_rest_uris[0]);

static void bolty_rest_server_start() {
  if (_rest_server != NULL) return;

  httpd_ssl_config_t conf = HTTPD_SSL_CONFIG_DEFAULT();
  conf.servercert = reinterpret_cast<const uint8_t *>(REST_SERVER_CERT_PEM);
  conf.servercert_len = sizeof(REST_SERVER_CERT_PEM);
  conf.prvtkey_pem = reinterpret_cast<const uint8_t *>(REST_SERVER_KEY_PEM);
  conf.prvtkey_len = sizeof(REST_SERVER_KEY_PEM);

  conf.httpd.stack_size = 10240;
  conf.httpd.max_open_sockets = 2;
  conf.httpd.max_uri_handlers = 12;
  conf.httpd.lru_purge_enable = true;
  conf.httpd.keep_alive_enable = true;
  conf.httpd.keep_alive_idle = 5;
  conf.httpd.keep_alive_interval = 3;
  conf.httpd.keep_alive_count = 2;
  conf.httpd.task_priority = tskIDLE_PRIORITY + 5;

  esp_err_t ret = httpd_ssl_start(&_rest_server, &conf);
  if (ret != ESP_OK) {
    Serial.print("[rest] HTTPS server start failed: ");
    Serial.println(esp_err_to_name(ret));
    _rest_server = NULL;
    return;
  }

  for (int i = 0; i < _rest_uri_count; i++) {
    esp_err_t reg = httpd_register_uri_handler(_rest_server, &_rest_uris[i]);
    if (reg != ESP_OK) {
      Serial.print("[rest] FAILED to register ");
      Serial.print(_rest_uris[i].uri);
      Serial.print(": ");
      Serial.println(esp_err_to_name(reg));
    }
  }

  Serial.println("[rest] HTTPS provisioning server started on port 443");

  if (MDNS.begin("bolty")) {
    MDNS.addService("bolty", "tcp", 443);
    Serial.println("[rest] mDNS: bolty.local → " + WiFi.localIP().toString());
  } else {
    Serial.println("[rest] mDNS start failed (non-fatal)");
  }
}

static void bolty_rest_server_stop() {
  if (_rest_server != NULL) {
    httpd_ssl_stop(_rest_server);
    _rest_server = NULL;
    Serial.println("[rest] HTTPS server stopped");
  }
}

#endif
