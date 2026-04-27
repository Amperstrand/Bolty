#ifndef BOLTY_LED_H
#define BOLTY_LED_H

#include "hardware_config.h"
#include <Arduino.h>
#include "debug.h"

#if HAS_LED_MATRIX
#include <M5Unified.h>
#endif

#if HAS_LED_MATRIX
namespace bolty_led_internal {
static bool initialized = false;
static bool supported = false;
static bool animating = false;

static unsigned long success_until = 0;
static unsigned long error_until = 0;
static unsigned long activity_until = 0;
static unsigned long card_blank_until = 0;
static unsigned long card_unknown_until = 0;
static unsigned long card_programmed_until = 0;
static unsigned long assessment_until = 0;
static uint8_t assessment_rows[5] = {0};
static unsigned long hold_countdown_until = 0;
static uint8_t hold_countdown_rows = 0;
static unsigned long key_local_until = 0;
static unsigned long key_online_until = 0;

static const uint8_t kLedCount = 25;
static const uint16_t kResultMs = 600;
static const uint16_t kActivityMs = 100;
static const uint16_t kCardPulseMs = 500;

static inline void hsv_to_rgb(uint16_t h, uint8_t s, uint8_t v,
                               uint8_t &r, uint8_t &g, uint8_t &b) {
  uint8_t region = (h / 60) % 6;
  uint8_t rem = (uint8_t)((h % 60) * 255 / 60);
  uint8_t p = (uint8_t)((v * (255 - s)) >> 8);
  uint8_t q = (uint8_t)((v * (255 - ((s * rem) >> 8))) >> 8);
  uint8_t t = (uint8_t)((v * (255 - ((s * (255 - rem)) >> 8))) >> 8);
  switch (region) {
    case 0: r = v; g = t; b = p; break;
    case 1: r = q; g = v; b = p; break;
    case 2: r = p; g = v; b = t; break;
    case 3: r = p; g = q; b = v; break;
    case 4: r = t; g = p; b = v; break;
    default: r = v; g = p; b = q; break;
  }
}

static inline void rainbow_cycle(uint16_t per_led_ms) {
  if (!initialized || !supported) return;
  animating = true;
  M5.Led.setBrightness(255);
  M5.Led.setAllColor(0, 0, 0);
  M5.Led.display();
  for (int i = 0; i < kLedCount; i++) {
    uint8_t r, g, b;
    hsv_to_rgb((uint16_t)(i * 360 / kLedCount), 255, 255, r, g, b);
    M5.Led.setColor(i, r, g, b);
    M5.Led.display();
    delay(per_led_ms);
  }
  delay(400);
  M5.Led.setAllColor(0, 0, 0);
  M5.Led.display();
  animating = false;
}

static inline void row_set(int row, uint8_t r, uint8_t g, uint8_t b) {
  for (int col = 0; col < 5; col++) {
    M5.Led.setColor(row * 5 + col, r, g, b);
  }
}

static inline void alternate_frame(bool frame_a) {
  if (!initialized || !supported) return;
  animating = true;
  M5.Led.setBrightness(255);
  M5.Led.setAllColor(0, 0, 0);
  for (int row = 0; row < 5; row++) {
    for (int col = 0; col < 5; col++) {
      if (((row + col) % 2 == 0) == frame_a) {
        M5.Led.setColor(row * 5 + col, 255, 255, 255);
      }
    }
  }
  M5.Led.display();
  animating = false;
}

static inline void render() {
  if (!initialized || !supported || animating) return;

  const unsigned long now = millis();
  const bool show_success = now < success_until;
  const bool show_error = now < error_until;
  const bool show_activity = now < activity_until;
  const bool show_blank = now < card_blank_until;
  const bool show_unknown = now < card_unknown_until;
  const bool show_programmed = now < card_programmed_until;
  const bool show_assessment = now < assessment_until;
  const bool show_hold_countdown = now < hold_countdown_until;
  const bool show_key_local = now < key_local_until;
  const bool show_key_online = now < key_online_until;

  if (!show_success && !show_error && !show_activity && !show_blank &&
      !show_unknown && !show_programmed && !show_assessment &&
      !show_hold_countdown && !show_key_local && !show_key_online) {
    M5.Led.setBrightness(1);
    M5.Led.setAllColor(0, 0, 0);
    M5.Led.display();
    return;
  }

  M5.Led.setBrightness(255);
  M5.Led.setAllColor(0, 0, 0);

  if (show_error) {
    M5.Led.setAllColor(255, 0, 0);
  } else if (show_success) {
    M5.Led.setAllColor(0, 255, 0);
  } else if (show_blank) {
    static const uint8_t pulse[] = {0, 2, 4, 10, 12, 14, 20, 22, 24};
    for (auto idx : pulse) M5.Led.setColor(idx, 0, 255, 0);
  } else if (show_programmed) {
    static const uint8_t pulse[] = {0, 2, 4, 10, 12, 14, 20, 22, 24};
    for (auto idx : pulse) M5.Led.setColor(idx, 255, 0, 0);
  } else if (show_unknown) {
    static const uint8_t pulse[] = {0, 2, 4, 10, 12, 14, 20, 22, 24};
    for (auto idx : pulse) M5.Led.setColor(idx, 0, 80, 255);
  } else if (show_hold_countdown) {
    for (uint8_t row = 0; row < hold_countdown_rows && row < 5; row++) {
      row_set(row, 255, 255, 255);
    }
  } else if (show_assessment) {
    for (uint8_t row = 0; row < 5; row++) {
      switch (assessment_rows[row]) {
        case 2:
          row_set(row, 0, 255, 0);
          break;
        case 1:
          row_set(row, 255, 180, 0);
          break;
        default:
          row_set(row, 60, 0, 0);
          break;
      }
    }
  } else if (show_key_local) {
    M5.Led.setAllColor(0, 255, 0);
  } else if (show_key_online) {
    M5.Led.setAllColor(255, 165, 0);
  } else if (show_activity) {
    M5.Led.setColor(12, 200, 200, 200);
  }

  M5.Led.display();
}
}

static inline void led_setup() {
  if (bolty_led_internal::initialized) return;

  auto cfg = M5.config();
  M5.begin(cfg);
  bolty_led_internal::initialized = true;
  bolty_led_internal::supported = M5.Led.isEnabled();
  DBG_PRINT("[led] Atom matrix enabled: ");
  DBG_PRINTLN(bolty_led_internal::supported ? "yes" : "no");
  if (!bolty_led_internal::supported) return;

  pinMode(M5_ATOM_BTN_PIN, INPUT);
  M5.Led.setBrightness(1);
  M5.Led.setAllColor(0, 0, 0);
  M5.Led.display();
}

// Self-test visual protocol: row 0 = LED matrix, row 1 = NFC, row 2 = button.
static inline void led_self_test(bool nfc_ok) {
  if (!bolty_led_internal::initialized || !bolty_led_internal::supported) return;
  bolty_led_internal::animating = true;
  M5.Led.setBrightness(255);

  M5.Led.setAllColor(0, 0, 0);
  bolty_led_internal::row_set(0, 255, 255, 0);
  M5.Led.display();
  DBG_PRINTLN("[test] LED matrix...");
  delay(300);
  M5.Led.setAllColor(0, 0, 0);
  bolty_led_internal::row_set(0, 0, 255, 0);
  M5.Led.display();
  DBG_PRINTLN("[test] LED matrix OK");
  delay(300);

  M5.Led.setAllColor(0, 0, 0);
  bolty_led_internal::row_set(0, 0, 255, 0);
  bolty_led_internal::row_set(1, 255, 255, 0);
  M5.Led.display();
  DBG_PRINTLN("[test] NFC...");
  delay(300);
  M5.Led.setAllColor(0, 0, 0);
  bolty_led_internal::row_set(0, 0, 255, 0);
  bolty_led_internal::row_set(1, nfc_ok ? 0 : 255, nfc_ok ? 255 : 0, 0);
  M5.Led.display();
  DBG_PRINT("[test] NFC "); DBG_PRINTLN(nfc_ok ? "OK" : "FAIL");
  delay(300);

  M5.Led.setAllColor(0, 0, 0);
  bolty_led_internal::row_set(0, 0, 255, 0);
  bolty_led_internal::row_set(1, nfc_ok ? 0 : 255, nfc_ok ? 255 : 0, 0);
  bolty_led_internal::row_set(2, 255, 255, 0);
  M5.Led.display();
  DBG_PRINTLN("[test] Button (GPIO39)...");
  delay(300);
  M5.Led.setAllColor(0, 0, 0);
  bolty_led_internal::row_set(0, 0, 255, 0);
  bolty_led_internal::row_set(1, nfc_ok ? 0 : 255, nfc_ok ? 255 : 0, 0);
  bolty_led_internal::row_set(2, 0, 255, 0);
  M5.Led.display();
  DBG_PRINTLN("[test] Button present");
  delay(300);

  if (nfc_ok) {
    bolty_led_internal::rainbow_cycle(20);
  } else {
    M5.Led.setAllColor(255, 0, 0);
    M5.Led.display();
    delay(500);
  }

  M5.Led.setBrightness(1);
  M5.Led.setAllColor(0, 0, 0);
  M5.Led.display();
  bolty_led_internal::animating = false;
}

static inline void led_boot_animation(bool hw_ready) {
  led_self_test(hw_ready);
}

static inline void led_tick() {
  bolty_led_internal::render();
}

static inline void led_set_hardware_ready(bool) {}
static inline void led_set_app_mode(uint8_t) {}

static inline void led_set_job_status(uint8_t job_status) {
  if (job_status == 4) {
    bolty_led_internal::success_until = millis() + bolty_led_internal::kResultMs;
  } else if (job_status == 5 || job_status == 6) {
    bolty_led_internal::error_until = millis() + bolty_led_internal::kResultMs;
  }
}

static inline void led_set_busy(bool) {}
static inline void led_notify_card_present() {}
static inline void led_notify_activity() {
  bolty_led_internal::activity_until = millis() + bolty_led_internal::kActivityMs;
}
static inline void led_notify_button_press() {}

static inline void led_signal_card_blank() {
  bolty_led_internal::card_blank_until = millis() + bolty_led_internal::kCardPulseMs;
}

static inline void led_signal_card_unknown() {
  bolty_led_internal::card_unknown_until = millis() + bolty_led_internal::kCardPulseMs;
}

static inline void led_signal_card_programmed() {
  bolty_led_internal::card_programmed_until = millis() + bolty_led_internal::kCardPulseMs;
}

static inline void led_signal_key_local() {
  bolty_led_internal::key_local_until = millis() + 3000;
}

static inline void led_signal_key_online() {
  bolty_led_internal::key_online_until = millis() + 3000;
}

static inline void led_show_key_assessment(const uint8_t rows[5], uint16_t duration_ms) {
  memcpy(bolty_led_internal::assessment_rows, rows, 5);
  bolty_led_internal::assessment_until = millis() + duration_ms;
}

static inline void led_show_hold_countdown(uint8_t rows, uint16_t duration_ms) {
  bolty_led_internal::hold_countdown_rows = rows;
  bolty_led_internal::hold_countdown_until = millis() + duration_ms;
}

static inline void led_button_cycle() {
  if (!bolty_led_internal::initialized || !bolty_led_internal::supported) return;
  for (int f = 0; f < 6; f++) {
    bolty_led_internal::alternate_frame(f % 2 == 0);
    delay(80);
  }
  M5.Led.setBrightness(1);
  M5.Led.setAllColor(0, 0, 0);
  M5.Led.display();
}

static inline void led_set_held(bool held) {
  if (!bolty_led_internal::initialized || !bolty_led_internal::supported) return;
  if (bolty_led_internal::animating) return;
  if (held) {
    M5.Led.setBrightness(255);
    M5.Led.setAllColor(255, 255, 255);
    M5.Led.display();
  } else {
    M5.Led.setBrightness(1);
    M5.Led.setAllColor(0, 0, 0);
    M5.Led.display();
  }
}

static inline void led_signal_result(bool success) {
  if (success) {
    bolty_led_internal::success_until = millis() + bolty_led_internal::kResultMs;
  } else {
    bolty_led_internal::error_until = millis() + bolty_led_internal::kResultMs;
  }
}

#else

static inline void led_setup() {}
static inline void led_boot_animation(bool hardware_ready) {
#if LED_PIN >= 0
  const int blink_count = hardware_ready ? 2 : 5;
  const int blink_ms = 100;
  for (int i = 0; i < blink_count; ++i) {
    digitalWrite(LED_PIN, LOW);
    delay(blink_ms);
    digitalWrite(LED_PIN, HIGH);
    if (i + 1 < blink_count) {
      delay(blink_ms);
    }
  }
#else
  (void)hardware_ready;
#endif
}
static inline void led_tick() {}
static inline void led_set_hardware_ready(bool) {}
static inline void led_set_app_mode(uint8_t) {}
static inline void led_set_job_status(uint8_t) {}
static inline void led_set_busy(bool) {}
static inline void led_notify_card_present() {}
static inline void led_notify_activity() {}
static inline void led_notify_button_press() {}
static inline void led_signal_card_blank() {}
static inline void led_signal_card_unknown() {}
static inline void led_signal_card_programmed() {}
static inline void led_signal_key_local() {}
static inline void led_signal_key_online() {}
static inline void led_button_cycle() {}
static inline void led_set_held(bool) {}
static inline void led_signal_result(bool) {}

#endif

#endif
