#ifndef BOLTY_LED_H
#define BOLTY_LED_H

#include "hardware_config.h"
#include <Arduino.h>

#if HAS_LED_MATRIX
#include <M5Unified.h>
#endif

#if HAS_LED_MATRIX
namespace bolty_led_internal {
static bool initialized = false;
static bool supported = false;
static bool hardware_ready = false;
static bool busy = false;
static uint8_t app_mode = 0;
static uint8_t job_status = 0;
static unsigned long card_present_until = 0;
static unsigned long activity_until = 0;
static unsigned long success_until = 0;
static unsigned long error_until = 0;
static uint32_t last_render_key = 0;
static bool force_render = true;

static const uint8_t kLedBrightness = 20;
static const uint16_t kOverlayCardMs = 350;
static const uint16_t kOverlayActivityMs = 120;
static const uint16_t kOverlayResultMs = 900;

static inline void set_all(uint8_t r, uint8_t g, uint8_t b) {
  M5.Led.setAllColor(r, g, b);
}

static inline void set_pixels(const uint8_t *indices, size_t count, uint8_t r,
                              uint8_t g, uint8_t b) {
  for (size_t i = 0; i < count; ++i) {
    M5.Led.setColor(indices[i], r, g, b);
  }
}

static inline void base_color(uint8_t &r, uint8_t &g, uint8_t &b) {
  if (!hardware_ready) {
    r = 20;
    g = 0;
    b = 0;
    return;
  }

  switch (job_status) {
    case 1:
      r = 0;
      g = 0;
      b = 18;
      return;
    case 2:
      r = 24;
      g = 10;
      b = 0;
      return;
    case 3:
      r = 18;
      g = 0;
      b = 8;
      return;
    case 4:
      r = 0;
      g = 22;
      b = 0;
      return;
    case 5:
      r = 22;
      g = 0;
      b = 0;
      return;
    case 6:
      r = 16;
      g = 0;
      b = 16;
      return;
    default:
      break;
  }

  switch (app_mode) {
    case 0:
      r = 0;
      g = 12;
      b = 12;
      break;
    case 1:
      r = 18;
      g = 10;
      b = 0;
      break;
    case 2:
      r = 16;
      g = 0;
      b = 10;
      break;
    default:
      r = 0;
      g = 10;
      b = 0;
      break;
  }
}

static inline uint32_t render_key(bool show_success, bool show_error,
                                  bool show_card, bool show_activity,
                                  uint8_t r, uint8_t g, uint8_t b) {
  return ((uint32_t)show_success << 31) | ((uint32_t)show_error << 30) |
         ((uint32_t)show_card << 29) | ((uint32_t)show_activity << 28) |
         ((uint32_t)busy << 27) | ((uint32_t)r << 16) | ((uint32_t)g << 8) |
         (uint32_t)b;
}

static inline void render() {
  if (!initialized || !supported) {
    return;
  }

  M5.update();

  const unsigned long now = millis();
  const bool show_success = now < success_until;
  const bool show_error = now < error_until;
  const bool show_card = now < card_present_until;
  const bool show_activity = now < activity_until;

  uint8_t r = 0;
  uint8_t g = 0;
  uint8_t b = 0;
  base_color(r, g, b);

  const uint32_t key = render_key(show_success, show_error, show_card,
                                  show_activity, r, g, b);
  if (!force_render && key == last_render_key) {
    return;
  }

  if (show_error) {
    set_all(48, 0, 0);
  } else if (show_success) {
    set_all(0, 36, 0);
  } else {
    set_all(r, g, b);

    if (busy) {
      static const uint8_t kBusyPixels[] = {2, 7, 10, 11, 12, 13, 14, 17, 22};
      set_pixels(kBusyPixels, sizeof(kBusyPixels), 24, 24, 24);
    } else if (show_activity) {
      static const uint8_t kActivityPixels[] = {12};
      set_pixels(kActivityPixels, sizeof(kActivityPixels), 18, 18, 18);
    }

    if (show_card) {
      static const uint8_t kCardPixels[] = {0, 4, 20, 24};
      set_pixels(kCardPixels, sizeof(kCardPixels), 0, 24, 0);
    }
  }

  M5.Led.display();
  last_render_key = key;
  force_render = false;
}
}

static inline void led_setup() {
  if (bolty_led_internal::initialized) {
    return;
  }

  M5.begin();
  bolty_led_internal::initialized = true;
  bolty_led_internal::supported = M5.Led.isEnabled();
  if (!bolty_led_internal::supported) {
    return;
  }

  M5.Led.setBrightness(bolty_led_internal::kLedBrightness);
  bolty_led_internal::force_render = true;
  bolty_led_internal::render();
}

static inline void led_tick() {
  bolty_led_internal::render();
}

static inline void led_set_hardware_ready(bool ready) {
  bolty_led_internal::hardware_ready = ready;
  bolty_led_internal::force_render = true;
}

static inline void led_set_app_mode(uint8_t app_mode) {
  bolty_led_internal::app_mode = app_mode;
  bolty_led_internal::force_render = true;
}

static inline void led_set_job_status(uint8_t job_status) {
  bolty_led_internal::job_status = job_status;
  if (job_status == 4) {
    bolty_led_internal::success_until = millis() + bolty_led_internal::kOverlayResultMs;
  } else if (job_status == 5 || job_status == 6) {
    bolty_led_internal::error_until = millis() + bolty_led_internal::kOverlayResultMs;
  }
  bolty_led_internal::force_render = true;
}

static inline void led_set_busy(bool busy) {
  bolty_led_internal::busy = busy;
  bolty_led_internal::force_render = true;
}

static inline void led_notify_card_present() {
  bolty_led_internal::card_present_until = millis() + bolty_led_internal::kOverlayCardMs;
  bolty_led_internal::force_render = true;
}

static inline void led_notify_activity() {
  bolty_led_internal::activity_until = millis() + bolty_led_internal::kOverlayActivityMs;
  bolty_led_internal::force_render = true;
}

static inline void led_signal_result(bool success) {
  if (success) {
    bolty_led_internal::success_until = millis() + bolty_led_internal::kOverlayResultMs;
  } else {
    bolty_led_internal::error_until = millis() + bolty_led_internal::kOverlayResultMs;
  }
  bolty_led_internal::force_render = true;
}

#else

static inline void led_setup() {}
static inline void led_tick() {}
static inline void led_set_hardware_ready(bool) {}
static inline void led_set_app_mode(uint8_t) {}
static inline void led_set_job_status(uint8_t) {}
static inline void led_set_busy(bool) {}
static inline void led_notify_card_present() {}
static inline void led_notify_activity() {}
static inline void led_signal_result(bool) {}

#endif

#endif
