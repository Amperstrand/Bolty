#ifndef HARDWARE_CONFIG_H
#define HARDWARE_CONFIG_H

// ============================================================
// Board Selection — set via PlatformIO build_flags (-DBOARD_*)
// ============================================================
//
// Supported boards (one must be defined via build_flags):
//   BOARD_M5STICK_MFRC522       ✅ PRIMARY — M5Stick-C Plus + Unit RFID
//   BOARD_M5STACK_ATOM_MFRC522  ⚠️  M5Atom Matrix + Unit RFID (LED safety issue)
//   BOARD_DEVKITC               ESP32-DevKitC + PN532 (SPI)
//   BOARD_DEVKITC_UART          ESP32-DevKitC + PN532 (UART)
//   BOARD_TTGO_TDISPLAY         LILYGO TTGO T-Display (original hardware)
//
// Each board config lives in boards/<name>.h and defines:
//   BOLTY_NFC_BACKEND_*, MFRC522_* or PN532_* pins,
//   HAS_DISPLAY, HAS_BUTTONS, HAS_LED_MATRIX, HAS_BATTERY, etc.

#if !defined(BOARD_TTGO_TDISPLAY) && !defined(BOARD_DEVKITC) && \
    !defined(BOARD_DEVKITC_UART) && \
    !defined(BOARD_M5STACK_ATOM_MFRC522) && !defined(BOARD_M5STICK_MFRC522)
#define BOARD_TTGO_TDISPLAY
#endif

#if defined(BOARD_M5STICK_MFRC522)
#include "boards/m5stick.h"
#elif defined(BOARD_M5STACK_ATOM_MFRC522)
#include "boards/m5atom.h"
#elif defined(BOARD_DEVKITC_UART)
#include "boards/devkitc_uart.h"
#elif defined(BOARD_DEVKITC)
#include "boards/devkitc_spi.h"
#else
#include "boards/ttgo_tdisplay.h"
#endif

// LED pin (no single-LED boards use this)
#define LED_PIN (-1)

// WiFi default (overridden by build_flags -DHAS_WIFI=0 for headless)
#ifndef HAS_WIFI
#define HAS_WIFI 1
#endif

#endif // HARDWARE_CONFIG_H
