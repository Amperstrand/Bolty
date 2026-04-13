#ifndef HARDWARE_CONFIG_H
#define HARDWARE_CONFIG_H

// ============================================================
// Board Selection
// ============================================================
// Uncomment ONE of the following to select your board:
// #define BOARD_TTGO_TDISPLAY    // Default: LILYGO TTGO T-Display (original Bolty hardware)
// #define BOARD_DEVKITC          // ESP32-DevKitC V4 + Sunfounder PN532

#ifndef BOARD_TTGO_TDISPLAY
#ifndef BOARD_DEVKITC
#define BOARD_TTGO_TDISPLAY  // Default to original Bolty hardware
#endif
#endif

// ============================================================
// NFC (PN532) Pin Configuration
// ============================================================
// Board comparison:
//
//   Function  TTGO T-Display   ESP32-DevKitC V4   Strapping Pin?
//   --------  --------------   ----------------    --------------
//   SCK       GPIO 17          GPIO 19            No
//   MISO      GPIO 12          GPIO 18            YES (flash voltage)
//   MOSI      GPIO 13          GPIO 17            No
//   CS/SS     GPIO 15          GPIO 25            YES (boot msg silence)
//   RST       GPIO 2           GPIO 26            YES (boot mode)
//   IRQ       (not used)       GPIO 16            No
//
// ESP32 strapping pin notes:
// - GPIO 12 (MISO on TTGO): Flash voltage select. LOW at boot = 1.8V flash.
//   If PN532 pulls MISO low during ESP32 boot, the chip enters 1.8V flash mode
//   and cannot boot. The TTGO board has proper pull-ups to prevent this.
//   On other boards this can cause a "brownout detector" or bricked flash.
//   Our DevKitC uses GPIO 18 instead to avoid this entirely.
// - GPIO 15 (CS on TTGO): Boot message silence. Low risk.
// - GPIO 2 (RST on TTGO): Boot mode select with GPIO 0. Low risk in practice.
//   Also the ESP32 built-in LED on most dev boards.
//
// Both pin sets work on their respective boards. The DevKitC pins are
// "safer" in general (no strapping pins), but the TTGO pins are fine
// on the TTGO T-Display because the PCB is designed around them.

#ifdef BOARD_DEVKITC
  // ESP32-DevKitC V4 + Sunfounder PN532 V1.0
  #define PN532_SCK    (19)
  #define PN532_MISO   (18)
  #define PN532_MOSI   (17)
  #define PN532_SS     (25)
  #define PN532_IRQ    (16)   // Not used by Bolty, but available
  #define PN532_RSTPD_N (26)
#else
  // LILYGO TTGO T-Display (original Bolty hardware)
  #define PN532_SCK    (17)
  #define PN532_MISO   (12)
  #define PN532_MOSI   (13)
  #define PN532_SS     (15)
  #define PN532_IRQ    (-1)   // Not used by Bolty
  #define PN532_RSTPD_N (2)
#endif

// ============================================================
// Display Pin Configuration
// ============================================================
// TTGO T-Display has a built-in ST7789 TFT (135x240) connected via SPI.
// TFT pins are configured in TFT_eSPI's User_Setup.h, NOT here.
// The only pin we configure here is the backlight.

#ifdef BOARD_DEVKITC
  // No display — headless mode
  // These defines exist but the display code will be stubbed out
  // (handled in a future commit: headless mode)
  #define HAS_DISPLAY   0
  #define TFT_BL        (-1)  // No backlight pin
#else
  // TTGO T-Display built-in ST7789
  #define HAS_DISPLAY   1
  #define TFT_BL        (4)   // Display backlight control pin
#endif

// ============================================================
// Button Pin Configuration
// ============================================================

#ifdef BOARD_DEVKITC
  // DevKitC has no dedicated buttons (GPIO 0 is BOOT button but it's a strapping pin)
  #define HAS_BUTTONS   0
  #define BUTTON_1      (-1)
  #define BUTTON_2      (-1)
#else
  // TTGO T-Display onboard buttons
  #define HAS_BUTTONS   1
  #define BUTTON_1      (35)
  #define BUTTON_2      (0)
#endif

// ============================================================
// LED Pin Configuration
// ============================================================

#ifdef BOARD_DEVKITC
  #define LED_PIN       (2)   // ESP32 built-in LED
#else
  #define LED_PIN       (-1)  // TTGO uses TFT backlight as indicator
#endif

// ============================================================
// ADC / Battery (TTGO only)
// ============================================================

#ifdef BOARD_DEVKITC
  #define HAS_BATTERY  0
  #define ADC_EN       (-1)
  #define ADC_PIN      (-1)
#else
  #define HAS_BATTERY  1
  #define ADC_EN       (14)
  #define ADC_PIN      (34)
#endif

// ============================================================
// WiFi Configuration
// ============================================================
// WiFi is always available (ESP32 built-in). This flag controls
// whether the WiFi stack is initialized at boot.
// Set to 0 for headless/serial-only mode.

#ifndef HAS_WIFI
  #define HAS_WIFI     1  // Default: WiFi enabled (original Bolty behavior)
#endif

#endif // HARDWARE_CONFIG_H
