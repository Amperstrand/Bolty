#ifndef HARDWARE_CONFIG_H
#define HARDWARE_CONFIG_H

// ============================================================
// Board Selection
// ============================================================
// Uncomment ONE of the following to select your board:
// #define BOARD_TTGO_TDISPLAY      // Default: LILYGO TTGO T-Display (original Bolty hardware)
// #define BOARD_DEVKITC            // ESP32-DevKitC V4 + Sunfounder PN532
// #define BOARD_M5STACK_ATOM_MFRC522 // M5Stack Atom Matrix + Unit RFID (MFRC522 over I2C)

#if !defined(BOARD_TTGO_TDISPLAY) && !defined(BOARD_DEVKITC) && \
    !defined(BOARD_M5STACK_ATOM_MFRC522)
#define BOARD_TTGO_TDISPLAY
#endif

#if defined(BOARD_M5STACK_ATOM_MFRC522)
#define BOLTY_NFC_BACKEND_MFRC522 1
#define BOLTY_NFC_BACKEND_PN532 0
#define BOLTY_BOARD_NAME "M5Stack Atom Matrix + Unit RFID"
#elif defined(BOARD_DEVKITC)
#define BOLTY_NFC_BACKEND_MFRC522 0
#define BOLTY_NFC_BACKEND_PN532 1
#define BOLTY_BOARD_NAME "ESP32-DevKitC V4 + Sunfounder PN532"
#else
#define BOLTY_NFC_BACKEND_MFRC522 0
#define BOLTY_NFC_BACKEND_PN532 1
#define BOLTY_BOARD_NAME "LILYGO TTGO T-Display + PN532"
#endif

// ============================================================
// NFC Pin Configuration
// ============================================================

#if BOLTY_NFC_BACKEND_MFRC522
// M5Stack Atom Matrix Grove port + Unit RFID (MFRC522 over I2C)
#define MFRC522_SDA (26)
#define MFRC522_SCL (32)
#define MFRC522_I2C_ADDRESS (0x28)
#define MFRC522_I2C_FREQUENCY (400000)
#define NFC_RESET_PIN (-1)
#elif defined(BOARD_DEVKITC)
// ESP32-DevKitC V4 + Sunfounder PN532 V1.0
#define PN532_SCK (19)
#define PN532_MISO (18)
#define PN532_MOSI (17)
#define PN532_SS (25)
#define PN532_IRQ (16)
#define PN532_RSTPD_N (26)
#define NFC_RESET_PIN PN532_RSTPD_N
#else
// LILYGO TTGO T-Display (original Bolty hardware)
#define PN532_SCK (17)
#define PN532_MISO (12)
#define PN532_MOSI (13)
#define PN532_SS (15)
#define PN532_IRQ (-1)
#define PN532_RSTPD_N (2)
#define NFC_RESET_PIN PN532_RSTPD_N
#endif

// ============================================================
// Display Pin Configuration
// ============================================================

#if defined(BOARD_DEVKITC) || defined(BOARD_M5STACK_ATOM_MFRC522)
#define HAS_DISPLAY 0
#define TFT_BL (-1)
#else
#define HAS_DISPLAY 1
#define TFT_BL (4)
#endif

// ============================================================
// Button Pin Configuration
// ============================================================

#if defined(BOARD_M5STACK_ATOM_MFRC522)
#define HAS_BUTTONS 1
#define BUTTON_1 (-1)
#define BUTTON_2 (-1)
#elif defined(BOARD_DEVKITC)
#define HAS_BUTTONS 0
#define BUTTON_1 (-1)
#define BUTTON_2 (-1)
#else
#define HAS_BUTTONS 1
#define BUTTON_1 (35)
#define BUTTON_2 (0)
#endif

// ============================================================
// LED Pin Configuration
// ============================================================

#if defined(BOARD_M5STACK_ATOM_MFRC522)
#define HAS_LED_MATRIX 1
#else
#define HAS_LED_MATRIX 0
#endif

#define LED_PIN (-1)

// ============================================================
// ADC / Battery (TTGO only)
// ============================================================

#if defined(BOARD_DEVKITC) || defined(BOARD_M5STACK_ATOM_MFRC522)
#define HAS_BATTERY 0
#define ADC_EN (-1)
#define ADC_PIN (-1)
#else
#define HAS_BATTERY 1
#define ADC_EN (14)
#define ADC_PIN (34)
#endif

// ============================================================
// WiFi Configuration
// ============================================================

#ifndef HAS_WIFI
#define HAS_WIFI 1
#endif

#endif // HARDWARE_CONFIG_H
