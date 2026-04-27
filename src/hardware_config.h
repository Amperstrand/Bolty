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
#elif defined(BOARD_DEVKITC_UART)
#define BOLTY_NFC_BACKEND_MFRC522 0
#define BOLTY_NFC_BACKEND_PN532_UART 1
#define BOLTY_NFC_BACKEND_PN532 0
#define BOLTY_BOARD_NAME "ESP32-DevKitC V4 + PN532 (UART)"
#elif defined(BOARD_DEVKITC)
#define BOLTY_NFC_BACKEND_MFRC522 0
#define BOLTY_NFC_BACKEND_PN532_UART 0
#define BOLTY_NFC_BACKEND_PN532 1
#define BOLTY_BOARD_NAME "ESP32-DevKitC V4 + Sunfounder PN532"
#else
#define BOLTY_NFC_BACKEND_MFRC522 0
#define BOLTY_NFC_BACKEND_PN532_UART 0
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
#define M5_ATOM_BTN_PIN (39)
#elif BOLTY_NFC_BACKEND_PN532_UART
// ESP32-DevKitC V4 + PN532 via UART (HSU) — 4 wires only
//
//   PN532     Wire      ESP32 GPIO   Function
//   ─────     ────      ──────────   ────────
//   VCC       Brown     5V or 3V3    Power
//   GND       Black     GND          Ground
//   TX        Gray      GPIO 16      ESP32 RX1 (PN532 TX -> ESP32 RX)
//   RX        Purple    GPIO 17      ESP32 TX1 (PN532 RX <- ESP32 TX)
//   RST       Green     GPIO 26      Reset (optional)
//
// DIP switches: SW1=H SW2=L for UART mode (check your board silkscreen)
//
#define PN532_UART_RX (16)
#define PN532_UART_TX (17)
#define PN532_RSTPD_N (26)
#define NFC_RESET_PIN PN532_RSTPD_N
#elif defined(BOARD_DEVKITC)
// ESP32-DevKitC V4 + PN532 V1.0 (software SPI via 4-pin constructor)
//
// PN532 header pin order (left to right, silk-screen side up):
//   SCK  MISO  MOSI  NSS  IRQ  RST  GND  5V
//
// Wire colors (reading from 5V pin toward SCK):
//   Brown  Black  White  Gray  Red  Orange  Yellow  Green
//
// Pin mapping:
//
//   PN532     Wire      ESP32 GPIO   Function
//   ─────     ────      ──────────   ────────
//   5V        Brown     5V           Power
//   GND       Black     GND          Ground
//   RST       White     GPIO 26      Reset (active low)
//   IRQ       Gray      GPIO 16      Interrupt (optional)
//   NSS/CS    Red       GPIO 25      Chip Select
//   MOSI      Orange    GPIO 17      SPI Data Out
//   MISO      Yellow    GPIO 18      SPI Data In
//   SCK       Green     GPIO 19      SPI Clock (software)
//
// Notes:
//   - Uses software bit-bang SPI at 100 kHz (Adafruit 4-pin constructor).
//   - GPIOs 17/18/19 are physically adjacent on DevKitC headers.
//   - GPIO 25/26 are adjacent on the other side of the header.
//   - For future hardware SPI upgrade (VSPI IOMUX, 500 kHz), use:
//       SCK=GPIO18, MISO=GPIO19, MOSI=GPIO23, CS=GPIO5
//     with Adafruit_PN532(ss, &SPI) constructor.
//   - Avoid HSPI IOMUX (GPIO 12 is a strapping pin — boot risk).
//
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

#if defined(BOARD_DEVKITC) || defined(BOARD_DEVKITC_UART) || defined(BOARD_M5STACK_ATOM_MFRC522)
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
#elif defined(BOARD_DEVKITC) || defined(BOARD_DEVKITC_UART)
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

#if defined(BOARD_DEVKITC) || defined(BOARD_DEVKITC_UART) || defined(BOARD_M5STACK_ATOM_MFRC522)
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
