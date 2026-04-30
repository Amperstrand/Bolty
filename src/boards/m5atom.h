#ifndef BOARDS_M5ATOM_H
#define BOARDS_M5ATOM_H
// ============================================================================
// M5Stack Atom Matrix + Unit RFID (MFRC522 over I2C)
// ============================================================================
//
// Hardware:
//   - ESP32-PICO-D4, 4MB flash
//   - Grove PORT.CUSTOM: Yellow=G26, White=G32
//   - Unit RFID (MFRC522) on Grove port
//   - 25x WS2812C NeoPixel on GPIO27
//   - Button on GPIO39
//   - BMI270 IMU on I2C (G21=SCL, G25=SDA, addr 0x68)
//
// ⚠️  NeoPixel SAFETY: max brightness 20/255. Never all-white.
//     See led.h for enforced limits.
// ============================================================================

// NFC backend: MFRC522 over I2C
#define BOLTY_NFC_BACKEND_MFRC522 1
#define BOLTY_NFC_BACKEND_PN532 0
#define BOLTY_BOARD_NAME "M5Stack Atom Matrix + Unit RFID"

// MFRC522 I2C on Grove port (Yellow=G26=SDA, White=G32=SCL)
#define MFRC522_SDA   (26)
#define MFRC522_SCL   (32)
#define MFRC522_I2C_ADDRESS  (0x28)
#define MFRC522_I2C_FREQUENCY (400000)
#define NFC_RESET_PIN (-1)

// M5Atom button (used for long-press WiFi reset via M5Unified)
#define M5_ATOM_BTN_PIN (39)

// No TFT display
#define HAS_DISPLAY 0
#define TFT_BL (-1)

// Buttons handled by M5Unified (M5.BtnA)
#define HAS_BUTTONS 1
#define BUTTON_1 (-1)
#define BUTTON_2 (-1)

// 5x5 NeoPixel matrix on GPIO27
#define HAS_LED_MATRIX 1

// No battery ADC
#define HAS_BATTERY 0
#define ADC_EN (-1)
#define ADC_PIN (-1)

#endif // BOARDS_M5ATOM_H
