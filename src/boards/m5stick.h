#ifndef BOARDS_M5STICK_H
#define BOARDS_M5STICK_H
// ============================================================================
// M5Stick-C Plus + Unit RFID (MFRC522 over I2C)
// ============================================================================
//
// Hardware:
//   - ESP32-PICO-D4, 4MB flash
//   - Grove port: G32 (SDA), G33 (SCL)
//   - Unit RFID (MFRC522) on Grove port
//   - ST7789V2 135x240 TFT on SPI (backlight on GPIO27)
//   - AXP192 PMU for power management
//   - Button A on GPIO37, Button B on GPIO39
//   - IMU (BMI270 or MPU6886) on internal I2C
//
// PRIMARY hardware target. Serial-driven headless mode by default.
// ============================================================================

#define BOLTY_NFC_BACKEND_MFRC522 1
#define BOLTY_NFC_BACKEND_PN532 0
#define BOLTY_BOARD_NAME "M5Stick-C Plus + Unit RFID"

// MFRC522 I2C on Grove port (G32=SDA, G33=SCL)
#define MFRC522_SDA   (32)
#define MFRC522_SCL   (33)
#define MFRC522_I2C_ADDRESS  (0x28)
#define MFRC522_I2C_FREQUENCY (400000)
#define NFC_RESET_PIN (-1)

// M5Stick buttons (not used in headless serial mode)
#define M5_ATOM_BTN_PIN (-1)

// Headless serial mode — no TFT UI
#define HAS_DISPLAY 0
#define TFT_BL (-1)

// No Button2 library — headless serial only
#define HAS_BUTTONS 0
#define BUTTON_1 (-1)
#define BUTTON_2 (-1)

// No NeoPixel matrix
#define HAS_LED_MATRIX 0

// No battery ADC (headless)
#define HAS_BATTERY 0
#define ADC_EN (-1)
#define ADC_PIN (-1)

#endif // BOARDS_M5STICK_H
