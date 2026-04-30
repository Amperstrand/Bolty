#ifndef BOARDS_DEVKITC_SPI_H
#define BOARDS_DEVKITC_SPI_H

#define BOLTY_NFC_BACKEND_MFRC522 0
#define BOLTY_NFC_BACKEND_PN532 1
#define BOLTY_BOARD_NAME "ESP32-DevKitC V4 + Sunfounder PN532"

// PN532 V1.0 software SPI
#define PN532_SCK (19)
#define PN532_MISO (18)
#define PN532_MOSI (17)
#define PN532_SS (25)
#define PN532_IRQ (16)
#define PN532_RSTPD_N (26)
#define NFC_RESET_PIN PN532_RSTPD_N

#define HAS_DISPLAY 0
#define TFT_BL (-1)
#define HAS_BUTTONS 0
#define BUTTON_1 (-1)
#define BUTTON_2 (-1)
#define HAS_LED_MATRIX 0
#define HAS_BATTERY 0
#define ADC_EN (-1)
#define ADC_PIN (-1)

#endif
