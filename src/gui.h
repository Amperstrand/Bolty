#ifndef GUI_H
#define GUI_H

#include "hardware_config.h"
#include <Arduino.h>

#if HAS_DISPLAY
  #include <TFT_eSPI.h>
#endif

#if HAS_DISPLAY
  #define APPWHITE TFT_WHITE
  #define APPBLACK TFT_BLACK
  #define APPGREEN TFT_DARKGREEN
  #define APPYELLOW TFT_YELLOW
  #define APPORANGE TFT_ORANGE
  #define APPRED TFT_RED
#else
  #define APPWHITE 0xFFFF
  #define APPBLACK 0x0000
  #define APPGREEN 0x03E0
  #define APPYELLOW 0xFFE0
  #define APPORANGE 0xFD20
  #define APPRED 0xF800
#endif

#define DEFAULT_TEXTSIZE 0

#define BTNMODE_IDLE 0
#define BTNMODE_BRIGHTNESS 1
#define BTNMODE_APP 2

struct varcollection {
  uint8_t app;
  byte tft_brightness;
  uint8_t buttonmode;
  byte evbuttons[2];
  byte appbuttons[2];
};

varcollection sharedvars = {
    .app = 0,
    .tft_brightness = 30,
    .buttonmode = BTNMODE_IDLE,
    .evbuttons = {0, 0},
    .appbuttons = {0, 0},
};

#if HAS_DISPLAY
TFT_eSPI tft = TFT_eSPI(135, 240);
#endif

#if HAS_BATTERY
int vref = 1100;
uint16_t v = 0;
static uint64_t timeStamp = 0;
#endif

void enablebrightnessctrl() { sharedvars.buttonmode = BTNMODE_BRIGHTNESS; }

uint16_t fromrgb(uint8_t r, uint8_t g, uint8_t b) {
  return ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3);
}

static inline void displayText(int col, int row, String txt) {
#if HAS_DISPLAY
  tft.fillScreen(APPWHITE);
  tft.setCursor(col * 10, row * 10);
  tft.print(txt);
#else
  Serial.println(txt);
#endif
}

static inline int displayTextCentered(int y, String txt) {
#if HAS_DISPLAY
  int16_t w = tft.textWidth(txt);
  int16_t h = tft.fontHeight();
  tft.setCursor(tft.width() / 2 - w / 2, y);
  tft.print(txt);
  return (y + h) * 1.01;
#else
  Serial.println(txt);
  return y + 21;
#endif
}

static inline int displayTextLeft(int y, String txt) {
#if HAS_DISPLAY
  int16_t h = tft.fontHeight();
  tft.setCursor(3, y);
  tft.print(txt);
  return (y + h) * 1.01;
#else
  Serial.println(txt);
  return y + 21;
#endif
}

static inline void displayMessage(String txt, uint8_t line) {
#if HAS_DISPLAY
  tft.setFreeFont(&FreeSans9pt7b);
  tft.setTextColor(APPWHITE);
  tft.fillRect(0, line, tft.width(), 23, APPBLACK);
  displayTextCentered(-3 + ((line + 1) * 21), txt);
  tft.setTextColor(APPBLACK);
#else
  Serial.println("[msg] " + txt);
#endif
}

#if HAS_BATTERY
void draw_battery(bool force_update = false) {
  if ((!force_update) && (millis() - timeStamp < 10000)) {
    return;
  }

  v = analogRead(ADC_PIN);
  timeStamp = millis();
  float battery_voltage = ((float)v / 4095.0) * 2.0 * 3.3 * (vref / 1000.0);
  String voltage = "Voltage :" + String(battery_voltage) + "V";
  Serial.println(voltage);

  float emptyvoltage = 3.2;
  if (battery_voltage < emptyvoltage) {
    emptyvoltage = battery_voltage;
  }
  float fullvoltage = 4.2 - emptyvoltage;
  int percentage = int(100. / fullvoltage * (battery_voltage - emptyvoltage));
  if (percentage > 100) {
    percentage = 100;
  }

#if HAS_DISPLAY
  uint16_t batcolor = APPGREEN;
  uint16_t txtcolor = APPWHITE;

  if (percentage < 80) {
    batcolor = APPYELLOW;
    txtcolor = APPBLACK;
  }
  if (percentage < 60) {
    batcolor = APPORANGE;
    txtcolor = APPBLACK;
  }
  if (percentage < 30) {
    batcolor = APPRED;
    txtcolor = APPWHITE;
  }

  int posx = 205;
  int posy = 15;
  int w = 30;
  int h = 10;
  uint8_t ws = int((w) / 100. * percentage);
  tft.fillRoundRect(posx, posy - h, w, h, 2, fromrgb(0x9d, 0x9f, 0x92));
  tft.fillRoundRect(posx, posy - h, ws, h, 2, batcolor);
  tft.drawRoundRect(posx, posy - h, w, h, 2, APPBLACK);
  h = 8;
  tft.setFreeFont();
  tft.setTextColor(txtcolor);
  if (battery_voltage > 4.3) {
    tft.setCursor(posx + 6, posy - 8);
    tft.print("PWR");
  } else {
    tft.setCursor(posx + 3, posy - 8);
    tft.print(String(battery_voltage));
  }
#endif
}
#else
static inline void draw_battery(bool force_update = false) {
  (void)force_update;
}
#endif

static inline void draw_wifi(bool wifi_enabled) {
#if HAS_DISPLAY
  int w = 30;
  int h = 10;
  int posx = 5;
  int posy = 15;
  tft.setFreeFont();
  if (wifi_enabled) {
    tft.fillRoundRect(posx, posy - h, w, h, 2, APPGREEN);
    tft.setTextColor(APPWHITE);
  } else {
    tft.fillRoundRect(posx, posy - h, w, h, 2, APPWHITE);
    tft.setTextColor(fromrgb(0xad, 0xaf, 0xa2));
  }
  tft.drawRoundRect(posx, posy - h, w, h, 2, APPBLACK);
  tft.setCursor(posx + 3, posy - 8);
  tft.print("WiFi");
#else
  Serial.println(wifi_enabled ? "[wifi] ON" : "[wifi] OFF");
#endif
}

static inline void screen_wait() {
#if HAS_DISPLAY
  tft.fillScreen(APPWHITE);
  tft.setFreeFont(&FreeSans9pt7b);
  displayTextCentered(75, "Please wait...");
#else
  Serial.println("Please wait...");
#endif
}

void update_screen();

#if HAS_DISPLAY
  #include <qrcode_rep.h>

bool displayQR(String input) {
  int qrSize = 10;
  int ec_lvl = 0;
  int const sizes[18][4] = {
      {17, 14, 11, 7},   {32, 26, 20, 14},  {53, 42, 32, 24},
      {78, 62, 46, 34},  {106, 84, 60, 44}, {134, 106, 74, 58},
      {154, 122, 86, 64}, {192, 152, 108, 84}, {230, 180, 130, 98},
      {271, 213, 151, 119}, {321, 251, 177, 137}, {367, 287, 203, 155},
      {425, 331, 241, 177}, {458, 362, 258, 194}, {520, 412, 292, 220},
      {586, 450, 322, 250}, {644, 504, 364, 280},
  };

  int len = input.length();
  for (int ii = 0; ii < 17; ii++) {
    qrSize = ii + 1;
    if (sizes[ii][ec_lvl] > len) {
      break;
    }
  }

  Serial.printf("len = %d, ec_lvl = %d, qrSize = %d\n", len, ec_lvl, qrSize);

  QRCode qrcode;
  uint8_t qrcodeData[qrcode_getBufferSize(qrSize)];
  qrcode_initText(&qrcode, qrcodeData, qrSize, ec_lvl, input.c_str());

  Serial.printf("saw qr mode = %d\n", qrcode.mode);

  int xoff = tft.width() / 2 - qrcode.size;
  int yoff = tft.height() / 2 - qrcode.size;
  tft.fillScreen(APPWHITE);

  for (uint8_t y = 0; y < qrcode.size; y++) {
    for (uint8_t x = 0; x < qrcode.size; x++) {
      tft.fillRect(xoff + x * 2, yoff + y * 2, 2, 2,
                   qrcode_getModule(&qrcode, x, y) ? APPBLACK : APPWHITE);
    }
  }
  delay(10000);
  return true;
}
#else
static inline bool displayQR(String input) {
  Serial.println("[qr] " + input);
  return true;
}
#endif

#if HAS_BUTTONS
  #include "Button2.h"

Button2 btn1(BUTTON_1);
Button2 btn2(BUTTON_2);

void button_loop() {
  sharedvars.evbuttons[0] = 0;
  sharedvars.evbuttons[1] = 0;
  btn1.loop();
  btn2.loop();
}

void handlebuttonevents(void *data) {
  varcollection *sharedp = (varcollection *)data;
  while (true) {
    switch (sharedp->buttonmode) {
    case BTNMODE_APP: {
      if ((sharedp->evbuttons[1] == 2) && (sharedp->evbuttons[0] == 2)) {
        break;
      }
      break;
    }
    }
    button_loop();
    delay(30);
  }
}

void button_init() {
  btn1.setReleasedHandler([](Button2 &b) {
    (void)b;
    sharedvars.evbuttons[0] = 1;
    sharedvars.appbuttons[0] = 1;
  });
  btn1.setLongClickHandler([](Button2 &b) {
    unsigned int time = b.wasPressedFor();
    if (time > 1000) {
      sharedvars.evbuttons[0] = 2;
      sharedvars.appbuttons[0] = 2;
    }
  });
  btn1.setDoubleClickHandler([](Button2 &b) {
    (void)b;
    sharedvars.evbuttons[0] = 3;
    sharedvars.appbuttons[0] = 3;
  });

  btn2.setReleasedHandler([](Button2 &b) {
    (void)b;
    sharedvars.evbuttons[1] = 1;
    sharedvars.appbuttons[1] = 1;
  });
  btn2.setLongClickHandler([](Button2 &b) {
    (void)b;
    sharedvars.appbuttons[1] = 2;
  });
  btn2.setDoubleClickHandler([](Button2 &b) {
    (void)b;
    sharedvars.appbuttons[1] = 3;
    sharedvars.evbuttons[1] = 3;
  });

  xTaskCreatePinnedToCore(handlebuttonevents, "Button Event Handler", 1000,
                          &sharedvars, 1, NULL, 0);
}
#else
static inline void button_init() {}

static inline void button_loop() {
  sharedvars.evbuttons[0] = 0;
  sharedvars.evbuttons[1] = 0;
}
#endif

#if HAS_DISPLAY
void drawscreen(void *data) {
  (void)data;
  while (true) {
    draw_battery();
    delay(1000);
  }
}

void setup_display() {
  button_init();
  tft.init();
  tft.setRotation(1);
  tft.fillScreen(APPWHITE);
  tft.setTextColor(APPBLACK);
  pinMode(TFT_BL, OUTPUT);
  ledcSetup(0, 5000, 8);
  ledcAttachPin(TFT_BL, 0);
  ledcWrite(0, sharedvars.tft_brightness);
  tft.setFreeFont(&FreeSans18pt7b);
  displayTextCentered(80, "Bolty");
  tft.setFreeFont(&FreeSans9pt7b);
  displayTextCentered(120, "Bolt Card assistant");
  enablebrightnessctrl();
}
#else
static inline void setup_display() {
  button_init();
  Serial.println("Headless mode — no display");
}
#endif

#endif
