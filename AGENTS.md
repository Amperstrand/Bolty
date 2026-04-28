# Bolty — Agent & Developer Notes

## HARDWARE SAFETY: M5Atom LED Overheating ⚠️

**DO NOT drive M5Atom NeoPixel LEDs at full brightness.**

Running `setBrightness(255)` or `setAllColor(255, 255, 255)` with all 25 LEDs on causes
the M5Atom Matrix to overheat rapidly (confirmed in hardware). The device had to be
disconnected to prevent damage.

**Rules for M5Atom LED usage:**
- Max brightness: **20** (out of 255). Never exceed this.
- Never set all 25 LEDs to white or full-on simultaneously.
- Animations must be **brief flashes only** (< 300 ms per frame).
- After any animation, immediately return all LEDs to off (`setAllColor(0,0,0)`).
- The `led.h` code enforces `kMaxBrightness = 20`. Never change this value upward.

## Hardware Targets

| Target | Status | NFC | I2C Pins | Notes |
|--------|--------|-----|----------|-------|
| M5Stick-C Plus | **Primary** ✅ | MFRC522 | G32 (SDA), G33 (SCL) | Use `BOARD_M5STICK_MFRC522` |
| M5Atom Matrix | Retired ⛔ | MFRC522 | G26 (SDA), G32 (SCL) | LED safety issue — overheating |
| ESP32-DevKitC | Secondary | PN532 SPI | — | For bench testing |
| LILYGO TTGO T-Display | Legacy | PN532 SPI | — | Original hardware |

All hardware testing must use the M5Stick. Do not enable M5Atom for new work.

## Key Constraints

- Keys must never be persisted to flash or logged
- WiFi credentials must not appear in any git commit
- Serial-driven, headless operation (no display required)
- Prefer simple test keys (1111…, 2222…, etc.) in test code
- Never blind-wipe a provisioned card — always require crypto proof first
