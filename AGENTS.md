# Bolty — Agent & Developer Notes

## HARDWARE SAFETY: M5Atom LED Overheating ⚠️

**DO NOT drive M5Atom NeoPixel LEDs at full brightness.**

Running `setBrightness(255)` or `setAllColor(255, 255, 255) with all 25 LEDs on causes
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
| M5Atom Matrix | **Testing** 🔧 | MFRC522 | G26 (SDA), G32 (SCL) | LED safety issue; used for NFC dev |
| ESP32-DevKitC | Secondary | PN532 SPI | — | For bench testing |
| LILYGO TTGO T-Display | Legacy | PN532 SPI | — | Original hardware |

## Known Good State (proven on hardware)

- **bolty-rs**: Full burn → inspect → wipe → check cycle proven on M5Atom (ttyUSB0)
- **C++ Bolty**: Both `m5stack-atom-mfrc522` and `m5stick-mfrc522` PlatformIO envs build clean
- **Test card**: UID `041065FA967380`, NTAG 424 DNA
- **Flash command**: `espflash flash --port /dev/ttyUSB0 --chip esp32 target/xtensa-esp32-espidf/release/bolty-esp32`
- **Serial**: 115200 baud, commands end with `\n` (not just `\r`)

## ntag424 Crate Patch (CRITICAL)

The upstream `ntag424 = "0.1.0-beta1"` crate has a **protocol bug** in `AuthenticateEV2 First`:

```
# Upstream (WRONG — NTAG 424 DNA rejects this):
[0x90, 0x71, 0x00, 0x00, 0x02, key_no, 0x00, 0x00]  # LenCap=0x00

# Patched (CORRECT — matches C++ and datasheet):
[0x90, 0x71, 0x00, 0x00, 0x05, key_no, 0x03, 0x00, 0x00, 0x00, 0x00]  # LenCap=0x03
```

`LenCap=0x03` signals AES-128 key type (NT4H2421Gx §10.4.1, Table 25). The NTAG 424 DNA
rejects `LenCap=0x00` for AES-authenticated applications, returning `AuthenticationError`.

The fix lives in `bolty-rs/crates/ntag424-patch/` applied via `[patch.crates-io]` in the
workspace `Cargo.toml`.

### Open Decision: ntag424 Crate Strategy

The `ntag424` crate is `0.1.0-beta1`, has this protocol bug, and we're now carrying a fork.
Options to discuss:

1. **Fork & maintain** — publish our patched version to crates.io as `bolty-ntag424`
2. **Upstream PR** — submit fix to `codeberg.org/jannschu/ntag424`, track response
3. **Replace** — evaluate alternative NTAG 424 crates or write a minimal protocol layer
4. **Vendor** — move the crate into `vendor/` with our other vendored deps

Considerations: The crate also has `authenticate_ev2_non_first` (line 30) which sends
`Lc=0x01` with no LenCap — may need the same fix for EV2 NonFirst auth. Test before relying on it.

## Key Constraints

- Keys must never be persisted to flash or logged
- WiFi credentials must not appear in any git commit
- Serial-driven, headless operation (no display required)
- Prefer simple test keys (1111…, 2222…, etc.) in test code
- Never blind-wipe a provisioned card — always require crypto proof first
- Build bolty-rs from `apps/bolty-esp32/` (`.cargo/config.toml` sets xtensa target)
- `cargo clean` from workspace root resets target to host arch — always build from `apps/bolty-esp32/`
