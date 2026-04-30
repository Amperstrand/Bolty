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

The fix lives in our GitHub fork pinned by commit hash in `Cargo.toml`.

## Forked Dependencies (GitHub, pinned by commit hash)

All external NFC/NFC-transport crates are forked under `github.com/Amperstrand` and pinned
to specific commit hashes in the workspace `Cargo.toml`. This gives us full control during
development and testing. After validation, consider upstream PRs.

| Crate | Fork | Upstream | Reason for fork |
|-------|------|----------|----------------|
| ntag424 | `Amperstrand/ntag424` | `codeberg.org/jannschu/ntag424` v0.1.0-beta1 | **Protocol bug**: LenCap=0x00 in AuthEV2 First |
| iso14443 | `Amperstrand/iso14443-rs` | `github.com/Foundation-Devices/iso14443-rs` | ESP-IDF I2C patches, PcdSession support |
| mfrc522 | `Amperstrand/mfrc522-rs` | vendored from esp32-ccid project | Timer/register patches for ESP-IDF |

### How to update a fork

1. Push changes to the fork repo on GitHub
2. Get the new commit hash: `gh api repos/Amperstrand/<repo>/commits/main --jq '.sha'`
3. Update the `rev = "..."` in `bolty-rs/Cargo.toml` `[workspace.dependencies]`
4. `cargo update -p <crate-name>` to refresh the lockfile

### Open: upstream PRs

- **ntag424**: The LenCap fix is a 1-line change. Submit to codeberg after testing NonFirst auth.
- **iso14443**: Evaluate if our patches can be upstreamed to Foundation-Devices.
- **mfrc522**: Unclear upstream origin — may need to remain a standalone fork.

## Key Constraints

- Keys must never be persisted to flash or logged
- WiFi credentials must not appear in any git commit
- Serial-driven, headless operation (no display required)
- Prefer simple test keys (1111…, 2222…, etc.) in test code
- Never blind-wipe a provisioned card — always require crypto proof first
- Build bolty-rs from `apps/bolty-esp32/` (`.cargo/config.toml` sets xtensa target)
- `cargo clean` from workspace root resets target to host arch — always build from `apps/bolty-esp32/`
