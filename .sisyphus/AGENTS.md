# NTAG424 DNA Bolt Card Provisioner — ESP32 + PN532

Reference document for adapting the Bolty firmware to run on ESP32-DevKitC V4 with a Sunfounder PN532 NFC module in headless serial-only mode. This covers hardware, the NTAG424 DNA protocol, official app behavior, our implementation state, and what remains to be done.

Upstream: https://github.com/bitcoin-ring/Bolty

---

## 1. Hardware

### Active Board

- **Board**: ESP32-DevKitC V4 (WROOM-32U)
- **USB**: Silicon Labs CP2102
- **Serial**: `/dev/serial/by-id/usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0`
- **PlatformIO target**: `esp32dev`

### NFC Module (CURRENT — Sunfounder PN532 V1.0)

- **Board**: Sunfounder PN532 NFC Module V1.0 (blue PCB, credit-card sized)
- **Antenna**: PCB trace antenna (no external antenna, UFL connector present but unused)
- **Features**: SET0/SET1 DIP switches, labeled "J2" near UFL connector
- **Firmware**: v1.6 (confirmed via getFirmwareVersion)

### NFC Module (BACKUP — Elechouse PN532 V3)

- **Board**: Red Elechouse PN532 V3
- **Status**: No pin headers soldered yet
- **Note**: Better antenna design than Sunfounder. Reserve if Sunfounder fails.

### Wiring (FINAL, VERIFIED)

```
Blue PN532 -> ESP32-DevKitC V4:
  BROWN  (5V)     -> Left pin 19
  BLACK  (GND)    -> Left pin 14
  WHITE  (RST)    -> Left pin 10 (GPIO26)
  RED    (CS)     -> Left pin 9  (GPIO25)
  GRAY   (IRQ)    -> Right pin 12 (GPIO16)
  ORANGE (MOSI)   -> Right pin 11 (GPIO17)
  YELLOW (MISO)   -> Right pin 9  (GPIO18)
  GREEN  (SCK)    -> Right pin 8  (GPIO19)
DIP: SW1=OFF(down) SW2=ON(up) = SPI mode
```

### Pin Assignments in Code

Defined in `Bolty/src/hardware_config.h` when `BOARD_DEVKITC` is set:

```cpp
#define PN532_SCK    (19)
#define PN532_MISO   (18)
#define PN532_MOSI   (17)
#define PN532_SS     (25)
#define PN532_IRQ    (16)
#define PN532_RSTPD_N (26)
#define LED_PIN      (-1)  // DevKitC V4 has no user-controllable LED
#define HAS_DISPLAY   0    // Headless — no TFT
#define HAS_BUTTONS   0    // Headless — no physical buttons
#define HAS_WIFI      0    // Headless — serial only
```

Strapping pin notes (from hardware_config.h):

| Function | DevKitC V4 Pin | Strapping Pin? |
|----------|---------------|----------------|
| SCK      | GPIO 19       | No             |
| MISO     | GPIO 18       | No             |
| MOSI     | GPIO 17       | No             |
| CS/SS    | GPIO 25       | Yes (boot msg silence) |
| RST      | GPIO 26       | Yes (boot mode) |
| IRQ      | GPIO 16       | No             |

The DevKitC pins avoid GPIO 12 (flash voltage select), which the TTGO T-Display uses for MISO. On boards without proper pull-ups, GPIO 12 pulled low during ESP32 boot causes 1.8V flash mode and a bricked boot.

### Power

- PN532 powered from ESP32 5V pin (USB power, ~500mA)
- PN532 draws 60-150mA during RF transmission
- USB power is sufficient but marginal — adding a 47-100uF capacitor across PN532 VCC/GND can help with RF transmission current spikes

---

## 2. Project Structure

```
pn532/
├── .sisyphus/
│   └── AGENTS.md                          # This file
├── Bolty/                                # Adapted Bolty firmware
│   ├── platformio.ini                    # Headless build config
│   └── src/
│       ├── bolty.ino                     # Main firmware (~1850 lines)
│       ├── bolt.h                        # BoltDevice class + provisioning logic
│       ├── gui.h                         # Display/UI stubs (no-op in headless)
│       └── hardware_config.h             # Pin definitions per board
├── Adafruit-PN532-NTAG424/              # Forked NTAG424 library
├── ndef_reader/                          # Standalone NDEF reader
├── test_full_cycle.py                    # Full provisioning cycle test (ALL 7 PHASES PASS)
├── test_zerokey_cycle.py                 # Zero-key automated test (all pass)
├── test_statickey_cycle.py               # Static-key test (superseded by test_full_cycle.py)
├── test_bolty_auto.py                    # Earlier test (superseded)
├── test_bolty_burn.py                    # Interactive burn test
└── README.md                             # OUTDATED
```

Key source files:

- **bolty.ino**: Serial command handler, key version checking, error code mapping, safety/test commands (check, dummyburn, reset), pre-burn guard logic
- **bolt.h**: `BoltDevice` class with `burn()` and `wipe()` methods. ChangeKey order is k1 -> k2 -> k3 -> k4 -> k0 (key 0 last). After burn, re-authenticates with new k0 to verify
- **gui.h**: Color and state definitions. In headless mode (`HAS_DISPLAY=0`), display calls become serial prints or no-ops
- **hardware_config.h**: Board presets (DevKitC vs TTGO). DevKitC disables display, buttons, LED, WiFi

---

## 3. Build & Flash

```bash
cd Bolty
pio run                # build
pio run -t upload      # flash to ESP32
# Monitor (pio device monitor doesn't work headless on this machine):
python3 -c "
import serial, time, sys
ser = serial.Serial('/dev/serial/by-id/usb-Silicon_Labs_CP2102_USB_to_UART_Bridge_Controller_0001-if00-port0', 115200, timeout=1)
time.sleep(4)
try:
    while True:
        data = ser.read(ser.in_waiting or 1)
        if data: sys.stdout.write(data.decode('utf-8', errors='replace')); sys.stdout.flush()
except KeyboardInterrupt: pass
ser.close()
"
```

Build flags in platformio.ini: `-DBOARD_DEVKITC -DHAS_WIFI=0 -DUSER_SETUP_LOADED`

Optional libraries (TFT_eSPI, Button2, ESPAsyncWebServer, ArduinoJson, ESP32-targz, QRCode) are listed in `lib_deps` but excluded at build time via `lib_ignore`.

---

## 4. Bolty Serial Commands (Headless Mode)

```
help              Show command list
uid               Scan card, print UID, check if NTAG424
status            Print current config (keys, URL, WiFi)
keys <k0> <k1> <k2> <k3> <k4>  Set 5 keys (32-char hex each, space-separated)
url <lnurl>        Set LNURL for burn command
burn              Provision card: write NDEF + change keys (tap card, uses k0)
wipe              Wipe card: zero keys + format NDEF (tap card, uses k0)
ndef              Read NDEF message without auth (tap card). Paginated 48-byte reads, retry loop (100ms/15s)
auth              Test k0 authentication (tap card)
ver               GetVersion + isNTAG424 check (tap card)
keyver            Read key versions (blank/provisioned check, tap card)
--- Safety / Testing ---
check             Auth with factory zero keys (confirm card is blank)
dummyburn         Burn with zero keys + dummy URL (test write path)
reset             Wipe from zero keys to zero keys (test wipe path)
```

### Command Details

| Command | Requires Tap | Auth Needed | Description |
|---------|-------------|-------------|-------------|
| `help` | No | No | Prints the command list |
| `uid` | Yes | No | Scans card, prints hex UID, reports whether card is NTAG424 DNA. 2-second debounce between reads |
| `status` | No | No | Prints NFC hardware ready state, last scanned UID, current job status, configured keys and URL |
| `keys <k0> <k1> <k2> <k3> <k4>` | No | No | Sets the 5 keys in `mBoltConfig`. Each key is 32 hex chars (16 bytes). `k0` is the auth key, `k1` is the PICC key, `k2` is the MAC key, `k3` = `k1`, `k4` = `k2` |
| `url <lnurl>` | No | No | Sets the LNURL string for the next burn command |
| `burn` | Yes | Yes (k0) | Full provisioning: writes NDEF with the LNURL, configures SDM file settings, changes all 5 keys. See pre-burn guard below |
| `wipe` | Yes | Yes (k0) | Resets card: zeroes all keys, disables SDM/mirroring, formats NDEF. See pre-wipe guard below |
| `ndef` | Yes | No | Reads NDEF via ISO-7816 SELECT AID + SELECT FILE + ReadBinary with paginated 48-byte reads. Retry loop with 100ms poll, 15s timeout. Prints hex and ASCII. Phones can also read Bolt Card URLs without knowing card keys |
| `auth` | Yes | Yes (k0) | Attempts authentication with configured k0. Prints result and session state. 15-second timeout |
| `ver` | Yes | No | Reads GetVersion from card. Reports whether card is NTAG424 DNA |
| `keyver` | Yes | No | Reads version byte for all 5 keys via GetKeyVersion APDU. Reports whether card is BLANK (all 0x00) or PROVISIONED. 15-second timeout |
| `check` | Yes | Yes (zero keys) | Authenticates with factory zero keys to confirm card is blank. 15-second timeout |
| `dummyburn` | Yes | Yes (zero keys) | Burns with all-zero current keys, all-zero new keys, and dummy URL `https://dummy.test`. Tests the write path without risking real keys. 30-second timeout |
| `reset` | Yes | Yes (zero keys) | Wipes from zero keys to zero keys. Used after dummyburn to return card to a known state. 30-second timeout |

### Pre-Burn / Pre-Wipe Guard Behavior (Bug G — FIXED in `34f6f14`)

Both `burn` and `wipe` have guard checks that run **inside** the card detection loop, ensuring the card actually being operated on is checked.

**Implementation:**
- `ntag424_getKeyVersion()` free function moved to `bolt.h` (before `class BoltDevice`) for shared access by `burn()` and `wipe()`
- `JOBSTATUS_GUARD_REJECT` (6) added as new status constant with text "guard rejected - card not in expected state"

**Burn guard** (inside `burn()` after card detected + NTAG424 confirmed):
1. Reads key 1 version via `ntag424_getKeyVersion(nfc, 1)`
2. If version != 0x00 → card already provisioned → prints ABORT, sets `JOBSTATUS_GUARD_REJECT`, returns
3. If version == 0x00 → factory keys → prints "Pre-burn check OK", proceeds

**Wipe guard** (inside `wipe()` after card detected + NTAG424 confirmed):
1. Reads key 1 version via `ntag424_getKeyVersion(nfc, 1)`
2. If version == 0x00 → card already has factory keys → prints ABORT, sets `JOBSTATUS_GUARD_REJECT`, returns
3. If version != 0x00 → card was provisioned → prints "Pre-wipe check OK" with version hex, proceeds

**Serial command handlers** (`bolty.ino`):
- Both `burn` and `wipe` handlers check for `JOBSTATUS_GUARD_REJECT` after the do-while loop
- On guard rejection: prints "[burn|wipe] ABORTED - guard rejected (card not in expected state)", blinks LED 5 times, returns

**Why inside the loop (Bug G fix):** The original 500ms pre-flight ran once before the main retry loop. If no card was present in that window, the guard silently passed and the card that eventually arrived was never checked. Moving guards inside the loop ensures the actual card being operated on is validated.

### Burn Verification

After a successful burn, the firmware reads back NDEF and reports whether the readback succeeded and the byte count.

---

## 5. NTAG424 DNA Protocol Reference

### Key Roles

The NTAG424 DNA uses 5 AES-128 keys. The Bolt Card ecosystem uses 3 unique keys with k3 and k4 as copies:

| Key | Purpose | LNbits Server | Bolty |
|-----|---------|---------------|-------|
| k0 | App Master Key (authentication) | Stored in DB | Configured via `keys` command |
| k1 | PICC Key (encrypts UID+counter in SUN) | Stored in DB | Configured via `keys` command |
| k2 | MAC Key (AES-CMAC for SDM verification) | Stored in DB | Configured via `keys` command |
| k3 | Reserved (copy of k1) | NOT stored (set k3=k1) | Configured via `keys` command |
| k4 | Reserved (copy of k2) | NOT stored (set k4=k2) | Configured via `keys` command |

**AppMasterKey = Key 0x00 (AppKey00), NOT key 14.** This is confirmed by NXP AN12196 Rev 2.0 (March 2025), Section 6.1: *"Prerequisites: Active Authentication with the AppMasterKey (AppKey00)"*. The manufacturer documentation refers to the master key as AppKey00 throughout. There is no "key 14" in the AN12196 specification. The concept of authenticating with key 14 for recovery does not come from NXP documentation.

LNbits generates keys client-side using `crypto.getRandomValues()` (browser CSPRNG). The server stores all keys in its database so it can always re-provision a card.

### GetKeyVersion APDU

Discovered and verified on hardware. Reads the version byte for a given key slot.

- **APDU**: `90 64 00 00 01 {keyNo} 00`
- **CommMode**: `NTAG424_COMM_MODE_PLAIN` (no authentication required)
- **CRITICAL prerequisite**: Must call `ISOSelectFileByDFN({0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01})` first. Without this file selection, the card returns garbage data.
- **Response**: `{version_byte, 0x91, 0x00}` (3 bytes, SW1=0x91, SW2=0x00 on success)
- **Implementation in bolt.h**: `ntag424_getKeyVersion()` free function (before `class BoltDevice`, moved from bolty.ino in `34f6f14`)

**Key version semantics (NXP AN12195, official Android app source, updated after `ba21c78` wipe fix):**

| State | Key Version Byte | Meaning |
|-------|-----------------|---------|
| Factory blank card | `0x00` | Keys are all zeros, card has never been provisioned |
| After `burn` | `0x01` | Key has been changed (provisioned with static keys) |
| After `wipe` (current firmware) | `0x00` | Wipe now explicitly passes `keyversion=0x00`, restoring factory-identical version byte |

The key version is a **per-key byte** stored on the card (keys 0-4 each have their own version). It is set by the `ChangeKey` APDU and stored verbatim — **the card does NOT auto-increment it**. The version byte is whatever the sender puts in the APDU payload.

**Before `273f0ba` (library fix):** The library hardcoded `0x01` in every `ntag424_ChangeKey()` call. This meant wipe also set versions to `0x01`, making wiped cards distinguishable from factory-blank by version alone.

**After `273f0ba` + `ba21c78`:** `ntag424_ChangeKey()` accepts explicit `keyversion`. Burn uses `0x01`, wipe uses `0x00`. A wiped card now has key versions `0x00` AND key values `0x00` — identical to a factory card. The `check` command (zero-key auth) still works as the definitive confirmation.

The official Android app (`boltcard/bolt-nfc-android-app`, `Ntag424.js`) passes keyVersion as a parameter to `changeKey()`, giving the caller control over the value. It uses this to detect provisioning state: `keyVersion('01') != '00'` means "already provisioned."

Practical implications for our firmware (current):
- Factory-fresh card: all key versions at `0x00`
- After `burn`: all key versions at `0x01`
- After `wipe`: all key versions at `0x00` (same as factory)
- `check` command (zero-key auth) is the definitive blank-card test
- Pre-burn guard (checks version == `0x00`) now correctly allows re-burning a wiped card

### ChangeKey Protocol

Key change order (from official Android app, implemented in bolt.h):

1. **k1** (key 4-1=3... wait, the loop iterates `i` from 0 to 4 and calls `ChangeKey(key_cur[4-i], key_new[4-i], 4-i)`, so the actual order is: key 4, key 3, key 2, key 1, key 0)
2. Corrected order: **k4 -> k3 -> k2 -> k1 -> k0** (key 0 is changed LAST to maintain authentication)

Key 0 ChangeKey specifics:
- Sends `NewKey + KeyVersion` only (no XOR, no CRC)
- This is different from keys 1-4

Keys 1-4 ChangeKey specifics:
- Sends `XOR(oldKey, newKey) + KeyVersion + CRC32(newKey)`
- The XOR means the card computes `newKey = received XOR oldKey`
- Key version is now a parameter to `ntag424_ChangeKey()` (default `0x01` in .h declaration). Burn passes explicit `0x01`, wipe passes explicit `0x00`.

The atomic nature of ChangeKey is important: each individual key change either succeeds completely or fails completely. There is no partial key update.

### SDM File Settings

From the official Android app's `setBoltCardFileSettings` function. Configured during burn:

```
40 00 E0 C1 FF 12 {piccOffset:3bytes LE} {macOffset:3bytes LE} {macOffset:3bytes LE}
```

Byte breakdown:

| Byte(s) | Value | Meaning |
|---------|-------|---------|
| 0 | `0x40` | File Option: SDM enabled + Mirroring enabled |
| 1-2 | `0x00 0xE0` | Access rights (read/write permission flags) |
| 3 | `0xC1` | Options: UID mirror (0x80) + SDMReadCtr (0x40) + ASCII encoding (0x01) |
| 4-5 | `0xFF 0x12` | SDM access rights |
| 6-8 | piccOffset | Offset in NDEF where PICC data (encrypted UID + counter) starts (3 bytes, little-endian) |
| 9-11 | macOffset | Offset in NDEF where MAC starts (3 bytes, little-endian) |
| 12-14 | macOffset | Same macOffset repeated (3 bytes, little-endian) |

The piccOffset and macOffset are computed dynamically based on the LNURL length:
- `piccDataOffset = lnurl.length() + 10`
- `sdmMacOffset = lnurl.length() + 45`

For wipe, file settings are set to `{0x40, 0xE0, 0xEE, 0x01, 0xFF, 0xFF}` (6 bytes — matches official Android app's `resetFileSettings()`). The `0x40` byte keeps the SDM option bit set, `0x01` sets SDMOptions, and `0xFF, 0xFF` disables SDM access rights.

### Error Codes

From the official Android app. Mapped in bolty.ino as `ntag424_error_name()` (line ~1266):

| Status Word | Name | Meaning |
|-------------|------|---------|
| `91 00` | OK | Success |
| `91 AE` | AUTHENTICATION_ERROR | Wrong key or authentication failed |
| `91 AD` | AUTHENTICATION_DELAY | SeqFailCtr triggered — 50+ consecutive failed auth attempts, card is delaying responses (NXP AN12196 §6.4) |
| `91 40` | NO_SUCH_KEY | Invalid key number specified (NOT AUTHENTICATION_DELAY — this was a misidentification from earlier sessions, corrected via Arduino MFRC522_NTAG424DNA.h and Flipper Zero nxp_native_command.h) |
| `91 BE` | BOUNDARY_ERROR | Address out of valid range |
| `91 EE` | MEMORY_ERROR | Memory operation failed |
| `91 1E` | INTEGRITY_ERROR | Data integrity check failed (CRC, MAC) |
| `91 7E` | LENGTH_ERROR | Wrong data length for command |
| `91 9D` | PERMISSION_DENIED | Insufficient access rights |
| `91 CA` | COMMAND_ABORTED | Command was aborted |
| `91 9E` | PARAMETER_ERROR | Invalid parameter in command |
| `91 F0` | FILE_NOT_FOUND | DESFire-level file not found (distinct from ISO `6A 82`) |
| `69 82` | SECURITY_STATUS_NOT_SATISFIED | Command requires authentication but none active |
| `69 85` | CONDITIONS_NOT_SATISFIED | Pre-conditions for command not met |
| `69 88` | REF_DATA_INVALID | Referenced data (key) is invalid |
| `6A 82` | FILE_NOT_FOUND | File ID does not exist |
| `6A 86` | INCORRECT_P1_P2 | Invalid P1/P2 parameters |

**Error code 91 40 note:** AN12196 does NOT define error codes (those are in the NTAG 424 DNA data sheet, doc.no. 4654). Our identification of 91 40 = NO_SUCH_KEY comes from the Arduino library and Flipper Zero firmware. We got 91 40 when attempting to authenticate with key number 14, which strongly suggests the card rejected the key NUMBER itself (14 is not a valid application key slot), not the key VALUE.

### Failed Authentication Counter (NXP AN12196 §6.4)

Each application key has its own instance set of three counters:

| Counter | Size | Default | Behavior |
|---------|------|---------|----------|
| **TotFailCtr** | 2 bytes | 0 | +1 per failed auth. -TotFailCtrDecr (default 10) per successful auth. When TotFailCtrLimit (1000) reached → **key permanently locked** |
| **SeqFailCtr** | 1 byte | 0 | +1 per consecutive failed auth. At 50 → responses delayed (91 AD). Delay increases gradually up to 255. **Successful auth resets to 0.** |
| **SpentTimeCtr** | 2 bytes | 0 | Tracks accumulated delay time caused by SeqFailCtr |

**Key quotes from AN12196:**
- *"By default after 50 consecutive failed authentication attempts NTAG 424 DNA starts to introduce a delay into its response (SW code response of 91AD)."*
- *"When changing a KeyID.AppKey with Cmd.ChangeKey, the related instance set of these three counters is reset to their default values at delivery."*
- *"Originality keys do not support the failed authentication counter feature."*

**How to reset the delay:**
1. Successfully authenticate with the key (resets SeqFailCtr to 0)
2. Change the key with Cmd.ChangeKey (resets all three counters to defaults)

**What this means for our bricked card:** The SeqFailCtr delay is temporary and self-healing — if we could authenticate with the correct key, it would reset. But our key 0 is corrupted (bug #3 wrote encrypted-then-decrypted garbage instead of the intended key), so we can't authenticate. The TotFailCtr hard limit of 1000 means after enough failed attempts, the key is permanently locked regardless.

### Bricking and Recovery

**Confirmed from NXP AN12196 Rev 2.0 (March 2025):**

- **NO factory reset exists.** AN12196 contains zero mentions of factory reset, card recovery, or any backdoor mechanism. There is no documented way to restore a card to factory state once keys are changed.
- **AppMasterKey = AppKey00 (key 0x00), NOT key 14.** The "key 14 recovery" concept is not supported by NXP documentation. AN12196 refers to the master key as "AppMasterKey (AppKey00)" throughout. Our attempt to authenticate with key number 14 returned 91 40 (NO_SUCH_KEY), confirming key 14 is not a valid application key slot on NTAG 424 DNA.
- **No "key 14" or "0x0E" exists in AN12196.** The document only shows examples using keys 0x00, 0x01, 0x02, 0x03. The data sheet (doc.no. 4654) would have the authoritative key number definitions, but AN12196's silence on key 14 combined with the 91 40 response strongly suggests it doesn't exist as an application key.
- **Primary bricking vector:** losing k0 (the authentication key). Without k0, you cannot authenticate, cannot run ChangeKey, cannot wipe.
- **Partial failure recovery:** if a burn or wipe is interrupted partway through ChangeKey, recovery depends on which keys were changed. Since Bolty changes k0 LAST, if the operation fails before k0 is changed, the card is still accessible with the old k0. If it fails after k0 is changed but before the re-authentication verify step, the new k0 still works because ChangeKey is atomic per key.
- **ChangeKey is atomic at the individual key level.** Each key change either fully succeeds or fully fails. There is no state where a key is half-changed.
- **TotFailCtr hard limit:** After 1000 total failed authentication attempts (across all time, not just consecutive), the key is **permanently** locked. This is different from SeqFailCtr which is temporary.
- **Detection strategy:** try authenticating with known keys, then check key versions with GetKeyVersion. If auth fails with all known keys, the card is bricked.

**Assessment of our bricked card (UID `04:33:65:FA:96:73:80`):**
- Keys 0-4 were corrupted by bug #3 during Bolty provisioning
- Bug #3 caused `AES_DECRYPT()` instead of `AES_ENCRYPT()` in ChangeKey, so the card stored deterministic garbage (a function of the intended key, session IV, and the card's RndA — but NOT random)
- The corrupted key values are unknown because RndA was not logged (NTAG424DEBUG was disabled during Bolty provisioning)
- SeqFailCtr was triggered from multiple failed auth attempts in subsequent sessions → 91 AD response
- Key 14 authentication attempt returned 91 40 (NO_SUCH_KEY) → key 14 is not a valid recovery path
- **Card is effectively permanently bricked** — no documented recovery mechanism exists in NXP AN12196

### NDEF Reading

Verified on hardware. NTAG424 DNA allows reading NDEF without authentication.

- `ntag424_ISOReadFile()` handles file selection internally (selects NDEF DFN `D2 76 00 00 85 01 01`, then file `E1 04`, then reads in 32-byte chunks)
- Returns byte count on success, 0 on failure
- Phones read Bolt Card URLs without knowing card keys — this is by design
- The standalone `ndef_reader/` project demonstrates this with minimal code (143 lines)

### ISO-7816 ReadBinary (ISOReadBinary)

Added to library as `ntag424_ISOReadBinary()`. Proper Case 2 APDU for reading files.

**Why this was needed (Bug 3 / Case 2 APDU):**
The library's `ntag424_apdu_send()` always prepends an `Lc=0` byte to the APDU, turning the 5-byte Case 2 APDU (`CLA INS P1 P2 Le`) into an invalid 6-byte hybrid. The NTAG424 rejects this with error `67 00` (Wrong Length). This is a fundamental APDU structural issue — Case 2 APDUs must NOT contain an Lc byte.

**APDU format (Case 2):**
- `00 B0 {P1} {P2} {Le}` — 5 bytes, no Lc
- P1P2 = file offset (big-endian)
- Le = expected response length

**Implementation:**
```cpp
uint8_t ntag424_ISOReadBinary(uint16_t offset, uint8_t le,
                               uint8_t *response, uint16_t response_bufsize);
```

- Constructs APDU directly (bypasses `ntag424_apdu_send`)
- Uses `uint16_t response_bufsize` to avoid uint8_t overflow (sizeof buffer > 255)
- Caps `read_len` at `sizeof(pn532_packetbuffer)` (64 bytes) to prevent overflow
- Returns card_resp_len (including SW1/SW2), or 0 on error
- Card response length derived from PN532 LEN field: `pn532_packetbuffer[3] - 3`

**Ref:** Android `Ntag424.js` `isoReadBinary()` (lines 716-745), iOS `readNDEFURL()`

### Paginated NDEF Reads

For NDEF payloads > ~54 bytes, single ReadBinary cannot fit the response in PN532's 64-byte buffer. Reads must be paginated:

1. SELECT AID (`D2760000850101`)
2. SELECT FILE (`E104`)
3. ReadBinary offset=0, Le=3 → get NLEN (2 bytes big-endian)
4. Loop: ReadBinary offset=2+total_read, Le=min(remaining, 48) until all bytes read

48-byte page size chosen to stay safely within PN532's 64-byte `pn532_packetbuffer` (64 - 8 header - 2 SW = 54 max, 48 for safety margin). This matches the library's own `ISOReadFile` pagination pattern.

**NDEF content after SDM provisioning:**
```
D1 01 4F 55 04  [NDEF record header: TNF=1 (well-known), type="U", ID=4 (https://)]
example.com/bolt?p=4EB4543E7C16C44955F011A4438DDE37&c=13414D13C710D411
```
- `p=` parameter: 32 hex chars (16 bytes) — AES-CBC encrypted PICC data (UID + read counter) using k1
- `c=` parameter: 16 hex chars (8 bytes) — AES-CMAC using k2
- Total NDEF message: ~83 bytes for `https://example.com/bolt` URL

---

## 6. Official Bolt Card App Research

### Android App (boltcard/bolt-nfc-android-app)

React Native. Open source.

**Pre-burn checks:**
- Reads key version for key 1 (`keyVersion('01')`)
- If version != `0x00`, card is detected as already provisioned and burn is blocked

**Post-burn verification:**
- Reads back NDEF message
- Re-authenticates with new k0
- Tests that the URL is readable
- Tests PICC decryption with k1 and AES-CMAC verification with k2

**Pre-wipe checks:**
- Reads key version for key 1
- If version == `0x00`, reports "already reset!" and blocks wipe

**Other features:**
- Random UID support (irreversible privacy feature, writes random UID to card)
- Wipe JSON format: `{"version": 1, "action": "wipe", "k0": "...", "k1": "...", ...}`

### Cross-Platform App (boltcard/bolt-card-programmer)

React Native/Expo. Open source. v0.5.1. Active development.

- 3,704 lines TypeScript/JavaScript
- Contains `NTag424.tsx` (814 lines) with full protocol implementation
- Supersedes the Android-only app
- Same protocol: pre-burn version check, ChangeKey order, SDM file settings, post-burn verification

### iOS App ("Boltcard NFC Programmer")

- CLOSED SOURCE
- App Store ID: 6450968873
- Same developer: Ones and Zeros Technology Limited
- Implements the same protocol

### LNbits boltcard Extension (lnbits/boltcards)

Python/FastAPI. Open source.

**Key generation:**
- Keys are generated CLIENT-SIDE via `crypto.getRandomValues()` (browser CSPRNG)
- Only 3 unique keys: k3 = copy of k1, k4 = copy of k2
- Server stores all 5 key slots in the database — can always re-provision a card

**OTP rotation:**
- Each SUN authentication request burns (consumes) the current OTP
- Server generates a new OTP after each use
- Counter replay protection prevents reusing old OTPs

**SUN verification flow:**
1. Phone reads NDEF URL (no auth needed)
2. Phone taps card, card encrypts UID + counter with k1 (AES-CBC), appends CMAC with k2
3. Server decrypts with k1, verifies CMAC with k2, checks counter is greater than last seen
4. If valid, server processes the payment and generates new OTP

---

## 7. Hardware Test Results

### Cards

| UID | State | Notes |
|-----|-------|-------|
| `04:06:60:FA:96:73:80` | Blank (wiped, zero keys, ver=0x01) | Full cycle test card. Phone test PASSED — NFC URL with SDM parameters readable on phone. Used for all automated testing. |
| `04:25:60:7A:8F:69:80` | Provisioned | Provisioned with unknown keys via LNbits boltcardpoc |
| `04:33:65:FA:96:73:80` | Bricked (permanently) | Corrupted keys from library bug #3 (setkey_enc vs setkey_dec). No recovery path — confirmed from NXP AN12196: no factory reset, AppMasterKey=key0 not key14, 91 40 on key 14 attempt confirms key 14 doesn't exist as valid slot |

### Zero-Key Cycle Test (PASS)

Full cycle on card `04:06:60:FA:96:73:80`:

```
check     -> SUCCESS (factory zero keys confirmed)
dummyburn -> SUCCESS (zero keys, dummy URL written)
check     -> SUCCESS (zero keys still work — ChangeKey with zeros preserves zero keys)
reset     -> SUCCESS (wiped from zero keys to zero keys)
check     -> SUCCESS (back to factory state)
```

All commands succeeded. The burn->verify readback also confirmed NDEF was written correctly.

### Key Version After Reset

After running `reset`, `keyver` shows all key versions as `0x01`, not `0x00`. This is expected behavior — `ChangeKey` sets the version byte to `0x01` (hardcoded in the library) even when the new key is all zeros. The card stores whatever version byte the APDU sends; it does not auto-increment.

This means:
- Factory blank card: all versions `0x00`
- After our `reset` (pre-T2): all versions `0x01` (but key VALUES are still zero, so `check` auth succeeds)
- After our `wipe` (post-T2 with `keyversion=0x00`): all versions `0x00` — identical to factory blank
- The pre-burn guard (checks version == `0x00`) now correctly allows re-burning a wiped card

### Pre-Burn Guard Flaw (Bug G — FIXED)

The 500ms pre-flight window in `burn` and `wipe` was too short. The guard ran once with `readPassiveTargetID(..., 500)`. If no card was present in that 500ms window, the guard silently passed without performing any check, and the main loop proceeded to wait for a card with a 30-second timeout. The card that eventually arrived was never checked.

**Fix (commit `34f6f14`):** Moved the guard logic inside the main do-while loop so it runs against the card that is actually about to be operated on. See Section 4 (Pre-Burn / Pre-Wipe Guard Behavior) for implementation details.

### Full Provisioning Cycle Test (PASS)

Test script: `test_full_cycle.py` — fully automated, no human interaction needed (card stays on reader).

**All 7 phases pass on card `04:06:60:FA:96:73:80`:**

| Phase | Description | Result |
|-------|-------------|--------|
| 1 | Detect state (keyver + zero-key auth tiebreaker) | Correctly identified wiped state |
| 2 | Ensure blank (wipe if needed) | Skipped — already blank |
| 3 | Burn (NDEF + SDM + 5 key changes + post-burn verify) | NLEN=83 |
| 4 | Verify provisioned (all 5 key versions) | All versions = 0x01 |
| 5 | Read NDEF (paginated, 2 pages: 48+35) | 83 bytes, URL with SDM params |
| 6 | Wipe (auth with static keys, change back to zeros) | |
| 7 | Verify blank (key versions 0x01, zero-key auth succeeds) | |

**State detection logic:** Key versions alone cannot distinguish wiped-from-zeros (versions=0x01, keys=zeros) from provisioned (versions=0x01, keys=static). The test uses `check` command (zero-key auth attempt) as tiebreaker: if auth succeeds, card has zero keys (blank). If auth fails, card has non-zero keys (provisioned).

**Static test keys used:**
```
K0 = "11111111111111111111111111111111"  (auth key)
K1 = "22222222222222222222222222222222"  (PICC / SDM file read key)
K2 = "33333333333333333333333333333333"  (MAC key)
K3 = K1, K4 = K2 (LNbits convention)
URL = "https://example.com/bolt"
```

---

## 8. Library Details

### Adafruit-PN532-NTAG424 (Fork)

- **Local path**: `/home/ubuntu/src/pn532/Adafruit-PN532-NTAG424/`
- **Remote**: `git@github.com:Amperstrand/Adafruit-PN532-NTAG424.git`
- **Branch**: `fix/3-setkey-enc-spi` (active hardware branch)
- **HEAD**: `273f0ba` (`feat: add keyVersion parameter to ntag424_ChangeKey (default 0x01)`)
- **NTAG424DEBUG**: disabled in source (line 75 of .cpp, also commented out in bolt.h)
- **Constructor**: `Adafruit_PN532(clk, miso, mosi, ss)` — 4 args, no RST pin
- **No patches needed** — stock upstream libraries work on ESP32 with software SPI

#### `ntag424_ChangeKey` API Change (commit `273f0ba`)

Signature changed to accept an explicit `keyversion` parameter:

```cpp
// Old (hardcoded 0x01):
uint8_t ntag424_ChangeKey(uint8_t *oldkey, uint8_t *newkey, uint8_t keynumber);

// New (explicit, default 0x01):
uint8_t ntag424_ChangeKey(uint8_t *oldkey, uint8_t *newkey,
                          uint8_t keynumber, uint8_t keyversion = 0x01);
```

- **Burn** passes `keyversion=0x01` explicitly
- **Wipe** passes `keyversion=0x00` — so after wipe, key versions return to `0x00` (indistinguishable from factory blank)
- This matches the official Android app's behavior (passes keyVersion as caller-controlled parameter)

### Dependencies

- **Adafruit BusIO** @ ^1.17.0 (stock, unpatched)
- **Arduino_CRC32** @ ^1.0.0 (required by NTAG424 library)
- **Adafruit PN532** included transitively via NTAG424 library

### PN532 Frame Parsing

From hardware debugging. Understanding this is necessary for interpreting raw SPI traffic:

- `ntag424_apdu_send()` response parsing: `response_length = pn532_packetbuffer[3] - 3`, data starts at offset 8

**Bug fix (SPI read length):** `ntag424_apdu_send()` originally used `readdata(pn532_packetbuffer, response_le)` which often read too few bytes (e.g., 30) to capture the full PN532 frame including CMAC. Fixed to `readdata(pn532_packetbuffer, sizeof(pn532_packetbuffer))` — always reads 64 bytes. PN532 zero-pads beyond the actual frame, so this is safe.
- PN532 frame structure: `00 00 FF LEN LCS TFI CMD STATUS [card_data...]`
  - `00 00 FF`: preamble + start code
  - `LEN`: payload length (TFI + CMD + STATUS + data)
  - `LCS`: length checksum (LEN + LCS should equal 0x00)
  - `TFI`: frame identifier (0xD5 for host-to-PN532 response, 0xD4 for PN532-to-host)
  - `CMD`: command code echoed back
  - `STATUS`: PN532 status byte
  - `[card_data...]`: actual card response data

### Issues Filed on Fork (17 open)

See full audit below. Key issue for our work:
- **Issue #20**: `beginTransaction()` vs `beginTransactionWithAssertingCS()` — the real SPI fix

---

## 9. Adafruit-PN532-NTAG424 Library Audit

### Repository

- **Upstream**: Adafruit/Adafruit-PN532-NTAG424
- **Fork with issues**: Amperstrand/Adafruit-PN532-NTAG424
- **Local clone**: `/home/ubuntu/src/pn532/Adafruit-PN532-NTAG424/`

### Issues Filed (17 open, 1 retracted)

**P0 (3)**: #1 MAC counter, #2 GetVersion VendorID overwrite, #3 setkey_dec for encryption
**P1 (5)**: #5 malloc null checks, #6 weak random, #7 IV buffer overflow, #8 aescmac.h header guard, #17 PrintHex duplicate
**P2 (5)**: #9 VLAs, #10 unconditional Serial.print, #11 cla/ins API, #12 auth state check, #18 ReadData bypass
**P3 (3)**: #13 zero sensitive data, #14 ReadSig crash, #16 session state
**META (2)**: #19 ESP32 SPI full-duplex bug, #21 Bug #3 key corruption during Bolty provisioning
**CLOSED**: #4 rotl direction — false positive, library is correct per NXP spec

### Host-Machine Proofs (5 issues)

Per-issue git clones in `/tmp/issue-N/`, each with 2 commits (proof program + fix):

| Issue | Clone | Proof Type | Branch Pushed |
|-------|-------|-----------|---------------|
| #3 setkey_dec | `/tmp/issue-3/` (deleted, on remote) | C + mbedtls, key schedule detection | Yes |
| #7 IV overflow | `/tmp/issue-7/` | C + ASan, 32 bytes into 16-byte buffer | Yes |
| #6 weak random | `/tmp/issue-6/` | C, Arduino LCG reproducibility | Yes |
| #8 aescmac.h | `/tmp/issue-8/` | Shell script, 5 sub-checks | Yes |
| #17 PrintHex dup | `/tmp/issue-17/` | Shell script, duplicate symbol grep | Yes |

### Hardware Fix Branch

**`fix/3-setkey-enc-spi`** — combines fix #3 with the ESP32 SPI workaround. This is the branch needed for all hardware testing and the card management tool. Committed and pushed. Clean working tree.

Contains:
1. `pn532_spi_full_duplex()` — standalone ESP32 full-duplex using `dev->write_and_read()` (Adafruit_SPIDevice method, works for both hardware and software SPI)
2. ESP32-specific paths in `readack()`, `isready()`, `readdata()` — bypass buggy `write_then_read()`
3. `setkey_dec` to `setkey_enc` in `ntag424_encrypt()` — fix issue #3
4. SPI speed 500kHz to 100kHz — stability for Sunfounder PN524

**SPI fix root cause (discovered this session):** The original `pn532_spi_full_duplex()` used `SPI.transferBytes()` (hardware SPI), but the 4-arg software SPI constructor sets `_spi=nullptr`, so hardware SPI is never initialized. The correct approach (matching Bolty) uses `Adafruit_SPIDevice::write_and_read()` which works for both hardware and software SPI via the `transfer()` method.

### Fix Branches

All fix branches pushed to remote Amperstrand fork. Each has proof output posted as issue comments. DO NOT delete `/tmp/issue-N/` clones — they contain the fix branches.

| Branch | Issues Fixed | Status |
|--------|-------------|--------|
| `fix/3-setkey-enc-spi` | #3 + #19 (SPI) | Committed, pushed, hardware-ready |
| `fix/batch-trivial` | #2, #5, #9, #10, #12, #14 | Committed, pushed |
| `fix/3-setkey-enc` | #3 (proof only) | Pushed |
| `fix/6-esp-random` | #6 | Pushed |
| `fix/7-iv-overflow` | #7 | Pushed |
| `fix/8-aescmac-header` | #8 | Pushed |
| `fix/17-printhex-dup` | #17 | Pushed |

### Remaining Library Work

1. Hardware fulltest — card management tool at `/tmp/ntag424-test/` is built against `fix/3-setkey-enc-spi`. User needs to disconnect/reconnect SPI wires, power cycle, then place card, open serial, type `reset` then `fulltest`, paste output.
2. Post hardware proof to GitHub issues #3 and #21
3. Merge proven fixes into master
4. Medium fixes remaining: #1 (MAC counter), #11 (cla/ins API refactor), #18 (ReadData bypass)

---

## 10. Bugs Found in Bolty (Upstream)

| Bug | Location | Status |
|-----|----------|--------|
| A: Boot auto-advance to BOLTBURN | `bolty.ino` line ~936 | Fixed (headless mode stays in APP_KEYSETUP) |
| B: burn/wipe false SUCCESS | `bolt.h` burn() ~line 338, wipe() ~line 438 | Fixed (early return on auth 1 failure) |
| C: GetVersion second frame fails silently | NTAG424 library `GetVersion()` | Known, not fixed (HWType corruption causes isNTAG424 to return false) |
| D: isNTAG424() resets session | NTAG424 library line ~2597 | Known, not fixed (polling loop now disabled in headless) |
| E: Polling loop races with serial commands | `bolty.ino` `loop()` / `app_stateengine()` | Fixed (polling loop disabled entirely in headless) |
| F: LED assumed on GPIO2 | `hardware_config.h` | Fixed (DevKitC V4 has no user-controllable LED, LED_PIN set to -1) |
| G: Pre-burn guard design flaw | `bolty.ino` burn() ~line 1458, wipe() ~line 1518 | **FIXED** (`34f6f14`). Guards moved inside card detection loop. Now checks the actual card about to be operated on. Burn rejects if key 1 version != 0x00 (already provisioned). Wipe rejects if key 1 version == 0x00 (factory keys, nothing to wipe). Added JOBSTATUS_GUARD_REJECT (6) status code. |
| H: `ndef` command single-poll failure | `bolty.ino` ndef handler | Fixed. After burn, `readPassiveTargetID` with 2000ms timeout fails to re-enumerate card. Fixed with retry loop (100ms per attempt, 15s overall) |
| I: Post-burn NDEF verification fails with `69 82` | `bolty.ino` burn() post-burn verify | Fixed. After auth/key change, ISO app selection state is lost. Fixed by adding SELECT AID + SELECT E104 before ReadBinary |

---

## 11. Branch History

Branch: `feat/headless-esp32-devkitc`

```
34f6f14  feat: add pre-burn/pre-wipe guards inside card detection loop
b884c83  fix: add missing NTAG424 error codes to error mapping
ba21c78  fix: correct wipe file settings and pass explicit keyVersion
90ddfa4  docs: add test scripts, AGENTS.md reference, and .gitignore
92a0885  feat: paginated NDEF reads, post-burn verify, and debug flag
3921ecb  feat: add keyver command, error mapping, and post-burn NDEF verification
1f227a1  build: set upload port to CP2102 USB-UART bridge
25800a6  feat: add check/dummyburn/reset safety commands for zero-key testing
```

Library branch `fix/3-setkey-enc-spi`:

```
273f0ba  feat: add keyVersion parameter to ntag424_ChangeKey (default 0x01)
c8550f4  fix: add ISOReadBinary, fix GetVersion multi-frame, fix apdu_send SPI read
a4b1db7  fix: use write_and_read for ESP32 SPI full-duplex (issue #19)
```

Working tree: **CLEAN** — All changes committed. Commits `ba21c78`, `b884c83`, `34f6f14` were added by a follow-up session on 2026-04-14 and are **not yet flashed to ESP32**. Rebuild and reflash before testing guard or wipe-keyversion behavior:

```bash
cd /home/ubuntu/src/pn532/Bolty
rm -rf .pio/libdeps   # pick up library changes
pio run -t upload
```

---

## 12. Current Phase

**Phase A**: COMPLETE — Hardware bring-up and card detection confirmed.
- PN532 SPI communication working
- NTAG424 DNA card UID reading confirmed
- Serial output working at 115200 baud

**Phase B**: COMPLETE — Adapt Bolty firmware for headless DevKitC + PN532.
- Bolty adapted on branch `feat/headless-esp32-devkitc`
- Builds and flashes successfully
- PN532 init, card detection, serial commands all verified
- Polling loop disabled in headless mode (loop() only handles serial commands)
- LED disabled (DevKitC V4 has no user-controllable LED)
- NTAG424DEBUG disabled in both fork source and libdeps cache
- SPI resolution: stock upstream libraries work, no patches needed. Issue #20 filed.

**Phase C**: COMPLETE — NDEF READ WORKING.
- Can read Bolt Card NDEF messages without authentication
- Standalone ndef_reader project also verified
- Phones read Bolt Card URLs without knowing card keys

**Phase 1 (Safety Hardening)**: COMPLETE.
- Features added: check, dummyburn, reset commands, pre-burn/pre-wipe guard, keyver command, GetKeyVersion APDU, error code mapping
- Zero-key cycle test passed on hardware
- Committed as `3921ecb`

**Phase 2 (Full Provisioning Cycle)**: COMPLETE — **Phone test PASSED on 2026-04-14.**
- Full burn→verify→ndef read→wipe→verify cycle working end-to-end
- Phone successfully read NFC URL with SDM parameters (`?p=...&c=...`) from provisioned card
- Static test keys (1111.../2222.../3333...)
- Automated test: test_full_cycle.py — all 7 phases pass
- Library fixes: ISOReadBinary, GetVersion rewrite, apdu_send SPI read, uint16_t bufsize, read_len cap, keyVersion parameter
- Firmware fixes: ndef retry loop, paginated reads, post-burn verify SELECT AID, wipe file settings, pre-burn/pre-wipe guards
- Card state detection: key version + zero-key auth tiebreaker (with new firmware: wipe returns versions to 0x00 so version alone is sufficient)

---

## 13. PN532 Reliability — Known RF Field Stuck State

### Issue

**GitHub issue**: [Amperstrand/Bolty#7](https://github.com/Amperstrand/Bolty/issues/7) — "PN532 RF field becomes unresponsive after prolonged idle — needs hardware reset to recover"

After the ESP32+PN532 has been running idle for some time (observed between sessions, possibly hours), the PN532 stops detecting cards. `readPassiveTargetID()` returns failure consistently even with a card physically on the reader. The PN532 still responds to `getFirmwareVersion()` over SPI — only the RF subsystem is stuck.

This is a **known PN532 hardware/firmware characteristic**, confirmed by multiple open-source projects (ESPEasy, RIOT-OS, ESPHome, libnfc) that implement recovery mechanisms for exactly this behavior.

### Detection

The stuck state is detectable because:
- `getFirmwareVersion()` succeeds (pure SPI, no RF) → PN532 chip is alive
- `readPassiveTargetID()` fails consistently (requires RF field) → RF subsystem is stuck
- `status` reports `NFC HW: ready` because the init check only calls `getFirmwareVersion()`

### Fix

A PN532 hardware reset + re-init cycle fixes it: `nfc->reset()` → delay → `nfc->wakeup()` → `nfc->getFirmwareVersion()` → `nfc->SAMConfig()`. This is what we currently do manually via DTR/RTS toggle when the stuck state is detected.

### What to watch for (reproduction)

We have NOT reliably reproduced the stuck state. If it happens again, note:
1. How long was the device idle before the stuck state?
2. Was there a card on the reader the entire time?
3. Did `getFirmwareVersion()` return a valid version? (It should — SPI stays alive)
4. How many consecutive `readPassiveTargetID()` failures before you gave up?
5. Did `nfc_stop()` → delay → `nfc_start()` → `nfc->begin()` fix it? Or did you need a full ESP32 reboot?

### Not the same as intermittent scan failures

Stress testing showed ~50% `readPassiveTargetID` failure rate with 2.2-second polling intervals — but this is a serial timing artifact (the `scanUID()` 2-second debounce vs 2.2s poll cycle), NOT the RF-field stuck state. The stuck state is **100% persistent failure** — every single scan fails, not intermittent. If you see intermittent failures, it's timing. If you see 100% persistent failure with card on reader, it's the stuck state.

### Current code gaps

- **No watchdog/health-check logic exists** in the firmware
- **`nfc_stop()`/`nfc_start()` only used for deep sleep** (bolty.ino line 618), never for recovery
- **`setPassiveActivationRetries()` exists in library but is never called** — could configure `InListPassiveTarget` retry behavior
- **`scanUID()` returns false with no recovery** — no re-init attempt after failures
- **Library `reset()` timing is minimal**: LOW → 1ms → HIGH → 2ms. RIOT-OS uses 400ms LOW for reliability.

### Recommended implementation (tracked in issue #7)

1. **Boot reset**: Toggle RSTPD_N LOW for 100ms+ before `nfc->begin()` in setup()
2. **Pre-scan health check**: If no successful scan in >60s, verify PN532 health before next operation
3. **Error counting**: Track consecutive `readPassiveTargetID()` failures. After 5+, trigger `pn532_reinit()`
4. **`pn532_reinit()` function**: `reset()` → delay → `wakeup()` → `getFirmwareVersion()` → `SAMConfig()`

### Build cache caveat

**PlatformIO caches library builds in `.pio/build/esp32dev/libeac/`**. When the local library changes, PlatformIO may not recompile it (it only recompiles the main sketch). After library changes, manually purge: `rm -rf .pio/build/esp32dev/libeac/` before rebuilding. This caused a real false-negative during testing — the old ChangeKey code (checking `result[0:1]`) was still running from cache despite source changes.

---

## 14. Remaining Work

1. ~~Create clean commits~~ — DONE (library `c8550f4`, firmware `92a0885` + `90ddfa4`)
2. ~~Phone test~~ — DONE. NFC URL with SDM parameters readable on phone. Card wiped back to blank after test.
3. ~~Feature parity with Android app~~ — DONE (2026-04-14). 5 tasks completed: keyVersion param (T1), wipe fileSettings + keyVersion args (T2), pre-burn/pre-wipe guards (T3), 4 missing error codes (T4), 6 GitHub issues filed (T5). Commits: library `273f0ba`, firmware `ba21c78` + `b884c83` + `34f6f14`. **Not yet hardware-tested** — flash and test before using guards or wipe keyVersion in production.
4. ~~Refactor both repos~~ — DONE (2026-04-14). Library: extracted ChangeKey helpers, fixed FULL-mode response parsing (issue #23), DRY refactor for GetCardUID/GetTTStatus/ISOSelect/FormatNDEF, gated debug prints. Bolty: extracted BoltDevice helpers, centralized NTAG424 constants, simplified convertCharToHex, fixed uninitialized success accumulator, fixed post-auth key index, static boltstatustext. Commits: library `5349624` + `4c03141`, Bolty `471c9ae` + `1c2d9c2`. All pushed. Issues #22 and #23 closed with detailed comments.
5. **PN532 reliability** (issue #7) — Implement boot reset, health check, and error counting with auto-recovery. See Section 13 for details.
6. **Phase 3: LNbits integration** — import card credentials JSON, SUN verification
7. **Phase 4: WiFi mode** — ESPAsyncWebServer, remote provisioning
8. **Phase 5: Advanced features** — random UID, SUN verification (AES-CBC decrypt with k1, AES-CMAC verify with k2, counter replay protection)
9. **Upstream library fixes** — merge proven fixes into master. Address remaining issues (#1 MAC counter, #11 cla/ins API, #18 ReadData bypass)

---

## 15. NXP Manufacturer Documentation

### AN12196 — NTAG 424 DNA Features and Hints (Rev 2.0, 4 March 2025)

- **Doc number**: 507220
- **URL**: https://www.nxp.com/docs/en/application-note/AN12196.pdf
- **Local copy**: `/home/ubuntu/.local/share/opencode/tool-output/tool_d888d938400104LzHMf9CpFKcu` (JSON with extracted text)
- **Extracted text**: `/tmp/an12196_clean.txt` (92K chars)
- **Nature**: Supplementary to the data sheet. Covers personalization workflow, SDM, SSM, special features. Does NOT define error codes, key number ranges, or command specifications — those are in the data sheet.
- **Status**: READ and analyzed. Key findings incorporated into Sections 5 (Key Roles, Error Codes, Failed Auth Counter, Bricking and Recovery) above.

**Key findings from AN12196:**
1. AppMasterKey = AppKey00 (key 0x00), NOT key 14. No "key 14" mentioned anywhere in the document.
2. SetConfiguration command (enables RandomID, configures fail counters, enables LRP) requires authentication with AppKey00.
3. Failed authentication counter mechanism fully documented (Section 6.4) — see Error Codes section above.
4. ChangeKey examples show keys 0x00 and 0x02. Document recommends configuring "all Application Keys" during personalization.
5. No factory reset, no recovery mode, no backdoor mechanism documented.
6. Originality keys (PICC keys, 4 keys from NXP factory) are separate from Application Keys and cannot be changed.

### NTAG 424 DNA Data Sheet (NOT YET READ)

- **Doc number**: 4654 (reference [1] in AN12196)
- **URL**: https://www.nxp.com/docs/en/data-sheet/NTAG424DNA.pdf (presumed)
- **Contents**: Authoritative definitions of key numbers, error codes, command APDU formats, memory layout
- **Why needed**: AN12196 is supplementary — the data sheet defines what key numbers exist (0-4? 0-14? 0-15?), what each error code means, and the exact APDU formats for AUTHENTICATE and ChangeKey including valid key number ranges. This would definitively answer whether key 14 exists and what 91 40 means.

---

## 16. Constraints

- "ideally i dont want to do any hardware wiring changes"
- "if we can postpone wifi i would prefer headless mode for now"
- "i want nice clean commits eventually"
- "Keep it headless and serial-driven."
- "Keep the code simple and robust."
- "Prefer the fastest working path over elegance."
- "i dont have something to connect to the ufl connector" (no external antenna)
- When building for ESP32 with NTAG424 library, always use `PN532_MIFARE_ISO14443A` as cardbaudrate
- Software SPI constructor is 4 args (no RST pin): `Adafruit_PN532(clk, miso, mosi, ss)`
- NTAG424 NDEF reading does NOT require authentication — `ntag424_ISOReadFile()` handles it
- NTAG424 writing/provisioning DOES require k0 authentication
- Card UID `04 25 60 7A 8F 69 80` is provisioned with unknown keys (LNbits boltcardpoc)
- Card UID `04 33 65 FA 96 73 80` is bricked (corrupted keys from bug #3) — confirmed permanently bricked from NXP AN12196 analysis
- ⛔ NEVER loop AUTH commands without a hard attempt limit (max 5 per key per session) — SeqFailCtr triggers at 50 consecutive failures, TotFailCtr permanently locks at 1000 total
- ⛔ NEVER call `ChangeKey`/`WriteData` with unfixed library (bug #3 corrupts keys)
- "i would rather you use z.ai web search and zread mcp to read and understand how it works as manufacturer documentation"
- AppMasterKey = key 0x00 per NXP AN12196 — do NOT assume key 14 exists as a recovery mechanism
