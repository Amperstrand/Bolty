# Bolty Deployment Guide

Quick reference for building, flashing, and updating Bolty firmware on M5Stack ATOM + MFRC522.

## Build Environments

| Environment | Mode | WiFi | Use Case |
|---|---|---|---|
| `m5stack-atom-mfrc522` | Serial headless | Off | Development, debugging |
| `m5stack-atom-mfrc522-rest` | REST HTTPS + serial | On | Production provisioning |
| `m5stack-atom-mfrc522-ota` | Serial + OTA check | On | Remote firmware updates |

## Initial Setup

### 1. WiFi Credentials

```bash
cp ota.env.example ota.env
# Edit ota.env with your WiFi SSID and password
```

`ota.env` is gitignored — credentials never enter version control.

### 2. REST TLS Certificates (REST mode only)

```bash
bash scripts/rest/generate_rest_cert.sh
```

Generates a private CA + server certificate in `scripts/rest/certs/`. The server cert is embedded into the firmware at build time. Copy the CA cert (`scripts/rest/certs/rest_ca_cert.pem`) to any host that will call the REST API.

To rotate certs: `bash scripts/rest/generate_rest_cert.sh --force`

### 3. OTA Signing Key (OTA mode only)

```bash
bash scripts/ota/generate_signing_key.sh
```

## Building and Flashing

### Serial (development)

```bash
pio run -e m5stack-atom-mfrc522 -t upload
pio device monitor
```

### REST provisioning mode

```bash
pio run -e m5stack-atom-mfrc522-rest -t upload
```

After boot, the device prints its IP over serial. The REST API is available at `https://<IP>/api/`.

### With auth tokens (REST mode)

```bash
pio run -e m5stack-atom-mfrc522-rest \
  -DREST_READ_TOKEN='"my-readonly-token"' \
  -DREST_WRITE_TOKEN='"my-readwrite-token"' \
  -t upload
```

- **Read token**: status, uid, keyver, check, ndef, job endpoints
- **Write token**: keys, url, burn, wipe endpoints
- Empty/undefined = no auth required

## mDNS Discovery

In REST mode, the device advertises itself as `bolty.local`:

```bash
ping bolty.local
curl -sk https://bolty.local/api/status
```

## REST API Reference

All endpoints are under `/api/`. TLS is required (self-signed CA).

### Read Endpoints

| Method | Path | Description |
|---|---|---|
| GET | `/api/status` | Device status (no card needed) |
| GET | `/api/uid` | Scan and return card UID (10s timeout) |
| GET | `/api/keyver` | Key versions for card on reader |
| GET | `/api/check` | Check if card is blank (zero-key auth) |
| GET | `/api/ndef` | Read NDEF message from card |
| GET | `/api/job` | Current job status |

### Write Endpoints

| Method | Path | Body | Description |
|---|---|---|---|
| POST | `/api/keys` | `{"k0":"..","k1":"..","k2":"..","k3":"..","k4":".."}` | Set 5 encryption keys (32 hex chars each) |
| POST | `/api/url` | `{"url":"https://..."}` | Set LNURL for burn |
| POST | `/api/burn` | — | Burn card with current keys + URL (30s timeout) |
| POST | `/api/wipe` | — | Wipe card back to factory state (30s timeout) |

### Example: Full provisioning cycle

```bash
# 1. Set keys
curl -sk -X POST https://bolty.local/api/keys \
  -H "Content-Type: application/json" \
  -d '{"k0":"11...11","k1":"22...22","k2":"33...33","k3":"22...22","k4":"33...33"}'

# 2. Set URL
curl -sk -X POST https://bolty.local/api/url \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com/bolt"}'

# 3. Burn (place card on reader first)
curl -sk -X POST https://bolty.local/api/burn

# 4. Verify
curl -sk https://bolty.local/api/keyver

# 5. Wipe
curl -sk -X POST https://bolty.local/api/wipe
```

## OTA Firmware Updates

### Publish new firmware

```bash
bash scripts/ota/publish.sh
```

Builds, signs, and publishes firmware to the OTA server directory.

### Start OTA server

```bash
cd scripts/ota
OTA_AUTH_TOKEN=your-token python3 serve.py --port 8765
```

### Push OTA to device

With the OTA build environment, the device checks for updates on every boot. Publish new firmware, then reboot the device (power cycle or serial `reset` command).

## E2E Tests

### Serial test

```bash
cd tests
python3 test_full_cycle.py
```

### REST test

```bash
cd tests
BOLTY_REST_URL="https://192.168.13.153/api" python3 test_full_cycle_rest.py
```

### With auth tokens

```bash
BOLTY_REST_URL="https://bolty.local/api" \
BOLTY_REST_READ_TOKEN="my-readonly-token" \
BOLTY_REST_WRITE_TOKEN="my-readwrite-token" \
python3 test_full_cycle_rest.py
```

## Serial Commands (all modes)

Type commands at 115200 baud over USB serial:

- `help` — List all commands
- `status` — Device and config status
- `uid` — Scan card UID
- `keyver` — Read key versions
- `keys K0 K1 K2 K3 K4` — Set 5 hex keys
- `url <lnurl>` — Set URL for burn
- `burn` — Burn card
- `wipe` — Wipe card
- `ndef` — Read NDEF data
- `check` — Verify card is blank

## Troubleshooting

### WiFi won't connect

Check `ota.env` has correct SSID/password. View serial output for connection details.

### REST API unreachable

- Verify device IP from serial: `status` command shows WiFi state
- Check mDNS: `ping bolty.local`
- REST mode uses `HAS_WIFI=0` internally — the `wifi` serial command is for the old web UI only

### Card not detected

- Card must be physically on the reader (MFRC522 range is ~1cm)
- REST endpoints have 10s card detection timeout
- Try `uid` via serial to confirm NFC hardware is working

### TLS certificate errors

Use `-k` / `--insecure` with curl, or pass the CA cert: `curl --cacert scripts/rest/certs/rest_ca_cert.pem`
