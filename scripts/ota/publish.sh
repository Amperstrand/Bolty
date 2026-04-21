#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOLTY_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
OTA_DIR="$SCRIPT_DIR"
ENV="esp32dev-ota"
FIRMWARE_SRC="$BOLTY_DIR/.pio/build/$ENV/firmware.bin"
BUILD_METADATA="$BOLTY_DIR/include/build_metadata.h"
SIGN_SCRIPT="$OTA_DIR/ota_sign.py"
PORT="${OTA_PORT:-8765}"
HOST="${OTA_HOST:-192.168.13.218}"

echo "=== Bolty OTA Publish ==="
echo "  Bolty dir : $BOLTY_DIR"
echo "  PIO env   : $ENV"
echo ""

cd "$BOLTY_DIR"

echo "[publish] Building $ENV..."
pio run -e "$ENV"

echo "[publish] Build done."

if [[ ! -f "$FIRMWARE_SRC" ]]; then
    echo "[publish] ERROR: firmware binary not found at $FIRMWARE_SRC"
    exit 1
fi

if [[ ! -f "$SIGN_SCRIPT" ]]; then
    echo "[publish] ERROR: signing helper not found at $SIGN_SCRIPT"
    exit 1
fi

VERSION_CODE=$(grep -E '#define FW_VERSION_CODE' "$BUILD_METADATA" | grep -oE '[0-9]+')
if [[ -z "$VERSION_CODE" ]]; then
    echo "[publish] ERROR: could not read FW_VERSION_CODE from $BUILD_METADATA"
    exit 1
fi

echo "[publish] FW_VERSION_CODE = $VERSION_CODE"

FIRMWARE_NAME="firmware-${VERSION_CODE}.bin"
FIRMWARE_DEST="$OTA_DIR/$FIRMWARE_NAME"
cp "$FIRMWARE_SRC" "$FIRMWARE_DEST"
SIZE=$(wc -c < "$FIRMWARE_DEST")

MANIFEST="$OTA_DIR/manifest.json"
cat > "$MANIFEST" <<EOF
{
  "version_code": $VERSION_CODE,
  "url": "http://${HOST}:${PORT}/${FIRMWARE_NAME}",
  "size": $SIZE
}
EOF

python3 "$SIGN_SCRIPT" "$MANIFEST" "$FIRMWARE_DEST"

echo "[publish] Published:"
echo "  Firmware  : $FIRMWARE_DEST ($SIZE bytes)"
echo "  Manifest  : $MANIFEST"
echo ""
echo "[publish] Start the server:"
echo "  python3 scripts/ota/serve.py"
echo ""
echo "[publish] Or set OTA_HOST/OTA_PORT for a different server address:"
echo "  OTA_HOST=192.168.1.5 OTA_PORT=9000 bash scripts/ota/publish.sh"
