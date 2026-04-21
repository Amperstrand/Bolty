#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEY_DIR="$SCRIPT_DIR/keys"
PRIVATE_KEY="$KEY_DIR/ota_signing_key.pem"
PUBLIC_KEY="$KEY_DIR/ota_signing_pub.pem"

mkdir -p "$KEY_DIR"

if [[ -e "$PRIVATE_KEY" || -e "$PUBLIC_KEY" ]]; then
    echo "[keys] Refusing to overwrite existing key material in $KEY_DIR" >&2
    exit 1
fi

openssl ecparam -name prime256v1 -genkey -noout -out "$PRIVATE_KEY"
openssl ec -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"

chmod 600 "$PRIVATE_KEY"
chmod 644 "$PUBLIC_KEY"

echo "[keys] Generated:"
echo "[keys]   private: $PRIVATE_KEY"
echo "[keys]   public : $PUBLIC_KEY"
