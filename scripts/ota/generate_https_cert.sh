#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BOLTY_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
CERT_DIR="$SCRIPT_DIR/certs"
ENV_FILE="$BOLTY_DIR/ota.env"
CA_KEY="$CERT_DIR/ota_ca_key.pem"
CA_CERT="$CERT_DIR/ota_ca_cert.pem"
SERVER_KEY="$CERT_DIR/ota_server_key.pem"
SERVER_CSR="$CERT_DIR/ota_server.csr"
SERVER_CERT="$CERT_DIR/ota_server_cert.pem"
SERVER_EXT="$CERT_DIR/ota_server_ext.cnf"
FORCE=0
HOST=""

for arg in "$@"; do
    if [[ "$arg" == "--force" ]]; then
        FORCE=1
    elif [[ -z "$HOST" ]]; then
        HOST="$arg"
    else
        echo "[tls] Unknown argument: $arg" >&2
        exit 1
    fi
done

if [[ -z "$HOST" && -f "$ENV_FILE" ]]; then
    HOST="$(grep '^OTA_HOST=' "$ENV_FILE" | cut -d= -f2-)"
fi

if [[ -z "$HOST" ]]; then
    HOST="192.168.13.218"
fi

mkdir -p "$CERT_DIR"

if [[ "$FORCE" != "1" ]] && [[ -e "$CA_KEY" || -e "$CA_CERT" || -e "$SERVER_KEY" || -e "$SERVER_CERT" ]]; then
    echo "[tls] Refusing to overwrite existing TLS material in $CERT_DIR" >&2
    echo "[tls] Re-run with --force to rotate the CA/server certificate." >&2
    exit 1
fi

rm -f "$CA_KEY" "$CA_CERT" "$CERT_DIR/ota_ca_cert.srl" "$SERVER_KEY" "$SERVER_CSR" "$SERVER_CERT" "$SERVER_EXT"

if [[ "$HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    SAN_MAIN="IP:${HOST}"
else
    SAN_MAIN="DNS:${HOST}"
fi

cat > "$SERVER_EXT" <<EOF
[v3_server]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = ${SAN_MAIN},DNS:localhost,IP:127.0.0.1
EOF

openssl ecparam -name prime256v1 -genkey -noout -out "$CA_KEY"
openssl req -x509 -new -sha256 -key "$CA_KEY" -days 3650 -out "$CA_CERT" \
    -subj "/CN=Bolty OTA Root CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"

openssl ecparam -name prime256v1 -genkey -noout -out "$SERVER_KEY"
openssl req -new -sha256 -key "$SERVER_KEY" -out "$SERVER_CSR" -subj "/CN=Bolty OTA Server"
openssl x509 -req -sha256 -in "$SERVER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" \
    -CAcreateserial -out "$SERVER_CERT" -days 3650 -extfile "$SERVER_EXT" -extensions v3_server

chmod 600 "$CA_KEY" "$SERVER_KEY"
chmod 644 "$CA_CERT" "$SERVER_CERT"

echo "[tls] Generated HTTPS OTA certificates for host: $HOST"
echo "[tls]   CA cert     : $CA_CERT"
echo "[tls]   Server cert : $SERVER_CERT"
echo "[tls]   Server key  : $SERVER_KEY"
echo "[tls] Rebuild OTA firmware so include/ota_ca_cert.h matches the CA cert."
