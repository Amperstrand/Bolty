#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERT_DIR="$SCRIPT_DIR/certs"
CA_KEY="$CERT_DIR/rest_ca_key.pem"
CA_CERT="$CERT_DIR/rest_ca_cert.pem"
SERVER_KEY="$CERT_DIR/rest_server_key.pem"
SERVER_CSR="$CERT_DIR/rest_server.csr"
SERVER_CERT="$CERT_DIR/rest_server_cert.pem"
SERVER_EXT="$CERT_DIR/rest_server_ext.cnf"
FORCE=0

for arg in "$@"; do
    if [[ "$arg" == "--force" ]]; then
        FORCE=1
    fi
done

mkdir -p "$CERT_DIR"

if [[ "$FORCE" != "1" ]] && [[ -e "$CA_KEY" || -e "$CA_CERT" || -e "$SERVER_KEY" || -e "$SERVER_CERT" ]]; then
    echo "[rest-tls] Refusing to overwrite existing TLS material in $CERT_DIR" >&2
    echo "[rest-tls] Re-run with --force to rotate." >&2
    exit 1
fi

rm -f "$CA_KEY" "$CA_CERT" "$CERT_DIR/rest_ca_cert.srl" "$SERVER_KEY" "$SERVER_CSR" "$SERVER_CERT" "$SERVER_EXT"

# REST server runs on the ESP32 — cert must be valid for whatever IP the device gets.
# Include common local ranges + localhost.
cat > "$SERVER_EXT" <<EOF
[v3_server]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:bolty.local,IP:127.0.0.1,IP:192.168.4.1,IP:192.168.1.1
EOF

openssl ecparam -name prime256v1 -genkey -noout -out "$CA_KEY"
openssl req -x509 -new -sha256 -key "$CA_KEY" -days 3650 -out "$CA_CERT" \
    -subj "/CN=Bolty REST Root CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash"

openssl ecparam -name prime256v1 -genkey -noout -out "$SERVER_KEY"
openssl req -new -sha256 -key "$SERVER_KEY" -out "$SERVER_CSR" -subj "/CN=Bolty REST Server"
openssl x509 -req -sha256 -in "$SERVER_CSR" -CA "$CA_CERT" -CAkey "$CA_KEY" \
    -CAcreateserial -out "$SERVER_CERT" -days 3650 -extfile "$SERVER_EXT" -extensions v3_server

chmod 600 "$CA_KEY" "$SERVER_KEY"
chmod 644 "$CA_CERT" "$SERVER_CERT"

echo "[rest-tls] Generated HTTPS REST server certificates"
echo "[rest-tls]   CA cert     : $CA_CERT"
echo "[rest-tls]   Server cert : $SERVER_CERT"
echo "[rest-tls]   Server key  : $SERVER_KEY"
echo "[rest-tls]   Client CA   : copy $CA_CERT to host to trust the device"
echo "[rest-tls] Rebuild REST firmware so include/rest_server_cert.h matches."
