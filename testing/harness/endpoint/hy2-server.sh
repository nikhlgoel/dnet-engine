#!/bin/bash
# Profile B (Hysteria 2) server for SPIKE-R4 (T018, partial).
#
# - Generates, once, a self-signed ECDSA P-256 certificate and two random secrets, persisted
#   under $HY2_STATE so restarts keep the same identity. TEST KEYS ONLY: the state directory is
#   gitignored and must never hold real credentials.
#   The certificate is ECDSA, never Ed25519: the client keeps Chrome QUIC mimicry on, Chrome
#   does not advertise Ed25519 signatures, and the handshake would fail against such a
#   certificate (the same constraint binds the provisioning bootstrap, T093).
# - Writes a primary-core server configuration: one `hysteria2` inbound with Salamander
#   obfuscation, an auth password and an obfuscation password that DIFFER (CC-10), and the
#   certificate. Congestion control is left at the default, so the server follows the client
#   (BBR when the client sends no bandwidth).
# - Validates that configuration with the core's own `check` before starting anything.
# - Puts the HTTP origin on the same TEST-NET-3 address the AmneziaWG server uses. It is
#   deliberately NOT an RFC1918 address: the client's built-in bypass rules send RFC1918 direct,
#   which would route around the tunnel under test.
# - Writes $HY2_STATE/../hy2-client.json: everything the Windows spike runner needs. The runner
#   refuses unknown fields, so a change here must be made there too.
#
# Knobs, so the same script can be exercised without Docker (all have container defaults):
#   HY2_STATE        state directory                       (/opt/state/hy2)
#   HY2_BIN          the primary core                      (primary-core)
#   HY2_PORT         UDP listen port                       (44443)
#   HY2_LISTEN       listen address                        (::)
#   HY2_SERVER_NAME  certificate name, sent as SNI         (hy2.harness.test)
#   HY2_ORIGIN_ADDR  origin address added on lo            (203.0.113.80)
#   --config-only    write and check the files, then exit; start nothing, touch no interface
#
# Run under Git Bash on Windows (to test without Docker), export MSYS_NO_PATHCONV=1 first: MSYS
# otherwise rewrites the `/CN=...` argument to openssl as if it were a file path.
set -euo pipefail

STATE="${HY2_STATE:-/opt/state/hy2}"
BIN="${HY2_BIN:-primary-core}"
PORT="${HY2_PORT:-44443}"
LISTEN="${HY2_LISTEN:-::}"
SERVER_NAME="${HY2_SERVER_NAME:-hy2.harness.test}"
ORIGIN_ADDR="${HY2_ORIGIN_ADDR:-203.0.113.80}"
CLIENT_JSON="$STATE/../hy2-client.json"
LOG="$STATE/../hy2-server.log"

CONFIG_ONLY=0
[ "${1:-}" = "--config-only" ] && CONFIG_ONLY=1

mkdir -p "$STATE"
chmod 700 "$STATE"

# Secrets: generated once, reused on restart. Two independent values.
for secret in auth obfs; do
  if [ ! -s "$STATE/$secret.secret" ]; then
    openssl rand -hex 16 > "$STATE/$secret.secret"
    chmod 600 "$STATE/$secret.secret"
  fi
done
# `\r` as well as `\n`: a CRLF-emitting openssl (Windows) would otherwise leave a carriage
# return inside the secret, and the client would be configured with a different password.
AUTH=$(tr -d '\r\n' < "$STATE/auth.secret")
OBFS=$(tr -d '\r\n' < "$STATE/obfs.secret")
[ "$AUTH" != "$OBFS" ] || { echo "[hy2] auth and obfs secrets must differ"; exit 1; }

# Certificate: ECDSA P-256, self-signed. The client pins its public key, so no CA is involved.
if [ ! -s "$STATE/server.crt" ] || [ ! -s "$STATE/server.key" ]; then
  # Errors are left visible: a silent failure here once cost a debugging round.
  openssl ecparam -name prime256v1 -genkey -noout -out "$STATE/server.key"
  chmod 600 "$STATE/server.key"
  openssl req -new -x509 -key "$STATE/server.key" -out "$STATE/server.crt" -days 3650 \
    -subj "/CN=$SERVER_NAME" -addext "subjectAltName=DNS:$SERVER_NAME"
fi

# SHA-256 of the DER SubjectPublicKeyInfo, as hex: what the client pins.
SPKI=$(openssl x509 -in "$STATE/server.crt" -pubkey -noout \
  | openssl pkey -pubin -outform DER \
  | openssl dgst -sha256 -binary | od -An -tx1 | tr -d ' \n')
[ "${#SPKI}" -eq 64 ] || { echo "[hy2] could not derive the certificate pin"; exit 1; }

cat > "$STATE/server.json" <<EOF
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen": "$LISTEN",
      "listen_port": $PORT,
      "obfs": { "type": "salamander", "password": "$OBFS" },
      "users": [ { "name": "harness", "password": "$AUTH" } ],
      "tls": {
        "enabled": true,
        "server_name": "$SERVER_NAME",
        "certificate_path": "$STATE/server.crt",
        "key_path": "$STATE/server.key"
      }
    }
  ],
  "outbounds": [ { "type": "direct", "tag": "direct" } ]
}
EOF
chmod 600 "$STATE/server.json"

echo "[hy2] checking the server configuration with the core's own validator"
"$BIN" check -c "$STATE/server.json"

# The runner's contract. Written atomically; readable only inside the state mount.
TMP=$(mktemp "$STATE/.client.XXXXXX")
cat > "$TMP" <<EOF
{
  "server_port": $PORT,
  "server_name": "$SERVER_NAME",
  "spki_sha256_hex": "$SPKI",
  "auth_password": "$AUTH",
  "obfs_password": "$OBFS",
  "origin_url": "http://$ORIGIN_ADDR:8080"
}
EOF
chmod 600 "$TMP"
mv "$TMP" "$CLIENT_JSON"

if [ "$CONFIG_ONLY" -eq 1 ]; then
  echo "[hy2] config written (--config-only); nothing started"
  exit 0
fi

# The origin address lives on lo so the server can reach it directly. Idempotent: the
# AmneziaWG server adds the same address when it runs.
ip addr add "${ORIGIN_ADDR}/32" dev lo 2>/dev/null || true

echo "[hy2] starting the primary core as a Hysteria 2 server on udp/$PORT"
"$BIN" run -c "$STATE/server.json" > "$LOG" 2>&1 &
for _ in $(seq 1 100); do
  grep -q "sing-box started" "$LOG" 2>/dev/null && break
  sleep 0.1
done
grep -q "sing-box started" "$LOG" 2>/dev/null \
  || { echo "[hy2] server did not report started; see hy2-server.log"; exit 1; }
echo "[hy2] server up; client parameters in .state/hy2-client.json"
