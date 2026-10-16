#!/bin/bash
# Profile C (VLESS+REALITY) server for the harness (T018, partial).
#
# - Generates, once, a REALITY X25519 key pair, a user UUID and a short id, persisted under
#   $REALITY_STATE so restarts keep the same identity. TEST KEYS ONLY: the state directory is
#   gitignored and must never hold real credentials.
# - Writes a primary-core server configuration: one `vless` inbound with `xtls-rprx-vision`
#   flow and REALITY. Unauthenticated handshakes are forwarded to a TLS 1.3 target the
#   endpoint hosts itself on loopback (reality-target.py), because the harness has no route to a
#   real third-party site.
# - Validates that configuration with the core's own `check` before starting anything.
# - Writes $REALITY_STATE/../reality-client.json: everything the client side needs. The Rust
#   side refuses unknown fields, so a change here must be made there too.
#
# Knobs, so the same script can be exercised without Docker (all have container defaults):
#   REALITY_STATE    state directory                       (/opt/state/reality)
#   REALITY_BIN      the primary core                      (primary-core)
#   REALITY_PORT     TCP listen port                       (8443)
#   REALITY_LISTEN   listen address                        (::)
#   TARGET_PORT      loopback port of the TLS target       (9443)
#   TARGET_DOMAIN    the name clients present as SNI       (harness-target.example.net)
#   ORIGIN_ADDR      origin address added on lo            (203.0.113.80)
#   --config-only    write and check the files, then exit; start nothing, touch no interface
#
# Under Git Bash on Windows, export MSYS_NO_PATHCONV=1 first (openssl's `/CN=` argument).
set -euo pipefail

STATE="${REALITY_STATE:-/opt/state/reality}"
BIN="${REALITY_BIN:-primary-core}"
PORT="${REALITY_PORT:-8443}"
LISTEN="${REALITY_LISTEN:-::}"
TARGET_PORT="${TARGET_PORT:-9443}"
TARGET_DOMAIN="${TARGET_DOMAIN:-harness-target.example.net}"
ORIGIN_ADDR="${ORIGIN_ADDR:-203.0.113.80}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_PY="${REALITY_TARGET_PY:-$HERE/reality-target.py}"
CLIENT_JSON="$STATE/../reality-client.json"
LOG="$STATE/../reality-server.log"

CONFIG_ONLY=0
[ "${1:-}" = "--config-only" ] && CONFIG_ONLY=1

mkdir -p "$STATE"
chmod 700 "$STATE"

# `\r` as well as `\n`: a CRLF-emitting tool (Windows) must not leave a carriage return inside
# a key or id.
clean() { tr -d '\r\n'; }

if [ ! -s "$STATE/private.key" ] || [ ! -s "$STATE/public.key" ]; then
  PAIR=$("$BIN" generate reality-keypair)
  echo "$PAIR" | sed -n 's/^PrivateKey: *//p' | clean > "$STATE/private.key"
  echo "$PAIR" | sed -n 's/^PublicKey: *//p' | clean > "$STATE/public.key"
  chmod 600 "$STATE/private.key" "$STATE/public.key"
fi
[ -s "$STATE/uuid" ] || { "$BIN" generate uuid | clean > "$STATE/uuid"; chmod 600 "$STATE/uuid"; }
[ -s "$STATE/short_id" ] || { "$BIN" generate rand --hex 8 | clean > "$STATE/short_id"; chmod 600 "$STATE/short_id"; }
PRIVATE=$(clean < "$STATE/private.key")
PUBLIC=$(clean < "$STATE/public.key")
UUID=$(clean < "$STATE/uuid")
SHORT_ID=$(clean < "$STATE/short_id")
[ -n "$PRIVATE" ] && [ -n "$PUBLIC" ] && [ -n "$UUID" ] && [ -n "$SHORT_ID" ] \
  || { echo "[reality] key generation produced an empty value"; exit 1; }

# The target's own certificate. Self-signed ECDSA; REALITY does not authenticate with it.
if [ ! -s "$STATE/target.crt" ] || [ ! -s "$STATE/target.key" ]; then
  openssl ecparam -name prime256v1 -genkey -noout -out "$STATE/target.key"
  chmod 600 "$STATE/target.key"
  openssl req -new -x509 -key "$STATE/target.key" -out "$STATE/target.crt" -days 3650 \
    -subj "/CN=$TARGET_DOMAIN" -addext "subjectAltName=DNS:$TARGET_DOMAIN"
fi

cat > "$STATE/server.json" <<EOF
{
  "log": { "level": "info", "timestamp": true },
  "inbounds": [
    {
      "type": "vless",
      "tag": "reality-in",
      "listen": "$LISTEN",
      "listen_port": $PORT,
      "users": [ { "name": "harness", "uuid": "$UUID", "flow": "xtls-rprx-vision" } ],
      "tls": {
        "enabled": true,
        "server_name": "$TARGET_DOMAIN",
        "reality": {
          "enabled": true,
          "handshake": { "server": "127.0.0.1", "server_port": $TARGET_PORT },
          "private_key": "$PRIVATE",
          "short_id": [ "$SHORT_ID" ]
        }
      }
    }
  ],
  "outbounds": [ { "type": "direct", "tag": "direct" } ]
}
EOF
chmod 600 "$STATE/server.json"

echo "[reality] checking the server configuration with the core's own validator"
"$BIN" check -c "$STATE/server.json"

TMP=$(mktemp "$STATE/.client.XXXXXX")
cat > "$TMP" <<EOF
{
  "server_port": $PORT,
  "target_domain": "$TARGET_DOMAIN",
  "public_key": "$PUBLIC",
  "short_id": "$SHORT_ID",
  "uuid": "$UUID",
  "flow": "xtls-rprx-vision",
  "origin_url": "http://$ORIGIN_ADDR:8080"
}
EOF
chmod 600 "$TMP"
mv "$TMP" "$CLIENT_JSON"

if [ "$CONFIG_ONLY" -eq 1 ]; then
  echo "[reality] config written (--config-only); nothing started"
  exit 0
fi

ip addr add "${ORIGIN_ADDR}/32" dev lo 2>/dev/null || true

echo "[reality] starting the TLS 1.3 target on 127.0.0.1:$TARGET_PORT"
python3 "$TARGET_PY" "$TARGET_PORT" "$STATE/target.crt" "$STATE/target.key" \
  > "$STATE/../reality-target.log" 2>&1 &
sleep 0.5

echo "[reality] starting the primary core as a VLESS+REALITY server on tcp/$PORT"
"$BIN" run -c "$STATE/server.json" > "$LOG" 2>&1 &
for _ in $(seq 1 100); do
  grep -q "sing-box started" "$LOG" 2>/dev/null && break
  sleep 0.1
done
grep -q "sing-box started" "$LOG" 2>/dev/null \
  || { echo "[reality] server did not report started; see reality-server.log"; exit 1; }
echo "[reality] server up; client parameters in .state/reality-client.json"
