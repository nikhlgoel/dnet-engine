#!/bin/bash
# Profile A (AmneziaWG) server for SPIKE-R4 (T018, partial).
#
# - Generates a server and a client X25519 keypair once, persisted under
#   /opt/state/awg/ so restarts keep the same identity. TEST KEYS ONLY: the state
#   directory is gitignored and must never hold real credentials.
# - Starts the pinned amneziawg-go in the foreground on `awg0`, configures it over its
#   UAPI socket with obfuscation parameters that MUST match the client's.
# - Puts the HTTP origin on a TEST-NET-3 address (203.0.113.80) reachable only through
#   the tunnel. It is deliberately NOT an RFC1918 address: the client's built-in bypass
#   rules send RFC1918 direct, which would route around the tunnel under test.
# - Writes /opt/state/awg-client.json: everything the Windows spike runner needs.
set -euo pipefail

STATE=/opt/state/awg
IFACE=awg0
SOCK=/var/run/amneziawg/${IFACE}.sock
SERVER_TUN_ADDR=10.66.0.1/24
CLIENT_TUN_ADDR=10.66.0.2
ORIGIN_ADDR=203.0.113.80
LISTEN_PORT=51820

# Obfuscation parameters. S1/S2 and H1..H4 must be identical on both ends; H1..H4 must
# not overlap (the core rejects overlapping headers).
JC=4; JMIN=40; JMAX=70; S1=15; S2=20
H1=1053421987; H2=2083245612; H3=3175921403; H4=4012837465

mkdir -p "$STATE"
chmod 700 "$STATE"

# Raw 32-byte X25519 keys as lowercase hex (the UAPI format).
priv_hex() { openssl pkey -in "$1" -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n'; }
pub_hex()  { openssl pkey -in "$1" -pubout -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \n'; }

for who in server client; do
  if [ ! -f "$STATE/$who.pem" ]; then
    openssl genpkey -algorithm X25519 -out "$STATE/$who.pem" 2>/dev/null
    chmod 600 "$STATE/$who.pem"
  fi
done

SERVER_PRIV=$(priv_hex "$STATE/server.pem")
SERVER_PUB=$(pub_hex "$STATE/server.pem")
CLIENT_PRIV=$(priv_hex "$STATE/client.pem")
CLIENT_PUB=$(pub_hex "$STATE/client.pem")

echo "[awg] starting amneziawg-go on $IFACE"
amneziawg-go -f "$IFACE" > /opt/state/awg-server.log 2>&1 &

for _ in $(seq 1 100); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "[awg] UAPI socket never appeared"; exit 1; }

python3 /opt/uapi_set.py "$SOCK" <<EOF
private_key=$SERVER_PRIV
listen_port=$LISTEN_PORT
jc=$JC
jmin=$JMIN
jmax=$JMAX
s1=$S1
s2=$S2
h1=$H1
h2=$H2
h3=$H3
h4=$H4
public_key=$CLIENT_PUB
allowed_ip=${CLIENT_TUN_ADDR}/32
EOF

ip addr add "$SERVER_TUN_ADDR" dev "$IFACE"
ip link set "$IFACE" up
ip addr add "${ORIGIN_ADDR}/32" dev lo

# The runner's contract. Written atomically; readable only inside the state mount.
TMP=$(mktemp "$STATE/.client.XXXXXX")
cat > "$TMP" <<EOF
{
  "client_private_key_hex": "$CLIENT_PRIV",
  "server_public_key_hex": "$SERVER_PUB",
  "client_address": "$CLIENT_TUN_ADDR",
  "prefix_len": 24,
  "listen_port": $LISTEN_PORT,
  "origin_url": "http://$ORIGIN_ADDR:8080",
  "obfuscation": { "jc": $JC, "jmin": $JMIN, "jmax": $JMAX, "s1": $S1, "s2": $S2,
                   "h1": $H1, "h2": $H2, "h3": $H3, "h4": $H4 }
}
EOF
chmod 600 "$TMP"
mv "$TMP" /opt/state/awg-client.json
echo "[awg] server up; client parameters in .state/awg-client.json"
