//! T093 — setting up the server (PR-12, PR-13, PR-14, PR-15, PR-16).
//!
//! A new machine is turned into an endpoint by one script, run once on it (`Provider::bootstrap`) and safe
//! to run again. This module makes that script and reads what it reports. Its shape follows the harness
//! endpoint (`testing/harness/endpoint/*.sh`), which is the server side the client has been proven against.
//!
//! # What the script does
//!
//! - Installs the **two server-side cores, pinned**: each is downloaded from a pinned address and its
//!   SHA-256 checked against a pinned value before it is made executable, and a mismatch stops everything
//!   (PR-12). The pins come from the caller (the release the client was built from), never from this crate.
//! - **Makes the server's private keys on the server** (PR-13): the AmneziaWG key pair, the Hysteria 2
//!   certificate and its key, the REALITY key pair, and the shared secrets. The client's own private key is
//!   made on the client; the script receives only its **public** key. The script contains no secret at all.
//! - Writes the configuration, checks it with the core's own `check` before anything is started, installs
//!   two services, and opens exactly the three ports.
//! - Records the cores' licence terms and source (PR-15), in `/opt/dnet/ATTRIBUTION`.
//! - Prints **one line**: [`REPORT_PREFIX`] and a JSON object. That is the whole reply.
//!
//! # Rules the script keeps
//!
//! - **The Hysteria 2 certificate is ECDSA, never Ed25519** (owner decision 2026-09-12, T093): the client
//!   keeps Chrome QUIC mimicry on, Chrome does not advertise Ed25519 signatures, and the handshake would
//!   fail. The script makes ECDSA P-256 and refuses to finish if the certificate it finds is anything else;
//!   [`BootstrapReport::parse`] refuses a report that says it is.
//! - **Nothing is regenerated, nothing is overwritten.** Every key, certificate and secret is made only if
//!   its file is absent. Running the script again against a set-up machine changes nothing and prints the
//!   same report (PR-14).
//! - **Every value that enters the script is validated first**, against a narrow alphabet, so no field can
//!   carry shell syntax into a script that runs as root (see [`BootstrapError::Unsafe`]).
//!
//! # What this module cannot show
//!
//! The script is text and is checked here for what it contains and that it parses (`sh -n`). That it
//! *works* on a real machine is checked in the lab (T098), against a real instance.

use std::net::Ipv4Addr;

use dnet_config::amneziawg::{ObfuscationParams, PrivateKey};
use dnet_config::credentials::{
    parse_spki_sha256_hex, AmneziaWgCredentials, EndpointCredentials, Hysteria2Bundle,
    RealityBundle, SessionBundle,
};
use dnet_config::hysteria2::{Hysteria2Credentials, Hysteria2EndpointParams, Hysteria2Obfs};
use dnet_config::reality::{
    RealityCredentials, RealityEndpointParams, RealityPublicKey, TargetDomain, VlessFlow,
};
use dnet_config::secret::Secret;
use dnet_config::tls::ServerTrust;
use dnet_core::origin::Origin;
use serde::Deserialize;

use crate::client_keys::{ClientKeys, SessionKeys};
use crate::provider::{PortRule, Protocol};

/// The line the script prints. Everything else it prints is progress text.
pub const REPORT_PREFIX: &str = "DNET-BOOTSTRAP-REPORT ";
/// The report format this crate reads. 2 added the session (ADR-0008); a server set up by an older script
/// reports 1 and is refused with the version, so the person sets it up again.
pub const REPORT_VERSION: u32 = 2;
/// Largest report accepted, in bytes. A report is a few hundred.
pub const MAX_REPORT_BYTES: usize = 16 * 1024;

/// Inside the AmneziaWG tunnel (the same addresses the harness uses).
pub const TUNNEL_SERVER: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 1);
pub const TUNNEL_CLIENT: Ipv4Addr = Ipv4Addr::new(10, 66, 0, 2);
pub const TUNNEL_PREFIX: u8 = 24;

/// Inside the session (ADR-0008): the addresses and the port, defined once in `dnet-config`, where the client's
/// configuration and the stored credentials need them too.
pub use dnet_config::session::{
    session_device_address, MAX_DEVICES, SESSION_ORIGIN, SESSION_PORT, SESSION_PREFIX,
    SESSION_SERVER,
};

/// The port of the measurement origin on the server's tunnel address.
pub const ORIGIN_PORT: u16 = 8080;
/// The most the origin gives out in one answer. A race asks for a few hundred kilobytes; nothing needs more.
pub const ORIGIN_MAX_BYTES: usize = 1_048_576;

/// Where the client measures a connection: the server's own tunnel address, which is private and so
/// reachable only through the tunnel. A fetch from it that completes proves the tunnel carries traffic;
/// a public address would be reached outside the tunnel and prove nothing.
pub fn measurement_origin() -> Origin {
    Origin::parse(&format!("http://{TUNNEL_SERVER}:{ORIGIN_PORT}")).expect("a fixed, valid origin")
}

/// The same, for the session: an address inside it that the server's exit maps to its own loopback origin,
/// so it is reachable only by a device with a key.
pub fn session_measurement_origin() -> Origin {
    Origin::parse(&format!("http://{SESSION_ORIGIN}:{ORIGIN_PORT}")).expect("a fixed, valid origin")
}

/// One server-side core, pinned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CorePin {
    /// A short name, lower case with hyphens.
    pub name: String,
    pub version: String,
    /// An `https` address to download the executable from.
    pub url: String,
    /// 64 lowercase hex digits.
    pub sha256: String,
    /// The licence terms, as a short identifier.
    pub licence: String,
    /// Where the source can be obtained (the licence's obligation, PR-15).
    pub source: String,
}

/// The processor a server has. The cores are built for one; running the wrong one fails unreadably, so the
/// script asks first and says so in words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerArch {
    /// Intel and AMD (`uname -m` says `x86_64`).
    Amd64,
    /// Arm (`uname -m` says `aarch64`).
    Arm64,
}

impl ServerArch {
    /// The name release files use.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Amd64 => "amd64",
            Self::Arm64 => "arm64",
        }
    }

    fn machine(self) -> &'static str {
        match self {
            Self::Amd64 => "x86_64",
            Self::Arm64 => "aarch64",
        }
    }
}

/// The two cores a server runs, matching the client's bundled versions (PR-12).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerCores {
    pub arch: ServerArch,
    /// Serves Hysteria 2 and VLESS+REALITY.
    pub primary_core: CorePin,
    pub amneziawg: CorePin,
}

/// The three ports the endpoint serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ports {
    pub amneziawg_udp: u16,
    pub hysteria2_udp: u16,
    pub reality_tcp: u16,
}

impl Default for Ports {
    /// The ports the harness endpoint and the client's tests use.
    fn default() -> Self {
        Self {
            amneziawg_udp: 51820,
            hysteria2_udp: 44443,
            reality_tcp: 8443,
        }
    }
}

impl Ports {
    /// The firewall rules the provider opens for these ports.
    pub fn rules(&self) -> Vec<PortRule> {
        vec![
            PortRule {
                protocol: Protocol::Udp,
                port: self.amneziawg_udp,
            },
            PortRule {
                protocol: Protocol::Udp,
                port: self.hysteria2_udp,
            },
            PortRule {
                protocol: Protocol::Tcp,
                port: self.reality_tcp,
            },
        ]
    }
}

/// Everything the script is built from. Nothing here is secret: the client's AmneziaWG key appears only as
/// its public half.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapPlan {
    pub cores: ServerCores,
    pub ports: Ports,
    /// 64 lowercase hex digits: the client's AmneziaWG public key.
    pub awg_client_public_hex: String,
    pub obfuscation: ObfuscationParams,
    /// The name the Hysteria 2 certificate is issued for, and the client sends as SNI.
    pub hysteria2_server_name: String,
    /// The site REALITY impersonates; handshakes that are not the client's are forwarded to it.
    pub reality_target: TargetDomain,
    /// The devices that may use the session (ADR-0008).
    pub session: SessionPlan,
}

/// Who may use the server's session. A device is its public key: the server holds no device secret, and a
/// device is removed by leaving its key out the next time the script runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPlan {
    /// One per device, 32 bytes in standard base64, in the order the devices get their addresses.
    pub device_public_keys: Vec<String>,
}

impl SessionPlan {
    /// The address device number `index` has, and its key, in the form the script and the report use.
    pub fn devices(&self) -> impl Iterator<Item = (Ipv4Addr, &str)> {
        self.device_public_keys
            .iter()
            .enumerate()
            .map(|(i, key)| (session_device_address(i), key.as_str()))
    }

    fn validate(&self) -> Result<(), BootstrapError> {
        let keys = &self.device_public_keys;
        if keys.is_empty() || keys.len() > MAX_DEVICES {
            return Err(BootstrapError::Invalid("the number of devices"));
        }
        for (i, key) in keys.iter().enumerate() {
            if !is_base64_key(key) {
                return Err(BootstrapError::Invalid("a device key"));
            }
            if keys[..i].contains(key) {
                return Err(BootstrapError::Invalid("a device key (it appears twice)"));
            }
        }
        Ok(())
    }
}

/// 32 bytes in standard base64, 44 characters: the form the core's key generator prints and its
/// configuration takes. Checking the alphabet is also what keeps the value safe in the script.
fn is_base64_key(text: &str) -> bool {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine as _;
    text.len() == 44 && STANDARD.decode(text).is_ok_and(|bytes| bytes.len() == 32)
}

/// Why a script could not be made, or a report could not be used.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BootstrapError {
    /// A value contains characters that are not allowed in the script. The value is not repeated.
    #[error("{0} contains characters that are not allowed in the bootstrap script")]
    Unsafe(&'static str),
    #[error("{0} is not valid")]
    Invalid(&'static str),
}

/// `[A-Za-z0-9._:/~+-]`: enough for an https address, a version and a licence identifier, and nothing a
/// shell treats as syntax.
fn plain(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '~' | '+' | '-')
}

fn safe(
    field: &'static str,
    value: &str,
    allowed: impl Fn(char) -> bool,
) -> Result<(), BootstrapError> {
    if value.is_empty() || value.len() > 300 || !value.chars().all(allowed) {
        return Err(BootstrapError::Unsafe(field));
    }
    Ok(())
}

fn hex64(field: &'static str, value: &str) -> Result<(), BootstrapError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Ok(())
    } else {
        Err(BootstrapError::Invalid(field))
    }
}

fn dns_name(field: &'static str, value: &str) -> Result<(), BootstrapError> {
    safe(field, value, |c| {
        c.is_ascii_alphanumeric() || matches!(c, '.' | '-')
    })?;
    match dnet_core::rule_eval::normalize_domain(value) {
        Some(normal) if normal == value => Ok(()),
        _ => Err(BootstrapError::Invalid(field)),
    }
}

impl CorePin {
    /// Whether every value would be accepted into the script.
    pub fn validate(&self, which: &'static str) -> Result<(), BootstrapError> {
        self.check(which)
    }

    fn check(&self, which: &'static str) -> Result<(), BootstrapError> {
        let name = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
        safe(which, &self.name, name)?;
        safe(which, &self.version, plain)?;
        safe(which, &self.licence, plain)?;
        safe(which, &self.source, plain)?;
        safe(which, &self.url, plain)?;
        if !self.url.starts_with("https://") {
            return Err(BootstrapError::Invalid(which));
        }
        hex64(which, &self.sha256)
    }
}

impl BootstrapPlan {
    /// Check every value that will enter the script.
    pub fn validate(&self) -> Result<(), BootstrapError> {
        self.cores.primary_core.check("the primary core pin")?;
        self.cores.amneziawg.check("the AmneziaWG core pin")?;
        hex64("the client public key", &self.awg_client_public_hex)?;
        self.obfuscation
            .validate()
            .map_err(|_| BootstrapError::Invalid("the obfuscation parameters"))?;
        dns_name("the Hysteria 2 server name", &self.hysteria2_server_name)?;
        self.session.validate()?;
        let ports = [
            self.ports.amneziawg_udp,
            self.ports.hysteria2_udp,
            self.ports.reality_tcp,
        ];
        if ports.contains(&0) || self.ports.amneziawg_udp == self.ports.hysteria2_udp {
            return Err(BootstrapError::Invalid("the ports"));
        }
        Ok(())
    }
}

// ------------------------------------------------------------------ the script

/// The script. `@@NAME@@` marks a value filled in from a validated [`BootstrapPlan`].
const TEMPLATE: &str = r##"#!/bin/sh
# DNet Engine endpoint bootstrap. Generated by the client; it contains no secret.
# Safe to run again: it repairs and reports, and never regenerates or overwrites a key.
# Keys are made on this machine, and only public material is reported.
set -eu
umask 077

BASE=/opt/dnet
BIN="$BASE/bin"
STATE=/var/lib/dnet
mkdir -p "$BIN" "$STATE/awg" "$STATE/primary"
# $STATE can be walked through (not listed or read) so the unprivileged core can reach its own directory.
chmod 711 "$STATE"
chmod 700 "$STATE/awg"
# $STATE/primary is made 700 by mkdir (umask 077) the first time; the end of this script gives it its final
# owner and mode, and later runs leave it alone, so a running core never loses its directory in the middle.

# ---- this must be the kind of machine the downloads are built for; say so before changing anything
MACHINE=$(uname -m)
if [ "$MACHINE" = "arm64" ]; then MACHINE=aarch64; fi
if [ "$MACHINE" != "@@MACHINE@@" ]; then
  echo "This server has a $MACHINE processor, but this script is for @@MACHINE@@ (@@ARCH@@). Go back to DNet Engine and choose the other kind of server." >&2
  exit 3
fi

need() { command -v "$1" >/dev/null 2>&1; }
ensure() {
  # ensure <command> <apt package> <dnf package>
  need "$1" && return 0
  if need apt-get; then DEBIAN_FRONTEND=noninteractive apt-get install -y "$2" >/dev/null
  elif need dnf; then dnf install -y "$3" >/dev/null
  fi
  need "$1" || { echo "missing tool: $1" >&2; exit 2; }
}
ensure curl curl curl
ensure openssl openssl openssl
ensure python3 python3 python3
ensure ip iproute2 iproute
ensure sha256sum coreutils coreutils

# ---- the core that faces the internet runs as a user of its own, with no shell and no home: a flaw in it
# is then a flaw in an account that can read its own keys and nothing else on this machine
id dnet >/dev/null 2>&1 \
  || useradd --system --no-create-home --shell /usr/sbin/nologin dnet >/dev/null 2>&1 \
  || useradd -r -M -s /sbin/nologin dnet >/dev/null 2>&1 || true
id dnet >/dev/null 2>&1 || { echo "could not create the account the core runs as" >&2; exit 2; }

# ---- the two cores, pinned: downloaded, checked, and only then made executable
fetch() {
  # fetch <name> <url> <sha256> <destination>
  if [ -f "$4" ] && [ "$(sha256sum "$4" | cut -d' ' -f1)" = "$3" ]; then return 0; fi
  tmp="$4.part"
  curl -fsSL --proto '=https' --tlsv1.2 --max-time 300 -o "$tmp" "$2"
  if [ "$(sha256sum "$tmp" | cut -d' ' -f1)" != "$3" ]; then
    rm -f "$tmp"
    echo "checksum mismatch for $1: refusing to install it" >&2
    exit 4
  fi
  chmod 0755 "$tmp"
  mv "$tmp" "$4"
}
fetch primary-core '@@PRIMARY_URL@@' '@@PRIMARY_SHA@@' "$BIN/primary-core"
fetch amneziawg-go '@@AWG_URL@@' '@@AWG_SHA@@' "$BIN/amneziawg-go"

cat > "$BASE/ATTRIBUTION" <<'ATTRIBUTION_EOF'
This machine runs third-party software installed by DNet Engine.
@@PRIMARY_NAME@@ @@PRIMARY_VERSION@@ - licence @@PRIMARY_LICENCE@@ - source @@PRIMARY_SOURCE@@
@@AWG_NAME@@ @@AWG_VERSION@@ - licence @@AWG_LICENCE@@ - source @@AWG_SOURCE@@
ATTRIBUTION_EOF
chmod 644 "$BASE/ATTRIBUTION"

hexkey() { od -An -tx1 | tr -d ' \r\n'; }
clean() { tr -d '\r\n'; }

# ---- AmneziaWG: the server's own key pair (the client's private key stays on the client)
if [ ! -s "$STATE/awg/server.pem" ]; then
  openssl genpkey -algorithm X25519 -out "$STATE/awg/server.pem" 2>/dev/null
  chmod 600 "$STATE/awg/server.pem"
fi
AWG_PUB=$(openssl pkey -in "$STATE/awg/server.pem" -pubout -outform DER | tail -c 32 | hexkey)
[ "${#AWG_PUB}" -eq 64 ] || { echo "could not derive the AmneziaWG public key" >&2; exit 1; }

# ---- Hysteria 2: an ECDSA certificate (never Ed25519), and two different secrets
for secret in auth obfs; do
  if [ ! -s "$STATE/primary/$secret.secret" ]; then
    openssl rand -hex 16 > "$STATE/primary/$secret.secret"
    chmod 600 "$STATE/primary/$secret.secret"
  fi
done
HY2_AUTH=$(clean < "$STATE/primary/auth.secret")
HY2_OBFS=$(clean < "$STATE/primary/obfs.secret")
[ "$HY2_AUTH" != "$HY2_OBFS" ] || { echo "the two Hysteria 2 secrets must differ" >&2; exit 1; }

if [ ! -s "$STATE/primary/server.crt" ] || [ ! -s "$STATE/primary/server.key" ]; then
  openssl ecparam -name prime256v1 -genkey -noout -out "$STATE/primary/server.key"
  chmod 600 "$STATE/primary/server.key"
  openssl req -new -x509 -key "$STATE/primary/server.key" -out "$STATE/primary/server.crt" -days 3650 \
    -subj "/CN=@@HY2_SNI@@" -addext "subjectAltName=DNS:@@HY2_SNI@@"
fi
CERT_TEXT=$(openssl x509 -in "$STATE/primary/server.crt" -noout -text)
case "$CERT_TEXT" in
  *id-ecPublicKey*) CERT_ALG=ecdsa-p256 ;;
  *rsaEncryption*) CERT_ALG=rsa ;;
  *) echo "the Hysteria 2 certificate must be ECDSA or RSA, never Ed25519" >&2; exit 3 ;;
esac
HY2_SPKI=$(openssl x509 -in "$STATE/primary/server.crt" -pubkey -noout \
  | openssl pkey -pubin -outform DER | openssl dgst -sha256 -binary | hexkey)
[ "${#HY2_SPKI}" -eq 64 ] || { echo "could not derive the certificate pin" >&2; exit 1; }

# ---- VLESS+REALITY: a key pair, a user id and a short id, made by the core itself
if [ ! -s "$STATE/primary/reality.private" ] || [ ! -s "$STATE/primary/reality.public" ]; then
  PAIR=$("$BIN/primary-core" generate reality-keypair)
  echo "$PAIR" | sed -n 's/^PrivateKey: *//p' | clean > "$STATE/primary/reality.private"
  echo "$PAIR" | sed -n 's/^PublicKey: *//p' | clean > "$STATE/primary/reality.public"
  chmod 600 "$STATE/primary/reality.private" "$STATE/primary/reality.public"
fi
[ -s "$STATE/primary/uuid" ] || { "$BIN/primary-core" generate uuid | clean > "$STATE/primary/uuid"; chmod 600 "$STATE/primary/uuid"; }
[ -s "$STATE/primary/short_id" ] || { "$BIN/primary-core" generate rand --hex 8 | clean > "$STATE/primary/short_id"; chmod 600 "$STATE/primary/short_id"; }
REALITY_PRIVATE=$(clean < "$STATE/primary/reality.private")
REALITY_PUBLIC=$(clean < "$STATE/primary/reality.public")
REALITY_UUID=$(clean < "$STATE/primary/uuid")
REALITY_SHORT=$(clean < "$STATE/primary/short_id")
[ -n "$REALITY_PRIVATE" ] && [ -n "$REALITY_PUBLIC" ] && [ -n "$REALITY_UUID" ] && [ -n "$REALITY_SHORT" ] \
  || { echo "key generation produced an empty value" >&2; exit 1; }

# ---- the session (ADR-0008): the server's own key pair. Each device has a key pair of its own, made on the
# device; only the public halves are here, so a lost device is removed by leaving its key out.
if [ ! -s "$STATE/primary/session.private" ] || [ ! -s "$STATE/primary/session.public" ]; then
  PAIR=$("$BIN/primary-core" generate wg-keypair)
  echo "$PAIR" | sed -n 's/^PrivateKey: *//p' | clean > "$STATE/primary/session.private"
  echo "$PAIR" | sed -n 's/^PublicKey: *//p' | clean > "$STATE/primary/session.public"
  chmod 600 "$STATE/primary/session.private" "$STATE/primary/session.public"
fi
SESSION_PRIVATE=$(clean < "$STATE/primary/session.private")
SESSION_PUBLIC=$(clean < "$STATE/primary/session.public")
[ "${#SESSION_PRIVATE}" -eq 44 ] && [ "${#SESSION_PUBLIC}" -eq 44 ] \
  || { echo "could not make the session key" >&2; exit 1; }

# ---- the primary core's server configuration: checked by the core itself before anything starts.
# It is derived from the keys above and the devices in this script, so it is rewritten every time and
# replaced only if the core accepts it; the service is restarted only if it actually changed.
CONFIG_CHANGED=0
cat > "$STATE/primary/server.json.new" <<CONFIG_EOF
{
  "log": { "level": "warn", "timestamp": true },
  "inbounds": [
    {
      "type": "hysteria2",
      "tag": "hy2-in",
      "listen": "::",
      "listen_port": @@HY2_PORT@@,
      "obfs": { "type": "salamander", "password": "$HY2_OBFS" },
      "users": [ { "name": "dnet", "password": "$HY2_AUTH" } ],
      "tls": {
        "enabled": true,
        "server_name": "@@HY2_SNI@@",
        "certificate_path": "$STATE/primary/server.crt",
        "key_path": "$STATE/primary/server.key"
      }
    },
    {
      "type": "vless",
      "tag": "reality-in",
      "listen": "::",
      "listen_port": @@REALITY_PORT@@,
      "users": [ { "name": "dnet", "uuid": "$REALITY_UUID", "flow": "xtls-rprx-vision" } ],
      "tls": {
        "enabled": true,
        "server_name": "@@REALITY_TARGET@@",
        "reality": {
          "enabled": true,
          "handshake": { "server": "@@REALITY_TARGET@@", "server_port": 443 },
          "private_key": "$REALITY_PRIVATE",
          "short_id": [ "$REALITY_SHORT" ]
        }
      }
    }
  ],
  "endpoints": [
    {
      "type": "@@SESSION_TYPE@@",
      "tag": "session-in",
      "system": false,
      "address": [ "@@SESSION_SERVER@@/@@SESSION_PREFIX@@" ],
      "private_key": "$SESSION_PRIVATE",
      "listen_port": @@SESSION_PORT@@,
      "peers": [
@@SESSION_PEERS@@
      ]
    }
  ],
  "outbounds": [ { "type": "direct", "tag": "direct" } ],
  "dns": { "servers": [ { "type": "local", "tag": "local" } ] },
  "route": {
    "default_domain_resolver": "local",
    "final": "direct",
    "rules": [
      { "inbound": [ "hy2-in", "reality-in" ], "ip_cidr": [ "127.0.0.1/32" ], "port": [ @@SESSION_PORT@@ ], "network": [ "udp" ], "action": "route", "outbound": "direct" },
      { "inbound": [ "hy2-in", "reality-in" ], "action": "reject" },
      { "inbound": [ "session-in" ], "ip_cidr": [ "@@SESSION_ORIGIN@@/32" ], "port": [ @@ORIGIN_PORT@@ ], "action": "route", "outbound": "direct", "override_address": "127.0.0.1", "override_port": @@ORIGIN_PORT@@ },
      { "inbound": [ "session-in" ], "action": "resolve", "strategy": "prefer_ipv4" },
      { "inbound": [ "session-in" ], "ip_is_private": true, "action": "reject" }
    ]
  }
}
CONFIG_EOF
chmod 600 "$STATE/primary/server.json.new"
"$BIN/primary-core" check -c "$STATE/primary/server.json.new" || { rm -f "$STATE/primary/server.json.new"; echo "the core rejected its configuration" >&2; exit 5; }
if [ -s "$STATE/primary/server.json" ] && cmp -s "$STATE/primary/server.json.new" "$STATE/primary/server.json"; then
  rm -f "$STATE/primary/server.json.new"
else
  [ -s "$STATE/primary/server.json" ] && CONFIG_CHANGED=1
  mv "$STATE/primary/server.json.new" "$STATE/primary/server.json"
fi
# The core runs as an account that may READ what it needs and may create or replace nothing here: root keeps
# owning the directory and every file in it, with the account's group allowed read-only. (If the account owned
# the directory, a flaw in the core could plant a symlink for the next run of this script, which is root and
# writes server.json.new with `cat >`, to follow.)
chown -R root:dnet "$STATE/primary"
chmod 750 "$STATE/primary"
find "$STATE/primary" -type f -exec chmod 640 {} +

# ---- AmneziaWG configuration helper: speaks the core's control socket
cat > "$BIN/dnet-uapi-set" <<'UAPI_EOF'
#!/usr/bin/env python3
import socket, sys
path = sys.argv[1]
body = "".join(l if l.endswith("\n") else l + "\n" for l in sys.stdin if l.strip())
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
    s.connect(path)
    s.sendall(("set=1\n" + body + "\n").encode())
    reply = b""
    while not reply.endswith(b"\n\n"):
        chunk = s.recv(4096)
        if not chunk:
            break
        reply += chunk
sys.exit(0 if b"errno=0" in reply else 1)
UAPI_EOF
chmod 0755 "$BIN/dnet-uapi-set"

cat > "$BIN/dnet-awg-configure" <<'AWGCONF_EOF'
#!/bin/sh
set -eu
STATE=/var/lib/dnet
SOCK=/var/run/amneziawg/awg0.sock
i=0
while [ ! -S "$SOCK" ] && [ "$i" -lt 100 ]; do i=$((i + 1)); sleep 0.1; done
[ -S "$SOCK" ] || { echo "the control socket never appeared" >&2; exit 1; }
PRIV=$(openssl pkey -in "$STATE/awg/server.pem" -outform DER | tail -c 32 | od -An -tx1 | tr -d ' \r\n')
/opt/dnet/bin/dnet-uapi-set "$SOCK" <<UAPI_BODY
private_key=$PRIV
listen_port=@@AWG_PORT@@
jc=@@JC@@
jmin=@@JMIN@@
jmax=@@JMAX@@
s1=@@S1@@
s2=@@S2@@
h1=@@H1@@
h2=@@H2@@
h3=@@H3@@
h4=@@H4@@
public_key=@@CLIENT_PUB@@
allowed_ip=@@TUN_CLIENT@@/32
UAPI_BODY
ip addr replace @@TUN_SERVER@@/@@TUN_PREFIX@@ dev awg0
ip link set awg0 up
AWGCONF_EOF
chmod 0755 "$BIN/dnet-awg-configure"

# ---- the machine's own firewall: these three ports are opened, and the AmneziaWG tunnel's exit is forwarded.
# It adds accept rules and sets no default of its own: what else is closed is up to the image's own rules
# and the provider's network rules (the guide has the person open exactly these three there).
cat > "$BIN/dnet-net-up" <<'NET_EOF'
#!/bin/sh
set -eu
if command -v sysctl >/dev/null 2>&1; then sysctl -qw net.ipv4.ip_forward=1; fi
if command -v iptables >/dev/null 2>&1; then
  allow() { iptables -C INPUT -p "$1" --dport "$2" -j ACCEPT 2>/dev/null || iptables -I INPUT 1 -p "$1" --dport "$2" -j ACCEPT; }
  allow udp @@AWG_PORT@@
  allow udp @@HY2_PORT@@
  allow tcp @@REALITY_PORT@@
  IFACE=$(ip -4 route show default | awk '{print $5; exit}')
  if [ -n "$IFACE" ]; then
    iptables -t nat -C POSTROUTING -s @@TUN_SERVER@@/@@TUN_PREFIX@@ -o "$IFACE" -j MASQUERADE 2>/dev/null \
      || iptables -t nat -A POSTROUTING -s @@TUN_SERVER@@/@@TUN_PREFIX@@ -o "$IFACE" -j MASQUERADE
  fi
fi
NET_EOF
chmod 0755 "$BIN/dnet-net-up"

# ---- housekeeping: a free server has no one watching its disk, so nothing here may grow without bound.
# Only logs and package downloads are touched, never a key, a certificate or the configuration.
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/dnet.conf <<'JOURNAL_EOF'
[Journal]
SystemMaxUse=100M
MaxRetentionSec=14day
JOURNAL_EOF
cat > "$BIN/dnet-housekeeping" <<'HOUSEKEEPING_EOF'
#!/bin/sh
journalctl --vacuum-size=100M >/dev/null 2>&1 || true
journalctl --vacuum-time=14d >/dev/null 2>&1 || true
if command -v apt-get >/dev/null 2>&1; then apt-get clean >/dev/null 2>&1 || true; fi
if command -v dnf >/dev/null 2>&1; then dnf clean all >/dev/null 2>&1 || true; fi
exit 0
HOUSEKEEPING_EOF
chmod 0755 "$BIN/dnet-housekeeping"
cat > /etc/systemd/system/dnet-housekeeping.service <<'UNIT_EOF'
[Unit]
Description=DNet Engine endpoint: trim logs and package downloads
[Service]
Type=oneshot
Nice=19
ExecStart=/opt/dnet/bin/dnet-housekeeping
UNIT_EOF
cat > /etc/systemd/system/dnet-housekeeping.timer <<'UNIT_EOF'
[Unit]
Description=DNet Engine endpoint: weekly housekeeping
[Timer]
OnCalendar=weekly
Persistent=true
[Install]
WantedBy=timers.target
UNIT_EOF
systemctl restart systemd-journald >/dev/null 2>&1 || true
"$BIN/dnet-housekeeping"

# ---- the measurement origin: what the client fetches through the tunnel to judge it. Bound to the tunnel's
# own private address and nothing else, so it is reachable only through the tunnel and never from outside.
cat > "$BIN/dnet-origin" <<'ORIGIN_EOF'
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BYTES = @@ORIGIN_MAX@@
BLOCK = os.urandom(65536)

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def do_GET(self):
        parts = self.path.split("/")
        if len(parts) != 3 or parts[0] != "" or parts[1] != "bytes" or not parts[2].isdigit() or len(parts[2]) > 9:
            self.send_error(404)
            return
        n = int(parts[2])
        if n < 1 or n > MAX_BYTES:
            self.send_error(400, "bad byte count")
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(n))
        self.end_headers()
        sent = 0
        while sent < n:
            chunk = BLOCK[: min(len(BLOCK), n - sent)]
            self.wfile.write(chunk)
            sent += len(chunk)

    def log_message(self, fmt, *args):
        pass

# The address to listen on is the one argument, and it must be one of the two this machine ever uses.
import sys
BIND = sys.argv[1] if len(sys.argv) == 2 else ""
if BIND not in ("@@TUN_SERVER@@", "127.0.0.1"):
    sys.exit("usage: dnet-origin <the tunnel address or 127.0.0.1>")
ThreadingHTTPServer((BIND, @@ORIGIN_PORT@@), Handler).serve_forever()
ORIGIN_EOF
chmod 0755 "$BIN/dnet-origin"
cat > /etc/systemd/system/dnet-origin.service <<'UNIT_EOF'
[Unit]
Description=DNet Engine endpoint: measurement origin (tunnel address only)
After=network-online.target dnet-awg.service
Requires=dnet-awg.service
[Service]
ExecStart=/usr/bin/python3 /opt/dnet/bin/dnet-origin @@TUN_SERVER@@
Restart=always
RestartSec=2
[Install]
WantedBy=multi-user.target
UNIT_EOF
# The same origin for the session: on this machine's own loopback, where the session's exit maps the
# session address to. It does not wait for the AmneziaWG tunnel, so the session works without it.
cat > /etc/systemd/system/dnet-origin-session.service <<'UNIT_EOF'
[Unit]
Description=DNet Engine endpoint: measurement origin for the session (loopback only)
After=network-online.target
[Service]
User=dnet
Group=dnet
ExecStart=/usr/bin/python3 /opt/dnet/bin/dnet-origin 127.0.0.1
Restart=always
RestartSec=2
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET
[Install]
WantedBy=multi-user.target
UNIT_EOF

# ---- services
cat > /etc/systemd/system/dnet-net.service <<'UNIT_EOF'
[Unit]
Description=DNet Engine endpoint: firewall and forwarding
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/dnet/bin/dnet-net-up
[Install]
WantedBy=multi-user.target
UNIT_EOF
cat > /etc/systemd/system/dnet-primary.service <<'UNIT_EOF'
[Unit]
Description=DNet Engine endpoint: Hysteria 2, VLESS+REALITY and the session
After=network-online.target dnet-net.service
Requires=dnet-net.service
[Service]
# The part of the server that faces the internet and parses what strangers send. It binds ports above 1024,
# makes no tunnel device (the session runs inside the core), and writes nothing, so it needs no privilege
# at all: no capabilities, no new ones, a read-only system, no home, no devices, only IP sockets.
User=dnet
Group=dnet
ExecStart=/opt/dnet/bin/primary-core run -c /var/lib/dnet/primary/server.json
Restart=on-failure
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
SystemCallArchitectures=native
UMask=0077
[Install]
WantedBy=multi-user.target
UNIT_EOF
cat > /etc/systemd/system/dnet-awg.service <<'UNIT_EOF'
[Unit]
Description=DNet Engine endpoint: AmneziaWG
After=network-online.target dnet-net.service
Requires=dnet-net.service
[Service]
RuntimeDirectory=amneziawg
ExecStart=/opt/dnet/bin/amneziawg-go -f awg0
ExecStartPost=/opt/dnet/bin/dnet-awg-configure
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT_EOF
systemctl daemon-reload
systemctl enable --now dnet-net.service dnet-primary.service dnet-awg.service dnet-origin.service dnet-origin-session.service >/dev/null
systemctl enable --now dnet-housekeeping.timer >/dev/null
# A configuration that changed (a device added or removed) takes effect now, not at the next restart.
if [ "$CONFIG_CHANGED" = 1 ]; then systemctl restart dnet-primary.service; fi

# ---- security updates: a server nobody logs in to has to patch itself. Best effort on purpose: a failure
# here must not undo a server that otherwise works, and it is reported by the next run's output.
if need apt-get; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y unattended-upgrades >/dev/null 2>&1 || true
  cat > /etc/apt/apt.conf.d/20auto-upgrades <<'APT_EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT_EOF
  cat > /etc/apt/apt.conf.d/52dnet-unattended <<'APT_EOF'
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-Time "04:00";
APT_EOF
elif need dnf; then
  dnf install -y dnf-automatic >/dev/null 2>&1 || true
  if [ -f /etc/dnf/automatic.conf ]; then
    sed -i 's/^apply_updates *=.*/apply_updates = yes/; s/^upgrade_type *=.*/upgrade_type = security/' /etc/dnf/automatic.conf
    systemctl enable --now dnf-automatic.timer >/dev/null 2>&1 || true
  fi
fi

@@KEEPALIVE@@

# ---- the report: public material, and the shared secrets the client has to hold
AWG_PUB="$AWG_PUB" HY2_SPKI="$HY2_SPKI" HY2_AUTH="$HY2_AUTH" HY2_OBFS="$HY2_OBFS" CERT_ALG="$CERT_ALG" \
REALITY_PUBLIC="$REALITY_PUBLIC" REALITY_SHORT="$REALITY_SHORT" REALITY_UUID="$REALITY_UUID" \
SESSION_PUBLIC="$SESSION_PUBLIC" \
PRIMARY_SHA='@@PRIMARY_SHA@@' AWG_SHA='@@AWG_SHA@@' python3 - <<'REPORT_EOF'
import json, os
e = os.environ
report = {
    "version": 2,
    "amneziawg": {"server_public_key_hex": e["AWG_PUB"], "listen_port": @@AWG_PORT@@,
                  "client_address": "@@TUN_CLIENT@@", "prefix_len": @@TUN_PREFIX@@,
                  "client_public_key_hex": "@@CLIENT_PUB@@"},
    "hysteria2": {"server_port": @@HY2_PORT@@, "server_name": "@@HY2_SNI@@",
                  "spki_sha256_hex": e["HY2_SPKI"], "auth_password": e["HY2_AUTH"],
                  "obfs_password": e["HY2_OBFS"], "cert_key_algorithm": e["CERT_ALG"]},
    "reality": {"server_port": @@REALITY_PORT@@, "target_domain": "@@REALITY_TARGET@@",
                "public_key": e["REALITY_PUBLIC"], "short_id": e["REALITY_SHORT"],
                "uuid": e["REALITY_UUID"], "flow": "xtls-rprx-vision"},
    "session": {"server_public_key": e["SESSION_PUBLIC"], "port": @@SESSION_PORT@@,
                "server_address": "@@SESSION_SERVER@@",
                "devices": [@@SESSION_DEVICES@@]},
    "cores": {"primary_core": {"version": "@@PRIMARY_VERSION@@", "sha256": e["PRIMARY_SHA"]},
              "amneziawg": {"version": "@@AWG_VERSION@@", "sha256": e["AWG_SHA"]}},
}
print("DNET-BOOTSTRAP-REPORT " + json.dumps(report, separators=(",", ":")))
REPORT_EOF
"##;

/// The peers of the server's session endpoint, one per device, as JSON for the configuration. The keys were
/// checked to be base64 of 32 bytes, so nothing in them is shell or JSON syntax.
fn session_peers(session: &SessionPlan) -> String {
    session
        .devices()
        .map(|(address, key)| {
            format!(
                "        {{ \"public_key\": \"{key}\", \"allowed_ips\": [ \"{address}/32\" ] }}"
            )
        })
        .collect::<Vec<_>>()
        .join(",\n")
}

/// The devices as the report prints them (a Python literal that is also valid JSON).
fn session_devices_literal(session: &SessionPlan) -> String {
    session
        .devices()
        .map(|(address, key)| format!("{{\"address\": \"{address}\", \"public_key\": \"{key}\"}}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The bootstrap script for `plan`. Fails, without making any text, if a value is not allowed in it.
pub fn script(plan: &BootstrapPlan) -> Result<String, BootstrapError> {
    plan.validate()?;
    let p = &plan.cores.primary_core;
    let a = &plan.cores.amneziawg;
    let o = &plan.obfuscation;
    let fills: Vec<(&str, String)> = vec![
        ("PRIMARY_URL", p.url.clone()),
        ("PRIMARY_SHA", p.sha256.clone()),
        ("PRIMARY_NAME", p.name.clone()),
        ("PRIMARY_VERSION", p.version.clone()),
        ("PRIMARY_LICENCE", p.licence.clone()),
        ("PRIMARY_SOURCE", p.source.clone()),
        ("AWG_URL", a.url.clone()),
        ("AWG_SHA", a.sha256.clone()),
        ("AWG_NAME", a.name.clone()),
        ("AWG_VERSION", a.version.clone()),
        ("AWG_LICENCE", a.licence.clone()),
        ("AWG_SOURCE", a.source.clone()),
        ("AWG_PORT", plan.ports.amneziawg_udp.to_string()),
        ("HY2_PORT", plan.ports.hysteria2_udp.to_string()),
        ("REALITY_PORT", plan.ports.reality_tcp.to_string()),
        ("HY2_SNI", plan.hysteria2_server_name.clone()),
        ("REALITY_TARGET", plan.reality_target.as_str().to_owned()),
        ("CLIENT_PUB", plan.awg_client_public_hex.clone()),
        ("JC", o.jc.to_string()),
        ("JMIN", o.jmin.to_string()),
        ("JMAX", o.jmax.to_string()),
        ("S1", o.s1.to_string()),
        ("S2", o.s2.to_string()),
        ("H1", o.h1.to_string()),
        ("H2", o.h2.to_string()),
        ("H3", o.h3.to_string()),
        ("H4", o.h4.to_string()),
        ("MACHINE", plan.cores.arch.machine().to_owned()),
        ("ARCH", plan.cores.arch.as_str().to_owned()),
        ("ORIGIN_PORT", ORIGIN_PORT.to_string()),
        ("ORIGIN_MAX", ORIGIN_MAX_BYTES.to_string()),
        ("TUN_SERVER", TUNNEL_SERVER.to_string()),
        ("TUN_CLIENT", TUNNEL_CLIENT.to_string()),
        ("TUN_PREFIX", TUNNEL_PREFIX.to_string()),
        (
            "SESSION_TYPE",
            dnet_config::session::SESSION_ENDPOINT_TYPE.to_owned(),
        ),
        ("SESSION_SERVER", SESSION_SERVER.to_string()),
        ("SESSION_ORIGIN", SESSION_ORIGIN.to_string()),
        ("SESSION_PREFIX", SESSION_PREFIX.to_string()),
        ("SESSION_PORT", SESSION_PORT.to_string()),
        ("SESSION_PEERS", session_peers(&plan.session)),
        ("SESSION_DEVICES", session_devices_literal(&plan.session)),
    ];
    // The keepalive is the standalone one, without its interpreter line: it is tested by itself, and the
    // same text is used here so the two cannot drift apart.
    let keepalive = crate::keepalive::script(&crate::keepalive::KeepalivePlan::default());
    let keepalive: String = keepalive.lines().skip(1).collect::<Vec<_>>().join("\n");
    let mut text = TEMPLATE.replace("@@KEEPALIVE@@", &keepalive);
    for (name, value) in &fills {
        text = text.replace(&format!("@@{name}@@"), value);
    }
    debug_assert!(!text.contains("@@"), "a placeholder was left unfilled");
    if text.contains("@@") {
        return Err(BootstrapError::Invalid("the script template"));
    }
    Ok(text)
}

// ------------------------------------------------------------------ the report

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportWire {
    version: u32,
    amneziawg: AwgWire,
    hysteria2: Hy2Wire,
    reality: RealityWire,
    session: SessionWire,
    cores: CoresWire,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionWire {
    /// The server's session public key, 32 bytes in standard base64. Public.
    server_public_key: String,
    port: u16,
    server_address: Ipv4Addr,
    devices: Vec<DeviceWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceWire {
    address: Ipv4Addr,
    /// The device key the server was given: ties this report to the script that made it.
    public_key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AwgWire {
    server_public_key_hex: String,
    listen_port: u16,
    client_address: Ipv4Addr,
    prefix_len: u8,
    /// The client key the server was given: ties this report to the script that made it.
    client_public_key_hex: String,
}

// `Debug` is deliberately not derived on the wire types: they hold secrets.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Hy2Wire {
    server_port: u16,
    server_name: String,
    spki_sha256_hex: String,
    auth_password: String,
    obfs_password: String,
    cert_key_algorithm: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RealityWire {
    server_port: u16,
    target_domain: String,
    public_key: String,
    short_id: String,
    uuid: String,
    flow: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoresWire {
    primary_core: CoreWire,
    amneziawg: CoreWire,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CoreWire {
    version: String,
    sha256: String,
}

/// Why a report was refused. No variant carries a value from the report: it holds secrets.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ReportError {
    #[error("the server printed no bootstrap report")]
    Missing,
    #[error("the server printed more than one bootstrap report")]
    Several,
    #[error("the bootstrap report is larger than {MAX_REPORT_BYTES} bytes")]
    TooLarge,
    #[error("the bootstrap report is malformed ({0})")]
    Malformed(&'static str),
    #[error("the bootstrap report is for format version {0}, which this version cannot read")]
    Version(u32),
    #[error("the bootstrap report has an invalid {0}")]
    Invalid(&'static str),
    /// The Hysteria 2 certificate is Ed25519 (T093: refused; Chrome QUIC mimicry cannot use it).
    #[error("the server made an Ed25519 certificate, which the Hysteria 2 profile cannot use")]
    Ed25519Certificate,
    /// The report says something other than what the client asked for.
    #[error("the server's report does not match what was asked for: {0}")]
    Mismatch(&'static str),
}

/// What the server reported, checked. The secrets are redacted from `Debug`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootstrapReport {
    awg_server_public_key_hex: String,
    awg_port: u16,
    awg_client_address: Ipv4Addr,
    awg_prefix_len: u8,
    awg_client_public_hex: String,
    hy2_port: u16,
    hy2_server_name: String,
    hy2_spki: [u8; 32],
    hy2_auth: Secret,
    hy2_obfs: Secret,
    reality_port: u16,
    reality_target: TargetDomain,
    reality_public_key: RealityPublicKey,
    reality_short_id: Secret,
    reality_uuid: Secret,
    session_server_public_key: String,
    session_port: u16,
    session_server_address: Ipv4Addr,
    session_devices: Vec<(Ipv4Addr, String)>,
    primary_sha256: String,
    primary_version: String,
    awg_sha256: String,
    awg_version: String,
}

fn is_hex(text: &str, even_len: std::ops::RangeInclusive<usize>) -> bool {
    even_len.contains(&text.len())
        && text.len().is_multiple_of(2)
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn is_uuid(text: &str) -> bool {
    let groups: Vec<&str> = text.split('-').collect();
    groups.len() == 5
        && [8, 4, 4, 4, 12]
            .iter()
            .zip(&groups)
            .all(|(len, g)| g.len() == *len && g.bytes().all(|b| b.is_ascii_hexdigit()))
}

impl BootstrapReport {
    /// Find the report in what the script printed and check it. Exactly one report line is expected.
    pub fn parse(output: &str) -> Result<Self, ReportError> {
        let mut lines = output
            .lines()
            .filter_map(|line| line.strip_prefix(REPORT_PREFIX));
        let json = lines.next().ok_or(ReportError::Missing)?;
        if lines.next().is_some() {
            return Err(ReportError::Several);
        }
        if json.len() > MAX_REPORT_BYTES {
            return Err(ReportError::TooLarge);
        }
        // serde can quote the offending text, and this text is full of secrets: say only where.
        let wire: ReportWire = serde_json::from_str(json).map_err(|e| {
            use serde_json::error::Category;
            ReportError::Malformed(match e.classify() {
                Category::Io => "unreadable",
                Category::Syntax => "not valid JSON",
                Category::Data => "a field is missing, unknown or of the wrong type",
                Category::Eof => "ends unexpectedly",
            })
        })?;
        if wire.version != REPORT_VERSION {
            return Err(ReportError::Version(wire.version));
        }

        let a = wire.amneziawg;
        if !is_hex(&a.server_public_key_hex, 64..=64) {
            return Err(ReportError::Invalid("AmneziaWG public key"));
        }
        if a.listen_port == 0 || !(16..=30).contains(&a.prefix_len) {
            return Err(ReportError::Invalid("AmneziaWG address or port"));
        }
        if !is_hex(&a.client_public_key_hex, 64..=64) {
            return Err(ReportError::Invalid("AmneziaWG client key"));
        }

        let h = wire.hysteria2;
        let algorithm = h.cert_key_algorithm.to_ascii_lowercase();
        if algorithm.contains("ed25519") {
            return Err(ReportError::Ed25519Certificate);
        }
        if !(algorithm.starts_with("ecdsa") || algorithm.starts_with("rsa")) {
            return Err(ReportError::Invalid("certificate key algorithm"));
        }
        let spki = parse_spki_sha256_hex(&h.spki_sha256_hex)
            .ok_or(ReportError::Invalid("certificate pin"))?;
        if h.server_port == 0 || h.server_name.is_empty() {
            return Err(ReportError::Invalid("Hysteria 2 port or name"));
        }
        if h.auth_password.len() < 16 || h.obfs_password.len() < 16 {
            return Err(ReportError::Invalid("Hysteria 2 secrets"));
        }
        if h.auth_password == h.obfs_password {
            return Err(ReportError::Invalid(
                "Hysteria 2 secrets (they must differ)",
            ));
        }

        let r = wire.reality;
        if r.server_port == 0 {
            return Err(ReportError::Invalid("REALITY port"));
        }
        if !is_hex(&r.short_id, 2..=16) {
            return Err(ReportError::Invalid("REALITY short id"));
        }
        if !is_uuid(&r.uuid) {
            return Err(ReportError::Invalid("REALITY user id"));
        }
        if r.flow != "xtls-rprx-vision" {
            return Err(ReportError::Invalid("REALITY flow"));
        }
        let reality_target = TargetDomain::parse(&r.target_domain)
            .map_err(|_| ReportError::Invalid("REALITY target"))?;
        let reality_public_key = RealityPublicKey::parse(&r.public_key)
            .map_err(|_| ReportError::Invalid("REALITY public key"))?;

        for sha in [
            &wire.cores.primary_core.sha256,
            &wire.cores.amneziawg.sha256,
        ] {
            if !is_hex(sha, 64..=64) {
                return Err(ReportError::Invalid("core checksum"));
            }
        }

        let s = wire.session;
        if !is_base64_key(&s.server_public_key) {
            return Err(ReportError::Invalid("session public key"));
        }
        if s.port == 0 || s.server_address != SESSION_SERVER {
            return Err(ReportError::Invalid("session address or port"));
        }
        if s.devices.is_empty() || s.devices.len() > MAX_DEVICES {
            return Err(ReportError::Invalid("session devices"));
        }
        let mut session_devices = Vec::with_capacity(s.devices.len());
        for device in s.devices {
            if !is_base64_key(&device.public_key) {
                return Err(ReportError::Invalid("session device key"));
            }
            session_devices.push((device.address, device.public_key));
        }

        Ok(Self {
            awg_server_public_key_hex: a.server_public_key_hex,
            awg_port: a.listen_port,
            awg_client_address: a.client_address,
            awg_prefix_len: a.prefix_len,
            awg_client_public_hex: a.client_public_key_hex,
            hy2_port: h.server_port,
            hy2_server_name: h.server_name,
            hy2_spki: spki,
            hy2_auth: Secret::new(h.auth_password),
            hy2_obfs: Secret::new(h.obfs_password),
            reality_port: r.server_port,
            reality_target,
            reality_public_key,
            reality_short_id: Secret::new(r.short_id),
            reality_uuid: Secret::new(r.uuid),
            session_server_public_key: s.server_public_key,
            session_port: s.port,
            session_server_address: s.server_address,
            session_devices,
            primary_sha256: wire.cores.primary_core.sha256,
            primary_version: wire.cores.primary_core.version,
            awg_sha256: wire.cores.amneziawg.sha256,
            awg_version: wire.cores.amneziawg.version,
        })
    }

    /// The report must describe the machine that was asked for: the ports, the names, the tunnel address,
    /// and above all **the cores that were pinned** (PR-12: not whatever the server happens to run).
    pub fn check_against(&self, plan: &BootstrapPlan) -> Result<(), ReportError> {
        if self.awg_port != plan.ports.amneziawg_udp
            || self.hy2_port != plan.ports.hysteria2_udp
            || self.reality_port != plan.ports.reality_tcp
        {
            return Err(ReportError::Mismatch("the ports"));
        }
        if self.hy2_server_name != plan.hysteria2_server_name {
            return Err(ReportError::Mismatch("the Hysteria 2 server name"));
        }
        if self.reality_target != plan.reality_target {
            return Err(ReportError::Mismatch("the REALITY target"));
        }
        if self.awg_client_address != TUNNEL_CLIENT || self.awg_prefix_len != TUNNEL_PREFIX {
            return Err(ReportError::Mismatch("the tunnel address"));
        }
        if self.awg_client_public_hex != plan.awg_client_public_hex {
            return Err(ReportError::Mismatch("the client key"));
        }
        // The session: the port, the server's address, and exactly the devices that were asked for, with the
        // addresses they were to get, in order. A report that lists a device nobody asked for is refused.
        if self.session_port != SESSION_PORT || self.session_server_address != SESSION_SERVER {
            return Err(ReportError::Mismatch("the session address"));
        }
        let asked: Vec<(Ipv4Addr, &str)> = plan.session.devices().collect();
        let told: Vec<(Ipv4Addr, &str)> = self
            .session_devices
            .iter()
            .map(|(address, key)| (*address, key.as_str()))
            .collect();
        if asked != told {
            return Err(ReportError::Mismatch("the session devices"));
        }
        if self.primary_sha256 != plan.cores.primary_core.sha256
            || self.primary_version != plan.cores.primary_core.version
            || self.awg_sha256 != plan.cores.amneziawg.sha256
            || self.awg_version != plan.cores.amneziawg.version
        {
            return Err(ReportError::Mismatch("the installed cores"));
        }
        Ok(())
    }

    /// The server's session public key (32 bytes, standard base64). Public.
    pub fn session_server_public_key(&self) -> &str {
        &self.session_server_public_key
    }

    /// The address device number `index` has inside the session, if the server reported that many.
    pub fn session_device_address(&self, index: usize) -> Option<Ipv4Addr> {
        self.session_devices.get(index).map(|(address, _)| *address)
    }

    /// The credentials for the three profiles this endpoint serves, and the session over the carriers. `keys` is
    /// the client's own AmneziaWG key pair; `session_keys` is this device's session key pair (the device that the
    /// plan listed first, whose public half went into the script); `obfuscation` is the set that was put in the
    /// script; `origin` is where probes will fetch from.
    pub fn credentials(
        &self,
        keys: &ClientKeys,
        session_keys: &SessionKeys,
        obfuscation: ObfuscationParams,
        origin: Option<Origin>,
    ) -> EndpointCredentials {
        EndpointCredentials {
            session: self
                .session_devices
                .first()
                .map(|(address, _)| SessionBundle {
                    device_private_key: Secret::new(session_keys.private_b64()),
                    server_public_key: self.session_server_public_key.clone(),
                    device_address: *address,
                    session_port: self.session_port,
                }),
            amneziawg: Some(AmneziaWgCredentials {
                client_private_key: PrivateKey::new(keys.private_hex()),
                server_public_key: self.awg_server_public_key_hex.clone(),
                client_address: self.awg_client_address,
                prefix_len: self.awg_prefix_len,
                obfuscation,
                server_port: self.awg_port,
            }),
            hysteria2: Some(Hysteria2Bundle {
                server_port: self.hy2_port,
                credentials: Hysteria2Credentials {
                    auth_password: self.hy2_auth.clone(),
                    obfs_password: self.hy2_obfs.clone(),
                },
                endpoint: Hysteria2EndpointParams {
                    obfs: Hysteria2Obfs::Salamander,
                    trust: ServerTrust::PinnedPublicKey {
                        server_name: self.hy2_server_name.clone(),
                        spki_sha256: self.hy2_spki,
                    },
                },
            }),
            reality: Some(RealityBundle {
                server_port: self.reality_port,
                credentials: RealityCredentials {
                    uuid: self.reality_uuid.clone(),
                    short_id: self.reality_short_id.clone(),
                },
                endpoint: RealityEndpointParams {
                    target_domain: self.reality_target.clone(),
                    public_key: self.reality_public_key.clone(),
                    flow: VlessFlow::Vision,
                },
            }),
            measure_origin: origin,
        }
    }
}

#[cfg(test)]
mod tests;
