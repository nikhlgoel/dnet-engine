// SPDX-License-Identifier: GPL-3.0-or-later
//! T188 — who may use a server: the server's own list of devices, and the scripts that add or take away one.
//!
//! A device is a key. The server holds only the public half; the private half is made on the device and never
//! leaves it. Before this, the list was baked into the script that set the server up, a device's address was its
//! place in that list, and running the script again replaced the list. That cannot work for friends: a friend added
//! later would be dropped by the next run, and taking one away would move everyone after them to another address,
//! breaking their configuration. So the list now lives **on the server**, in `devices.json`, kept by one small
//! program, `dnet-devices`, that every script installs and uses:
//!
//! - an address is given once and never changes or is given to another device;
//! - the setup script only ever **adds** to the list (so it can be run again at any time);
//! - one script adds one device, another takes one away, a third lists them, and each reports in one line;
//! - the new configuration is written beside the old and checked by the core itself first, and both the list and
//!   the configuration are replaced together only if it accepts it, so a refusal leaves the server as it was;
//! - the configuration is changed as text, in exactly the form the setup script writes, so the setup script does not
//!   see a difference and restart the server for nothing.

use std::net::Ipv4Addr;

use dnet_config::invite::valid_name;
use dnet_config::session::{session_device_address, MAX_DEVICES};
use serde::{Deserialize, Serialize};

/// What a device request starts with.
pub const REQUEST_PREFIX: &str = "DNET-DEVICE-REQUEST ";

/// What the add, remove and list scripts print their result after.
pub const REPORT_PREFIX: &str = "DNET-DEVICE-REPORT ";

/// The most pasted text that is looked at for a request or a report.
pub const MAX_PASTE_LEN: usize = 16 * 1024;

/// Why a request or a report was refused. Never repeats what was pasted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeviceError {
    #[error("that is not a device request")]
    NotARequest,
    #[error("that is not the result of a device script")]
    NotAReport,
    #[error("that is too long")]
    TooLarge,
    #[error("the device name is not allowed: use 1 to 32 letters, digits, spaces, dots, dashes or underscores")]
    Name,
    #[error("the device key is not valid")]
    Key,
    #[error(
        "the result is not the one for this device: it comes from another script or another device"
    )]
    Mismatch,
}

/// 32 bytes in standard base64: a device's public key as the core prints and takes it.
#[must_use]
pub fn is_device_key(text: &str) -> bool {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    // 32 bytes, and not the all-zero key: that one is the placeholder an invite carries, never a real key.
    text.len() == 44
        && STANDARD
            .decode(text)
            .is_ok_and(|b| b.len() == 32 && b.iter().any(|x| *x != 0))
}

// ------------------------------------------------------------------ the request

/// What a friend's computer sends the owner: a name and the public half of a key made on that computer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRequest {
    version: u32,
    name: String,
    public_key: String,
}

impl DeviceRequest {
    pub fn new(name: &str, public_key: &str) -> Result<Self, DeviceError> {
        if !valid_name(name) {
            return Err(DeviceError::Name);
        }
        if !is_device_key(public_key) {
            return Err(DeviceError::Key);
        }
        Ok(Self {
            version: 1,
            name: name.to_owned(),
            public_key: public_key.to_owned(),
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[must_use]
    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    /// The line to send: public material only.
    #[must_use]
    pub fn encode(&self) -> String {
        format!(
            "{REQUEST_PREFIX}{}",
            serde_json::to_string(self).unwrap_or_default()
        )
    }

    /// Read a request out of pasted text (other lines around it are ignored). Strict about every field.
    pub fn decode(pasted: &str) -> Result<Self, DeviceError> {
        if pasted.len() > MAX_PASTE_LEN {
            return Err(DeviceError::TooLarge);
        }
        let json = line_after(pasted, REQUEST_PREFIX).ok_or(DeviceError::NotARequest)?;
        let wire: Self = serde_json::from_str(json).map_err(|_| DeviceError::NotARequest)?;
        if wire.version != 1 {
            return Err(DeviceError::NotARequest);
        }
        Self::new(&wire.name, &wire.public_key)
    }
}

/// The rest of the first line of `text` that holds `prefix`, from just after it.
fn line_after<'a>(text: &'a str, prefix: &str) -> Option<&'a str> {
    text.lines()
        .find_map(|line| line.find(prefix).map(|at| line[at + prefix.len()..].trim()))
}

// ------------------------------------------------------------------ the reports

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReportWire {
    version: u32,
    action: String,
    #[serde(default)]
    public_key: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    address: Option<Ipv4Addr>,
    #[serde(default)]
    added: Option<bool>,
    #[serde(default)]
    removed: Option<bool>,
    #[serde(default)]
    server_public_key: Option<String>,
    #[serde(default)]
    port: Option<u16>,
    #[serde(default)]
    devices: Option<u32>,
    #[serde(default)]
    list: Option<Vec<ListedDevice>>,
}

/// One device as the server lists it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ListedDevice {
    pub address: Ipv4Addr,
    pub public_key: String,
    pub name: String,
}

/// What the server said after an add: the address the device has, and the server's session key and port, which must
/// be the ones the owner already holds for this server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceAdded {
    pub public_key: String,
    pub name: String,
    pub address: Ipv4Addr,
    pub server_public_key: String,
    pub port: u16,
    pub devices: u32,
    /// Whether the device was new: asking again for one the server already has is not an error.
    pub added: bool,
}

fn report_of(pasted: &str) -> Result<ReportWire, DeviceError> {
    if pasted.len() > MAX_PASTE_LEN {
        return Err(DeviceError::TooLarge);
    }
    let json = line_after(pasted, REPORT_PREFIX).ok_or(DeviceError::NotAReport)?;
    let wire: ReportWire = serde_json::from_str(json).map_err(|_| DeviceError::NotAReport)?;
    if wire.version != 1 {
        return Err(DeviceError::NotAReport);
    }
    Ok(wire)
}

impl DeviceAdded {
    /// [`parse`](Self::parse), and the server key and port in it must be the ones the owner already holds for this
    /// server: a report that names another key would hand the friend a session that is not the owner's.
    pub fn parse_for_server(
        pasted: &str,
        request: &DeviceRequest,
        server_public_key: &str,
        port: u16,
    ) -> Result<Self, DeviceError> {
        let added = Self::parse(pasted, request)?;
        if added.server_public_key != server_public_key || added.port != port {
            return Err(DeviceError::Mismatch);
        }
        Ok(added)
    }

    /// Read the result of an add script, and check it is for `request`: the same key and the same name, an address a
    /// device can have, and a server key that is a key.
    pub fn parse(pasted: &str, request: &DeviceRequest) -> Result<Self, DeviceError> {
        let wire = report_of(pasted)?;
        if wire.action != "add" {
            return Err(DeviceError::Mismatch);
        }
        let (
            Some(key),
            Some(name),
            Some(address),
            Some(server),
            Some(port),
            Some(devices),
            Some(added),
        ) = (
            wire.public_key,
            wire.name,
            wire.address,
            wire.server_public_key,
            wire.port,
            wire.devices,
            wire.added,
        )
        else {
            return Err(DeviceError::NotAReport);
        };
        if key != request.public_key || name != request.name {
            return Err(DeviceError::Mismatch);
        }
        if !dnet_config::session::is_device_address(address)
            || !is_device_key(&server)
            || port == 0
            || devices == 0
            || devices as usize > MAX_DEVICES
        {
            return Err(DeviceError::NotAReport);
        }
        Ok(Self {
            public_key: key,
            name,
            address,
            server_public_key: server,
            port,
            devices,
            added,
        })
    }
}

/// What the server said after a removal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRemoved {
    pub public_key: String,
    /// Whether the device was on the list: removing one that is not is not an error.
    pub removed: bool,
    pub devices: u32,
}

impl DeviceRemoved {
    pub fn parse(pasted: &str, public_key: &str) -> Result<Self, DeviceError> {
        let wire = report_of(pasted)?;
        if wire.action != "remove" {
            return Err(DeviceError::Mismatch);
        }
        let (Some(key), Some(removed), Some(devices)) =
            (wire.public_key, wire.removed, wire.devices)
        else {
            return Err(DeviceError::NotAReport);
        };
        if key != public_key {
            return Err(DeviceError::Mismatch);
        }
        Ok(Self {
            public_key: key,
            removed,
            devices,
        })
    }
}

/// The devices the server lists.
pub fn parse_list(pasted: &str) -> Result<Vec<ListedDevice>, DeviceError> {
    let wire = report_of(pasted)?;
    if wire.action != "list" {
        return Err(DeviceError::Mismatch);
    }
    let list = wire.list.ok_or(DeviceError::NotAReport)?;
    if list.len() > MAX_DEVICES
        || list.iter().any(|d| {
            !is_device_key(&d.public_key)
                || !valid_name(&d.name)
                || !dnet_config::session::is_device_address(d.address)
        })
    {
        return Err(DeviceError::NotAReport);
    }
    Ok(list)
}

// ------------------------------------------------------------------ the program that keeps the list

/// The program the scripts install on the server as `/opt/dnet/bin/dnet-devices`. `@@NAME@@` marks a value from
/// the session's own constants, so the program and the client cannot disagree about an address.
const PROGRAM: &str = r##"#!/usr/bin/env python3
# dnet-devices: this server's list of devices, and the session's peers made from it. Written by DNet Engine.
# A device is its public key. Every device keeps the address it was first given; the list only grows and shrinks one
# device at a time, and a change is written beside the old files and replaced together only after the core accepted it.
import base64
import json
import os
import sys

try:
    import fcntl
except ImportError:  # not on the server; the client's tests run this on other systems too
    fcntl = None

MAX_DEVICES = @@MAX_DEVICES@@
PREFIX = "@@ADDRESS_PREFIX@@"
FIRST = @@FIRST_HOST@@
NAME_CHARS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ._-"


def fail(code, message):
    sys.stderr.write(message + "\n")
    sys.exit(code)


def key_ok(key):
    if len(key) != 44:
        return False
    try:
        raw = base64.b64decode(key, validate=True)
    except Exception:
        return False
    # 32 bytes, and not the all-zero key (the placeholder an invite carries, never a real key).
    return len(raw) == 32 and raw != bytes(32)


def name_ok(name):
    return 1 <= len(name) <= 32 and name == name.strip() and all(c in NAME_CHARS for c in name)


def address(index):
    return "%s%d" % (PREFIX, FIRST + index)


ADDRESSES = [address(i) for i in range(MAX_DEVICES)]


class Registry:
    """The list, held under a lock so two runs cannot interleave."""

    def __init__(self, path):
        self.path = path
        self.lock = None

    def __enter__(self):
        if fcntl is not None:
            self.lock = os.open(self.path + ".lock", os.O_CREAT | os.O_RDWR, 0o600)
            fcntl.flock(self.lock, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        if self.lock is not None:
            os.close(self.lock)
        return False

    def exists(self):
        return os.path.exists(self.path)

    def load(self):
        try:
            with open(self.path, "r") as f:
                data = json.load(f)
            devices = data["devices"]
            seen_keys, seen_addresses, seen_names = set(), set(), set()
            for d in devices:
                if sorted(d.keys()) != ["address", "name", "public_key"]:
                    raise ValueError("fields")
                if d["address"] not in ADDRESSES or not key_ok(d["public_key"]) or not name_ok(d["name"]):
                    raise ValueError("value")
                if d["public_key"] in seen_keys or d["address"] in seen_addresses or d["name"] in seen_names:
                    raise ValueError("duplicate")
                seen_keys.add(d["public_key"])
                seen_addresses.add(d["address"])
                seen_names.add(d["name"])
            return devices
        except Exception:
            fail(7, "the list of devices on this server is damaged; it was not changed. Look at %s" % self.path)


def peers_text(devices):
    return ",\n".join(
        '        { "public_key": "%s", "allowed_ips": [ "%s/32" ] }' % (d["public_key"], d["address"])
        for d in devices
    )


def write_new(path, text):
    new = path + ".new"
    fd = os.open(new, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", newline="") as f:  # exactly the text given, on any system
        f.write(text)
    return new


def registry_text(devices):
    return json.dumps({"version": 1, "devices": devices}, indent=2) + "\n"


PEERS_START = '"peers": [\n'
PEERS_END = "\n      ]"


def config_with(config_path, devices):
    """The configuration with its session peers replaced: text, in the form the setup script writes."""
    with open(config_path, "r", newline="") as f:  # exactly the text there is, on any system
        text = f.read()
    start = text.find(PEERS_START)
    if start < 0 or text.count(PEERS_START) != 1:
        fail(7, "the server's configuration is not in the form this program changes; it was not changed")
    start += len(PEERS_START)
    end = text.find(PEERS_END, start)
    if end < 0:
        fail(7, "the server's configuration is not in the form this program changes; it was not changed")
    out = text[:start] + peers_text(devices) + text[end:]
    try:
        json.loads(out)
    except Exception:
        fail(7, "the new configuration would not be valid; nothing was changed")
    return out


def import_from_config(config_path):
    """A server set up before the list existed: its devices are the peers its configuration has."""
    if not os.path.exists(config_path):
        return []
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
        peers = []
        for endpoint in config.get("endpoints", []):
            if endpoint.get("tag") == "session-in":
                peers = endpoint.get("peers", [])
        devices = []
        for i, peer in enumerate(peers):
            addr = peer["allowed_ips"][0].split("/")[0]
            devices.append({"address": addr, "public_key": peer["public_key"],
                            "name": "first device" if i == 0 else "device %d" % (i + 1)})
    except Exception:
        fail(7, "the server's configuration could not be read; nothing was changed")
    # What is taken in must meet the same rules as what load() accepts, or the list would be written damaged.
    if (len(devices) > MAX_DEVICES
            or len(set(d["address"] for d in devices)) != len(devices)
            or len(set(d["public_key"] for d in devices)) != len(devices)
            or any(d["address"] not in ADDRESSES or not key_ok(d["public_key"]) for d in devices)):
        fail(7, "the server's configuration holds devices this program does not recognise; nothing was changed")
    return devices


def first_free(devices):
    used = set(d["address"] for d in devices)
    for a in ADDRESSES:
        if a not in used:
            return a
    return None


def stage(registry, config_path, devices):
    """Write the new list and configuration beside the old ones."""
    write_new(registry.path, registry_text(devices))
    write_new(config_path, config_with(config_path, devices))


def main(argv):
    if len(argv) < 3:
        fail(2, "usage: dnet-devices <sync|peers|json|list|add|remove|commit|discard> <list file> ...")
    command, path = argv[1], argv[2]
    rest = argv[3:]
    with Registry(path) as r:
        if command == "sync":
            # sync <list> <config> <key>...: make sure the list exists, and holds these keys.
            config_path, keys = rest[0], rest[1:]
            devices = r.load() if r.exists() else import_from_config(config_path)
            before = json.dumps(devices)
            for key in keys:
                if not key_ok(key):
                    fail(2, "a device key is not valid")
                if key not in [d["public_key"] for d in devices]:
                    free = first_free(devices)
                    if free is None:
                        fail(6, "this server already has the most devices it can have")
                    devices.append({"address": free, "public_key": key,
                                    "name": "first device" if not devices else "device %d" % (len(devices) + 1)})
            if not r.exists() or json.dumps(devices) != before:
                write_new(path, registry_text(devices))
                os.replace(path + ".new", path)
            return
        if command == "peers":
            print(peers_text(r.load()))
            return
        if command == "json":
            print(json.dumps([{"address": d["address"], "public_key": d["public_key"]} for d in r.load()], separators=(",", ":")))
            return
        if command == "list":
            print(json.dumps([{"address": d["address"], "public_key": d["public_key"], "name": d["name"]} for d in r.load()], separators=(",", ":")))
            return
        if command == "add":
            # add <list> <config> <key> <name>: stage the new list and configuration (always, so a half-done run is repaired).
            config_path, key, name = rest[0], rest[1], rest[2]
            if not key_ok(key):
                fail(2, "the device key is not valid")
            if not name_ok(name):
                fail(2, "the device name is not allowed")
            devices = r.load() if r.exists() else import_from_config(config_path)
            existing = [d for d in devices if d["public_key"] == key]
            if existing:
                device, added = existing[0], False
            else:
                if any(d["name"] == name for d in devices):
                    fail(5, "a device called that is already on this server; choose another name")
                free = first_free(devices)
                if free is None:
                    fail(6, "this server already has the most devices it can have (%d); remove one first" % MAX_DEVICES)
                device, added = {"address": free, "public_key": key, "name": name}, True
                devices = devices + [device]
            stage(r, config_path, devices)
            print(json.dumps({"address": device["address"], "name": device["name"], "devices": len(devices), "added": added}))
            return
        if command == "remove":
            config_path, key = rest[0], rest[1]
            if not key_ok(key):
                fail(2, "the device key is not valid")
            devices = r.load() if r.exists() else import_from_config(config_path)
            kept = [d for d in devices if d["public_key"] != key]
            if not kept:
                fail(5, "that is the only device on this server; removing it would leave nobody able to use it")
            stage(r, config_path, kept)
            print(json.dumps({"removed": len(kept) != len(devices), "devices": len(kept)}))
            return
        if command == "commit":
            config_path = rest[0]
            os.replace(path + ".new", path)
            os.replace(config_path + ".new", config_path)
            return
        if command == "discard":
            config_path = rest[0]
            for p in (path + ".new", config_path + ".new"):
                if os.path.exists(p):
                    os.remove(p)
            return
        fail(2, "unknown command")


main(sys.argv)
"##;

/// The program, with the session's own constants filled in.
#[must_use]
pub fn program() -> String {
    let first = session_device_address(0);
    let octets = first.octets();
    PROGRAM
        .replace("@@MAX_DEVICES@@", &MAX_DEVICES.to_string())
        .replace(
            "@@ADDRESS_PREFIX@@",
            &format!("{}.{}.{}.", octets[0], octets[1], octets[2]),
        )
        .replace("@@FIRST_HOST@@", &octets[3].to_string())
}

// ------------------------------------------------------------------ the scripts

/// The head every device script shares: root, a DNet server, python, and the program installed.
fn head(what: &str) -> String {
    format!(
        r##"#!/bin/sh
# DNet Engine: {what}. Generated by the client; it holds no secret.
set -eu
umask 077
# A dropped connection must not stop the script half way: the files are swapped as one step, and so is the restart.
trap '' HUP
BIN=/opt/dnet/bin
STATE=/var/lib/dnet
[ "$(id -u)" = 0 ] || {{ echo "run this as root: put sudo in front of it, or log in as root" >&2; exit 2; }}
[ -x "$BIN/primary-core" ] && [ -s "$STATE/primary/server.json" ] \
  || {{ echo "this does not look like a DNet Engine server (no program or no configuration): set it up first" >&2; exit 2; }}
command -v python3 >/dev/null 2>&1 || {{ echo "python3 is needed on this server" >&2; exit 2; }}
# One of these scripts at a time, from staging to restart (the setup script takes the same lock).
if command -v flock >/dev/null 2>&1; then
  exec 9>"$STATE/primary/.script.lock"
  flock 9
fi
cat > "$BIN/dnet-devices" <<'DEVICES_EOF'
{program}
DEVICES_EOF
chmod 755 "$BIN/dnet-devices"
REG="$STATE/primary/devices.json"
CONFIG="$STATE/primary/server.json"
"##,
        program = program().trim_end()
    )
}

/// What every script that changes the list does after the program has staged the new files: the core checks the new
/// configuration, and only then are the list and the configuration replaced together; the server is restarted only if
/// the configuration changed.
const APPLY: &str = r##"if ! "$BIN/primary-core" check -c "$CONFIG.new" >/dev/null 2>&1; then
  python3 "$BIN/dnet-devices" discard "$REG" "$CONFIG"
  echo "the core rejected the new list of devices; nothing was changed on this server" >&2
  exit 5
fi
if cmp -s "$CONFIG.new" "$CONFIG"; then CHANGED=0; else CHANGED=1; fi
# Set who may read the new files before they take the old ones' place, so the core is never left unable to read.
chown root:dnet "$REG.new" "$CONFIG.new"
chmod 640 "$REG.new" "$CONFIG.new"
python3 "$BIN/dnet-devices" commit "$REG" "$CONFIG"
# The core runs as an account that may read what it needs and may replace nothing here.
chown -R root:dnet "$STATE/primary"
chmod 750 "$STATE/primary"
find "$STATE/primary" -type f -exec chmod 640 {} +
# A removal always restarts: a run that was cut off after the swap must still end the removed device's session.
if [ "$CHANGED" = 1 ] || [ "${FORCE_RESTART:-0}" = 1 ]; then systemctl restart dnet-primary.service; fi
"##;

fn safe_for_script(text: &str) -> bool {
    text.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '-' | '_' | '+' | '/' | '='))
}

/// The script that adds the device in `request` and says which address it has.
#[must_use]
pub fn add_device_script(request: &DeviceRequest) -> String {
    debug_assert!(safe_for_script(&request.public_key) && safe_for_script(&request.name));
    let session_port = dnet_config::session::SESSION_PORT;
    format!(
        r##"{head}
RESULT=$(python3 "$BIN/dnet-devices" add "$REG" "$CONFIG" '{key}' '{name}')
{APPLY}SESSION_PUBLIC=$(tr -d '[:space:]' < "$STATE/primary/session.public")
RESULT="$RESULT" SESSION_PUBLIC="$SESSION_PUBLIC" KEY='{key}' NAME='{name}' python3 - <<'REPORT_EOF'
import json, os
e = os.environ
r = json.loads(e["RESULT"])
print("DNET-DEVICE-REPORT " + json.dumps({{
    "version": 1, "action": "add", "public_key": e["KEY"], "name": e["NAME"], "address": r["address"],
    "added": r["added"], "server_public_key": e["SESSION_PUBLIC"], "port": {session_port}, "devices": r["devices"],
}}, separators=(",", ":")))
REPORT_EOF
"##,
        head = head("add a device"),
        key = request.public_key,
        name = request.name,
    )
}

/// The script that takes the device with `public_key` off the server. Removing one that is not there is not an error.
pub fn remove_device_script(public_key: &str) -> Result<String, DeviceError> {
    if !is_device_key(public_key) || !safe_for_script(public_key) {
        return Err(DeviceError::Key);
    }
    Ok(format!(
        r##"{head}
FORCE_RESTART=1
RESULT=$(python3 "$BIN/dnet-devices" remove "$REG" "$CONFIG" '{key}')
{APPLY}RESULT="$RESULT" KEY='{key}' python3 - <<'REPORT_EOF'
import json, os
e = os.environ
r = json.loads(e["RESULT"])
print("DNET-DEVICE-REPORT " + json.dumps({{
    "version": 1, "action": "remove", "public_key": e["KEY"], "removed": r["removed"], "devices": r["devices"],
}}, separators=(",", ":")))
REPORT_EOF
"##,
        head = head("take a device off"),
        key = public_key,
    ))
}

/// The script that lists the devices on the server. It changes nothing.
#[must_use]
pub fn list_devices_script() -> String {
    format!(
        r##"{head}
LIST=$(python3 "$BIN/dnet-devices" list "$REG")
LIST="$LIST" python3 - <<'REPORT_EOF'
import json, os
print("DNET-DEVICE-REPORT " + json.dumps({{"version": 1, "action": "list", "list": json.loads(os.environ["LIST"])}}, separators=(",", ":")))
REPORT_EOF
"##,
        head = head("list the devices"),
    )
}

#[cfg(test)]
mod tests;
