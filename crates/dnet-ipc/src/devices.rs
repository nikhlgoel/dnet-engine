// SPDX-License-Identifier: GPL-3.0-or-later
//! T188 — the wire form of adding a friend's device to the person's own server (ADR-0008 "Share a server").
//!
//! A friend's computer makes its own key and answers `RequestJoin` with a short text (a name and the public half
//! of that key). The owner gives it to `PrepareDevice`, which answers with a script for their server; the script
//! prints a result, and `FinishDevice` turns that result into an invite. The friend pastes the invite into
//! `AcceptInvite`, which adds the server with the key that never left the friend's computer.
//!
//! Everything a reply carries is read by the window as untrusted input: a text that is not what was promised is
//! refused, not shown. The checks here are shape and size only; what the texts mean is the service's to decide.

use serde_json::{json, Map, Value};

use crate::protocol::IpcError;

/// The longest request text a reply may carry or a person may paste: a name and a key, with some room.
pub const MAX_REQUEST_CHARS: usize = 16 * 1024;
/// The longest invite a reply may carry (the invite's own limit).
pub const MAX_INVITE_CHARS: usize = dnet_config::invite::MAX_PASTE_LEN;
/// The longest script a reply may carry.
pub const MAX_SCRIPT_CHARS: usize = 64 * 1024;
/// The longest a prepared request waits for its result, in seconds (a day).
pub const MAX_VALID_FOR_S: u64 = 86_400;

/// What a request text starts with.
pub const REQUEST_PREFIX: &str = "DNET-DEVICE-REQUEST ";
/// What an invite starts with.
pub const INVITE_PREFIX: &str = dnet_config::invite::PREFIX;

/// What `RequestJoin` answers with: the text the friend sends to the owner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinRequested {
    /// The name this device gave itself.
    pub name: String,
    /// The text to send: its name and the public half of a key made on this computer. It holds no secret.
    pub text: String,
    /// How long the service keeps the key waiting for the invite.
    pub valid_for_s: u64,
}

/// What `PrepareDevice` answers with: the script that adds the device on the server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePrepared {
    /// The device's name, as the owner will see it again.
    pub name: String,
    pub script: String,
    /// How long the service keeps this waiting for what the script prints.
    pub valid_for_s: u64,
}

/// What `FinishDevice` answers with: the invite to send back to the friend.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInvited {
    pub name: String,
    /// The address the server gave the device inside its private network.
    pub address: String,
    /// The invite. It holds the server's access details, never a private key of the friend's or the owner's.
    pub invite: String,
}

fn invalid(detail: impl Into<String>) -> IpcError {
    IpcError::InvalidRequest {
        detail: detail.into(),
    }
}

fn object(wire: &str) -> Result<Map<String, Value>, IpcError> {
    match serde_json::from_str::<Value>(wire) {
        Ok(Value::Object(o)) => Ok(o),
        Ok(_) => Err(invalid("the reply is not an object")),
        Err(_) => Err(invalid("the reply is not JSON")),
    }
}

fn text_field<'a>(o: &'a Map<String, Value>, name: &str, max: usize) -> Result<&'a str, IpcError> {
    o.get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.chars().count() <= max)
        .ok_or_else(|| invalid(format!("`{name}` is missing, empty or too large")))
}

fn name_field(o: &Map<String, Value>) -> Result<&str, IpcError> {
    o.get("name")
        .and_then(Value::as_str)
        .filter(|n| dnet_config::invite::valid_name(n))
        .ok_or_else(|| invalid("`name` is missing or not an allowed name"))
}

fn valid_for(o: &Map<String, Value>) -> Result<u64, IpcError> {
    o.get("valid_for_s")
        .and_then(Value::as_u64)
        .filter(|s| (1..=MAX_VALID_FOR_S).contains(s))
        .ok_or_else(|| invalid("`valid_for_s` is missing or out of range"))
}

pub fn encode_join_requested(reply: &JoinRequested) -> String {
    json!({ "name": reply.name, "text": reply.text, "valid_for_s": reply.valid_for_s }).to_string()
}

pub fn decode_join_requested(wire: &str) -> Result<JoinRequested, IpcError> {
    let o = object(wire)?;
    let text = text_field(&o, "text", MAX_REQUEST_CHARS)?;
    if !text.starts_with(REQUEST_PREFIX) || text.chars().any(char::is_control) {
        return Err(invalid("`text` is not a device request"));
    }
    Ok(JoinRequested {
        name: name_field(&o)?.to_owned(),
        text: text.to_owned(),
        valid_for_s: valid_for(&o)?,
    })
}

pub fn encode_device_prepared(reply: &DevicePrepared) -> String {
    json!({ "name": reply.name, "script": reply.script, "valid_for_s": reply.valid_for_s })
        .to_string()
}

pub fn decode_device_prepared(wire: &str) -> Result<DevicePrepared, IpcError> {
    let o = object(wire)?;
    Ok(DevicePrepared {
        name: name_field(&o)?.to_owned(),
        script: text_field(&o, "script", MAX_SCRIPT_CHARS)?.to_owned(),
        valid_for_s: valid_for(&o)?,
    })
}

pub fn encode_device_invited(reply: &DeviceInvited) -> String {
    json!({ "name": reply.name, "address": reply.address, "invite": reply.invite }).to_string()
}

pub fn decode_device_invited(wire: &str) -> Result<DeviceInvited, IpcError> {
    let o = object(wire)?;
    let invite = text_field(&o, "invite", MAX_INVITE_CHARS)?;
    if !invite.starts_with(INVITE_PREFIX)
        || !invite[INVITE_PREFIX.len()..]
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(invalid("`invite` is not an invite"));
    }
    let address = text_field(&o, "address", 15)?;
    match address.parse::<std::net::Ipv4Addr>() {
        Ok(ip) if dnet_config::session::is_device_address(ip) => {}
        _ => return Err(invalid("`address` is not an address a device can have")),
    }
    Ok(DeviceInvited {
        name: name_field(&o)?.to_owned(),
        address: address.to_owned(),
        invite: invite.to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requested() -> JoinRequested {
        JoinRequested {
            name: "Ravi laptop".into(),
            text: format!("{REQUEST_PREFIX}{{\"version\":1}}"),
            valid_for_s: 3600,
        }
    }

    #[test]
    fn every_reply_round_trips() {
        let r = requested();
        assert_eq!(decode_join_requested(&encode_join_requested(&r)), Ok(r));
        let p = DevicePrepared {
            name: "Ravi laptop".into(),
            script: "#!/bin/sh\n".into(),
            valid_for_s: 60,
        };
        assert_eq!(decode_device_prepared(&encode_device_prepared(&p)), Ok(p));
        let i = DeviceInvited {
            name: "Ravi laptop".into(),
            address: "10.9.0.3".into(),
            invite: format!("{INVITE_PREFIX}abc-_123"),
        };
        assert_eq!(decode_device_invited(&encode_device_invited(&i)), Ok(i));
    }

    #[test]
    fn a_reply_that_is_not_what_was_promised_is_refused() {
        for wire in [
            "",
            "[]",
            "{}",
            r#"{"name":"x","text":"nope","valid_for_s":60}"#,
            r#"{"name":"bad'name","text":"DNET-DEVICE-REQUEST {}","valid_for_s":60}"#,
            r#"{"name":"x","text":"DNET-DEVICE-REQUEST {}","valid_for_s":0}"#,
            r#"{"name":"x","text":"DNET-DEVICE-REQUEST {}","valid_for_s":999999999}"#,
        ] {
            assert!(decode_join_requested(wire).is_err(), "{wire}");
        }
        for wire in [
            r#"{"name":"x","script":"","valid_for_s":60}"#,
            r#"{"name":"x","valid_for_s":60}"#,
            r#"{"name":"x","script":5,"valid_for_s":60}"#,
        ] {
            assert!(decode_device_prepared(wire).is_err(), "{wire}");
        }
        for wire in [
            r#"{"name":"x","address":"10.9.0.3","invite":"DNET-INVITE-1:ab cd"}"#,
            r#"{"name":"x","address":"10.9.0.3","invite":"nope"}"#,
            r#"{"name":"x","address":"not an address","invite":"DNET-INVITE-1:abc"}"#,
        ] {
            assert!(decode_device_invited(wire).is_err(), "{wire}");
        }
    }

    #[test]
    fn a_reply_over_its_size_is_refused() {
        let big = "x".repeat(MAX_SCRIPT_CHARS + 1);
        let wire = json!({ "name": "x", "script": big, "valid_for_s": 60 }).to_string();
        assert!(decode_device_prepared(&wire).is_err());
        let big = format!("{REQUEST_PREFIX}{}", "x".repeat(MAX_REQUEST_CHARS));
        let wire = json!({ "name": "x", "text": big, "valid_for_s": 60 }).to_string();
        assert!(decode_join_requested(&wire).is_err());
    }
}
