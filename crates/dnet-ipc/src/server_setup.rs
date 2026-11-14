// SPDX-License-Identifier: GPL-3.0-or-later
//! T150 — the wire form of setting up the person's own server (contracts/ipc-protocol.md IPC-26).
//!
//! `PrepareServer` asks the service for the setup script and the ports to open; the person runs the script
//! on their server, and `FinishServer` hands back what it printed. The service holds the keys in between.
//!
//! The reply to `PrepareServer` is read by the window as untrusted input (the other end of the pipe is not
//! trusted): a script or a port list that is not what was promised is refused, not shown.

use serde_json::{json, Map, Value};

use crate::protocol::IpcError;

/// The kind of processor the person's server has. The cores are built for one; the script checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerKind {
    /// Intel and AMD.
    Amd64,
    /// Arm.
    Arm64,
}

impl ServerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Amd64 => "amd64",
            Self::Arm64 => "arm64",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "amd64" => Some(Self::Amd64),
            "arm64" => Some(Self::Arm64),
            _ => None,
        }
    }
}

/// The longest text a person may paste back: what a server prints, with a prompt or two around it.
pub const MAX_REPORT_CHARS: usize = 32 * 1024;
/// The longest script a reply may carry.
pub const MAX_SCRIPT_CHARS: usize = 64 * 1024;
/// The most ports a reply may list.
pub const MAX_PORTS: usize = 8;
/// The longest a prepared setup may wait for its report, in seconds (a day).
pub const MAX_VALID_FOR_S: u64 = 86_400;

/// One port the person opens in their cloud network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortToOpen {
    /// `udp` or `tcp`.
    pub protocol: String,
    pub port: u16,
}

/// What `PrepareServer` answers with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prepared {
    pub arch: ServerKind,
    pub script: String,
    pub ports: Vec<PortToOpen>,
    /// How long the service keeps the keys waiting for the report.
    pub valid_for_s: u64,
}

fn invalid(detail: impl Into<String>) -> IpcError {
    IpcError::InvalidRequest {
        detail: detail.into(),
    }
}

pub fn encode_prepared(prepared: &Prepared) -> String {
    let ports: Vec<Value> = prepared
        .ports
        .iter()
        .map(|p| json!({ "protocol": p.protocol, "port": p.port }))
        .collect();
    let mut object = Map::new();
    object.insert("arch".into(), json!(prepared.arch.as_str()));
    object.insert("script".into(), json!(prepared.script));
    object.insert("ports".into(), Value::Array(ports));
    object.insert("valid_for_s".into(), json!(prepared.valid_for_s));
    Value::Object(object).to_string()
}

pub fn decode_prepared(wire: &str) -> Result<Prepared, IpcError> {
    let value: Value = serde_json::from_str(wire).map_err(|_| invalid("the reply is not JSON"))?;
    let o = value
        .as_object()
        .ok_or_else(|| invalid("the reply is not an object"))?;
    let arch = o
        .get("arch")
        .and_then(Value::as_str)
        .and_then(ServerKind::parse)
        .ok_or_else(|| invalid("`arch` is missing or unknown"))?;
    let script = o
        .get("script")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.chars().count() <= MAX_SCRIPT_CHARS)
        .ok_or_else(|| invalid("`script` is missing, empty or too large"))?;
    let list = o
        .get("ports")
        .and_then(Value::as_array)
        .filter(|l| !l.is_empty() && l.len() <= MAX_PORTS)
        .ok_or_else(|| invalid("`ports` is missing or not a short list"))?;
    let mut ports = Vec::with_capacity(list.len());
    for entry in list {
        let entry = entry
            .as_object()
            .ok_or_else(|| invalid("a port entry is not an object"))?;
        let protocol = entry
            .get("protocol")
            .and_then(Value::as_str)
            .filter(|p| matches!(*p, "udp" | "tcp"))
            .ok_or_else(|| invalid("a port has no protocol of udp or tcp"))?;
        let port = entry
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p != 0)
            .ok_or_else(|| invalid("a port is not between 1 and 65535"))?;
        ports.push(PortToOpen {
            protocol: protocol.to_owned(),
            port,
        });
    }
    let valid_for_s = o
        .get("valid_for_s")
        .and_then(Value::as_u64)
        .filter(|s| (1..=MAX_VALID_FOR_S).contains(s))
        .ok_or_else(|| invalid("`valid_for_s` is missing or out of range"))?;
    Ok(Prepared {
        arch,
        script: script.to_owned(),
        ports,
        valid_for_s,
    })
}
