//! T132 — the version of the control protocol, and the rule for when two ends can talk.
//!
//! The service and the programs that drive it (`dnetctl` now, the tray app later, anything else
//! someday) are installed and updated separately, so at some point they will not be the same
//! build. Docker's engine API handles this the same way: the engine reports the newest API version
//! it speaks and the oldest it still accepts, and a client checks that its own version lies in that
//! range before it does anything else. This is that, for the control pipe.
//!
//! - [`PROTOCOL_VERSION`] is the version this build speaks. It goes up when a change would break an
//!   existing client: a request or field removed or changed in meaning, a stricter rule an old
//!   client would trip over. Adding a request, or an optional field a client may ignore, does not
//!   change it.
//! - [`MIN_PROTOCOL_VERSION`] is the oldest client this build still serves. It is raised only when
//!   keeping compatibility is no longer worth its cost.
//! - A client with version `c` can talk to a service reporting `(min, newest)` when
//!   `min <= c <= newest`. Outside that range the answer says which end to update.
//!
//! The service answers `GetVersion` by itself, before any state is involved, to any authenticated
//! caller. The reply is read by a client as untrusted input, like every other reply: [`decode`] is
//! strict, and a service that sends nonsense is reported as one the client cannot read, not trusted.

use serde_json::{json, Value};

/// The protocol version this build speaks.
pub const PROTOCOL_VERSION: u32 = 1;

/// The oldest protocol version this build still serves.
pub const MIN_PROTOCOL_VERSION: u32 = 1;

// A build that serves a range it cannot speak, or a version below 1, does not compile.
const _: () = assert!(MIN_PROTOCOL_VERSION >= 1 && MIN_PROTOCOL_VERSION <= PROTOCOL_VERSION);

/// The longest `service_version` accepted from a service.
const MAX_SERVICE_VERSION_LEN: usize = 64;

/// What a service says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceVersion {
    /// The newest protocol version the service speaks.
    pub protocol: u32,
    /// The oldest protocol version the service still serves.
    pub min_protocol: u32,
    /// The build of the service, such as `0.1.0`. For people to read, never to decide on.
    pub service: String,
}

/// The reply to `GetVersion`, as the service writes it.
pub fn reply() -> String {
    json!({
        "protocol_version": PROTOCOL_VERSION,
        "min_protocol_version": MIN_PROTOCOL_VERSION,
        "service_version": env!("CARGO_PKG_VERSION"),
    })
    .to_string()
}

/// Read a `GetVersion` reply as untrusted input. `Err` says what was wrong, without echoing it.
pub fn decode(reply: &Value) -> Result<ServiceVersion, String> {
    let object = reply
        .as_object()
        .ok_or("the version is not a JSON object")?;
    let number = |key: &str| -> Result<u32, String> {
        object
            .get(key)
            .and_then(Value::as_u64)
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| *n >= 1)
            .ok_or_else(|| format!("`{key}` is not a version number"))
    };
    let protocol = number("protocol_version")?;
    let min_protocol = number("min_protocol_version")?;
    if min_protocol > protocol {
        return Err("the oldest version it serves is newer than the newest it speaks".to_owned());
    }
    let service = object
        .get("service_version")
        .and_then(Value::as_str)
        .filter(|s| {
            !s.is_empty()
                && s.len() <= MAX_SERVICE_VERSION_LEN
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+' | b'_'))
        })
        .ok_or("`service_version` is not a plain version string")?
        .to_owned();
    Ok(ServiceVersion {
        protocol,
        min_protocol,
        service,
    })
}

/// Why two ends cannot talk, and which one to update.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Incompatible {
    /// The client is older than the oldest the service serves.
    #[error(
        "this program is too old for the installed service (it speaks protocol {client}; the \
         service serves {min} to {newest}). Update this program."
    )]
    ClientTooOld { client: u32, min: u32, newest: u32 },
    /// The client is newer than the newest the service speaks.
    #[error(
        "this program is newer than the installed service (it speaks protocol {client}; the \
         service speaks up to {newest}). Update the DNet Engine service."
    )]
    ServiceTooOld { client: u32, min: u32, newest: u32 },
}

/// Whether a client speaking `client` can talk to `service`.
pub fn check(client: u32, service: &ServiceVersion) -> Result<(), Incompatible> {
    let (min, newest) = (service.min_protocol, service.protocol);
    if client < min {
        Err(Incompatible::ClientTooOld {
            client,
            min,
            newest,
        })
    } else if client > newest {
        Err(Incompatible::ServiceTooOld {
            client,
            min,
            newest,
        })
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(min: u32, newest: u32) -> ServiceVersion {
        ServiceVersion {
            protocol: newest,
            min_protocol: min,
            service: "0.1.0".into(),
        }
    }

    #[test]
    fn the_reply_decodes_to_what_this_build_speaks() {
        let value: Value = serde_json::from_str(&reply()).unwrap();
        let v = decode(&value).unwrap();
        assert_eq!(v.protocol, PROTOCOL_VERSION);
        assert_eq!(v.min_protocol, MIN_PROTOCOL_VERSION);
        assert_eq!(v.service, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn this_build_can_talk_to_itself() {
        let value: Value = serde_json::from_str(&reply()).unwrap();
        assert_eq!(check(PROTOCOL_VERSION, &decode(&value).unwrap()), Ok(()));
    }

    #[test]
    fn a_client_inside_the_range_can_talk_at_both_edges() {
        assert_eq!(check(3, &service(3, 5)), Ok(()));
        assert_eq!(check(4, &service(3, 5)), Ok(()));
        assert_eq!(check(5, &service(3, 5)), Ok(()));
    }

    #[test]
    fn a_client_older_than_the_service_serves_is_told_to_update_itself() {
        let e = check(2, &service(3, 5)).unwrap_err();
        assert_eq!(
            e,
            Incompatible::ClientTooOld {
                client: 2,
                min: 3,
                newest: 5
            }
        );
        assert!(e.to_string().contains("Update this program"));
    }

    #[test]
    fn a_client_newer_than_the_service_is_told_to_update_the_service() {
        let e = check(6, &service(3, 5)).unwrap_err();
        assert_eq!(
            e,
            Incompatible::ServiceTooOld {
                client: 6,
                min: 3,
                newest: 5
            }
        );
        assert!(e.to_string().contains("Update the DNet Engine service"));
    }

    fn v(text: &str) -> Value {
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn a_reply_that_is_not_a_plain_version_is_refused() {
        let ok =
            r#"{"protocol_version":2,"min_protocol_version":1,"service_version":"1.2.3-rc.1+b5"}"#;
        assert!(decode(&v(ok)).is_ok());
        for bad in [
            r#"[]"#,
            r#"{}"#,
            r#"{"protocol_version":2,"min_protocol_version":1}"#,
            r#"{"protocol_version":"2","min_protocol_version":1,"service_version":"1"}"#,
            r#"{"protocol_version":2.5,"min_protocol_version":1,"service_version":"1"}"#,
            r#"{"protocol_version":-1,"min_protocol_version":1,"service_version":"1"}"#,
            r#"{"protocol_version":0,"min_protocol_version":0,"service_version":"1"}"#,
            r#"{"protocol_version":4294967296,"min_protocol_version":1,"service_version":"1"}"#,
            r#"{"protocol_version":1,"min_protocol_version":2,"service_version":"1"}"#,
            r#"{"protocol_version":2,"min_protocol_version":1,"service_version":""}"#,
            r#"{"protocol_version":2,"min_protocol_version":1,"service_version":"a b"}"#,
            r#"{"protocol_version":2,"min_protocol_version":1,"service_version":"1\u001b[31m"}"#,
            r#"{"protocol_version":2,"min_protocol_version":1,"service_version":7}"#,
        ] {
            assert!(decode(&v(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn an_overlong_service_version_is_refused() {
        let long = "1".repeat(MAX_SERVICE_VERSION_LEN + 1);
        let text = format!(
            r#"{{"protocol_version":1,"min_protocol_version":1,"service_version":"{long}"}}"#
        );
        assert!(decode(&v(&text)).is_err());
        let at_limit = "1".repeat(MAX_SERVICE_VERSION_LEN);
        let text = format!(
            r#"{{"protocol_version":1,"min_protocol_version":1,"service_version":"{at_limit}"}}"#
        );
        assert!(decode(&v(&text)).is_ok());
    }

    #[test]
    fn an_error_does_not_echo_what_the_service_sent() {
        let hostile =
            r#"{"protocol_version":1,"min_protocol_version":1,"service_version":"EVIL PAYLOAD"}"#;
        let e = decode(&v(hostile)).unwrap_err();
        assert!(!e.contains("EVIL"), "{e}");
    }
}
