//! T188 — an invite: what the owner of a server sends a friend, so the friend's computer can use that server
//! with a key of its own.
//!
//! The friend makes a key pair on their own computer and sends the owner only the public half (a "device request",
//! `dnet-provision::devices`). The owner has the server accept that key, and the server says which address inside
//! the session the device gets. The invite carries the carriers' details (which are the same for everyone on one
//! server: the passwords of the two carriers, and what each needs to be reached) and the server's session key, the
//! port and this device's address. It never carries a device key: where the friend's private key goes, it holds a
//! fixed placeholder that the friend's computer replaces with the key it made, and an invite that holds anything
//! else there is refused. So a friend never holds the owner's key, the owner never holds the friend's, and one
//! friend can be taken off the server without touching the others.
//!
//! The carriers' passwords do reach the friend, as they must for the friend to reach the server at all. They are
//! not enough to use it: the carriers forward only to the session, and the session lets in only a registered key.
//! An invite is still a secret (the text of it is how the friend gets in), so it is shown with that said, and never
//! logged.

use std::net::Ipv4Addr;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::credentials::{EndpointCredentials, SessionBundle, MAX_STORED_LEN};
use crate::secret::Secret;

/// What an invite starts with. The `1` is the format's version.
pub const PREFIX: &str = "DNET-INVITE-1:";

/// The most an invite may be, as text: the largest credentials, grown by base64, with room for the envelope.
pub const MAX_INVITE_LEN: usize = 32 * 1024;

/// The most pasted text that is looked at for an invite at all (an invite and some words around it).
pub const MAX_PASTE_LEN: usize = 64 * 1024;

/// The longest name for an invite's server or a friend's device.
pub const MAX_NAME_LEN: usize = 32;

/// 32 zero bytes: "the friend's own key goes here". Valid as a key, and nothing's real one.
const PLACEHOLDER: [u8; 32] = [0; 32];

/// Why an invite was not made or not accepted. Names what is wrong, never a value from it.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InviteError {
    #[error("that is not an invite")]
    NotAnInvite,
    #[error("that is too long to be an invite")]
    TooLarge,
    #[error("the invite is damaged: ask for it again")]
    Damaged,
    #[error("the invite is in a format this version does not read (version {0})")]
    UnsupportedVersion(u32),
    #[error("the name is not allowed: use 1 to {MAX_NAME_LEN} letters, digits, spaces, dots, dashes or underscores")]
    Name,
    #[error("the server's address is not valid")]
    Host,
    #[error("the invite cannot be used: {0}")]
    Credentials(String),
    #[error("this server's details have no session, so a friend's device cannot be added to it")]
    NoSession,
    #[error("the invite holds a device key, which an invite never does")]
    CarriesAKey,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    version: u32,
    label: String,
    host: String,
    credentials: Value,
}

/// An invite: the server's address and name, and everything about it that is the same for every device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invite {
    label: String,
    host: String,
    /// The owner's carriers and origin, the session's public side, and this device's address, with the placeholder
    /// where the device's own key goes. No AmneziaWG: its key is the owner's alone.
    credentials: EndpointCredentials,
}

/// Whether `name` is one a person may give a server or a device: short, plain, and nothing that could mislead
/// (no control or direction characters, no quotes, nothing outside ASCII).
#[must_use]
pub fn valid_name(name: &str) -> bool {
    let n = name.chars().count();
    (1..=MAX_NAME_LEN).contains(&n)
        && name.trim() == name
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, ' ' | '.' | '-' | '_'))
}

/// The same rule a server typed into the window must meet (`dnet-ipc`'s `check_host`): an address or a name with no
/// scheme, port or path, and not an address nothing can have.
fn valid_host(host: &str) -> bool {
    host.len() <= 253
        && crate::persist::host_is_acceptable(host)
        && host
            .parse::<std::net::IpAddr>()
            .map_or(true, address_could_be_a_server)
}

/// An address a server could have: not nothing, not this machine, not a group, not the link-local range, and not an
/// IPv6 address that is really one of those in an IPv4 coat. (A private range is allowed: a server in the same house
/// is a real case.)
fn address_could_be_a_server(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_unspecified()
                || v4.is_loopback()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_link_local())
        }
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => address_could_be_a_server(IpAddr::V4(v4)),
            None => {
                !(v6.is_unspecified()
                    || v6.is_loopback()
                    || v6.is_multicast()
                    // Link-local (fe80::/10).
                    || (v6.segments()[0] & 0xffc0) == 0xfe80)
            }
        },
    }
}

impl Invite {
    /// An invite to `host`, for a device that the server gave `device_address`, from the owner's own `credentials`
    /// for that server. The owner's device key and AmneziaWG key stay out of it.
    pub fn new(
        label: &str,
        host: &str,
        owner: &EndpointCredentials,
        device_address: Ipv4Addr,
    ) -> Result<Self, InviteError> {
        if !valid_name(label) {
            return Err(InviteError::Name);
        }
        if !valid_host(host) {
            return Err(InviteError::Host);
        }
        let session = owner.session.as_ref().ok_or(InviteError::NoSession)?;
        let mut credentials = owner.clone();
        credentials.amneziawg = None;
        credentials.session = Some(SessionBundle {
            device_private_key: Secret::new(STANDARD.encode(PLACEHOLDER)),
            server_public_key: session.server_public_key.clone(),
            device_address,
            session_port: session.session_port,
        });
        // Whatever the stored form would refuse, an invite is not made from.
        credentials
            .to_plaintext_json()
            .map_err(|e| InviteError::Credentials(e.to_string()))?;
        Ok(Self {
            label: label.to_owned(),
            host: host.to_owned(),
            credentials,
        })
    }

    /// The name the server is shown under.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The server's address.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The address this device has inside the session.
    #[must_use]
    pub fn device_address(&self) -> Option<Ipv4Addr> {
        self.credentials.session.as_ref().map(|s| s.device_address)
    }

    /// The text to send: one token, safe to paste into a message.
    pub fn encode(&self) -> Result<String, InviteError> {
        let stored = self
            .credentials
            .to_plaintext_json()
            .map_err(|e| InviteError::Credentials(e.to_string()))?;
        let credentials: Value =
            serde_json::from_slice(&stored).map_err(|_| InviteError::Damaged)?;
        let wire = Wire {
            version: 1,
            label: self.label.clone(),
            host: self.host.clone(),
            credentials,
        };
        let json = serde_json::to_vec(&wire).map_err(|_| InviteError::Damaged)?;
        let text = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(json));
        if text.len() > MAX_INVITE_LEN {
            return Err(InviteError::TooLarge);
        }
        Ok(text)
    }

    /// Read an invite out of pasted text. Strict: an unknown field, a wrong version, a name or address that is not
    /// allowed, credentials the stored form would refuse, anything with an AmneziaWG key, and anything but the
    /// placeholder where the device's key goes, are all refused. Words around the invite are ignored.
    pub fn decode(pasted: &str) -> Result<Self, InviteError> {
        if pasted.len() > MAX_PASTE_LEN {
            return Err(InviteError::TooLarge);
        }
        let Some((text, ends)) = tokens_in(pasted) else {
            return Err(InviteError::NotAnInvite);
        };
        // The token may have been wrapped over lines, and a word on the next line looks just like another wrapped
        // piece. So the longest reading is tried first, then shorter ones, and the first that is an invite wins; if
        // none is, the longest reading's reason is the one given.
        let mut first_error = None;
        for end in ends.iter().rev() {
            match Self::from_token(&text[..*end]) {
                Ok(invite) => return Ok(invite),
                Err(e) => {
                    first_error.get_or_insert(e);
                }
            }
        }
        Err(first_error.unwrap_or(InviteError::NotAnInvite))
    }

    fn from_token(token: &str) -> Result<Self, InviteError> {
        if token.len() > MAX_INVITE_LEN {
            return Err(InviteError::TooLarge);
        }
        let json = URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| InviteError::Damaged)?;
        let wire: Wire = serde_json::from_slice(&json).map_err(|_| InviteError::Damaged)?;
        if wire.version != 1 {
            return Err(InviteError::UnsupportedVersion(wire.version));
        }
        if !valid_name(&wire.label) {
            return Err(InviteError::Name);
        }
        if !valid_host(&wire.host) {
            return Err(InviteError::Host);
        }
        let stored = serde_json::to_vec(&wire.credentials).map_err(|_| InviteError::Damaged)?;
        if stored.len() > MAX_STORED_LEN {
            return Err(InviteError::TooLarge);
        }
        let credentials = EndpointCredentials::from_plaintext_json(&stored)
            .map_err(|e| InviteError::Credentials(e.to_string()))?;
        let session = credentials.session.as_ref().ok_or(InviteError::NoSession)?;
        if session.device_private_key.expose() != STANDARD.encode(PLACEHOLDER) {
            return Err(InviteError::CarriesAKey);
        }
        if credentials.amneziawg.is_some() {
            return Err(InviteError::Credentials(
                "it holds an AmneziaWG key, which belongs to the owner alone".to_owned(),
            ));
        }
        Ok(Self {
            label: wire.label,
            host: wire.host,
            credentials,
        })
    }

    /// The credentials this computer will use: the invite's, with `device_private_key` (made here) in place of the
    /// placeholder. Refuses a key that is not 32 bytes in base64, and the placeholder itself.
    pub fn accept(self, device_private_key: Secret) -> Result<EndpointCredentials, InviteError> {
        let key = device_private_key.expose();
        if !crate::session::is_key(key) || key == STANDARD.encode(PLACEHOLDER) {
            return Err(InviteError::Credentials(
                "this computer's device key".to_owned(),
            ));
        }
        let mut credentials = self.credentials;
        let session = credentials.session.as_mut().ok_or(InviteError::NoSession)?;
        session.device_private_key = device_private_key;
        credentials
            .to_plaintext_json()
            .map_err(|e| InviteError::Credentials(e.to_string()))?;
        Ok(credentials)
    }
}

/// The invite's token in `pasted`, as one run of text and the places a reading of it may end, shortest first (each
/// reading is the run up to one of those places, so no copy is made per line). The token starts at the prefix and
/// runs over the base64url characters to the end of that line; the lines straight after it that hold nothing but
/// those characters may be more of it (a message app may wrap a long token), and a blank line, or a line with
/// anything else in it, ends it. Each further line gives a longer reading. Nothing is taken past
/// `MAX_INVITE_LEN`: a longer token is not an invite, and a hostile paste of thousands of one-letter lines must not
/// cost more than that.
fn tokens_in(pasted: &str) -> Option<(String, Vec<usize>)> {
    let at = pasted.find(PREFIX)?;
    let is_token_char = |c: char| c.is_ascii_alphanumeric() || c == '-' || c == '_';
    let mut lines = pasted[at + PREFIX.len()..]
        .split('\n')
        .map(|l| l.trim_end_matches('\r'));
    let first = lines.next().unwrap_or("");
    let head: String = first.chars().take_while(|c| is_token_char(*c)).collect();
    if head.is_empty() {
        return None;
    }
    let mut ends = vec![head.len()];
    let mut text = head;
    // Only a first line that is all token may be continued onto the next.
    if text.len() == first.len() {
        for line in lines {
            if line.is_empty() || !line.chars().all(is_token_char) {
                break;
            }
            if text.len() + line.len() > MAX_INVITE_LEN {
                break;
            }
            text.push_str(line);
            ends.push(text.len());
        }
    }
    Some((text, ends))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::tests::with_session;

    fn owner() -> EndpointCredentials {
        with_session()
    }

    fn address(n: usize) -> Ipv4Addr {
        crate::session::session_device_address(n)
    }

    fn invite() -> Invite {
        Invite::new("Ravis laptop", "203.0.113.9", &owner(), address(1)).unwrap()
    }

    #[test]
    fn an_invite_round_trips_and_the_friend_gets_credentials_with_their_own_key() {
        let text = invite().encode().unwrap();
        assert!(text.starts_with(PREFIX), "{text}");
        let read = Invite::decode(&text).unwrap();
        assert_eq!(read.label(), "Ravis laptop");
        assert_eq!(read.host(), "203.0.113.9");
        assert_eq!(read.device_address(), Some(address(1)));

        let own_key = STANDARD.encode([9u8; 32]);
        let mine = read.accept(Secret::new(own_key.clone())).unwrap();
        let session = mine.session.as_ref().unwrap();
        assert_eq!(session.device_private_key.expose(), own_key);
        assert_eq!(session.device_address, address(1));
        let theirs = owner();
        assert_eq!(
            session.server_public_key,
            theirs.session.as_ref().unwrap().server_public_key
        );
        assert_eq!(mine.hysteria2, theirs.hysteria2);
        assert_eq!(mine.reality, theirs.reality);
        assert_eq!(mine.measure_origin, theirs.measure_origin);
    }

    #[test]
    fn no_key_of_the_owners_is_in_an_invite() {
        let owners = owner();
        let session_key = owners
            .session
            .as_ref()
            .unwrap()
            .device_private_key
            .expose()
            .to_owned();
        let awg_key = owners
            .amneziawg
            .as_ref()
            .unwrap()
            .client_private_key
            .expose_wire()
            .to_owned();
        let text = invite().encode().unwrap();
        let decoded = String::from_utf8(
            URL_SAFE_NO_PAD
                .decode(text.strip_prefix(PREFIX).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert!(
            !decoded.contains(&session_key),
            "the owner's device key is in the invite"
        );
        assert!(
            !decoded.contains(&awg_key),
            "the owner's AmneziaWG key is in the invite"
        );
        assert!(
            !decoded.contains("amneziawg"),
            "AmneziaWG is the owner's alone"
        );
        // And what is printed of it says nothing either.
        assert!(!format!("{:?}", invite()).contains(&session_key));
    }

    #[test]
    fn an_invite_that_carries_a_real_device_key_is_refused() {
        // Someone swapped in a key: an invite never holds one, so the friend's computer would be handed a key it
        // did not make.
        let mut creds = owner();
        creds.amneziawg = None;
        let text = {
            let wire_creds: Value =
                serde_json::from_slice(&creds.to_plaintext_json().unwrap()).unwrap();
            let wire = Wire {
                version: 1,
                label: "A".into(),
                host: "203.0.113.9".into(),
                credentials: wire_creds,
            };
            format!(
                "{PREFIX}{}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&wire).unwrap())
            )
        };
        assert_eq!(Invite::decode(&text), Err(InviteError::CarriesAKey));
    }

    #[test]
    fn an_invite_without_a_session_is_not_made() {
        let mut creds = owner();
        creds.session = None;
        assert_eq!(
            Invite::new("A", "203.0.113.9", &creds, address(1)),
            Err(InviteError::NoSession)
        );
    }

    #[test]
    fn names_and_addresses_are_checked_going_out_and_coming_in() {
        let long = "a".repeat(MAX_NAME_LEN + 1);
        for bad in [
            "",
            " a",
            "a ",
            "a\u{202e}b",
            "quote'd",
            "é",
            "tab\there",
            long.as_str(),
        ] {
            assert_eq!(
                Invite::new(bad, "203.0.113.9", &owner(), address(1)),
                Err(InviteError::Name),
                "{bad:?}"
            );
        }
        assert!(valid_name(&"a".repeat(MAX_NAME_LEN)));
        assert!(valid_name("Ravi_2.0 -x"));
        for bad in [
            "",
            "not a host",
            "a/b",
            "http://x",
            "x:1",
            "127.0.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "169.254.1.1",
            "::1",
            "::",
            "fe80::1",
            "ff02::1",
            "::ffff:127.0.0.1",
            "::ffff:0.0.0.0",
        ] {
            assert_eq!(
                Invite::new("A", bad, &owner(), address(1)),
                Err(InviteError::Host),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_paste_of_thousands_of_tiny_lines_is_read_in_bounded_time_and_refused() {
        let hostile = format!("{PREFIX}A\n{}", "A\n".repeat(30_000));
        assert!(hostile.len() <= MAX_PASTE_LEN);
        let started = std::time::Instant::now();
        assert!(Invite::decode(&hostile).is_err());
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "took {:?}",
            started.elapsed()
        );
        let (text, ends) = tokens_in(&hostile).unwrap();
        assert!(text.len() <= MAX_INVITE_LEN);
        assert!(ends.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn words_around_an_invite_and_wrapped_lines_are_fine() {
        let text = invite().encode().unwrap();
        let (a, b) = text.split_at(text.len() / 2);
        let pasted = format!("Here you go!\n{a}\n{b}\n\nSee you soon.");
        assert_eq!(Invite::decode(&pasted).unwrap().host(), "203.0.113.9");
        assert_eq!(
            Invite::decode(&format!("  \n{text}  ")).unwrap().host(),
            "203.0.113.9"
        );
    }

    #[test]
    fn what_is_not_an_invite_is_said_so_and_nothing_panics() {
        for junk in [
            "",
            "hello",
            "DNET-INVITE-1:",
            "DNET-INVITE-1:!!!!",
            "DNET-INVITE-1:AAAA",
            "DNET-INVITE-2:AAAA",
        ] {
            assert!(Invite::decode(junk).is_err(), "{junk:?}");
        }
        assert_eq!(Invite::decode("hello"), Err(InviteError::NotAnInvite));
        assert_eq!(
            Invite::decode(&format!("{PREFIX}{}", "A".repeat(MAX_INVITE_LEN + 1))),
            Err(InviteError::TooLarge)
        );
        assert_eq!(
            Invite::decode(&"x".repeat(MAX_PASTE_LEN + 1)),
            Err(InviteError::TooLarge)
        );
    }

    #[test]
    fn a_damaged_or_altered_invite_is_refused_and_never_echoes_its_content() {
        let text = invite().encode().unwrap();
        // One character changed somewhere in the middle.
        let mut bytes = text.clone().into_bytes();
        let at = PREFIX.len() + (bytes.len() - PREFIX.len()) / 2;
        bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
        let altered = String::from_utf8(bytes).unwrap();
        let err =
            Invite::decode(&altered).expect_err("an altered invite must not be accepted as it is");
        let said = err.to_string();
        assert!(
            !said.contains(&altered[PREFIX.len()..PREFIX.len() + 20]),
            "{said}"
        );

        // A field this version does not know, and a version it does not know.
        let wire = |edit: fn(&mut Value)| {
            let mut v: Value = serde_json::from_slice(
                &URL_SAFE_NO_PAD
                    .decode(text.strip_prefix(PREFIX).unwrap())
                    .unwrap(),
            )
            .unwrap();
            edit(&mut v);
            format!(
                "{PREFIX}{}",
                URL_SAFE_NO_PAD.encode(serde_json::to_vec(&v).unwrap())
            )
        };
        assert_eq!(
            Invite::decode(&wire(|v| v["extra"] = Value::from(1))),
            Err(InviteError::Damaged)
        );
        assert_eq!(
            Invite::decode(&wire(|v| v["version"] = Value::from(2))),
            Err(InviteError::UnsupportedVersion(2))
        );
        assert_eq!(
            Invite::decode(&wire(|v| v["label"] = Value::from("bad'name"))),
            Err(InviteError::Name)
        );
        assert_eq!(
            Invite::decode(&wire(|v| v["host"] = Value::from("not a host"))),
            Err(InviteError::Host)
        );
    }

    #[test]
    fn the_friends_own_key_must_be_a_real_key_and_not_the_placeholder() {
        let read = Invite::decode(&invite().encode().unwrap()).unwrap();
        let short = STANDARD.encode([1u8; 31]);
        let placeholder = STANDARD.encode(PLACEHOLDER);
        for bad in ["", "short", short.as_str(), placeholder.as_str()] {
            assert!(read.clone().accept(Secret::new(bad)).is_err(), "{bad:?}");
        }
        assert!(read.accept(Secret::new(STANDARD.encode([7u8; 32]))).is_ok());
    }

    #[test]
    fn arbitrary_pasted_text_never_panics() {
        // A deterministic spread of hostile shapes, with the prefix in front of most so the parser goes deep.
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for i in 0..4000 {
            let len = (next() % 200) as usize;
            let body: String = (0..len)
                .map(|_| {
                    let r = next();
                    match r % 6 {
                        0 => char::from_u32((r >> 8) as u32 % 0x11_0000).unwrap_or('?'),
                        1 => '\n',
                        2 => '-',
                        _ => (b'A' + (r % 26) as u8) as char,
                    }
                })
                .collect();
            let text = if i % 4 == 0 {
                body
            } else {
                format!("{PREFIX}{body}")
            };
            let _ = Invite::decode(&text);
        }
    }
}
