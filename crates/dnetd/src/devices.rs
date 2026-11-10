//! T188 — a friend's device joins someone's server, and the owner invites it (ADR-0008 "Share a server").
//!
//! Two halves, both held in memory only:
//!
//! - **The friend's computer** ([`Joining`]) makes a key of its own, answers with the public half and a name,
//!   and keeps the private half waiting. When the owner's invite arrives it checks that the invite was made for
//!   *this* key, and only then puts the key in and hands back the credentials to seal.
//! - **The owner's computer** ([`Inviting`]) remembers which friend's requests it has made a script for. A
//!   result is turned into an invite only for a request it prepared, for the server it was prepared for, and
//!   only if the server's own key and port in the result are the ones this computer already holds.
//!
//! - **The private key of a device never leaves it.** The invite carries the server's details and the public
//!   half of the friend's key; the friend's computer adds its own private half.
//! - **A failed paste keeps waiting**, so the person can paste again; a success consumes it.
//! - **Nothing a person pasted is repeated** in an error: it is read as hostile input.

use std::sync::{Mutex, MutexGuard, PoisonError};

use dnet_config::credentials::EndpointCredentials;
use dnet_config::invite::Invite;
use dnet_config::secret::Secret;
use dnet_core::ids::EndpointId;
use dnet_ipc::devices::{DeviceInvited, DevicePrepared, JoinRequested};
use dnet_provision::client_keys::SessionKeys;
use dnet_provision::devices::{add_device_script, DeviceAdded, DeviceRequest};

/// How long a request or a join waits for the other side. Long enough to send a message and get an answer;
/// short enough that nothing sits in memory for a day. In memory only.
pub const WAIT_S: u64 = 6 * 3600;

/// How many friends' requests an owner may have prepared at once.
pub const MAX_PREPARED: usize = 8;

/// How long an approved invite waits to be asked for. The person who approved it asks straight away; one that
/// nobody asks for is dropped, not kept.
pub const READY_FOR_S: u64 = 10 * 60;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DevicesError {
    #[error("this computer has not asked to join a server; start from the first step")]
    NotJoining,
    #[error("the request waited more than six hours; start again from the first step")]
    Expired,
    #[error("the keys could not be made")]
    Keys,
    #[error("the invite cannot be used: {0}")]
    Invite(String),
    #[error(
        "this invite was made for another device, not for this computer. Send the request this \
         computer made and ask for an invite for it"
    )]
    WrongDevice,
    #[error("the request cannot be used: {0}")]
    Request(String),
    #[error("the result cannot be used: {0}")]
    Report(String),
    #[error(
        "no device is being added with that request on that server; start again from the first step"
    )]
    NotPrepared,
    #[error("this server has no private session, so a friend's device cannot be added to it")]
    NoSession,
    #[error("this server's details cannot be read: {0}")]
    Unreadable(String),
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

// ------------------------------------------------------------------ the friend's computer

struct PendingJoin {
    keys: SessionKeys,
    name: String,
    made_at_s: u64,
}

/// What a pasted invite yields: the server as this computer will know it, ready to save.
pub struct Accepted {
    pub label: String,
    pub host: String,
    pub credentials: EndpointCredentials,
}

/// A friend's computer asking to join.
#[derive(Default)]
pub struct Joining {
    slot: Mutex<Option<PendingJoin>>,
}

impl Joining {
    pub fn new() -> Self {
        Self::default()
    }

    /// Ask to join as `name`. The same request while one is waiting under that name: the key does not change,
    /// so a request already sent stays good when the window is closed and opened again.
    pub fn request(&self, name: &str, now_s: u64) -> Result<JoinRequested, DevicesError> {
        let mut slot = lock(&self.slot);
        if let Some(waiting) = slot.as_ref() {
            if waiting.name == name && now_s.saturating_sub(waiting.made_at_s) <= WAIT_S {
                return describe(waiting, now_s);
            }
        }
        let keys = SessionKeys::generate().map_err(|_| DevicesError::Keys)?;
        let pending = PendingJoin {
            keys,
            name: name.to_owned(),
            made_at_s: now_s,
        };
        let reply = describe(&pending, now_s)?;
        *slot = Some(pending);
        Ok(reply)
    }

    /// Read a pasted invite. The credentials are returned and the join **keeps waiting**: the caller still has
    /// to save them, and a save that fails (a name in use) must not cost the person their key. [`Self::complete`]
    /// ends the wait once the server is saved.
    pub fn accept(&self, pasted: &str, now_s: u64) -> Result<Accepted, DevicesError> {
        let mut slot = lock(&self.slot);
        let pending = slot.as_ref().ok_or(DevicesError::NotJoining)?;
        if now_s.saturating_sub(pending.made_at_s) > WAIT_S {
            *slot = None;
            return Err(DevicesError::Expired);
        }
        let invite = Invite::decode(pasted).map_err(|e| DevicesError::Invite(e.to_string()))?;
        if invite.device_public_key() != pending.keys.public_b64() {
            return Err(DevicesError::WrongDevice);
        }
        let label = invite.label().to_owned();
        let host = invite.host().to_owned();
        let credentials = invite
            .accept(Secret::new(pending.keys.private_b64().to_owned()))
            .map_err(|e| DevicesError::Invite(e.to_string()))?;
        Ok(Accepted {
            label,
            host,
            credentials,
        })
    }

    /// The server is saved: drop the key that was waiting for it.
    pub fn complete(&self) {
        *lock(&self.slot) = None;
    }

    /// Whether a join is waiting (for tests and diagnostics).
    #[cfg(test)]
    pub fn waiting(&self) -> bool {
        lock(&self.slot).is_some()
    }
}

fn describe(pending: &PendingJoin, now_s: u64) -> Result<JoinRequested, DevicesError> {
    let request = DeviceRequest::new(&pending.name, pending.keys.public_b64())
        .map_err(|e| DevicesError::Request(e.to_string()))?;
    let left = WAIT_S.saturating_sub(now_s.saturating_sub(pending.made_at_s));
    Ok(JoinRequested {
        name: pending.name.clone(),
        text: request.encode(),
        valid_for_s: left.max(1),
    })
}

// ------------------------------------------------------------------ the owner's computer

struct Prepared {
    endpoint: EndpointId,
    request: DeviceRequest,
    made_at_s: u64,
}

/// What an owner pasted to have an invite made: the friend's request, and what the server printed for it.
struct Asked<'a> {
    endpoint: EndpointId,
    text: &'a str,
    report: &'a str,
}

/// An invite that was made after an approval and is waiting to be asked for, once.
struct Ready {
    endpoint: EndpointId,
    public_key: String,
    invited: DeviceInvited,
    made_at_s: u64,
}

/// What an owner's computer needs to remember about the servers it is adding devices to.
#[derive(Default)]
pub struct Inviting {
    prepared: Mutex<Vec<Prepared>>,
    ready: Mutex<Vec<Ready>>,
}

/// What the owner's computer knows about the server a device is added to.
pub struct ServerFacts {
    pub label: String,
    pub host: String,
    pub credentials: EndpointCredentials,
}

impl Inviting {
    pub fn new() -> Self {
        Self::default()
    }

    /// Make the script that adds the device in `text` to the server `endpoint`. `has_session` says whether that
    /// server has a private session at all (an older server does not, and cannot take a friend's device).
    pub fn prepare(
        &self,
        endpoint: EndpointId,
        text: &str,
        has_session: bool,
        now_s: u64,
    ) -> Result<DevicePrepared, DevicesError> {
        if !has_session {
            return Err(DevicesError::NoSession);
        }
        let request =
            DeviceRequest::decode(text).map_err(|e| DevicesError::Request(e.to_string()))?;
        let script = add_device_script(&request);
        let name = request.name().to_owned();
        let mut list = lock(&self.prepared);
        list.retain(|p| now_s.saturating_sub(p.made_at_s) <= WAIT_S);
        // The same request for the same server is the same preparation, however many times it is asked for.
        list.retain(|p| {
            !(p.endpoint == endpoint && p.request.public_key() == request.public_key())
        });
        if list.len() >= MAX_PREPARED {
            list.remove(0);
        }
        list.push(Prepared {
            endpoint,
            request,
            made_at_s: now_s,
        });
        Ok(DevicePrepared {
            name,
            script,
            valid_for_s: WAIT_S,
        })
    }

    /// Check, without changing anything, that what the script printed could be made into an invite: the request
    /// was prepared for this server, and the result is the one for it. Nothing is read from the sealed store for
    /// a request nobody made. Used before anyone is asked to approve making the invite.
    pub fn check(
        &self,
        endpoint: EndpointId,
        text: &str,
        report: &str,
        server: impl FnOnce() -> Result<ServerFacts, DevicesError>,
        now_s: u64,
    ) -> Result<(), DevicesError> {
        let asked = Asked {
            endpoint,
            text,
            report,
        };
        self.build(&asked, server, now_s, false).map(drop)
    }

    /// Turn what the script printed into the invite, once the person has approved making it. The request is
    /// consumed; the invite waits for [`Self::take_ready`], and is also returned for a caller that holds nothing
    /// back (the tests).
    pub fn finish(
        &self,
        endpoint: EndpointId,
        text: &str,
        report: &str,
        server: impl FnOnce() -> Result<ServerFacts, DevicesError>,
        now_s: u64,
    ) -> Result<DeviceInvited, DevicesError> {
        let asked = Asked {
            endpoint,
            text,
            report,
        };
        let invited = self.build(&asked, server, now_s, true)?;
        let request =
            DeviceRequest::decode(text).map_err(|e| DevicesError::Request(e.to_string()))?;
        let mut ready = lock(&self.ready);
        ready.retain(|r| now_s.saturating_sub(r.made_at_s) <= READY_FOR_S);
        ready.retain(|r| !(r.endpoint == endpoint && r.public_key == request.public_key()));
        if ready.len() >= MAX_PREPARED {
            ready.remove(0);
        }
        ready.push(Ready {
            endpoint,
            public_key: request.public_key().to_owned(),
            invited: invited.clone(),
            made_at_s: now_s,
        });
        Ok(invited)
    }

    /// Whether an approved invite for this request is waiting.
    pub fn is_ready(&self, endpoint: EndpointId, text: &str, now_s: u64) -> bool {
        let Ok(request) = DeviceRequest::decode(text) else {
            return false;
        };
        lock(&self.ready).iter().any(|r| {
            r.endpoint == endpoint
                && r.public_key == request.public_key()
                && now_s.saturating_sub(r.made_at_s) <= READY_FOR_S
        })
    }

    /// The approved invite for this request, once: it is forgotten as it is handed over.
    pub fn take_ready(
        &self,
        endpoint: EndpointId,
        text: &str,
        now_s: u64,
    ) -> Option<DeviceInvited> {
        let request = DeviceRequest::decode(text).ok()?;
        let mut ready = lock(&self.ready);
        ready.retain(|r| now_s.saturating_sub(r.made_at_s) <= READY_FOR_S);
        let at = ready
            .iter()
            .position(|r| r.endpoint == endpoint && r.public_key == request.public_key())?;
        Some(ready.remove(at).invited)
    }

    /// The one place an invite is made. `server` is asked for only once the request is known to have been
    /// prepared for this server. With `consume`, the preparation is used up.
    fn build(
        &self,
        asked: &Asked<'_>,
        server: impl FnOnce() -> Result<ServerFacts, DevicesError>,
        now_s: u64,
        consume: bool,
    ) -> Result<DeviceInvited, DevicesError> {
        let Asked {
            endpoint,
            text,
            report,
        } = *asked;
        let request =
            DeviceRequest::decode(text).map_err(|e| DevicesError::Request(e.to_string()))?;
        let mut list = lock(&self.prepared);
        let at = list
            .iter()
            .position(|p| {
                p.endpoint == endpoint
                    && p.request.public_key() == request.public_key()
                    && p.request.name() == request.name()
            })
            .ok_or(DevicesError::NotPrepared)?;
        if now_s.saturating_sub(list[at].made_at_s) > WAIT_S {
            list.remove(at);
            return Err(DevicesError::Expired);
        }
        let facts = server()?;
        let session = facts
            .credentials
            .session
            .as_ref()
            .ok_or(DevicesError::NoSession)?;
        // The server's own key and port in the result must be the ones this computer already holds for it: a
        // result that names another would hand the friend a session that is not the owner's.
        let added = DeviceAdded::parse_for_server(
            report,
            &request,
            &session.server_public_key,
            session.session_port,
        )
        .map_err(|e| DevicesError::Report(e.to_string()))?;
        let invite = Invite::new(
            &facts.label,
            &facts.host,
            &facts.credentials,
            added.address,
            request.public_key(),
        )
        .map_err(|e| DevicesError::Invite(e.to_string()))?;
        let invite_text = invite
            .encode()
            .map_err(|e| DevicesError::Invite(e.to_string()))?;
        if consume {
            list.remove(at);
        }
        Ok(DeviceInvited {
            name: added.name,
            address: added.address.to_string(),
            invite: invite_text,
        })
    }

    /// How many requests are prepared (for tests).
    #[cfg(test)]
    pub fn count(&self) -> usize {
        lock(&self.prepared).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use dnet_config::credentials::{Hysteria2Bundle, SessionBundle};
    use dnet_config::hysteria2::{Hysteria2Credentials, Hysteria2EndpointParams, Hysteria2Obfs};
    use dnet_config::tls::ServerTrust;
    use dnet_provision::devices::REPORT_PREFIX;
    use serde_json::json;

    const NOW: u64 = 1_000_000;

    fn b64(byte: u8) -> String {
        STANDARD.encode([byte; 32])
    }

    /// An owner's credentials for a server: one carrier, and the session with the owner's own device key.
    fn owner_credentials() -> EndpointCredentials {
        EndpointCredentials {
            hysteria2: Some(Hysteria2Bundle {
                server_port: 44443,
                credentials: Hysteria2Credentials {
                    auth_password: Secret::new("a-password-of-some-length"),
                    obfs_password: Secret::new("an-obfs-password-long-enough"),
                },
                endpoint: Hysteria2EndpointParams {
                    obfs: Hysteria2Obfs::Salamander,
                    trust: ServerTrust::PinnedPublicKey {
                        server_name: "hy2.harness.test".into(),
                        spki_sha256: [7; 32],
                    },
                },
            }),
            session: Some(SessionBundle {
                device_private_key: Secret::new(b64(9)),
                server_public_key: b64(5),
                device_address: dnet_config::session::session_device_address(0),
                session_port: dnet_config::session::SESSION_PORT,
            }),
            ..EndpointCredentials::default()
        }
    }

    fn facts() -> ServerFacts {
        ServerFacts {
            label: "My server".into(),
            host: "203.0.113.9".into(),
            credentials: owner_credentials(),
        }
    }

    /// What the add script prints on a server whose session key is `server`.
    fn printed(request: &DeviceRequest, address: &str, server: &str, port: u16) -> String {
        format!(
            "{REPORT_PREFIX}{}",
            json!({
                "version": 1, "action": "add", "public_key": request.public_key(),
                "name": request.name(), "address": address, "added": true,
                "server_public_key": server, "port": port, "devices": 2,
            })
        )
    }

    fn good_report(request: &DeviceRequest) -> String {
        printed(
            request,
            "10.9.0.3",
            &b64(5),
            dnet_config::session::SESSION_PORT,
        )
    }

    /// A friend has asked and the owner has prepared the request for `endpoint`.
    fn asked_and_prepared(name: &str, endpoint: EndpointId) -> (Joining, Inviting, String) {
        let friend = Joining::new();
        let asked = friend.request(name, NOW).unwrap();
        let owner = Inviting::new();
        owner.prepare(endpoint, &asked.text, true, NOW).unwrap();
        (friend, owner, asked.text)
    }

    #[test]
    fn a_friend_asks_the_owner_prepares_and_finishes_and_the_friend_accepts_with_a_key_of_their_own(
    ) {
        let endpoint = EndpointId::new();
        let (friend, owner, text) = asked_and_prepared("Ravi laptop", endpoint);
        let request = DeviceRequest::decode(&text).unwrap();
        assert_eq!(request.name(), "Ravi laptop");

        let invited = owner
            .finish(
                endpoint,
                &text,
                &good_report(&request),
                || Ok(facts()),
                NOW + 5,
            )
            .unwrap();
        assert_eq!(invited.address, "10.9.0.3");
        assert_eq!(owner.count(), 0, "a result belongs to one request");

        let accepted = friend.accept(&invited.invite, NOW + 10).unwrap();
        assert_eq!(accepted.label, "My server");
        assert_eq!(accepted.host, "203.0.113.9");
        let session = accepted.credentials.session.as_ref().unwrap();
        assert_eq!(session.device_address.to_string(), "10.9.0.3");
        // The friend's own private key is in; the owner's is nowhere in the invite or in what the friend holds,
        // and the placeholder is gone.
        let held = String::from_utf8(accepted.credentials.to_plaintext_json().unwrap()).unwrap();
        assert!(!held.contains(&b64(9)), "the owner's device key");
        assert!(!held.contains(&b64(0)), "the placeholder");
        assert!(!invited.invite.contains(&b64(9)));
        assert!(friend.waiting(), "kept until it is saved");
        friend.complete();
        assert!(!friend.waiting());
    }

    #[test]
    fn asking_again_under_the_same_name_keeps_the_key_and_another_name_starts_over() {
        let friend = Joining::new();
        let a = friend.request("Ravi", NOW).unwrap();
        assert_eq!(friend.request("Ravi", NOW + 60).unwrap().text, a.text);
        let b = friend.request("Asha", NOW + 61).unwrap();
        assert_ne!(b.text, a.text);
        // One that has waited too long is replaced.
        assert_ne!(
            friend.request("Asha", NOW + 61 + WAIT_S + 1).unwrap().text,
            b.text
        );
        assert!(b.valid_for_s <= WAIT_S && b.valid_for_s >= 1);
    }

    #[test]
    fn an_invite_made_for_another_device_is_refused_and_the_wait_continues() {
        let endpoint = EndpointId::new();
        let (ravi, owner, text) = asked_and_prepared("Ravi", endpoint);
        let asha = Joining::new();
        asha.request("Asha", NOW).unwrap();
        let request = DeviceRequest::decode(&text).unwrap();
        let invite = owner
            .finish(endpoint, &text, &good_report(&request), || Ok(facts()), NOW)
            .unwrap()
            .invite;
        assert!(matches!(
            asha.accept(&invite, NOW),
            Err(DevicesError::WrongDevice)
        ));
        assert!(asha.waiting(), "Asha may still receive her own");
        assert!(ravi.accept(&invite, NOW).is_ok());
    }

    #[test]
    fn nothing_is_accepted_without_a_request_or_after_it_expired_or_from_text_that_is_not_an_invite(
    ) {
        let none = Joining::new();
        assert!(matches!(
            none.accept("DNET-INVITE-1:abc", NOW),
            Err(DevicesError::NotJoining)
        ));
        let friend = Joining::new();
        friend.request("Ravi", NOW).unwrap();
        for junk in [
            "",
            "hello",
            "DNET-INVITE-1:",
            "DNET-INVITE-1:!!!!",
            &"A".repeat(100_000),
        ] {
            assert!(
                matches!(friend.accept(junk, NOW), Err(DevicesError::Invite(_))),
                "{:?}",
                junk.chars().take(20).collect::<String>()
            );
        }
        assert!(friend.waiting(), "a bad paste does not cost the key");
        assert!(matches!(
            friend.accept("DNET-INVITE-1:abc", NOW + WAIT_S + 1),
            Err(DevicesError::Expired)
        ));
        assert!(!friend.waiting());
    }

    #[test]
    fn an_error_never_repeats_what_was_pasted() {
        let friend = Joining::new();
        friend.request("Ravi", NOW).unwrap();
        let secret_looking = "DNET-INVITE-1:SUPERSECRETTOKEN123";
        let message = friend
            .accept(secret_looking, NOW)
            .err()
            .unwrap()
            .to_string();
        assert!(!message.contains("SUPERSECRET"), "{message}");
    }

    #[test]
    fn a_script_is_made_only_for_a_server_that_can_take_a_device_and_a_request_that_is_one() {
        let owner = Inviting::new();
        let friend = Joining::new();
        let asked = friend.request("Ravi", NOW).unwrap();
        assert_eq!(
            owner.prepare(EndpointId::new(), &asked.text, false, NOW),
            Err(DevicesError::NoSession)
        );
        for junk in [
            "",
            "hello",
            "DNET-DEVICE-REQUEST {}",
            "DNET-DEVICE-REQUEST {\"version\":1,\"name\":\"a'b\",\"public_key\":\"x\"}",
        ] {
            assert!(
                matches!(
                    owner.prepare(EndpointId::new(), junk, true, NOW),
                    Err(DevicesError::Request(_))
                ),
                "{junk}"
            );
        }
        assert_eq!(owner.count(), 0);
    }

    #[test]
    fn an_invite_is_made_only_for_a_request_that_was_prepared_for_that_server() {
        let endpoint = EndpointId::new();
        let (_friend, owner, text) = asked_and_prepared("Ravi", endpoint);
        let request = DeviceRequest::decode(&text).unwrap();
        let report = good_report(&request);
        let mut read = false;
        // Another server: nothing is read from the store for it.
        let other = owner.finish(
            EndpointId::new(),
            &text,
            &report,
            || {
                read = true;
                Ok(facts())
            },
            NOW,
        );
        assert_eq!(other, Err(DevicesError::NotPrepared));
        assert!(
            !read,
            "the sealed credentials are not read for a request nobody made"
        );
        // Another friend's request, with its own key.
        let stranger = Joining::new().request("Ravi", NOW).unwrap().text;
        assert_eq!(
            owner.finish(endpoint, &stranger, &report, || Ok(facts()), NOW),
            Err(DevicesError::NotPrepared)
        );
        // The right one, but the same name under another key does not count either.
        assert_eq!(owner.count(), 1);
    }

    #[test]
    fn a_result_that_names_another_server_or_another_device_is_refused_and_the_request_stays() {
        let endpoint = EndpointId::new();
        let (_friend, owner, text) = asked_and_prepared("Ravi", endpoint);
        let request = DeviceRequest::decode(&text).unwrap();
        let port = dnet_config::session::SESSION_PORT;
        for bad in [
            // Another server's key, and another port.
            printed(&request, "10.9.0.3", &b64(6), port),
            printed(&request, "10.9.0.3", &b64(5), port + 1),
            // An address no device can have.
            printed(&request, "192.168.1.1", &b64(5), port),
            // Not a result at all.
            "hello".to_owned(),
            String::new(),
        ] {
            assert!(
                matches!(
                    owner.finish(endpoint, &text, &bad, || Ok(facts()), NOW),
                    Err(DevicesError::Report(_))
                ),
                "{bad}"
            );
        }
        // A result for a different device.
        let other = DeviceRequest::new("Other", &b64(3)).unwrap();
        assert!(matches!(
            owner.finish(endpoint, &text, &good_report(&other), || Ok(facts()), NOW),
            Err(DevicesError::Report(_))
        ));
        assert_eq!(
            owner.count(),
            1,
            "a bad paste does not cost the preparation"
        );
        assert!(owner
            .finish(endpoint, &text, &good_report(&request), || Ok(facts()), NOW)
            .is_ok());
    }

    #[test]
    fn a_preparation_that_waited_too_long_is_dropped() {
        let endpoint = EndpointId::new();
        let (_friend, owner, text) = asked_and_prepared("Ravi", endpoint);
        let request = DeviceRequest::decode(&text).unwrap();
        assert_eq!(
            owner.finish(
                endpoint,
                &text,
                &good_report(&request),
                || Ok(facts()),
                NOW + WAIT_S + 1
            ),
            Err(DevicesError::Expired)
        );
        assert_eq!(owner.count(), 0);
    }

    #[test]
    fn only_so_many_requests_wait_and_asking_twice_is_one() {
        let owner = Inviting::new();
        let endpoint = EndpointId::new();
        for i in 0..(MAX_PREPARED + 4) {
            let text = DeviceRequest::new(&format!("Friend {i}"), &b64(10 + i as u8))
                .unwrap()
                .encode();
            owner
                .prepare(endpoint, &text, true, NOW + i as u64)
                .unwrap();
        }
        assert_eq!(owner.count(), MAX_PREPARED);
        let again = DeviceRequest::new("Again", &b64(200)).unwrap().encode();
        owner.prepare(endpoint, &again, true, NOW + 100).unwrap();
        owner.prepare(endpoint, &again, true, NOW + 101).unwrap();
        assert_eq!(owner.count(), MAX_PREPARED);
    }

    #[test]
    fn a_server_whose_details_cannot_be_read_gives_that_reason_and_nothing_else() {
        let endpoint = EndpointId::new();
        let (_friend, owner, text) = asked_and_prepared("Ravi", endpoint);
        let request = DeviceRequest::decode(&text).unwrap();
        let result = owner.finish(
            endpoint,
            &text,
            &good_report(&request),
            || {
                Err(DevicesError::Unreadable(
                    "it has no credentials stored".into(),
                ))
            },
            NOW,
        );
        assert!(matches!(result, Err(DevicesError::Unreadable(_))));
        assert_eq!(owner.count(), 1);
    }

    #[test]
    fn checking_changes_nothing_and_an_approved_invite_is_handed_over_once_and_not_for_long() {
        let endpoint = EndpointId::new();
        let (_friend, owner, text) = asked_and_prepared("Ravi", endpoint);
        let request = DeviceRequest::decode(&text).unwrap();
        let report = good_report(&request);
        // A check says yes and leaves everything as it was.
        owner
            .check(endpoint, &text, &report, || Ok(facts()), NOW)
            .unwrap();
        assert_eq!(owner.count(), 1);
        assert!(!owner.is_ready(endpoint, &text, NOW));
        assert!(owner.take_ready(endpoint, &text, NOW).is_none());
        // A check says no for what finishing would refuse.
        assert!(matches!(
            owner.check(endpoint, &text, "hello", || Ok(facts()), NOW),
            Err(DevicesError::Report(_))
        ));
        // Finishing makes the invite and keeps it for the person who approved it.
        let made = owner
            .finish(endpoint, &text, &report, || Ok(facts()), NOW)
            .unwrap();
        assert_eq!(owner.count(), 0);
        assert!(owner.is_ready(endpoint, &text, NOW + 1));
        // Not for another server, and not for another request.
        assert!(!owner.is_ready(EndpointId::new(), &text, NOW + 1));
        assert!(owner
            .take_ready(EndpointId::new(), &text, NOW + 1)
            .is_none());
        // Once, and then it is gone.
        assert_eq!(owner.take_ready(endpoint, &text, NOW + 1), Some(made));
        assert!(owner.take_ready(endpoint, &text, NOW + 1).is_none());
    }

    #[test]
    fn an_approved_invite_that_nobody_asks_for_is_dropped() {
        let endpoint = EndpointId::new();
        let (_friend, owner, text) = asked_and_prepared("Ravi", endpoint);
        let request = DeviceRequest::decode(&text).unwrap();
        owner
            .finish(endpoint, &text, &good_report(&request), || Ok(facts()), NOW)
            .unwrap();
        assert!(!owner.is_ready(endpoint, &text, NOW + READY_FOR_S + 1));
        assert!(owner
            .take_ready(endpoint, &text, NOW + READY_FOR_S + 1)
            .is_none());
    }

    // ------------------------------------------------------------------ the edges the mutation run showed were not pinned

    #[test]
    fn the_waits_are_six_hours_for_a_request_ten_minutes_for_an_approved_invite_and_eight_prepared_at_most(
    ) {
        assert_eq!(WAIT_S, 21_600);
        assert_eq!(READY_FOR_S, 600);
        assert_eq!(MAX_PREPARED, 8);
    }

    #[test]
    fn a_join_that_waited_exactly_the_limit_is_still_good_and_one_second_more_is_not() {
        let friend = Joining::new();
        let asked = friend.request("Ravi laptop", NOW).unwrap();
        let request = DeviceRequest::decode(&asked.text).unwrap();
        let (owner, endpoint) = (Inviting::new(), EndpointId::new());
        owner.prepare(endpoint, &asked.text, true, NOW).unwrap();
        let invite = owner
            .finish(
                endpoint,
                &asked.text,
                &good_report(&request),
                || Ok(facts()),
                NOW,
            )
            .unwrap()
            .invite;
        // Exactly at the limit it is accepted (and the join keeps waiting, so the next call can show the expiry).
        assert!(friend.accept(&invite, NOW + WAIT_S).is_ok());
        assert!(matches!(
            friend.accept(&invite, NOW + WAIT_S + 1),
            Err(DevicesError::Expired)
        ));
    }

    #[test]
    fn a_preparation_that_waited_exactly_the_limit_is_still_good_and_one_second_more_is_expired() {
        let endpoint = EndpointId::new();
        let (_, owner, text) = asked_and_prepared("Ravi laptop", endpoint);
        let request = DeviceRequest::decode(&text).unwrap();
        let report = good_report(&request);
        assert!(owner
            .check(endpoint, &text, &report, || Ok(facts()), NOW + WAIT_S)
            .is_ok());
        assert_eq!(
            owner.check(endpoint, &text, &report, || Ok(facts()), NOW + WAIT_S + 1),
            Err(DevicesError::Expired)
        );
        // And once expired it is gone, not merely refused.
        assert_eq!(
            owner.check(endpoint, &text, &report, || Ok(facts()), NOW),
            Err(DevicesError::NotPrepared)
        );
    }

    #[test]
    fn the_same_friend_prepared_for_two_servers_is_two_preparations_and_for_one_server_twice_is_one(
    ) {
        let (first, second) = (EndpointId::new(), EndpointId::new());
        let friend = Joining::new();
        let asked = friend.request("Ravi laptop", NOW).unwrap();
        let request = DeviceRequest::decode(&asked.text).unwrap();
        let owner = Inviting::new();
        owner.prepare(first, &asked.text, true, NOW).unwrap();
        owner.prepare(second, &asked.text, true, NOW).unwrap();
        // Asking again for the first server does not disturb the second.
        owner.prepare(first, &asked.text, true, NOW + 5).unwrap();
        let report = good_report(&request);
        assert!(owner
            .check(first, &asked.text, &report, || Ok(facts()), NOW + 5)
            .is_ok());
        assert!(owner
            .check(second, &asked.text, &report, || Ok(facts()), NOW + 5)
            .is_ok());
        assert_eq!(lock(&owner.prepared).len(), 2);
    }

    #[test]
    fn an_approved_invite_waits_exactly_ten_minutes_and_is_handed_over_once() {
        let endpoint = EndpointId::new();
        let (_, owner, text) = asked_and_prepared("Ravi laptop", endpoint);
        let request = DeviceRequest::decode(&text).unwrap();
        owner
            .finish(endpoint, &text, &good_report(&request), || Ok(facts()), NOW)
            .unwrap();
        assert!(owner.is_ready(endpoint, &text, NOW + READY_FOR_S));
        assert!(!owner.is_ready(endpoint, &text, NOW + READY_FOR_S + 1));
        assert!(owner
            .take_ready(endpoint, &text, NOW + READY_FOR_S)
            .is_some());
        assert!(
            owner
                .take_ready(endpoint, &text, NOW + READY_FOR_S)
                .is_none(),
            "once"
        );
    }

    #[test]
    fn an_invite_that_nobody_asked_for_is_dropped_and_not_kept_for_the_next_request() {
        let endpoint = EndpointId::new();
        let (_, owner, text) = asked_and_prepared("Ravi laptop", endpoint);
        let request = DeviceRequest::decode(&text).unwrap();
        owner
            .finish(endpoint, &text, &good_report(&request), || Ok(facts()), NOW)
            .unwrap();
        // Later, another request is finished: the old one has expired and is no longer there.
        let (_, _, other_text) = {
            let friend = Joining::new();
            let asked = friend.request("Asha phone", NOW + 2 * READY_FOR_S).unwrap();
            owner
                .prepare(endpoint, &asked.text, true, NOW + 2 * READY_FOR_S)
                .unwrap();
            (friend, (), asked.text)
        };
        let other = DeviceRequest::decode(&other_text).unwrap();
        owner
            .finish(
                endpoint,
                &other_text,
                &good_report(&other),
                || Ok(facts()),
                NOW + 2 * READY_FOR_S,
            )
            .unwrap();
        assert_eq!(lock(&owner.ready).len(), 1, "the expired one was dropped");
        assert!(!owner.is_ready(endpoint, &text, NOW + 2 * READY_FOR_S));
    }

    #[test]
    fn finishing_the_same_request_again_replaces_the_waiting_invite_and_another_server_keeps_its_own(
    ) {
        let (first, second) = (EndpointId::new(), EndpointId::new());
        let friend = Joining::new();
        let asked = friend.request("Ravi laptop", NOW).unwrap();
        let request = DeviceRequest::decode(&asked.text).unwrap();
        let owner = Inviting::new();
        owner.prepare(first, &asked.text, true, NOW).unwrap();
        owner.prepare(second, &asked.text, true, NOW).unwrap();
        let report = good_report(&request);
        owner
            .finish(first, &asked.text, &report, || Ok(facts()), NOW)
            .unwrap();
        owner
            .finish(second, &asked.text, &report, || Ok(facts()), NOW)
            .unwrap();
        // The first server's request was used up; asking again prepares it afresh, and finishing keeps one invite.
        owner.prepare(first, &asked.text, true, NOW + 1).unwrap();
        owner
            .finish(first, &asked.text, &report, || Ok(facts()), NOW + 1)
            .unwrap();
        assert_eq!(
            lock(&owner.ready).len(),
            2,
            "one per server, never two for the same"
        );
        assert!(owner.is_ready(first, &asked.text, NOW + 1));
        assert!(owner.is_ready(second, &asked.text, NOW + 1));
    }
}
