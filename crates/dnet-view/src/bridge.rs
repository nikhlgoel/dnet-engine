//! T100 — every command the window may give, and every question it may ask.
//!
//! The web view's capability list is the minimum (ADR-0007 R4): these are the commands, and there is no
//! others. Each takes plain values, checks them with the service's own grammar before sending (so a typo is
//! caught here and nothing goes out), and answers in the window's shapes: a view-model for a question, an
//! outcome (`outcome`) for a request that changes something.
//!
//! Nothing here keeps what it is given. The credentials file's text goes into a typed value, then into one
//! request, then out of scope; it is never logged, never returned, and an error about it says what was
//! wrong with it, not what it said.

use dnet_config::credentials::EndpointCredentials;
use dnet_ipc::client::Reply;
use dnet_ipc::netview::{decode_paths, decode_stats};
use dnet_ipc::protocol::{decode_request, decode_state_snapshot, NewEndpoint, Request};
use serde_json::{json, Value};

use crate::link::Link;
use crate::outcome::{from_reply, refused};
use crate::{lists, snapshot};

/// What a UTF-8 byte-order mark looks like at the start of a file a PowerShell redirect wrote.
const BOM: &str = "\u{feff}";

/// The commands, over a link to the service.
pub struct Bridge<L> {
    link: L,
}

impl<L: Link> Bridge<L> {
    #[must_use]
    pub fn new(link: L) -> Self {
        Self { link }
    }

    /// What this build can do, so the window shows a feature it lacks as unavailable and never fakes it.
    /// Setting up a server (T093 and a provider) does not exist yet. Checking for updated connection methods
    /// does, and the service answers plainly when this build has no trust anchor for it.
    #[must_use]
    pub fn capabilities(&self) -> Value {
        json!({ "provisioning": false, "updates": true })
    }

    // ------------------------------------------------------------------ questions

    /// The whole picture: state, networks and counters, as one view. `last_because` is the reason of the
    /// latest event, which the caller keeps. A service that cannot answer paths or stats (an older one) is
    /// shown as not measuring; one that cannot answer the state at all is an error.
    pub async fn snapshot(&self, last_because: Option<&str>, now_ms: u64) -> Result<Value, String> {
        let state_reply = self.link.call(Request::GetState).await;
        let state = match state_reply {
            Err(error) => return Err(error.to_string()),
            Ok(Reply::Refused(refusal)) => return Err(refusal_text(&refusal.detail)),
            Ok(Reply::Done(value)) => decode_state_snapshot(&value.to_string())
                .map_err(|e| format!("the service's state could not be read: {e}"))?,
        };
        let paths = self
            .optional(Request::GetPaths, |v| decode_paths(&v.to_string()))
            .await;
        let stats = self
            .optional(Request::GetStats, |v| decode_stats(&v.to_string()))
            .await;
        Ok(snapshot::view(
            &state,
            paths.as_ref(),
            stats.as_ref(),
            last_because,
            now_ms,
        ))
    }

    /// A question a service may be too old to answer (T144): an old service's `InvalidRequest`, a failure to
    /// read the answer, and a failure to ask all read as "cannot say", which is shown as not measured.
    async fn optional<T, E>(
        &self,
        request: Request,
        decode: impl FnOnce(&Value) -> Result<T, E>,
    ) -> Option<T> {
        match self.link.call(request).await {
            Ok(Reply::Done(value)) => decode(&value).ok(),
            Ok(Reply::Refused(_)) | Err(_) => None,
        }
    }

    pub async fn endpoints(&self) -> Result<Value, String> {
        match self.link.call(Request::ListEndpoints).await {
            Err(error) => Err(error.to_string()),
            Ok(Reply::Refused(refusal)) => Err(refusal_text(&refusal.detail)),
            Ok(Reply::Done(value)) => lists::endpoints(&value),
        }
    }

    /// The live map of parts (T170). An older service that does not know the request is `supported: false`;
    /// any other refusal, and anything the strict decoder refuses, is an error that repeats nothing.
    pub async fn components(&self) -> Result<Value, String> {
        match self.link.call(Request::GetComponents).await {
            Err(error) => Err(error.to_string()),
            Ok(Reply::Refused(refusal))
                if refusal.code == "InvalidRequest"
                    && refusal.detail.contains("unknown request") =>
            {
                Ok(lists::components_unsupported())
            }
            Ok(Reply::Refused(refusal)) => Err(refusal_text(&refusal.detail)),
            Ok(Reply::Done(value)) => {
                dnet_ipc::componentview::decode_components(&value.to_string())
                    .map(|reply| lists::components(&reply))
                    .map_err(|_| {
                        "The service's list of parts was not what was expected.".to_owned()
                    })
            }
        }
    }

    pub async fn profiles(&self) -> Result<Value, String> {
        match self.link.call(Request::ListProfiles).await {
            Err(error) => Err(error.to_string()),
            Ok(Reply::Refused(refusal)) => Err(refusal_text(&refusal.detail)),
            Ok(Reply::Done(value)) => lists::profiles(&value),
        }
    }

    pub async fn rules(&self) -> Result<Value, String> {
        match self.link.call(Request::ListRules).await {
            Err(error) => Err(error.to_string()),
            Ok(Reply::Refused(refusal)) => Err(refusal_text(&refusal.detail)),
            Ok(Reply::Done(value)) => lists::rules(&value),
        }
    }

    /// The changes waiting for an elevated approval (T160).
    pub async fn pending(&self) -> Result<Value, String> {
        match self.link.call(Request::ListPending).await {
            Err(error) => Err(error.to_string()),
            Ok(Reply::Refused(refusal)) => Err(refusal_text(&refusal.detail)),
            Ok(Reply::Done(value)) => lists::pending(&value),
        }
    }

    /// Drop a waiting change without applying it. Approving is not here: only an elevated client may, and
    /// the window is not one, so it opens `dnetctl approve` (the shell does), which asks Windows.
    pub async fn reject_change(&self, id: &str) -> Value {
        let wire = json!({ "request": "RejectChange", "id": id });
        let request = match decode_request(&wire.to_string()) {
            Ok(request) => request,
            Err(why) => return refused(&why.to_string(), "Refused"),
        };
        from_reply(self.link.call(request).await, |reply| {
            if reply.get("applied").and_then(Value::as_bool) == Some(true) {
                Ok(json!({}))
            } else {
                Err("The service did not say that the change was dropped.".to_owned())
            }
        })
    }

    // ------------------------------------------------------------------ the one control

    /// Turn the connection on or off. Turning it on without `acknowledge_tier2` may come back as a request
    /// for that consent (`code: "TierConsentRequired"`); the window asks, and asks again with it.
    pub async fn stabilize(&self, on: bool, acknowledge_tier2: bool) -> Value {
        let request = if on {
            Request::Connect {
                acknowledge_tier2,
                profile: None,
                endpoint: None,
            }
        } else {
            Request::Disconnect
        };
        from_reply(self.link.call(request).await, |_| Ok(json!({})))
    }

    // ------------------------------------------------------------------ endpoints

    /// Add a server the person already runs. `credentials` is the text of the connection file; it is read
    /// with the same rules the service stores credentials under, so what passes here can always be saved.
    pub async fn add_endpoint(&self, label: &str, host: &str, credentials: &str) -> Value {
        let request = match add_endpoint_request(label, host, credentials) {
            Ok(request) => request,
            Err(why) => return refused(&why, "Refused"),
        };
        from_reply(self.link.call(request).await, |reply| {
            let id = reply
                .get("endpoint")
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    "The service added the endpoint but did not say which.".to_owned()
                })?;
            Ok(json!({ "id": id }))
        })
    }

    pub async fn remove_endpoint(&self, id: &str) -> Value {
        self.by_id("RemoveEndpoint", id, None).await
    }

    pub async fn set_endpoint_enabled(&self, id: &str, enabled: bool) -> Value {
        self.by_id("SetEndpointEnabled", id, Some(enabled)).await
    }

    /// A request that names one endpoint, checked by the service's own grammar for an id.
    async fn by_id(&self, name: &str, id: &str, enabled: Option<bool>) -> Value {
        let mut wire = json!({ "request": name, "endpoint": id });
        if let Some(enabled) = enabled {
            wire["enabled"] = Value::Bool(enabled);
        }
        let request = match decode_request(&wire.to_string()) {
            Ok(request) => request,
            Err(why) => return refused(&why.to_string(), "Refused"),
        };
        from_reply(self.link.call(request).await, |reply| {
            if reply.get("applied").and_then(Value::as_bool) == Some(true) {
                Ok(json!({}))
            } else {
                Err("The service did not say that the change was made.".to_owned())
            }
        })
    }

    // ------------------------------------------------------------------ the person's own server (T150)

    /// Begin setting up a server: the script to run on it and the ports to open. `arch` is `amd64` or
    /// `arm64`. The reply is read as untrusted input; what is not as promised is never shown.
    pub async fn prepare_server(&self, arch: &str) -> Value {
        let wire = json!({ "request": "PrepareServer", "arch": arch });
        let request = match decode_request(&wire.to_string()) {
            Ok(request) => request,
            Err(why) => return refused(&why.to_string(), "Refused"),
        };
        from_reply(self.link.call(request).await, |reply| {
            let prepared = dnet_ipc::server_setup::decode_prepared(&reply.to_string())
                .map_err(|_| "The service's answer was not what was expected.".to_owned())?;
            Ok(json!({
                "arch": prepared.arch.as_str(),
                "script": prepared.script,
                "ports": prepared.ports.iter()
                    .map(|p| json!({ "protocol": p.protocol, "port": p.port }))
                    .collect::<Vec<_>>(),
                "validForMinutes": prepared.valid_for_s / 60,
            }))
        })
    }

    /// Finish it: `report` is the text the server printed, pasted back. Checked by the service's own
    /// grammar before anything is sent; the reply names the new server.
    pub async fn finish_server(&self, label: &str, host: &str, report: &str) -> Value {
        let wire = json!({
            "request": "FinishServer", "label": label, "host": host, "report": report,
        });
        let request = match decode_request(&wire.to_string()) {
            Ok(request) => request,
            Err(why) => return refused(&why.to_string(), "Refused"),
        };
        from_reply(self.link.call(request).await, |reply| {
            let id = reply
                .get("endpoint")
                .and_then(Value::as_str)
                .ok_or_else(|| "The service added the server but did not say which.".to_owned())?;
            Ok(json!({ "id": crate::text::plain(id, 64) }))
        })
    }

    // ------------------------------------------------------------------ a friend's device (T188)

    /// A friend's computer asks to join: the text to send to the owner (a name and the public half of a key
    /// made on this computer). Nothing is saved. The reply is read as untrusted input.
    pub async fn request_join(&self, name: &str) -> Value {
        let wire = json!({ "request": "RequestJoin", "name": name });
        let request = match decode_request(&wire.to_string()) {
            Ok(request) => request,
            Err(why) => return refused(&why.to_string(), "Refused"),
        };
        from_reply(self.link.call(request).await, |reply| {
            let asked = dnet_ipc::devices::decode_join_requested(&reply.to_string())
                .map_err(|_| "The service's answer was not what was expected.".to_owned())?;
            Ok(json!({
                "name": asked.name,
                "text": asked.text,
                "validForMinutes": asked.valid_for_s / 60,
            }))
        })
    }

    /// The owner's invite, pasted: the server is added after an approval, with this computer's own key.
    /// `label` names the server here (the invite's own name when `None`). Checked by the service's own grammar
    /// before anything is sent; the reply names the new server.
    pub async fn accept_invite(&self, invite: &str, label: Option<&str>) -> Value {
        let mut wire = json!({ "request": "AcceptInvite", "invite": invite });
        if let Some(label) = label {
            wire["label"] = Value::String(label.to_owned());
        }
        let request = match decode_request(&wire.to_string()) {
            Ok(request) => request,
            Err(why) => return refused(&why.to_string(), "Refused"),
        };
        from_reply(self.link.call(request).await, |reply| {
            let id = reply
                .get("endpoint")
                .and_then(Value::as_str)
                .ok_or_else(|| "The service added the server but did not say which.".to_owned())?;
            Ok(json!({ "id": crate::text::plain(id, 64) }))
        })
    }

    /// The owner adds a friend's device to `endpoint`: the script to run on that server. `text` is what the
    /// friend sent. The reply is read as untrusted input.
    pub async fn prepare_device(&self, endpoint: &str, text: &str) -> Value {
        let wire = json!({ "request": "PrepareDevice", "endpoint": endpoint, "text": text });
        let request = match decode_request(&wire.to_string()) {
            Ok(request) => request,
            Err(why) => return refused(&why.to_string(), "Refused"),
        };
        from_reply(self.link.call(request).await, |reply| {
            let prepared = dnet_ipc::devices::decode_device_prepared(&reply.to_string())
                .map_err(|_| "The service's answer was not what was expected.".to_owned())?;
            Ok(json!({
                "name": prepared.name,
                "script": prepared.script,
                "validForMinutes": prepared.valid_for_s / 60,
            }))
        })
    }

    /// Finish it: `report` is what the script printed, pasted back. The reply is the invite to send to the
    /// friend, read as untrusted input.
    pub async fn finish_device(&self, endpoint: &str, text: &str, report: &str) -> Value {
        let wire = json!({
            "request": "FinishDevice", "endpoint": endpoint, "text": text, "report": report,
        });
        let request = match decode_request(&wire.to_string()) {
            Ok(request) => request,
            Err(why) => return refused(&why.to_string(), "Refused"),
        };
        from_reply(self.link.call(request).await, |reply| {
            let invited = dnet_ipc::devices::decode_device_invited(&reply.to_string())
                .map_err(|_| "The service's answer was not what was expected.".to_owned())?;
            Ok(json!({
                "name": invited.name,
                "address": invited.address,
                "invite": invited.invite,
            }))
        })
    }

    // ------------------------------------------------------------------ rules (T108)

    /// Add a rule: `kind` is `domain`, `domain_suffix`, `ip_cidr` or `application`; `action` is `tunnel` or
    /// `bypass`. Checked by the service's own grammar before anything is sent; the reply names the new rule.
    pub async fn add_rule(&self, kind: &str, value: &str, action: &str) -> Value {
        let wire = json!({ "request": "AddRule", "kind": kind, "value": value, "action": action });
        let request = match decode_request(&wire.to_string()) {
            Ok(request) => request,
            Err(why) => return refused(&why.to_string(), "Refused"),
        };
        from_reply(self.link.call(request).await, |reply| {
            let id = reply
                .get("rule")
                .and_then(Value::as_str)
                .ok_or_else(|| "The service added the rule but did not say which.".to_owned())?;
            Ok(json!({ "id": crate::text::plain(id, 64) }))
        })
    }

    pub async fn remove_rule(&self, id: &str) -> Value {
        let wire = json!({ "request": "RemoveRule", "rule": id });
        let request = match decode_request(&wire.to_string()) {
            Ok(request) => request,
            Err(why) => return refused(&why.to_string(), "Refused"),
        };
        from_reply(self.link.call(request).await, |reply| {
            if reply.get("applied").and_then(Value::as_bool) == Some(true) {
                Ok(json!({}))
            } else {
                Err("The service did not say that the change was made.".to_owned())
            }
        })
    }

    // ------------------------------------------------------------------ Brutal (T105)

    /// Turn Brutal on for `profile` with `(up, down)` Mbit/s, or off with `None`. `warning_revision` is the
    /// revision of the warning the window showed and the person accepted; the service records it only if it
    /// is the one in force. Checked by the service's own grammar before anything is sent.
    pub async fn set_brutal(
        &self,
        profile: &str,
        bandwidth: Option<(u32, u32)>,
        warning_revision: u32,
    ) -> Value {
        let wire = match bandwidth {
            Some((up, down)) => json!({
                "request": "EnableBrutal",
                "profile": profile,
                "up_mbps": up,
                "down_mbps": down,
                "warning_revision": warning_revision,
            }),
            None => json!({ "request": "DisableBrutal", "profile": profile }),
        };
        let request = match decode_request(&wire.to_string()) {
            Ok(request) => request,
            Err(why) => return refused(&why.to_string(), "Refused"),
        };
        from_reply(self.link.call(request).await, |reply| {
            if reply.get("applied").and_then(Value::as_bool) == Some(true) {
                Ok(json!({}))
            } else {
                Err("The service did not say that the change was made.".to_owned())
            }
        })
    }

    // ------------------------------------------------------------------ encrypted name lookups

    /// Block programs' own encrypted name lookups, or stop blocking them. Stopping is the one-action opt-out
    /// and its reply states what it costs, which the window shows; a reply without that is malformed
    /// (contract §Configuration requests), and is reported as such rather than as a change that was explained.
    pub async fn set_encrypted_dns(&self, block: bool) -> Value {
        from_reply(
            self.link
                .call(Request::SetEncryptedDnsHandling { block })
                .await,
            |reply| {
                if block {
                    return Ok(json!({}));
                }
                match reply.get("consequence").and_then(Value::as_str) {
                Some(consequence) if !consequence.is_empty() => {
                    Ok(json!({ "consequence": crate::text::plain(consequence, 400) }))
                }
                _ => Err("The service changed the setting but did not say what it costs. Open Settings to see where it stands."
                    .to_owned()),
            }
            },
        )
    }

    // ------------------------------------------------------------------ updates

    /// Check for updated connection-method definitions now, because the person asked. The reply says which
    /// network the check goes over (through the tunnel, or directly while disconnected); the result arrives
    /// as an event.
    pub async fn check_updates(&self) -> Value {
        from_reply(self.link.call(Request::FetchFeed).await, |reply| {
            if reply.get("started").and_then(Value::as_bool) != Some(true) {
                return Err("The service did not start the check.".to_owned());
            }
            match reply.get("route").and_then(Value::as_str) {
                Some(route @ ("tunnel" | "physical")) => Ok(json!({ "route": route })),
                _ => Err("The service did not say which network the check uses.".to_owned()),
            }
        })
    }

    /// Open the sign-in page of a captive portal. The service does not hand a client the address (the
    /// network chooses it, and it is offered only to the person's own browser by the service), so there is
    /// nothing to open yet; the person is told what to do instead. The honest answer, not a guess at an
    /// address.
    #[must_use]
    pub fn open_login_page(&self) -> Value {
        refused(
            "This version cannot open the sign-in page for you. Open any web page in your browser; the network will show its sign-in page.",
            "Refused",
        )
    }
}

fn refusal_text(detail: &str) -> String {
    if detail.is_empty() {
        "The service declined, and gave no reason.".to_owned()
    } else {
        crate::text::plain(detail, 400)
    }
}

/// The request for a new endpoint, from what was typed and what the credentials file holds. The service's own
/// checks, applied here, so a mistake is reported at once and nothing is sent.
fn add_endpoint_request(label: &str, host: &str, credentials: &str) -> Result<Request, String> {
    // The reader refuses anything longer than a stored credential set can be, before it looks inside.
    let text = credentials.strip_prefix(BOM).unwrap_or(credentials);
    let credentials = EndpointCredentials::from_plaintext_json(text.as_bytes())
        .map_err(|e| format!("The connection file is not usable: {e}"))?;
    if credentials.is_empty() {
        return Err("The connection file holds no connection method.".to_owned());
    }
    NewEndpoint::new(label, host, credentials)
        .map(|new| Request::AddEndpoint(Box::new(new)))
        .map_err(|e| e.to_string())
}
