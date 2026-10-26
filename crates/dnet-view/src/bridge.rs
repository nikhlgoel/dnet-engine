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

    pub async fn rules(&self) -> Result<Value, String> {
        match self.link.call(Request::ListRules).await {
            Err(error) => Err(error.to_string()),
            Ok(Reply::Refused(refusal)) => Err(refusal_text(&refusal.detail)),
            Ok(Reply::Done(value)) => lists::rules(&value),
        }
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
