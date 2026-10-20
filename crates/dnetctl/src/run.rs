//! T127 — doing what was asked, and saying what happened.
//!
//! Generic over how the daemon is reached ([`Connector`]) and where output goes ([`Sink`]), so
//! every command is tested against the real server dispatch in memory, with the clock paused.
//!
//! **What an exit code means** (the scripts' view of the same answer the prose gives):
//! 0 done; 1 the service refused or the connection failed; 2 usage; 3 the service cannot be
//! reached; 4 timed out waiting (the work carries on in the service); 5 the reply was not one this
//! client understands.
//!
//! Waiting is polling `GetState`, not a subscription: it needs no second connection, works with
//! the subscriber limit reached, and a state is an answer where an event is only a hint.

use std::future::Future;
use std::time::Duration;

use dnet_core::ids::ProfileId;
use dnet_ipc::client::{ClientError, Connection, Reply};
use dnet_ipc::protocol::{
    decode_request, decode_state_snapshot, encode_request, ConnectionStatus, Request, StateSnapshot,
};
use dnet_ipc::wire::decode_event_view;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;

use crate::cli::{Command, Invocation, USAGE};
use crate::render;

pub mod exit {
    pub const OK: i32 = 0;
    pub const REFUSED: i32 = 1;
    pub const USAGE: i32 = 2;
    pub const UNREACHABLE: i32 = 3;
    pub const TIMED_OUT: i32 = 4;
    pub const UNEXPECTED: i32 = 5;
}

/// How long one request may wait for its answer.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// How often a waiting command asks for the state again.
pub const POLL_EVERY: Duration = Duration::from_millis(500);

/// After a connect is accepted the state may, for an instant, still be the one before it. A
/// `Disconnected` that lasts longer than this many polls is the connection having ended.
const DISCONNECTED_GRACE_POLLS: u32 = 4;

/// Where output goes. Results go to `out`, problems to `err`.
pub trait Sink {
    fn out(&mut self, line: &str);
    fn err(&mut self, line: &str);
}

/// How the daemon is reached.
pub trait Connector {
    type Stream: AsyncRead + AsyncWrite + Unpin;
    /// `trust_any_service` is the development opt-out of checking who owns the pipe.
    fn connect(
        &self,
        trust_any_service: bool,
    ) -> impl Future<Output = Result<Connection<Self::Stream>, ClientError>>;
}

/// What one request came to.
enum Answer {
    Done(Value),
    Refused(dnet_ipc::client::Refusal),
}

fn problem(sink: &mut dyn Sink, error: &ClientError) -> i32 {
    sink.err(&format!("dnetctl: {}", render::plain(&error.to_string())));
    match error {
        ClientError::Unreachable(_) => exit::UNREACHABLE,
        _ => exit::UNEXPECTED,
    }
}

fn refusal(sink: &mut dyn Sink, refusal: &dnet_ipc::client::Refusal) -> i32 {
    let mut line = format!(
        "dnetctl: the service refused: {}",
        render::plain(&refusal.detail)
    );
    if refusal.detail.is_empty() {
        line = format!(
            "dnetctl: the service refused ({})",
            render::plain(&refusal.code)
        );
    }
    sink.err(&line);
    if refusal.retryable {
        sink.err("This may pass; try again in a moment.");
    }
    if refusal.code == "TierDowngradeRequiresConsent" {
        sink.err(
            "That profile's connections may break when the network interface changes. Run again with --accept-tier2 to accept that.",
        );
    }
    exit::REFUSED
}

async fn ask<S: AsyncRead + AsyncWrite + Unpin>(
    connection: &mut Connection<S>,
    request: &Request,
) -> Result<Answer, ClientError> {
    match tokio::time::timeout(REQUEST_TIMEOUT, connection.call(request)).await {
        Err(_) => Err(ClientError::Io(
            "the service did not answer in time".to_string(),
        )),
        Ok(Err(e)) => Err(e),
        Ok(Ok(Reply::Done(value))) => Ok(Answer::Done(value)),
        Ok(Ok(Reply::Refused(r))) => Ok(Answer::Refused(r)),
    }
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

fn snapshot(value: &Value) -> Result<StateSnapshot, ClientError> {
    decode_state_snapshot(&value.to_string()).map_err(|_| {
        ClientError::Malformed("the state is not one this client understands".to_string())
    })
}

/// Run one invocation. Returns the process exit code.
pub async fn run<C: Connector>(
    invocation: Invocation,
    connector: &C,
    sink: &mut dyn Sink,
    interrupt: impl Future<Output = ()>,
) -> i32 {
    if invocation.command == Command::Help {
        sink.out(USAGE);
        return exit::OK;
    }

    // Checked before the service is bothered, so a typo is a usage error and sends nothing.
    let request = match &invocation.command {
        Command::Connect {
            profile,
            acknowledge_tier2,
            ..
        } => {
            let request = Request::Connect {
                acknowledge_tier2: *acknowledge_tier2,
                profile: profile.as_deref().map(ProfileId::new),
                endpoint: None,
            };
            // The service's own grammar for a profile id, applied here.
            if let Err(e) = decode_request(&encode_request(&request)) {
                sink.err(&format!("dnetctl: {}", render::plain(&e.to_string())));
                return exit::USAGE;
            }
            Some(request)
        }
        _ => None,
    };

    let mut connection = match connector.connect(invocation.trust_any_service).await {
        Ok(connection) => connection,
        Err(e) => return problem(sink, &e),
    };

    match invocation.command {
        Command::Help => unreachable!("handled above"),
        Command::Status => status(&mut connection, invocation.json, sink).await,
        Command::Profiles => list(&mut connection, Request::ListProfiles, &invocation, sink).await,
        Command::Endpoints => {
            list(&mut connection, Request::ListEndpoints, &invocation, sink).await
        }
        Command::Connect { wait, .. } => {
            let request = request.expect("built above for a connect");
            connect(&mut connection, request, wait, &invocation, sink).await
        }
        Command::Disconnect { wait } => disconnect(&mut connection, wait, &invocation, sink).await,
        Command::Events { follow } => {
            events(&mut connection, follow, invocation.json, sink, interrupt).await
        }
    }
}

async fn status<S: AsyncRead + AsyncWrite + Unpin>(
    connection: &mut Connection<S>,
    json: bool,
    sink: &mut dyn Sink,
) -> i32 {
    match ask(connection, &Request::GetState).await {
        Err(e) => problem(sink, &e),
        Ok(Answer::Refused(r)) => refusal(sink, &r),
        Ok(Answer::Done(value)) => {
            if json {
                sink.out(&pretty(&value));
                return exit::OK;
            }
            match snapshot(&value) {
                Ok(state) => {
                    sink.out(&render::state(&state));
                    exit::OK
                }
                Err(e) => problem(sink, &e),
            }
        }
    }
}

async fn list<S: AsyncRead + AsyncWrite + Unpin>(
    connection: &mut Connection<S>,
    request: Request,
    invocation: &Invocation,
    sink: &mut dyn Sink,
) -> i32 {
    match ask(connection, &request).await {
        Err(e) => problem(sink, &e),
        Ok(Answer::Refused(r)) => refusal(sink, &r),
        Ok(Answer::Done(value)) => {
            if invocation.json {
                sink.out(&pretty(&value));
                return exit::OK;
            }
            let text = if request == Request::ListProfiles {
                render::profiles(&value)
            } else {
                render::endpoints(&value)
            };
            match text {
                Ok(text) => {
                    sink.out(&text);
                    exit::OK
                }
                Err(why) => problem(sink, &ClientError::Malformed(why)),
            }
        }
    }
}

/// Print the final state of a wait, as prose or as the service's own JSON.
fn finish(state: &StateSnapshot, value: &Value, json: bool, sink: &mut dyn Sink) {
    if json {
        sink.out(&pretty(value));
    } else {
        sink.out(&render::state(state));
    }
}

async fn connect<S: AsyncRead + AsyncWrite + Unpin>(
    connection: &mut Connection<S>,
    request: Request,
    wait: bool,
    invocation: &Invocation,
    sink: &mut dyn Sink,
) -> i32 {
    match ask(connection, &request).await {
        Err(e) => return problem(sink, &e),
        Ok(Answer::Refused(r)) => return refusal(sink, &r),
        Ok(Answer::Done(_)) => {}
    }
    if !wait {
        if !invocation.json {
            sink.out("Connect requested. Run 'dnetctl status' to see how it goes.");
        }
        return exit::OK;
    }

    let deadline = Instant::now() + invocation.timeout;
    let mut said_connecting = false;
    let mut disconnected_polls = 0;
    loop {
        let (state, value) = match ask(connection, &Request::GetState).await {
            Err(e) => return problem(sink, &e),
            Ok(Answer::Refused(r)) => return refusal(sink, &r),
            Ok(Answer::Done(value)) => match snapshot(&value) {
                Ok(state) => (state, value),
                Err(e) => return problem(sink, &e),
            },
        };
        match state.status {
            ConnectionStatus::Connected => {
                finish(&state, &value, invocation.json, sink);
                return exit::OK;
            }
            ConnectionStatus::Failed => {
                finish(&state, &value, invocation.json, sink);
                return exit::REFUSED;
            }
            ConnectionStatus::Disconnected => {
                disconnected_polls += 1;
                if disconnected_polls > DISCONNECTED_GRACE_POLLS {
                    sink.err(
                        "dnetctl: the connection ended before it was made (it was disconnected).",
                    );
                    finish(&state, &value, invocation.json, sink);
                    return exit::REFUSED;
                }
            }
            ConnectionStatus::Probing => {
                disconnected_polls = 0;
                if !said_connecting && !invocation.json {
                    sink.out("Connecting...");
                    said_connecting = true;
                }
            }
        }
        if Instant::now() >= deadline {
            sink.err(&format!(
                "dnetctl: still connecting after {} s. The service carries on in the background; run 'dnetctl status' to see where it got to.",
                invocation.timeout.as_secs()
            ));
            return exit::TIMED_OUT;
        }
        tokio::time::sleep(POLL_EVERY).await;
    }
}

async fn disconnect<S: AsyncRead + AsyncWrite + Unpin>(
    connection: &mut Connection<S>,
    wait: bool,
    invocation: &Invocation,
    sink: &mut dyn Sink,
) -> i32 {
    match ask(connection, &Request::Disconnect).await {
        Err(e) => return problem(sink, &e),
        // Asked to be disconnected and already is: nothing to do, and not a failure.
        Ok(Answer::Refused(r)) if r.code == "NotConnected" => {
            if !invocation.json {
                sink.out("Not connected.");
            }
            return exit::OK;
        }
        Ok(Answer::Refused(r)) => return refusal(sink, &r),
        Ok(Answer::Done(_)) => {}
    }
    if !wait {
        if !invocation.json {
            sink.out("Disconnect requested.");
        }
        return exit::OK;
    }

    let deadline = Instant::now() + invocation.timeout;
    loop {
        let (state, value) = match ask(connection, &Request::GetState).await {
            Err(e) => return problem(sink, &e),
            Ok(Answer::Refused(r)) => return refusal(sink, &r),
            Ok(Answer::Done(value)) => match snapshot(&value) {
                Ok(state) => (state, value),
                Err(e) => return problem(sink, &e),
            },
        };
        if state.status == ConnectionStatus::Disconnected {
            if invocation.json {
                sink.out(&pretty(&value));
            } else {
                sink.out("Disconnected.");
            }
            return exit::OK;
        }
        if Instant::now() >= deadline {
            sink.err(&format!(
                "dnetctl: still disconnecting after {} s. The service carries on in the background; run 'dnetctl status' to see where it got to.",
                invocation.timeout.as_secs()
            ));
            return exit::TIMED_OUT;
        }
        tokio::time::sleep(POLL_EVERY).await;
    }
}

async fn events<S: AsyncRead + AsyncWrite + Unpin>(
    connection: &mut Connection<S>,
    follow: bool,
    json: bool,
    sink: &mut dyn Sink,
    interrupt: impl Future<Output = ()>,
) -> i32 {
    if let Err(e) = connection.send(&Request::Subscribe).await {
        return problem(sink, &e);
    }
    // The acknowledgement says how many events of the session so far follow.
    let ack = match connection.next_frame().await {
        Err(e) => return problem(sink, &e),
        Ok(None) => return problem(sink, &ClientError::Closed),
        Ok(Some(payload)) => payload,
    };
    let backlog = match dnet_ipc::client::classify_reply(&ack) {
        Err(e) => return problem(sink, &e),
        Ok(Reply::Refused(r)) => return refusal(sink, &r),
        Ok(Reply::Done(value)) if value.get("subscribed") == Some(&Value::Bool(true)) => value
            .get("backlog")
            .and_then(Value::as_u64)
            .unwrap_or_default(),
        Ok(Reply::Done(_)) => {
            return problem(
                sink,
                &ClientError::Malformed("not an acknowledgement of the subscription".into()),
            )
        }
    };

    let show = |payload: &str, sink: &mut dyn Sink| {
        if json {
            sink.out(payload);
        } else {
            match decode_event_view(payload) {
                Ok(view) => sink.out(&render::event(&view)),
                // Said, not skipped: a silent gap in "what did the service do" would mislead.
                Err(_) => sink.out("#- (an event this client could not read)"),
            }
        }
    };

    if backlog == 0 && !json && !follow {
        sink.out("No events in this session yet.");
    }
    for _ in 0..backlog {
        match connection.next_frame().await {
            Err(e) => return problem(sink, &e),
            Ok(None) => return exit::OK,
            Ok(Some(payload)) => show(&payload, sink),
        }
    }
    if !follow {
        return exit::OK;
    }

    tokio::pin!(interrupt);
    loop {
        tokio::select! {
            _ = &mut interrupt => return exit::OK,
            frame = connection.next_frame() => match frame {
                Err(e) => return problem(sink, &e),
                Ok(None) => {
                    sink.err("dnetctl: the service closed the event stream.");
                    return exit::OK;
                }
                Ok(Some(payload)) => show(&payload, sink),
            },
        }
    }
}

#[cfg(test)]
mod tests;
