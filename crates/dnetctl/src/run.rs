//! T127 — doing what was asked, and saying what happened.
//!
//! Generic over how the daemon is reached ([`Connector`]) and where output goes ([`Sink`]), so
//! every command is tested against the real server dispatch in memory, with the clock paused.
//!
//! **What an exit code means** (the scripts' view of the same answer the prose gives):
//! 0 done; 1 the service refused or the connection failed; 2 usage; 3 the service cannot be
//! reached; 4 timed out waiting (the work carries on in the service); 5 the reply was not one this
//! client understands; 6 this program and the service do not speak a common protocol version.
//!
//! **Every command starts by asking the service which protocol it speaks** (T132) and goes no
//! further if the two cannot talk, because anything sent after that would be read by a service that
//! may not mean what this program means. `dnetctl version` is the exception: it is how a person
//! finds out why, so it reports the mismatch instead of stopping at it.
//!
//! Waiting is polling `GetState`, not a subscription: it needs no second connection, works with
//! the subscriber limit reached, and a state is an answer where an event is only a hint.

use std::future::Future;
use std::time::Duration;

use dnet_core::ids::ProfileId;
use dnet_ipc::client::{check_version, ClientError, Connection, Reply, VersionCheck};
use dnet_ipc::protocol::{
    decode_request, decode_state_snapshot, encode_request, ConnectionStatus, FeedImport,
    NewEndpoint, Request, StateSnapshot,
};
use dnet_ipc::version::{self, ServiceVersion};
use dnet_ipc::wire::decode_event_view;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;

use crate::cli::{Command, CredentialsSource, Invocation, USAGE};
use crate::{input, render};

pub mod exit {
    pub const OK: i32 = 0;
    pub const REFUSED: i32 = 1;
    pub const USAGE: i32 = 2;
    pub const UNREACHABLE: i32 = 3;
    pub const TIMED_OUT: i32 = 4;
    pub const UNEXPECTED: i32 = 5;
    pub const INCOMPATIBLE: i32 = 6;
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

    /// Whether this program holds an elevated token (the person answered the Windows prompt).
    fn is_elevated(&self) -> bool {
        false
    }

    /// Run this program again with `args` in an elevated window, which makes Windows ask the person,
    /// and wait for it. Its exit code, or why it could not be done (the person said no).
    fn relaunch_elevated(&self, _args: &[String]) -> Result<i32, String> {
        Err("this program cannot ask Windows for elevation here".to_string())
    }

    /// Show `prompt` and return the line the person types. Empty when there is no one to ask.
    fn ask_line(&self, _prompt: &str) -> String {
        String::new()
    }
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
        ClientError::Incompatible(_) => exit::INCOMPATIBLE,
        _ => exit::UNEXPECTED,
    }
}

/// Ask which protocol the service speaks and stop unless this program can talk to it. `Err` is the
/// exit code, with the reason already printed.
async fn negotiate<S: AsyncRead + AsyncWrite + Unpin>(
    connection: &mut Connection<S>,
    sink: &mut dyn Sink,
) -> Result<ServiceVersion, i32> {
    let reply = version_reply(connection)
        .await
        .map_err(|e| problem(sink, &e))?;
    match check_version(reply) {
        Ok(VersionCheck::Compatible(service)) => Ok(service),
        Ok(VersionCheck::Refused(r)) => Err(refusal(sink, &r)),
        Err(e) => Err(problem(sink, &e)),
    }
}

async fn version_reply<S: AsyncRead + AsyncWrite + Unpin>(
    connection: &mut Connection<S>,
) -> Result<Reply, ClientError> {
    match tokio::time::timeout(REQUEST_TIMEOUT, connection.call(&Request::GetVersion)).await {
        Err(_) => Err(ClientError::Io(
            "the service did not answer in time".to_string(),
        )),
        Ok(reply) => reply,
    }
}

/// `dnetctl version`: both ends' versions, and whether they can talk. A mismatch is reported, not
/// refused, because finding out about it is what this command is for.
async fn version<S: AsyncRead + AsyncWrite + Unpin>(
    connection: &mut Connection<S>,
    json: bool,
    sink: &mut dyn Sink,
) -> i32 {
    let reply = match version_reply(connection).await {
        Ok(reply) => reply,
        Err(e) => return problem(sink, &e),
    };
    let value = match reply {
        Reply::Done(value) => value,
        // An older service answers `InvalidRequest`; anything else is an ordinary refusal.
        Reply::Refused(r) => {
            return match check_version(Reply::Refused(r)) {
                Ok(VersionCheck::Refused(r)) => refusal(sink, &r),
                Ok(VersionCheck::Compatible(_)) => unreachable!("a refusal is not compatible"),
                Err(e) => problem(sink, &e),
            };
        }
    };
    let service = match version::decode(&value) {
        Ok(service) => service,
        Err(why) => return problem(sink, &ClientError::Malformed(why)),
    };
    let verdict = version::check(version::PROTOCOL_VERSION, &service);
    if json {
        sink.out(&pretty(&serde_json::json!({
            "client": {
                "version": env!("CARGO_PKG_VERSION"),
                "protocol_version": version::PROTOCOL_VERSION,
            },
            "service": {
                "version": service.service,
                "protocol_version": service.protocol,
                "min_protocol_version": service.min_protocol,
            },
            "compatible": verdict.is_ok(),
        })));
    } else {
        sink.out(&format!(
            "dnetctl:  {} (speaks protocol {})",
            env!("CARGO_PKG_VERSION"),
            version::PROTOCOL_VERSION
        ));
        sink.out(&format!(
            "service:  {} (speaks protocol {} to {})",
            render::plain(&service.service),
            service.min_protocol,
            service.protocol
        ));
    }
    match verdict {
        Ok(()) => {
            if !json {
                sink.out("They can talk to each other.");
            }
            exit::OK
        }
        Err(e) => {
            sink.err(&format!("dnetctl: {e}"));
            exit::INCOMPATIBLE
        }
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
        Command::AddEndpoint {
            label,
            host,
            source,
        } => match add_endpoint_request(label, host, source) {
            Ok(request) => Some(request),
            Err(why) => {
                sink.err(&format!("dnetctl: {}", render::plain(&why)));
                return exit::USAGE;
            }
        },
        Command::RemoveEndpoint { endpoint } => match by_id("RemoveEndpoint", endpoint, None) {
            Ok(request) => Some(request),
            Err(why) => {
                sink.err(&format!("dnetctl: {}", render::plain(&why)));
                return exit::USAGE;
            }
        },
        Command::SetEndpointEnabled { endpoint, enabled } => {
            match by_id("SetEndpointEnabled", endpoint, Some(*enabled)) {
                Ok(request) => Some(request),
                Err(why) => {
                    sink.err(&format!("dnetctl: {}", render::plain(&why)));
                    return exit::USAGE;
                }
            }
        }
        Command::EncryptedDns { block } => Some(Request::SetEncryptedDnsHandling { block: *block }),
        Command::AddRule {
            kind,
            value,
            action,
        } => match checked(serde_json::json!({
            "request": "AddRule", "kind": kind, "value": value, "action": action,
        })) {
            Ok(request) => Some(request),
            Err(why) => {
                sink.err(&format!("dnetctl: {}", render::plain(&why)));
                return exit::USAGE;
            }
        },
        Command::RemoveRule { rule } => {
            match checked(serde_json::json!({ "request": "RemoveRule", "rule": rule })) {
                Ok(request) => Some(request),
                Err(why) => {
                    sink.err(&format!("dnetctl: {}", render::plain(&why)));
                    return exit::USAGE;
                }
            }
        }
        Command::BrutalOn {
            profile,
            up,
            down,
            accept_warning,
        } => {
            if !accept_warning {
                // Shown before anything is sent or even checked: the person decides on the warning.
                let w = dnet_core::profile::brutal_warning();
                sink.err(&format!(
                    "{}\n\n{}\n{}\n{}\n\nNothing was changed. Run again with --accept-warning to accept it.",
                    w.title, w.body, w.consequence, w.note
                ));
                return exit::REFUSED;
            }
            match brutal_request(profile, Some((up, down))) {
                Ok(request) => Some(request),
                Err(why) => {
                    sink.err(&format!("dnetctl: {}", render::plain(&why)));
                    return exit::USAGE;
                }
            }
        }
        Command::BrutalOff { profile } => match brutal_request(profile, None) {
            Ok(request) => Some(request),
            Err(why) => {
                sink.err(&format!("dnetctl: {}", render::plain(&why)));
                return exit::USAGE;
            }
        },
        Command::CheckUpdates => Some(Request::FetchFeed),
        Command::ImportFeed { keys, feed } => {
            match import_request(keys.as_deref(), feed.as_deref()) {
                Ok(request) => Some(request),
                Err(why) => {
                    sink.err(&format!("dnetctl: {}", render::plain(&why)));
                    return exit::USAGE;
                }
            }
        }
        _ => None,
    };

    let mut connection = match connector.connect(invocation.trust_any_service).await {
        Ok(connection) => connection,
        Err(e) => return problem(sink, &e),
    };

    if invocation.command == Command::Version {
        return version(&mut connection, invocation.json, sink).await;
    }
    if let Err(code) = negotiate(&mut connection, sink).await {
        return code;
    }

    match invocation.command {
        Command::Help => unreachable!("handled above"),
        Command::Version => unreachable!("handled above"),
        Command::Status => status(&mut connection, invocation.json, sink).await,
        Command::Profiles => list(&mut connection, Request::ListProfiles, &invocation, sink).await,
        Command::Rules => list(&mut connection, Request::ListRules, &invocation, sink).await,
        Command::Endpoints => {
            list(&mut connection, Request::ListEndpoints, &invocation, sink).await
        }
        Command::Paths => paths(&mut connection, invocation.json, sink).await,
        Command::Stats => stats(&mut connection, invocation.json, sink).await,
        Command::Connect { wait, .. } => {
            let request = request.expect("built above for a connect");
            connect(&mut connection, request, wait, &invocation, sink).await
        }
        Command::Disconnect { wait } => disconnect(&mut connection, wait, &invocation, sink).await,
        Command::Pending => pending(&mut connection, invocation.json, sink).await,
        Command::Reject { ref id } => {
            let request = Request::RejectChange { id: id.clone() };
            change(&mut connection, &request, &invocation, sink, |_| {
                Some("Dropped. The change was not applied.".to_string())
            })
            .await
        }
        Command::Approve { ref id, pause } => {
            approve(&mut connection, connector, id, pause, &invocation, sink).await
        }
        Command::Events { follow } => {
            events(&mut connection, follow, invocation.json, sink, interrupt).await
        }
        Command::AddEndpoint { ref source, .. } => {
            let request = request.expect("built above for an add");
            let file = matches!(source, CredentialsSource::File(_));
            change(&mut connection, &request, &invocation, sink, |reply| {
                let id = reply.get("endpoint").and_then(Value::as_str)?;
                let mut text = format!(
                    "Endpoint added ({}). Run 'dnetctl endpoints' to see it.",
                    render::plain(id)
                );
                if file {
                    text.push_str(
                        "\nThe file you gave still holds the keys in plain text; delete it now.",
                    );
                }
                Some(text)
            })
            .await
        }
        Command::RemoveEndpoint { .. } => {
            let request = request.expect("built above for a removal");
            change(&mut connection, &request, &invocation, sink, |_| {
                Some("Endpoint removed, and its credentials forgotten.".to_string())
            })
            .await
        }
        Command::SetEndpointEnabled { enabled, .. } => {
            let request = request.expect("built above for an enable or disable");
            change(&mut connection, &request, &invocation, sink, |_| {
                Some(if enabled {
                    "Endpoint enabled.".to_string()
                } else {
                    "Endpoint disabled: it is kept but will not be used.".to_string()
                })
            })
            .await
        }
        Command::AddRule { .. } => {
            let request = request.expect("built above for a rule");
            change(&mut connection, &request, &invocation, sink, |reply| {
                let id = reply.get("rule")?.as_str()?;
                Some(format!(
                    "Rule added ({}). It applies from the next connection.",
                    render::plain(id)
                ))
            })
            .await
        }
        Command::RemoveRule { .. } => {
            let request = request.expect("built above for a removal");
            change(&mut connection, &request, &invocation, sink, |_| {
                Some("Rule removed. It stops applying from the next connection.".to_string())
            })
            .await
        }
        Command::BrutalOn { .. } | Command::BrutalOff { .. } => {
            let on = matches!(invocation.command, Command::BrutalOn { .. });
            let request = request.expect("built above for Brutal");
            change(&mut connection, &request, &invocation, sink, |_| {
                Some(if on {
                    "Aggressive speed mode is on for that profile from the next connection. It makes \
                     the network worse for everyone around you; turn it off with 'dnetctl brutal-off'."
                        .to_string()
                } else {
                    "Aggressive speed mode is off: the profile backs off when the network is busy."
                        .to_string()
                })
            })
            .await
        }
        Command::CheckUpdates => {
            let request = request.expect("built above for a check");
            change(&mut connection, &request, &invocation, sink, |reply| {
                if reply.get("started") != Some(&Value::Bool(true)) {
                    return None;
                }
                let how = match reply.get("route")?.as_str()? {
                    "tunnel" => "through your connection",
                    "physical" => {
                        "directly over your network, because you asked while disconnected"
                    }
                    _ => return None,
                };
                Some(format!(
                    "Checking for updated connection methods {how}. The result shows in 'dnetctl events'."
                ))
            })
            .await
        }
        Command::ImportFeed { .. } => {
            let request = request.expect("built above for an import");
            change(&mut connection, &request, &invocation, sink, |reply| {
                if reply.get("imported") != Some(&Value::Bool(true)) {
                    return None;
                }
                let changes = reply.get("changes")?.as_array()?;
                if changes.is_empty() {
                    return Some("Nothing changed: the service already had these.".to_string());
                }
                let sentences: Option<Vec<String>> = changes
                    .iter()
                    .map(|c| c.as_str().map(change_sentence))
                    .collect();
                Some(sentences?.join(
                    "
",
                ))
            })
            .await
        }
        Command::EncryptedDns { block } => {
            let request = request.expect("built above for the encrypted-DNS choice");
            change(&mut connection, &request, &invocation, sink, |reply| {
                if block {
                    return Some(
                        "Encrypted name lookups by programs are blocked while connected, so your \
                         rules for sites apply to them."
                            .to_string(),
                    );
                }
                // The service must say what allowing costs, and the person must be shown it. A
                // reply that does not is not one to act on.
                let consequence = reply.get("consequence").and_then(Value::as_str)?;
                Some(format!(
                    "Encrypted name lookups by programs are no longer blocked.\n{}",
                    render::plain(consequence)
                ))
            })
            .await
        }
    }
}

/// `EnableBrutal` (with both speeds) or `DisableBrutal`, checked by the service's own grammar, so a value it
/// would refuse is a usage error here and nothing is sent. The revision sent is the warning just accepted.
/// A request checked by the service's own grammar, so what it would refuse is a usage error here and
/// nothing is sent. The error names a field, never the value.
fn checked(wire: Value) -> Result<Request, String> {
    decode_request(&wire.to_string()).map_err(|e| e.to_string())
}

fn brutal_request(profile: &str, speeds: Option<(&String, &String)>) -> Result<Request, String> {
    let wire = match speeds {
        Some((up, down)) => {
            let mbps = |name: &str, text: &str| {
                text.parse::<u64>()
                    .map_err(|_| format!("--{name} needs a whole number of Mbit/s"))
            };
            serde_json::json!({
                "request": "EnableBrutal",
                "profile": profile,
                "up_mbps": mbps("up", up)?,
                "down_mbps": mbps("down", down)?,
                "warning_revision": dnet_core::profile::BRUTAL_WARNING_REVISION,
            })
        }
        None => serde_json::json!({ "request": "DisableBrutal", "profile": profile }),
    };
    decode_request(&wire.to_string()).map_err(|e| e.to_string())
}

/// The request that hands the service signed documents from files. Nothing is interpreted here: the
/// service checks the signatures, and a file that is not a signed document is refused there.
fn import_request(keys: Option<&str>, feed: Option<&str>) -> Result<Request, String> {
    let keys = keys.map(input::read_document).transpose()?;
    let feed = feed.map(input::read_document).transpose()?;
    FeedImport::new(keys, feed)
        .map(Request::ImportFeed)
        .map_err(|e| e.to_string())
}

/// The sentence for one change an import made.
fn change_sentence(name: &str) -> String {
    match name {
        "Updated" => "Connection method definitions updated. They apply from the next connection."
            .to_string(),
        "Evicted" => "The new keys no longer include the key that signed the earlier update, so the                       built-in definitions are back in use."
            .to_string(),
        "OutOfDate" => "The definitions in use are out of date.".to_string(),
        "Discarded" => "A saved update could not be checked again and was set aside.".to_string(),
        other => format!("A change this program does not know ({}).", render::plain(other)),
    }
}

/// The request for a new endpoint, from what was typed and what the credentials file holds. The
/// service's own checks, applied here, so a mistake is a usage error that sends nothing.
fn add_endpoint_request(
    label: &str,
    host: &str,
    source: &CredentialsSource,
) -> Result<Request, String> {
    let bytes = input::read_bytes(source)?;
    let credentials = input::parse(&bytes)?;
    NewEndpoint::new(label, host, credentials)
        .map(|new| Request::AddEndpoint(Box::new(new)))
        .map_err(|e| e.to_string())
}

/// A request that names one endpoint, checked by the service's own grammar for an id.
fn by_id(name: &str, endpoint: &str, enabled: Option<bool>) -> Result<Request, String> {
    let mut wire = serde_json::json!({ "request": name, "endpoint": endpoint });
    if let Some(enabled) = enabled {
        wire["enabled"] = Value::Bool(enabled);
    }
    decode_request(&wire.to_string()).map_err(|e| e.to_string())
}

/// Ask for a configuration change and say what came of it. `done` makes the sentence for a reply
/// that is what was promised; `None` means the reply was not, which is reported as unexpected rather
/// than as success.
async fn change<S: AsyncRead + AsyncWrite + Unpin>(
    connection: &mut Connection<S>,
    request: &Request,
    invocation: &Invocation,
    sink: &mut dyn Sink,
    done: impl FnOnce(&Value) -> Option<String>,
) -> i32 {
    match ask(connection, request).await {
        Err(e) => problem(sink, &e),
        Ok(Answer::Refused(r)) => refusal(sink, &r),
        Ok(Answer::Done(value)) => match done(&value) {
            None => problem(
                sink,
                &ClientError::Malformed("the reply is not what was promised".to_string()),
            ),
            Some(text) => {
                sink.out(&if invocation.json {
                    pretty(&value)
                } else {
                    text
                });
                exit::OK
            }
        },
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

/// What a refusal of `GetPaths` or `GetStats` means when the service simply does not know the request:
/// it is older than this program, and cannot say. That is not an empty answer, and is not shown as one.
fn too_old(refusal: &dnet_ipc::client::Refusal) -> bool {
    refusal.code == "InvalidRequest" && refusal.detail.contains("unknown request")
}

async fn paths<S: AsyncRead + AsyncWrite + Unpin>(
    connection: &mut Connection<S>,
    json: bool,
    sink: &mut dyn Sink,
) -> i32 {
    match ask(connection, &Request::GetPaths).await {
        Err(e) => problem(sink, &e),
        Ok(Answer::Refused(r)) if too_old(&r) => {
            sink.err("dnetctl: this service is older than dnetctl and cannot report the networks; update the service.");
            exit::REFUSED
        }
        Ok(Answer::Refused(r)) => refusal(sink, &r),
        Ok(Answer::Done(value)) => {
            if json {
                sink.out(&pretty(&value));
                return exit::OK;
            }
            match dnet_ipc::netview::decode_paths(&value.to_string()) {
                Ok(reply) => {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
                    sink.out(&render::paths(&reply, now));
                    exit::OK
                }
                Err(_) => problem(
                    sink,
                    &ClientError::Malformed(
                        "the networks are not in a form this client understands".to_string(),
                    ),
                ),
            }
        }
    }
}

async fn stats<S: AsyncRead + AsyncWrite + Unpin>(
    connection: &mut Connection<S>,
    json: bool,
    sink: &mut dyn Sink,
) -> i32 {
    match ask(connection, &Request::GetStats).await {
        Err(e) => problem(sink, &e),
        Ok(Answer::Refused(r)) if too_old(&r) => {
            sink.err("dnetctl: this service is older than dnetctl and cannot report counts; update the service.");
            exit::REFUSED
        }
        Ok(Answer::Refused(r)) => refusal(sink, &r),
        Ok(Answer::Done(value)) => {
            if json {
                sink.out(&pretty(&value));
                return exit::OK;
            }
            match dnet_ipc::netview::decode_stats(&value.to_string()) {
                Ok(reply) => {
                    sink.out(&render::stats(&reply));
                    exit::OK
                }
                Err(_) => problem(
                    sink,
                    &ClientError::Malformed(
                        "the counts are not in a form this client understands".to_string(),
                    ),
                ),
            }
        }
    }
}

/// The changes waiting for approval (T160).
async fn pending<S: AsyncRead + AsyncWrite + Unpin>(
    connection: &mut Connection<S>,
    json: bool,
    sink: &mut dyn Sink,
) -> i32 {
    match ask(connection, &Request::ListPending).await {
        Err(e) => problem(sink, &e),
        Ok(Answer::Refused(r)) => refusal(sink, &r),
        Ok(Answer::Done(value)) => {
            if json {
                sink.out(&pretty(&value));
                return exit::OK;
            }
            match render::pending(&value, now_unix_ms()) {
                Ok(text) => {
                    sink.out(&text);
                    exit::OK
                }
                Err(why) => problem(sink, &ClientError::Malformed(why)),
            }
        }
    }
}

fn now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// `dnetctl approve <id>` (T160, ADR-0008 F13).
///
/// Approving is the one act a program running as the person must not be able to do alone, so the
/// service accepts it only from an elevated client. This command therefore has two halves. The
/// ordinary half checks that the change exists and shows what it is, then runs this program again in
/// its own elevated window, which makes Windows ask the person on the secure desktop. The elevated
/// half shows the change once more, because the Windows prompt names this program and not the server,
/// and applies it only if the person types `yes`. There is deliberately no option to skip that: a
/// program that started the elevated half could otherwise answer for the person.
async fn approve<S: AsyncRead + AsyncWrite + Unpin, C: Connector>(
    connection: &mut Connection<S>,
    connector: &C,
    id: &str,
    pause: bool,
    invocation: &Invocation,
    sink: &mut dyn Sink,
) -> i32 {
    let code = approve_once(connection, connector, id, invocation, sink).await;
    if pause {
        // The window this program opened closes when it ends; let the person read the result.
        let _ = connector.ask_line("Press Enter to close this window.");
    }
    code
}

async fn approve_once<S: AsyncRead + AsyncWrite + Unpin, C: Connector>(
    connection: &mut Connection<S>,
    connector: &C,
    id: &str,
    invocation: &Invocation,
    sink: &mut dyn Sink,
) -> i32 {
    // What the change is, as the service describes it. A name the service does not hold is said now,
    // before the person is asked anything.
    let what = match ask(connection, &Request::ListPending).await {
        Err(e) => return problem(sink, &e),
        Ok(Answer::Refused(r)) => return refusal(sink, &r),
        Ok(Answer::Done(value)) => match waiting_change(&value, id) {
            Ok(Some(what)) => what,
            Ok(None) => {
                sink.err(&format!(
                    "dnetctl: no change is waiting under '{}'. It may have been applied, dropped, or \
                     have waited more than ten minutes. 'dnetctl pending' lists what waits.",
                    render::plain(id)
                ));
                return exit::REFUSED;
            }
            Err(why) => return problem(sink, &ClientError::Malformed(why)),
        },
    };
    sink.out(&format!(
        "Waiting for your approval: {}",
        render::plain(&what)
    ));

    if !connector.is_elevated() {
        sink.out(
            "Windows will now ask whether to allow this. Only you can answer that prompt; a program \
             running as you cannot.",
        );
        let mut args = vec!["approve".to_string(), id.to_string(), "--pause".to_string()];
        if invocation.trust_any_service {
            args.push("--allow-unprivileged-service".to_string());
        }
        return match connector.relaunch_elevated(&args) {
            Ok(code) => code,
            Err(why) => {
                sink.err(&format!(
                    "dnetctl: not approved: {}. Nothing was changed; the change keeps waiting for ten \
                     minutes from when it was asked for.",
                    render::plain(&why)
                ));
                exit::REFUSED
            }
        };
    }

    let answer = connector.ask_line(&format!(
        "Type yes to apply it, or anything else to leave it waiting: {}\n> ",
        render::plain(&what)
    ));
    if answer.trim() != "yes" {
        sink.err(
            "dnetctl: not approved. Nothing was changed. 'dnetctl reject <id>' drops the change; \
             otherwise it is dropped after ten minutes.",
        );
        return exit::REFUSED;
    }
    let request = Request::ApproveChange { id: id.to_string() };
    change(connection, &request, invocation, sink, |_| {
        Some("Approved and applied.".to_string())
    })
    .await
}

/// The description of the waiting change `id` in a `ListPending` reply, if the service holds it.
fn waiting_change(value: &Value, id: &str) -> Result<Option<String>, String> {
    let waiting = value
        .get("pending")
        .and_then(Value::as_array)
        .ok_or_else(|| "the list of waiting changes is missing".to_string())?;
    for item in waiting {
        if item.get("id").and_then(Value::as_str) == Some(id) {
            let what = item
                .get("what")
                .and_then(Value::as_str)
                .ok_or_else(|| "a waiting change does not say what it does".to_string())?;
            return Ok(Some(what.to_string()));
        }
    }
    Ok(None)
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
            let text = match request {
                Request::ListProfiles => render::profiles(&value),
                Request::ListRules => render::rules(&value),
                _ => render::endpoints(&value),
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
