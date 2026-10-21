//! `dnetctl` — control the DNet Engine service from a terminal (T127).
//!
//! The command-line client for the control pipe: connect, disconnect, status, events. It exists so
//! that the whole path can be driven and tested before the tray does, and stays useful afterwards
//! for scripts and for support ("what did the service do, and why").
//!
//! It holds no privilege and makes no decision: it asks the service, which authorizes every
//! request against who is asking, and prints what the service says. See `cli::USAGE`.

mod cli;
#[cfg(test)]
mod fuzz;
mod render;
mod run;

use std::future::Future;
use std::io::Write;
use std::process::ExitCode;

use dnet_ipc::client::{ClientError, Connection};

/// Prints to the terminal. A closed pipe (`dnetctl events | head`) ends output quietly.
struct Terminal;

impl run::Sink for Terminal {
    fn out(&mut self, line: &str) {
        let _ = writeln!(std::io::stdout().lock(), "{line}");
    }
    fn err(&mut self, line: &str) {
        let _ = writeln!(std::io::stderr().lock(), "{line}");
    }
}

#[cfg(windows)]
struct Pipe;

#[cfg(windows)]
impl run::Connector for Pipe {
    type Stream = tokio::net::windows::named_pipe::NamedPipeClient;
    fn connect(
        &self,
        trust_any_service: bool,
    ) -> impl Future<Output = Result<Connection<Self::Stream>, ClientError>> {
        use dnet_ipc::client::Trust;
        dnet_ipc::client::connect(if trust_any_service {
            Trust::AnyServer
        } else {
            Trust::ServiceOwnedOnly
        })
    }
}

/// Off Windows there is no service to reach.
#[cfg(not(windows))]
struct Pipe;

#[cfg(not(windows))]
impl run::Connector for Pipe {
    type Stream = tokio::io::DuplexStream;
    fn connect(
        &self,
        _trust_any_service: bool,
    ) -> impl Future<Output = Result<Connection<Self::Stream>, ClientError>> {
        std::future::ready(Err(ClientError::Unreachable(
            "the DNet Engine service runs on Windows only; there is nothing to control here"
                .to_string(),
        )))
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let invocation = match cli::parse(&args) {
        Ok(invocation) => invocation,
        Err(message) => {
            eprintln!("dnetctl: {message}");
            return ExitCode::from(run::exit::USAGE as u8);
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            eprintln!("dnetctl: could not start ({})", e.kind());
            return ExitCode::from(run::exit::UNEXPECTED as u8);
        }
    };
    let interrupted = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    let code = runtime.block_on(run::run(invocation, &Pipe, &mut Terminal, interrupted));
    ExitCode::from(code as u8)
}
