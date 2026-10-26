//! T100 — the way a request reaches the service.
//!
//! [`Link`] is one request, one reply. The commands (`bridge`) are written against it, so they are tested with
//! a fake that records what was asked and answers from a script; [`PipeLink`] is the real one, which opens the
//! control pipe, and exists only on Windows.

use std::future::Future;

use dnet_ipc::client::{ClientError, Reply};
use dnet_ipc::protocol::Request;

/// Something that can put one request to the service and bring back the reply.
pub trait Link: Send + Sync {
    /// Ask. A refusal is `Ok(Reply::Refused(..))`; `Err` is a failure to ask at all.
    fn call(&self, request: Request) -> impl Future<Output = Result<Reply, ClientError>> + Send;
}

/// A shared link is a link: the shell holds one `PipeLink` for the commands and for the event stream.
impl<L: Link> Link for std::sync::Arc<L> {
    fn call(&self, request: Request) -> impl Future<Output = Result<Reply, ClientError>> + Send {
        L::call(self, request)
    }
}

#[cfg(windows)]
pub use pipe::PipeLink;

#[cfg(windows)]
mod pipe {
    use std::sync::atomic::{AtomicBool, Ordering};

    use dnet_ipc::client::{check_version, connect, ClientError, Reply, Trust, VersionCheck};
    use dnet_ipc::protocol::Request;

    use super::Link;

    /// The real link: the control pipe, owned by the service (never by another program), with the protocol
    /// version checked once before anything else is sent (T132).
    pub struct PipeLink {
        trust: Trust,
        version_checked: AtomicBool,
    }

    impl PipeLink {
        /// A link that talks only to a pipe the real service owns.
        #[must_use]
        pub fn service() -> Self {
            Self::with_trust(Trust::ServiceOwnedOnly)
        }

        /// A link with an explicit trust. `Trust::AnyServer` is for a development run of an unprivileged
        /// service and lets any local program pose as the service; the shell offers it only behind a flag.
        #[must_use]
        pub fn with_trust(trust: Trust) -> Self {
            Self {
                trust,
                version_checked: AtomicBool::new(false),
            }
        }

        /// Open a connection, checking the version first the first time.
        async fn open(
            &self,
        ) -> Result<
            dnet_ipc::client::Connection<tokio::net::windows::named_pipe::NamedPipeClient>,
            ClientError,
        > {
            let mut connection = connect(self.trust).await?;
            if !self.version_checked.load(Ordering::Relaxed) {
                let reply = connection.call(&Request::GetVersion).await?;
                // A refusal to say (busy, not authorised) tells nothing about compatibility; the request
                // that follows will report its own refusal. An incompatible service is an error.
                match check_version(reply)? {
                    VersionCheck::Compatible(_) => {
                        self.version_checked.store(true, Ordering::Relaxed)
                    }
                    VersionCheck::Refused(_) => {}
                }
            }
            Ok(connection)
        }

        /// A connection for the event stream.
        pub async fn stream(
            &self,
        ) -> Result<
            dnet_ipc::client::Connection<tokio::net::windows::named_pipe::NamedPipeClient>,
            ClientError,
        > {
            self.open().await
        }
    }

    impl Link for PipeLink {
        async fn call(&self, request: Request) -> Result<Reply, ClientError> {
            let mut connection = self.open().await?;
            connection.call(&request).await
        }
    }
}
