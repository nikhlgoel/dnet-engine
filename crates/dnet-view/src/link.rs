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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use dnet_ipc::client::{ClientError, Refusal, Reply};
    use serde_json::json;

    use super::*;

    /// A link that records every request and answers from a fixed reply.
    struct Recording {
        seen: Mutex<Vec<Request>>,
        calls: AtomicUsize,
        reply: fn() -> Result<Reply, ClientError>,
    }

    impl Recording {
        fn new(reply: fn() -> Result<Reply, ClientError>) -> Arc<Self> {
            Arc::new(Self {
                seen: Mutex::new(Vec::new()),
                calls: AtomicUsize::new(0),
                reply,
            })
        }
    }

    impl Link for Recording {
        async fn call(&self, request: Request) -> Result<Reply, ClientError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.seen.lock().unwrap().push(request);
            (self.reply)()
        }
    }

    fn done() -> Result<Reply, ClientError> {
        Ok(Reply::Done(json!({ "ok": true })))
    }

    fn refused() -> Result<Reply, ClientError> {
        Ok(Reply::Refused(Refusal {
            code: "ServiceBusy".to_owned(),
            detail: "busy".to_owned(),
            retryable: true,
        }))
    }

    fn unreachable() -> Result<Reply, ClientError> {
        Err(ClientError::Unreachable("no service".to_owned()))
    }

    #[tokio::test]
    async fn a_shared_link_passes_the_request_on_unchanged() {
        let inner = Recording::new(done);
        let shared: Arc<Recording> = Arc::clone(&inner);
        let reply = shared.call(Request::GetState).await.unwrap();
        assert!(matches!(reply, Reply::Done(_)));
        assert_eq!(*inner.seen.lock().unwrap(), vec![Request::GetState]);
    }

    #[tokio::test]
    async fn every_call_through_the_shared_link_reaches_the_one_link() {
        let inner = Recording::new(done);
        let shared = Arc::clone(&inner);
        for _ in 0..25 {
            shared.call(Request::ListEndpoints).await.unwrap();
        }
        assert_eq!(inner.calls.load(Ordering::SeqCst), 25);
    }

    #[tokio::test]
    async fn clones_of_the_shared_link_are_one_link() {
        let inner = Recording::new(done);
        let (a, b) = (Arc::clone(&inner), Arc::clone(&inner));
        a.call(Request::GetState).await.unwrap();
        b.call(Request::GetSession).await.unwrap();
        assert_eq!(
            *inner.seen.lock().unwrap(),
            vec![Request::GetState, Request::GetSession]
        );
    }

    #[tokio::test]
    async fn a_refusal_comes_back_as_a_refusal_and_is_not_turned_into_an_error() {
        let shared = Recording::new(refused);
        match shared.call(Request::Disconnect).await {
            Ok(Reply::Refused(r)) => {
                assert_eq!(r.code, "ServiceBusy");
                assert!(r.retryable);
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_failure_to_ask_comes_back_as_an_error_with_its_words() {
        let shared = Recording::new(unreachable);
        match shared.call(Request::GetState).await {
            Err(ClientError::Unreachable(why)) => assert_eq!(why, "no service"),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn a_link_inside_a_link_still_delivers_the_request() {
        let inner = Recording::new(done);
        let outer = Arc::new(Arc::clone(&inner));
        outer.call(Request::GetPaths).await.unwrap();
        assert_eq!(*inner.seen.lock().unwrap(), vec![Request::GetPaths]);
    }

    #[tokio::test]
    async fn requests_from_many_tasks_all_arrive() {
        let inner = Recording::new(done);
        let mut tasks = Vec::new();
        for _ in 0..40 {
            let link = Arc::clone(&inner);
            tasks.push(tokio::spawn(async move {
                link.call(Request::GetStats).await.unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
        assert_eq!(inner.calls.load(Ordering::SeqCst), 40);
    }

    #[cfg(windows)]
    mod windows {
        use dnet_ipc::client::Trust;

        use super::super::PipeLink;

        /// Making the link opens nothing: the pipe is reached only when a request is made.
        #[test]
        fn a_new_link_has_not_touched_the_pipe() {
            let _ = PipeLink::service();
            let _ = PipeLink::with_trust(Trust::ServiceOwnedOnly);
        }
    }
}
