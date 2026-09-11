//! T043 — child spawn with captured stdio and readiness detection (SUP-01, SUP-06).
//!
//! A core is spawned as a child with its stdio captured (parsed for health, never
//! echoed raw to the user), and it must signal readiness within a timeout or be treated
//! as failed — never awaited indefinitely (SUP-06). The readiness wait is factored out
//! as a combinator so it can be tested without a real process (SUP-T4).

use std::future::Future;
use std::time::Duration;

/// Why a core was not ready.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ReadyError {
    /// The core did not signal ready before the timeout elapsed.
    #[error("core did not signal ready within {0:?}")]
    Timeout(Duration),
    /// The core exited before signalling ready.
    #[error("core exited before signalling ready")]
    Exited,
}

/// Await a readiness signal with a hard timeout.
///
/// `ready` resolves to `true` when the core signalled ready, or `false` if it exited
/// first. If neither happens within `within`, the core is treated as failed rather than
/// awaited forever (SUP-06).
pub async fn await_ready<F>(ready: F, within: Duration) -> Result<(), ReadyError>
where
    F: Future<Output = bool>,
{
    match tokio::time::timeout(within, ready).await {
        Err(_elapsed) => Err(ReadyError::Timeout(within)),
        Ok(true) => Ok(()),
        Ok(false) => Err(ReadyError::Exited),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_core_that_never_signals_ready_times_out() {
        // A readiness future that never resolves; with paused time the timeout fires as
        // soon as the runtime is otherwise idle, so the test does not actually wait.
        let never = std::future::pending::<bool>();
        let result = await_ready(never, Duration::from_secs(5)).await;
        assert_eq!(result, Err(ReadyError::Timeout(Duration::from_secs(5))));
    }

    #[tokio::test(start_paused = true)]
    async fn a_ready_signal_before_the_timeout_succeeds() {
        let result = await_ready(async { true }, Duration::from_secs(5)).await;
        assert_eq!(result, Ok(()));
    }

    #[tokio::test(start_paused = true)]
    async fn an_early_exit_is_reported_distinctly_from_a_timeout() {
        let result = await_ready(async { false }, Duration::from_secs(5)).await;
        assert_eq!(result, Err(ReadyError::Exited));
    }
}
