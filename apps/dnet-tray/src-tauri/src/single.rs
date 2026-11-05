//! T101 — one tray per person, and a window when the person starts the program (the "no single-instance guard" gap).
//!
//! **Why.** The program has no window at login (R2), which is right for the copy the login starts, but it meant that
//! starting it from the Start menu, or from the installer's last page, showed only a tray icon that may sit in the
//! overflow area: a person who has just installed it saw nothing happen. And with nothing to stop it, starting it
//! while it already ran made a second tray icon.
//!
//! **What.**
//! - The login start passes `--background` and opens no window; any other start opens one ([`shows_window`]).
//! - The first copy owns a per-user named pipe. A second copy connects to it, which is all the message there is, and
//!   exits; the first copy answers by opening its window. A connection carries no data, so there is nothing for
//!   another program on the pipe to say.
//! - If the name is taken by something that does not answer, the program starts anyway: a second tray is a smaller
//!   fault than none.
//!
//! No new dependency: the named pipe is the one `tokio` already provides.

use std::io;
use std::time::Duration;

use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};

/// Whether this start should open the window. Only the login start (`--background`) does not: nobody is waiting for a
/// window then, and the tray alone is what a login should leave. `--open` is the older spelling of what is now the
/// default and is accepted and ignored.
pub fn shows_window(args: impl IntoIterator<Item = String>) -> bool {
    !args.into_iter().any(|a| a == "--background")
}

/// The pipe a person's copy owns. Per user, so two people signed in at once each have their own tray; the name keeps
/// only characters a pipe name allows.
pub fn pipe_name() -> String {
    let user: String = std::env::var("USERNAME")
        .unwrap_or_default()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    format!(r"\\.\pipe\DNetEngine\tray-{user}")
}

/// What this copy is.
pub enum Role {
    /// The first copy: it owns the pipe and listens on it.
    First(Listener),
    /// Another copy owns the pipe.
    Second,
}

/// The first copy's end of the pipe.
pub struct Listener {
    name: String,
    server: NamedPipeServer,
}

/// Take the name, if nobody has it. Must run inside the async runtime.
pub fn acquire(name: &str) -> io::Result<Role> {
    match ServerOptions::new()
        .first_pipe_instance(true)
        .reject_remote_clients(true)
        .create(name)
    {
        Ok(server) => Ok(Role::First(Listener {
            name: name.to_owned(),
            server,
        })),
        // The pipe exists and `first_pipe_instance` refuses a second: the system reports it as access denied.
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => Ok(Role::Second),
        Err(error) => Err(error),
    }
}

impl Listener {
    /// Wait until another copy asks, then be ready for the next ask.
    pub async fn wait(&mut self) -> io::Result<()> {
        self.server.connect().await?;
        let next = ServerOptions::new()
            .reject_remote_clients(true)
            .create(&self.name)?;
        // Dropping the connected end ends that conversation.
        drop(std::mem::replace(&mut self.server, next));
        Ok(())
    }
}

/// Ask the copy that owns the name to open its window. A busy pipe, or one not yet listening, is tried again for a
/// moment; an answer that never comes is an error, and the caller starts anyway.
pub async fn tell_first(name: &str) -> io::Result<()> {
    let mut last = io::Error::new(io::ErrorKind::NotFound, "nobody answers on the tray's pipe");
    for _ in 0..20 {
        match ClientOptions::new().open(name) {
            Ok(_connected) => return Ok(()),
            Err(error) => last = error,
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn unique() -> String {
        format!(
            r"\\.\pipe\DNetEngine\test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        )
    }

    fn run<T>(future: impl std::future::Future<Output = T>) -> T {
        tauri::async_runtime::block_on(future)
    }

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn only_the_login_start_opens_no_window() {
        assert!(shows_window(args(&[])), "a start by hand opens the window");
        assert!(
            shows_window(args(&["--open"])),
            "the older spelling still does"
        );
        assert!(
            shows_window(args(&["--allow-unprivileged-service"])),
            "a development flag changes nothing about it"
        );
        assert!(
            !shows_window(args(&["--background"])),
            "the login start is tray only"
        );
        assert!(!shows_window(args(&[
            "--allow-unprivileged-service",
            "--background"
        ])));
    }

    #[test]
    fn the_pipe_name_is_per_user_and_holds_only_what_a_pipe_name_allows() {
        let name = pipe_name();
        assert!(name.starts_with(r"\\.\pipe\DNetEngine\tray-"), "{name}");
        let user = name.rsplit("tray-").next().unwrap();
        assert!(
            user.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "{name}"
        );
    }

    #[test]
    fn the_first_copy_takes_the_name_and_the_second_is_told_so() {
        let name = unique();
        run(async {
            let first = acquire(&name).unwrap();
            assert!(matches!(first, Role::First(_)));
            let second = acquire(&name).unwrap();
            assert!(matches!(second, Role::Second));
            // And it stays taken for the third.
            assert!(matches!(acquire(&name).unwrap(), Role::Second));
        });
    }

    #[test]
    fn an_ask_wakes_the_first_copy_and_it_can_be_woken_again() {
        let name = unique();
        run(async {
            let Role::First(mut listener) = acquire(&name).unwrap() else {
                panic!("not first");
            };
            for _ in 0..3 {
                tell_first(&name).await.unwrap();
                tokio::time::timeout(Duration::from_secs(3), listener.wait())
                    .await
                    .expect("the first copy was not woken")
                    .unwrap();
            }
        });
    }

    #[test]
    fn when_the_first_copy_is_gone_the_next_one_is_first() {
        let name = unique();
        run(async {
            let first = acquire(&name).unwrap();
            assert!(matches!(first, Role::First(_)));
            drop(first);
            assert!(matches!(acquire(&name).unwrap(), Role::First(_)));
        });
    }

    #[test]
    fn asking_when_nobody_listens_is_an_error_not_a_hang() {
        let name = unique();
        let started = std::time::Instant::now();
        let outcome = run(tell_first(&name));
        assert!(outcome.is_err());
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "it kept trying for too long"
        );
    }
}
