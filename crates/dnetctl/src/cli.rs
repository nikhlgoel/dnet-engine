//! T127 — what the user typed.
//!
//! Parsing is by hand: five commands and a handful of options do not justify a dependency, and a
//! dependency would be one more thing to audit for licence and supply chain in a tool that talks
//! to a privileged service. An unknown option is an error, never ignored: a mistyped `--profile`
//! that silently connected with the default would be worse than a refusal.

use std::time::Duration;

/// How long `connect` and `disconnect` wait for the daemon to finish, unless told otherwise.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// The longest `--timeout` accepted, in seconds.
pub const MAX_TIMEOUT_SECS: u64 = 3600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Status,
    Connect {
        profile: Option<String>,
        acknowledge_tier2: bool,
        wait: bool,
    },
    Disconnect {
        wait: bool,
    },
    Events {
        follow: bool,
    },
    Profiles,
    Endpoints,
    Help,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invocation {
    pub command: Command,
    /// Talk to a service not owned by SYSTEM or Administrators. Development only.
    pub trust_any_service: bool,
    /// Print the daemon's answers as JSON instead of prose, for scripts.
    pub json: bool,
    /// How long to wait for the daemon (`connect` and `disconnect`).
    pub timeout: Duration,
}

pub const USAGE: &str = "\
dnetctl: control the DNet Engine service

usage: dnetctl <command> [options]

commands:
  status                 show whether a tunnel is up, which profile carries it, and why
  connect                connect with the best profile (the service chooses)
  disconnect             disconnect
  events                 show what the service did and why (--follow to keep watching)
  profiles               list the connection profiles
  endpoints              list the configured endpoints
  help                   show this text

options:
  --json                 print the service's answers as JSON (for scripts)
  --timeout <seconds>    how long connect/disconnect wait (default 120, at most 3600)
  --profile <id>         connect: use only this profile (e.g. hy2-default)
  --accept-tier2         connect: consent to a profile whose connections may break when the
                         network interface changes
  --no-wait              connect/disconnect: return as soon as the service accepts the request
  -f, --follow           events: keep watching until interrupted
  --allow-unprivileged-service
                         DEVELOPMENT ONLY: also talk to a service that is not running as SYSTEM
                         or an administrator. Without it a process posing as the service is refused.

exit codes: 0 done | 1 refused or failed | 2 usage | 3 service not reachable | 4 timed out |
            5 unexpected reply";

fn command_named(name: &str) -> Option<Command> {
    Some(match name {
        "status" => Command::Status,
        "connect" => Command::Connect {
            profile: None,
            acknowledge_tier2: false,
            wait: true,
        },
        "disconnect" => Command::Disconnect { wait: true },
        "events" => Command::Events { follow: false },
        "profiles" => Command::Profiles,
        "endpoints" => Command::Endpoints,
        "help" | "--help" | "-h" => Command::Help,
        _ => return None,
    })
}

/// Parse the arguments after the program name. `Err` is a message for the user.
pub fn parse(args: &[String]) -> Result<Invocation, String> {
    let Some(first) = args.first() else {
        return Err(format!("no command given\n\n{USAGE}"));
    };
    let mut command = command_named(first)
        .ok_or_else(|| format!("unknown command '{}'\n\n{USAGE}", shown(first)))?;
    let mut json = false;
    let mut trust_any_service = false;
    let mut timeout = DEFAULT_TIMEOUT;
    let mut seen: Vec<&str> = Vec::new();

    let mut rest = args[1..].iter();
    while let Some(option) = rest.next() {
        let name = option.as_str();
        if seen.contains(&name) {
            return Err(format!("'{}' was given twice", shown(name)));
        }
        seen.push(name);
        match (name, &mut command) {
            ("--json", _) => json = true,
            ("--allow-unprivileged-service", _) => trust_any_service = true,
            ("--timeout", _) => {
                let value = rest
                    .next()
                    .ok_or_else(|| "--timeout needs a number of seconds".to_string())?;
                let seconds: u64 = value.parse().map_err(|_| {
                    format!(
                        "--timeout needs a whole number of seconds, not '{}'",
                        shown(value)
                    )
                })?;
                if seconds == 0 || seconds > MAX_TIMEOUT_SECS {
                    return Err(format!(
                        "--timeout must be between 1 and {MAX_TIMEOUT_SECS} seconds"
                    ));
                }
                timeout = Duration::from_secs(seconds);
            }
            ("--profile", Command::Connect { profile, .. }) => {
                let value = rest
                    .next()
                    .ok_or_else(|| "--profile needs a profile id".to_string())?;
                *profile = Some(value.clone());
            }
            (
                "--accept-tier2",
                Command::Connect {
                    acknowledge_tier2, ..
                },
            ) => {
                *acknowledge_tier2 = true;
            }
            ("--no-wait", Command::Connect { wait, .. } | Command::Disconnect { wait }) => {
                *wait = false;
            }
            ("-f" | "--follow", Command::Events { follow }) => *follow = true,
            (other, _) => {
                return Err(format!(
                    "'{}' is not an option of '{}'\n\n{USAGE}",
                    shown(other),
                    shown(first)
                ))
            }
        }
    }
    Ok(Invocation {
        command,
        trust_any_service,
        json,
        timeout,
    })
}

/// Text typed by the user, made safe to print back: control characters (a terminal escape
/// sequence among them) would otherwise be interpreted by the terminal.
fn shown(text: &str) -> String {
    crate::render::plain(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(args: &[&str]) -> Result<Invocation, String> {
        let args: Vec<String> = args.iter().map(|a| (*a).to_string()).collect();
        parse(&args)
    }

    fn command(args: &[&str]) -> Command {
        parsed(args).unwrap().command
    }

    #[test]
    fn each_command_has_its_defaults() {
        assert_eq!(command(&["status"]), Command::Status);
        assert_eq!(
            command(&["connect"]),
            Command::Connect {
                profile: None,
                acknowledge_tier2: false,
                wait: true
            }
        );
        assert_eq!(command(&["disconnect"]), Command::Disconnect { wait: true });
        assert_eq!(command(&["events"]), Command::Events { follow: false });
        assert_eq!(command(&["profiles"]), Command::Profiles);
        assert_eq!(command(&["endpoints"]), Command::Endpoints);
        assert_eq!(parsed(&["status"]).unwrap().timeout, DEFAULT_TIMEOUT);
        assert!(!parsed(&["status"]).unwrap().json);
    }

    #[test]
    fn options_apply_to_the_command_that_takes_them() {
        assert_eq!(
            command(&[
                "connect",
                "--profile",
                "hy2-default",
                "--accept-tier2",
                "--no-wait"
            ]),
            Command::Connect {
                profile: Some("hy2-default".into()),
                acknowledge_tier2: true,
                wait: false
            }
        );
        assert_eq!(
            command(&["disconnect", "--no-wait"]),
            Command::Disconnect { wait: false }
        );
        assert_eq!(command(&["events", "-f"]), Command::Events { follow: true });
        assert_eq!(
            command(&["events", "--follow"]),
            Command::Events { follow: true }
        );
        let global = parsed(&["status", "--json", "--timeout", "30"]).unwrap();
        assert!(global.json);
        assert_eq!(global.timeout, Duration::from_secs(30));
    }

    /// Off unless asked for, and asked for by a name that says what it risks.
    #[test]
    fn trusting_any_service_is_off_by_default_and_a_global_option() {
        assert!(!parsed(&["status"]).unwrap().trust_any_service);
        for command in ["status", "connect", "disconnect", "events", "profiles"] {
            assert!(
                parsed(&[command, "--allow-unprivileged-service"])
                    .unwrap()
                    .trust_any_service,
                "{command}"
            );
        }
    }

    #[test]
    fn help_is_a_command_in_any_spelling() {
        for spelling in ["help", "--help", "-h"] {
            assert_eq!(command(&[spelling]), Command::Help);
        }
    }

    #[test]
    fn an_option_the_command_does_not_take_is_refused_not_ignored() {
        for args in [
            &["status", "--profile", "x"][..],
            &["status", "--follow"],
            &["events", "--no-wait"],
            &["disconnect", "--accept-tier2"],
            &["profiles", "--bogus"],
        ] {
            let error = parsed(args).unwrap_err();
            assert!(error.contains("not an option"), "{args:?}: {error}");
        }
    }

    #[test]
    fn missing_and_unknown_commands_say_so_and_show_the_usage() {
        let none = parsed(&[]).unwrap_err();
        assert!(
            none.contains("no command") && none.contains("usage:"),
            "{none}"
        );
        let unknown = parsed(&["frobnicate"]).unwrap_err();
        assert!(
            unknown.contains("unknown command 'frobnicate'"),
            "{unknown}"
        );
    }

    #[test]
    fn an_option_that_needs_a_value_says_so() {
        assert!(parsed(&["connect", "--profile"])
            .unwrap_err()
            .contains("needs a profile id"));
        assert!(parsed(&["status", "--timeout"])
            .unwrap_err()
            .contains("needs a number"));
    }

    #[test]
    fn timeouts_are_whole_seconds_in_range() {
        for bad in ["0", "-5", "3601", "abc", "1.5", ""] {
            let error = parsed(&["connect", "--timeout", bad]).unwrap_err();
            assert!(error.contains("--timeout"), "{bad:?}: {error}");
        }
        assert_eq!(
            parsed(&["connect", "--timeout", "3600"]).unwrap().timeout,
            Duration::from_secs(3600)
        );
        assert_eq!(
            parsed(&["connect", "--timeout", "1"]).unwrap().timeout,
            Duration::from_secs(1)
        );
    }

    #[test]
    fn an_option_given_twice_is_refused() {
        let error = parsed(&["connect", "--no-wait", "--no-wait"]).unwrap_err();
        assert!(error.contains("twice"), "{error}");
    }

    /// What was typed is printed back; it must not be able to drive the terminal.
    #[test]
    fn typed_text_is_printed_back_without_control_characters() {
        let error = parsed(&["\u{1b}[31mred\u{1b}[0m"]).unwrap_err();
        assert!(!error.contains('\u{1b}'), "{error:?}");
    }
}
