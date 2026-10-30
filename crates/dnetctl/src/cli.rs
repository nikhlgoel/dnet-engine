//! T127 — what the user typed.
//!
//! Parsing is by hand: five commands and a handful of options do not justify a dependency, and a
//! dependency would be one more thing to audit for licence and supply chain in a tool that talks
//! to a privileged service. An unknown option is an error, never ignored: a mistyped `--profile`
//! that silently connected with the default would be worse than a refusal.
//!
//! **Credentials are never typed on the command line.** `add-endpoint` reads them from a file or from
//! standard input: an argument is kept in shell history and visible to every process on the machine.

use std::time::Duration;

/// How long `connect` and `disconnect` wait for the daemon to finish, unless told otherwise.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// The longest `--timeout` accepted, in seconds.
pub const MAX_TIMEOUT_SECS: u64 = 3600;

/// Where the credentials for a new endpoint are read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialsSource {
    /// A file the person prepared. Named by path; its content is never printed.
    File(String),
    Stdin,
}

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
    /// The networks, which one carries the connection, and how good each is.
    Paths,
    /// What the product did during this connection.
    Stats,
    /// Which versions of the protocol this program and the service speak.
    Version,
    /// Add a server the person controls.
    AddEndpoint {
        label: String,
        host: String,
        source: CredentialsSource,
    },
    RemoveEndpoint {
        endpoint: String,
    },
    /// `enable-endpoint` and `disable-endpoint`.
    SetEndpointEnabled {
        endpoint: String,
        enabled: bool,
    },
    /// Block (`true`, the default) or allow (`false`) programs' own encrypted name lookups.
    EncryptedDns {
        block: bool,
    },
    /// List the routing rules, the built-in ones and the person's.
    Rules,
    /// Add a rule: what it matches (`kind`, `value`) and what it does (`action`).
    AddRule {
        kind: String,
        value: String,
        action: String,
    },
    RemoveRule {
        rule: String,
    },
    /// Turn Brutal congestion control on for a Hysteria 2 profile (T105). Nothing is sent unless the
    /// person accepted the warning, which is shown otherwise.
    BrutalOn {
        profile: String,
        up: String,
        down: String,
        accept_warning: bool,
    },
    /// Turn Brutal off again.
    BrutalOff {
        profile: String,
    },
    /// Ask the service to check now for updated connection method definitions.
    CheckUpdates,
    /// Hand the service signed profile-feed documents from files (an offline import).
    ImportFeed {
        keys: Option<String>,
        feed: Option<String>,
    },
    Help,
}

impl Command {
    /// Whether the command takes one word that is not an option: a label, an id, a choice.
    fn takes_positional(&self) -> bool {
        matches!(
            self,
            Command::AddEndpoint { .. }
                | Command::RemoveEndpoint { .. }
                | Command::SetEndpointEnabled { .. }
                | Command::EncryptedDns { .. }
                | Command::BrutalOn { .. }
                | Command::BrutalOff { .. }
                | Command::RemoveRule { .. }
        )
    }
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
  paths                  show the networks, which one carries the connection, and how good each is
  stats                  show what the product did during this connection (counts, never a comparison)
  version                show this program's version and the service's, and whether they match
  add-endpoint <label>   add a server: --host <address> and --credentials-file <path> (or
                         --credentials-stdin)
  remove-endpoint <id>   remove an endpoint and forget its credentials
  enable-endpoint <id>   let an endpoint be used again
  disable-endpoint <id>  keep an endpoint but do not use it
  encrypted-dns <block|allow>
                         block (the default) or allow programs' own encrypted name lookups
  rules                  list the routing rules, built-in and your own, in the order they apply
  add-rule               add a rule: one of --domain <name>, --suffix <name> (the name and every
                         name under it) or --cidr <range>, and --tunnel or --bypass
  remove-rule <id>       remove one of your rules (built-in rules cannot be removed)
  brutal-on <profile>    turn on aggressive speed mode (Brutal) for a Hysteria 2 profile:
                         --up <Mbit/s> --down <Mbit/s>. It shows its warning and does nothing
                         until run again with --accept-warning.
  brutal-off <profile>   turn it off again (the default)
  check-updates          check now for updated connection methods (through the tunnel if one is up,
                         directly over your network if you are disconnected: only because you asked)
  import-feed            hand the service signed profile updates from files: --keys-file <path>
                         and/or --feed-file <path>. The service checks signatures; nothing here does.
  help                   show this text

Endpoints, rules, the encrypted-DNS choice and Brutal can be changed only while disconnected.

options:
  --json                 print the service's answers as JSON (for scripts)
  --timeout <seconds>    how long connect/disconnect wait (default 120, at most 3600)
  --profile <id>         connect: use only this profile (e.g. hy2-default)
  --accept-tier2         connect: consent to a profile whose connections may break when the
                         network interface changes
  --no-wait              connect/disconnect: return as soon as the service accepts the request
  --host <address>       add-endpoint: the server's IP address or host name
  --credentials-file <path>
                         add-endpoint: a file holding the connection details. Delete it afterwards:
                         it holds the keys. They are never accepted on the command line.
  --credentials-stdin    add-endpoint: read the connection details from standard input
  --up <Mbit/s>          brutal-on: your upload speed, a whole number
  --down <Mbit/s>        brutal-on: your download speed, a whole number
  --accept-warning       brutal-on: you have read the warning and accept it
  --keys-file <path>     import-feed: a signed keys document (taken first, if both are given)
  --feed-file <path>     import-feed: a signed profile feed
  -f, --follow           events: keep watching until interrupted
  --allow-unprivileged-service
                         DEVELOPMENT ONLY: also talk to a service that is not running as SYSTEM
                         or an administrator. Without it a process posing as the service is refused.

exit codes: 0 done | 1 refused or failed | 2 usage | 3 service not reachable | 4 timed out |
            5 unexpected reply | 6 this program and the service cannot talk (update one)";

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
        "paths" => Command::Paths,
        "stats" => Command::Stats,
        "version" | "--version" | "-V" => Command::Version,
        // Filled in from the words that follow; `parse` refuses the command if any are missing.
        "add-endpoint" => Command::AddEndpoint {
            label: String::new(),
            host: String::new(),
            source: CredentialsSource::Stdin,
        },
        "remove-endpoint" => Command::RemoveEndpoint {
            endpoint: String::new(),
        },
        "enable-endpoint" => Command::SetEndpointEnabled {
            endpoint: String::new(),
            enabled: true,
        },
        "disable-endpoint" => Command::SetEndpointEnabled {
            endpoint: String::new(),
            enabled: false,
        },
        "encrypted-dns" => Command::EncryptedDns { block: true },
        "rules" => Command::Rules,
        "add-rule" => Command::AddRule {
            kind: String::new(),
            value: String::new(),
            action: String::new(),
        },
        "remove-rule" => Command::RemoveRule {
            rule: String::new(),
        },
        "brutal-on" => Command::BrutalOn {
            profile: String::new(),
            up: String::new(),
            down: String::new(),
            accept_warning: false,
        },
        "brutal-off" => Command::BrutalOff {
            profile: String::new(),
        },
        "check-updates" => Command::CheckUpdates,
        "import-feed" => Command::ImportFeed {
            keys: None,
            feed: None,
        },
        "help" | "--help" | "-h" => Command::Help,
        _ => return None,
    })
}

/// The options that mean the same for every command. They may come before the command or after it:
/// `dnetctl --json status` and `dnetctl status --json` are the same.
fn move_global_options_after_the_command(args: &[String]) -> Vec<String> {
    let mut leading = Vec::new();
    let mut rest = args.iter().peekable();
    while let Some(arg) = rest.peek() {
        match arg.as_str() {
            "--json" | "--allow-unprivileged-service" => leading.push(rest.next().unwrap().clone()),
            // Its value goes with it; a missing value is left for the parser to complain about.
            "--timeout" => {
                leading.push(rest.next().unwrap().clone());
                if let Some(value) = rest.next() {
                    leading.push(value.clone());
                }
            }
            _ => break,
        }
    }
    let mut ordered: Vec<String> = rest.cloned().collect();
    // With nothing but options there is no command, which is what is then said.
    if !ordered.is_empty() {
        ordered.extend(leading);
    }
    ordered
}

/// Parse the arguments after the program name. `Err` is a message for the user.
pub fn parse(args: &[String]) -> Result<Invocation, String> {
    let args = &move_global_options_after_the_command(args);
    let Some(first) = args.first() else {
        return Err(format!("no command given\n\n{USAGE}"));
    };
    let mut command = command_named(first)
        .ok_or_else(|| format!("unknown command '{}'\n\n{USAGE}", shown(first)))?;
    let mut json = false;
    let mut trust_any_service = false;
    let mut timeout = DEFAULT_TIMEOUT;
    let mut seen: Vec<&str> = Vec::new();
    let mut word: Option<String> = None;
    let mut host: Option<String> = None;
    let mut credentials_file: Option<String> = None;
    let mut credentials_stdin = false;
    let mut matches: Vec<(&str, String)> = Vec::new();
    let mut actions: Vec<&str> = Vec::new();

    let mut rest = args[1..].iter();
    while let Some(option) = rest.next() {
        let name = option.as_str();
        if !name.starts_with('-') && command.takes_positional() {
            if word.is_some() {
                return Err(format!(
                    "'{}' is one word too many for '{}'\n\n{USAGE}",
                    shown(name),
                    shown(first)
                ));
            }
            word = Some(name.to_owned());
            continue;
        }
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
            ("--host", Command::AddEndpoint { .. }) => {
                host = Some(
                    rest.next()
                        .ok_or_else(|| "--host needs an address".to_string())?
                        .clone(),
                );
            }
            ("--credentials-file", Command::AddEndpoint { .. }) => {
                credentials_file = Some(
                    rest.next()
                        .ok_or_else(|| "--credentials-file needs a path".to_string())?
                        .clone(),
                );
            }
            ("--credentials-stdin", Command::AddEndpoint { .. }) => credentials_stdin = true,
            ("--domain" | "--suffix" | "--cidr", Command::AddRule { .. }) => {
                let value = rest
                    .next()
                    .ok_or_else(|| format!("{name} needs a value"))?
                    .clone();
                let kind = match name {
                    "--domain" => "domain",
                    "--suffix" => "domain_suffix",
                    _ => "ip_cidr",
                };
                matches.push((kind, value));
            }
            ("--tunnel", Command::AddRule { .. }) => actions.push("tunnel"),
            ("--bypass", Command::AddRule { .. }) => actions.push("bypass"),
            ("--up", Command::BrutalOn { up, .. }) => {
                *up = rest
                    .next()
                    .ok_or_else(|| "--up needs a speed in Mbit/s".to_string())?
                    .clone();
            }
            ("--down", Command::BrutalOn { down, .. }) => {
                *down = rest
                    .next()
                    .ok_or_else(|| "--down needs a speed in Mbit/s".to_string())?
                    .clone();
            }
            ("--accept-warning", Command::BrutalOn { accept_warning, .. }) => {
                *accept_warning = true;
            }
            ("--keys-file", Command::ImportFeed { keys, .. }) => {
                *keys = Some(
                    rest.next()
                        .ok_or_else(|| "--keys-file needs a path".to_string())?
                        .clone(),
                );
            }
            ("--feed-file", Command::ImportFeed { feed, .. }) => {
                *feed = Some(
                    rest.next()
                        .ok_or_else(|| "--feed-file needs a path".to_string())?
                        .clone(),
                );
            }
            (other, _) => {
                return Err(format!(
                    "'{}' is not an option of '{}'\n\n{USAGE}",
                    shown(other),
                    shown(first)
                ))
            }
        }
    }
    match &mut command {
        Command::AddEndpoint {
            label,
            host: address,
            source,
        } => {
            *label =
                word.ok_or("add-endpoint needs a label, e.g. 'dnetctl add-endpoint home ...'")?;
            *address = host.ok_or("add-endpoint needs --host <address>")?;
            *source = match (credentials_file, credentials_stdin) {
                (Some(path), false) => CredentialsSource::File(path),
                (None, true) => CredentialsSource::Stdin,
                (Some(_), true) => return Err(
                    "give the credentials by --credentials-file or --credentials-stdin, not both"
                        .to_string(),
                ),
                (None, false) => {
                    return Err(
                        "add-endpoint needs --credentials-file <path> or --credentials-stdin; \
                         credentials are never accepted on the command line"
                            .to_string(),
                    )
                }
            };
        }
        Command::RemoveEndpoint { endpoint } | Command::SetEndpointEnabled { endpoint, .. } => {
            *endpoint = word.ok_or_else(|| {
                format!(
                    "{} needs an endpoint id (see 'dnetctl endpoints')",
                    shown(first)
                )
            })?;
        }
        Command::BrutalOn {
            profile, up, down, ..
        } => {
            *profile = word.ok_or("brutal-on needs a profile id (see 'dnetctl profiles')")?;
            if up.is_empty() || down.is_empty() {
                return Err("brutal-on needs both --up <Mbit/s> and --down <Mbit/s>".to_string());
            }
        }
        Command::AddRule {
            kind,
            value,
            action,
        } => {
            let (k, v) = match matches.len() {
                0 => {
                    return Err(
                        "add-rule needs --domain <name>, --suffix <name> or --cidr <range>"
                            .to_string(),
                    )
                }
                1 => matches.remove(0),
                _ => return Err("add-rule matches one of --domain, --suffix or --cidr".to_string()),
            };
            *kind = k.to_owned();
            *value = v;
            *action = match actions.as_slice() {
                [one] => (*one).to_owned(),
                [] => return Err("add-rule needs --tunnel or --bypass".to_string()),
                _ => return Err("add-rule takes --tunnel or --bypass, not both".to_string()),
            };
        }
        Command::RemoveRule { rule } => {
            *rule = word.ok_or("remove-rule needs a rule id (see 'dnetctl rules')")?;
        }
        Command::BrutalOff { profile } => {
            *profile = word.ok_or("brutal-off needs a profile id (see 'dnetctl profiles')")?;
        }
        Command::ImportFeed { keys, feed } => {
            if keys.is_none() && feed.is_none() {
                return Err(
                    "import-feed needs --keys-file <path>, --feed-file <path>, or both".to_string(),
                );
            }
        }
        Command::EncryptedDns { block } => {
            *block = match word.as_deref() {
                Some("block") => true,
                Some("allow") => false,
                _ => return Err("encrypted-dns needs 'block' or 'allow'".to_string()),
            };
        }
        _ => {}
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

    // ------------------------------------------------------------ configuration commands

    #[test]
    fn add_endpoint_takes_a_label_an_address_and_a_credentials_source() {
        assert_eq!(
            command(&[
                "add-endpoint",
                "home",
                "--host",
                "203.0.113.9",
                "--credentials-file",
                "creds.json"
            ]),
            Command::AddEndpoint {
                label: "home".into(),
                host: "203.0.113.9".into(),
                source: CredentialsSource::File("creds.json".into()),
            }
        );
        // The label may come after the options.
        assert_eq!(
            command(&[
                "add-endpoint",
                "--host",
                "h.example.net",
                "--credentials-stdin",
                "home"
            ]),
            Command::AddEndpoint {
                label: "home".into(),
                host: "h.example.net".into(),
                source: CredentialsSource::Stdin,
            }
        );
    }

    #[test]
    fn add_endpoint_refuses_what_is_missing_and_says_which() {
        let cases: [(&[&str], &str); 5] = [
            (
                &["add-endpoint", "--host", "h", "--credentials-stdin"],
                "label",
            ),
            (&["add-endpoint", "home", "--credentials-stdin"], "--host"),
            (
                &["add-endpoint", "home", "--host", "h"],
                "--credentials-file",
            ),
            (
                &[
                    "add-endpoint",
                    "home",
                    "--host",
                    "h",
                    "--credentials-file",
                    "f",
                    "--credentials-stdin",
                ],
                "not both",
            ),
            (&["add-endpoint", "home", "--host"], "needs an address"),
        ];
        for (args, expected) in cases {
            let error = parsed(args).unwrap_err();
            assert!(error.contains(expected), "{args:?}: {error}");
        }
    }

    #[test]
    fn credentials_are_not_accepted_as_an_argument() {
        for option in ["--credentials", "--password", "--key", "--auth"] {
            let error = parsed(&[
                "add-endpoint",
                "home",
                "--host",
                "h",
                "--credentials-stdin",
                option,
                "secret-value",
            ])
            .unwrap_err();
            assert!(error.contains("not an option"), "{option}: {error}");
            assert!(!error.contains("secret-value"), "{error}");
        }
    }

    #[test]
    fn the_endpoint_commands_take_one_id() {
        assert_eq!(
            command(&["remove-endpoint", "abc"]),
            Command::RemoveEndpoint {
                endpoint: "abc".into()
            }
        );
        assert_eq!(
            command(&["enable-endpoint", "abc"]),
            Command::SetEndpointEnabled {
                endpoint: "abc".into(),
                enabled: true
            }
        );
        assert_eq!(
            command(&["disable-endpoint", "abc"]),
            Command::SetEndpointEnabled {
                endpoint: "abc".into(),
                enabled: false
            }
        );
        for name in ["remove-endpoint", "enable-endpoint", "disable-endpoint"] {
            assert!(parsed(&[name])
                .unwrap_err()
                .contains("needs an endpoint id"));
            assert!(parsed(&[name, "a", "b"])
                .unwrap_err()
                .contains("one word too many"));
        }
    }

    #[test]
    fn add_rule_takes_one_thing_to_match_and_one_action() {
        assert_eq!(
            command(&["add-rule", "--suffix", "example.com", "--bypass"]),
            Command::AddRule {
                kind: "domain_suffix".into(),
                value: "example.com".into(),
                action: "bypass".into(),
            }
        );
        assert_eq!(
            command(&["add-rule", "--cidr", "198.51.100.0/24", "--tunnel"]),
            Command::AddRule {
                kind: "ip_cidr".into(),
                value: "198.51.100.0/24".into(),
                action: "tunnel".into(),
            }
        );
        for (args, says) in [
            (vec!["add-rule", "--tunnel"], "--domain"),
            (
                vec!["add-rule", "--domain", "a.example"],
                "--tunnel or --bypass",
            ),
            (
                vec![
                    "add-rule",
                    "--domain",
                    "a.example",
                    "--suffix",
                    "b.example",
                    "--tunnel",
                ],
                "one of",
            ),
            (
                vec!["add-rule", "--domain", "a.example", "--tunnel", "--bypass"],
                "not both",
            ),
            (vec!["remove-rule"], "needs a rule id"),
        ] {
            let error = parsed(&args).unwrap_err();
            assert!(error.contains(says), "{args:?}: {error}");
        }
        assert_eq!(command(&["rules"]), Command::Rules);
    }

    #[test]
    fn brutal_on_takes_a_profile_and_both_speeds_and_brutal_off_a_profile() {
        assert_eq!(
            command(&["brutal-on", "hy2-default", "--up", "50", "--down", "200"]),
            Command::BrutalOn {
                profile: "hy2-default".into(),
                up: "50".into(),
                down: "200".into(),
                accept_warning: false,
            }
        );
        assert!(matches!(
            command(&[
                "brutal-on",
                "hy2-default",
                "--up",
                "1",
                "--down",
                "1",
                "--accept-warning"
            ]),
            Command::BrutalOn {
                accept_warning: true,
                ..
            }
        ));
        assert_eq!(
            command(&["brutal-off", "hy2-default"]),
            Command::BrutalOff {
                profile: "hy2-default".into()
            }
        );
        for (args, says) in [
            (
                vec!["brutal-on", "hy2-default", "--down", "200"],
                "both --up",
            ),
            (
                vec!["brutal-on", "--up", "1", "--down", "1"],
                "needs a profile id",
            ),
            (vec!["brutal-off"], "needs a profile id"),
            (
                vec!["brutal-off", "hy2-default", "--up", "1"],
                "not an option",
            ),
            (
                vec!["brutal-on", "a", "b", "--up", "1", "--down", "1"],
                "one word too many",
            ),
        ] {
            let error = parsed(&args).unwrap_err();
            assert!(error.contains(says), "{args:?}: {error}");
        }
    }

    #[test]
    fn encrypted_dns_takes_block_or_allow_and_nothing_else() {
        assert_eq!(
            command(&["encrypted-dns", "block"]),
            Command::EncryptedDns { block: true }
        );
        assert_eq!(
            command(&["encrypted-dns", "allow"]),
            Command::EncryptedDns { block: false }
        );
        for bad in [
            &["encrypted-dns"][..],
            &["encrypted-dns", "yes"],
            &["encrypted-dns", "Block"],
        ] {
            assert!(
                parsed(bad).unwrap_err().contains("'block' or 'allow'"),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn import_feed_takes_one_or_both_files() {
        assert_eq!(
            command(&["import-feed", "--feed-file", "f.json"]),
            Command::ImportFeed {
                keys: None,
                feed: Some("f.json".into())
            }
        );
        assert_eq!(
            command(&["import-feed", "--keys-file", "k", "--feed-file", "f"]),
            Command::ImportFeed {
                keys: Some("k".into()),
                feed: Some("f".into())
            }
        );
        assert!(parsed(&["import-feed"])
            .unwrap_err()
            .contains("--keys-file"));
        assert!(parsed(&["import-feed", "--feed-file"])
            .unwrap_err()
            .contains("needs a path"));
        assert!(parsed(&["import-feed", "--host", "x"])
            .unwrap_err()
            .contains("not an option"));
        assert!(parsed(&["status", "--feed-file", "x"])
            .unwrap_err()
            .contains("not an option"));
    }

    #[test]
    fn global_options_may_come_before_the_command() {
        let before = parsed(&[
            "--allow-unprivileged-service",
            "--json",
            "--timeout",
            "30",
            "status",
        ])
        .unwrap();
        let after = parsed(&[
            "status",
            "--allow-unprivileged-service",
            "--json",
            "--timeout",
            "30",
        ])
        .unwrap();
        assert_eq!(before, after);
        assert!(before.trust_any_service && before.json);
        assert_eq!(before.timeout, Duration::from_secs(30));
    }

    #[test]
    fn options_before_a_command_do_not_hide_a_mistake() {
        // An option only some commands take is still refused for the others.
        assert!(parsed(&["--profile", "x", "status"])
            .unwrap_err()
            .contains("unknown command"));
        assert!(parsed(&["--json"]).unwrap_err().contains("no command"));
        assert!(parsed(&["--timeout"]).unwrap_err().contains("no command"));
        // Given twice, wherever.
        assert!(parsed(&["--json", "status", "--json"])
            .unwrap_err()
            .contains("twice"));
        // And help is still help.
        assert_eq!(command(&["--help"]), Command::Help);
    }

    #[test]
    fn a_word_is_refused_by_a_command_that_takes_none() {
        for args in [
            &["status", "extra"][..],
            &["connect", "now"],
            &["profiles", "x"],
        ] {
            assert!(
                parsed(args).unwrap_err().contains("not an option"),
                "{args:?}"
            );
        }
    }

    #[test]
    fn the_new_options_belong_to_add_endpoint_alone() {
        for args in [
            &["connect", "--host", "h"][..],
            &["remove-endpoint", "a", "--credentials-stdin"],
            &["status", "--credentials-file", "f"],
        ] {
            assert!(
                parsed(args).unwrap_err().contains("not an option"),
                "{args:?}"
            );
        }
    }

    /// What was typed is printed back; it must not be able to drive the terminal.
    #[test]
    fn typed_text_is_printed_back_without_control_characters() {
        let error = parsed(&["\u{1b}[31mred\u{1b}[0m"]).unwrap_err();
        assert!(!error.contains('\u{1b}'), "{error:?}");
    }
}
