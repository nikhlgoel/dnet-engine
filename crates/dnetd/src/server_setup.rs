//! T150 — setting up the person's own server from the window (IPC-26).
//!
//! `prepare` makes the keys that stay on this computer, keeps them for an hour, and returns the script to
//! run on the server and the ports to open. `finish` reads what the script printed, checks it against what
//! was asked for, and returns the credentials to seal. Nothing is created in the person's cloud account and
//! no cloud credential is ever held: the person does those steps themselves, in their own browser.
//!
//! - **Fail closed.** No downloads list (this build has none), no pending setup, an expired one, or a
//!   report that does not match each answer with a sentence and change nothing.
//! - **A report belongs to one script.** It carries the client key the server was given, so a report from
//!   a server set up by an earlier script is refused instead of being used with the wrong keys.
//! - **A failed paste keeps the setup waiting**, so the person can paste again; a success consumes it.
//! - **Nothing a person pasted is repeated** in an error: the report is read as hostile input.

use std::sync::Mutex;

use dnet_config::credentials::EndpointCredentials;
use dnet_config::reality::TargetDomain;
use dnet_ipc::server_setup::{PortToOpen, Prepared, ServerKind};
use dnet_provision::bootstrap::{
    self, BootstrapPlan, BootstrapReport, Ports, ReportError, ServerArch, SessionPlan,
};
use dnet_provision::client_keys::{self, ClientKeys, SessionKeys};
use dnet_provision::provider::Protocol;
use dnet_provision::server_pins::ServerPins;

/// How long a prepared setup waits for its report. Long enough for a first-time account (identity checks
/// can take a while) and a server; short enough that keys do not sit in memory for a day. In memory only.
pub const WAIT_S: u64 = 6 * 3600;

/// The name the Hysteria 2 certificate is issued for and the REALITY handshake is forwarded to: a large
/// site that serves TLS 1.3 and HTTP/2 (checked 2026-10-30). The signed feed can propose others later.
pub const DEFAULT_SITE: &str = "www.microsoft.com";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SetupError {
    #[error(
        "setting up a server is not available in this build: it has no list of server downloads"
    )]
    NoDownloads,
    #[error("this release has no server downloads for that kind of server")]
    NoBuild,
    #[error("no server setup is waiting for a result; start again from the first step")]
    Nothing,
    #[error("that setup waited more than six hours; start again from the first step")]
    Expired,
    #[error("the script could not be made")]
    Script,
    #[error("the result cannot be used: {0}")]
    Report(String),
}

struct Pending {
    keys: ClientKeys,
    /// The device's session key pair (ADR-0008). Only the public half is in the script; the private half
    /// goes into the credentials with the others once the server has reported.
    session_keys: SessionKeys,
    plan: BootstrapPlan,
    script: String,
    kind: ServerKind,
    made_at_s: u64,
}

/// The downloads list installed beside the service, if there is one and it is sound. The reason it is
/// not is logged, never its contents.
#[cfg(windows)]
pub fn installed_pins() -> Option<ServerPins> {
    use std::io::Read;

    let path = std::env::current_exe()
        .ok()?
        .with_file_name(dnet_provision::server_pins::FILE_NAME);
    let mut text = String::new();
    let read = std::fs::File::open(&path).and_then(|file| {
        file.take(dnet_provision::server_pins::MAX_PINS_BYTES as u64 + 1)
            .read_to_string(&mut text)
    });
    if let Err(error) = read {
        tracing::warn!(kind = ?error.kind(), "no list of server downloads is installed; setting up a server is unavailable");
        return None;
    }
    match ServerPins::parse(&text) {
        Ok(pins) => Some(pins),
        Err(error) => {
            tracing::error!(%error, "the list of server downloads is not usable; setting up a server is unavailable");
            None
        }
    }
}

pub struct ServerSetup {
    pins: Option<ServerPins>,
    pending: Mutex<Option<Pending>>,
}

fn arch_of(kind: ServerKind) -> ServerArch {
    match kind {
        ServerKind::Amd64 => ServerArch::Amd64,
        ServerKind::Arm64 => ServerArch::Arm64,
    }
}

impl ServerSetup {
    pub fn new(pins: Option<ServerPins>) -> Self {
        Self {
            pins,
            pending: Mutex::new(None),
        }
    }

    fn slot(&self) -> std::sync::MutexGuard<'_, Option<Pending>> {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Start a setup. A setup already waiting is replaced: its keys are dropped, and a result from its
    /// script will be refused.
    pub fn prepare(&self, kind: ServerKind, now_s: u64) -> Result<Prepared, SetupError> {
        let pins = self.pins.as_ref().ok_or(SetupError::NoDownloads)?;
        // The same setup, if one for this kind of server is still waiting: the window may have been closed
        // and opened again, and a script already run on a server must keep matching.
        if let Some(waiting) = self.slot().as_ref() {
            if waiting.kind == kind && now_s.saturating_sub(waiting.made_at_s) <= WAIT_S {
                return Ok(self.describe(waiting));
            }
        }
        let cores = pins
            .cores_for(arch_of(kind))
            .map_err(|_| SetupError::NoBuild)?;
        let keys = ClientKeys::generate().map_err(|_| SetupError::Script)?;
        let session_keys = SessionKeys::generate().map_err(|_| SetupError::Script)?;
        let obfuscation = client_keys::random_obfuscation().map_err(|_| SetupError::Script)?;
        let ports = Ports::default();
        let plan = BootstrapPlan {
            cores,
            ports,
            awg_client_public_hex: keys.public_hex().to_owned(),
            obfuscation,
            hysteria2_server_name: DEFAULT_SITE.to_owned(),
            reality_target: TargetDomain::parse(DEFAULT_SITE).map_err(|_| SetupError::Script)?,
            session: SessionPlan {
                device_public_keys: vec![session_keys.public_b64().to_owned()],
            },
        };
        let script = bootstrap::script(&plan).map_err(|_| SetupError::Script)?;
        let pending = Pending {
            keys,
            session_keys,
            plan,
            script,
            kind,
            made_at_s: now_s,
        };
        let prepared = self.describe(&pending);
        *self.slot() = Some(pending);
        Ok(prepared)
    }

    fn describe(&self, pending: &Pending) -> Prepared {
        let to_open = pending
            .plan
            .ports
            .rules()
            .into_iter()
            .map(|rule| PortToOpen {
                protocol: match rule.protocol {
                    Protocol::Udp => "udp",
                    Protocol::Tcp => "tcp",
                }
                .to_owned(),
                port: rule.port,
            })
            .collect();
        Prepared {
            arch: pending.kind,
            script: pending.script.clone(),
            ports: to_open,
            valid_for_s: WAIT_S,
        }
    }

    /// Read what the script printed. The credentials are returned and the setup **keeps waiting**: the
    /// caller still has to save them, and a save that fails (a name already in use, a full disk) must not
    /// cost the person their keys. [`Self::complete`] ends the setup once they are saved. On any failure
    /// it also keeps waiting, unless it has expired.
    pub fn finish(&self, pasted: &str, now_s: u64) -> Result<EndpointCredentials, SetupError> {
        let mut slot = self.slot();
        let pending = slot.as_ref().ok_or(SetupError::Nothing)?;
        if now_s.saturating_sub(pending.made_at_s) > WAIT_S {
            *slot = None;
            return Err(SetupError::Expired);
        }
        let report =
            BootstrapReport::parse(pasted).map_err(|e| SetupError::Report(e.to_string()))?;
        report.check_against(&pending.plan).map_err(|e| match e {
            // The one mismatch a person can cause by starting over, said so they can act on it.
            ReportError::Mismatch("the client key") => SetupError::Report(
                "it comes from a server set up with a different script than the one now waiting; \
                 run the script shown on this screen, or start the setup again"
                    .to_owned(),
            ),
            other => SetupError::Report(other.to_string()),
        })?;
        // The origin the script put on the server: without it no connection could be tested or checked.
        Ok(report.credentials(
            &pending.keys,
            &pending.session_keys,
            pending.plan.obfuscation,
            Some(bootstrap::measurement_origin()),
        ))
    }

    /// The server is saved: drop the keys that were waiting for it.
    pub fn complete(&self) {
        *self.slot() = None;
    }

    /// Whether a setup is waiting (for tests and diagnostics).
    #[cfg(test)]
    pub fn waiting(&self) -> bool {
        self.slot().is_some()
    }
}

/// The session part of the report a server would print for `script`: its public key, and the devices the
/// script was given, read off the script the way the server would. For the tests that fake a server.
#[cfg(test)]
pub(crate) fn session_printed_by(script: &str) -> serde_json::Value {
    // A new server's list is made from the keys the script hands to `dnet-devices sync`, each at the address its
    // place gives it.
    let keys: Vec<&str> = script
        .lines()
        .find(|l| l.contains("dnet-devices\" sync "))
        .expect("the script gives its devices to the server's list")
        .split('\'')
        .skip(1)
        .step_by(2)
        .collect();
    let devices: Vec<serde_json::Value> = keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            serde_json::json!({
                "address": dnet_config::session::session_device_address(i).to_string(),
                "public_key": key,
            })
        })
        .collect();
    serde_json::json!({
        "server_public_key": "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM=",
        "port": 25182,
        "server_address": "10.9.0.1",
        "devices": devices,
    })
}

#[cfg(test)]
mod tests {
    use serde_json::{json, Value};

    use super::*;

    fn pins() -> ServerPins {
        ServerPins::parse(
            &json!({
                "version": 1,
                "base_url": "https://example.test/releases/download/v0.1.0/",
                "primary_core": {
                    "name": "primary-core", "version": "v1.14.0", "licence": "GPL-3.0-or-later",
                    "source": "https://example.test/source",
                    "amd64": { "file": "primary-core-linux-amd64", "sha256": "a".repeat(64) },
                    "arm64": { "file": "primary-core-linux-arm64", "sha256": "b".repeat(64) },
                },
                "amneziawg": {
                    "name": "amneziawg-go", "version": "v3.1.0", "licence": "MIT",
                    "source": "https://example.test/awg",
                    "amd64": { "file": "amneziawg-go-linux-amd64", "sha256": "c".repeat(64) },
                    "arm64": { "file": "amneziawg-go-linux-arm64", "sha256": "d".repeat(64) },
                },
            })
            .to_string(),
        )
        .unwrap()
    }

    fn setup() -> ServerSetup {
        ServerSetup::new(Some(pins()))
    }

    /// What a server set up by `prepared`'s script prints: read off the script the way the server would.
    fn printed_by(prepared: &Prepared, edit: impl FnOnce(&mut Value)) -> String {
        let client = prepared
            .script
            .lines()
            .find_map(|l| l.strip_prefix("public_key="))
            .unwrap()
            .to_owned();
        let (primary, awg) = match prepared.arch {
            ServerKind::Amd64 => ('a', 'c'),
            ServerKind::Arm64 => ('b', 'd'),
        };
        let mut report = json!({
            "version": 2,
            "session": super::session_printed_by(&prepared.script),
            "amneziawg": {
                "server_public_key_hex": "d".repeat(64), "listen_port": 51820,
                "client_address": "10.66.0.2", "prefix_len": 24, "client_public_key_hex": client,
            },
            "hysteria2": {
                "server_port": 44443, "server_name": DEFAULT_SITE, "spki_sha256_hex": "e".repeat(64),
                "auth_password": "auth-secret-0123456789abcdef",
                "obfs_password": "obfs-secret-0123456789abcdef",
                "cert_key_algorithm": "ecdsa-p256",
            },
            "reality": {
                "server_port": 8443, "target_domain": DEFAULT_SITE,
                "public_key": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
                "short_id": "0123456789abcdef", "uuid": "bf000d23-0752-40b4-affe-68f7707a9661",
                "flow": "xtls-rprx-vision",
            },
            "cores": {
                "primary_core": { "version": "v1.14.0", "sha256": primary.to_string().repeat(64) },
                "amneziawg": { "version": "v3.1.0", "sha256": awg.to_string().repeat(64) },
            },
        });
        edit(&mut report);
        format!("last login: today\nroot@vm:~# sh setup.sh\nworking...\nDNET-BOOTSTRAP-REPORT {report}\nroot@vm:~# ")
    }

    #[test]
    fn a_setup_without_a_downloads_list_says_so_and_makes_nothing() {
        let setup = ServerSetup::new(None);
        assert_eq!(
            setup.prepare(ServerKind::Amd64, 0),
            Err(SetupError::NoDownloads)
        );
        assert!(!setup.waiting());
    }

    /// The window may be closed and opened again while the person creates their server; the same script
    /// comes back, so a script already run still matches. A different kind of server is a new setup.
    #[test]
    fn asking_again_returns_the_same_script_until_it_is_used_or_expires() {
        let setup = setup();
        let first = setup.prepare(ServerKind::Amd64, 100).unwrap();
        let again = setup.prepare(ServerKind::Amd64, 100 + WAIT_S / 2).unwrap();
        assert_eq!(first.script, again.script);
        // The wait is counted from the first, not renewed by asking.
        assert!(setup
            .finish(&printed_by(&first, |_| {}), 100 + WAIT_S + 1)
            .is_err());
        let fresh = setup.prepare(ServerKind::Amd64, 100 + WAIT_S + 2).unwrap();
        assert_ne!(
            first.script, fresh.script,
            "an expired setup is made again, with new keys"
        );
        // Another kind of server is its own setup.
        let arm = setup.prepare(ServerKind::Arm64, 100 + WAIT_S + 3).unwrap();
        assert_ne!(fresh.script, arm.script);
        // Once saved, the next one is new.
        let used = printed_by(&arm, |_| {});
        assert!(setup.finish(&used, 100 + WAIT_S + 4).is_ok());
        setup.complete();
        assert_ne!(
            setup
                .prepare(ServerKind::Arm64, 100 + WAIT_S + 5)
                .unwrap()
                .script,
            arm.script
        );
    }

    #[test]
    fn a_result_from_an_earlier_script_is_explained_in_words() {
        let setup = setup();
        let first = setup.prepare(ServerKind::Amd64, 0).unwrap();
        let from_first = printed_by(&first, |r| {
            r["amneziawg"]["client_public_key_hex"] = json!("9".repeat(64))
        });
        let message = setup.finish(&from_first, 1).unwrap_err().to_string();
        assert!(message.contains("different script"), "{message}");
        assert!(!message.contains("client key"), "no jargon: {message}");
    }

    #[test]
    fn prepare_gives_a_script_for_the_kind_of_server_and_the_three_ports() {
        let setup = setup();
        let amd = setup.prepare(ServerKind::Amd64, 100).unwrap();
        assert_eq!(amd.arch, ServerKind::Amd64);
        assert!(amd.script.contains("primary-core-linux-amd64"));
        assert!(amd.script.contains("!= \"x86_64\""));
        let ports: Vec<_> = amd
            .ports
            .iter()
            .map(|p| (p.protocol.as_str(), p.port))
            .collect();
        assert_eq!(ports, [("udp", 51820), ("udp", 44443), ("tcp", 8443)]);
        assert_eq!(amd.valid_for_s, WAIT_S);
        let arm = setup.prepare(ServerKind::Arm64, 100).unwrap();
        assert!(arm.script.contains("primary-core-linux-arm64") && arm.script.contains("aarch64"));
        assert!(!arm.script.contains("amd64"));
    }

    /// The script is not secret, but the client's private key must not be in it.
    #[test]
    fn the_script_holds_the_public_key_and_never_the_private_one() {
        let setup = setup();
        let prepared = setup.prepare(ServerKind::Amd64, 0).unwrap();
        let slot = setup.slot();
        let keys = &slot.as_ref().unwrap().keys;
        assert!(prepared.script.contains(keys.public_hex()));
        assert!(!prepared.script.contains(keys.private_hex()));
    }

    #[test]
    fn a_matching_report_yields_credentials_with_this_computers_own_key_and_ends_when_saved() {
        let setup = setup();
        let prepared = setup.prepare(ServerKind::Arm64, 1000).unwrap();
        let private = setup.slot().as_ref().unwrap().keys.private_hex().to_owned();
        let credentials = setup.finish(&printed_by(&prepared, |_| {}), 1500).unwrap();
        let awg = credentials
            .amneziawg
            .as_ref()
            .expect("AmneziaWG credentials");
        assert_eq!(awg.client_private_key.expose_wire(), private);
        assert!(credentials.hysteria2.is_some() && credentials.reality.is_some());
        // Still waiting until the caller has saved them; then gone.
        assert!(setup.waiting());
        setup.complete();
        assert!(!setup.waiting());
        assert_eq!(
            setup.finish(&printed_by(&prepared, |_| {}), 1501),
            Err(SetupError::Nothing)
        );
    }

    /// A first-time account can take hours (identity checks); the wait is six hours, not what a slip in the
    /// arithmetic would make it. The setup is still good at five.
    /// The whole point: a server made by the guide is one the connection code will use. Before the origin was
    /// carried, every such server was refused with "no measurement origin" at the first connect.
    #[test]
    fn a_server_made_by_the_guide_is_usable_by_the_connection_code() {
        use dnet_config::secret_store::{MemorySecretStore, SecretKey, SecretStore};
        use dnet_core::endpoint::{Endpoint, EndpointAddress, EndpointOrigin};
        use dnet_core::ids::EndpointId;

        let setup = setup();
        let prepared = setup.prepare(ServerKind::Arm64, 0).unwrap();
        let credentials = setup.finish(&printed_by(&prepared, |_| {}), 1).unwrap();
        assert_eq!(
            credentials.measure_origin,
            Some(bootstrap::measurement_origin())
        );

        let id = EndpointId::new();
        let key = SecretKey::for_endpoint(id);
        let secrets = MemorySecretStore::new();
        secrets.put(&key, &credentials).unwrap();
        let endpoint = Endpoint::new(
            id,
            "my server",
            EndpointAddress::new("203.0.113.10", 44443).unwrap(),
            EndpointOrigin::Manual,
            key.credential_ref(),
        )
        .unwrap();
        let assessed = crate::plan::assess_endpoints(std::slice::from_ref(&endpoint), &secrets);
        assert!(assessed.problems.is_empty(), "{:?}", assessed.problems);
        assert_eq!(assessed.usable, [endpoint]);
        assert_eq!(
            assessed.served.len(),
            3,
            "all three connection methods: {:?}",
            assessed.served
        );
    }

    #[test]
    fn the_wait_is_six_hours() {
        assert_eq!(WAIT_S, 21_600);
        let setup = setup();
        let prepared = setup.prepare(ServerKind::Amd64, 0).unwrap();
        assert_eq!(prepared.valid_for_s, 21_600);
        assert!(setup
            .finish(&printed_by(&prepared, |_| {}), 5 * 3600)
            .is_ok());
    }

    #[test]
    fn nothing_waiting_and_too_late_are_said_in_words() {
        let setup = setup();
        assert_eq!(
            setup.finish("DNET-BOOTSTRAP-REPORT {}", 0),
            Err(SetupError::Nothing)
        );
        let prepared = setup.prepare(ServerKind::Amd64, 1000).unwrap();
        let late = printed_by(&prepared, |_| {});
        assert_eq!(
            setup.finish(&late, 1000 + WAIT_S + 1),
            Err(SetupError::Expired)
        );
        assert!(!setup.waiting(), "an expired setup is dropped");
        // Exactly at the limit is still in time.
        let prepared = setup.prepare(ServerKind::Amd64, 5000).unwrap();
        assert!(setup
            .finish(&printed_by(&prepared, |_| {}), 5000 + WAIT_S)
            .is_ok());
    }

    #[test]
    fn a_result_that_does_not_fit_is_refused_and_the_setup_keeps_waiting() {
        let setup = setup();
        let prepared = setup.prepare(ServerKind::Amd64, 0).unwrap();
        let cases: Vec<(&str, String)> = vec![
            ("nothing printed", "just a prompt".to_owned()),
            (
                "other port",
                printed_by(&prepared, |r| r["hysteria2"]["server_port"] = json!(1234)),
            ),
            (
                "other core",
                printed_by(&prepared, |r| {
                    r["cores"]["primary_core"]["sha256"] = json!("f".repeat(64))
                }),
            ),
            (
                "arm core on an x86 script",
                printed_by(&prepared, |r| {
                    r["cores"]["primary_core"]["sha256"] = json!("b".repeat(64))
                }),
            ),
            (
                "other client key",
                printed_by(&prepared, |r| {
                    r["amneziawg"]["client_public_key_hex"] = json!("9".repeat(64))
                }),
            ),
            (
                "ed25519",
                printed_by(&prepared, |r| {
                    r["hysteria2"]["cert_key_algorithm"] = json!("ed25519")
                }),
            ),
            (
                "other site",
                printed_by(&prepared, |r| {
                    r["reality"]["target_domain"] = json!("www.example.com")
                }),
            ),
        ];
        for (what, pasted) in cases {
            let error = setup.finish(&pasted, 10).unwrap_err();
            assert!(matches!(error, SetupError::Report(_)), "{what}: {error:?}");
            assert!(setup.waiting(), "{what}: the setup must keep waiting");
        }
        // And the right one still works afterwards.
        assert!(setup.finish(&printed_by(&prepared, |_| {}), 20).is_ok());
    }

    /// A result from a server set up by an earlier script, after that setup ran out and a new one began.
    #[test]
    fn a_result_from_the_previous_script_is_refused_after_a_new_setup_begins() {
        let setup = setup();
        let first = setup.prepare(ServerKind::Amd64, 0).unwrap();
        let from_first = printed_by(&first, |_| {});
        let second = setup.prepare(ServerKind::Amd64, WAIT_S + 1).unwrap();
        assert_ne!(first.script, second.script);
        assert!(matches!(
            setup.finish(&from_first, WAIT_S + 2),
            Err(SetupError::Report(m)) if m.contains("different script")
        ));
        assert!(setup
            .finish(&printed_by(&second, |_| {}), WAIT_S + 3)
            .is_ok());
    }

    #[test]
    fn no_error_repeats_what_was_pasted_or_any_secret() {
        let setup = setup();
        let prepared = setup.prepare(ServerKind::Amd64, 0).unwrap();
        let pasted = printed_by(&prepared, |r| {
            r["hysteria2"]["auth_password"] = json!("SENTINEL-short");
            r["hysteria2"]["server_name"] = json!("SENTINEL.example.net");
            r["surprise-SENTINEL"] = json!(1);
        });
        let shown = format!(
            "{:?} {}",
            setup.finish(&pasted, 1),
            setup.finish(&pasted, 1).unwrap_err()
        );
        assert!(!shown.contains("SENTINEL"), "{shown}");
        assert!(!shown.contains("auth-secret"), "{shown}");
    }
}
