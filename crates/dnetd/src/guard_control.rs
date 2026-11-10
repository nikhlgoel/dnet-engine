//! T161 — the one door between the service and the firewall guard (ADR-0006 §5a).
//!
//! The service decides *when* the guard is in (the person's choice, a tunnel that is up); the operating system
//! side lives in `dnet_netstate::guard_engine`. This trait is the seam between them, so the decisions are
//! tested against a fake and the real firewall is only touched by the Windows implementation, which the lab VM
//! has run (`testing/vm`).
//!
//! `release` is the way out and is written to need nothing else to work: not the person's choice, not the
//! journal, not a readable filter (conditions 3 and 4 of §5a).

use dnet_core::guard::GuardPlan;

/// Put the guard in, take it out, and ask whether it is in.
pub trait GuardControl: Send + Sync + 'static {
    /// Put the guard in for `plan`, all or nothing, and say how many rules the firewall now holds. The firewall's
    /// contents are read back and compared with the plan before this returns `Ok`; a guard that is not the one
    /// asked for is taken out again.
    fn engage(&self, plan: &GuardPlan) -> Result<usize, String>;

    /// Take the guard out: every rule, the sublayer and the provider. Nothing there is not an error.
    fn release(&self) -> Result<(), String>;

    /// Whether the guard's provider is in the firewall now.
    fn is_in(&self) -> Result<bool, String>;
}

/// What the connection engine needs to honour the person's kill-switch choice: the choice itself, shared with the
/// service that changes it, and the door to the firewall.
#[derive(Clone)]
pub struct GuardWiring {
    pub switch: std::sync::Arc<crate::killswitch::KillSwitch>,
    pub control: std::sync::Arc<dyn GuardControl>,
}

/// The account both programs run as: the service is started by the system and starts the transport core itself, so
/// the core inherits it. The model accepts only one specific identifier, never a group.
const SYSTEM_ACCOUNT: &str = "S-1-5-18";

/// The plan for the guard around one tunnel: everything in it is something the service already knows. Nothing is
/// checked here; `Guard::build` refuses a plan that names the same program twice, a path that is not a local full
/// path, a missing adapter or port, and anything that would leak.
#[cfg_attr(not(windows), allow(dead_code))] // Called by the Windows effects; tested everywhere.
pub fn plan_for(
    core: &std::path::Path,
    service: &std::path::Path,
    control_port: u16,
    tunnel_luid: u64,
) -> GuardPlan {
    GuardPlan {
        tunnel: dnet_core::ids::InterfaceId::new(tunnel_luid),
        core_program: core.to_string_lossy().into_owned(),
        core_user: SYSTEM_ACCOUNT.to_owned(),
        service_program: service.to_string_lossy().into_owned(),
        service_user: SYSTEM_ACCOUNT.to_owned(),
        control_port,
        local_ranges: dnet_core::guard::local_ranges(),
    }
}

/// What the kill switch means for the connection about to be made.
#[cfg_attr(not(windows), allow(dead_code))] // Called by the Windows effects; tested everywhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Coverage {
    /// The person has not asked for it: nothing is put in.
    NotWanted,
    /// Put the guard in once the tunnel is up; the service's permit is to this loopback port of the core.
    Wanted { control_port: u16 },
    /// Asked for, but this connection cannot be covered. The connection is not made, with these words: a
    /// connection without the protection that was asked for is not what the person chose.
    CannotCover(String),
}

/// Decide, from the person's choice and what the connection is, whether and how the guard goes in.
///
/// An AmneziaWG connection has its own adapter and its own program, which the guard's single transport-program
/// permit does not describe yet; a connection with no control port has no loopback permit to write. Both are
/// refused plainly rather than covered wrongly.
#[cfg_attr(not(windows), allow(dead_code))] // Called by the Windows effects; tested everywhere.
pub fn coverage(enabled: bool, amneziawg: bool, control_port: Option<u16>) -> Coverage {
    if !enabled {
        return Coverage::NotWanted;
    }
    if amneziawg {
        return Coverage::CannotCover(
            "the kill switch cannot cover this connection method yet; turn the kill switch off or choose another method"
                .to_owned(),
        );
    }
    match control_port {
        Some(control_port) if control_port != 0 => Coverage::Wanted { control_port },
        _ => Coverage::CannotCover(
            "the kill switch cannot cover this connection yet (it has no control port); turn the kill switch off"
                .to_owned(),
        ),
    }
}

#[cfg(windows)]
pub use real::WindowsGuard;

#[cfg(windows)]
mod real {
    use std::sync::Arc;

    use dnet_netstate::guard_engine::{install_guard, Engine};
    use dnet_netstate::undo::{UndoRecord, UndoRegistry};
    use dnet_netstate::win_route::WindowsUndoExecutor;

    use super::{GuardControl, GuardPlan};

    /// The guard in the Windows firewall, with its undo record kept in the service's journal.
    pub struct WindowsGuard {
        undo: Arc<UndoRegistry>,
    }

    impl WindowsGuard {
        pub fn new(undo: Arc<UndoRegistry>) -> Self {
            Self { undo }
        }
    }

    impl GuardControl for WindowsGuard {
        fn engage(&self, plan: &GuardPlan) -> Result<usize, String> {
            install_guard(&self.undo, plan).map_err(|e| e.to_string())
        }

        fn release(&self) -> Result<(), String> {
            // The journal's record first, so it does not stay behind to be replayed; a failure there is only noted.
            for entry in self.undo.outstanding() {
                if matches!(entry.record, UndoRecord::GuardFilters { .. }) {
                    if let Err(error) = self.undo.undo(entry.id, &WindowsUndoExecutor) {
                        tracing::warn!(%error, "the guard's undo record could not be run; removing the guard directly");
                    }
                }
            }
            // And then the removal itself, by the provider's key, whatever the journal said: this is the
            // outcome that is reported.
            Engine::open()
                .and_then(|engine| engine.remove_all())
                .map_err(|e| e.to_string())
        }

        fn is_in(&self) -> Result<bool, String> {
            Engine::open()
                .and_then(|engine| engine.is_installed())
                .map_err(|e| e.to_string())
        }
    }
}

/// A guard that only records what it was asked, for the tests of the decisions around it.
#[cfg(test)]
pub mod fake {
    use std::sync::Mutex;

    use super::{GuardControl, GuardPlan};

    #[derive(Default)]
    pub struct FakeGuard {
        pub calls: Mutex<Vec<String>>,
        pub is_in: Mutex<bool>,
        pub fail_engage: Mutex<Option<String>>,
        pub fail_release: Mutex<Option<String>>,
        pub plans: Mutex<Vec<GuardPlan>>,
    }

    impl FakeGuard {
        pub fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl GuardControl for FakeGuard {
        fn engage(&self, plan: &GuardPlan) -> Result<usize, String> {
            self.calls.lock().unwrap().push("engage".into());
            if let Some(why) = self.fail_engage.lock().unwrap().clone() {
                return Err(why);
            }
            self.plans.lock().unwrap().push(plan.clone());
            *self.is_in.lock().unwrap() = true;
            Ok(48)
        }

        fn release(&self) -> Result<(), String> {
            self.calls.lock().unwrap().push("release".into());
            if let Some(why) = self.fail_release.lock().unwrap().clone() {
                return Err(why);
            }
            *self.is_in.lock().unwrap() = false;
            Ok(())
        }

        fn is_in(&self) -> Result<bool, String> {
            Ok(*self.is_in.lock().unwrap())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use dnet_core::guard::{Guard, GuardError};

    use super::*;

    fn installed() -> GuardPlan {
        plan_for(
            Path::new(r"C:\Program Files\DNet Engine\primary-core.exe"),
            Path::new(r"C:\Program Files\DNet Engine\dnetd.exe"),
            34_567,
            0x0006_0000_0000_0001,
        )
    }

    #[test]
    fn the_plan_for_the_installed_layout_makes_a_guard() {
        let guard = Guard::build(&installed()).expect("the installed layout is a sound plan");
        assert!(!guard.filters().is_empty());
    }

    #[test]
    fn the_programs_run_as_the_system_account_and_the_local_list_is_the_built_in_one() {
        let plan = installed();
        assert_eq!(plan.core_user, "S-1-5-18");
        assert_eq!(plan.service_user, "S-1-5-18");
        assert_eq!(plan.local_ranges, dnet_core::guard::local_ranges());
        assert_eq!(plan.control_port, 34_567);
        assert_eq!(plan.tunnel.luid(), 0x0006_0000_0000_0001);
    }

    #[test]
    fn a_missing_tunnel_a_missing_port_or_one_program_twice_is_refused_by_the_model() {
        let mut no_tunnel = installed();
        no_tunnel.tunnel = dnet_core::ids::InterfaceId::new(0);
        assert!(matches!(
            Guard::build(&no_tunnel),
            Err(GuardError::NoTunnel)
        ));

        let mut no_port = installed();
        no_port.control_port = 0;
        assert!(matches!(Guard::build(&no_port), Err(GuardError::NoPort)));

        let same = plan_for(
            Path::new(r"C:\Program Files\DNet Engine\dnetd.exe"),
            Path::new(r"C:\Program Files\DNet Engine\dnetd.exe"),
            34_567,
            1,
        );
        assert!(matches!(Guard::build(&same), Err(GuardError::SameProgram)));
    }

    #[test]
    fn a_path_that_is_not_a_full_local_path_is_refused_by_the_model() {
        let relative = plan_for(
            Path::new("primary-core.exe"),
            Path::new(r"C:\Program Files\DNet Engine\dnetd.exe"),
            34_567,
            1,
        );
        assert!(matches!(
            Guard::build(&relative),
            Err(GuardError::NotAFullPath(_))
        ));
        let share = plan_for(
            Path::new(r"\\server\share\primary-core.exe"),
            Path::new(r"C:\Program Files\DNet Engine\dnetd.exe"),
            34_567,
            1,
        );
        assert!(matches!(
            Guard::build(&share),
            Err(GuardError::NotAFullPath(_))
        ));
    }

    #[test]
    fn nothing_is_put_in_unless_the_person_asked() {
        for (awg, port) in [(false, Some(1)), (true, Some(1)), (false, None)] {
            assert_eq!(coverage(false, awg, port), Coverage::NotWanted);
        }
    }

    #[test]
    fn a_covered_connection_names_the_control_port() {
        assert_eq!(
            coverage(true, false, Some(34_567)),
            Coverage::Wanted {
                control_port: 34_567
            }
        );
    }

    #[test]
    fn a_connection_that_cannot_be_covered_is_refused_in_plain_words() {
        for (awg, port) in [(true, Some(34_567)), (false, None), (false, Some(0))] {
            match coverage(true, awg, port) {
                Coverage::CannotCover(why) => {
                    assert!(why.contains("kill switch"), "{why}");
                    assert!(why.contains("turn the kill switch off"), "{why}");
                }
                other => panic!("{awg} {port:?}: {other:?}"),
            }
        }
    }
}
