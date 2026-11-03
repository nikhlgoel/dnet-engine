//! T114 — `dnetd install`, `dnetd uninstall` and `dnetd stop`: the service registers and removes itself,
//! so any installer (or a person, by hand) needs only to copy the files and call these.
//!
//! - **`install`** refuses unless the programs it would run as SYSTEM are out of reach of ordinary
//!   users (the same check the service makes before connecting) and the primary core sits beside it.
//!   It makes `%PROGRAMDATA%\DNet Engine` and its `run` and `state` directories private to SYSTEM and
//!   Administrators, refusing one someone else owns. It then registers (or, on an upgrade,
//!   re-registers) `DNetEngine` as an automatic LocalSystem service that waits for the network stack and
//!   is restarted by the SCM if it fails, and starts it.
//! - **`uninstall`** stops the service, which takes any tunnel down; restores anything a stop left
//!   (the same recovery the service runs at start); and only then deletes the service. If the network
//!   cannot be restored the service stays installed, so its next start can try again: nobody would
//!   restore it after the service is gone. `--remove-settings` also deletes the saved settings and
//!   endpoint credentials.
//! - **`stop`** stops the service and waits, for an upgrade to replace the files.
//!
//! Each prints one line per step and exits non-zero on the first failure, for an installer's log.

/// What `dnetd` was asked to do from the command line, when it is not being started as the service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admin {
    Install,
    Uninstall { remove_settings: bool },
    Stop,
}

/// The administrative command in `args` (without the program name), `None` for an ordinary start (by
/// the SCM, or `--console`), or why the words are not a command.
#[cfg_attr(not(windows), allow(dead_code))] // Windows reads it at start; the tests run everywhere.
pub fn admin_command(args: &[String]) -> Option<Result<Admin, String>> {
    let (first, rest) = args.split_first()?;
    let command = match first.as_str() {
        "install" => Admin::Install,
        "uninstall" => Admin::Uninstall {
            remove_settings: false,
        },
        "stop" => Admin::Stop,
        _ => return None,
    };
    Some(match (command, rest) {
        (_, []) => Ok(command),
        (Admin::Uninstall { .. }, [flag]) if flag == "--remove-settings" => Ok(Admin::Uninstall {
            remove_settings: true,
        }),
        _ => Err(format!(
            "`dnetd {first}` takes no other words{}",
            if first == "uninstall" {
                " except --remove-settings"
            } else {
                ""
            }
        )),
    })
}

#[cfg(windows)]
pub use windows_impl::run;

#[cfg(windows)]
mod windows_impl {
    use std::ffi::OsString;
    use std::path::Path;
    use std::time::{Duration, Instant};

    use anyhow::{anyhow, bail, Context};
    use dnet_config::persist::default_config_path;
    use dnet_config::write::{default_run_dir, prepare_private_dir};
    use windows_service::service::{
        Service, ServiceAccess, ServiceAction, ServiceActionType, ServiceDependency,
        ServiceErrorControl, ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo,
        ServiceStartType, ServiceState, ServiceType,
    };
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};

    use super::Admin;
    use crate::effects::{programs_of, Layout};
    use crate::svc::SERVICE_NAME;

    const DISPLAY_NAME: &str = "DNet Engine";
    const DESCRIPTION: &str =
        "Keeps this computer's connection working on restrictive and unreliable networks.";

    const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
    const ERROR_SERVICE_NOT_ACTIVE: i32 = 1062;

    /// How long a start may take to report Running.
    const START_WAIT: Duration = Duration::from_secs(30);

    pub fn run(command: Admin) -> anyhow::Result<()> {
        match command {
            Admin::Install => install(),
            Admin::Uninstall { remove_settings } => uninstall(remove_settings),
            Admin::Stop => match open(ServiceAccess::QUERY_STATUS | ServiceAccess::STOP)? {
                Some(service) => stop_and_wait(&service),
                None => {
                    println!("the service is not installed; nothing to stop");
                    Ok(())
                }
            },
        }
    }

    fn install() -> anyhow::Result<()> {
        let exe = std::env::current_exe().context("the service cannot find its own path")?;
        let layout = Layout::installed().context("the service cannot find its own directory")?;
        if !layout.primary_core.is_file() {
            bail!(
                "{} is missing; the package is incomplete",
                layout.primary_core.display()
            );
        }
        // A service runs as SYSTEM: registering one that an ordinary user could replace would hand
        // that user SYSTEM. The service refuses to connect from such a folder; refuse to install there.
        dnet_config::install_trust::verify_programs(&programs_of(&layout)).map_err(|problem| {
            anyhow!("refusing to install where ordinary users could change the programs ({problem}); install into a folder only administrators can change")
        })?;
        println!("installation folder: only administrators can change it");

        let run = default_run_dir();
        let base = run
            .parent()
            .ok_or_else(|| anyhow!("the data folder has no parent"))?
            .to_path_buf();
        let state = default_config_path()
            .parent()
            .ok_or_else(|| anyhow!("the settings folder has no parent"))?
            .to_path_buf();
        // The base first: its owner decides who could later rewrite what is inside it.
        for dir in [&base, &run, &state] {
            prepare_private_dir(dir).with_context(|| {
                format!(
                    "{} could not be made private to SYSTEM and Administrators",
                    dir.display()
                )
            })?;
        }
        println!(
            "data folder: {} (SYSTEM and Administrators only)",
            base.display()
        );

        let manager = ServiceManager::local_computer(
            None::<&str>,
            ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
        )
        .context("the Service Control Manager refused; run this from an elevated prompt")?;
        let info = ServiceInfo {
            name: OsString::from(SERVICE_NAME),
            display_name: OsString::from(DISPLAY_NAME),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::AutoStart,
            error_control: ServiceErrorControl::Normal,
            executable_path: exe,
            launch_arguments: vec![],
            // Start-up recovery restores routes and name servers through the network stack, so it
            // must be up first; a recovery that failed for want of it would keep the service from
            // connecting until the next restart.
            dependencies: vec![
                ServiceDependency::Service(OsString::from("Nsi")),
                ServiceDependency::Service(OsString::from("Tcpip")),
            ],
            account_name: None, // LocalSystem
            account_password: None,
        };
        let access = ServiceAccess::QUERY_STATUS
            | ServiceAccess::START
            | ServiceAccess::STOP
            | ServiceAccess::CHANGE_CONFIG;
        let service = match manager.open_service(SERVICE_NAME, access) {
            Ok(service) => {
                service
                    .change_config(&info)
                    .context("the existing service could not be updated")?;
                println!("service: updated");
                service
            }
            Err(error) if os_error(&error) == Some(ERROR_SERVICE_DOES_NOT_EXIST) => {
                let service = manager
                    .create_service(&info, access)
                    .context("the service could not be registered")?;
                println!("service: registered");
                service
            }
            Err(error) => return Err(error).context("the service could not be opened"),
        };
        service.set_description(DESCRIPTION)?;
        // A crash restarts it (and its start-up recovery restores the network, then resumes the
        // connection the person left on); three failures in a day stop the retries.
        service.update_failure_actions(ServiceFailureActions {
            reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(24 * 60 * 60)),
            reboot_msg: None,
            command: None,
            actions: Some(
                [5, 30, 60]
                    .into_iter()
                    .map(|seconds| ServiceAction {
                        action_type: ServiceActionType::Restart,
                        delay: Duration::from_secs(seconds),
                    })
                    .collect(),
            ),
        })?;
        service.set_failure_actions_on_non_crash_failures(true)?;
        println!("service: restarts on failure (5 s, 30 s, 60 s)");

        if service.query_status()?.current_state != ServiceState::Running {
            service
                .start::<&str>(&[])
                .context("the service could not be started")?;
        }
        wait_for(&service, ServiceState::Running, START_WAIT)?;
        println!("service: running");
        Ok(())
    }

    fn uninstall(remove_settings: bool) -> anyhow::Result<()> {
        match open(ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE)? {
            None => println!("service: not installed"),
            Some(service) => {
                stop_and_wait(&service)?;
                // Whatever a stop could not undo (one that ran out of time, an earlier crash) is undone
                // now, while nothing is running and before the only thing that would undo it is gone.
                crate::recovery::recover_installation().map_err(|error| {
                    anyhow!("the network changes could not all be restored ({error}); the service is left installed so its next start can try again")
                })?;
                println!("network: restored");
                service
                    .delete()
                    .context("the service could not be removed")?;
                println!("service: removed");
            }
        }
        if remove_settings {
            remove_data_folder()?;
        }
        Ok(())
    }

    fn open(access: ServiceAccess) -> anyhow::Result<Option<Service>> {
        let manager =
            ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
                .context("the Service Control Manager refused; run this from an elevated prompt")?;
        match manager.open_service(SERVICE_NAME, access) {
            Ok(service) => Ok(Some(service)),
            Err(error) if os_error(&error) == Some(ERROR_SERVICE_DOES_NOT_EXIST) => Ok(None),
            Err(error) => Err(error).context("the service could not be opened"),
        }
    }

    /// Stop the service and wait until it has: it takes the tunnel down first, which may take up to
    /// the service's own shutdown allowance.
    fn stop_and_wait(service: &Service) -> anyhow::Result<()> {
        if service.query_status()?.current_state == ServiceState::Stopped {
            println!("service: already stopped");
            return Ok(());
        }
        match service.stop() {
            Ok(_) => {}
            Err(error) if os_error(&error) == Some(ERROR_SERVICE_NOT_ACTIVE) => {}
            Err(error) => return Err(error).context("the service could not be stopped"),
        }
        wait_for(
            service,
            ServiceState::Stopped,
            crate::SHUTDOWN_WAIT + Duration::from_secs(30),
        )?;
        println!("service: stopped");
        Ok(())
    }

    fn wait_for(service: &Service, want: ServiceState, limit: Duration) -> anyhow::Result<()> {
        let started = Instant::now();
        loop {
            let state = service.query_status()?.current_state;
            if state == want {
                return Ok(());
            }
            if started.elapsed() > limit {
                bail!(
                    "the service did not reach {want:?} within {} s (it is {state:?})",
                    limit.as_secs()
                );
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }

    /// Delete `%PROGRAMDATA%\DNet Engine`, only if it is a real directory owned by SYSTEM or
    /// Administrators. Never through a link: removal by an administrator must not be steerable by
    /// whoever could have planted one.
    fn remove_data_folder() -> anyhow::Result<()> {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

        let run = default_run_dir();
        let Some(base) = run.parent() else {
            bail!("the data folder has no parent");
        };
        let meta = match std::fs::symlink_metadata(base) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                println!("settings: none to remove");
                return Ok(());
            }
            Err(error) => return Err(error).context("the data folder could not be examined"),
        };
        if !meta.is_dir() || meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            bail!("{} is not a plain folder; left as it is", base.display());
        }
        if !owned_by_system_or_administrators(base)? {
            bail!(
                "{} is not owned by SYSTEM or Administrators; left as it is",
                base.display()
            );
        }
        std::fs::remove_dir_all(base)
            .with_context(|| format!("{} could not be removed", base.display()))?;
        println!("settings: removed {}", base.display());
        Ok(())
    }

    fn owned_by_system_or_administrators(dir: &Path) -> anyhow::Result<bool> {
        let sddl = dnet_config::write::win::read_owner_and_dacl_sddl(dir)?;
        Ok(sddl.starts_with("O:SY") || sddl.starts_with("O:BA"))
    }

    fn os_error(error: &windows_service::Error) -> Option<i32> {
        match error {
            windows_service::Error::Winapi(io) => io.raw_os_error(),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(words: &[&str]) -> Option<Result<Admin, String>> {
        admin_command(&words.iter().map(|w| w.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn the_three_commands_are_recognised() {
        assert_eq!(parse(&["install"]), Some(Ok(Admin::Install)));
        assert_eq!(parse(&["stop"]), Some(Ok(Admin::Stop)));
        assert_eq!(
            parse(&["uninstall"]),
            Some(Ok(Admin::Uninstall {
                remove_settings: false
            }))
        );
        assert_eq!(
            parse(&["uninstall", "--remove-settings"]),
            Some(Ok(Admin::Uninstall {
                remove_settings: true
            }))
        );
    }

    /// The SCM starts the service with no words; development runs use flags. Neither is a command.
    #[test]
    fn an_ordinary_start_is_not_a_command() {
        assert_eq!(parse(&[]), None);
        assert_eq!(parse(&["--console"]), None);
        assert_eq!(
            parse(&["--console", "--allow-untrusted-install", "install"]),
            None
        );
    }

    /// A word too many is refused rather than ignored: `install --remove-settings` must not install.
    #[test]
    fn extra_words_are_refused() {
        for words in [
            &["install", "--remove-settings"][..],
            &["install", "now"],
            &["stop", "--force"],
            &["uninstall", "--remove-setting"],
            &["uninstall", "--remove-settings", "--remove-settings"],
        ] {
            assert!(matches!(parse(words), Some(Err(_))), "{words:?}");
        }
    }
}
