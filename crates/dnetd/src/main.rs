//! DNet Engine privileged background service (`dnetd`).
//!
//! Runs as LocalSystem. It is the only component permitted to alter routing, DNS, or
//! adapter state (Constitution Principle V).
//!
//! Two entry modes on Windows:
//! - **service** (default): registered with the SCM and started as a Windows service.
//! - **`--console`**: runs the control listener in the foreground for development,
//!   without the SCM. Handy on a dev box; it is not how the product ships.
//! - **`--allow-untrusted-install`** (development, only with `--console`): do not require the
//!   programs run as SYSTEM to be out of reach of ordinary users. Without it, a service installed
//!   where a user could replace a program refuses to connect.
//! - **`install`**, **`uninstall [--remove-settings]`**, **`stop`**: register, remove or stop the
//!   service, from an elevated prompt or an installer (T114, see `install`).
//! - **`--no-path-watch`** (development): do not watch the network or probe any path. A test run
//!   uses it so that it never sends a probe to the network it happens to run on.
//!
//! `dnetd` is Windows-only (constitution v1 scope); off Windows it only type-checks.
//!
//! See `specs/001-network-resilience-client/` for the governing specification.

// Reached only through the Windows service entry points today; the Linux entry point
// will use them too. Their unit tests run on every platform.
// What a person can safely hand over to explain a failure (T112); reached through the service.
#[cfg_attr(not(windows), allow(dead_code))]
mod approval;
// What the Registry is told about each part (T170 step 2). Built and tested; the service does not call it
// yet (the next step wires it to GetComponents), so it is unused on every platform until then.
#[allow(dead_code)]
mod components;
#[cfg_attr(not(windows), allow(dead_code))]
mod configure;
mod devices;
mod diagnostics;
#[cfg_attr(not(windows), allow(dead_code))]
mod domain;
// `dnetd install`, `uninstall` and `stop` (T114); the words are read on every platform.
mod install;
mod intent;
// The person's kill-switch choice, remembered (T161).
#[cfg_attr(not(windows), allow(dead_code))]
mod killswitch;
// The one door to the firewall guard, and a fake of it for the tests (T161).
#[cfg_attr(not(windows), allow(dead_code))]
mod guard_control;
// Setting up the person's own server from the window (T150).
#[cfg_attr(not(windows), allow(dead_code))]
mod server_setup;
// Tries again while the person has left it on (T148); started by the Windows service.
#[cfg_attr(not(windows), allow(dead_code))]
mod keep_trying;
// Runs the connection engine (T126). The production service attaches it on Windows; off Windows the
// entry point only reports that the service is Windows-only, so the module is exercised by its tests.
#[cfg_attr(not(windows), allow(dead_code))]
mod netwatch;
#[cfg_attr(not(windows), allow(dead_code))]
mod orchestrator;
mod telemetry;
// What the network is asked and how each answer is read (T126). Reached through the real effects,
// which are Windows-only; their tests run on every platform.
#[cfg_attr(not(windows), allow(dead_code))]
mod checks;
// Decides what a connection starts; carried out by the real effects (T126).
#[cfg_attr(not(windows), allow(dead_code))]
mod plan;
// The profile feed held by the service (T066a): restore, offer, apply.
#[cfg_attr(not(windows), allow(dead_code))]
mod feed_service;
// Fetches the signed profile feed on a schedule and when asked (T066b).
#[cfg_attr(not(windows), allow(dead_code))]
mod feed_fetch;
// The trust anchor compiled into this build (empty until the key ceremony, T066d).
#[cfg_attr(not(windows), allow(dead_code))]
mod feed_trust;
// Feed step 8: a trial configuration for every profile before a feed is kept.
#[cfg_attr(not(windows), allow(dead_code))]
mod feed_trial;
// Asks the network whether a captive portal is in the way (T077); used by the real effects.
#[cfg_attr(not(windows), allow(dead_code))]
mod listener;
#[cfg_attr(not(windows), allow(dead_code))]
mod portal_probe;
#[cfg_attr(not(windows), allow(dead_code))]
mod recovery;
#[cfg_attr(not(windows), allow(dead_code))]
mod resume;
#[cfg_attr(not(windows), allow(dead_code))]
mod service_impl;
#[cfg(test)]
mod session_e2e;
mod session_switch;
// Brings one tunnel up and down; used by the real effects (T126).
#[cfg_attr(not(windows), allow(dead_code))]
mod tunnel;

#[cfg(windows)]
mod console;
#[cfg(windows)]
mod effects;
#[cfg(windows)]
mod svc;
#[cfg(windows)]
mod winwatch;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    #[cfg(windows)]
    {
        let args: Vec<String> = std::env::args().skip(1).collect();
        if let Some(command) = install::admin_command(&args) {
            return install::run(command.map_err(|why| anyhow::anyhow!(why))?);
        }
        if std::env::args().any(|a| a == "--console") {
            run_console()
        } else {
            svc::run_as_service()
        }
    }
    #[cfg(not(windows))]
    {
        anyhow::bail!("dnetd is a Windows-only service")
    }
}

/// Run the control listener in the foreground until Ctrl-C.
#[cfg(windows)]
fn run_console() -> anyhow::Result<()> {
    tracing::info!("dnetd starting in console mode");
    let runtime = tokio::runtime::Runtime::new()?;
    // The orchestrator spawns its tasks when the service is built, so a runtime must be current.
    let _entered = runtime.enter();
    let service = build_service();
    runtime.block_on(async {
        tokio::select! {
            result = dnet_ipc::server::run_control_listener(listening(&service)) => {
                if let Err(e) = result {
                    tracing::error!(error = %e, "control listener stopped with an error");
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutdown requested (Ctrl-C)");
            }
        }
        // The orchestrator in use now, not the one the service started with: a configuration change
        // replaces it, and stopping the retired one would leave the live tunnel up.
        shutdown_orchestrator(service.orchestrator_handle()).await;
    });
    Ok(())
}

/// How long stopping the service may wait for the tunnel to come down.
#[cfg(windows)]
pub(crate) const SHUTDOWN_WAIT: std::time::Duration = std::time::Duration::from_secs(90);

/// Take the tunnel down before the process goes (SUP-04): a service that stopped with a core
/// running and a route installed would leave the machine without a working network.
#[cfg(windows)]
pub(crate) async fn shutdown_orchestrator(handle: Option<orchestrator::Handle>) {
    let Some(handle) = handle else { return };
    if tokio::time::timeout(SHUTDOWN_WAIT, handle.shutdown())
        .await
        .is_err()
    {
        tracing::error!(
            "the tunnel did not come down in time; the next start will restore what it left"
        );
    }
}

/// Construct the production service. Shared by both entry modes, and called with a Tokio runtime
/// current. To stop its tunnel, ask the service for its orchestrator *when stopping*
/// (`DnetService::orchestrator_handle`): a configuration change replaces the orchestrator, so a handle
/// taken at start-up would stop the wrong one.
///
/// Start-up recovery (T038) runs here, first, before the control listener exists and
/// before anything could create a core or adapter. Its outcome gates the service: without a
/// clean recovery, or with a refused configuration, no orchestrator is attached and nothing
/// connects.
#[cfg(windows)]
pub(crate) fn build_service() -> std::sync::Arc<service_impl::DnetService> {
    let recovery = recovery::recover_installation();
    let service = service_impl::DnetService::production(recovery).with_production_orchestrator();
    // Left on before this start (a reboot, an update, a crash): connect again (T147). Only after
    // recovery, and only through an orchestrator that recovery allowed to exist.
    service.resume_if_left_on();
    let service = std::sync::Arc::new(service);
    // Record what each part of the connection is doing, once a second, so the parts' ages are true (T170).
    service.keep_components_current();
    // And keep trying while it is left on and down (T148): on a timer, and sooner when the network
    // changes. The change registration lives as long as the retries do.
    match dnet_netstate::notify::ChangeSource::start() {
        Ok((source, changes)) => {
            let retries = service.keep_trying(Some(changes));
            tokio::spawn(async move {
                let _ = retries.await;
                drop(source);
            });
        }
        Err(error) => {
            tracing::warn!(%error, "network changes cannot be watched; a failed connection is retried on a timer only");
            service.keep_trying(None);
        }
    }
    service
}

/// The service as the control listener takes it.
#[cfg(windows)]
pub(crate) fn listening(
    service: &std::sync::Arc<service_impl::DnetService>,
) -> std::sync::Arc<dyn dnet_ipc::service::Service> {
    std::sync::Arc::clone(service) as std::sync::Arc<dyn dnet_ipc::service::Service>
}
