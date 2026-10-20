//! DNet Engine privileged background service (`dnetd`).
//!
//! Runs as LocalSystem. It is the only component permitted to alter routing, DNS, or
//! adapter state (Constitution Principle V).
//!
//! Two entry modes on Windows:
//! - **service** (default): registered with the SCM and started as a Windows service.
//! - **`--console`**: runs the control listener in the foreground for development,
//!   without the SCM. Handy on a dev box; it is not how the product ships.
//!
//! `dnetd` is Windows-only (constitution v1 scope); off Windows it only type-checks.
//!
//! See `specs/001-network-resilience-client/` for the governing specification.

// Reached only through the Windows service entry points today; the Linux entry point
// will use them too. Their unit tests run on every platform.
#[cfg_attr(not(windows), allow(dead_code))]
mod domain;
// Runs the connection engine (T126). The production service attaches it on Windows; off Windows the
// entry point only reports that the service is Windows-only, so the module is exercised by its tests.
#[cfg_attr(not(windows), allow(dead_code))]
mod orchestrator;
// What the network is asked and how each answer is read (T126). Reached through the real effects,
// which are Windows-only; their tests run on every platform.
#[cfg_attr(not(windows), allow(dead_code))]
mod checks;
// Decides what a connection starts; carried out by the real effects (T126).
#[cfg_attr(not(windows), allow(dead_code))]
mod plan;
#[cfg_attr(not(windows), allow(dead_code))]
mod recovery;
#[cfg_attr(not(windows), allow(dead_code))]
mod service_impl;
// Brings one tunnel up and down; used by the real effects (T126).
#[cfg_attr(not(windows), allow(dead_code))]
mod tunnel;

#[cfg(windows)]
mod console;
#[cfg(windows)]
mod effects;
#[cfg(windows)]
mod svc;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    #[cfg(windows)]
    {
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
    let (service, orchestrator) = build_service();
    runtime.block_on(async {
        tokio::select! {
            result = dnet_ipc::server::run_control_listener(service) => {
                if let Err(e) = result {
                    tracing::error!(error = %e, "control listener stopped with an error");
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutdown requested (Ctrl-C)");
            }
        }
        shutdown_orchestrator(orchestrator).await;
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

/// Construct the production service and the handle that stops its tunnel. Shared by both entry
/// modes, and called with a Tokio runtime current.
///
/// Start-up recovery (T038) runs here, first, before the control listener exists and
/// before anything could create a core or adapter. Its outcome gates the service: without a
/// clean recovery, or with a refused configuration, no orchestrator is attached and nothing
/// connects.
#[cfg(windows)]
pub(crate) fn build_service() -> (
    std::sync::Arc<dyn dnet_ipc::service::Service>,
    Option<orchestrator::Handle>,
) {
    let recovery = recovery::recover_installation();
    let service = service_impl::DnetService::production(recovery).with_production_orchestrator();
    let handle = service.orchestrator_handle();
    (std::sync::Arc::new(service), handle)
}
