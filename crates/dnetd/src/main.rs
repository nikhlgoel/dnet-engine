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

mod domain;
mod service_impl;

#[cfg(windows)]
mod console;
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
    runtime.block_on(async {
        let service = build_service();
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
    });
    Ok(())
}

/// Construct the production service. Shared by both entry modes.
#[cfg(windows)]
fn build_service() -> std::sync::Arc<dyn dnet_ipc::service::Service> {
    std::sync::Arc::new(service_impl::DnetService::production())
}
