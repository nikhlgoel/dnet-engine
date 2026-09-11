//! Windows Service (SCM) lifecycle.
//!
//! Registers `dnetd` with the Service Control Manager, reports Running, runs the
//! control listener, and stops cleanly on a Stop/Shutdown control. This path only runs
//! when the binary is started by the SCM as an installed service; for development use
//! `dnetd --console`, which shares the same listener.
//!
//! This code cannot be exercised in CI (it requires an installed service and the SCM),
//! so it is kept deliberately thin — all real logic lives in the listener and the
//! service implementation, which are tested directly.

#![cfg(windows)]

use std::ffi::OsString;
use std::time::Duration;

use windows_service::service::{
    ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::{define_windows_service, service_dispatcher};

/// The registered service name.
pub const SERVICE_NAME: &str = "DNetEngine";

const SERVICE_TYPE: ServiceType = ServiceType::OWN_PROCESS;

define_windows_service!(ffi_service_main, service_main);

/// Hand control to the SCM, which calls back into `service_main`.
pub fn run_as_service() -> anyhow::Result<()> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
        .map_err(|e| anyhow::anyhow!("failed to start the service dispatcher: {e}"))
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = run() {
        tracing::error!(error = %e, "dnetd service exited with an error");
    }
}

fn run() -> anyhow::Result<()> {
    // The SCM control handler runs on its own OS thread. It signals shutdown over an
    // unbounded channel whose send is callable synchronously from that thread.
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::unbounded_channel::<()>();

    let handler = move |control| match control {
        ServiceControl::Stop | ServiceControl::Shutdown => {
            let _ = shutdown_tx.send(());
            ServiceControlHandlerResult::NoError
        }
        ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
        _ => ServiceControlHandlerResult::NotImplemented,
    };

    let status_handle = service_control_handler::register(SERVICE_NAME, handler)
        .map_err(|e| anyhow::anyhow!("failed to register the service control handler: {e}"))?;

    let report = |state: ServiceState, accept: ServiceControlAccept| -> anyhow::Result<()> {
        status_handle
            .set_service_status(ServiceStatus {
                service_type: SERVICE_TYPE,
                current_state: state,
                controls_accepted: accept,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::from_secs(5),
                process_id: None,
            })
            .map_err(|e| anyhow::anyhow!("failed to set service status: {e}"))
    };

    report(ServiceState::Running, ServiceControlAccept::STOP)?;
    tracing::info!("dnetd running as a Windows service");

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        let service = crate::build_service();
        tokio::select! {
            result = dnet_ipc::server::run_control_listener(service) => {
                if let Err(e) = result {
                    tracing::error!(error = %e, "control listener stopped with an error");
                }
            }
            _ = shutdown_rx.recv() => {
                tracing::info!("stop requested by the SCM");
            }
        }
    });

    report(ServiceState::Stopped, ServiceControlAccept::empty())?;
    Ok(())
}
