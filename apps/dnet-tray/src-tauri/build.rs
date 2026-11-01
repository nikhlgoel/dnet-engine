//! The window may give these commands and no others (ADR-0007 R4). Declaring them here makes each one a
//! permission the capability file must grant by name, so a command added to `main.rs` and forgotten here is
//! refused by the framework instead of being quietly available to the web view.

const COMMANDS: &[&str] = &[
    "capabilities",
    "snapshot",
    "activity_backlog",
    "stabilize",
    "list_endpoints",
    "add_endpoint",
    "remove_endpoint",
    "prepare_server",
    "finish_server",
    "set_endpoint_enabled",
    "list_profiles",
    "set_brutal",
    "list_rules",
    "add_rule",
    "remove_rule",
    "list_pending",
    "reject_change",
    "approve_change",
    "set_encrypted_dns",
    "check_updates",
    "open_login_page",
];

fn main() {
    let attributes = tauri_build::Attributes::new()
        .app_manifest(tauri_build::AppManifest::new().commands(COMMANDS));
    tauri_build::try_build(attributes).expect("could not generate the application's permissions");
}
