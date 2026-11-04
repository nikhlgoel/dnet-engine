//! T100, T101 — the tray, the window's life, and the commands (ADR-0007 R1, R2, R4).
//!
//! Everything that decides something is in `dnet-view`; this is the part that touches the operating system.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dnet_ipc::client::Trust;
use dnet_view::events::{follow, Ended};
use dnet_view::link::PipeLink;
use dnet_view::session::{poll_interval, Backlog, Grace, GRACE};
use dnet_view::tray::{self, Control, TrayText};
use dnet_view::Bridge;
use serde_json::Value;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{TrayIcon, TrayIconBuilder};
use tauri::webview::PageLoadEvent;
use tauri::{
    AppHandle, Emitter, Manager, RunEvent, State, WebviewUrl, WebviewWindowBuilder, WindowEvent,
    Wry,
};

/// The one window's label.
const WINDOW: &str = "main";

/// What the tray menu is made of, kept so its text can change as the state does.
struct TrayParts {
    icon: TrayIcon<Wry>,
    state: MenuItem<Wry>,
    control: MenuItem<Wry>,
}

/// Everything the tray, the window and the commands share.
struct Shell {
    link: Arc<PipeLink>,
    bridge: Bridge<Arc<PipeLink>>,
    /// What the service reported this session, for a window that opens late, and the latest reason.
    backlog: Mutex<Backlog>,
    /// When the web view is let go after the window closes (R2).
    grace: Mutex<Grace>,
    /// Whether the window is on screen. Nothing is sent to it while it is not.
    visible: AtomicBool,
    /// The page has drawn its own title bar. The window has no system frame, so if this does not become true soon
    /// after the window is made, the frame is given back (a page that failed to start must not leave a window that
    /// cannot be moved or closed).
    page_ready: AtomicBool,
    /// Wakes the state loop early: the service said something, or the person asked for something.
    wake: tokio::sync::Notify,
    tray: Mutex<Option<TrayParts>>,
    /// The menu as last drawn, so it is only touched when it changes.
    text: Mutex<Option<TrayText>>,
}

impl Shell {
    fn new(link: Arc<PipeLink>) -> Self {
        Self {
            bridge: Bridge::new(link.clone()),
            link,
            backlog: Mutex::new(Backlog::new()),
            grace: Mutex::new(Grace::new()),
            visible: AtomicBool::new(false),
            page_ready: AtomicBool::new(false),
            wake: tokio::sync::Notify::new(),
            tray: Mutex::new(None),
            text: Mutex::new(None),
        }
    }

    fn last_because(&self) -> Option<String> {
        self.backlog
            .lock()
            .unwrap()
            .last_because()
            .map(str::to_owned)
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(0))
}

// ---------------------------------------------------------------------------------------- the tray

/// Change the menu to say `text`, if it is not saying it already.
fn apply_tray(shell: &Shell, text: TrayText) {
    let mut current = shell.text.lock().unwrap();
    if current.as_ref() == Some(&text) {
        return;
    }
    if let Some(parts) = shell.tray.lock().unwrap().as_ref() {
        let _ = parts.state.set_text(&text.state);
        let _ = parts.control.set_text(&text.control);
        let _ = parts.control.set_enabled(text.action != Control::None);
        let _ = parts.icon.set_tooltip(Some(&text.state));
    }
    *current = Some(text);
}

fn build_tray(app: &tauri::App, shell: &Arc<Shell>) -> tauri::Result<()> {
    let initial = tray::text(None);
    let state = MenuItem::with_id(app, "state", &initial.state, false, None::<&str>)?;
    let control = MenuItem::with_id(app, "control", &initial.control, false, None::<&str>)?;
    let open = MenuItem::with_id(app, "open", &initial.open, true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", &initial.quit, true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&state, &control, &separator, &open, &quit])?;

    let mut builder = TrayIconBuilder::with_id("main")
        .menu(&menu)
        // A left click opens the native menu (R1); nothing about it depends on the web view.
        .show_menu_on_left_click(true)
        .tooltip(&initial.state)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "open" => open_window(app),
            // Quitting this app does not touch the service: the connection stays exactly as it was.
            "quit" => app.exit(0),
            "control" => {
                let app = app.clone();
                tauri::async_runtime::spawn(async move { press_control(&app).await });
            }
            _ => {}
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    let icon = builder.build(app)?;
    *shell.tray.lock().unwrap() = Some(TrayParts {
        icon,
        state,
        control,
    });
    Ok(())
}

/// The tray's one control, which is the window's one control (FR-036). A refusal, including the one that asks
/// for consent to a method that drops connections, is answered by opening the window, where the reason and the
/// consent can be shown: a menu has no room for either.
async fn press_control(app: &AppHandle) {
    let shell = app.state::<Arc<Shell>>().inner().clone();
    let action = shell.text.lock().unwrap().as_ref().map(|t| t.action);
    let outcome = match action {
        Some(Control::Connect) => shell.bridge.stabilize(true, false).await,
        Some(Control::Disconnect) => shell.bridge.stabilize(false, false).await,
        Some(Control::None) | None => return,
    };
    if outcome["ok"] != Value::Bool(true) {
        open_window(app);
    }
    shell.wake.notify_one();
}

// ---------------------------------------------------------------------------------------- the window

fn open_window(app: &AppHandle) {
    let shell = app.state::<Arc<Shell>>();
    shell.grace.lock().unwrap().window_opened();
    shell.visible.store(true, Ordering::Relaxed);
    if let Some(window) = app.get_webview_window(WINDOW) {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
        shell.wake.notify_one();
        return;
    }
    // Created hidden and shown when the page has loaded, so there is no blank frame (R2).
    shell.page_ready.store(false, Ordering::Relaxed);
    let built = WebviewWindowBuilder::new(app, WINDOW, WebviewUrl::App("index.html".into()))
        .title("DNet Engine")
        // No system frame: the page draws the title bar and the edge (ADR-0007 R4 keeps what it may ask of the
        // window to the four commands below).
        .decorations(false)
        .inner_size(960.0, 660.0)
        .min_inner_size(560.0, 420.0)
        .visible(false)
        .on_page_load(|webview, payload| {
            if let PageLoadEvent::Finished = payload.event() {
                let _ = webview.show();
            }
        })
        .build();
    match built {
        Ok(_) => {
            shell.wake.notify_one();
            watch_page(app.clone());
        }
        Err(error) => {
            shell.visible.store(false, Ordering::Relaxed);
            eprintln!("could not open the window: {error}");
        }
    }
}

/// How long a new window has to say its title bar is drawn before the system frame is given back.
const PAGE_READY_WITHIN: Duration = Duration::from_secs(10);

/// Give the window its system frame back if its page never says it is up: the window has none of its own, and a
/// page that failed to start would otherwise leave it with no way to move or close it.
fn watch_page(app: AppHandle) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(PAGE_READY_WITHIN).await;
        let shell = app.state::<Arc<Shell>>();
        if shell.page_ready.load(Ordering::Relaxed) {
            return;
        }
        if let Some(window) = app.get_webview_window(WINDOW) {
            eprintln!("the window's page did not start; giving the window its system frame back");
            let _ = window.set_decorations(true);
        }
    });
}

/// The window was closed: hide it, send it nothing, and let the web view go if nobody wants it back (R2).
fn close_window(app: &AppHandle) {
    let shell = app.state::<Arc<Shell>>().inner().clone();
    shell.visible.store(false, Ordering::Relaxed);
    if let Some(window) = app.get_webview_window(WINDOW) {
        let _ = window.hide();
    }
    let token = shell.grace.lock().unwrap().window_closed();
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(GRACE).await;
        if shell.grace.lock().unwrap().still_current(token) {
            if let Some(window) = app.get_webview_window(WINDOW) {
                let _ = window.destroy();
            }
        }
    });
}

// ---------------------------------------------------------------------------------------- watching

/// Ask the service for the state: often while the window is on screen, rarely while only the tray is there,
/// and at once when the service says something happened. The tray always follows; the window only when shown.
async fn watch_state(app: AppHandle, shell: Arc<Shell>) {
    loop {
        let because = shell.last_because();
        match shell.bridge.snapshot(because.as_deref(), now_ms()).await {
            Ok(view) => {
                apply_tray(&shell, tray::text(Some(&view)));
                if shell.visible.load(Ordering::Relaxed) {
                    let _ = app.emit_to(WINDOW, "dnet:snapshot", &view);
                }
            }
            Err(_) => apply_tray(&shell, tray::text(None)),
        }
        let wait = poll_interval(shell.visible.load(Ordering::Relaxed));
        tokio::select! {
            () = shell.wake.notified() => {}
            () = tokio::time::sleep(wait) => {}
        }
    }
}

/// Follow the service's events, for the Activity view and for the reason under the state. A service that is
/// not there yet, or goes away, is retried with a growing pause; the state loop shows meanwhile that it did not
/// answer.
async fn follow_events(app: AppHandle, shell: Arc<Shell>) {
    let mut pause = Duration::from_secs(1);
    loop {
        if let Ok(mut connection) = shell.link.stream().await {
            // The service replays the session it still holds, so what was kept is replaced and not added to.
            shell.backlog.lock().unwrap().restart();
            let ended = follow(&mut connection, |line, replay| {
                shell.backlog.lock().unwrap().push(line.clone());
                if !replay {
                    if shell.visible.load(Ordering::Relaxed) {
                        let _ = app.emit_to(WINDOW, "dnet:activity", &line);
                    }
                    shell.wake.notify_one();
                }
                true
            })
            .await;
            if matches!(ended, Ok(Ended::Closed | Ended::Stopped)) {
                pause = Duration::from_secs(1);
            }
        }
        tokio::time::sleep(pause).await;
        pause = (pause * 2).min(Duration::from_secs(30));
    }
}

// ---------------------------------------------------------------------------------------- commands
//
// The web view may give exactly these (build.rs, capabilities/default.json), and each is one call into
// `dnet_view::Bridge`, which checks what it is given before anything goes to the service.

type Shared<'a> = State<'a, Arc<Shell>>;

#[tauri::command]
fn capabilities(shell: Shared<'_>) -> Value {
    shell.bridge.capabilities()
}

#[tauri::command]
async fn snapshot(shell: Shared<'_>) -> Result<Value, String> {
    let because = shell.last_because();
    shell.bridge.snapshot(because.as_deref(), now_ms()).await
}

#[tauri::command]
fn activity_backlog(shell: Shared<'_>) -> Vec<Value> {
    shell.backlog.lock().unwrap().items()
}

#[tauri::command]
async fn stabilize(shell: Shared<'_>, on: bool, acknowledge_tier2: bool) -> Result<Value, String> {
    let outcome = shell.bridge.stabilize(on, acknowledge_tier2).await;
    shell.wake.notify_one();
    Ok(outcome)
}

#[tauri::command]
async fn list_endpoints(shell: Shared<'_>) -> Result<Value, String> {
    shell.bridge.endpoints().await
}

#[tauri::command]
async fn add_endpoint(
    shell: Shared<'_>,
    label: String,
    host: String,
    credentials: String,
) -> Result<Value, String> {
    let outcome = shell.bridge.add_endpoint(&label, &host, &credentials).await;
    shell.wake.notify_one();
    Ok(outcome)
}

#[tauri::command]
async fn remove_endpoint(shell: Shared<'_>, id: String) -> Result<Value, String> {
    let outcome = shell.bridge.remove_endpoint(&id).await;
    shell.wake.notify_one();
    Ok(outcome)
}

#[tauri::command]
async fn set_endpoint_enabled(
    shell: Shared<'_>,
    id: String,
    enabled: bool,
) -> Result<Value, String> {
    let outcome = shell.bridge.set_endpoint_enabled(&id, enabled).await;
    shell.wake.notify_one();
    Ok(outcome)
}

#[tauri::command]
async fn list_profiles(shell: Shared<'_>) -> Result<Value, String> {
    shell.bridge.profiles().await
}

/// Brutal on (`up` and `down` in Mbit/s) or off (neither). `warning_revision` is the revision of the
/// warning the window showed; the service records the acceptance only if it is the one in force.
#[tauri::command]
async fn set_brutal(
    shell: Shared<'_>,
    profile: String,
    up: Option<u32>,
    down: Option<u32>,
    warning_revision: u32,
) -> Result<Value, String> {
    let bandwidth = match (up, down) {
        (Some(up), Some(down)) => Some((up, down)),
        (None, None) => None,
        // One direction alone would half-enable it (CC-04): not a request this window makes.
        _ => return Err("both directions are needed, or neither".to_owned()),
    };
    let outcome = shell
        .bridge
        .set_brutal(&profile, bandwidth, warning_revision)
        .await;
    shell.wake.notify_one();
    Ok(outcome)
}

/// The script to run on the person's own server, and the ports to open (T150).
#[tauri::command]
async fn prepare_server(shell: Shared<'_>, arch: String) -> Result<Value, String> {
    Ok(shell.bridge.prepare_server(&arch).await)
}

/// What the server printed, pasted back: checked, and the server added (T150).
#[tauri::command]
async fn finish_server(
    shell: Shared<'_>,
    label: String,
    host: String,
    report: String,
) -> Result<Value, String> {
    let outcome = shell.bridge.finish_server(&label, &host, &report).await;
    shell.wake.notify_one();
    Ok(outcome)
}

#[tauri::command]
async fn add_rule(
    shell: Shared<'_>,
    kind: String,
    value: String,
    action: String,
) -> Result<Value, String> {
    let outcome = shell.bridge.add_rule(&kind, &value, &action).await;
    shell.wake.notify_one();
    Ok(outcome)
}

#[tauri::command]
async fn remove_rule(shell: Shared<'_>, id: String) -> Result<Value, String> {
    let outcome = shell.bridge.remove_rule(&id).await;
    shell.wake.notify_one();
    Ok(outcome)
}

/// The live map of parts, read-only (T170).
#[tauri::command]
async fn list_components(shell: Shared<'_>) -> Result<Value, String> {
    shell.bridge.components().await
}

#[tauri::command]
async fn list_rules(shell: Shared<'_>) -> Result<Value, String> {
    shell.bridge.rules().await
}

#[tauri::command]
async fn list_pending(shell: Shared<'_>) -> Result<Value, String> {
    shell.bridge.pending().await
}

#[tauri::command]
async fn reject_change(shell: Shared<'_>, id: String) -> Result<Value, String> {
    let outcome = shell.bridge.reject_change(&id).await;
    shell.wake.notify_one();
    Ok(outcome)
}

/// Approve a waiting change (T160b). The window is not an elevated client, so the service would refuse it:
/// this starts `dnetctl approve <id>` beside the window's own program, which asks Windows for elevation and
/// applies the change only when the person types `yes` in its own window. Only the change's name is handed
/// over, checked first (`dnet_view::approver`). Waits for it to end, which is when the person has answered.
#[tauri::command]
async fn approve_change(shell: Shared<'_>, id: String) -> Result<Value, String> {
    let any_service = std::env::args().any(|a| a == "--allow-unprivileged-service");
    let args = match dnet_view::approver::arguments(&id, any_service) {
        Ok(args) => args,
        Err(why) => return Ok(dnet_view::outcome::refused(&why, "Refused")),
    };
    let ended = tauri::async_runtime::spawn_blocking(move || run_approver(&args))
        .await
        .map_err(|_| "the approval could not be waited for".to_string())?;
    shell.wake.notify_one();
    Ok(dnet_view::approver::outcome(ended))
}

/// Run `dnetctl` beside this program with `args` and say how it ended: its exit code, or `None` when it
/// could not be started or ended without one. It has no console window of its own (the elevated window it
/// opens does).
fn run_approver(args: &[String]) -> Option<i32> {
    let program = std::env::current_exe()
        .ok()?
        .parent()?
        .join(dnet_view::approver::APPROVER);
    let mut command = std::process::Command::new(program);
    command
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    command.status().ok()?.code()
}

// ---------------------------------------------------------------------------------------- the window's frame
//
// The page draws its own title bar, so it needs four things from the window and no more. Each acts on this
// program's own window and takes no argument.

#[tauri::command]
fn window_minimize(app: AppHandle) {
    if let Some(window) = app.get_webview_window(WINDOW) {
        let _ = window.minimize();
    }
}

#[tauri::command]
fn window_toggle_maximize(app: AppHandle) {
    if let Some(window) = app.get_webview_window(WINDOW) {
        let maximized = window.is_maximized().unwrap_or(false);
        let _ = if maximized {
            window.unmaximize()
        } else {
            window.maximize()
        };
    }
}

#[tauri::command]
fn window_start_drag(app: AppHandle) {
    if let Some(window) = app.get_webview_window(WINDOW) {
        let _ = window.start_dragging();
    }
}

/// Asks to close, which is what the system's own button did: the close handler hides the window and lets the web
/// view go after its grace (R2). The tray keeps running.
#[tauri::command]
fn window_close(app: AppHandle) {
    if let Some(window) = app.get_webview_window(WINDOW) {
        let _ = window.close();
    }
}

/// The page has drawn its title bar: the system frame is not needed (see `watch_page`).
#[tauri::command]
fn window_ready(shell: Shared<'_>) {
    shell.page_ready.store(true, Ordering::Relaxed);
}

#[tauri::command]
async fn set_encrypted_dns(shell: Shared<'_>, block: bool) -> Result<Value, String> {
    Ok(shell.bridge.set_encrypted_dns(block).await)
}

#[tauri::command]
async fn check_updates(shell: Shared<'_>) -> Result<Value, String> {
    Ok(shell.bridge.check_updates().await)
}

#[tauri::command]
fn open_login_page(shell: Shared<'_>) -> Value {
    shell.bridge.open_login_page()
}

// ---------------------------------------------------------------------------------------- start

pub fn run() {
    let trust = if std::env::args().any(|a| a == "--allow-unprivileged-service") {
        eprintln!("--allow-unprivileged-service: talking to a control pipe that any program could have made");
        Trust::AnyServer
    } else {
        Trust::ServiceOwnedOnly
    };
    let shell = Arc::new(Shell::new(Arc::new(PipeLink::with_trust(trust))));

    let app = tauri::Builder::default()
        .manage(shell.clone())
        .invoke_handler(tauri::generate_handler![
            capabilities,
            snapshot,
            activity_backlog,
            stabilize,
            list_endpoints,
            add_endpoint,
            remove_endpoint,
            prepare_server,
            finish_server,
            set_endpoint_enabled,
            list_profiles,
            list_components,
            set_brutal,
            list_rules,
            add_rule,
            remove_rule,
            list_pending,
            reject_change,
            approve_change,
            set_encrypted_dns,
            check_updates,
            open_login_page,
            window_minimize,
            window_toggle_maximize,
            window_start_drag,
            window_close,
            window_ready,
        ])
        .on_window_event(|window, event| {
            if window.label() == WINDOW {
                match event {
                    WindowEvent::CloseRequested { api, .. } => {
                        api.prevent_close();
                        close_window(window.app_handle());
                    }
                    // The page draws a Maximize or a Restore button; it is told which, whoever changed it (the
                    // title bar, a keyboard shortcut, or snapping the window to an edge).
                    WindowEvent::Resized(_) => {
                        let maximized = window.is_maximized().unwrap_or(false);
                        let _ = window.emit_to(WINDOW, "dnet:window", maximized);
                    }
                    _ => {}
                }
            }
        })
        .setup(move |app| {
            build_tray(app, &shell)?;
            tauri::async_runtime::spawn(watch_state(app.handle().clone(), shell.clone()));
            tauri::async_runtime::spawn(follow_events(app.handle().clone(), shell.clone()));
            // `--open` starts with the window showing, for a person starting it from a shortcut and for tests.
            if std::env::args().any(|a| a == "--open") {
                open_window(app.handle());
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("could not build the application");

    app.run(|_app, event| {
        // Closing the last window must not end the app: it lives in the tray.
        if let RunEvent::ExitRequested { api, code, .. } = event {
            if code.is_none() {
                api.prevent_exit();
            }
        }
    });
}
