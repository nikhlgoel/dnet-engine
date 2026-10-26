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
    let built = WebviewWindowBuilder::new(app, WINDOW, WebviewUrl::App("index.html".into()))
        .title("DNet Engine")
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
        Ok(_) => shell.wake.notify_one(),
        Err(error) => {
            shell.visible.store(false, Ordering::Relaxed);
            eprintln!("could not open the window: {error}");
        }
    }
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
async fn list_rules(shell: Shared<'_>) -> Result<Value, String> {
    shell.bridge.rules().await
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
            set_endpoint_enabled,
            list_rules,
            set_encrypted_dns,
            check_updates,
            open_login_page,
        ])
        .on_window_event(|window, event| {
            if window.label() == WINDOW {
                if let WindowEvent::CloseRequested { api, .. } = event {
                    api.prevent_close();
                    close_window(window.app_handle());
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
