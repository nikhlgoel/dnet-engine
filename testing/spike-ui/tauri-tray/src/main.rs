// SPDX-License-Identifier: GPL-3.0-or-later
//! Measurement spike (not product code): the mandated UI stack as a tray-resident app.
//!
//! The question it answers is what the stack costs in the state the product spends nearly all of its
//! life in: running in the tray with no window open. The process starts with no window and no web
//! view; "Open" creates one, closing destroys it, and the process carries on.
//!
//! `SPIKE_SCRIPT=1` runs a fixed timetable so a measuring script can sample each phase:
//! 15 s in, open the window; 45 s in, destroy it.

use std::time::Duration;

use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;
use tauri::{AppHandle, Manager, RunEvent, WebviewUrl, WebviewWindowBuilder};

const WINDOW: &str = "main";

fn open_window(app: &AppHandle) {
    if let Some(existing) = app.get_webview_window(WINDOW) {
        let _ = existing.set_focus();
        return;
    }
    let asked = std::time::Instant::now();
    let built = WebviewWindowBuilder::new(app, WINDOW, WebviewUrl::App("index.html".into()))
        .title("spike")
        .inner_size(420.0, 640.0)
        .on_page_load(move |_, payload| {
            if let tauri::webview::PageLoadEvent::Finished = payload.event() {
                eprintln!("page loaded {} ms after the request", asked.elapsed().as_millis());
            }
        })
        .build();
    match built {
        Ok(_) => eprintln!("window created {} ms after the request", asked.elapsed().as_millis()),
        Err(error) => eprintln!("could not open the window: {error}"),
    }
}

fn close_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(WINDOW) {
        let _ = window.destroy();
    }
}

fn main() {
    let app = tauri::Builder::default()
        .setup(|app| {
            let open = MenuItem::with_id(app, "open", "Open", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &quit])?;
            let mut tray = TrayIconBuilder::new()
                .menu(&menu)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => open_window(app),
                    "quit" => app.exit(0),
                    _ => {}
                });
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            tray.build(app)?;

            if let Some(mode) = std::env::var_os("SPIKE_SCRIPT") {
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    if mode == "timing" {
                        // Open and destroy the window four times: the first open meets a cold
                        // runtime, the later ones a warm one.
                        for round in 1..=4 {
                            eprintln!("--- open {round}");
                            open_window(&handle);
                            pause(4).await;
                            close_window(&handle);
                            pause(3).await;
                        }
                        handle.exit(0);
                    } else {
                        pause(15).await;
                        open_window(&handle);
                        pause(30).await;
                        close_window(&handle);
                    }
                });
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

async fn pause(seconds: u64) {
    tauri::async_runtime::spawn_blocking(move || std::thread::sleep(Duration::from_secs(seconds)))
        .await
        .ok();
}
