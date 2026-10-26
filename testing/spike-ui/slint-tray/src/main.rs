//! Measurement spike (not product code): a native toolkit as a tray-resident app, for comparison
//! with the Tauri spike. Same timetable (open at 15 s, destroy at 45 s), same content.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, TrayIconBuilder};

slint::slint! {
    component Row inherits Rectangle {
        in property <string> label;
        in property <string> value;
        height: 28px;
        HorizontalLayout {
            Text { text: root.label; color: #9db1a6; font-size: 13px; vertical-alignment: center; }
            Text { text: root.value; color: #e6efe9; font-size: 13px; horizontal-alignment: right; vertical-alignment: center; }
        }
    }

    export component Panel inherits Window {
        title: "spike";
        preferred-width: 420px;
        preferred-height: 640px;
        background: #0e1311;
        in property <string> uptime: "0 s";
        VerticalLayout {
            padding: 20px;
            spacing: 12px;
            alignment: start;
            Rectangle {
                background: #151c19;
                border-radius: 10px;
                border-width: 1px;
                border-color: #24302b;
                height: 70px;
                VerticalLayout {
                    padding: 14px;
                    Text { text: "Connected"; color: #e6efe9; font-size: 20px; font-weight: 600; }
                    Text { text: "Carrying traffic through the tunnel"; color: #9db1a6; font-size: 13px; }
                }
            }
            Rectangle {
                background: #151c19;
                border-radius: 10px;
                border-width: 1px;
                border-color: #24302b;
                height: 170px;
                VerticalLayout {
                    padding: 14px;
                    Row { label: "Profile"; value: "AmneziaWG"; }
                    Row { label: "Endpoint"; value: "endpoint-1"; }
                    Row { label: "Latency"; value: "43 ms"; }
                    Row { label: "Loss"; value: "2 %"; }
                    Row { label: "Uptime"; value: root.uptime; }
                }
            }
        }
    }
}

fn tray_icon() -> Icon {
    // A plain teal disc, built in memory so the spike needs no image file.
    let size = 32u32;
    let mut rgba = Vec::with_capacity((size * size * 4) as usize);
    for y in 0..size {
        for x in 0..size {
            let (dx, dy) = (x as f32 - 16.0, y as f32 - 16.0);
            if dx * dx + dy * dy < 13.0 * 13.0 {
                rgba.extend_from_slice(&[20, 184, 166, 255]);
            } else {
                rgba.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }
    Icon::from_rgba(rgba, size, size).expect("a valid icon")
}

/// The window and the timer that updates it live and die together.
struct Open {
    panel: Panel,
    _tick: slint::Timer,
}

fn open(window: &Rc<RefCell<Option<Open>>>) {
    if window.borrow().is_some() {
        return;
    }
    let panel = Panel::new().expect("could not create the window");
    panel.show().expect("could not show the window");
    // A live readout, as the real status view will have: one small update a second.
    let weak = panel.as_weak();
    let mut seconds = 0u32;
    let tick = slint::Timer::default();
    tick.start(slint::TimerMode::Repeated, Duration::from_secs(1), move || {
        seconds += 1;
        if let Some(panel) = weak.upgrade() {
            panel.set_uptime(format!("{seconds} s").into());
        }
    });
    *window.borrow_mut() = Some(Open { panel, _tick: tick });
}

fn close(window: &Rc<RefCell<Option<Open>>>) {
    if let Some(open) = window.borrow_mut().take() {
        let _ = open.panel.hide();
    }
}

fn main() {
    let menu = Menu::new();
    let open_item = MenuItem::new("Open", true, None);
    let quit_item = MenuItem::new("Quit", true, None);
    menu.append_items(&[&open_item, &quit_item]).expect("menu");
    let _tray = TrayIconBuilder::new()
        .with_menu(Box::new(menu))
        .with_icon(tray_icon())
        .build()
        .expect("tray icon");

    let window: Rc<RefCell<Option<Open>>> = Rc::new(RefCell::new(None));

    // Menu clicks arrive on a channel; look for them a few times a second.
    let poll_window = Rc::clone(&window);
    let (open_id, quit_id) = (open_item.id().clone(), quit_item.id().clone());
    let poll = slint::Timer::default();
    poll.start(slint::TimerMode::Repeated, Duration::from_millis(150), move || {
        while let Ok(event) = MenuEvent::receiver().try_recv() {
            if event.id == open_id {
                open(&poll_window);
            } else if event.id == quit_id {
                let _ = slint::quit_event_loop();
            }
        }
    });

    if std::env::var_os("SPIKE_SCRIPT").is_some() {
        let w = Rc::clone(&window);
        slint::Timer::single_shot(Duration::from_secs(15), move || open(&w));
        let w = Rc::clone(&window);
        slint::Timer::single_shot(Duration::from_secs(45), move || close(&w));
    }

    // With no window open the loop must keep running: the app lives in the tray.
    slint::run_event_loop_until_quit().expect("event loop");
}
