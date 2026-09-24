use tauri::{
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager,
};

use crate::{set_tray_error, shutdown_for_exit, tray_toggle, AppState};

const SHOW: &str = "show";
const TOGGLE: &str = "toggle";
const QUIT: &str = "quit";

pub(crate) fn install(app: &mut tauri::App) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, SHOW, "Открыть BatmanVPN", true, None::<&str>)?;
    let toggle = MenuItem::with_id(app, TOGGLE, "Подключить / отключить", true, None::<&str>)?;
    let separator = PredefinedMenuItem::separator(app)?;
    let quit = MenuItem::with_id(app, QUIT, "Выйти", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &toggle, &separator, &quit])?;

    let mut tray = TrayIconBuilder::new()
        .tooltip("BatmanVPN")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            SHOW => show_main_window(app),
            TOGGLE => {
                let state = app.state::<AppState>();
                if let Err(error) = tray_toggle(&state) {
                    set_tray_error(&state, error);
                    show_main_window(app);
                }
            }
            QUIT => {
                let state = app.state::<AppState>();
                shutdown_for_exit(&state);
                app.exit(0);
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if matches!(
                event,
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                }
            ) {
                show_main_window(tray.app_handle());
            }
        });
    if let Some(icon) = app.default_window_icon().cloned() {
        tray = tray.icon(icon);
    }
    tray.build(app)?;
    Ok(())
}

fn show_main_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}
