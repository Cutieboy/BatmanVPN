#[path = "../helper_runtime.rs"]
mod helper_runtime;

use std::{net::Ipv4Addr, path::Path};

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let result = match arguments.as_slice() {
        [_, config, path] if config == "--config" => helper_runtime::run(Path::new(path)),
        [_, watchdog, parent_flag, parent, started_flag, started, server_flag, server]
            if watchdog == "--network-watchdog"
                && parent_flag == "--parent"
                && started_flag == "--started"
                && server_flag == "--server" =>
        {
            parse_watchdog(parent, started, server)
        }
        _ => {
            eprintln!("MOUSEVPN_ERROR=Использование: mousevpn-helper --config <profile.toml>");
            std::process::exit(2);
        }
    };
    if let Err(error) = result {
        eprintln!("MOUSEVPN_ERROR={error}");
        std::process::exit(1);
    }
}

fn parse_watchdog(parent: &str, started: &str, server: &str) -> Result<(), String> {
    let parent = parent
        .parse()
        .map_err(|_| "Неверный PID watchdog".to_owned())?;
    let started = started
        .parse()
        .map_err(|_| "Неверное время старта watchdog".to_owned())?;
    let server: Ipv4Addr = server
        .parse()
        .map_err(|_| "Неверный адрес сервера watchdog".to_owned())?;
    helper_runtime::run_watchdog(parent, started, server)
}
