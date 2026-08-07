#[path = "../helper_runtime.rs"]
mod helper_runtime;

use std::path::Path;

fn main() {
    let arguments: Vec<String> = std::env::args().collect();
    let config_path = match arguments.as_slice() {
        [_, config, path] if config == "--config" => path,
        _ => {
            eprintln!("MOUSEVPN_ERROR=Использование: mousevpn-helper --config <profile.toml>");
            std::process::exit(2);
        }
    };
    if let Err(error) = helper_runtime::run(Path::new(config_path)) {
        eprintln!("MOUSEVPN_ERROR={error}");
        std::process::exit(1);
    }
}
