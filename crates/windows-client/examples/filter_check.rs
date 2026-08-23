//! Compiles candidate capture filters and reports why any of them fail.
//!
//! Needs neither the driver nor Administrator, because
//! `WinDivertHelperCompileFilter` runs entirely in the library.

fn main() {
    #[cfg(windows)]
    {
        let candidates: Vec<String> = std::env::args().skip(1).collect();
        match mousevpn_windows_client::check_capture_filters(&candidates) {
            Ok(report) => print!("{report}"),
            Err(error) => {
                eprintln!("filter check failed: {error}");
                std::process::exit(1);
            }
        }
    }

    #[cfg(not(windows))]
    eprintln!("the filter check only runs on Windows");
}
