//! Tracing initialization for the CLI.
//!
//! Reads the `-v` count and maps it to an `RUST_LOG`-style filter so that the
//! default is warnings/errors only and each `-v` lowers the threshold.

use tracing_subscriber::EnvFilter;

/// Initialize the global tracing subscriber. Safe to call once per process.
pub fn init(verbose: u8) {
    let default_level = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("seednet={default_level}")));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .try_init();
}
