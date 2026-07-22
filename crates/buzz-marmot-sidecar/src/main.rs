//! Executable entry point for the native Marmot sidecar.

#![forbid(unsafe_code)]

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    if buzz_marmot_sidecar::run_sidecar(tokio::io::stdin(), tokio::io::stdout())
        .await
        .is_ok()
    {
        ExitCode::SUCCESS
    } else {
        // Stdout is protocol-only and underlying errors may contain database
        // details. The supervising Tauri process receives only the exit code.
        ExitCode::FAILURE
    }
}
