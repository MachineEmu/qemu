//! Serve a canned SPICE audio session on a Unix socket.
//!
//! ```text
//! spice-audio-fake-server --socket /tmp/spice.sock
//! ```
//!
//! The console's WebSocket-proxy tests point a session's `spice.sock` at this
//! instead of starting QEMU.

use std::path::PathBuf;
use std::process::ExitCode;

use spice_audio::server::FakeServer;

#[tokio::main]
async fn main() -> ExitCode {
    let mut socket = PathBuf::new();
    let mut args = std::env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--socket" => match args.next() {
                Some(value) => socket = PathBuf::from(value),
                None => {
                    eprintln!("spice-audio-fake-server: --socket needs a path");
                    return ExitCode::from(2);
                }
            },
            other => {
                eprintln!("spice-audio-fake-server: unknown argument {other}");
                return ExitCode::from(2);
            }
        }
    }
    if socket.as_os_str().is_empty() {
        eprintln!("spice-audio-fake-server: --socket is required");
        return ExitCode::from(2);
    }
    let server = match FakeServer::bind(&socket) {
        Ok(server) => server,
        Err(error) => {
            eprintln!("spice-audio-fake-server: {error}");
            return ExitCode::FAILURE;
        }
    };
    // Announce readiness on stdout so a test can wait for the socket without
    // polling the filesystem.
    println!("ready {}", socket.display());
    if let Err(error) = server.serve().await {
        eprintln!("spice-audio-fake-server: {error}");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
