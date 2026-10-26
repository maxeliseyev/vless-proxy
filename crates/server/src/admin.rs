//! A local Unix-socket admin surface: newline-delimited JSON [`Snapshot`]s,
//! one per second to each reader. Local only, no auth — it exposes counts, not
//! secrets, and is meant to be read from the same host (e.g. `docker compose
//! exec`). `vproxy-server --stats` and `--tui` are its clients.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::stats::{Snapshot, Stats};

/// Where the server serves, and the clients look, unless overridden.
pub const DEFAULT_SOCKET: &str = "/run/vproxy-server.sock";

/// Serve snapshots on `path` until the process ends. Replaces a stale socket
/// file left by a previous run.
pub async fn serve(path: &Path, stats: Arc<Stats>) -> Result<()> {
    let _ = std::fs::remove_file(path);
    let listener = UnixListener::bind(path)
        .with_context(|| format!("bind admin socket {}", path.display()))?;
    loop {
        let Ok((mut sock, _)) = listener.accept().await else {
            continue;
        };
        let stats = stats.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(1));
            loop {
                tick.tick().await;
                let Ok(mut line) = serde_json::to_string(&stats.snapshot()) else {
                    continue;
                };
                line.push('\n');
                if sock.write_all(line.as_bytes()).await.is_err() || sock.flush().await.is_err() {
                    break;
                }
            }
        });
    }
}

/// Connect and read one snapshot (for `--stats`).
pub async fn fetch(path: &Path) -> Result<Snapshot> {
    let stream = UnixStream::connect(path)
        .await
        .with_context(|| format!("connect {} (is the server running?)", path.display()))?;
    let mut lines = BufReader::new(stream).lines();
    let line = lines
        .next_line()
        .await?
        .context("admin socket closed before a snapshot")?;
    Ok(serde_json::from_str(&line)?)
}
