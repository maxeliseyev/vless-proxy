//! Desktop process lifecycle: signals, proxy listeners and sidecars.

use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tracing::{info, warn};
use vproxy_core::proxy::runtime::serve_with_shutdown;
use vproxy_core::{ActiveServer, Config};

pub async fn serve(config: Arc<Config>) -> Result<()> {
    let active = ActiveServer::new(config.server.clone());
    serve_with_server(config, active).await
}

/// Like [`serve`], with an [`ActiveServer`] handle the caller can use to
/// switch servers while running (the TUI does this).
pub async fn serve_with_server(config: Arc<Config>, active: ActiveServer) -> Result<()> {
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let use_sidecar = config.needs_xray_sidecar()?;

    let mut ctrl_c_stream =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut sigterm_stream =
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    let shutdown_signal = async {
        tokio::select! {
            _ = ctrl_c_stream.recv() => {
                info!("Received SIGINT, initiating graceful shutdown");
            }
            _ = sigterm_stream.recv() => {
                info!("Received SIGTERM, initiating graceful shutdown");
            }
        }
    };

    let core = async {
        if use_sidecar {
            return crate::system::xray_sidecar::run(config.clone()).await;
        }
        serve_with_shutdown(config.clone(), active.clone(), shutdown_rx.clone()).await
    };
    let mut tun_task = config
        .tun
        .enabled
        .then(|| tokio::spawn(run_tun(config.clone(), shutdown_rx.clone())));
    let tun_failed = async {
        match tun_task.as_mut() {
            Some(task) => match task.await {
                Ok(result) => result,
                Err(e) => Err(anyhow::anyhow!("TUN sidecar task failed: {e}")),
            },
            None => std::future::pending().await,
        }
    };
    tokio::pin!(tun_failed);

    let mut tun_done = false;
    let result = tokio::select! {
        result = core => result,
        result = &mut tun_failed => {
            tun_done = true;
            result
        }
        _ = shutdown_signal => {
            info!("Shutdown signal received, stopping server");
            let _ = shutdown_tx.send(true);
            Ok(())
        }
    };

    // Give the TUN sidecar time to restore routes/DNS before we exit.
    // A finished `tun_failed` must not be polled again.
    let _ = shutdown_tx.send(true);
    if config.tun.enabled && !tun_done {
        match tokio::time::timeout(Duration::from_secs(6), &mut tun_failed).await {
            Ok(Err(e)) if result.is_ok() => warn!("TUN sidecar stopped with error: {e}"),
            Err(_) => warn!("TUN sidecar did not stop in time"),
            _ => {}
        }
    }

    result
}

async fn run_tun(config: Arc<Config>, shutdown: watch::Receiver<bool>) -> Result<()> {
    crate::system::tun::run(config, shutdown).await
}
