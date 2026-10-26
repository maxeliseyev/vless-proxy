//! The in-process netstack on a real TUN interface, the way the iOS Packet
//! Tunnel will drive it: packets are handed over through a channel device.
//!
//! Only the fake DNS range 198.18.0.0/15 is routed into the interface, so
//! the server connection and the rest of the machine are untouched:
//!
//! ```sh
//! sudo cargo run --example utun -- 'vless://...'      # or a links file
//! dig +short @198.18.0.2 ifconfig.me                   # -> 198.18.0.x
//! curl --resolve ifconfig.me:443:198.18.0.x https://ifconfig.me
//! ```
//!
//! The curl answer is the server's exit IP. `VERBOSE=1` logs every flow,
//! Ctrl-C stops it.

use anyhow::{bail, Context, Result};
use std::net::Ipv4Addr;
use std::sync::Arc;
use vproxy_core::netstack::device::channel_device;
use vproxy_core::netstack::fakedns::{FakeDns, DEFAULT_POOL};
use vproxy_core::netstack::flows::{FlowLog, DEFAULT_CAPACITY};
use vproxy_core::netstack::Netstack;
use vproxy_core::{ActiveServer, ProxyClient};

const MTU: u16 = 1500;

#[tokio::main]
async fn main() -> Result<()> {
    let level = if std::env::var_os("VERBOSE").is_some() {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    tracing_subscriber::fmt().with_max_level(level).init();
    let Some(source) = std::env::args().nth(1) else {
        bail!("usage: sudo cargo run --example utun -- <vless:// link | links file>");
    };
    let link = if source.contains("://") {
        source
    } else {
        std::fs::read_to_string(&source)
            .with_context(|| format!("cannot read {source}"))?
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with('#'))
            .context("no link in the file")?
            .to_string()
    };
    let config = vproxy_core::config::servers::config_from_link(&link, 0)?;
    let connector = ProxyClient::new(
        ActiveServer::new(config.server.clone()),
        config.dns.clone(),
        config.runtime.clone(),
        &config.routing,
        &config.mux,
    )?;

    let tun = tun_rs::DeviceBuilder::new()
        .ipv4(Ipv4Addr::new(198, 18, 0, 1), 15, None)
        .mtu(MTU)
        .build_async()
        .context("cannot create the TUN interface (run with sudo)")?;
    let name = tun.name()?;
    add_route(&name)?;
    let tun = Arc::new(tun);

    let (device, mut host) = channel_device();
    let reader = tun.clone();
    let to_stack = host.to_stack.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; MTU as usize + 64];
        while let Ok(n) = reader.recv(&mut buf).await {
            if to_stack.send(buf[..n].to_vec()).await.is_err() {
                break;
            }
        }
    });
    let writer = tun.clone();
    tokio::spawn(async move {
        while let Some(packet) = host.from_stack.recv().await {
            let _ = writer.send(&packet).await;
        }
    });

    let netstack = Netstack {
        connector,
        dns: Arc::new(FakeDns::new(DEFAULT_POOL, 16_384)),
        mtu: MTU,
        flows: Arc::new(FlowLog::new(DEFAULT_CAPACITY)),
    };
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(netstack.run(device, shutdown));
    println!(
        "{name} up, server {}.\n  dig +short @198.18.0.2 ifconfig.me\n  curl --resolve ifconfig.me:443:<that address> https://ifconfig.me",
        config.server.endpoint()
    );
    tokio::signal::ctrl_c().await?;
    let _ = stop.send(true);
    task.await??;
    Ok(())
}

/// Route the fake range into the interface; an existing route is fine.
fn add_route(name: &str) -> Result<()> {
    let status = if cfg!(target_os = "macos") {
        std::process::Command::new("route")
            .args(["-n", "add", "-net", "198.18.0.0/15", "-interface", name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()?
    } else {
        std::process::Command::new("ip")
            .args(["route", "replace", "198.18.0.0/15", "dev", name])
            .status()?
    };
    if !status.success() {
        tracing::debug!("route for 198.18.0.0/15 via {name} not added (may already exist)");
    }
    Ok(())
}
