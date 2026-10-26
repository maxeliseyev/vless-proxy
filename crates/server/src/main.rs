//! `vproxy-server -c server.toml [-v]`: run the h3 transport server.
//! `vproxy-server --stats [--admin <socket>]`: print a live stats snapshot.

use anyhow::{bail, Result};
use std::path::PathBuf;
use vproxy_server::{Server, Settings, Snapshot, DEFAULT_ADMIN_SOCKET};

mod tui;

const USAGE: &str = "usage: vproxy-server -c server.toml [-v]\n       vproxy-server --stats [--admin <socket>]\n       vproxy-server --tui [--admin <socket>]";

#[tokio::main]
async fn main() -> Result<()> {
    let mut config: Option<PathBuf> = None;
    let mut admin: Option<PathBuf> = None;
    let mut stats = false;
    let mut tui = false;
    let mut verbose = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => config = args.next().map(PathBuf::from),
            "--stats" => stats = true,
            "--tui" => tui = true,
            "--admin" => admin = args.next().map(PathBuf::from),
            "-v" | "--verbose" => verbose = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            other => bail!("unknown argument {other:?}\n{USAGE}"),
        }
    }

    if stats || tui {
        let path = admin.unwrap_or_else(|| PathBuf::from(DEFAULT_ADMIN_SOCKET));
        if tui {
            return tui::run(&path).await;
        }
        let snap = vproxy_server::fetch_stats(&path).await?;
        print_stats(&snap);
        return Ok(());
    }

    let Some(config) = config else {
        bail!("{USAGE}");
    };
    tracing_subscriber::fmt()
        .with_max_level(if verbose {
            tracing::Level::DEBUG
        } else {
            tracing::Level::INFO
        })
        .with_target(false)
        .init();

    let settings = Settings::load(&config)?;
    let server = Server::from_settings(&settings)?;
    tokio::select! {
        result = server.run() => result,
        _ = tokio::signal::ctrl_c() => Ok(()),
    }
}

fn print_stats(s: &Snapshot) {
    println!("uptime     {}", duration(s.uptime_secs));
    println!("conns      {} open · {} total", s.conns_open, s.conns_total);
    println!(
        "streams    {} open · {} total",
        s.streams_open, s.streams_total
    );
    println!("udp        {} open · {} total", s.udp_open, s.udp_total);
    println!(
        "traffic    up {} · down {}",
        bytes(s.bytes_up),
        bytes(s.bytes_down)
    );
    println!("site       {} HTTP/3 requests", s.site_requests);
    if !s.accounts.is_empty() {
        println!("\naccount   open  total  idle");
        for a in &s.accounts {
            println!(
                "{:<8}  {:>4}  {:>5}  {}",
                a.tag,
                a.open,
                a.total,
                duration(a.idle_secs)
            );
        }
    }
}

fn duration(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
    if d > 0 {
        format!("{d}d{h}h")
    } else if h > 0 {
        format!("{h}h{m}m")
    } else if m > 0 {
        format!("{m}m{s}s")
    } else {
        format!("{s}s")
    }
}

fn bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}
