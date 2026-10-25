//! `vproxy-server -c server.toml [-v]`: run the h3 transport server.

use anyhow::{bail, Result};
use std::path::PathBuf;
use vproxy_server::{Server, Settings};

const USAGE: &str = "usage: vproxy-server -c server.toml [-v]";

#[tokio::main]
async fn main() -> Result<()> {
    let mut config: Option<PathBuf> = None;
    let mut verbose = false;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => config = args.next().map(PathBuf::from),
            "-v" | "--verbose" => verbose = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(());
            }
            other => bail!("unknown argument {other:?}\n{USAGE}"),
        }
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
