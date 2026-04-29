use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, Level};
use vproxy::{serve, Config};

struct Args {
    config_path: PathBuf,
    verbose: bool,
    check_config: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;
    tracing_subscriber::fmt()
        .with_target(false)
        .with_max_level(if args.verbose {
            Level::DEBUG
        } else {
            Level::INFO
        })
        .init();

    let config = Arc::new(Config::load(&args.config_path)?);
    info!(
        "Loaded config from {} (inbound: {}, security: {:?}, dns: {:?}/{:?})",
        args.config_path.display(),
        config.inbound_addr(),
        config.transport_security()?,
        config.dns_resolve_mode()?,
        config.dns_ip_strategy()?
    );

    if args.check_config {
        info!("Configuration is valid");
        return Ok(());
    }

    serve(config).await
}

fn parse_args() -> Result<Args> {
    let mut config_path = None;
    let mut verbose = false;
    let mut check_config = false;

    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("-c") | Some("--config") => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--config requires a path"))?;
                config_path = Some(PathBuf::from(value));
            }
            Some("-v") | Some("--verbose") => verbose = true,
            Some("--check-config") => check_config = true,
            Some("-h") | Some("--help") => {
                print_help();
                std::process::exit(0);
            }
            Some(value) if value.starts_with('-') => {
                anyhow::bail!("Unknown argument: {value}");
            }
            _ => {
                if config_path.is_some() {
                    anyhow::bail!("Config path can only be provided once");
                }
                config_path = Some(PathBuf::from(arg));
            }
        }
    }

    Ok(Args {
        config_path: config_path.unwrap_or_else(|| PathBuf::from("config.toml")),
        verbose,
        check_config,
    })
}

fn print_help() {
    println!(
        "\
vproxy - terminal VLESS client

Usage:
  vproxy [OPTIONS] [config-path]

Options:
  -c, --config <PATH>   Path to TOML config
  -v, --verbose         Enable debug logging
      --check-config    Validate config and exit
  -h, --help            Show this help
"
    );
}
