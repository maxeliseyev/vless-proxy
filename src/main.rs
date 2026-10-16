use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, Level};
use vproxy::{serve, Config, VlessUrl};

#[derive(Clone)]
struct Args {
    config_path: Option<PathBuf>,
    vless_url: Option<String>,
    inbound_port: Option<u16>,
    verbose: bool,
    check_config: bool,
    probe: bool,
    tun: bool,
    print_tun_config: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .with_max_level(if args.verbose {
            Level::DEBUG
        } else {
            Level::INFO
        })
        .init();

    let mut config = load_config(args.clone())?;
    if args.tun || args.print_tun_config {
        config.tun.enabled = true;
        config.validate()?;
    }
    let config = Arc::new(config);
    let sidecar = if config.needs_xray_sidecar()? {
        config.runtime.xray_path.as_str()
    } else {
        "native"
    };
    info!(
        "Loaded config (inbound: {}, security: {:?}, dns: {:?}/{:?}, runtime: max_conn={}, timeouts: connect={}s/read={}s/write={}s/idle={}s, transport={})",
        config.inbound_addr(),
        config.transport_security()?,
        config.dns_resolve_mode()?,
        config.dns_ip_strategy()?,
        config.runtime.max_connections,
        config.runtime.connect_timeout_secs,
        config.runtime.read_timeout_secs,
        config.runtime.write_timeout_secs,
        config.runtime.idle_timeout_secs,
        sidecar,
    );

    if args.check_config {
        info!("Configuration is valid");
        return Ok(());
    }

    if args.print_tun_config {
        let rendered = vproxy::tun::build_sing_box_config(
            config.as_ref(),
            vproxy::tun::current_process_name().as_deref(),
        )?;
        println!("{}", serde_json::to_string_pretty(&rendered)?);
        return Ok(());
    }

    if args.probe {
        let report = vproxy::runtime::probe_transport(config.as_ref()).await?;
        info!("{report}");
        return Ok(());
    }

    serve(config).await
}

fn load_config(args: Args) -> Result<Config> {
    if let Some(url_str) = args.vless_url {
        let url = VlessUrl::parse(&url_str)?;
        let inbound_port = args.inbound_port.unwrap_or(1080);
        let config = Config::from_vless_url(&url, inbound_port);
        config.validate()?;

        if let Some(remark) = &url.remark {
            info!("Using VLESS server: {}", remark);
        }
        info!(
            "Server: {}:{} (security: {}, tls: {})",
            url.host,
            url.port,
            url.security,
            url.use_tls()
        );

        Ok(config)
    } else if let Some(config_path) = args.config_path {
        info!("Loading config from: {}", config_path.display());
        Config::load(&config_path)
    } else {
        anyhow::bail!("No config provided. Use --config, --url, or provide a config path");
    }
}

fn parse_args() -> Result<Args> {
    let mut config_path = None;
    let mut vless_url = None;
    let mut inbound_port = None;
    let mut verbose = false;
    let mut check_config = false;
    let mut probe = false;
    let mut tun = false;
    let mut print_tun_config = false;

    let mut args = std::env::args_os().skip(1);
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("-c") | Some("--config") => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--config requires a path"))?;
                config_path = Some(PathBuf::from(value));
            }
            Some("-u") | Some("--url") => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--url requires a vless:// URL"))?;
                vless_url = Some(
                    value
                        .into_string()
                        .map_err(|_| anyhow::anyhow!("Invalid URL encoding"))?,
                );
            }
            Some("-p") | Some("--inbound-port") => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--inbound-port requires a port number"))?;
                inbound_port = Some(
                    value
                        .into_string()
                        .map_err(|_| anyhow::anyhow!("Invalid port encoding"))?
                        .parse()
                        .map_err(|_| anyhow::anyhow!("Invalid port number"))?,
                );
            }
            Some("-v") | Some("--verbose") => verbose = true,
            Some("--check-config") => check_config = true,
            Some("--probe") => probe = true,
            Some("--tun") => tun = true,
            Some("--print-tun-config") => print_tun_config = true,
            Some("-h") | Some("--help") => {
                print_help();
                std::process::exit(0);
            }
            Some(value) if value.starts_with('-') => {
                anyhow::bail!("Unknown argument: {value}");
            }
            Some(value) if value.starts_with("vless://") => {
                if vless_url.is_some() {
                    anyhow::bail!("VLESS URL can only be provided once");
                }
                vless_url = Some(value.to_string());
            }
            _ => {
                if config_path.is_some() || vless_url.is_some() {
                    anyhow::bail!("Config path or URL can only be provided once");
                }
                config_path = Some(PathBuf::from(arg));
            }
        }
    }

    Ok(Args {
        config_path,
        vless_url,
        inbound_port,
        verbose,
        check_config,
        probe,
        tun,
        print_tun_config,
    })
}

fn print_help() {
    println!(
        "\
vproxy - terminal VLESS client

Usage:
  vproxy [OPTIONS] [config-path|vless://...]

Options:
  -c, --config <PATH>       Path to TOML config
  -u, --url <VLESS_URL>     VLESS subscription URL (vless://...)
  -p, --inbound-port <PORT> Local inbound port (default: 1080)
  -v, --verbose             Enable debug logging
      --check-config        Validate config and exit
      --probe               Connect once, finish the transport (TLS/REALITY) handshake and exit
      --tun                 System-wide mode: run a sing-box TUN sidecar on top of the SOCKS5 inbound (needs root)
      --print-tun-config    Print the generated sing-box config for --tun and exit
  -h, --help                Show this help

Examples:
  vproxy config.toml
  vproxy --url 'vless://uuid@host:port?security=tls'
  vproxy -u 'vless://...' -p 8080
  sudo vproxy --tun -u 'vless://...'
"
    );
}
