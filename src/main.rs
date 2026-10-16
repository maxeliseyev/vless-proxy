use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{info, Level};
use vproxy::{serve, serve_with_server, ActiveServer, Config, ServerList, VlessUrl};

#[derive(Clone)]
struct Args {
    config_path: Option<PathBuf>,
    vless_url: Option<String>,
    url_file: Option<PathBuf>,
    inbound_port: Option<u16>,
    verbose: bool,
    check_config: bool,
    probe: bool,
    tun: bool,
    print_tun_config: bool,
    tui: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args()?;
    let level = if args.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };
    let tui_logs = if args.tui {
        let logs = vproxy::tui::LogBuffer::new(1000);
        tracing_subscriber::fmt()
            .with_writer(vproxy::tui::LogSink(logs.clone()))
            .with_timer(tracing_subscriber::fmt::time::uptime())
            .with_ansi(false)
            .with_target(false)
            .with_max_level(level)
            .init();
        Some(logs)
    } else {
        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_target(false)
            .with_max_level(level)
            .init();
        None
    };

    info!("vproxy {} starting", env!("CARGO_PKG_VERSION"));
    let (mut config, servers) = load_config(args.clone())?;
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

    match tui_logs {
        Some(logs) => {
            let active = ActiveServer::new(config.server.clone());
            let server = tokio::spawn(serve_with_server(config.clone(), active.clone()));
            vproxy::tui::run(config, servers, active, logs, server).await
        }
        None => serve(config).await,
    }
}

/// First `vless://` link in a text file (blank lines and `#` comment lines skipped).
fn read_url_file(path: &PathBuf) -> Result<String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Cannot read {}: {e}", path.display()))?;
    content
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("No vless:// link found in {}", path.display()))
}

/// `~/.config/vproxy`
fn user_config_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config").join("vproxy"))
}

enum DiscoveredSource {
    /// First link and the links file it came from.
    Url(String, PathBuf),
    ConfigFile(PathBuf),
}

/// Without explicit arguments look for `./server.txt`, then
/// `~/.config/vproxy/config.toml`, then `~/.config/vproxy/server.txt`.
fn discover_source() -> Result<Option<DiscoveredSource>> {
    let local = PathBuf::from("server.txt");
    if local.is_file() {
        info!("Using link from {}", local.display());
        return Ok(Some(DiscoveredSource::Url(read_url_file(&local)?, local)));
    }
    if let Some(dir) = user_config_dir() {
        let toml = dir.join("config.toml");
        if toml.is_file() {
            return Ok(Some(DiscoveredSource::ConfigFile(toml)));
        }
        let links = dir.join("server.txt");
        if links.is_file() {
            info!("Using link from {}", links.display());
            return Ok(Some(DiscoveredSource::Url(read_url_file(&links)?, links)));
        }
    }
    Ok(None)
}

/// Normalise a pasted link: trim, drop surrounding quotes, accept a bare value.
fn clean_pasted_link(raw: &str) -> String {
    let s = raw.trim();
    let s = s
        .strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        .or_else(|| s.strip_prefix('"').and_then(|s| s.strip_suffix('"')))
        .unwrap_or(s);
    s.trim().to_string()
}

/// First run: ask for a vless:// link on the terminal, validate it and save it
/// to `~/.config/vproxy/server.txt` so the next start needs no arguments.
fn ask_for_link() -> Result<String> {
    use std::io::{BufRead, IsTerminal, Write};
    if !std::io::stdin().is_terminal() {
        anyhow::bail!(
            "No config provided. Use --config, --url, --url-file, put a vless:// link into ./server.txt \
             or ~/.config/vproxy/server.txt, or run vproxy in a terminal to be asked for one"
        );
    }
    let mut stderr = std::io::stderr();
    let stdin = std::io::stdin();
    for attempt in 1..=3 {
        write!(stderr, "Paste your vless:// link and press Enter: ")?;
        stderr.flush()?;
        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            anyhow::bail!("No link entered");
        }
        let link = clean_pasted_link(&line);
        match VlessUrl::parse(&link) {
            Ok(url) => {
                if let Some(dir) = user_config_dir() {
                    let path = dir.join("server.txt");
                    match std::fs::create_dir_all(&dir)
                        .and_then(|_| std::fs::write(&path, format!("{link}\n")))
                    {
                        Ok(()) => info!(
                            "Saved to {} ({}); next time just run `vproxy`",
                            path.display(),
                            url.remark.as_deref().unwrap_or(&url.host)
                        ),
                        Err(e) => eprintln!(
                            "warning: could not save the link to {}: {e}",
                            path.display()
                        ),
                    }
                }
                return Ok(link);
            }
            Err(e) => {
                eprintln!(
                    "That does not look like a valid vless:// link ({e}). Attempt {attempt}/3."
                );
            }
        }
    }
    anyhow::bail!("No valid vless:// link entered")
}

/// Returns the config to start with and every server the TUI may switch to.
fn load_config(args: Args) -> Result<(Config, ServerList)> {
    let inbound_port = args.inbound_port.unwrap_or(1080);
    let mut links_file: Option<PathBuf> = args.url_file.clone();
    let mut vless_url = match (args.vless_url, args.url_file.as_ref()) {
        (Some(url), _) => Some(url),
        (None, Some(path)) => Some(read_url_file(path)?),
        (None, None) => None,
    };
    let mut config_path = args.config_path;
    if vless_url.is_none() && config_path.is_none() {
        match discover_source()? {
            Some(DiscoveredSource::Url(url, path)) => {
                vless_url = Some(url);
                links_file = Some(path);
            }
            Some(DiscoveredSource::ConfigFile(path)) => config_path = Some(path),
            None => {
                vless_url = Some(ask_for_link()?);
                links_file = user_config_dir().map(|d| d.join("server.txt"));
            }
        }
    }
    if let Some(url_str) = vless_url {
        let url = VlessUrl::parse(&url_str)?;
        let config = Config::from_vless_url(&url, inbound_port);
        config.validate()?;
        let servers = match links_file.as_deref().filter(|p| p.is_file()) {
            Some(path) => match ServerList::from_file(path, inbound_port) {
                Ok(list) => list,
                Err(e) => {
                    tracing::warn!("Server list not loaded ({e}); switching disabled");
                    ServerList::single(config.server.clone())
                }
            },
            None => ServerList::single(config.server.clone()),
        };
        if servers.len() > 1 {
            info!("{} servers available (switch in --tui)", servers.len());
        }

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

        Ok((config, servers))
    } else if let Some(config_path) = config_path {
        info!("Loading config from: {}", config_path.display());
        if config_path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("json"))
        {
            let config = vproxy::xray_import::load(&config_path, args.inbound_port)?;
            let servers = ServerList::single(config.server.clone());
            info!(
                "Imported Xray config: {} {}:{} ({} over {}{})",
                config.server.remark.as_deref().unwrap_or("-"),
                config.server.address,
                config.server.port,
                config.server.security,
                config.server.transport,
                if config.routing.rules.is_empty() {
                    String::new()
                } else {
                    format!(", {} routing rules", config.routing.rules.len())
                }
            );
            return Ok((config, servers));
        }
        let config = Config::load(&config_path)?;
        let servers = ServerList::single(config.server.clone());
        Ok((config, servers))
    } else {
        anyhow::bail!("No config provided");
    }
}

fn parse_args() -> Result<Args> {
    let mut config_path = None;
    let mut vless_url = None;
    let mut url_file = None;
    let mut inbound_port = None;
    let mut verbose = false;
    let mut check_config = false;
    let mut probe = false;
    let mut tun = false;
    let mut print_tun_config = false;
    let mut tui = false;

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
            Some("-f") | Some("--url-file") => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--url-file requires a path"))?;
                url_file = Some(PathBuf::from(value));
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
            Some("--tui") => tui = true,
            Some("-h") | Some("--help") => {
                print_help();
                std::process::exit(0);
            }
            Some("-V") | Some("--version") => {
                println!("vproxy {}", env!("CARGO_PKG_VERSION"));
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
        url_file,
        inbound_port,
        verbose,
        check_config,
        probe,
        tun,
        print_tun_config,
        tui,
    })
}

fn print_help() {
    println!(
        "\
vproxy - terminal VLESS client

Usage:
  vproxy [OPTIONS] [config-path|vless://...]

Without arguments vproxy uses ./server.txt, then ~/.config/vproxy/config.toml or
~/.config/vproxy/server.txt; if none exists it asks for a vless:// link (pasted as
is, no quoting) and saves it to ~/.config/vproxy/server.txt. A links file may hold
several servers (one per line): the first is used, --tui switches between them.

Options:
  -c, --config <PATH>       Path to TOML config, or an Xray/Happ JSON config (*.json)
  -u, --url <VLESS_URL>     VLESS link (vless://...), quote it in the shell
  -f, --url-file <PATH>     Read the vless:// link from a file (first non-comment line)
  -p, --inbound-port <PORT> Local inbound port (default: 1080)
  -v, --verbose             Enable debug logging
      --check-config        Validate config and exit
      --probe               Connect once, finish the transport (TLS/REALITY) handshake and exit
      --tun                 System-wide mode: run a sing-box TUN sidecar on top of the SOCKS5 inbound (needs root)
      --print-tun-config    Print the generated sing-box config for --tun and exit
      --tui                 Terminal UI with live counters and logs (q to quit)
  -h, --help                Show this help
  -V, --version             Print version

Examples:
  vproxy config.toml
  vproxy --url 'vless://uuid@host:port?security=tls'
  vproxy -u 'vless://...' -p 8080
  vproxy -f server.txt -p 1080
  sudo vproxy --tun -f server.txt
  sudo vproxy --tui --tun -f server.txt
"
    );
}

#[cfg(test)]
mod tests {
    use super::clean_pasted_link;

    #[test]
    fn pasted_links_are_cleaned() {
        assert_eq!(
            clean_pasted_link("  vless://a@b:1?x=1&y=2#n \n"),
            "vless://a@b:1?x=1&y=2#n"
        );
        assert_eq!(
            clean_pasted_link("'vless://a@b:1?x=1'"),
            "vless://a@b:1?x=1"
        );
        assert_eq!(clean_pasted_link("\"vless://a@b:1\"\r\n"), "vless://a@b:1");
    }
}
