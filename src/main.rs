use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, Level};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;
use vproxy::config::servers::config_from_link;
use vproxy::{serve, serve_with_server, ActiveServer, Config, ServerList};

/// Subcommands that run instead of the proxy.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Subcommand {
    InstallSingBox,
    Service(String),
}

#[derive(Clone)]
struct Args {
    command: Option<Subcommand>,
    /// `--sing-box <PATH>`: sing-box binary for TUN mode.
    sing_box: Option<PathBuf>,
    /// `--yes`: accept the default answer to every question.
    yes: bool,
    /// `--download`: fetch the sing-box release instead of using a package manager.
    download: bool,
    config_path: Option<PathBuf>,
    vless_url: Option<String>,
    url_file: Option<PathBuf>,
    inbound_port: Option<u16>,
    /// `-l ADDR`: address the local inbound listens on (default 127.0.0.1).
    listen: Option<String>,
    verbose: bool,
    check_config: bool,
    probe: bool,
    /// `--ping`: measure every server's handshake and exit.
    ping: bool,
    /// `-s URL`: fetch a subscription into the links file first.
    subscription: Option<String>,
    /// `--refresh`: update the links file from its subscription and exit.
    refresh: bool,
    tun: bool,
    print_tun_config: bool,
    tui: bool,
    /// `--log-file <PATH>`: where the TUI persists its log (`none` disables).
    log_file: Option<PathBuf>,
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
        let file = open_tui_log_file(args.log_file.as_deref());
        let logs = vproxy::ui::tui::LogBuffer::new(5000, file);
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(vproxy::ui::tui::LogSink(logs.clone()))
                    .with_timer(tracing_subscriber::fmt::time::uptime())
                    .with_ansi(false)
                    .with_target(false)
                    .with_filter(log_targets(level)),
            )
            .init();
        Some(logs)
    } else {
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stderr)
                    .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
                    .with_target(false)
                    .with_filter(log_targets(level)),
            )
            .init();
        None
    };

    if let Some(command) = &args.command {
        return run_subcommand(command.clone(), args).await;
    }
    info!("vproxy {} starting", env!("CARGO_PKG_VERSION"));
    let mut args = args;
    if prepare_subscription(&mut args).await? {
        return Ok(());
    }

    let (mut config, servers) = load_config(args.clone())?;
    if let Some(listen) = &args.listen {
        config.inbound.address = listen.clone();
    }
    if args.tun || args.print_tun_config {
        config.tun.enabled = true;
        config.validate()?;
    }
    if args.tun {
        config.tun.sing_box_path = resolve_sing_box(&args, &config.tun.sing_box_path).await?;
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
        let rendered = vproxy::system::tun::build_sing_box_config(
            config.as_ref(),
            vproxy::system::tun::current_process_name().as_deref(),
        )?;
        println!("{}", serde_json::to_string_pretty(&rendered)?);
        return Ok(());
    }

    if args.probe {
        let report = vproxy::proxy::runtime::probe_transport(config.as_ref()).await?;
        info!("{report}");
        return Ok(());
    }

    if args.ping {
        let limit = Duration::from_secs(config.runtime.connect_timeout_secs.clamp(1, 10));
        let list: Vec<_> = servers.entries.iter().map(|e| e.server.clone()).collect();
        let results = vproxy::proxy::runtime::ping_servers(&list, limit).await;
        let mut rows: Vec<(usize, &vproxy::ServerEntry, &Result<Duration, String>)> = servers
            .entries
            .iter()
            .zip(results.iter())
            .enumerate()
            .map(|(i, (e, r))| (i, e, r))
            .collect();
        rows.sort_by_key(|(_, _, r)| r.as_ref().map(|d| d.as_millis()).unwrap_or(u128::MAX));
        for (i, entry, result) in rows {
            let latency = match result {
                Ok(d) => format!("{:>6} ms", d.as_millis()),
                Err(e) => format!("   fail   {e}"),
            };
            println!(
                "{:<28} {:<22} {:<16} {}",
                entry.name,
                entry.server.endpoint(),
                entry.kind(),
                if i == 0 {
                    format!("{latency}  (current)")
                } else {
                    latency
                }
            );
        }
        return Ok(());
    }

    match tui_logs {
        Some(logs) => {
            let active = ActiveServer::new(config.server.clone());
            let server = tokio::spawn(serve_with_server(config.clone(), active.clone()));
            vproxy::ui::tui::run(config, servers, active, logs, server).await
        }
        None => serve(config).await,
    }
}

/// Find sing-box for TUN mode, offering to install it on a terminal.
async fn resolve_sing_box(args: &Args, configured: &str) -> Result<String> {
    if let Some(path) = &args.sing_box {
        return match vproxy::system::singbox::locate(&path.display().to_string()) {
            Some(p) => Ok(p.display().to_string()),
            None => anyhow::bail!("--sing-box {} is not an executable", path.display()),
        };
    }
    if let Some(found) = vproxy::system::singbox::locate(configured) {
        return Ok(found.display().to_string());
    }
    eprintln!("{}", vproxy::system::singbox::not_found_hint());
    if vproxy::system::singbox::ask("Install sing-box now?", true, args.yes)? {
        let path = vproxy::system::singbox::install(args.yes).await?;
        return Ok(path.display().to_string());
    }
    anyhow::bail!("sing-box is required for --tun")
}

/// `install-sing-box` and `service ...`.
async fn run_subcommand(command: Subcommand, args: Args) -> Result<()> {
    match command {
        Subcommand::InstallSingBox => {
            let path = if args.download {
                vproxy::system::singbox::download_release(args.yes).await?
            } else {
                vproxy::system::singbox::install(args.yes).await?
            };
            info!("sing-box ready at {}", path.display());
            Ok(())
        }
        Subcommand::Service(action) => match action.as_str() {
            "install" => service_install(args).await,
            "uninstall" | "remove" => {
                let p = vproxy::system::service::uninstall(args.tun)?;
                info!("Service removed ({})", p.unit.display());
                Ok(())
            }
            "status" => {
                print!("{}", vproxy::system::service::status(args.tun)?);
                Ok(())
            }
            "logs" | "log" => vproxy::system::service::logs(args.tun),
            other => {
                anyhow::bail!("unknown service action {other:?} (install, uninstall, status, logs)")
            }
        },
    }
}

/// Resolve the config source to absolute paths, check it loads, pick the
/// sing-box binary for `--tun`, then install the launchd/systemd service.
async fn service_install(args: Args) -> Result<()> {
    use vproxy::system::service::absolute;
    let mut service_args: Vec<String> = Vec::new();
    let mut check = args.clone();
    check.command = None;
    if let Some(path) = &args.config_path {
        let path = absolute(path)?;
        service_args.extend(["-c".to_string(), path.display().to_string()]);
        check.config_path = Some(path);
    } else if let Some(file) = &args.url_file {
        let file = absolute(file)?;
        service_args.extend(["-f".to_string(), file.display().to_string()]);
        check.url_file = Some(file);
    } else if let Some(link) = &args.vless_url {
        // The service cannot take the link on its command line safely; keep it in a file.
        let dir = vproxy::system::singbox::real_home()
            .map(|h| h.join(".config").join("vproxy"))
            .ok_or_else(|| anyhow::anyhow!("HOME is not set"))?;
        let file = dir.join("service.txt");
        vproxy::config::write_private(&file, format!("{link}\n"))?;
        service_args.extend(["-f".to_string(), file.display().to_string()]);
        check.vless_url = None;
        check.url_file = Some(file);
    } else {
        // Same discovery as a plain `vproxy`, but the daemon has no cwd of ours.
        match discover_source()? {
            Some(DiscoveredSource::Url(_, path)) => {
                let path = absolute(&path)?;
                service_args.extend(["-f".to_string(), path.display().to_string()]);
                check.url_file = Some(path);
            }
            Some(DiscoveredSource::ConfigFile(path)) => {
                let path = absolute(&path)?;
                service_args.extend(["-c".to_string(), path.display().to_string()]);
                check.config_path = Some(path);
            }
            None => anyhow::bail!(
                "No config to install: pass -c config.toml, -f server.txt or -u 'vless://...'"
            ),
        }
    }
    if let Some(port) = args.inbound_port {
        service_args.extend(["-p".to_string(), port.to_string()]);
    }
    if let Some(listen) = &args.listen {
        service_args.extend(["-l".to_string(), listen.clone()]);
    }
    let (mut config, _) = load_config(check.clone())?;
    if args.tun {
        config.tun.enabled = true;
        config.validate()?;
        let sing_box = resolve_sing_box(&args, &config.tun.sing_box_path).await?;
        service_args.push("--tun".to_string());
        service_args.extend(["--sing-box".to_string(), sing_box]);
    } else {
        config.validate()?;
    }
    if args.verbose {
        service_args.push("-v".to_string());
    }
    let binary = std::env::current_exe()?
        .canonicalize()
        .context("cannot resolve the vproxy binary path")?;
    let plan = vproxy::system::service::ServicePlan {
        tun: args.tun,
        binary,
        args: service_args,
    };
    let p = vproxy::system::service::install(&plan)?;
    info!(
        "Service installed and started: {} ({} {})",
        p.unit.display(),
        plan.binary.display(),
        plan.args.join(" ")
    );
    info!(
        "Logs: {}. Remove with: {}vproxy service uninstall{}",
        p.log.display(),
        if args.tun { "sudo " } else { "" },
        if args.tun { " --tun" } else { "" }
    );
    Ok(())
}

/// The TUI keeps logs in memory and mirrors them to a size-capped file
/// (`~/.config/vproxy/vproxy.log`, 5 MiB × 3 by default). `none` disables it.
/// Failing to open the file is reported after the subscriber is up, not fatal.
fn open_tui_log_file(path: Option<&Path>) -> Option<vproxy::logging::RotatingFile> {
    if path.map(|p| p.as_os_str() == "none").unwrap_or(false) {
        return None;
    }
    let path = match path {
        Some(p) => p.to_path_buf(),
        None => user_config_dir()?.join("vproxy.log"),
    };
    match vproxy::logging::RotatingFile::open(
        &path,
        vproxy::logging::DEFAULT_MAX_BYTES,
        vproxy::logging::DEFAULT_KEEP,
    ) {
        Ok(mut f) => {
            let _ = f.write_session_header();
            Some(f)
        }
        Err(e) => {
            eprintln!("warning: cannot open log file {}: {e}", path.display());
            None
        }
    }
}

/// Our own logs at `level`; the HTTP and TLS libraries only when something
/// is wrong (their debug output drowns everything else).
fn log_targets(level: Level) -> tracing_subscriber::filter::Targets {
    tracing_subscriber::filter::Targets::new()
        .with_default(level)
        .with_target("h2", Level::WARN)
        .with_target("hyper", Level::WARN)
        .with_target("hyper_util", Level::WARN)
        .with_target("tungstenite", Level::INFO)
        .with_target("tokio_tungstenite", Level::INFO)
        .with_target("rustls", Level::INFO)
}

/// The links file a run will use: `-f`, else the discovered one.
fn links_file_in_use(args: &Args) -> Option<PathBuf> {
    if let Some(f) = &args.url_file {
        return Some(f.clone());
    }
    if args.config_path.is_some() || args.vless_url.is_some() {
        return None;
    }
    let local = PathBuf::from("server.txt");
    if local.is_file() {
        return Some(local);
    }
    let dir = user_config_dir()?;
    if dir.join("config.toml").is_file() {
        return None;
    }
    let links = dir.join("server.txt");
    links.is_file().then_some(links)
}

/// `-s URL`, `--refresh` and the automatic refresh of a stale subscription.
/// Returns true when the run should end here (`--refresh`).
async fn prepare_subscription(args: &mut Args) -> Result<bool> {
    let inbound_port = args.inbound_port.unwrap_or(1080);
    if let Some(url) = args.subscription.clone() {
        let file = args.url_file.clone().unwrap_or_else(|| {
            user_config_dir()
                .map(|d| d.join("server.txt"))
                .unwrap_or_else(|| PathBuf::from("server.txt"))
        });
        info!(
            "Fetching subscription {}",
            vproxy::config::subscription::redact_url(&url)
        );
        let sub = vproxy::config::subscription::fetch(&url).await?;
        if let Some(dir) = file.parent().filter(|d| !d.as_os_str().is_empty()) {
            vproxy::config::create_private_dir(dir)?;
        }
        let mut list = if file.is_file() {
            ServerList::from_file(&file, inbound_port).unwrap_or_else(|_| ServerList {
                file: Some(file.clone()),
                ..Default::default()
            })
        } else {
            vproxy::config::write_private(&file, "")?;
            ServerList {
                file: Some(file.clone()),
                ..Default::default()
            }
        };
        list.apply_subscription(&sub, inbound_port)?;
        info!("{}", subscription_summary(&sub, &list, &file));
        args.url_file = Some(file);
        args.subscription = None;
    }

    let Some(file) = links_file_in_use(args) else {
        if args.refresh {
            anyhow::bail!(
                "--refresh needs a links file with a subscription (start once with -s URL)"
            );
        }
        return Ok(false);
    };
    let Ok(content) = std::fs::read_to_string(&file) else {
        return Ok(false);
    };
    let Some(meta) = vproxy::config::subscription::Meta::from_lines(content.lines()) else {
        if args.refresh {
            anyhow::bail!(
                "{} has no `# subscription:` header; start once with -s URL",
                file.display()
            );
        }
        return Ok(false);
    };
    if args.refresh || meta.is_stale() {
        if !args.refresh {
            info!(
                "Subscription {} ({}): refreshing",
                meta.title
                    .clone()
                    .unwrap_or_else(|| vproxy::config::subscription::redact_url(&meta.url)),
                meta.age_text()
            );
        }
        match vproxy::config::subscription::fetch(&meta.url).await {
            Ok(sub) => {
                let mut list = ServerList::from_file(&file, inbound_port)?;
                list.apply_subscription(&sub, inbound_port)?;
                info!("{}", subscription_summary(&sub, &list, &file));
            }
            Err(e) if args.refresh => return Err(e),
            Err(e) => tracing::warn!("Subscription refresh failed, using the saved list: {e:#}"),
        }
    }
    Ok(args.refresh)
}

fn subscription_summary(
    sub: &vproxy::config::subscription::Subscription,
    list: &ServerList,
    file: &std::path::Path,
) -> String {
    let mut text = format!(
        "Subscription {}: {} servers saved to {}",
        sub.meta.title.as_deref().unwrap_or(&sub.meta.url),
        list.len(),
        file.display()
    );
    if sub.skipped > 0 {
        text.push_str(&format!(
            " ({} links of other protocols skipped)",
            sub.skipped
        ));
    }
    if let Some(info) = &sub.meta.userinfo {
        let summary = info.summary();
        if !summary.is_empty() {
            text.push_str(&format!("; {summary}"));
        }
    }
    text
}

/// First `vless://` or `vpn://` link in a text file (blank lines and `#`
/// comment lines skipped), or the `# active:` link when the file names one.
fn read_url_file(path: &PathBuf) -> Result<String> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("Cannot read {}: {e}", path.display()))?;
    if let Some(active) = vproxy::config::servers::active_link(&content) {
        return Ok(active);
    }
    content
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .ok_or_else(|| anyhow::anyhow!("No vless:// or vpn:// link found in {}", path.display()))
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

/// First run: ask for a vless:// (or Amnezia vpn://) link on the terminal, validate it and save it
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
        write!(
            stderr,
            "Paste your vless:// (or Amnezia vpn://) link and press Enter: "
        )?;
        stderr.flush()?;
        let mut line = String::new();
        if stdin.lock().read_line(&mut line)? == 0 {
            anyhow::bail!("No link entered");
        }
        let link = clean_pasted_link(&line);
        match config_from_link(&link, 1080) {
            Ok(config) => {
                if let Some(dir) = user_config_dir() {
                    let path = dir.join("server.txt");
                    match vproxy::config::write_private(&path, format!("{link}\n")) {
                        Ok(()) => info!(
                            "Saved to {} ({}); next time just run `vproxy`",
                            path.display(),
                            config
                                .server
                                .remark
                                .as_deref()
                                .unwrap_or(&config.server.address)
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
        let config = config_from_link(&url_str, inbound_port)?;
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

        if let Some(remark) = config.server.remark.as_deref().filter(|r| !r.is_empty()) {
            info!("Using VLESS server: {}", remark);
        }
        info!(
            "Server: {}:{} (security: {}, transport: {})",
            config.server.address,
            config.server.port,
            config.server.security,
            config.server.transport
        );

        Ok((config, servers))
    } else if let Some(config_path) = config_path {
        info!("Loading config from: {}", config_path.display());
        if config_path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("vpn"))
        {
            let config =
                vproxy::config::import::amnezia::load_file(&config_path, args.inbound_port)?;
            let servers = ServerList::single(config.server.clone());
            info!(
                "Imported Amnezia config: {} {}:{} ({} over {})",
                config.server.remark.as_deref().unwrap_or("-"),
                config.server.address,
                config.server.port,
                config.server.security,
                config.server.transport
            );
            return Ok((config, servers));
        }
        if config_path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("json"))
        {
            let config = vproxy::config::import::xray::load(&config_path, args.inbound_port)?;
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
    let mut listen = None;
    let mut verbose = false;
    let mut check_config = false;
    let mut probe = false;
    let mut ping = false;
    let mut subscription = None;
    let mut refresh = false;
    let mut tun = false;
    let mut print_tun_config = false;
    let mut tui = false;
    let mut log_file = None;
    let mut command = None;
    let mut sing_box = None;
    let mut yes = false;
    let mut download = false;

    let mut args = std::env::args_os().skip(1).peekable();
    match args.peek().and_then(|a| a.to_str()) {
        Some("install-sing-box") => {
            args.next();
            command = Some(Subcommand::InstallSingBox);
        }
        Some("service") => {
            args.next();
            let action = args
                .next()
                .and_then(|a| a.to_str().map(str::to_string))
                .ok_or_else(|| {
                    anyhow::anyhow!("service needs an action: install, uninstall, status, logs")
                })?;
            command = Some(Subcommand::Service(action));
        }
        _ => {}
    }
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
                    .ok_or_else(|| anyhow::anyhow!("--url requires a vless:// or vpn:// link"))?;
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
            Some("-l") | Some("--listen") => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--listen requires an address"))?;
                let value = value
                    .into_string()
                    .map_err(|_| anyhow::anyhow!("Invalid listen address"))?;
                value.parse::<std::net::IpAddr>().map_err(|_| {
                    anyhow::anyhow!("--listen must be an IP address, got {value:?}")
                })?;
                listen = Some(value);
            }
            Some("-v") | Some("--verbose") => verbose = true,
            Some("--check-config") => check_config = true,
            Some("--probe") => probe = true,
            Some("--ping") => ping = true,
            Some("--refresh") => refresh = true,
            Some("-s") | Some("--subscription") => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--subscription requires a URL"))?;
                subscription = Some(
                    value
                        .into_string()
                        .map_err(|_| anyhow::anyhow!("Invalid URL encoding"))?,
                );
            }
            Some("--tun") => tun = true,
            Some("--print-tun-config") => print_tun_config = true,
            Some("--tui") => tui = true,
            Some("--log-file") => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--log-file requires a path or none"))?;
                log_file = Some(PathBuf::from(value));
            }
            Some("--sing-box") => {
                let value = args
                    .next()
                    .ok_or_else(|| anyhow::anyhow!("--sing-box requires a path"))?;
                sing_box = Some(PathBuf::from(value));
            }
            Some("-y") | Some("--yes") => yes = true,
            Some("--download") => download = true,
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
            Some(value) if value.starts_with("vless://") || value.starts_with("vpn://") => {
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
        command,
        sing_box,
        yes,
        download,
        config_path,
        vless_url,
        url_file,
        inbound_port,
        listen,
        verbose,
        check_config,
        probe,
        ping,
        subscription,
        refresh,
        tun,
        print_tun_config,
        tui,
        log_file,
    })
}

fn print_help() {
    println!(
        "\
vproxy - terminal VLESS client

Usage:
  vproxy [OPTIONS] [config-path|vless://...|vpn://...]
  vproxy install-sing-box [--yes] [--download]
  vproxy service install|uninstall|status|logs [--tun] [config options]

Without arguments vproxy uses ./server.txt, then ~/.config/vproxy/config.toml or
~/.config/vproxy/server.txt; if none exists it asks for a vless:// link (pasted as
is, no quoting) and saves it to ~/.config/vproxy/server.txt. A links file may hold
several servers (one per line): the first is used, --tui switches between them.

Options:
  -c, --config <PATH>       Path to TOML config, an Xray/Happ JSON config (*.json) or an Amnezia *.vpn file
  -u, --url <LINK>          vless:// link or Amnezia vpn:// link, quote it in the shell
  -f, --url-file <PATH>     Read the link from a file (first non-comment line)
  -s, --subscription <URL>  Fetch a subscription (base64 or plain list of links) into the links file
                            (-f or ~/.config/vproxy/server.txt), then run; refreshed automatically
                            when older than the provider's interval, by u in the TUI, or --refresh
      --refresh             Update the links file from its subscription and exit
  -p, --inbound-port <PORT> Local inbound port (default: 1080)
  -l, --listen <ADDR>       Inbound address (default: 127.0.0.1; 0.0.0.0 inside a container)
  -v, --verbose             Enable debug logging
      --check-config        Validate config and exit
      --probe               Connect once, finish the transport (TLS/REALITY) handshake and exit
      --ping                Measure the handshake latency of every server in the list and exit
      --tun                 System-wide mode: run a sing-box TUN sidecar on top of the SOCKS5 inbound (needs root)
      --print-tun-config    Print the generated sing-box config for --tun and exit
      --tui                 Terminal UI with live counters and logs (q to quit); the log is also
                            written to ~/.config/vproxy/vproxy.log (5 MiB, 3 rotated copies kept)
      --log-file <PATH>     --tui: log file instead of the default; none keeps logs in memory only
      --sing-box <PATH>     sing-box binary for --tun (default: ~/.config/vproxy/bin, PATH, Homebrew, Happ)
  -y, --yes                 Answer yes to questions (install prompts)
      --download            install-sing-box: skip package managers, download the GitHub release
  -h, --help                Show this help
  -V, --version             Print version

Commands:
  install-sing-box          Install sing-box for TUN mode: Homebrew / the official repo script
                            when available, otherwise the GitHub release into ~/.config/vproxy/bin
  service install           Run vproxy in the background (launchd / systemd), start at login or boot;
                            with --tun a system daemon (sudo). uninstall, status and logs manage it

Examples:
  vproxy config.toml
  vproxy --url 'vless://uuid@host:port?security=tls'
  vproxy -u 'vless://...' -p 8080
  vproxy -f server.txt -p 1080
  vproxy --ping -f server.txt                     # latency of every server in the file
  vproxy -s 'https://provider/sub/token' --tui    # subscription → ~/.config/vproxy/server.txt
  sudo vproxy --tun -f server.txt
  sudo vproxy --tui --tun -f server.txt
  vproxy service install -f server.txt            # background local proxy, starts at login
  sudo vproxy service install --tun -f server.txt # background system-wide VPN
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
