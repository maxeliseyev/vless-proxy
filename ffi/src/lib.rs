//! C ABI over the vproxy core for the Ratatosk iOS Packet Tunnel; the
//! header is `include/ratatosk.h`, the Swift wrapper `swift/RatatoskCore.swift`.
//!
//! One [`Tunnel`] owns a small tokio runtime running the netstack. The host
//! pushes packets it read from `packetFlow` with [`ratatosk_push_packet`] and
//! gets the stack's packets back through the callback given to
//! [`ratatosk_start`], to write to `packetFlow`. Both may be used from any
//! thread; [`ratatosk_stop`] must not be called from the callback.
//!
//! Outside a tunnel, for the app as well: [`ratatosk_ping`] times server
//! handshakes and [`ratatosk_fetch_subscription`] downloads a subscription.
//! Both block and return a JSON string to free with [`ratatosk_string_free`].

use std::ffi::{c_char, c_void, CStr, CString};
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use vproxy::netstack::device::channel_device;
use vproxy::netstack::fakedns::{FakeDns, DEFAULT_POOL};
use vproxy::netstack::flows::{FlowLog, DEFAULT_CAPACITY};
use vproxy::netstack::Netstack;
use vproxy::proxy::stats::{human_bytes, STATS};
use vproxy::{ActiveServer, ProxyClient};

/// Names handed out by the fake DNS before the oldest is reused.
const FAKE_DNS_CAPACITY: u32 = 16_384;

/// Called with each IP packet the stack sends towards the system.
pub type PacketCallback = extern "C" fn(ctx: *mut c_void, packet: *const u8, len: usize);
/// Called with each log line (NUL-terminated, valid only during the call).
pub type LogCallback = extern "C" fn(ctx: *mut c_void, level: u8, line: *const c_char);

/// The host's context pointer, passed back untouched. The host promises it
/// stays valid and usable from any thread until `ratatosk_stop` returns.
#[derive(Clone, Copy)]
struct HostContext(*mut c_void);
unsafe impl Send for HostContext {}
unsafe impl Sync for HostContext {}

pub struct Tunnel {
    runtime: Option<tokio::runtime::Runtime>,
    connector: ProxyClient,
    flows: Arc<FlowLog>,
    to_stack: mpsc::Sender<Vec<u8>>,
    stop: watch::Sender<bool>,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct RatatoskStats {
    pub active: u64,
    pub total: u64,
    pub up: u64,
    pub down: u64,
    pub errors: u64,
}

/// Start the tunnel core for a `vless://`, `h3://` or `vpn://` link. Returns NULL on
/// failure with the reason in `error` (truncated, NUL-terminated).
///
/// # Safety
/// `link` is a NUL-terminated string; `error` is NULL or `error_len`
/// writable bytes; `ctx` is valid for `on_packet` until `ratatosk_stop`.
#[no_mangle]
pub unsafe extern "C" fn ratatosk_start(
    link: *const c_char,
    mtu: u16,
    on_packet: PacketCallback,
    ctx: *mut c_void,
    error: *mut c_char,
    error_len: usize,
) -> *mut Tunnel {
    let link = if link.is_null() {
        Err(anyhow::anyhow!("link is NULL"))
    } else {
        CStr::from_ptr(link)
            .to_str()
            .map_err(|_| anyhow::anyhow!("link is not UTF-8"))
    };
    match link.and_then(|link| start(link, mtu, on_packet, HostContext(ctx))) {
        Ok(tunnel) => Box::into_raw(Box::new(tunnel)),
        Err(e) => {
            write_error(error, error_len, &format!("{e:#}"));
            std::ptr::null_mut()
        }
    }
}

fn start(
    link: &str,
    mtu: u16,
    on_packet: PacketCallback,
    ctx: HostContext,
) -> anyhow::Result<Tunnel> {
    let mut config = vproxy::config::servers::config_from_link(link, 0)?;
    if config.needs_xray_sidecar()? {
        anyhow::bail!(
            "this server needs xray-core (XTLS Vision over plain TLS), which iOS cannot run"
        );
    }
    // A phone opens dozens of connections at once. Without Vision the server
    // accepts Mux.Cool, so they share a few server connections instead of
    // each costing a handshake. Vision cannot be multiplexed; there the
    // handshake limiter (runtime.max_parallel_handshakes) paces them.
    if config.server.vision_flow()?.is_none() {
        config.mux.enabled = true;
    }
    // Two workers: the Packet Tunnel extension has a tight memory budget.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("ratatosk")
        .enable_all()
        .build()?;
    let _guard = runtime.enter();
    let connector = ProxyClient::new(
        ActiveServer::new(config.server.clone()),
        config.dns.clone(),
        config.runtime.clone(),
        &config.routing,
        &config.mux,
    )?;
    let flows = Arc::new(FlowLog::new(DEFAULT_CAPACITY));
    let netstack = Netstack {
        connector: connector.clone(),
        dns: Arc::new(FakeDns::new(DEFAULT_POOL, FAKE_DNS_CAPACITY)),
        mtu,
        flows: flows.clone(),
    };
    let (device, mut host) = channel_device();
    let (stop, shutdown) = watch::channel(false);
    runtime.spawn(async move {
        if let Err(e) = netstack.run(device, shutdown).await {
            tracing::error!("netstack stopped: {e:#}");
        }
    });
    runtime.spawn(async move {
        let ctx = ctx;
        while let Some(packet) = host.from_stack.recv().await {
            on_packet(ctx.0, packet.as_ptr(), packet.len());
        }
    });
    runtime.spawn(log_stats_every(STATS_EVERY));
    tracing::info!("Tunnel core started for {}", config.server.endpoint());
    let server = &config.server;
    tracing::info!(
        "server: {} {} flow {} sni {} fp {} mux {}",
        server.security,
        server.transport,
        server.flow.as_deref().unwrap_or("-"),
        server.sni.as_deref().unwrap_or("-"),
        server.fingerprint.as_deref().unwrap_or("-"),
        if config.mux.enabled { "on" } else { "off" },
    );
    Ok(Tunnel {
        runtime: Some(runtime),
        connector,
        flows,
        to_stack: host.to_stack,
        stop,
    })
}

/// Hand one IP packet read from the system to the stack. Returns false when
/// it was dropped (queue full or tunnel stopping).
///
/// # Safety
/// `tunnel` comes from `ratatosk_start`; `packet` points to `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn ratatosk_push_packet(
    tunnel: *const Tunnel,
    packet: *const u8,
    len: usize,
) -> bool {
    let Some(tunnel) = tunnel.as_ref() else {
        return false;
    };
    if packet.is_null() || len == 0 {
        return false;
    }
    let bytes = std::slice::from_raw_parts(packet, len).to_vec();
    tunnel.to_stack.try_send(bytes).is_ok()
}

/// The device's network changed (the host's path monitor says so): an h3
/// connection moves to a new socket on the new path instead of timing out.
///
/// # Safety
/// `tunnel` comes from `ratatosk_start`.
#[no_mangle]
pub unsafe extern "C" fn ratatosk_network_changed(tunnel: *const Tunnel) {
    let Some(tunnel) = tunnel.as_ref() else {
        return;
    };
    if let Some(runtime) = tunnel.runtime.as_ref() {
        let connector = tunnel.connector.clone();
        runtime.spawn(async move { connector.network_changed().await });
    }
}

/// Process-wide traffic counters.
///
/// # Safety
/// `out` is NULL or points to a writable `RatatoskStats`.
#[no_mangle]
pub unsafe extern "C" fn ratatosk_stats(out: *mut RatatoskStats) {
    let Some(out) = out.as_mut() else { return };
    let s = STATS.snapshot();
    *out = RatatoskStats {
        active: s.active as u64,
        total: s.total,
        up: s.up,
        down: s.down,
        errors: s.errors,
    };
}

/// The newest `max` flows, newest first, as a JSON array of
/// `{id, t, proto, host, port, route, up, down, open, failed}` (`t` in unix
/// ms). Writes it NUL-terminated into `buf` when it fits and returns its
/// length without the NUL; a return of `buf_len` or more means it did not
/// fit and nothing was written.
///
/// # Safety
/// `tunnel` comes from `ratatosk_start`; `buf` is NULL or `buf_len` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn ratatosk_flows_json(
    tunnel: *const Tunnel,
    max: usize,
    buf: *mut c_char,
    buf_len: usize,
) -> usize {
    let Some(tunnel) = tunnel.as_ref() else {
        return 0;
    };
    let json = tunnel.flows.to_json(max);
    if !buf.is_null() && json.len() < buf_len {
        std::ptr::copy_nonoverlapping(json.as_ptr(), buf.cast::<u8>(), json.len());
        *buf.add(json.len()) = 0;
    }
    json.len()
}

/// Stop the tunnel and free it; waits up to two seconds for tasks to end.
///
/// # Safety
/// `tunnel` comes from `ratatosk_start` and is not used afterwards. Not to
/// be called from inside a callback.
#[no_mangle]
pub unsafe extern "C" fn ratatosk_stop(tunnel: *mut Tunnel) {
    if tunnel.is_null() {
        return;
    }
    let mut tunnel = Box::from_raw(tunnel);
    // Flows only log when they end; those cut by the stop would go unsaid.
    for flow in tunnel.flows.still_open() {
        tracing::info!("flow {}", flow.summary());
    }
    log_stats();
    let _ = tunnel.stop.send(true);
    if let Some(runtime) = tunnel.runtime.take() {
        runtime.shutdown_timeout(Duration::from_secs(2));
    }
    tracing::info!("Tunnel core stopped");
}

/// How often the traffic counters go to the log while they change.
const STATS_EVERY: Duration = Duration::from_secs(30);

async fn log_stats_every(period: Duration) {
    let mut last = None;
    let mut ticks = tokio::time::interval(period);
    ticks.tick().await;
    loop {
        ticks.tick().await;
        let s = STATS.snapshot();
        let now = (s.active, s.total, s.up, s.down, s.errors);
        if last != Some(now) {
            last = Some(now);
            log_stats();
        }
    }
}

/// `stats: 4 open · 57 total · up 1.2 MiB · down 31.0 MiB · 2 errors`
fn log_stats() {
    let s = STATS.snapshot();
    tracing::info!(
        "stats: {} open · {} total · up {} · down {} · {} errors",
        s.active,
        s.total,
        human_bytes(s.up),
        human_bytes(s.down),
        s.errors
    );
}

/// Send the core's logs to `on_log`, up to `max_level` (1 error .. 5 trace).
/// Only the first call in a process takes effect.
///
/// # Safety
/// `ctx` stays valid for `on_log` for the life of the process.
#[no_mangle]
pub unsafe extern "C" fn ratatosk_set_logger(on_log: LogCallback, ctx: *mut c_void, max_level: u8) {
    let level = match max_level {
        0 | 1 => tracing::Level::ERROR,
        2 => tracing::Level::WARN,
        3 => tracing::Level::INFO,
        4 => tracing::Level::DEBUG,
        _ => tracing::Level::TRACE,
    };
    let ctx = HostContext(ctx);
    let _ = tracing_subscriber::fmt()
        .with_max_level(level)
        .with_ansi(false)
        .without_time()
        .with_target(false)
        .with_writer(move || LineWriter {
            on_log,
            ctx,
            buf: Vec::new(),
        })
        .try_init();
    // A panic would otherwise go to stderr, which nobody reads on iOS; the
    // host writes this line to its log before the process can go away.
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current();
        tracing::error!("panic in {}: {info}", thread.name().unwrap_or("?"));
        default(info);
    }));
}

/// Handshake time to each server of `links_json`, a JSON array of link
/// strings, all measured at once from this process with `timeout_ms` each:
/// a JSON array of milliseconds, `null` where the link is bad or the server
/// did not answer. NULL when `links_json` is not such an array.
///
/// Blocks. Inside the Packet Tunnel the sockets bypass the tunnel; an app
/// with the VPN on would measure through it, so it asks the extension.
///
/// # Safety
/// `links_json` is a NUL-terminated string. Free the result with
/// `ratatosk_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ratatosk_ping(links_json: *const c_char, timeout_ms: u32) -> *mut c_char {
    let Some(links) = c_str(links_json).and_then(|s| serde_json::from_str::<Vec<String>>(s).ok())
    else {
        return std::ptr::null_mut();
    };
    let servers: Vec<Option<vproxy::ServerConfig>> = links
        .iter()
        .map(|link| {
            vproxy::config::servers::config_from_link(link, 0)
                .ok()
                .map(|c| c.server)
        })
        .collect();
    let valid: Vec<vproxy::ServerConfig> = servers.iter().flatten().cloned().collect();
    let limit = Duration::from_millis(u64::from(timeout_ms.max(1)));
    let measured = match blocking_runtime() {
        Ok(runtime) => runtime.block_on(vproxy::proxy::runtime::ping_servers(&valid, limit)),
        Err(_) => return std::ptr::null_mut(),
    };
    let mut measured = measured.into_iter();
    let out: Vec<Option<u64>> = servers
        .iter()
        .map(|server| {
            server.as_ref()?;
            measured.next()?.ok().map(|d| d.as_millis() as u64)
        })
        .collect();
    owned_string(serde_json::Value::from(out).to_string())
}

/// Download the subscription at `url` (an `https://` link from a panel):
/// JSON `{title, links, skipped, upload, download, total, expire,
/// interval_hours}` (`title` and the traffic fields may be null; bytes and
/// unix seconds), or `{error}`. Blocks.
///
/// # Safety
/// `url` is a NUL-terminated string. Free the result with
/// `ratatosk_string_free`.
#[no_mangle]
pub unsafe extern "C" fn ratatosk_fetch_subscription(url: *const c_char) -> *mut c_char {
    let result = match (c_str(url), blocking_runtime()) {
        (None, _) => Err(anyhow::anyhow!("url is NULL or not UTF-8")),
        (_, Err(e)) => Err(e.into()),
        (Some(url), Ok(runtime)) => runtime.block_on(vproxy::config::subscription::fetch(url)),
    };
    let json = match result {
        Ok(sub) => {
            let info = sub.meta.userinfo.unwrap_or_default();
            serde_json::json!({
                "title": sub.meta.title,
                "links": sub.links,
                "skipped": sub.skipped,
                "upload": info.upload,
                "download": info.download,
                "total": info.total,
                "expire": info.expire,
                "interval_hours": sub.meta.interval_hours,
            })
        }
        Err(e) => serde_json::json!({ "error": format!("{e:#}") }),
    };
    owned_string(json.to_string())
}

/// Free a string returned by `ratatosk_ping` or `ratatosk_fetch_subscription`.
///
/// # Safety
/// `s` is NULL or such a string, not freed before.
#[no_mangle]
pub unsafe extern "C" fn ratatosk_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

unsafe fn c_str<'a>(s: *const c_char) -> Option<&'a str> {
    (!s.is_null())
        .then(|| CStr::from_ptr(s).to_str().ok())
        .flatten()
}

/// A runtime for one blocking call from a host thread.
fn blocking_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

fn owned_string(s: String) -> *mut c_char {
    CString::new(s)
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

/// `vproxy-ffi <version>`, static.
#[no_mangle]
pub extern "C" fn ratatosk_version() -> *const c_char {
    concat!("vproxy-ffi ", env!("CARGO_PKG_VERSION"), "\0")
        .as_ptr()
        .cast()
}

/// Collects one formatted event and hands it to the host on drop.
struct LineWriter {
    on_log: LogCallback,
    ctx: HostContext,
    buf: Vec<u8>,
}

impl Write for LineWriter {
    fn write(&mut self, data: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(data);
        Ok(data.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for LineWriter {
    fn drop(&mut self) {
        while self.buf.last().is_some_and(|b| *b == b'\n') {
            self.buf.pop();
        }
        if self.buf.is_empty() {
            return;
        }
        self.buf.retain(|b| *b != 0);
        let start = self.buf.iter().take_while(|b| **b == b' ').count();
        self.buf.drain(..start);
        let level = match self.buf.split(|b| *b == b' ').find(|w| !w.is_empty()) {
            Some(b"ERROR") => 1,
            Some(b"WARN") => 2,
            Some(b"INFO") => 3,
            Some(b"DEBUG") => 4,
            _ => 5,
        };
        self.buf.push(0);
        (self.on_log)(self.ctx.0, level, self.buf.as_ptr().cast());
    }
}

unsafe fn write_error(error: *mut c_char, error_len: usize, message: &str) {
    if error.is_null() || error_len == 0 {
        return;
    }
    let bytes = message.as_bytes();
    let n = bytes.len().min(error_len - 1);
    std::ptr::copy_nonoverlapping(bytes.as_ptr(), error.cast::<u8>(), n);
    *error.add(n) = 0;
}
