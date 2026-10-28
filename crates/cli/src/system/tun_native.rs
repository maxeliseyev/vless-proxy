//! Native TUN mode (macOS): vproxy owns the utun interface and runs the
//! in-process netstack (`vproxy_core::netstack`) directly — no sing-box.
//!
//! The netstack turns tunnelled packets into routed connections through
//! `ProxyClient`. This module does the OS plumbing sing-box used to do: create
//! the utun, point the default route and DNS at it, keep vproxy's own sockets
//! off the tunnel, and restore all of it on exit.
//!
//! Loop avoidance: the one connection to the server is kept off the tunnel by a
//! host route via the original gateway; `direct`-routed flows egress the
//! physical interface because `ProxyClient` is given its index (`IP_BOUND_IF`,
//! see `vproxy_core::proxy::egress`); LAN/private ranges are routed around the
//! tunnel outright.

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::watch;
use vproxy_core::Config;

/// Entry point used by the process lifecycle (`crate::runtime`).
pub async fn run(config: Arc<Config>, shutdown: watch::Receiver<bool>) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        macos::run(config, shutdown).await
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (config, shutdown);
        anyhow::bail!(
            "native --tun is only supported on macOS right now (Linux support is planned)"
        )
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use anyhow::{bail, Context, Result};
    use std::net::Ipv4Addr;
    use std::process::Command;
    use std::sync::Arc;
    use tokio::sync::watch;
    use tracing::{info, warn};
    use vproxy_core::netstack::device::channel_device;
    use vproxy_core::netstack::fakedns::{FakeDns, DEFAULT_POOL};
    use vproxy_core::netstack::flows::{FlowLog, DEFAULT_CAPACITY};
    use vproxy_core::netstack::Netstack;
    use vproxy_core::proxy::egress::Egress;
    use vproxy_core::proxy::runtime::ProxyClient;
    use vproxy_core::{ActiveServer, Config};

    const FAKE_DNS_CAPACITY: u32 = 16_384;
    /// Routed around the tunnel via the original gateway (LAN, link-local,
    /// multicast). The tunnel's own /30 is more specific, so it still wins.
    const LOCAL_NETS: [&str; 5] = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "224.0.0.0/4",
    ];

    fn is_root() -> bool {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() == 0 }
    }

    pub async fn run(config: Arc<Config>, shutdown: watch::Receiver<bool>) -> Result<()> {
        if !is_root() {
            bail!("TUN mode creates a network interface and must run as root (sudo vproxy --tun ...)");
        }

        // Discover the real default route before we change anything.
        let (gateway, phys_iface) = default_route().context("find the default route")?;
        // SAFETY: if_nametoindex on a NUL-terminated interface name.
        let cstr = std::ffi::CString::new(phys_iface.clone()).unwrap();
        let ifindex = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
        if ifindex == 0 {
            bail!("cannot resolve interface index for {phys_iface}");
        }
        info!("Default route: gateway {gateway} on {phys_iface} (index {ifindex})");

        // Resolve the server address now, while normal DNS still works, so we
        // can pin a host route to it (keeps the transport off the tunnel).
        let server_ips = resolve_server(&config).await?;
        if server_ips.is_empty() {
            bail!("could not resolve the server address {}", config.server.address);
        }

        // Build the proxy connector, pinned to the physical interface so every
        // `direct` dial egresses there instead of looping into the tunnel.
        let connector = ProxyClient::new(
            ActiveServer::new(config.server.clone()),
            config.dns.clone(),
            config.runtime.clone(),
            &config.routing,
            &config.mux,
        )?
        .with_egress(Egress::new(ifindex));

        let fake_dns = Arc::new(FakeDns::new(DEFAULT_POOL, FAKE_DNS_CAPACITY));
        let dns_addr = fake_dns.server_addr();
        let mtu = config.tun.mtu as u16;

        // Create the utun. tun-rs assigns the name; read it back for routing.
        let (addr, prefix) = parse_cidr(&config.tun.address)?;
        let device = tun_rs::DeviceBuilder::new()
            .mtu(mtu)
            .ipv4(addr, prefix, None)
            .build_async()
            .context("create utun device (needs root)")?;
        let iface = device.name().context("read utun name")?;
        info!("utun {iface} up ({}/{}, mtu {mtu})", addr, prefix);
        let device = Arc::new(device);

        // Install routes + DNS; the guard restores everything on drop (so a
        // panic or an early return cannot leave the network broken).
        let mut guard = NetGuard {
            gateway: gateway.clone(),
            iface: iface.clone(),
            phys_iface: phys_iface.clone(),
            server_ips: server_ips.clone(),
            bypass_nets: Vec::new(),
            service: None,
            saved_dns: None,
        };
        guard.install(&config, dns_addr)?;

        // Bridge the utun to the netstack through the channel device.
        let (chan_dev, mut host) = channel_device();
        let reader_dev = device.clone();
        let to_stack = host.to_stack.clone();
        let reader = tokio::spawn(async move {
            let mut buf = vec![0u8; mtu as usize + 4];
            loop {
                match reader_dev.recv(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if to_stack.send(buf[..n].to_vec()).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("utun read ended: {e}");
                        break;
                    }
                }
            }
        });
        let writer_dev = device.clone();
        let writer = tokio::spawn(async move {
            while let Some(pkt) = host.from_stack.recv().await {
                if writer_dev.send(&pkt).await.is_err() {
                    break;
                }
            }
        });

        let netstack = Netstack {
            connector,
            dns: fake_dns,
            mtu,
            flows: Arc::new(FlowLog::new(DEFAULT_CAPACITY)),
        };
        info!("Native TUN up: all traffic via {}", config.server.endpoint());

        let result = netstack.run(chan_dev, shutdown).await;

        // Stop the bridge, release the utun, then the guard restores routes/DNS.
        reader.abort();
        writer.abort();
        drop(device);
        drop(guard);
        info!("Native TUN stopped, routes and DNS restored");
        result
    }

    /// Everything we changed in the OS, restored on drop (best effort).
    struct NetGuard {
        gateway: String,
        iface: String,
        /// The physical interface (e.g. en0) — whose `networksetup` service
        /// carries the DNS configuration, not the utun.
        phys_iface: String,
        server_ips: Vec<Ipv4Addr>,
        bypass_nets: Vec<String>,
        service: Option<String>,
        /// `Some(servers)` records the DNS we overrode; empty vec means "was
        /// unset" (restore to DHCP). `None` means we never touched DNS.
        saved_dns: Option<Vec<String>>,
    }

    impl NetGuard {
        fn install(&mut self, config: &Config, dns_addr: Ipv4Addr) -> Result<()> {
            // Keep the transport off the tunnel: server IPs via the real gateway.
            for ip in &self.server_ips {
                route(&["-n", "add", "-host", &ip.to_string(), &self.gateway])?;
            }
            // Override the default route without deleting it: two /1 halves to
            // the utun (restored by deleting just these two).
            route(&["-n", "add", "-net", "0.0.0.0/1", "-interface", &self.iface])?;
            route(&["-n", "add", "-net", "128.0.0.0/1", "-interface", &self.iface])?;
            // LAN / link-local / multicast and configured bypasses go around it.
            for net in LOCAL_NETS
                .iter()
                .map(|s| s.to_string())
                .chain(config.tun.bypass_cidrs.iter().cloned())
            {
                if route(&["-n", "add", "-net", &net, &self.gateway]).is_ok() {
                    self.bypass_nets.push(net);
                }
            }
            // Point the system resolver at the netstack's FakeDNS. The DNS
            // config lives on the physical interface's service (e.g. Wi-Fi),
            // not the utun.
            if let Some(service) = network_service(&self.phys_iface) {
                let saved = current_dns(&service);
                if set_dns(&service, &[dns_addr.to_string()]).is_ok() {
                    info!("DNS -> {dns_addr} (FakeDNS) on \"{service}\"");
                    self.service = Some(service);
                    self.saved_dns = Some(saved);
                }
            } else {
                warn!("could not find the network service for {}; DNS not redirected (names may not resolve through the tunnel)", self.phys_iface);
            }
            Ok(())
        }

        fn restore(&mut self) {
            for ip in &self.server_ips {
                let _ = route(&["-n", "delete", "-host", &ip.to_string()]);
            }
            let _ = route(&["-n", "delete", "-net", "0.0.0.0/1"]);
            let _ = route(&["-n", "delete", "-net", "128.0.0.0/1"]);
            for net in &self.bypass_nets {
                let _ = route(&["-n", "delete", "-net", net]);
            }
            if let (Some(service), Some(saved)) = (&self.service, &self.saved_dns) {
                if saved.is_empty() {
                    let _ = set_dns(service, &["Empty".to_string()]);
                } else {
                    let _ = set_dns(service, saved);
                }
            }
        }
    }

    impl Drop for NetGuard {
        fn drop(&mut self) {
            self.restore();
        }
    }

    fn route(args: &[&str]) -> Result<()> {
        let out = Command::new("/sbin/route")
            .args(args)
            .output()
            .context("run /sbin/route")?;
        if !out.status.success() {
            bail!(
                "route {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    /// `(gateway, interface)` of the current default route, via `route get`.
    fn default_route() -> Result<(String, String)> {
        let out = Command::new("/sbin/route")
            .args(["-n", "get", "default"])
            .output()
            .context("run route get default")?;
        if !out.status.success() {
            bail!("no default route (route get default failed)");
        }
        let text = String::from_utf8_lossy(&out.stdout);
        let field = |key: &str| {
            text.lines()
                .find_map(|l| l.trim().strip_prefix(&format!("{key}: ")))
                .map(|v| v.trim().to_string())
        };
        let gateway = field("gateway").context("default route has no gateway")?;
        let iface = field("interface").context("default route has no interface")?;
        Ok((gateway, iface))
    }

    /// The `networksetup` service name (e.g. "Wi-Fi") for a BSD device (en0).
    fn network_service(iface: &str) -> Option<String> {
        let out = Command::new("/usr/sbin/networksetup")
            .arg("-listnetworkserviceorder")
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        // Blocks: "(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)".
        let mut current: Option<String> = None;
        for line in text.lines() {
            let t = line.trim();
            if let Some(rest) = t.strip_prefix('(') {
                if let Some((num, name)) = rest.split_once(')') {
                    if !num.is_empty() && num.chars().all(|c| c.is_ascii_digit()) {
                        current = Some(name.trim().to_string());
                        continue;
                    }
                }
            }
            if t.contains(&format!("Device: {iface}")) {
                return current.clone();
            }
        }
        None
    }

    fn current_dns(service: &str) -> Vec<String> {
        let out = match Command::new("/usr/sbin/networksetup")
            .args(["-getdnsservers", service])
            .output()
        {
            Ok(o) => o,
            Err(_) => return Vec::new(),
        };
        let text = String::from_utf8_lossy(&out.stdout);
        if text.contains("aren't any") || text.contains("any DNS Servers") {
            return Vec::new();
        }
        text.lines()
            .map(str::trim)
            .filter(|l| l.parse::<std::net::IpAddr>().is_ok())
            .map(String::from)
            .collect()
    }

    fn set_dns(service: &str, servers: &[String]) -> Result<()> {
        let out = Command::new("/usr/sbin/networksetup")
            .arg("-setdnsservers")
            .arg(service)
            .args(servers)
            .output()
            .context("run networksetup -setdnsservers")?;
        if !out.status.success() {
            bail!(
                "networksetup -setdnsservers {service}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    /// Parse "172.18.0.1/30" into an address and prefix length.
    fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8)> {
        let (addr, prefix) = cidr
            .split_once('/')
            .context("tun.address must be CIDR, e.g. 172.18.0.1/30")?;
        Ok((
            addr.parse().with_context(|| format!("bad tun address {addr}"))?,
            prefix.parse().with_context(|| format!("bad prefix /{prefix}"))?,
        ))
    }

    async fn resolve_server(config: &Config) -> Result<Vec<Ipv4Addr>> {
        let host = config.server.address.clone();
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Ok(vec![ip]);
        }
        // IPv6-literal server: no v4 host route needed (we only split v4).
        if host.parse::<std::net::Ipv6Addr>().is_ok() {
            return Ok(Vec::new());
        }
        let addrs = tokio::net::lookup_host((host.as_str(), config.server.port)).await?;
        Ok(addrs
            .filter_map(|a| match a.ip() {
                std::net::IpAddr::V4(v4) => Some(v4),
                std::net::IpAddr::V6(_) => None,
            })
            .collect())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn parses_cidr() {
            assert_eq!(
                parse_cidr("172.18.0.1/30").unwrap(),
                ("172.18.0.1".parse().unwrap(), 30)
            );
            assert!(parse_cidr("172.18.0.1").is_err());
        }

        #[test]
        fn local_nets_cover_rfc1918_and_multicast() {
            assert!(LOCAL_NETS.contains(&"192.168.0.0/16"));
            assert!(LOCAL_NETS.contains(&"224.0.0.0/4"));
        }
    }
}
