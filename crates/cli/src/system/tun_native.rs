//! Native TUN mode: vproxy owns the TUN interface and runs the in-process
//! netstack (`vproxy_core::netstack`) directly — no sing-box.
//!
//! The netstack turns tunnelled packets into routed connections through
//! `ProxyClient`. This module does the OS plumbing sing-box used to do: create
//! the TUN, point the default route and DNS at it, keep vproxy's own sockets
//! off the tunnel, and restore all of it on exit.
//!
//! Loop avoidance: the one connection to the server is kept off the tunnel by a
//! host route via the original gateway; `direct`-routed flows egress the
//! physical interface because `ProxyClient` is given its name (`IP_BOUND_IF` on
//! macOS, `SO_BINDTODEVICE` on Linux — see `vproxy_core::proxy::egress`);
//! LAN/private ranges are routed around the tunnel outright.
//!
//! The netstack, the TUN device creation and the connector are shared; each OS
//! differs only in how it reads the default route and sets routes + DNS
//! (`route`/`networksetup` on macOS, `ip`/`resolv.conf` on Linux).

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
    #[cfg(target_os = "linux")]
    {
        linux::run(config, shutdown).await
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (config, shutdown);
        anyhow::bail!("native --tun is supported on macOS and Linux only")
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
use shared::*;

/// OS-agnostic pieces: the netstack, the TUN device, the connector.
#[cfg(any(target_os = "macos", target_os = "linux"))]
mod shared {
    use anyhow::{Context, Result};
    use std::net::Ipv4Addr;
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

    pub const FAKE_DNS_CAPACITY: u32 = 16_384;
    /// Routed around the tunnel via the original gateway (LAN, link-local,
    /// multicast). The tunnel's own /30 is more specific, so it still wins.
    pub const LOCAL_NETS: [&str; 5] = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "224.0.0.0/4",
    ];

    pub fn is_root() -> bool {
        // SAFETY: geteuid has no preconditions.
        unsafe { libc::geteuid() == 0 }
    }

    pub fn new_fake_dns() -> Arc<FakeDns> {
        Arc::new(FakeDns::new(DEFAULT_POOL, FAKE_DNS_CAPACITY))
    }

    /// The proxy connector, pinned to the physical interface so every `direct`
    /// dial egresses there instead of looping back into the tunnel.
    pub fn connector(config: &Config, phys_iface: &str) -> Result<ProxyClient> {
        Ok(ProxyClient::new(
            ActiveServer::new(config.server.clone()),
            config.dns.clone(),
            config.runtime.clone(),
            &config.routing,
            &config.mux,
        )?
        .with_egress(Egress::new(phys_iface)))
    }

    /// Create the TUN device (brought up, addressed), returning it and its name.
    pub fn build_device(config: &Config) -> Result<(Arc<tun_rs::AsyncDevice>, String)> {
        let (addr, prefix) = parse_cidr(&config.tun.address)?;
        let device = tun_rs::DeviceBuilder::new()
            .mtu(config.tun.mtu as u16)
            .ipv4(addr, prefix, None)
            .enable(true)
            .build_async()
            .context("create TUN device (needs root)")?;
        let name = device.name().context("read TUN name")?;
        info!("TUN {name} up ({addr}/{prefix}, mtu {})", config.tun.mtu);
        Ok((Arc::new(device), name))
    }

    /// Pump packets between the TUN and the netstack through the channel
    /// device, run the netstack until `shutdown`, then stop and release the TUN.
    pub async fn drive(
        netstack: Netstack,
        device: Arc<tun_rs::AsyncDevice>,
        mtu: u16,
        shutdown: watch::Receiver<bool>,
    ) -> Result<()> {
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
                        warn!("TUN read ended: {e}");
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

        let result = netstack.run(chan_dev, shutdown).await;
        reader.abort();
        writer.abort();
        drop(device);
        result
    }

    /// Build the netstack from a connector and a FakeDNS.
    pub fn netstack(connector: ProxyClient, dns: Arc<FakeDns>, mtu: u16) -> Netstack {
        Netstack {
            connector,
            dns,
            mtu,
            flows: Arc::new(FlowLog::new(DEFAULT_CAPACITY)),
        }
    }

    /// Parse "172.18.0.1/30" into an address and prefix length.
    pub fn parse_cidr(cidr: &str) -> Result<(Ipv4Addr, u8)> {
        let (addr, prefix) = cidr
            .split_once('/')
            .context("tun.address must be CIDR, e.g. 172.18.0.1/30")?;
        Ok((
            addr.parse()
                .with_context(|| format!("bad tun address {addr}"))?,
            prefix
                .parse()
                .with_context(|| format!("bad prefix /{prefix}"))?,
        ))
    }

    /// Resolve the server to its IPv4 addresses (for the host-route exception),
    /// while normal DNS still works. Empty for an IPv6-literal server.
    pub async fn resolve_server(config: &Config) -> Result<Vec<Ipv4Addr>> {
        let host = config.server.address.clone();
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            return Ok(vec![ip]);
        }
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

// ---------------------------------------------------------------- macOS ------

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use anyhow::{bail, Context, Result};
    use std::net::Ipv4Addr;
    use std::process::Command;
    use std::sync::Arc;
    use tokio::sync::watch;
    use tracing::{info, warn};
    use vproxy_core::Config;

    pub async fn run(config: Arc<Config>, shutdown: watch::Receiver<bool>) -> Result<()> {
        if !is_root() {
            bail!(
                "TUN mode creates a network interface and must run as root (sudo vproxy --tun ...)"
            );
        }
        let (gateway, phys_iface) = default_route().context("find the default route")?;
        info!("Default route: gateway {gateway} on {phys_iface}");
        let server_ips = resolve_server(&config).await?;
        if server_ips.is_empty() {
            bail!(
                "could not resolve the server address {}",
                config.server.address
            );
        }

        let fake_dns = new_fake_dns();
        let dns_addr = fake_dns.server_addr();
        let mtu = config.tun.mtu as u16;
        let (device, iface) = build_device(&config)?;

        let mut guard = NetGuard {
            gateway,
            iface: iface.clone(),
            phys_iface: phys_iface.clone(),
            server_ips,
            bypass_nets: Vec::new(),
            service: None,
            saved_dns: None,
        };
        guard.install(&config, dns_addr)?;

        let netstack = netstack(connector(&config, &phys_iface)?, fake_dns, mtu);
        info!(
            "Native TUN up: all traffic via {}",
            config.server.endpoint()
        );
        let result = drive(netstack, device, mtu, shutdown).await;
        drop(guard);
        info!("Native TUN stopped, routes and DNS restored");
        result
    }

    struct NetGuard {
        gateway: String,
        iface: String,
        /// The physical interface (e.g. en0) — whose `networksetup` service
        /// carries the DNS configuration, not the utun.
        phys_iface: String,
        server_ips: Vec<Ipv4Addr>,
        bypass_nets: Vec<String>,
        service: Option<String>,
        saved_dns: Option<Vec<String>>,
    }

    impl NetGuard {
        fn install(&mut self, config: &Config, dns_addr: Ipv4Addr) -> Result<()> {
            for ip in &self.server_ips {
                route(&["-n", "add", "-host", &ip.to_string(), &self.gateway])?;
            }
            route(&["-n", "add", "-net", "0.0.0.0/1", "-interface", &self.iface])?;
            route(&[
                "-n",
                "add",
                "-net",
                "128.0.0.0/1",
                "-interface",
                &self.iface,
            ])?;
            for net in LOCAL_NETS
                .iter()
                .map(|s| s.to_string())
                .chain(config.tun.bypass_cidrs.iter().cloned())
            {
                if route(&["-n", "add", "-net", &net, &self.gateway]).is_ok() {
                    self.bypass_nets.push(net);
                }
            }
            if let Some(service) = network_service(&self.phys_iface) {
                let saved = current_dns(&service);
                if set_dns(&service, &[dns_addr.to_string()]).is_ok() {
                    info!("DNS -> {dns_addr} (FakeDNS) on \"{service}\"");
                    self.service = Some(service);
                    self.saved_dns = Some(saved);
                }
            } else {
                warn!(
                    "could not find the network service for {}; DNS not redirected",
                    self.phys_iface
                );
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
        Ok((
            field("gateway").context("default route has no gateway")?,
            field("interface").context("default route has no interface")?,
        ))
    }

    fn network_service(iface: &str) -> Option<String> {
        let out = Command::new("/usr/sbin/networksetup")
            .arg("-listnetworkserviceorder")
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
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
        let Ok(out) = Command::new("/usr/sbin/networksetup")
            .args(["-getdnsservers", service])
            .output()
        else {
            return Vec::new();
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
}

// ---------------------------------------------------------------- Linux ------

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use anyhow::{bail, Context, Result};
    use std::net::Ipv4Addr;
    use std::process::Command;
    use std::sync::Arc;
    use tokio::sync::watch;
    use tracing::{info, warn};
    use vproxy_core::Config;

    /// Where the system resolver reads from. Replaced while the tunnel is up,
    /// restored on teardown.
    const RESOLV_CONF: &str = "/etc/resolv.conf";

    pub async fn run(config: Arc<Config>, shutdown: watch::Receiver<bool>) -> Result<()> {
        if !is_root() {
            bail!(
                "TUN mode creates a network interface and must run as root (sudo vproxy --tun ...)"
            );
        }
        let (gateway, phys_iface) = default_route().context("find the default route")?;
        info!("Default route: gateway {gateway} on {phys_iface}");
        let server_ips = resolve_server(&config).await?;
        if server_ips.is_empty() {
            bail!(
                "could not resolve the server address {}",
                config.server.address
            );
        }

        let fake_dns = new_fake_dns();
        let dns_addr = fake_dns.server_addr();
        let mtu = config.tun.mtu as u16;
        let (device, iface) = build_device(&config)?;

        let mut guard = NetGuard {
            gateway,
            phys_iface,
            iface: iface.clone(),
            server_ips,
            routed_nets: Vec::new(),
            saved_resolv: None,
        };
        guard.install(&config, dns_addr)?;

        let netstack = netstack(connector(&config, &guard.phys_iface)?, fake_dns, mtu);
        info!(
            "Native TUN up: all traffic via {}",
            config.server.endpoint()
        );
        let result = drive(netstack, device, mtu, shutdown).await;
        drop(guard);
        info!("Native TUN stopped, routes and DNS restored");
        result
    }

    struct NetGuard {
        gateway: String,
        phys_iface: String,
        iface: String,
        server_ips: Vec<Ipv4Addr>,
        /// Networks we added via the gateway (deleted on teardown). The two
        /// split-default routes to the TUN go away with the interface.
        routed_nets: Vec<String>,
        /// Previous `/etc/resolv.conf` content, restored on teardown. `None`
        /// means we did not touch it.
        saved_resolv: Option<Vec<u8>>,
    }

    impl NetGuard {
        fn install(&mut self, config: &Config, dns_addr: Ipv4Addr) -> Result<()> {
            // Server IPs via the real gateway (transport off the tunnel).
            for ip in &self.server_ips {
                let net = format!("{ip}/32");
                ip_route(&["add", &net, "via", &self.gateway, "dev", &self.phys_iface])?;
                self.routed_nets.push(net);
            }
            // Override the default without deleting it: two /1 halves to the TUN.
            ip_route(&["add", "0.0.0.0/1", "dev", &self.iface])?;
            ip_route(&["add", "128.0.0.0/1", "dev", &self.iface])?;
            self.routed_nets.push("0.0.0.0/1".into());
            self.routed_nets.push("128.0.0.0/1".into());
            // LAN / link-local / multicast and configured bypasses around it.
            for net in LOCAL_NETS
                .iter()
                .map(|s| s.to_string())
                .chain(config.tun.bypass_cidrs.iter().cloned())
            {
                if ip_route(&["add", &net, "via", &self.gateway, "dev", &self.phys_iface]).is_ok() {
                    self.routed_nets.push(net);
                }
            }
            // Point the resolver at the netstack's FakeDNS.
            match std::fs::read(RESOLV_CONF) {
                Ok(prev) => {
                    if std::fs::write(RESOLV_CONF, format!("nameserver {dns_addr}\n")).is_ok() {
                        info!("DNS -> {dns_addr} (FakeDNS) in {RESOLV_CONF}");
                        self.saved_resolv = Some(prev);
                    } else {
                        warn!("could not write {RESOLV_CONF}; DNS not redirected");
                    }
                }
                Err(e) => warn!("could not read {RESOLV_CONF} ({e}); DNS not redirected"),
            }
            Ok(())
        }

        fn restore(&mut self) {
            for net in self.routed_nets.iter().rev() {
                // Default-split routes are dev routes; the rest carry a gateway.
                if net == "0.0.0.0/1" || net == "128.0.0.0/1" {
                    let _ = ip_route(&["del", net, "dev", &self.iface]);
                } else {
                    let _ = ip_route(&["del", net, "via", &self.gateway, "dev", &self.phys_iface]);
                }
            }
            if let Some(prev) = &self.saved_resolv {
                let _ = std::fs::write(RESOLV_CONF, prev);
            }
        }
    }

    impl Drop for NetGuard {
        fn drop(&mut self) {
            self.restore();
        }
    }

    fn ip_route(args: &[&str]) -> Result<()> {
        let mut full = vec!["route"];
        full.extend_from_slice(args);
        let out = Command::new("ip")
            .args(&full)
            .output()
            .context("run ip route")?;
        if !out.status.success() {
            bail!(
                "ip {}: {}",
                full.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    /// `(gateway, interface)` of the current default route via `ip route`.
    fn default_route() -> Result<(String, String)> {
        let out = Command::new("ip")
            .args(["-4", "route", "show", "default"])
            .output()
            .context("run ip route show default")?;
        if !out.status.success() {
            bail!("no default route (ip route show default failed)");
        }
        // "default via 192.168.1.1 dev eth0 proto dhcp ..."
        let text = String::from_utf8_lossy(&out.stdout);
        let line = text.lines().next().context("no default route")?;
        let toks: Vec<&str> = line.split_whitespace().collect();
        let after = |key: &str| {
            toks.iter()
                .position(|t| *t == key)
                .and_then(|i| toks.get(i + 1))
                .map(|s| s.to_string())
        };
        Ok((
            after("via").context("default route has no gateway")?,
            after("dev").context("default route has no interface")?,
        ))
    }
}
