//! In-process TUN: IP packets in, routed connections out, no sing-box.
//!
//! [`ipstack`] turns packets into TCP streams and UDP flows; each one goes
//! through [`ProxyClient`] like a SOCKS request would. Names come from
//! [`FakeDns`]: the tunnel announces [`FakeDns::server_addr`] as its DNS
//! server, so connections arrive at fake addresses that map back to domains.
//!
//! The host provides the packets: a [`device::ChannelDevice`] on iOS, or a
//! TUN file descriptor wrapped as `AsyncRead + AsyncWrite` on desktop. The
//! host also keeps the stack's own connections to the server out of the
//! tunnel (the iOS Packet Tunnel does this by itself).

pub mod device;
pub mod fakedns;
pub mod flows;

use crate::protocol::vless::{self, Address};
use crate::proxy::runtime::{relay_tcp, ProxyClient, UdpOutbound};
use crate::proxy::stats::STATS;
use anyhow::Result;
use fakedns::FakeDns;
use flows::{Counted, Flow, FlowLog};
use ipstack::{
    IpStack, IpStackConfig, IpStackStream, IpStackTcpStream, IpStackUdpStream, TcpConfig,
};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{watch, Semaphore};
use tracing::{debug, info, warn};

/// A UDP flow nobody sent on for this long is closed (as in SOCKS UDP).
const UDP_IDLE: Duration = Duration::from_secs(120);

pub struct Netstack {
    pub connector: ProxyClient,
    pub dns: Arc<FakeDns>,
    /// MTU of the tunnel interface; packets are read into a buffer this big.
    pub mtu: u16,
    /// Every TCP connection and UDP flow is recorded here for the host's log.
    pub flows: Arc<FlowLog>,
}

impl Netstack {
    /// Serve `device` until `shutdown` turns true.
    pub async fn run<D>(self, device: D, mut shutdown: watch::Receiver<bool>) -> Result<()>
    where
        D: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let runtime = self.connector.runtime().clone();
        let mut tcp = TcpConfig::default();
        // Let the relay close idle connections first, quietly.
        tcp.timeout = Duration::from_secs(runtime.idle_timeout_secs + 30);
        let mut config = IpStackConfig::default();
        config
            .mtu(self.mtu)
            .map_err(|e| anyhow::anyhow!("netstack MTU {}: {e}", self.mtu))?
            .with_tcp_config(tcp)
            .udp_timeout(UDP_IDLE);
        let mut stack = IpStack::new(config, device);
        let limit = Arc::new(Semaphore::new(runtime.max_connections));
        let shared = Arc::new(self);
        info!(
            "Netstack up (mtu {}, dns {})",
            shared.mtu,
            shared.dns.server_addr()
        );

        loop {
            let stream = tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        break;
                    }
                    continue;
                }
                stream = stack.accept() => stream?,
            };
            match stream {
                IpStackStream::Tcp(tcp) => {
                    let Ok(permit) = limit.clone().try_acquire_owned() else {
                        warn!(
                            "Dropping TCP to {}: max connections reached",
                            tcp.peer_addr()
                        );
                        continue;
                    };
                    let this = shared.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        this.handle_tcp(tcp).await;
                    });
                }
                IpStackStream::Udp(udp) => {
                    let this = shared.clone();
                    tokio::spawn(async move { this.handle_udp(udp).await });
                }
                // ICMP and the like: nothing to route them to.
                IpStackStream::UnknownTransport(_) | IpStackStream::UnknownNetwork(_) => {}
            }
        }
        info!("Netstack stopped");
        Ok(())
    }

    /// The real target behind a destination address; `None` for a fake
    /// address that maps to nothing (handed out before a restart).
    fn target(&self, addr: SocketAddr) -> Option<Address> {
        match addr.ip() {
            IpAddr::V4(ip) if self.dns.is_fake(ip) => self.dns.domain_for(ip).map(Address::Domain),
            IpAddr::V4(ip) => Some(Address::Ipv4(ip)),
            IpAddr::V6(ip) => Some(Address::Ipv6(ip)),
        }
    }

    async fn handle_tcp(&self, tcp: IpStackTcpStream) {
        let dst = tcp.peer_addr();
        let Some(address) = self.target(dst) else {
            debug!("TCP to unknown fake address {dst}, dropped");
            return;
        };
        debug!("TCP {} -> {address}:{}", tcp.local_addr(), dst.port());
        let route = self.connector.router().decide(&address, dst.port());
        let flow = self
            .flows
            .open("tcp", address.to_string(), dst.port(), route);
        STATS.connection_opened();
        let client = Counted::new(tcp, flow.clone());
        let result = relay_tcp(client, &self.connector, address.clone(), dst.port(), || {
            flow.dialed()
        })
        .await;
        match result {
            Ok(()) => flow.close(true),
            Err(error) => {
                STATS.error();
                flow.fail(format!("{error:#}"));
            }
        }
        info!("flow {}", flow.summary());
        STATS.connection_closed();
    }

    async fn handle_udp(&self, mut udp: IpStackUdpStream) {
        let dst = udp.peer_addr();
        if dst == SocketAddr::from((self.dns.server_addr(), 53)) {
            return self.serve_dns(udp).await;
        }
        let Some(address) = self.target(dst) else {
            debug!("UDP to unknown fake address {dst}, dropped");
            return;
        };
        let route = self.connector.router().decide(&address, dst.port());
        let started = std::time::Instant::now();
        let outbound = match self.connector.open_udp(address.clone(), dst.port()).await {
            Ok(outbound) => outbound,
            Err(error) => {
                // Vision refuses UDP/443 on purpose: QUIC falls back to TCP,
                // which then shows up in the log; the refusal itself does not.
                let text = error.to_string();
                if text.contains("XTLS rejected") {
                    debug!("Dropping UDP to {address}:{}: {text}", dst.port());
                } else if text.contains("blocked by routing") {
                    debug!("Dropping UDP to {address}:{}: {text}", dst.port());
                    self.flows
                        .open("udp", address.to_string(), dst.port(), route)
                        .close(true);
                } else {
                    warn!(
                        "Failed to open UDP session to {address}:{} after {}ms: {text}",
                        dst.port(),
                        started.elapsed().as_millis()
                    );
                }
                return;
            }
        };
        debug!("UDP {} -> {address}:{}", udp.local_addr(), dst.port());
        let flow = self
            .flows
            .open("udp", address.to_string(), dst.port(), route);
        let result = match outbound {
            UdpOutbound::Proxy(remote) => relay_udp_vless(&mut udp, *remote, &flow).await,
            UdpOutbound::Direct(socket) => relay_udp_direct(&mut udp, socket, &flow).await,
        };
        if let Err(error) = &result {
            debug!("UDP to {address}:{} ended: {error}", dst.port());
        }
        // A UDP flow normally ends by timing out, which is not a failure.
        flow.close(true);
        info!("flow {}", flow.summary());
    }

    /// Answer queries to the tunnel's DNS address from the fake pool.
    async fn serve_dns(&self, mut udp: IpStackUdpStream) {
        let mut buf = vec![0u8; 1500];
        while let Ok(n) = udp.read(&mut buf).await {
            if n == 0 {
                break;
            }
            if let Some(reply) = self.dns.answer(&buf[..n]) {
                if udp.write_all(&reply).await.is_err() {
                    break;
                }
            }
        }
    }
}

/// One UDP flow over a VLESS UDP session, a frame per datagram. Ends when
/// either side stops (the flow times out after [`UDP_IDLE`]).
async fn relay_udp_vless(
    udp: &mut IpStackUdpStream,
    remote: crate::proxy::runtime::RemoteStream,
    flow: &Flow,
) -> Result<()> {
    let (mut reader, mut writer) = tokio::io::split(remote);
    let (mut udp_in, mut udp_out) = tokio::io::split(udp);
    let up = async {
        let mut buf = vec![0u8; 65_535];
        loop {
            let n = udp_in.read(&mut buf).await?;
            if n == 0 {
                return Ok::<_, anyhow::Error>(());
            }
            vless::write_udp_frame(&mut writer, &buf[..n]).await?;
            writer.flush().await?;
            STATS.add_up(n);
            flow.add_up(n);
        }
    };
    let down = async {
        loop {
            let payload = vless::read_udp_frame(&mut reader).await?;
            STATS.add_down(payload.len());
            flow.add_down(payload.len());
            udp_out.write_all(&payload).await?;
        }
    };
    tokio::select! {
        result = up => result,
        result = down => result,
    }
}

/// One UDP flow sent straight from this host (routing said `direct`).
async fn relay_udp_direct(
    udp: &mut IpStackUdpStream,
    socket: tokio::net::UdpSocket,
    flow: &Flow,
) -> Result<()> {
    let (mut udp_in, mut udp_out) = tokio::io::split(udp);
    let up = async {
        let mut buf = vec![0u8; 65_535];
        loop {
            let n = udp_in.read(&mut buf).await?;
            if n == 0 {
                return Ok::<_, anyhow::Error>(());
            }
            socket.send(&buf[..n]).await?;
            STATS.add_up(n);
            flow.add_up(n);
        }
    };
    let down = async {
        let mut buf = vec![0u8; 65_535];
        loop {
            let n = socket.recv(&mut buf).await?;
            STATS.add_down(n);
            flow.add_down(n);
            udp_out.write_all(&buf[..n]).await?;
        }
    };
    tokio::select! {
        result = up => result,
        result = down => result,
    }
}
