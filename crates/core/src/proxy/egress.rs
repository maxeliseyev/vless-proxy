//! Bind outbound sockets to a specific network interface.
//!
//! In TUN mode on desktop the tunnel is the default route, so a socket vproxy
//! opens for a `direct` connection would be routed back into the tunnel and
//! loop. Binding that socket to the physical interface makes it egress there
//! regardless of the route table (macOS `IP_BOUND_IF` / `IPV6_BOUND_IF`).
//!
//! The server transport is kept off the tunnel by a host route instead, so
//! only the `direct` dials in [`crate::proxy::runtime`] use this. Where the
//! host sets up its own routing (iOS, where NetworkExtension does it), no
//! egress is set and these calls are absent.

use std::net::SocketAddr;

/// A physical interface to pin `direct` outbound sockets to, by index.
#[derive(Clone, Copy, Debug)]
pub struct Egress {
    ifindex: u32,
}

impl Egress {
    /// Pin to the interface with this index (`if_nametoindex`).
    pub fn new(ifindex: u32) -> Self {
        Self { ifindex }
    }

    pub fn ifindex(&self) -> u32 {
        self.ifindex
    }

    /// Bind `fd` to the interface for the given address family. A no-op on
    /// platforms without `IP_BOUND_IF` (only macOS TUN mode uses it today).
    #[cfg(target_os = "macos")]
    pub fn bind_fd(&self, fd: std::os::unix::io::RawFd, target: SocketAddr) -> std::io::Result<()> {
        // <net/if.h>: not in the libc crate's Darwin bindings, stable values.
        const IP_BOUND_IF: libc::c_int = 25;
        const IPV6_BOUND_IF: libc::c_int = 125;
        let (level, name) = if target.is_ipv6() {
            (libc::IPPROTO_IPV6, IPV6_BOUND_IF)
        } else {
            (libc::IPPROTO_IP, IP_BOUND_IF)
        };
        let idx = self.ifindex as libc::c_uint;
        // SAFETY: setsockopt on a valid fd with a 4-byte c_uint option value.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                name,
                &idx as *const libc::c_uint as *const libc::c_void,
                std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    pub fn bind_fd(&self, _fd: std::os::unix::io::RawFd, _target: SocketAddr) -> std::io::Result<()> {
        Ok(())
    }
}
