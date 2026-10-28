//! Bind outbound sockets to a specific network interface.
//!
//! In TUN mode on desktop the tunnel is the default route, so a socket vproxy
//! opens for a `direct` connection would be routed back into the tunnel and
//! loop. Binding that socket to the physical interface makes it egress there
//! regardless of the route table (macOS `IP_BOUND_IF` / `IPV6_BOUND_IF`,
//! Linux `SO_BINDTODEVICE`).
//!
//! The server transport is kept off the tunnel by a host route instead, so
//! only the `direct` dials in [`crate::proxy::runtime`] use this. Where the
//! host sets up its own routing (iOS, where NetworkExtension does it), no
//! egress is set and these calls are absent.

#[cfg(unix)]
use std::os::unix::io::RawFd;

/// A physical interface to pin `direct` outbound sockets to, by name.
#[derive(Clone, Debug)]
pub struct Egress {
    ifname: String,
}

impl Egress {
    /// Pin to the interface with this name (e.g. `en0`, `eth0`).
    pub fn new(ifname: impl Into<String>) -> Self {
        Self {
            ifname: ifname.into(),
        }
    }

    pub fn ifname(&self) -> &str {
        &self.ifname
    }

    /// Bind `fd` so it egresses this interface. A no-op on platforms without a
    /// device-binding socket option (only desktop TUN mode uses it).
    #[cfg(target_os = "macos")]
    pub fn bind_fd(&self, fd: RawFd, target: std::net::SocketAddr) -> std::io::Result<()> {
        // <net/if.h>: not in the libc crate's Darwin bindings, stable values.
        const IP_BOUND_IF: libc::c_int = 25;
        const IPV6_BOUND_IF: libc::c_int = 125;
        let cstr = std::ffi::CString::new(self.ifname.as_str())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        // SAFETY: if_nametoindex on a NUL-terminated name.
        let idx = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
        if idx == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let (level, name) = if target.is_ipv6() {
            (libc::IPPROTO_IPV6, IPV6_BOUND_IF)
        } else {
            (libc::IPPROTO_IP, IP_BOUND_IF)
        };
        // SAFETY: setsockopt with a 4-byte c_uint option value on a valid fd.
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

    #[cfg(target_os = "linux")]
    pub fn bind_fd(&self, fd: RawFd, _target: std::net::SocketAddr) -> std::io::Result<()> {
        let name = self.ifname.as_bytes();
        // SAFETY: setsockopt SO_BINDTODEVICE with the interface name bytes on a
        // valid fd. Needs CAP_NET_RAW, which TUN mode (root) already has.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                name.as_ptr() as *const libc::c_void,
                name.len() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    pub fn bind_fd(&self, _fd: RawFd, _target: std::net::SocketAddr) -> std::io::Result<()> {
        Ok(())
    }
}
