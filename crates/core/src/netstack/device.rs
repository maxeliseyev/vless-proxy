//! A packet device made of two channels, for hosts that hand packets over
//! one by one instead of giving a file descriptor: the iOS Packet Tunnel
//! (`packetFlow.readPackets` / `writePackets`) and tests.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;

/// Packets queued in each direction before new ones are dropped, the way a
/// full interface queue drops them; TCP retransmits.
const QUEUE: usize = 1024;

/// The netstack's side: each read is one IP packet from the host, each
/// write is one IP packet to it.
pub struct ChannelDevice {
    from_host: mpsc::Receiver<Vec<u8>>,
    to_host: mpsc::Sender<Vec<u8>>,
}

/// The host's side of a [`ChannelDevice`].
pub struct HostPackets {
    /// Packets the host read from the system, towards the netstack.
    pub to_stack: mpsc::Sender<Vec<u8>>,
    /// Packets the netstack produced, for the host to write to the system.
    pub from_stack: mpsc::Receiver<Vec<u8>>,
}

pub fn channel_device() -> (ChannelDevice, HostPackets) {
    let (to_stack, from_host) = mpsc::channel(QUEUE);
    let (to_host, from_stack) = mpsc::channel(QUEUE);
    (
        ChannelDevice { from_host, to_host },
        HostPackets {
            to_stack,
            from_stack,
        },
    )
}

impl AsyncRead for ChannelDevice {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.from_host.poll_recv(cx) {
            Poll::Ready(Some(packet)) => {
                // Longer than the stack's MTU buffer: cut, as a short read would.
                let n = packet.len().min(buf.remaining());
                buf.put_slice(&packet[..n]);
                Poll::Ready(Ok(()))
            }
            // Host gone. Stay pending rather than report EOF: the stack would
            // spin on zero-length reads, and it is stopped by dropping it.
            Poll::Ready(None) => Poll::Pending,
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for ChannelDevice {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.to_host.try_send(buf.to_vec()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Poll::Ready(Ok(buf.len())),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
