//! UDP transport — wraps a `tokio::net::UdpSocket`.

use std::{net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::net::UdpSocket;

use crate::{MAX_UDP, Transport, TransportAddr};

/// Thin wrapper around `Arc<UdpSocket>` that implements [`Transport`].
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
    local: SocketAddr,
}

impl UdpTransport {
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        let local = socket.local_addr().expect("UdpSocket must be bound");
        Self { socket, local }
    }

    /// Access the inner socket (e.g. for STUN queries).
    pub fn inner(&self) -> &Arc<UdpSocket> {
        &self.socket
    }
}

#[async_trait]
impl Transport for UdpTransport {
    async fn send_to(&self, buf: &[u8], addr: TransportAddr) -> std::io::Result<()> {
        self.socket.send_to(buf, addr.socket_addr()).await?;
        Ok(())
    }

    async fn recv_from(&self) -> std::io::Result<(Bytes, TransportAddr)> {
        let mut buf = vec![0u8; MAX_UDP];
        let (n, from) = self.socket.recv_from(&mut buf).await?;
        buf.truncate(n);
        Ok((Bytes::from(buf), TransportAddr::Udp(from)))
    }

    /// Zero-allocation receive: writes directly into the caller's buffer.
    async fn recv_into(&self, buf: &mut [u8]) -> std::io::Result<(usize, TransportAddr)> {
        let (n, from) = self.socket.recv_from(buf).await?;
        Ok((n, TransportAddr::Udp(from)))
    }

    fn local_addr(&self) -> TransportAddr {
        TransportAddr::Udp(self.local)
    }
}
