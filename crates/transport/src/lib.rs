//! Pluggable transport layer for SeedNet.
//!
//! All transports share the same Noise XX encryption; only the wire framing
//! differs.  UDP sends raw datagrams (no length prefix); TCP, WS, and WSS
//! prepend a 4-byte big-endian length so they can delimit messages over a
//! byte stream.

mod frame;
pub mod multi;
mod tcp;
mod udp;
mod ws;

pub use multi::MultiTransport;
pub use tcp::TcpTransport;
pub use udp::UdpTransport;
pub use ws::WsTransport;

use std::{fmt, net::SocketAddr};

use async_trait::async_trait;
use bytes::Bytes;

/// The address of a peer, tagged with the transport protocol used to reach it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TransportAddr {
    Udp(SocketAddr),
    Tcp(SocketAddr),
    Ws(SocketAddr),
    Wss(SocketAddr),
}

impl TransportAddr {
    pub fn socket_addr(&self) -> SocketAddr {
        match self {
            Self::Udp(a) | Self::Tcp(a) | Self::Ws(a) | Self::Wss(a) => *a,
        }
    }

    pub fn kind(&self) -> TransportKind {
        match self {
            Self::Udp(_) => TransportKind::Udp,
            Self::Tcp(_) => TransportKind::Tcp,
            Self::Ws(_) => TransportKind::Ws,
            Self::Wss(_) => TransportKind::Wss,
        }
    }

    /// Build a `TransportAddr` from a `SocketAddr` and a `TransportKind`.
    pub fn with_kind(addr: SocketAddr, kind: TransportKind) -> Self {
        match kind {
            TransportKind::Udp => Self::Udp(addr),
            TransportKind::Tcp => Self::Tcp(addr),
            TransportKind::Ws => Self::Ws(addr),
            TransportKind::Wss => Self::Wss(addr),
        }
    }
}

impl fmt::Display for TransportAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Udp(a) => write!(f, "udp:{a}"),
            Self::Tcp(a) => write!(f, "tcp:{a}"),
            Self::Ws(a) => write!(f, "ws:{a}"),
            Self::Wss(a) => write!(f, "wss:{a}"),
        }
    }
}

/// Which transport protocol a `TransportAddr` uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TransportKind {
    Udp,
    Tcp,
    Ws,
    Wss,
}

/// Common interface over all transport protocols.
///
/// Implementations must be `Send + Sync + 'static` so they can be placed behind
/// `Arc<dyn Transport>` and shared across async tasks.
#[async_trait]
pub trait Transport: Send + Sync + 'static {
    /// Send `buf` to the given address.
    async fn send_to(&self, buf: &[u8], addr: TransportAddr) -> std::io::Result<()>;

    /// Receive the next message, returning (payload, sender address).
    /// Blocks until a message arrives.
    async fn recv_from(&self) -> std::io::Result<(Bytes, TransportAddr)>;

    /// The local address this transport is bound to.
    fn local_addr(&self) -> TransportAddr;
}
