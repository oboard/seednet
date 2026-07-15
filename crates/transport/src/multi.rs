//! `MultiTransport` — combines multiple `Transport` impls into one.
//!
//! Receive: polls all transports concurrently via a shared channel.
//! Send:    routes to the transport that matches the `TransportAddr` variant.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::mpsc;

use crate::{TcpTransport, Transport, TransportAddr, TransportKind, UdpTransport, WsTransport};

type RxMsg = (Bytes, TransportAddr);

/// A transport that fans out over up to one of each kind (UDP, TCP, WS).
///
/// Receive races all transports; send dispatches by `TransportAddr` variant.
pub struct MultiTransport {
    udp: Option<Arc<UdpTransport>>,
    tcp: Option<Arc<TcpTransport>>,
    ws: Option<Arc<WsTransport>>,
    rx: tokio::sync::Mutex<mpsc::Receiver<RxMsg>>,
    // Kept alive to prevent the channel from closing when all sub-transports
    // are idle; sub-transport tasks hold clones of this sender.
    #[allow(dead_code)]
    tx: mpsc::Sender<RxMsg>,
}

impl MultiTransport {
    pub fn builder() -> MultiTransportBuilder {
        MultiTransportBuilder::new()
    }

    /// Access the inner UDP transport (needed by STUN).
    pub fn udp(&self) -> Option<&Arc<UdpTransport>> {
        self.udp.as_ref()
    }

    fn spawn_receiver<T: Transport + 'static>(transport: Arc<T>, tx: mpsc::Sender<RxMsg>) {
        tokio::spawn(async move {
            loop {
                match transport.recv_from().await {
                    Ok(msg) => {
                        if tx.send(msg).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            target: "seednet::transport::multi",
                            error = %e,
                            "recv_from error"
                        );
                        // Transient errors: keep running.
                    }
                }
            }
        });
    }
}

#[async_trait]
impl Transport for MultiTransport {
    async fn send_to(&self, buf: &[u8], addr: TransportAddr) -> std::io::Result<()> {
        match addr.kind() {
            TransportKind::Udp => {
                let t = self.udp.as_ref().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::Unsupported, "UDP not enabled")
                })?;
                t.send_to(buf, addr).await
            }
            TransportKind::Tcp => {
                let t = self.tcp.as_ref().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::Unsupported, "TCP not enabled")
                })?;
                t.send_to(buf, addr).await
            }
            TransportKind::Ws => {
                let t = self.ws.as_ref().ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::Unsupported, "WS not enabled")
                })?;
                t.send_to(buf, addr).await
            }
            TransportKind::Wss => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "WSS not yet implemented",
            )),
        }
    }

    async fn recv_from(&self) -> std::io::Result<(Bytes, TransportAddr)> {
        self.rx.lock().await.recv().await.ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "all transports closed")
        })
    }

    fn local_addr(&self) -> TransportAddr {
        // Return the UDP address as the primary; callers that need a specific
        // transport's address should query the sub-transport directly.
        if let Some(udp) = &self.udp {
            return udp.local_addr();
        }
        if let Some(tcp) = &self.tcp {
            return tcp.local_addr();
        }
        if let Some(ws) = &self.ws {
            return ws.local_addr();
        }
        panic!("MultiTransport has no transports");
    }
}

/// Builder for [`MultiTransport`].
pub struct MultiTransportBuilder {
    udp: Option<Arc<UdpTransport>>,
    tcp: Option<Arc<TcpTransport>>,
    ws: Option<Arc<WsTransport>>,
}

impl MultiTransportBuilder {
    fn new() -> Self {
        Self {
            udp: None,
            tcp: None,
            ws: None,
        }
    }

    pub fn udp(mut self, t: UdpTransport) -> Self {
        self.udp = Some(Arc::new(t));
        self
    }

    pub fn tcp(mut self, t: TcpTransport) -> Self {
        self.tcp = Some(Arc::new(t));
        self
    }

    pub fn ws(mut self, t: WsTransport) -> Self {
        self.ws = Some(Arc::new(t));
        self
    }

    pub fn build(self) -> MultiTransport {
        let (tx, rx) = mpsc::channel::<RxMsg>(4096);

        if let Some(ref t) = self.udp {
            MultiTransport::spawn_receiver(t.clone(), tx.clone());
        }
        if let Some(ref t) = self.tcp {
            MultiTransport::spawn_receiver(t.clone(), tx.clone());
        }
        if let Some(ref t) = self.ws {
            MultiTransport::spawn_receiver(t.clone(), tx.clone());
        }

        MultiTransport {
            udp: self.udp,
            tcp: self.tcp,
            ws: self.ws,
            rx: tokio::sync::Mutex::new(rx),
            tx,
        }
    }
}
