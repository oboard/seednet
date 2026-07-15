//! WebSocket transport using tokio-tungstenite.
//!
//! Each logical "connection" is one WS session.  The URL path is always `/`
//! and no subprotocol negotiation is performed — the WS layer is purely used
//! as framing to bypass firewalls that allow HTTP upgrade traffic.
//!
//! Each connection is represented by a `mpsc::Sender` that writes to a
//! background task owning the actual WS stream — this avoids the generic
//! type proliferation from `WebSocketStream<MaybeTlsStream<…>>` vs
//! `WebSocketStream<TcpStream>`.

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::{
    net::TcpListener,
    sync::{Mutex, mpsc},
};
use tokio_tungstenite::{accept_async, connect_async, tungstenite::Message as WsMessage};
use tracing::debug;

/// Each outbound connection is serviced by a background task; we hold a
/// channel to send frames into it.
type ConnTx = mpsc::Sender<Bytes>;
type RxSender = mpsc::Sender<(Bytes, SocketAddr)>;
type RxReceiver = Mutex<mpsc::Receiver<(Bytes, SocketAddr)>>;
type ConnMap = Mutex<HashMap<SocketAddr, ConnTx>>;

pub struct WsTransport {
    local: SocketAddr,
    rx: RxReceiver,
    conns: Arc<ConnMap>,
}

impl WsTransport {
    pub async fn bind(addr: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        let (tx, rx) = mpsc::channel::<(Bytes, SocketAddr)>(1024);
        let conns: Arc<ConnMap> = Arc::new(Mutex::new(HashMap::new()));

        let conns2 = conns.clone();
        tokio::spawn(accept_loop(listener, tx, conns2));

        Ok(Self {
            local,
            rx: Mutex::new(rx),
            conns,
        })
    }

    async fn get_or_connect(&self, addr: SocketAddr) -> std::io::Result<ConnTx> {
        let mut map = self.conns.lock().await;
        if let Some(tx) = map.get(&addr)
            && !tx.is_closed()
        {
            return Ok(tx.clone());
        }
        let url = format!("ws://{addr}/");
        let (ws, _) = connect_async(&url).await.map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e.to_string())
        })?;
        let (mut sink, _stream) = ws.split();
        let (conn_tx, mut conn_rx) = mpsc::channel::<Bytes>(256);
        // Drive outbound sends in a background task.
        tokio::spawn(async move {
            while let Some(bytes) = conn_rx.recv().await {
                if sink.send(WsMessage::Binary(bytes)).await.is_err() {
                    break;
                }
            }
        });
        map.insert(addr, conn_tx.clone());
        Ok(conn_tx)
    }
}

#[async_trait]
impl crate::Transport for WsTransport {
    async fn send_to(&self, buf: &[u8], addr: crate::TransportAddr) -> std::io::Result<()> {
        let remote = addr.socket_addr();
        let conn_tx = self.get_or_connect(remote).await?;
        conn_tx
            .send(Bytes::copy_from_slice(buf))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "ws conn closed"))?;
        Ok(())
    }

    async fn recv_from(&self) -> std::io::Result<(Bytes, crate::TransportAddr)> {
        self.rx
            .lock()
            .await
            .recv()
            .await
            .map(|(b, a)| (b, crate::TransportAddr::Ws(a)))
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "ws rx closed"))
    }

    fn local_addr(&self) -> crate::TransportAddr {
        crate::TransportAddr::Ws(self.local)
    }
}

async fn accept_loop(listener: TcpListener, tx: RxSender, conns: Arc<ConnMap>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                debug!(target: "seednet::transport::ws", %peer, "accepted WS connection");
                let tx2 = tx.clone();
                let conns2 = conns.clone();
                tokio::spawn(async move {
                    match accept_async(stream).await {
                        Ok(ws) => {
                            let (mut sink, mut stream) = ws.split();
                            // Create a channel to forward inbound send requests.
                            let (conn_tx, mut conn_rx) = mpsc::channel::<Bytes>(256);
                            conns2.lock().await.insert(peer, conn_tx);
                            // Drive outbound sends.
                            tokio::spawn(async move {
                                while let Some(bytes) = conn_rx.recv().await {
                                    if sink.send(WsMessage::Binary(bytes)).await.is_err() {
                                        break;
                                    }
                                }
                            });
                            // Read inbound frames.
                            while let Some(msg) = stream.next().await {
                                match msg {
                                    Ok(WsMessage::Binary(data)) => {
                                        if tx2.send((data, peer)).await.is_err() {
                                            break;
                                        }
                                    }
                                    Ok(WsMessage::Close(_)) | Err(_) => break,
                                    _ => {}
                                }
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                target: "seednet::transport::ws",
                                %peer, error = %e, "WS upgrade failed"
                            );
                        }
                    }
                });
            }
            Err(e) => {
                tracing::warn!(target: "seednet::transport::ws", error = %e, "accept error");
            }
        }
    }
}
