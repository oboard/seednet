//! TCP transport with 4-byte length framing.
//!
//! Maintains a pool of outbound connections keyed by remote `SocketAddr`.
//! Inbound connections are accepted by the listener task and fed into the
//! same shared receive channel.

use std::{collections::HashMap, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc},
};
use tracing::debug;

use crate::{Transport, TransportAddr, frame};

type RxSender = mpsc::Sender<(Bytes, SocketAddr)>;
type RxReceiver = Mutex<mpsc::Receiver<(Bytes, SocketAddr)>>;
type ConnMap = Mutex<HashMap<SocketAddr, Arc<Mutex<TcpStream>>>>;

pub struct TcpTransport {
    local: SocketAddr,
    rx: RxReceiver,
    conns: Arc<ConnMap>,
}

impl TcpTransport {
    pub async fn bind(addr: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        let (tx, rx) = mpsc::channel::<(Bytes, SocketAddr)>(1024);
        let conns: Arc<ConnMap> = Arc::new(Mutex::new(HashMap::new()));

        // Spawn accept loop.
        let conns2 = conns.clone();
        tokio::spawn(accept_loop(listener, tx, conns2));

        Ok(Self {
            local,
            rx: Mutex::new(rx),
            conns,
        })
    }

    async fn get_or_connect(&self, addr: SocketAddr) -> std::io::Result<Arc<Mutex<TcpStream>>> {
        let mut map = self.conns.lock().await;
        if let Some(conn) = map.get(&addr) {
            return Ok(conn.clone());
        }
        let stream = TcpStream::connect(addr).await?;
        let arc = Arc::new(Mutex::new(stream));
        map.insert(addr, arc.clone());
        Ok(arc)
    }
}

#[async_trait]
impl Transport for TcpTransport {
    async fn send_to(&self, buf: &[u8], addr: TransportAddr) -> std::io::Result<()> {
        let remote = addr.socket_addr();
        let conn = self.get_or_connect(remote).await?;
        let mut stream = conn.lock().await;
        frame::write_frame(&mut *stream, buf).await?;
        stream.flush().await?;
        Ok(())
    }

    async fn recv_from(&self) -> std::io::Result<(Bytes, TransportAddr)> {
        let mut rx = self.rx.lock().await;
        rx.recv()
            .await
            .map(|(b, a)| (b, TransportAddr::Tcp(a)))
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::BrokenPipe, "tcp rx closed"))
    }

    fn local_addr(&self) -> TransportAddr {
        TransportAddr::Tcp(self.local)
    }
}

async fn accept_loop(listener: TcpListener, tx: RxSender, conns: Arc<ConnMap>) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                debug!(target: "seednet::transport::tcp", %peer, "accepted TCP connection");
                let tx2 = tx.clone();
                let conns2 = conns.clone();
                let stream = Arc::new(Mutex::new(stream));
                conns2.lock().await.insert(peer, stream.clone());
                tokio::spawn(read_loop(stream, peer, tx2));
            }
            Err(e) => {
                tracing::warn!(target: "seednet::transport::tcp", error = %e, "accept error");
            }
        }
    }
}

async fn read_loop(stream: Arc<Mutex<TcpStream>>, peer: SocketAddr, tx: RxSender) {
    loop {
        let result = {
            let mut s = stream.lock().await;
            frame::read_frame(&mut *s).await
        };
        match result {
            Ok(bytes) => {
                if tx.send((bytes, peer)).await.is_err() {
                    break;
                }
            }
            Err(e) => {
                debug!(target: "seednet::transport::tcp", %peer, error = %e, "TCP read error");
                break;
            }
        }
    }
}
