//! [`MessageChannel`] — async UDP send/recv with Noise encryption and framing.
//!
//! Wraps a `UdpSocket`, performs Noise XX handshake on first contact, then
//! sends/receives framed and encrypted [`Message`]s. A heartbeat task keeps
//! sessions alive.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use seednet_common::{Error, NetworkSecret, OVERLAY_MTU, PeerId};
use seednet_crypto::{DeviceKeys, InitiatorHandshake, ResponderHandshake, SecureTransport};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::sync::mpsc;

use crate::frame;
use crate::message::{self, InboundMessage, Message, OutboundMessage};
use crate::session::Session;

const INBOUND_BUF: usize = 256;
const OUTBOUND_BUF: usize = 256;
const MAX_DATAGRAM: usize = OVERLAY_MTU + frame::HEADER_LEN + 16 + 64;

#[derive(Debug)]
struct PeerTransport {
    transport: SecureTransport,
    session: Session,
}

pub struct MessageChannel {
    socket: Arc<UdpSocket>,
    network_secret: NetworkSecret,
    device_keys: DeviceKeys,
    transports: Arc<RwLock<HashMap<SocketAddr, PeerTransport>>>,
    inbound_tx: mpsc::Sender<InboundMessage>,
    outbound_rx: mpsc::Receiver<OutboundMessage>,
    outbound_tx: mpsc::Sender<OutboundMessage>,
}

impl MessageChannel {
    pub fn new(socket: UdpSocket, network_secret: NetworkSecret, device_keys: DeviceKeys) -> Self {
        let (inbound_tx, _) = mpsc::channel(INBOUND_BUF);
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_BUF);
        Self {
            socket: Arc::new(socket),
            network_secret,
            device_keys,
            transports: Arc::new(RwLock::new(HashMap::new())),
            inbound_tx,
            outbound_rx,
            outbound_tx,
        }
    }

    pub fn sender(&self) -> mpsc::Sender<OutboundMessage> {
        self.outbound_tx.clone()
    }

    pub fn take_receiver(&mut self) -> mpsc::Receiver<InboundMessage> {
        let (tx, rx) = mpsc::channel(INBOUND_BUF);
        self.inbound_tx = tx;
        rx
    }

    pub fn local_addr(&self) -> std::result::Result<SocketAddr, std::io::Error> {
        self.socket.local_addr()
    }

    pub async fn initate_handshake(&self, addr: SocketAddr) -> std::result::Result<PeerId, Error> {
        let mut initiator = InitiatorHandshake::new(&self.network_secret, &self.device_keys)?;
        let msg_a = initiator.write_message_a(&[])?;

        self.socket
            .send_to(&msg_a, addr)
            .await
            .map_err(|e| Error::NoiseTransport(format!("send msg A: {e}")))?;

        let mut buf = vec![0u8; MAX_DATAGRAM];
        let (n, from) = self
            .socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| Error::NoiseTransport(format!("recv msg B: {e}")))?;

        if from != addr {
            return Err(Error::NoiseTransport(
                "msg B from unexpected address".into(),
            ));
        }

        initiator.read_message_b(&buf[..n])?;
        let init_result = initiator.finish(&[])?;

        let remote_static = *init_result.transport.remote_static_key();
        let peer_id = PeerId::from_bytes(remote_static);

        self.socket
            .send_to(&init_result.msg_bytes, addr)
            .await
            .map_err(|e| Error::NoiseTransport(format!("send msg C: {e}")))?;

        self.transports.write().await.insert(
            addr,
            PeerTransport {
                transport: init_result.transport,
                session: Session::new(),
            },
        );

        Ok(peer_id)
    }

    async fn handle_inbound_datagram(
        &self,
        data: &[u8],
        from: SocketAddr,
    ) -> std::result::Result<(), Error> {
        let mut transports = self.transports.write().await;

        if let Some(pt) = transports.get_mut(&from) {
            let framed = frame::decode_frame(data)?;
            let decrypted = pt.transport.decrypt(framed)?;
            pt.session.record_activity();
            let msg = message::deserialize_message(&decrypted)
                .map_err(|e| Error::NoiseTransport(format!("deserialize: {e}")))?;
            let _ = self
                .inbound_tx
                .try_send(InboundMessage { message: msg, from });
            return Ok(());
        }

        drop(transports);

        let mut responder = ResponderHandshake::new(&self.network_secret, &self.device_keys)?;
        responder.read_message_a(data)?;

        let msg_b = responder.write_message_b(&[])?;
        self.socket
            .send_to(&msg_b, from)
            .await
            .map_err(|e| Error::NoiseTransport(format!("send msg B: {e}")))?;

        let mut buf = vec![0u8; MAX_DATAGRAM];
        let (n, from2) = self
            .socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| Error::NoiseTransport(format!("recv msg C: {e}")))?;

        if from2 != from {
            return Err(Error::NoiseTransport(
                "msg C from unexpected address".into(),
            ));
        }

        let resp_result = responder.finish(&buf[..n])?;
        let remote_static = *resp_result.transport.remote_static_key();
        let peer_id = PeerId::from_bytes(remote_static);

        tracing::info!(peer = %peer_id.short(), addr = %from, "handshake completed (responder side)");

        self.transports.write().await.insert(
            from,
            PeerTransport {
                transport: resp_result.transport,
                session: Session::new(),
            },
        );

        Ok(())
    }

    async fn send_message(&self, msg: &OutboundMessage) -> std::result::Result<(), Error> {
        let mut transports = self.transports.write().await;
        let pt = transports
            .get_mut(&msg.to)
            .ok_or_else(|| Error::NoiseTransport(format!("no transport for {}", msg.to)))?;

        let payload = message::serialize_message(&msg.message);
        let encrypted = pt.transport.encrypt(&payload)?;
        let framed = frame::encode_frame(&encrypted);

        self.socket
            .send_to(&framed, msg.to)
            .await
            .map_err(|e| Error::NoiseTransport(format!("send: {e}")))?;
        pt.session.record_activity();
        Ok(())
    }

    pub async fn run(&mut self) {
        let mut buf = vec![0u8; MAX_DATAGRAM];
        loop {
            tokio::select! {
                result = self.socket.recv_from(&mut buf) => {
                    match result {
                        Ok((n, from)) => {
                            if let Err(e) = self.handle_inbound_datagram(&buf[..n], from).await {
                                tracing::debug!(from = %from, error = %e, "inbound handling failed");
                            }
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "recv_from error");
                        }
                    }
                }
                Some(out) = self.outbound_rx.recv() => {
                    if let Err(e) = self.send_message(&out).await {
                        tracing::debug!(to = %out.to, error = %e, "send failed");
                    }
                }
                else => {
                    break;
                }
            }
        }
    }

    pub async fn prune_expired(&self) -> Vec<SocketAddr> {
        let mut transports = self.transports.write().await;
        let expired: Vec<SocketAddr> = transports
            .iter()
            .filter(|(_, pt)| pt.session.is_expired())
            .map(|(addr, _)| *addr)
            .collect();
        for addr in &expired {
            transports.remove(addr);
        }
        expired
    }

    pub async fn heartbeat_needed(&self) -> Vec<SocketAddr> {
        let transports = self.transports.read().await;
        transports
            .iter()
            .filter(|(_, pt)| pt.session.should_send_heartbeat())
            .map(|(addr, _)| *addr)
            .collect()
    }

    pub async fn send_heartbeat(&self, addr: SocketAddr) -> std::result::Result<(), Error> {
        self.send_message(&OutboundMessage {
            message: Message::Heartbeat,
            to: addr,
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seednet_common::OverlayAddr;
    use seednet_common::Seed;
    use seednet_crypto::{DeviceSeedBytes, complete_handshake_pair, derive_network_secret};

    fn test_secret() -> NetworkSecret {
        derive_network_secret(&Seed::from_passphrase("test"))
    }

    fn _test_keys() -> DeviceKeys {
        DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0x55u8; 32]))
    }

    #[test]
    fn frame_encrypt_decrypt_roundtrip() {
        let secret = test_secret();
        let keys_a = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0x11u8; 32]));
        let keys_b = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0x22u8; 32]));

        let (mut t_a, mut t_b) =
            complete_handshake_pair(&secret, &keys_a, &secret, &keys_b).unwrap();

        let msg = Message::Data(b"hello overlay".to_vec().into());
        let payload = message::serialize_message(&msg);
        let encrypted: Vec<u8> = t_a.encrypt(&payload).unwrap();
        let framed = frame::encode_frame(&encrypted);

        let inner = frame::decode_frame(&framed).unwrap();
        let decrypted: Vec<u8> = t_b.decrypt(inner).unwrap();
        let recovered: Message = message::deserialize_message(&decrypted).unwrap();
        assert_eq!(recovered, msg);
    }

    #[test]
    fn session_expiry_works() {
        let mut s = Session::with_config(
            std::time::Duration::from_millis(1),
            std::time::Duration::from_millis(1),
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
        assert!(s.is_expired());
        s.record_activity();
        assert!(!s.is_expired());
    }

    #[test]
    fn serialize_deserialize_messages() {
        let cases = vec![
            Message::Data(vec![1, 2, 3].into()),
            Message::Heartbeat,
            Message::Ping { sent_ms: 0 },
            Message::Pong { sent_ms: 0 },
            Message::SessionInit {
                overlay: OverlayAddr::new(std::net::Ipv4Addr::new(10, 88, 1, 1)),
                overlay_ipv6: None,
                hostname: String::new(),
                public_addr: None,
            },
        ];
        for msg in cases {
            let bytes = message::serialize_message(&msg);
            let recovered = message::deserialize_message(&bytes).unwrap();
            assert_eq!(recovered, msg);
        }
    }
}
