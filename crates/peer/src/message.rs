//! Wire messages exchanged between SeedNet peers.
//!
//! Every message is serialized with `postcard` (compact, no-schema).

use std::net::SocketAddr;

use seednet_common::{OverlayAddr, PeerId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Message {
    Data(Vec<u8>),
    Heartbeat,
    /// Latency probe; recipient echoes back with Pong.
    Ping {
        /// Milliseconds since Unix epoch at send time (for RTT calculation).
        sent_ms: u64,
    },
    /// Response to Ping; echoes sent_ms so sender can compute RTT.
    Pong {
        sent_ms: u64,
    },
    SessionInit {
        peer_id: PeerId,
        overlay: OverlayAddr,
        /// Deterministic ULA IPv6 address (`fd::/8`).
        overlay_ipv6: Option<[u8; 16]>,
        /// Hostname of the sending device (best-effort, may be empty).
        hostname: String,
        /// STUN-discovered public address of the sender.
        public_addr: Option<SocketAddr>,
    },
    /// Unencrypted probe sent to open a NAT mapping.
    /// Wire format: HOLE_PUNCH_PROBE_PREFIX + postcard(this variant).
    HolePunchProbe {
        token: u64,
    },
    /// Acknowledgement to a HolePunchProbe.
    HolePunchAck {
        token: u64,
    },
    /// Request a relay node to forward traffic to `dst_peer_id`.
    RelayRequest {
        dst_peer_id: PeerId,
    },
    /// Relay node confirms it can forward between the two peers.
    RelayReady {
        relay_peer_id: PeerId,
        dst_peer_id: PeerId,
    },
    /// Encapsulated data for relay forwarding.
    /// `payload` is already Noise-encrypted — relay never decrypts it.
    RelayData {
        dst_peer_id: PeerId,
        payload: Vec<u8>,
    },
    /// Broadcast by relay-capable nodes to advertise their public address.
    RelayAnnounce {
        relay_peer_id: PeerId,
        public_addr: SocketAddr,
    },
    /// Relay-capable node sends a directory of all known peers so new
    /// joiners can request relay immediately without waiting for DHT or
    /// a direct handshake attempt.
    PeerDirectory {
        /// (peer_id, public_addr) pairs known to the sender.
        entries: Vec<(PeerId, SocketAddr)>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InboundMessage {
    pub message: Message,
    pub from: SocketAddr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OutboundMessage {
    pub message: Message,
    pub to: SocketAddr,
}

pub fn serialize_message(msg: &Message) -> Vec<u8> {
    postcard::to_allocvec(msg).expect("postcard serialize")
}

pub fn deserialize_message(data: &[u8]) -> Result<Message, postcard::Error> {
    postcard::from_bytes(data)
}
