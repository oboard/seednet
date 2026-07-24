//! Wire messages exchanged between SeedNet peers.
//!
//! Every message is serialized with `postcard` (compact, no-schema).

use std::borrow::Cow;
use std::net::SocketAddr;

use seednet_common::{OverlayAddr, PeerId};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Message {
    /// Raw IP packet payload.
    /// Use `Cow::Borrowed` on the send path to avoid cloning the TUN buffer.
    /// Deserializing always yields `Cow::Owned`.
    Data(#[serde(with = "serde_cow_bytes")] Cow<'static, [u8]>),
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
    /// Sent immediately after a successful Noise handshake to exchange overlay
    /// metadata. The sender's PeerId is already known from the handshake
    /// (== the sender's X25519 static key), so it is not repeated here.
    SessionInit {
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
    /// `payload` is Noise-encrypted with the sender→dst session key.
    /// The relay forwards it opaquely; the destination decrypts with the sender's session.
    RelayData {
        src_peer_id: PeerId,
        dst_peer_id: PeerId,
        #[serde(with = "serde_cow_bytes")]
        payload: Cow<'static, [u8]>,
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
        /// `(peer_id, public_addr, hop_count)` tuples known to the sender.
        /// `hop_count = 1` means a direct neighbor of the sender.
        entries: Vec<(PeerId, SocketAddr, u8)>,
    },
}

/// Serde shim: serialize `Cow<'static, [u8]>` as a byte sequence (same wire
/// format as `Vec<u8>`), and deserialize into the owned variant so the result
/// is independent of the input buffer.
mod serde_cow_bytes {
    use std::borrow::Cow;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use serde_bytes::ByteBuf;

    pub fn serialize<S: Serializer>(cow: &[u8], s: S) -> Result<S::Ok, S::Error> {
        serde_bytes::Bytes::new(cow).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Cow<'static, [u8]>, D::Error> {
        ByteBuf::deserialize(d).map(|b| Cow::Owned(b.into_vec()))
    }
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

/// Serialize `msg` into `buf` (cleared first), reusing its allocation.
/// Prefer this over `serialize_message` on hot paths to avoid per-call heap
/// allocation.
pub fn serialize_message_into(msg: &Message, buf: &mut Vec<u8>) {
    buf.clear();
    postcard::to_io(msg, buf).expect("postcard serialize");
}

pub fn deserialize_message(data: &[u8]) -> Result<Message, postcard::Error> {
    postcard::from_bytes(data)
}
