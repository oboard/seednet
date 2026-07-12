//! Wire messages exchanged between SeedNet peers.
//!
//! Every message is serialized with `postcard` (compact, no-schema) and framed
//! as `[u32 BE len][payload]` before hitting the UDP socket.

use std::net::SocketAddr;

use seednet_common::{PeerId, OverlayAddr};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Message {
    Data(Vec<u8>),
    Heartbeat,
    Ping,
    Pong,
    SessionInit { peer_id: PeerId, overlay: OverlayAddr },
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
