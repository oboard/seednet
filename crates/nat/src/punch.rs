//! UDP hole-punch coordinator.
//!
//! Generates tokens and tracks which `SocketAddr` responded to a probe.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use std::time::Instant;

use seednet_common::HOLE_PUNCH_PROBE_PREFIX;

const TOKEN_TTL: Duration = Duration::from_secs(30);

/// Builds the unencrypted wire bytes for a HolePunchProbe or HolePunchAck.
pub fn probe_bytes(token: u64) -> Vec<u8> {
    // Variant tag 0 = HolePunchProbe in the Message enum postcard encoding.
    // We serialize manually to avoid depending on seednet-peer here.
    // Wire: PREFIX + varint(variant_index) + varint(token)
    // postcard encodes the enum as: tag byte + fields
    // HolePunchProbe is variant 6 (0-indexed: Data=0, Heartbeat=1, Ping=2, Pong=3,
    // SessionInit=4, HolePunchProbe=5)
    let mut buf = HOLE_PUNCH_PROBE_PREFIX.to_vec();
    // postcard enum tag for HolePunchProbe (variant 5)
    buf.push(5);
    // postcard encodes u64 as varint
    encode_varint(&mut buf, token);
    buf
}

pub fn ack_bytes(token: u64) -> Vec<u8> {
    let mut buf = HOLE_PUNCH_PROBE_PREFIX.to_vec();
    // HolePunchAck is variant 6
    buf.push(6);
    encode_varint(&mut buf, token);
    buf
}

fn encode_varint(buf: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7F) as u8;
        v >>= 7;
        if v == 0 {
            buf.push(byte);
            break;
        } else {
            buf.push(byte | 0x80);
        }
    }
}

/// Tracks in-flight hole-punch tokens and the addresses that responded.
pub struct PunchCoordinator {
    /// token → (expected_addr, created_at)
    pending: HashMap<u64, (SocketAddr, Instant)>,
    /// token → confirmed addr (punch succeeded)
    confirmed: HashMap<u64, SocketAddr>,
}

impl PunchCoordinator {
    pub fn new() -> Self {
        Self {
            pending: HashMap::new(),
            confirmed: HashMap::new(),
        }
    }

    /// Generate a fresh random token for a new punch attempt toward `addr`.
    pub fn new_token(&mut self, addr: SocketAddr) -> u64 {
        self.evict_stale();
        let token: u64 = rand::random();
        self.pending.insert(token, (addr, Instant::now()));
        token
    }

    /// Called when a HolePunchAck arrives from `from`.
    pub fn record_ack(&mut self, token: u64, from: SocketAddr) {
        self.confirmed.insert(token, from);
    }

    /// Called when a HolePunchProbe arrives from `from` (we are the responder).
    /// Returns the ack+probe bytes to send back.
    pub fn handle_probe(&mut self, token: u64, from: SocketAddr) -> (Vec<u8>, Vec<u8>) {
        self.confirmed.insert(token, from);
        (ack_bytes(token), probe_bytes(token))
    }

    /// Check if a token has been confirmed.
    pub fn is_confirmed(&self, token: u64) -> Option<SocketAddr> {
        self.confirmed.get(&token).copied()
    }

    fn evict_stale(&mut self) {
        let now = Instant::now();
        self.pending
            .retain(|_, (_, t)| now.duration_since(*t) < TOKEN_TTL);
    }
}

impl Default for PunchCoordinator {
    fn default() -> Self {
        Self::new()
    }
}
