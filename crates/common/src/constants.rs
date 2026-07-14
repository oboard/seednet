//! Compile-time constants governing the SeedNet overlay.

use std::net::Ipv4Addr;

/// SeedNet's protocol magic. Used as an HKDF salt and as a framing tag so that
/// SeedNet traffic can be distinguished from unrelated UDP on the same port.
pub const PROTOCOL_MAGIC: &[u8] = b"seednet-v1";

/// Default UDP port SeedNet listens on. Deliberately in the ephemeral range to
/// improve NAT compatibility.
pub const DEFAULT_PORT: u16 = 4242;

/// Overlay IP subnet: `10.88.0.0/16`. Devices receive addresses inside this range.
pub const OVERLAY_SUBNET_BASE: Ipv4Addr = Ipv4Addr::new(10, 88, 0, 0);
/// Prefix length of the overlay subnet.
pub const OVERLAY_SUBNET_PREFIX: u8 = 16;
/// First usable overlay octet-3 range. We reserve `10.88.0.0/24` for network
/// infrastructure and allocate device addresses starting at `10.88.1.0`.
pub const OVERLAY_HOST_RANGE_START: u8 = 1;

/// Maximum transmission unit for the overlay. 1280 is the IPv6 minimum and a
/// safe value that avoids fragmenting after WireGuard-style UDP encapsulation
/// and Noise framing overhead on typical Internet paths.
pub const OVERLAY_MTU: usize = 1280;

/// Noise prologue length (SHA-256 sized). Matches the NetworkSecret length.
pub const NOISE_PROLOGUE_LEN: usize = 32;

/// BitTorrent info-hash length (SHA-1 sized).
pub const INFOHASH_LEN: usize = 20;

/// Ed25519 / X25519 key sizes.
pub const PUBLIC_KEY_LEN: usize = 32;
pub const SECRET_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

/// Heartbeat interval for the reliable message layer (seconds).
pub const HEARTBEAT_INTERVAL_SECS: u64 = 15;
/// Peer session expiration: no traffic for this long marks a peer `Dead`.
pub const SESSION_EXPIRY_SECS: u64 = 60;

/// Public STUN servers used to discover the node's NAT-mapped public address.
/// Queried in order; first success wins.
pub const STUN_SERVERS: &[&str] = &[
    "stun.l.google.com:19302",
    "stun.cloudflare.com:3478",
    "stun1.l.google.com:19302",
];

/// Wire prefix for unencrypted hole-punch probe packets.
/// Must not collide with Noise handshake prefixes (`seednet-hs-a`, `seednet-hs-b`).
pub const HOLE_PUNCH_PROBE_PREFIX: &[u8] = b"seednet-hp\0";
