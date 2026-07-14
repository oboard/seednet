//! Cryptography for SeedNet.
//!
//! Responsibilities:
//!   * Deterministically derive a [`NetworkSecret`] from a user-supplied
//!     [`Seed`](seednet_common::Seed) using HKDF-SHA256.
//!   * Derive the BitTorrent [`InfoHash`](seednet_common::InfoHash) (SHA-1) used
//!     for DHT announce/lookup.
//!   * Generate and persist per-device [`DeviceKeys`] (Ed25519 + X25519).
//!   * Deterministically derive an [`OverlayAddr`] from a device's public key.
//!
//! Per-device keys are generated randomly on first run and persisted; they are
//! **not** derived from the seed. This is deliberate: deriving from the shared
//! seed would give every device an identical private key, defeating Noise XX
//! mutual authentication. The shared [`NetworkSecret`] instead acts as the
//! Noise *prologue*, gating network membership.

pub mod device;
pub mod noise;
pub mod seed;

pub use device::{DeviceKeys, DeviceKeysBytes, DeviceSeedBytes};
pub use noise::{
    HandshakeResult, InitiatorHandshake, ResponderHandshake, SecureTransport,
    complete_handshake_pair,
};
pub use seed::{derive_infohash, derive_network_secret, derive_overlay_addr, derive_overlay_ipv6};

/// Crypto-crate-local error alias. Forwards to [`seednet_common::Error`] so all
/// crates in the workspace share a single error type.
pub type Error = seednet_common::Error;

// Re-export common types for convenience.
pub use seednet_common::{InfoHash, NetworkSecret, OverlayAddr, PeerId, Seed};
