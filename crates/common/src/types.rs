//! Core SeedNet types: [`Seed`], [`NetworkSecret`], [`InfoHash`], [`PeerId`],
//! [`OverlayAddr`].
//!
//! All of these are plain `#[repr(transparent)]` newtypes around byte arrays so
//! that they are cheap to pass around, [`Copy`] where the inner type allows it,
//! and serializable with `serde` + `postcard` for persistence and wire framing.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::constants::{
    INFOHASH_LEN, NOISE_PROLOGUE_LEN, PROTOCOL_MAGIC, PUBLIC_KEY_LEN, SECRET_KEY_LEN,
};
use crate::error::{Error, Result};

// ---------------------------------------------------------------------------
// Seed
// ---------------------------------------------------------------------------

/// The user-supplied passphrase that bootstraps a network.
///
/// Every device using the same seed joins the same overlay. Stored as owned
/// bytes so that it can be constructed from a `&str` or raw bytes and then
/// dropped from memory deliberately by the caller.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Seed(Vec<u8>);

impl Seed {
    /// Construct a [`Seed`] from a passphrase string.
    pub fn from_passphrase(s: &str) -> Self {
        Self(s.as_bytes().to_vec())
    }

    /// Raw passphrase bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Minimum accepted passphrase length. We do not enforce complexity rules;
    /// the user is responsible for entropy, but we refuse the empty string.
    pub const MIN_LEN: usize = 1;
}

impl FromStr for Seed {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.len() < Self::MIN_LEN {
            return Err(Error::EmptySeed);
        }
        Ok(Self::from_passphrase(s))
    }
}

impl fmt::Display for Seed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the raw passphrase; show only a fingerprint.
        let fp = blake3_fingerprint(self.as_bytes());
        write!(f, "seed:{}", hex_short(&fp))
    }
}

// ---------------------------------------------------------------------------
// NetworkSecret
// ---------------------------------------------------------------------------

/// A 32-byte secret derived from the [`Seed`] via HKDF-SHA256.
///
/// Identical on every device sharing the same seed. It is *not* a transport
/// key; it serves two purposes:
///   1. hashed to the BitTorrent [`InfoHash`] used for DHT announce/lookup;
///   2. used as the Noise protocol *prologue*, so that only devices that know
///      the same network secret can complete a Noise XX handshake.
#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
pub struct NetworkSecret([u8; NOISE_PROLOGUE_LEN]);

impl NetworkSecret {
    /// Construct from a raw 32-byte array. Only `seednet-crypto` should call
    /// this; the public API is `derive_network_secret`.
    pub const fn from_bytes(bytes: [u8; NOISE_PROLOGUE_LEN]) -> Self {
        Self(bytes)
    }

    /// View as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Reveal the underlying array (used when an API requires owned bytes).
    pub fn into_inner(self) -> [u8; NOISE_PROLOGUE_LEN] {
        self.0
    }
}

impl fmt::Debug for NetworkSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never leak the secret; show only a short fingerprint.
        let fp = blake3_fingerprint(&self.0);
        write!(f, "NetworkSecret({})", hex_short(&fp))
    }
}

// ---------------------------------------------------------------------------
// InfoHash
// ---------------------------------------------------------------------------

/// A 20-byte BitTorrent Mainline DHT info-hash, the SHA-1 of the
/// [`NetworkSecret`]. Peers announce and look up this value to find each other.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct InfoHash([u8; INFOHASH_LEN]);

impl InfoHash {
    pub const fn from_bytes(bytes: [u8; INFOHASH_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for InfoHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Hex-encode lowercase, matching the conventional magnet/infohash form.
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl fmt::Debug for InfoHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InfoHash({})", self)
    }
}

impl FromStr for InfoHash {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let bytes = hex_decode(s)?;
        if bytes.len() != INFOHASH_LEN {
            return Err(Error::InvalidInfoHashLen(bytes.len()));
        }
        let mut out = [0u8; INFOHASH_LEN];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }
}

// ---------------------------------------------------------------------------
// PeerId
// ---------------------------------------------------------------------------

/// A 32-byte identifier for a device: the Ed25519 public key of that device.
///
/// Distinct per device (unlike the shared [`NetworkSecret`]), so it is the
/// canonical identity used in the peer table and for overlay-IP derivation.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct PeerId([u8; PUBLIC_KEY_LEN]);

impl PeerId {
    pub const fn from_bytes(bytes: [u8; PUBLIC_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// A short, human-friendly hex prefix for log lines.
    pub fn short(&self) -> String {
        hex_short(&self.0)
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PeerId({})", self.short())
    }
}

impl FromStr for PeerId {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let bytes = hex_decode(s)?;
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(Error::InvalidPeerIdLen(bytes.len()));
        }
        let mut out = [0u8; PUBLIC_KEY_LEN];
        out.copy_from_slice(&bytes);
        Ok(Self(out))
    }
}

// ---------------------------------------------------------------------------
// OverlayAddr
// ---------------------------------------------------------------------------

/// An overlay IPv4 address assigned to a device inside the SeedNet subnet.
///
/// This newtype prevents accidentally mixing overlay addresses with underlay
/// transport addresses.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct OverlayAddr(Ipv4Addr);

impl OverlayAddr {
    pub const fn new(addr: Ipv4Addr) -> Self {
        Self(addr)
    }

    pub const fn ip(self) -> Ipv4Addr {
        self.0
    }
}

impl fmt::Display for OverlayAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for OverlayAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OverlayAddr({})", self.0)
    }
}

impl From<Ipv4Addr> for OverlayAddr {
    fn from(addr: Ipv4Addr) -> Self {
        Self(addr)
    }
}

impl From<OverlayAddr> for Ipv4Addr {
    fn from(addr: OverlayAddr) -> Self {
        addr.0
    }
}

// ---------------------------------------------------------------------------
// SecretKeyBytes — generic 32-byte secret material for persistence
// ---------------------------------------------------------------------------

/// Owned 32-byte secret material used as a transport/serialization envelope.
///
/// Kept opaque and non-[`Debug`]-revealing so that secrets are not accidentally
/// logged.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct SecretKeyBytes([u8; SECRET_KEY_LEN]);

impl SecretKeyBytes {
    pub const fn from_bytes(bytes: [u8; SECRET_KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_inner(self) -> [u8; SECRET_KEY_LEN] {
        self.0
    }
}

impl fmt::Debug for SecretKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let fp = blake3_fingerprint(&self.0);
        write!(f, "SecretKeyBytes({})", hex_short(&fp))
    }
}

// ---------------------------------------------------------------------------
// helpers (not public API)
// ---------------------------------------------------------------------------

fn blake3_fingerprint(input: &[u8]) -> [u8; 16] {
    // We pull blake3 via a tiny FFI-free path here: hash through a const
    // computation is not available, so we re-implement a stable short digest
    // using the first 16 bytes of two rounds of FNV-1a over the protocol magic
    // and input. This is *only* a display fingerprint, never used for security.
    let mut h = [0u8; 16];
    // Seed the state with the protocol magic so fingerprints are namespaced.
    let mut a: u64 = 0xcbf29ce484222325;
    let mut b: u64 = 0x84222325cbf29ce4;
    for &m in PROTOCOL_MAGIC {
        a ^= u64::from(m);
        a = a.wrapping_mul(0x100000001b3);
    }
    for &x in input {
        a ^= u64::from(x);
        a = a.wrapping_mul(0x100000001b3);
        b = b.wrapping_add(a).rotate_left(7);
    }
    h[..8].copy_from_slice(&a.to_le_bytes());
    h[8..].copy_from_slice(&b.to_le_bytes());
    h
}

fn hex_short(bytes: &[u8]) -> String {
    // First 4 bytes → 8 hex chars; enough to disambiguate in logs.
    let n = bytes.len().min(4);
    let mut s = String::with_capacity(n * 2);
    for &b in &bytes[..n] {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(Error::InvalidHexLength(s.len()));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks_exact(2) {
        let hi = hex_val(chunk[0])?;
        let lo = hex_val(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_val(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(Error::InvalidHexChar(c as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_round_trip() {
        let s = Seed::from_passphrase("correct horse battery staple");
        assert_eq!(s.as_bytes(), b"correct horse battery staple");
    }

    #[test]
    fn seed_rejects_empty() {
        assert!(matches!(Seed::from_str(""), Err(Error::EmptySeed)));
    }

    #[test]
    fn infohash_display_roundtrip() {
        let raw = [0xabu8; INFOHASH_LEN];
        let h = InfoHash::from_bytes(raw);
        let s = h.to_string();
        let parsed: InfoHash = s.parse().expect("parse");
        assert_eq!(parsed, h);
    }

    #[test]
    fn peer_id_parse_roundtrip() {
        let raw = [0x11u8; PUBLIC_KEY_LEN];
        let id = PeerId::from_bytes(raw);
        let s = id.to_string();
        let parsed: PeerId = s.parse().expect("parse");
        assert_eq!(parsed, id);
    }

    #[test]
    fn peer_id_rejects_wrong_length() {
        assert!(matches!(
            PeerId::from_str("deadbeef"),
            Err(Error::InvalidPeerIdLen(4))
        ));
    }

    #[test]
    fn network_secret_debug_redacted() {
        let ns = NetworkSecret::from_bytes([0xff; NOISE_PROLOGUE_LEN]);
        let dbg = format!("{:?}", ns);
        assert!(!dbg.contains("ff"), "secret leaked: {}", dbg);
    }

    #[test]
    fn overlay_addr_conversions() {
        let ip = Ipv4Addr::new(10, 88, 1, 5);
        let oa = OverlayAddr::new(ip);
        assert_eq!(Ipv4Addr::from(oa), ip);
        assert_eq!(oa.to_string(), "10.88.1.5");
    }

    #[test]
    fn hex_decode_basic() {
        let v = hex_decode("deadbeef").unwrap();
        assert_eq!(v, [0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    fn hex_decode_rejects_odd() {
        assert!(hex_decode("abc").is_err());
    }
}
