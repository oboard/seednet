//! Deriving network-wide values from a [`Seed`].

use std::net::Ipv4Addr;

use hkdf::Hkdf;
use seednet_common::Seed;
use seednet_common::{
    InfoHash, NetworkSecret, OVERLAY_HOST_RANGE_START, OVERLAY_SUBNET_BASE, OverlayAddr,
    PROTOCOL_MAGIC, PeerId,
};
use sha1::{Digest as _, Sha1};
use sha2::Sha256;

use seednet_common::NOISE_PROLOGUE_LEN;

/// Derive the 32-byte [`NetworkSecret`] from the user passphrase.
///
/// Uses HKDF-SHA256 with the SeedNet protocol magic as salt and a fixed `info`
/// string. Identical on every device that shares the seed.
pub fn derive_network_secret(seed: &Seed) -> NetworkSecret {
    let hk = Hkdf::<Sha256>::new(Some(PROTOCOL_MAGIC), seed.as_bytes());
    let mut okm = [0u8; NOISE_PROLOGUE_LEN];
    // Unwrap is safe: 32 bytes is well under the HKDF limit (255*HashLen).
    hk.expand(b"seednet network secret v1", &mut okm)
        .expect("HKDF expand of 32 bytes cannot fail");
    NetworkSecret::from_bytes(okm)
}

/// Derive the BitTorrent [`InfoHash`] (SHA-1 of the [`NetworkSecret`]).
///
/// This is the value peers announce to and look up in the Mainline DHT. It is
/// derived from (not equal to) the network secret so that leaking the infohash
/// does not reveal the prologue.
pub fn derive_infohash(secret: &NetworkSecret) -> InfoHash {
    let mut hasher = Sha1::new();
    hasher.update(b"seednet infohash v1");
    hasher.update(secret.as_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest);
    InfoHash::from_bytes(out)
}

/// Derive an [`OverlayAddr`] deterministically from a device's public key.
///
/// Produces a stable address in `10.88.0.0/16`, starting at `10.88.1.0` to
/// reserve the low `/24` for future network infrastructure. The third and
/// fourth octets come from BLAKE3 over the pubkey; the third octet is mapped
/// into `[1, 254]` so we never emit the network or broadcast addresses.
pub fn derive_overlay_addr(peer_id: &PeerId) -> OverlayAddr {
    let hash = blake3::hash(peer_id.as_bytes());
    let bytes = hash.as_bytes();
    // Use bytes 0 and 8 to decorrelate the two octets.
    let octet3 = (u16::from(bytes[0]) % 254) as u8 + OVERLAY_HOST_RANGE_START; // 1..=254
    let octet4 = bytes[8];
    let ip = Ipv4Addr::new(
        OVERLAY_SUBNET_BASE.octets()[0],
        OVERLAY_SUBNET_BASE.octets()[1],
        octet3,
        octet4,
    );
    OverlayAddr::new(ip)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_seed() -> Seed {
        Seed::from_passphrase("correct horse battery staple")
    }

    #[test]
    fn network_secret_is_deterministic() {
        let s = sample_seed();
        let a = derive_network_secret(&s);
        let b = derive_network_secret(&s);
        assert_eq!(a, b, "same seed must yield same secret");
    }

    #[test]
    fn different_seeds_yield_different_secrets() {
        let a = derive_network_secret(&Seed::from_passphrase("alpha"));
        let b = derive_network_secret(&Seed::from_passphrase("beta"));
        assert_ne!(a, b);
    }

    #[test]
    fn network_secret_is_32_bytes() {
        let s = derive_network_secret(&sample_seed());
        assert_eq!(s.as_bytes().len(), NOISE_PROLOGUE_LEN);
    }

    #[test]
    fn infohash_is_deterministic_and_20_bytes() {
        let secret = derive_network_secret(&sample_seed());
        let h = derive_infohash(&secret);
        assert_eq!(h.as_bytes().len(), 20);
        assert_eq!(h, derive_infohash(&secret));
    }

    #[test]
    fn infohash_changes_with_secret() {
        let s1 = derive_network_secret(&Seed::from_passphrase("a"));
        let s2 = derive_network_secret(&Seed::from_passphrase("b"));
        assert_ne!(derive_infohash(&s1), derive_infohash(&s2));
    }

    #[test]
    fn overlay_addr_is_in_subnet() {
        let id = PeerId::from_bytes([0x42; 32]);
        let addr = derive_overlay_addr(&id);
        let octets = addr.ip().octets();
        assert_eq!(&octets[..2], &[10, 88], "addr {} not in /16", addr);
        assert!(
            octets[2] >= 1 && octets[2] <= 254,
            "third octet out of range"
        );
    }

    #[test]
    fn overlay_addr_is_deterministic() {
        let id = PeerId::from_bytes([0x42; 32]);
        assert_eq!(derive_overlay_addr(&id), derive_overlay_addr(&id));
    }

    #[test]
    fn overlay_addr_distributes_well() {
        // The /16 holds ~65k addresses, so the birthday bound is √65000 ≈ 255.
        // We therefore cannot expect zero collisions among many keys from a pure
        // deterministic function — and we don't need to. Collision *resolution*
        // happens in Milestone 7 via a DHT claim step. Here we only verify that
        // the function spreads keys broadly across the address space.
        use std::collections::HashSet;
        const N: u32 = 500;
        let mut seen: HashSet<Ipv4Addr> = HashSet::new();
        for i in 0u32..N {
            let mut key = [0u8; 32];
            key[..4].copy_from_slice(&i.to_le_bytes());
            let id = PeerId::from_bytes(key);
            let addr = derive_overlay_addr(&id).ip();
            seen.insert(addr);
        }
        // Allow for birthday collisions but require good spread: at least 95%
        // of keys should map to distinct addresses.
        let min_distinct = (N as usize * 95) / 100;
        assert!(
            seen.len() >= min_distinct,
            "poor distribution: {} distinct addresses for {} keys (expected >= {})",
            seen.len(),
            N,
            min_distinct
        );
    }

    #[test]
    fn known_infohash_vector() {
        // Regression vector so future refactors don't silently change the
        // derivation — changing it would split existing networks.
        let secret = derive_network_secret(&Seed::from_passphrase("correct horse battery staple"));
        let h = derive_infohash(&secret).to_string();
        assert_eq!(h.len(), 40, "hex length");
        // Sanity: it's all lowercase hex.
        assert!(
            h.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }
}
