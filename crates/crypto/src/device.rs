//! Per-device cryptographic keys.
//!
//! Each SeedNet device owns:
//!   * an **Ed25519** signing keypair (identity + [`PeerId`]);
//!   * an **X25519** static Diffie-Hellman key (used as the Noise static key).
//!
//! The two share the same 32-byte seed: Curve25519 is birationally equivalent
//! to Ed25519, so we derive both views from a single random scalar to keep
//! storage compact (one 32-byte secret on disk). The X25519 secret is produced
//! by clamping; this is independent of and does not weaken Ed25519 security.

use ed25519_dalek::SigningKey;
use seednet_common::{PUBLIC_KEY_LEN, PeerId, SECRET_KEY_LEN, SecretKeyBytes};
use serde::{Deserialize, Serialize};

use crate::Error;

/// The 32-byte secret seed from which a device's Ed25519 and X25519 keys are
/// both derived. This is the only secret that must be persisted.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeviceSeedBytes([u8; SECRET_KEY_LEN]);

impl DeviceSeedBytes {
    /// Generate a fresh, cryptographically random device seed.
    pub fn generate() -> Self {
        Self(rand::random::<[u8; SECRET_KEY_LEN]>())
    }

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

impl std::fmt::Debug for DeviceSeedBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Do not reveal secret material.
        write!(f, "DeviceSeedBytes(**redacted**)")
    }
}

/// All cryptographic keys for one device, derived from a [`DeviceSeedBytes`].
///
/// Constructed via [`DeviceKeys::from_seed`] and cheap to re-derive on load.
#[derive(Clone, Debug)]
pub struct DeviceKeys {
    /// Ed25519 signing key (32-byte secret, carries the verifying key).
    signing: SigningKey,
}

impl DeviceKeys {
    /// Generate a brand-new random identity. Used on first run.
    pub fn generate() -> Self {
        Self::from_seed(DeviceSeedBytes::generate())
    }

    /// Re-derive the full key set from a stored 32-byte seed.
    pub fn from_seed(seed: DeviceSeedBytes) -> Self {
        let signing = SigningKey::from_bytes(&seed.0);
        Self { signing }
    }

    /// The persisted seed material (the only thing written to disk).
    pub fn seed_bytes(&self) -> DeviceSeedBytes {
        DeviceSeedBytes(*self.signing.as_bytes())
    }

    /// The 32-byte Ed25519 verifying (public) key.
    pub fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.signing.verifying_key().to_bytes()
    }

    /// The device's [`PeerId`] (== its Ed25519 public key).
    pub fn peer_id(&self) -> PeerId {
        PeerId::from_bytes(self.public_key())
    }

    /// The 32-byte X25519 static secret, clamped, suitable as a Noise static
    /// key. Derived from the same seed via standard scalar clamping.
    pub fn x25519_static_secret(&self) -> [u8; SECRET_KEY_LEN] {
        // X25519 and Ed25519 share Curve25519; the standard approach is to
        // clamp the Ed25519 seed bytes into a valid X25519 scalar. We reuse the
        // same seed, clamp it, and return the clamped bytes.
        let mut k = *self.signing.as_bytes();
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
        k
    }

    /// The 32-byte X25519 public key derived from the static secret.
    pub fn x25519_public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        let secret = x25519_dalek::StaticSecret::from(self.x25519_static_secret());
        let public = x25519_dalek::PublicKey::from(&secret);
        public.to_bytes()
    }

    /// The Ed25519 signing key, for signing application-level messages.
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing
    }
}

/// Serialization envelope written to `~/.seednet/identity.bin`.
///
/// Versioned so future format changes can migrate cleanly.
#[derive(Serialize, Deserialize)]
pub struct DeviceKeysBytes {
    pub version: u32,
    pub seed: SecretKeyBytes,
}

impl DeviceKeysBytes {
    /// Current serialization format version.
    pub const CURRENT_VERSION: u32 = 1;

    /// Serialize a [`DeviceKeys`] into the on-disk envelope.
    pub fn from_keys(keys: &DeviceKeys) -> Self {
        let seed = keys.seed_bytes();
        Self {
            version: Self::CURRENT_VERSION,
            seed: SecretKeyBytes::from_bytes(seed.into_inner()),
        }
    }

    /// Deserialize the on-disk envelope into raw seed bytes.
    pub fn into_seed(self) -> Result<DeviceSeedBytes, Error> {
        if self.version != Self::CURRENT_VERSION {
            return Err(Error::UnsupportedIdentityVersion(self.version));
        }
        Ok(DeviceSeedBytes::from_bytes(self.seed.into_inner()))
    }

    /// Encode to compact bytes (postcard).
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        Ok(postcard::to_allocvec(self)?)
    }

    /// Decode from compact bytes (postcard).
    pub fn from_bytes(input: &[u8]) -> Result<Self, Error> {
        Ok(postcard::from_bytes(input)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_via_seed_bytes() {
        let keys = DeviceKeys::generate();
        let seed = keys.seed_bytes();
        let restored = DeviceKeys::from_seed(seed);
        assert_eq!(restored.public_key(), keys.public_key());
        assert_eq!(restored.peer_id(), keys.peer_id());
    }

    #[test]
    fn two_generations_are_distinct() {
        let a = DeviceKeys::generate();
        let b = DeviceKeys::generate();
        assert_ne!(a.public_key(), b.public_key());
        assert_ne!(a.peer_id(), b.peer_id());
    }

    #[test]
    fn envelope_round_trip() {
        let keys = DeviceKeys::generate();
        let env = DeviceKeysBytes::from_keys(&keys);
        let bytes = env.to_bytes().unwrap();
        let decoded = DeviceKeysBytes::from_bytes(&bytes).unwrap();
        let seed = decoded.into_seed().unwrap();
        let restored = DeviceKeys::from_seed(seed);
        assert_eq!(restored.public_key(), keys.public_key());
    }

    #[test]
    fn unsupported_version_rejected() {
        let env = DeviceKeysBytes {
            version: 999,
            seed: SecretKeyBytes::from_bytes([0u8; SECRET_KEY_LEN]),
        };
        assert!(matches!(
            env.into_seed(),
            Err(Error::UnsupportedIdentityVersion(999))
        ));
    }

    #[test]
    fn x25519_public_is_32_bytes_and_stable() {
        let keys = DeviceKeys::generate();
        let pk = keys.x25519_public_key();
        assert_eq!(pk.len(), 32);
        assert_eq!(pk, keys.x25519_public_key());
    }

    #[test]
    fn peer_id_is_32_bytes() {
        let keys = DeviceKeys::generate();
        assert_eq!(keys.peer_id().as_bytes().len(), 32);
    }
}
