//! Error types shared across the SeedNet workspace.

use thiserror::Error;

/// The canonical Result alias for SeedNet-internal operations.
pub type Result<T> = std::result::Result<T, Error>;

/// All SeedNet errors. Each variant corresponds to a distinct recoverable or
/// non-recoverable condition so callers can match precisely.
#[derive(Debug, Error)]
pub enum Error {
    // --- Seed / identity ---------------------------------------------------
    #[error("seed (passphrase) must not be empty")]
    EmptySeed,

    #[error("invalid hex input: odd length {0}")]
    InvalidHexLength(usize),

    #[error("invalid hex character: {0:?}")]
    InvalidHexChar(char),

    #[error("infohash must be 20 bytes, got {0}")]
    InvalidInfoHashLen(usize),

    #[error("peer id must be 32 bytes, got {0}")]
    InvalidPeerIdLen(usize),

    // --- Crypto ------------------------------------------------------------
    #[error("cryptography error: {0}")]
    Crypto(String),

    #[error("Noise handshake failed: {0}")]
    NoiseHandshake(String),

    #[error("Noise transport error: {0}")]
    NoiseTransport(String),

    // --- Config / persistence ---------------------------------------------
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialize(String),

    #[error("identity file missing or unreadable at {0}")]
    IdentityMissing(std::path::PathBuf),

    #[error("identity file corrupt: {0}")]
    IdentityCorrupt(String),

    #[error("unsupported identity file version: {0}")]
    UnsupportedIdentityVersion(u32),

    // --- Networking --------------------------------------------------------
    #[error("address parse error: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    #[error("DHT error: {0}")]
    Dht(String),
}

impl From<postcard::Error> for Error {
    fn from(e: postcard::Error) -> Self {
        Error::Serialize(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_error_conversion() {
        let io = std::io::Error::new(std::io::ErrorKind::NotFound, "x");
        let e: Error = io.into();
        assert!(matches!(e, Error::Io(_)));
        assert!(e.to_string().contains("io error"));
    }
}
