//! Noise XX handshake and encrypted transport for SeedNet.
//!
//! Uses the `Noise_XX_25519_ChaChaPoly_BLAKE2s` pattern with the
//! [`NetworkSecret`] as the prologue. Only peers sharing the same network
//! secret can complete the handshake — prologue mismatch causes the
//! `snow` handshake to fail, gating network membership.
//!
//! # Handshake flow (3 messages)
//!
//! ```text
//! Initiator                          Responder
//!    │  → e                                    │  (msg 1: ephemeral key)
//!    │  → e, ee, s, es                         │  (msg 2: e + ee + s + es)
//!    │  → s, se                                │  (msg 3: s + se)
//!    │                    → Transport ←         │
//! ```

use crate::device::DeviceKeys;
use seednet_common::{Error, NetworkSecret};

pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
pub const MAX_MESSAGE_LEN: usize = 65535;
/// Per-packet overhead: 8-byte nonce prefix + 16-byte AEAD tag.
pub const TRANSPORT_OVERHEAD: usize = 8 + 16;

/// Nonce size prepended to every encrypted UDP datagram.
const NONCE_LEN: usize = 8;

/// Encrypted transport using `StatelessTransportState` (per-packet nonce).
///
/// Each datagram carries its 8-byte LE nonce as a prefix, so dropped or
/// reordered UDP packets never desynchronize the counter.
#[derive(Debug)]
pub struct SecureTransport {
    state: snow::StatelessTransportState,
    remote_static: [u8; 32],
    send_nonce: u64,
}

pub struct HandshakeResult {
    pub transport: SecureTransport,
    pub msg_bytes: Vec<u8>,
}

fn initiator_state(
    network_secret: &NetworkSecret,
    device_keys: &DeviceKeys,
) -> std::result::Result<snow::HandshakeState, Error> {
    snow::Builder::new(NOISE_PATTERN.parse().unwrap())
        .prologue(network_secret.as_bytes())
        .map_err(|e| Error::NoiseHandshake(format!("prologue: {e}")))?
        .local_private_key(&device_keys.x25519_static_secret())
        .map_err(|e| Error::NoiseHandshake(format!("local key: {e}")))?
        .build_initiator()
        .map_err(|e| Error::NoiseHandshake(format!("initiator build: {e}")))
}

fn responder_state(
    network_secret: &NetworkSecret,
    device_keys: &DeviceKeys,
) -> std::result::Result<snow::HandshakeState, Error> {
    snow::Builder::new(NOISE_PATTERN.parse().unwrap())
        .prologue(network_secret.as_bytes())
        .map_err(|e| Error::NoiseHandshake(format!("prologue: {e}")))?
        .local_private_key(&device_keys.x25519_static_secret())
        .map_err(|e| Error::NoiseHandshake(format!("local key: {e}")))?
        .build_responder()
        .map_err(|e| Error::NoiseHandshake(format!("responder build: {e}")))
}

fn into_transport(state: snow::HandshakeState) -> std::result::Result<SecureTransport, Error> {
    let remote_static = state
        .get_remote_static()
        .ok_or_else(|| Error::NoiseHandshake("remote static key unavailable".into()))?;
    let mut rs = [0u8; 32];
    rs.copy_from_slice(remote_static);
    let ts = state
        .into_stateless_transport_mode()
        .map_err(|e| Error::NoiseHandshake(format!("into transport: {e}")))?;
    Ok(SecureTransport {
        state: ts,
        remote_static: rs,
        send_nonce: 0,
    })
}

#[derive(Debug)]
pub struct InitiatorHandshake {
    state: Option<snow::HandshakeState>,
}

impl InitiatorHandshake {
    pub fn new(
        network_secret: &NetworkSecret,
        device_keys: &DeviceKeys,
    ) -> std::result::Result<Self, Error> {
        Ok(Self {
            state: Some(initiator_state(network_secret, device_keys)?),
        })
    }

    pub fn write_message_a(&mut self, payload: &[u8]) -> std::result::Result<Vec<u8>, Error> {
        let state = self.state.as_mut().unwrap();
        let mut buf = vec![0u8; MAX_MESSAGE_LEN];
        let n = state
            .write_message(payload, &mut buf)
            .map_err(|e| Error::NoiseHandshake(format!("msg A write: {e}")))?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn read_message_b(&mut self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
        let state = self.state.as_mut().unwrap();
        let mut buf = vec![0u8; MAX_MESSAGE_LEN];
        let n = state
            .read_message(msg, &mut buf)
            .map_err(|e| Error::NoiseHandshake(format!("msg B read: {e}")))?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn finish(mut self, payload: &[u8]) -> std::result::Result<HandshakeResult, Error> {
        let mut state = self.state.take().unwrap();
        let mut buf = vec![0u8; MAX_MESSAGE_LEN];
        let n = state
            .write_message(payload, &mut buf)
            .map_err(|e| Error::NoiseHandshake(format!("msg C write: {e}")))?;
        buf.truncate(n);
        let msg_bytes = buf;
        let transport = into_transport(state)?;
        Ok(HandshakeResult {
            transport,
            msg_bytes,
        })
    }
}

#[derive(Debug)]
pub struct ResponderHandshake {
    state: Option<snow::HandshakeState>,
}

impl ResponderHandshake {
    pub fn new(
        network_secret: &NetworkSecret,
        device_keys: &DeviceKeys,
    ) -> std::result::Result<Self, Error> {
        Ok(Self {
            state: Some(responder_state(network_secret, device_keys)?),
        })
    }

    pub fn read_message_a(&mut self, msg: &[u8]) -> std::result::Result<Vec<u8>, Error> {
        let state = self.state.as_mut().unwrap();
        let mut buf = vec![0u8; MAX_MESSAGE_LEN];
        let n = state
            .read_message(msg, &mut buf)
            .map_err(|e| Error::NoiseHandshake(format!("msg A read: {e}")))?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn write_message_b(&mut self, payload: &[u8]) -> std::result::Result<Vec<u8>, Error> {
        let state = self.state.as_mut().unwrap();
        let mut buf = vec![0u8; MAX_MESSAGE_LEN];
        let n = state
            .write_message(payload, &mut buf)
            .map_err(|e| Error::NoiseHandshake(format!("msg B write: {e}")))?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn finish(mut self, msg: &[u8]) -> std::result::Result<HandshakeResult, Error> {
        let mut state = self.state.take().unwrap();
        let mut buf = vec![0u8; MAX_MESSAGE_LEN];
        state
            .read_message(msg, &mut buf)
            .map_err(|e| Error::NoiseHandshake(format!("msg C read: {e}")))?;
        let transport = into_transport(state)?;
        Ok(HandshakeResult {
            transport,
            msg_bytes: Vec::new(),
        })
    }
}

impl SecureTransport {
    /// Encrypt `plaintext`. Wire format: `[ nonce: 8 B LE ][ ciphertext + AEAD tag ]`.
    pub fn encrypt(&mut self, plaintext: &[u8]) -> std::result::Result<Vec<u8>, Error> {
        let nonce = self.send_nonce;
        self.send_nonce = self.send_nonce.wrapping_add(1);

        let mut out = Vec::with_capacity(NONCE_LEN + plaintext.len() + 16);
        out.extend_from_slice(&nonce.to_le_bytes());
        let body_start = out.len();
        out.resize(body_start + plaintext.len() + 16, 0u8);

        let n = self
            .state
            .write_message(nonce, plaintext, &mut out[body_start..])
            .map_err(|e| Error::NoiseTransport(format!("encrypt: {e}")))?;
        out.truncate(body_start + n);
        Ok(out)
    }

    /// Decrypt a datagram produced by `encrypt`.
    pub fn decrypt(&mut self, datagram: &[u8]) -> std::result::Result<Vec<u8>, Error> {
        if datagram.len() < NONCE_LEN + 16 {
            return Err(Error::NoiseTransport("datagram too short".into()));
        }
        let nonce = u64::from_le_bytes(datagram[..NONCE_LEN].try_into().unwrap());
        let ciphertext = &datagram[NONCE_LEN..];
        let mut buf = vec![0u8; ciphertext.len()];
        let n = self
            .state
            .read_message(nonce, ciphertext, &mut buf)
            .map_err(|e| Error::NoiseTransport(format!("decrypt: {e}")))?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn remote_static_key(&self) -> &[u8; 32] {
        &self.remote_static
    }
}

pub fn complete_handshake_pair(
    secret_a: &NetworkSecret,
    keys_a: &DeviceKeys,
    secret_b: &NetworkSecret,
    keys_b: &DeviceKeys,
) -> std::result::Result<(SecureTransport, SecureTransport), Error> {
    let mut initiator = InitiatorHandshake::new(secret_a, keys_a)?;
    let mut responder = ResponderHandshake::new(secret_b, keys_b)?;

    let msg_a = initiator.write_message_a(&[])?;
    responder.read_message_a(&msg_a)?;

    let msg_b = responder.write_message_b(&[])?;
    initiator.read_message_b(&msg_b)?;

    let init_result = initiator.finish(&[])?;
    let resp_result = responder.finish(&init_result.msg_bytes)?;

    Ok((init_result.transport, resp_result.transport))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seed::derive_network_secret;
    use seednet_common::Seed;

    fn test_keys_a() -> DeviceKeys {
        DeviceKeys::from_seed(crate::device::DeviceSeedBytes::from_bytes([0x11u8; 32]))
    }

    fn test_keys_b() -> DeviceKeys {
        DeviceKeys::from_seed(crate::device::DeviceSeedBytes::from_bytes([0x22u8; 32]))
    }

    fn test_secret() -> NetworkSecret {
        derive_network_secret(&Seed::from_passphrase("test net"))
    }

    #[test]
    fn full_xx_handshake_roundtrip() {
        let secret = test_secret();
        let keys_a = test_keys_a();
        let keys_b = test_keys_b();

        let (mut t_a, mut t_b) =
            complete_handshake_pair(&secret, &keys_a, &secret, &keys_b).unwrap();

        let encrypted = t_a.encrypt(b"hello from A").unwrap();
        let decrypted = t_b.decrypt(&encrypted).unwrap();
        assert_eq!(&decrypted, b"hello from A");

        let encrypted2 = t_b.encrypt(b"hello from B").unwrap();
        let decrypted2 = t_a.decrypt(&encrypted2).unwrap();
        assert_eq!(&decrypted2, b"hello from B");
    }

    #[test]
    fn wrong_prologue_fails() {
        let secret_a = derive_network_secret(&Seed::from_passphrase("network alpha"));
        let secret_b = derive_network_secret(&Seed::from_passphrase("network beta"));
        let keys_a = test_keys_a();
        let keys_b = test_keys_b();

        let result = complete_handshake_pair(&secret_a, &keys_a, &secret_b, &keys_b);
        assert!(result.is_err(), "handshake with wrong prologue should fail");
    }

    #[test]
    fn remote_static_key_matches() {
        let secret = test_secret();
        let keys_a = test_keys_a();
        let keys_b = test_keys_b();

        let (t_a, t_b) = complete_handshake_pair(&secret, &keys_a, &secret, &keys_b).unwrap();

        assert_eq!(t_a.remote_static_key(), &keys_b.x25519_public_key());
        assert_eq!(t_b.remote_static_key(), &keys_a.x25519_public_key());
    }

    #[test]
    fn multiple_encrypt_decrypt_roundtrips() {
        let secret = test_secret();
        let keys_a = test_keys_a();
        let keys_b = test_keys_b();

        let (mut t_a, mut t_b) =
            complete_handshake_pair(&secret, &keys_a, &secret, &keys_b).unwrap();

        for i in 0u32..10 {
            let msg = format!("message {i}");
            let enc = t_a.encrypt(msg.as_bytes()).unwrap();
            let dec = t_b.decrypt(&enc).unwrap();
            assert_eq!(&dec, msg.as_bytes());
        }
    }

    #[test]
    fn decrypt_garbage_fails() {
        let secret = test_secret();
        let keys_a = test_keys_a();
        let keys_b = test_keys_b();

        let (_, mut t_b) = complete_handshake_pair(&secret, &keys_a, &secret, &keys_b).unwrap();

        let result = t_b.decrypt(&[0xff; NONCE_LEN + 16 + 1]);
        assert!(result.is_err(), "decrypting garbage should fail");
    }

    #[test]
    fn empty_payload_handshake() {
        let secret = test_secret();
        let keys_a = test_keys_a();
        let keys_b = test_keys_b();

        let (mut t_a, mut t_b) =
            complete_handshake_pair(&secret, &keys_a, &secret, &keys_b).unwrap();

        let enc = t_a.encrypt(&[]).unwrap();
        let dec = t_b.decrypt(&enc).unwrap();
        assert!(dec.is_empty());
    }

    #[test]
    fn out_of_order_and_dropped_packets_still_decrypt() {
        let secret = test_secret();
        let keys_a = test_keys_a();
        let keys_b = test_keys_b();

        let (mut t_a, mut t_b) =
            complete_handshake_pair(&secret, &keys_a, &secret, &keys_b).unwrap();

        let enc0 = t_a.encrypt(b"pkt 0").unwrap();
        let enc1 = t_a.encrypt(b"pkt 1").unwrap();
        let enc2 = t_a.encrypt(b"pkt 2").unwrap();

        // Drop enc0; pkt 1 and 2 must still work.
        assert_eq!(&t_b.decrypt(&enc1).unwrap(), b"pkt 1");
        assert_eq!(&t_b.decrypt(&enc2).unwrap(), b"pkt 2");

        // Out-of-order: enc0 arrives late.
        assert_eq!(&t_b.decrypt(&enc0).unwrap(), b"pkt 0");
    }
}
