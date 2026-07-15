//! End-to-end test: two devices complete the full Noise XX handshake
//! and then exchange encrypted messages in both directions.

use seednet_common::{OverlayAddr, PeerId, Seed};
use seednet_crypto::{
    DeviceKeys, DeviceSeedBytes, InitiatorHandshake, ResponderHandshake, complete_handshake_pair,
    derive_network_secret,
};
use seednet_peer::frame;
use seednet_peer::message::{self, Message};

/// Two devices with different keys but same network secret complete the
/// full 3-message Noise XX handshake, then exchange multiple encrypted
/// messages in both directions.
#[test]
fn two_devices_handshake_and_exchange_messages() {
    let secret = derive_network_secret(&Seed::from_passphrase("integration test net"));
    let keys_a = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xAA; 32]));
    let keys_b = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xBB; 32]));

    let (mut t_a, mut t_b) = complete_handshake_pair(&secret, &keys_a, &secret, &keys_b).unwrap();

    // A → B: encrypted application message
    let msg_a = b"hello from device A";
    let enc_a = t_a.encrypt(msg_a).unwrap();
    let dec_a: Vec<u8> = t_b.decrypt(&enc_a).unwrap();
    assert_eq!(&dec_a, msg_a);

    // B → A: reply
    let msg_b = b"hello from device B!";
    let enc_b = t_b.encrypt(msg_b).unwrap();
    let dec_b: Vec<u8> = t_a.decrypt(&enc_b).unwrap();
    assert_eq!(&dec_b, msg_b);

    // Many round-trips with increasing sizes
    for size in [0, 1, 100, 500, 1000] {
        let payload: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        let enc = t_a.encrypt(&payload).unwrap();
        let dec: Vec<u8> = t_b.decrypt(&enc).unwrap();
        assert_eq!(dec, payload);
    }
}

/// Handshake step-by-step (initiator sends msg A, responder reads and
/// replies with msg B, initiator reads B and sends msg C) to verify
/// each phase individually.
#[test]
fn handshake_step_by_step() {
    let secret = derive_network_secret(&Seed::from_passphrase("step by step"));
    let keys_i = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0x11; 32]));
    let keys_r = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0x22; 32]));

    let mut initiator = InitiatorHandshake::new(&secret, &keys_i).unwrap();
    let mut responder = ResponderHandshake::new(&secret, &keys_r).unwrap();

    // Message A: initiator → responder (ephemeral key)
    let msg_a = initiator.write_message_a(&[]).unwrap();
    assert!(!msg_a.is_empty());
    let payload_a = responder.read_message_a(&msg_a).unwrap();
    assert!(payload_a.is_empty());

    // Message B: responder → initiator (ephemeral + ee + static + es)
    let msg_b = responder.write_message_b(&[]).unwrap();
    assert!(!msg_b.is_empty());
    let payload_b = initiator.read_message_b(&msg_b).unwrap();
    assert!(payload_b.is_empty());

    // Message C: initiator → responder (static + se) → transport mode
    let init_result = initiator.finish(&[]).unwrap();
    let resp_result = responder.finish(&init_result.msg_bytes).unwrap();

    // Verify mutual authentication: each side knows the other's static key
    assert_eq!(
        init_result.transport.remote_static_key(),
        &keys_r.x25519_public_key()
    );
    assert_eq!(
        resp_result.transport.remote_static_key(),
        &keys_i.x25519_public_key()
    );
}

/// Wrong network secret (prologue) should cause the handshake to fail.
#[test]
fn wrong_network_secret_handshake_fails() {
    let secret_a = derive_network_secret(&Seed::from_passphrase("network alpha"));
    let secret_b = derive_network_secret(&Seed::from_passphrase("network beta"));
    let keys_a = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0x11; 32]));
    let keys_b = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0x22; 32]));

    let result = complete_handshake_pair(&secret_a, &keys_a, &secret_b, &keys_b);
    assert!(
        result.is_err(),
        "handshake with mismatched prologue must fail"
    );
}

/// Encrypted message framed and sent over a simulated "wire" (just bytes)
/// gets correctly received and decrypted on the other side, with a real
/// SeedNet Message payload inside.
#[test]
fn full_stack_message_over_wire() {
    let secret = derive_network_secret(&Seed::from_passphrase("wire test"));
    let keys_a = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xAA; 32]));
    let keys_b = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xBB; 32]));

    let (mut t_a, mut t_b) = complete_handshake_pair(&secret, &keys_a, &secret, &keys_b).unwrap();

    // Sender side: build Message → serialize → encrypt → frame
    let msg = Message::Data(b"overlay packet payload".to_vec());
    let serialized = message::serialize_message(&msg);
    let encrypted = t_a.encrypt(&serialized).unwrap();
    let framed = frame::encode_frame(&encrypted);

    // "Wire" is just the framed bytes
    let wire_bytes = framed.clone();

    // Receiver side: unframe → decrypt → deserialize
    let inner = frame::decode_frame(&wire_bytes).unwrap();
    let decrypted: Vec<u8> = t_b.decrypt(inner).unwrap();
    let recovered: Message = message::deserialize_message(&decrypted).unwrap();

    assert_eq!(recovered, msg);
}

/// All message types survive the full stack round-trip.
#[test]
fn all_message_types_over_wire() {
    let secret = derive_network_secret(&Seed::from_passphrase("msg types"));
    let keys_a = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0x10; 32]));
    let keys_b = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0x20; 32]));

    let (mut t_a, mut t_b) = complete_handshake_pair(&secret, &keys_a, &secret, &keys_b).unwrap();

    let messages = vec![
        Message::Data(vec![1, 2, 3, 4, 5]),
        Message::Heartbeat,
        Message::Ping { sent_ms: 0 },
        Message::Pong { sent_ms: 0 },
        Message::SessionInit {
            peer_id: PeerId::from_bytes([0x99; 32]),
            overlay: OverlayAddr::new(std::net::Ipv4Addr::new(10, 88, 3, 42)),
            overlay_ipv6: Some([0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            hostname: "test-host".to_string(),
            public_addr: None,
        },
    ];

    for msg in messages {
        let serialized = message::serialize_message(&msg);
        let encrypted = t_a.encrypt(&serialized).unwrap();
        let framed = frame::encode_frame(&encrypted);

        let inner = frame::decode_frame(&framed).unwrap();
        let decrypted: Vec<u8> = t_b.decrypt(inner).unwrap();
        let recovered: Message = message::deserialize_message(&decrypted).unwrap();
        assert_eq!(recovered, msg);
    }
}

/// Tampering with the ciphertext on the wire should cause decryption to fail.
#[test]
fn tampered_ciphertext_detected() {
    let secret = derive_network_secret(&Seed::from_passphrase("tamper test"));
    let keys_a = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0x10; 32]));
    let keys_b = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0x20; 32]));

    let (mut t_a, mut t_b) = complete_handshake_pair(&secret, &keys_a, &secret, &keys_b).unwrap();

    let msg = Message::Data(b"sensitive data".to_vec());
    let serialized = message::serialize_message(&msg);
    let mut encrypted = t_a.encrypt(&serialized).unwrap();

    // Flip a bit in the ciphertext
    let mid = encrypted.len() / 2;
    encrypted[mid] ^= 0xFF;

    let framed = frame::encode_frame(&encrypted);
    let inner = frame::decode_frame(&framed).unwrap();
    let result = t_b.decrypt(inner);
    assert!(result.is_err(), "tampered ciphertext must be rejected");
}

/// Replay attack: sending the same encrypted message twice — the second
/// should fail because Noise uses a nonce counter.
#[test]
fn replay_attack_detected() {
    let secret = derive_network_secret(&Seed::from_passphrase("replay test"));
    let keys_a = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0x10; 32]));
    let keys_b = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0x20; 32]));

    let (mut t_a, mut t_b) = complete_handshake_pair(&secret, &keys_a, &secret, &keys_b).unwrap();

    let encrypted = t_a.encrypt(b"first message").unwrap();

    // First decrypt succeeds
    let dec: Vec<u8> = t_b.decrypt(&encrypted).unwrap();
    assert_eq!(&dec, b"first message");

    // Replay the same ciphertext — must fail (nonce already used)
    let replay_result = t_b.decrypt(&encrypted);
    assert!(
        replay_result.is_err(),
        "replayed ciphertext must be rejected"
    );
}
