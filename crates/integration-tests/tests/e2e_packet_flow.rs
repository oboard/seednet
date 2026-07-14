//! End-to-end packet flow test.
//!
//! Simulates two peers doing a full Noise handshake, then verifies that an
//! IP packet sent through the Message::Data path arrives intact on the other
//! side — the same code path used by the live engine for TUN traffic.

use std::net::Ipv4Addr;

use seednet_common::Seed;
use seednet_crypto::{DeviceKeys, DeviceSeedBytes, complete_handshake_pair, derive_network_secret};
use seednet_peer::message::{Message, deserialize_message, serialize_message};

fn make_ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    const HDR: usize = 20;
    let total = HDR + payload.len();
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45; // version=4, IHL=5
    pkt[2] = ((total >> 8) & 0xFF) as u8;
    pkt[3] = (total & 0xFF) as u8;
    pkt[8] = 64; // TTL
    pkt[9] = 1; // ICMP
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    pkt[HDR..].copy_from_slice(payload);
    pkt
}

/// Verifies the full send/receive pipeline:
///   TUN read → Message::Data wrap → serialize → encrypt → (wire) →
///   decrypt → deserialize → Message::Data unwrap → TUN write
#[test]
fn ip_packet_survives_full_message_pipeline() {
    let secret = derive_network_secret(&Seed::from_passphrase("e2e test"));
    let keys_a = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xAA; 32]));
    let keys_b = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xBB; 32]));

    let (mut transport_a, mut transport_b) =
        complete_handshake_pair(&secret, &keys_a, &secret, &keys_b).unwrap();

    let src = Ipv4Addr::new(10, 88, 7, 3);
    let dst = Ipv4Addr::new(10, 88, 20, 207);
    let icmp_payload = b"\x08\x00\xf7\xff\x00\x01\x00\x01hello"; // ICMP echo
    let ip_packet = make_ipv4_packet(src, dst, icmp_payload);

    // ── Send side (A → B): same as outbound_handle in core ──────────────
    let wire_bytes = {
        let wrapped = serialize_message(&Message::Data(ip_packet.clone()));
        transport_a.encrypt(&wrapped).unwrap()
    };

    // ── Receive side (B): same as inbound_handle in core ────────────────
    let decrypted = transport_b.decrypt(&wire_bytes).unwrap();
    let recovered = deserialize_message(&decrypted).unwrap();

    match recovered {
        Message::Data(payload) => {
            assert_eq!(
                payload, ip_packet,
                "IP packet must arrive byte-for-byte intact"
            );
            // Verify destination IP is preserved.
            assert_eq!(&payload[16..20], &dst.octets());
            assert_eq!(&payload[12..16], &src.octets());
        }
        other => panic!("expected Message::Data, got {other:?}"),
    }
}

/// Heartbeat does NOT write to TUN — only Data does. Verify Heartbeat is
/// correctly serialized and identified.
#[test]
fn heartbeat_is_not_data() {
    let secret = derive_network_secret(&Seed::from_passphrase("hb test"));
    let keys_a = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0x11; 32]));
    let keys_b = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0x22; 32]));

    let (mut t_a, mut t_b) = complete_handshake_pair(&secret, &keys_a, &secret, &keys_b).unwrap();

    let wire = t_a
        .encrypt(&serialize_message(&Message::Heartbeat))
        .unwrap();
    let dec = t_b.decrypt(&wire).unwrap();
    let msg = deserialize_message(&dec).unwrap();
    assert!(matches!(msg, Message::Heartbeat));
    assert!(!matches!(msg, Message::Data(_)));
}

/// Garbage bytes after decrypt must fail deserialization cleanly (no panic).
#[test]
fn garbage_after_decrypt_is_dropped() {
    let garbage = b"\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF";
    let result = deserialize_message(garbage);
    assert!(
        result.is_err(),
        "garbage must not deserialize as a valid message"
    );
}

/// Many IP packets of different sizes all survive the pipeline.
#[test]
fn various_packet_sizes_survive() {
    let secret = derive_network_secret(&Seed::from_passphrase("sizes"));
    let keys_a = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xAA; 32]));
    let keys_b = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xBB; 32]));

    let (mut t_a, mut t_b) = complete_handshake_pair(&secret, &keys_a, &secret, &keys_b).unwrap();

    for size in [0, 1, 20, 100, 500, 1200, 1400] {
        let payload: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let pkt = make_ipv4_packet(
            Ipv4Addr::new(10, 88, 1, 1),
            Ipv4Addr::new(10, 88, 2, 2),
            &payload,
        );

        let wire = t_a
            .encrypt(&serialize_message(&Message::Data(pkt.clone())))
            .unwrap();
        let dec = t_b.decrypt(&wire).unwrap();
        match deserialize_message(&dec).unwrap() {
            Message::Data(received) => assert_eq!(received, pkt, "size={size}"),
            other => panic!("size={size}: expected Data, got {other:?}"),
        }
    }
}
