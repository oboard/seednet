//! UDP loopback integration test.
//!
//! Spins up two engines on localhost, waits for them to complete a handshake
//! via in-process "DHT" injection, then sends an overlay IP packet from A to B
//! and verifies it arrives on B's TUN writer side.
//!
//! This test does NOT create real TUN devices — it patches the engine's
//! message path using the lower-level crypto + framing primitives directly,
//! simulating what the outbound/inbound tasks do.

use std::borrow::Cow;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use seednet_common::Seed;
use seednet_crypto::{
    DeviceKeys, DeviceSeedBytes, InitiatorHandshake, ResponderHandshake, derive_network_secret,
    derive_overlay_addr,
};
use seednet_peer::message::{Message, deserialize_message, serialize_message};
use tokio::net::UdpSocket;

fn make_ipv4_icmp(src: Ipv4Addr, dst: Ipv4Addr) -> Vec<u8> {
    const HDR: usize = 20;
    let payload = b"ping payload";
    let total = HDR + payload.len();
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2] = ((total >> 8) & 0xFF) as u8;
    pkt[3] = (total & 0xFF) as u8;
    pkt[8] = 64;
    pkt[9] = 1; // ICMP
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    pkt[HDR..].copy_from_slice(payload);
    pkt
}

/// Full Noise XX handshake + data exchange over real loopback UDP sockets.
#[tokio::test]
async fn noise_handshake_and_data_over_loopback_udp() {
    let secret = derive_network_secret(&Seed::from_passphrase("loopback test"));
    let keys_a = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xAA; 32]));
    let keys_b = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xBB; 32]));

    let overlay_a = derive_overlay_addr(&keys_a.peer_id());
    let overlay_b = derive_overlay_addr(&keys_b.peer_id());

    // Bind two UDP sockets on loopback.
    let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let sock_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a: SocketAddr = sock_a.local_addr().unwrap();
    let addr_b: SocketAddr = sock_b.local_addr().unwrap();

    const PREFIX_A: &[u8] = b"seednet-hs-a";
    const PREFIX_B: &[u8] = b"seednet-hs-b";

    // ── Initiator (A) sends msg A ────────────────────────────────────────
    let mut initiator = InitiatorHandshake::new(&secret, &keys_a).unwrap();
    let msg_a = initiator.write_message_a(&[]).unwrap();
    let mut tagged_a = PREFIX_A.to_vec();
    tagged_a.extend_from_slice(&msg_a);
    sock_a.send_to(&tagged_a, addr_b).await.unwrap();

    // ── Responder (B) reads msg A, sends msg B ───────────────────────────
    let mut buf = vec![0u8; 4096];
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), sock_b.recv_from(&mut buf))
        .await
        .expect("timeout waiting for msg A")
        .unwrap();
    let recv_a = buf[..n].to_vec();
    assert!(recv_a.starts_with(PREFIX_A));

    let mut responder = ResponderHandshake::new(&secret, &keys_b).unwrap();
    responder.read_message_a(&recv_a[PREFIX_A.len()..]).unwrap();
    let msg_b = responder.write_message_b(&[]).unwrap();
    let mut tagged_b = PREFIX_B.to_vec();
    tagged_b.extend_from_slice(&msg_b);
    sock_b.send_to(&tagged_b, addr_a).await.unwrap();

    // ── Initiator (A) reads msg B, sends msg C ───────────────────────────
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), sock_a.recv_from(&mut buf))
        .await
        .expect("timeout waiting for msg B")
        .unwrap();
    let recv_b = buf[..n].to_vec();
    assert!(recv_b.starts_with(PREFIX_B));

    initiator.read_message_b(&recv_b[PREFIX_B.len()..]).unwrap();
    let init_result = initiator.finish(&[]).unwrap();
    sock_a
        .send_to(&init_result.msg_bytes, addr_b)
        .await
        .unwrap();

    let mut transport_a = init_result.transport;

    // ── Responder (B) reads msg C, transport established ─────────────────
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), sock_b.recv_from(&mut buf))
        .await
        .expect("timeout waiting for msg C")
        .unwrap();
    let resp_result = responder.finish(&buf[..n]).unwrap();
    let mut transport_b = resp_result.transport;

    // Verify mutual auth.
    assert_eq!(transport_a.remote_static_key(), &keys_b.x25519_public_key());
    assert_eq!(transport_b.remote_static_key(), &keys_a.x25519_public_key());

    // ── A sends an overlay IP packet to B ────────────────────────────────
    let ip_packet = make_ipv4_icmp(overlay_a.ip(), overlay_b.ip());
    let wrapped = serialize_message(&Message::Data(Cow::Owned(ip_packet.clone())));
    let encrypted = transport_a.encrypt(&wrapped).unwrap();
    sock_a.send_to(&encrypted, addr_b).await.unwrap();

    // ── B receives and decrypts it ────────────────────────────────────────
    let (n, _) = tokio::time::timeout(Duration::from_secs(2), sock_b.recv_from(&mut buf))
        .await
        .expect("timeout waiting for data packet")
        .unwrap();
    let decrypted = transport_b.decrypt(&buf[..n]).unwrap();
    let msg = deserialize_message(&decrypted).unwrap();

    match msg {
        Message::Data(payload) => {
            assert_eq!(&*payload, ip_packet.as_slice(), "IP packet arrived intact");
            assert_eq!(&payload[12..16], &overlay_a.ip().octets(), "src IP correct");
            assert_eq!(&payload[16..20], &overlay_b.ip().octets(), "dst IP correct");
        }
        other => panic!("expected Data, got {other:?}"),
    }

    // ── B sends reply to A ────────────────────────────────────────────────
    let reply = make_ipv4_icmp(overlay_b.ip(), overlay_a.ip());
    let wrapped_reply = serialize_message(&Message::Data(Cow::Owned(reply.clone())));
    let enc_reply = transport_b.encrypt(&wrapped_reply).unwrap();
    sock_b.send_to(&enc_reply, addr_a).await.unwrap();

    let (n, _) = tokio::time::timeout(Duration::from_secs(2), sock_a.recv_from(&mut buf))
        .await
        .expect("timeout waiting for reply")
        .unwrap();
    let dec_reply = transport_a.decrypt(&buf[..n]).unwrap();
    match deserialize_message(&dec_reply).unwrap() {
        Message::Data(payload) => {
            assert_eq!(&*payload, reply.as_slice(), "reply arrived intact");
        }
        other => panic!("expected Data reply, got {other:?}"),
    }
}

/// SessionInit is correctly serialized with hostname + ipv6 and round-trips.
#[tokio::test]
async fn session_init_with_metadata_round_trips() {
    use seednet_crypto::{DeviceKeys, DeviceSeedBytes, derive_overlay_ipv6};

    let secret = derive_network_secret(&Seed::from_passphrase("session init test"));
    let keys_a = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xAA; 32]));
    let keys_b = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xBB; 32]));

    let peer_id_a = keys_a.peer_id();
    let overlay_a = derive_overlay_addr(&peer_id_a);
    let ipv6_a = derive_overlay_ipv6(&peer_id_a);

    let (mut t_a, mut t_b) =
        seednet_crypto::complete_handshake_pair(&secret, &keys_a, &secret, &keys_b).unwrap();

    let init_msg = Message::SessionInit {
        overlay: overlay_a,
        overlay_ipv6: Some(ipv6_a.octets()),
        hostname: "my-server.local".to_string(),
        public_addr: None,
    };

    let wire = t_a.encrypt(&serialize_message(&init_msg)).unwrap();
    let dec = t_b.decrypt(&wire).unwrap();
    let recovered = deserialize_message(&dec).unwrap();

    match recovered {
        Message::SessionInit {
            overlay,
            overlay_ipv6,
            hostname,
            ..
        } => {
            assert_eq!(overlay, overlay_a);
            assert_eq!(
                overlay_ipv6,
                Some(ipv6_a.octets()),
                "IPv6 must survive wire"
            );
            assert_eq!(hostname, "my-server.local");
        }
        other => panic!("expected SessionInit, got {other:?}"),
    }
}

/// Verifies that derive_overlay_ipv6 is deterministic and produces a ULA address.
#[test]
fn overlay_ipv6_is_deterministic_ula() {
    use seednet_crypto::{DeviceKeys, DeviceSeedBytes, derive_overlay_ipv6};

    let keys = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xCC; 32]));
    let ipv6 = derive_overlay_ipv6(&keys.peer_id());

    // ULA prefix: first byte must be 0xfd.
    assert_eq!(ipv6.octets()[0], 0xfd, "must be ULA (fd::/8)");

    // Deterministic.
    assert_eq!(derive_overlay_ipv6(&keys.peer_id()), ipv6);

    // Different keys → different address.
    let keys2 = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xDD; 32]));
    assert_ne!(derive_overlay_ipv6(&keys2.peer_id()), ipv6);
}
