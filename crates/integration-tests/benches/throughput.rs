//! SeedNet throughput benchmarks.
//!
//! Three groups:
//!
//! 1. **serialize** — postcard serialize + deserialize for `Message::Data`
//!    at various payload sizes. Pure CPU, no I/O.
//!
//! 2. **crypto** — full encrypt→decrypt round-trip (Noise ChaChaPoly) in
//!    process at various payload sizes.
//!
//! 3. **udp_loopback** — two real `UdpSocket`s on 127.0.0.1, full
//!    Noise XX handshake, then N×1400-byte packets sent from node A
//!    and received by node B. Measures end-to-end wire throughput
//!    including serialization and encryption on loopback.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use seednet_common::Seed;
use seednet_crypto::{DeviceKeys, DeviceSeedBytes, complete_handshake_pair, derive_network_secret};
use seednet_peer::message::{Message, deserialize_message, serialize_message};
use seednet_transport::{Transport, TransportAddr, UdpTransport};
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;

// ── helpers ──────────────────────────────────────────────────────────────────

fn rt() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Minimal fake IPv4 packet (20-byte header + payload).
fn fake_ip_packet(size: usize) -> Vec<u8> {
    let total = 20 + size;
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45; // IPv4, IHL=5
    pkt[2] = ((total >> 8) & 0xFF) as u8;
    pkt[3] = (total & 0xFF) as u8;
    pkt[8] = 64; // TTL
    pkt[9] = 17; // UDP
    // src 10.88.0.1 → dst 10.88.0.2
    pkt[12..16].copy_from_slice(&[10, 88, 0, 1]);
    pkt[16..20].copy_from_slice(&[10, 88, 0, 2]);
    for (i, b) in pkt[20..].iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    pkt
}

// ── Group 1: serialization ────────────────────────────────────────────────────

fn bench_serialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialize");

    for &size in &[64usize, 512, 1400] {
        let pkt = fake_ip_packet(size);
        group.throughput(Throughput::Bytes(pkt.len() as u64));

        group.bench_with_input(BenchmarkId::new("serialize_message", size), &pkt, |b, p| {
            b.iter(|| {
                let bytes = serialize_message(&Message::Data(p.clone()));
                std::hint::black_box(bytes);
            });
        });

        let serialized = serialize_message(&Message::Data(pkt.clone()));
        group.bench_with_input(
            BenchmarkId::new("deserialize_message", size),
            &serialized,
            |b, s| {
                b.iter(|| {
                    let msg = deserialize_message(s).unwrap();
                    std::hint::black_box(msg);
                });
            },
        );
    }

    group.finish();
}

// ── Group 2: crypto (encrypt + decrypt in process) ───────────────────────────

fn bench_crypto(c: &mut Criterion) {
    let secret = derive_network_secret(&Seed::from_passphrase("bench-crypto"));
    let keys_a = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xAA; 32]));
    let keys_b = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xBB; 32]));

    let mut group = c.benchmark_group("crypto");

    for &size in &[64usize, 512, 1400] {
        let pkt = fake_ip_packet(size);
        let payload = serialize_message(&Message::Data(pkt));
        group.throughput(Throughput::Bytes(payload.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("encrypt_decrypt", size),
            &payload,
            |b, p| {
                // Re-create transports each outer iteration to avoid nonce exhaustion
                // across iterations; creation cost is amortised by Criterion.
                let (mut t_a, mut t_b) =
                    complete_handshake_pair(&secret, &keys_a, &secret, &keys_b).unwrap();
                b.iter(|| {
                    let enc = t_a.encrypt(p).unwrap();
                    let dec = t_b.decrypt(&enc).unwrap();
                    std::hint::black_box(dec);
                });
            },
        );
    }

    group.finish();
}

// ── Group 3: UDP loopback (two real sockets, full encrypt/decrypt) ────────────

/// Sends `packet_count` packets of `payload_size` bytes from A→B over
/// loopback UDP (Noise-encrypted) and waits for all of them to arrive.
/// Returns the elapsed wall-clock duration so we can compute throughput.
async fn udp_loopback_run(payload_size: usize, packet_count: usize) -> Duration {
    // Bind two sockets on ephemeral loopback ports.
    let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr_a: SocketAddr = sock_a.local_addr().unwrap();
    let addr_b: SocketAddr = sock_b.local_addr().unwrap();

    let transport_a = UdpTransport::new(sock_a.clone());
    let transport_b = UdpTransport::new(sock_b.clone());

    // Perform Noise XX handshake over the real sockets.
    let secret = derive_network_secret(&Seed::from_passphrase("bench-udp"));
    let keys_a = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xAA; 32]));
    let keys_b = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xBB; 32]));

    use seednet_crypto::{InitiatorHandshake, ResponderHandshake};
    const HS_A_PREFIX: &[u8] = b"seednet-hs-a";
    const HS_B_PREFIX: &[u8] = b"seednet-hs-b";

    let mut initiator = InitiatorHandshake::new(&secret, &keys_a).unwrap();
    let mut responder = ResponderHandshake::new(&secret, &keys_b).unwrap();

    // msg A: A → B
    let msg_a = initiator.write_message_a(&[]).unwrap();
    let mut tagged_a = HS_A_PREFIX.to_vec();
    tagged_a.extend_from_slice(&msg_a);
    transport_a
        .send_to(&tagged_a, TransportAddr::Udp(addr_b))
        .await
        .unwrap();

    // B receives msg A, sends msg B
    let (data, _) = transport_b.recv_from().await.unwrap();
    assert!(data.starts_with(HS_A_PREFIX));
    responder
        .read_message_a(&data[HS_A_PREFIX.len()..])
        .unwrap();
    let msg_b = responder.write_message_b(&[]).unwrap();
    let mut tagged_b = HS_B_PREFIX.to_vec();
    tagged_b.extend_from_slice(&msg_b);
    transport_b
        .send_to(&tagged_b, TransportAddr::Udp(addr_a))
        .await
        .unwrap();

    // A receives msg B, sends msg C
    let (data, _) = transport_a.recv_from().await.unwrap();
    assert!(data.starts_with(HS_B_PREFIX));
    initiator
        .read_message_b(&data[HS_B_PREFIX.len()..])
        .unwrap();
    let init_result = initiator.finish(&[]).unwrap();
    transport_a
        .send_to(&init_result.msg_bytes, TransportAddr::Udp(addr_b))
        .await
        .unwrap();

    // B receives msg C, finalises
    let (data, _) = transport_b.recv_from().await.unwrap();
    let resp_result = responder.finish(&data).unwrap();

    let mut noise_a = init_result.transport;
    let mut noise_b = resp_result.transport;

    // Build payload once.
    let pkt = fake_ip_packet(payload_size);
    let plaintext = serialize_message(&Message::Data(pkt));

    // ── timed section ────────────────────────────────────────────────────────
    let t0 = Instant::now();

    // Sender task: encrypt + send all packets.
    let plaintext_clone = plaintext.clone();
    let addr_b_clone = addr_b;
    let sender = tokio::spawn(async move {
        for _ in 0..packet_count {
            let enc = noise_a.encrypt(&plaintext_clone).unwrap();
            sock_a.send_to(&enc, addr_b_clone).await.unwrap();
        }
    });

    // Receiver: decrypt all packets.
    let receiver = tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        for _ in 0..packet_count {
            let (n, _) = sock_b.recv_from(&mut buf).await.unwrap();
            let dec = noise_b.decrypt(&buf[..n]).unwrap();
            std::hint::black_box(dec);
        }
    });

    tokio::try_join!(sender, receiver).unwrap();
    t0.elapsed()
}

fn bench_udp_loopback(c: &mut Criterion) {
    let rt = rt();
    let mut group = c.benchmark_group("udp_loopback");
    // Criterion measures iterations/s; we report throughput as bytes/s.
    // Each "iteration" sends PACKET_COUNT packets of PAYLOAD_SIZE bytes.
    const PACKET_COUNT: usize = 500;

    for &size in &[64usize, 512, 1400] {
        let total_bytes = (size + 20) * PACKET_COUNT; // IP header + payload × count
        group.throughput(Throughput::Bytes(total_bytes as u64));

        // Warm up: give the OS time to set up routes.
        rt.block_on(udp_loopback_run(size, 10));

        group.bench_function(BenchmarkId::new("a_to_b", size), |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    total += rt.block_on(udp_loopback_run(size, PACKET_COUNT));
                }
                total
            });
        });
    }

    group.finish();
}

// ── criterion boilerplate ─────────────────────────────────────────────────────

criterion_group!(
    name = benches;
    config = Criterion::default()
        .measurement_time(Duration::from_secs(10))
        .warm_up_time(Duration::from_secs(3));
    targets = bench_serialize, bench_crypto, bench_udp_loopback
);
criterion_main!(benches);
