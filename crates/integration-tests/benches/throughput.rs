//! SeedNet throughput benchmarks.
//!
//! Groups:
//!
//! 1. **serialize** — postcard serialize + deserialize for `Message::Data`
//!    at various payload sizes. Pure CPU, no I/O.
//!
//! 2. **crypto** — full encrypt→decrypt round-trip (Noise ChaChaPoly) in
//!    process at various payload sizes. Uses zero-allocation `encrypt_into` /
//!    `decrypt_into` paths to measure raw cipher throughput.
//!
//! 3. **udp_loopback** — two real `UdpSocket`s on 127.0.0.1, full
//!    Noise XX handshake, then N×1400-byte packets sent from node A
//!    and received by node B.
//!
//! 4. **tcp_loopback** — same shape as udp_loopback but over TCP with 4-byte
//!    length framing.
//!
//! 5. **ws_loopback** — same shape but over WebSocket.

use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use seednet_common::Seed;
use seednet_crypto::{
    DeviceKeys, DeviceSeedBytes, TRANSPORT_OVERHEAD, complete_handshake_pair, derive_network_secret,
};
use seednet_peer::message::{
    Message, deserialize_message, serialize_message, serialize_message_into,
};
use seednet_transport::{TcpTransport, Transport, TransportAddr, UdpTransport, WsTransport};
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
    pkt[12..16].copy_from_slice(&[10, 88, 0, 1]);
    pkt[16..20].copy_from_slice(&[10, 88, 0, 2]);
    for (i, b) in pkt[20..].iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    pkt
}

/// Perform a 3-message Noise XX handshake over `transport_a` / `transport_b`
/// and return the two `SecureTransport`s ready for data exchange.
/// `taddr_a` / `taddr_b` must use the correct `TransportAddr` variant for the
/// given transport (Udp, Tcp, or Ws).
async fn noise_handshake(
    transport_a: &impl Transport,
    transport_b: &impl Transport,
    taddr_a: TransportAddr,
    taddr_b: TransportAddr,
) -> (
    seednet_crypto::SecureTransport,
    seednet_crypto::SecureTransport,
) {
    use seednet_crypto::{InitiatorHandshake, ResponderHandshake};
    let secret = derive_network_secret(&Seed::from_passphrase("bench-noise"));
    let keys_a = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xAA; 32]));
    let keys_b = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xBB; 32]));

    const HS_A: &[u8] = b"bench-hs-a";
    const HS_B: &[u8] = b"bench-hs-b";

    let mut init = InitiatorHandshake::new(&secret, &keys_a).unwrap();
    let mut resp = ResponderHandshake::new(&secret, &keys_b).unwrap();

    let msg_a = init.write_message_a(&[]).unwrap();
    let mut tagged = HS_A.to_vec();
    tagged.extend_from_slice(&msg_a);
    transport_a.send_to(&tagged, taddr_b.clone()).await.unwrap();

    let (data, _) = transport_b.recv_from().await.unwrap();
    resp.read_message_a(&data[HS_A.len()..]).unwrap();
    let msg_b = resp.write_message_b(&[]).unwrap();
    let mut tagged = HS_B.to_vec();
    tagged.extend_from_slice(&msg_b);
    transport_b.send_to(&tagged, taddr_a.clone()).await.unwrap();

    let (data, _) = transport_a.recv_from().await.unwrap();
    init.read_message_b(&data[HS_B.len()..]).unwrap();
    let init_result = init.finish(&[]).unwrap();
    transport_a
        .send_to(&init_result.msg_bytes, taddr_b)
        .await
        .unwrap();

    let (data, _) = transport_b.recv_from().await.unwrap();
    let resp_result = resp.finish(&data).unwrap();

    (init_result.transport, resp_result.transport)
}

// ── Group 1: serialization ────────────────────────────────────────────────────

fn bench_serialize(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialize");

    for &size in &[64usize, 512, 1400] {
        let pkt = fake_ip_packet(size);
        group.throughput(Throughput::Bytes(pkt.len() as u64));

        group.bench_with_input(BenchmarkId::new("serialize_message", size), &pkt, |b, p| {
            let mut buf = Vec::with_capacity(p.len() + 16);
            b.iter(|| {
                serialize_message_into(&Message::Data(Cow::Owned(p.clone())), &mut buf);
                std::hint::black_box(&buf);
            });
        });

        let serialized = serialize_message(&Message::Data(Cow::Owned(pkt.clone())));
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

// ── Group 2: crypto (encrypt + decrypt, zero-allocation paths) ────────────────

fn bench_crypto(c: &mut Criterion) {
    let secret = derive_network_secret(&Seed::from_passphrase("bench-crypto"));
    let keys_a = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xAA; 32]));
    let keys_b = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xBB; 32]));

    let mut group = c.benchmark_group("crypto");

    for &size in &[64usize, 512, 1400] {
        let pkt = fake_ip_packet(size);
        let payload = serialize_message(&Message::Data(Cow::Owned(pkt)));
        group.throughput(Throughput::Bytes(payload.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("encrypt_decrypt", size),
            &payload,
            |b, p| {
                let (mut t_a, mut t_b) =
                    complete_handshake_pair(&secret, &keys_a, &secret, &keys_b).unwrap();
                let mut enc_buf = vec![0u8; p.len() + TRANSPORT_OVERHEAD];
                let mut dec_buf = vec![0u8; p.len() + TRANSPORT_OVERHEAD];
                b.iter(|| {
                    let n = t_a.encrypt_into(p, &mut enc_buf).unwrap();
                    let m = t_b.decrypt_into(&enc_buf[..n], &mut dec_buf).unwrap();
                    std::hint::black_box(&dec_buf[..m]);
                });
            },
        );
    }

    group.finish();
}

// ── Group 3: UDP loopback ─────────────────────────────────────────────────────

async fn udp_loopback_run(payload_size: usize, packet_count: usize) -> Duration {
    let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr_a: SocketAddr = sock_a.local_addr().unwrap();
    let addr_b: SocketAddr = sock_b.local_addr().unwrap();

    let transport_a = UdpTransport::new(sock_a.clone());
    let transport_b = UdpTransport::new(sock_b.clone());

    let (mut noise_a, mut noise_b) = noise_handshake(
        &transport_a,
        &transport_b,
        TransportAddr::Udp(addr_a),
        TransportAddr::Udp(addr_b),
    )
    .await;

    let pkt = fake_ip_packet(payload_size);
    let plaintext = serialize_message(&Message::Data(Cow::Owned(pkt)));

    let t0 = Instant::now();

    let plaintext_clone = plaintext.clone();
    let sender = tokio::spawn(async move {
        let mut enc_buf = vec![0u8; plaintext_clone.len() + TRANSPORT_OVERHEAD];
        for _ in 0..packet_count {
            let n = noise_a
                .encrypt_into(&plaintext_clone, &mut enc_buf)
                .unwrap();
            sock_a.send_to(&enc_buf[..n], addr_b).await.unwrap();
        }
    });

    let receiver = tokio::spawn(async move {
        let mut recv_buf = vec![0u8; 65536];
        let mut dec_buf = vec![0u8; 65536];
        for _ in 0..packet_count {
            let (n, _) = sock_b.recv_from(&mut recv_buf).await.unwrap();
            let m = noise_b.decrypt_into(&recv_buf[..n], &mut dec_buf).unwrap();
            std::hint::black_box(&dec_buf[..m]);
        }
    });

    tokio::try_join!(sender, receiver).unwrap();
    t0.elapsed()
}

fn bench_udp_loopback(c: &mut Criterion) {
    let rt = rt();
    let mut group = c.benchmark_group("udp_loopback");
    const PACKET_COUNT: usize = 500;

    for &size in &[64usize, 512, 1400] {
        let total_bytes = (size + 20) * PACKET_COUNT;
        group.throughput(Throughput::Bytes(total_bytes as u64));
        rt.block_on(udp_loopback_run(size, 10)); // warm-up
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

// ── Group 4: TCP loopback ─────────────────────────────────────────────────────

async fn tcp_loopback_run(payload_size: usize, packet_count: usize) -> Duration {
    use tokio::time::sleep;
    let secret = derive_network_secret(&Seed::from_passphrase("bench-tcp"));
    let keys_a = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xAA; 32]));
    let keys_b = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xBB; 32]));

    let transport_b = TcpTransport::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr_b = transport_b.local_addr().socket_addr();
    let transport_a = TcpTransport::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    // Brief yield so the accept loop task can run before we connect.
    sleep(std::time::Duration::from_millis(1)).await;

    // Establish TCP connection A→B (triggers accept) before Noise session.
    transport_a
        .send_to(b"ping", TransportAddr::Tcp(addr_b))
        .await
        .unwrap();
    transport_b.recv_from().await.unwrap(); // consume the ping

    // Use in-process Noise handshake — no second round-trip needed for keys.
    let (mut noise_a, mut noise_b) =
        complete_handshake_pair(&secret, &keys_a, &secret, &keys_b).unwrap();

    let pkt = fake_ip_packet(payload_size);
    let plaintext = serialize_message(&Message::Data(Cow::Owned(pkt)));

    let t0 = Instant::now();

    let transport_a = Arc::new(transport_a);
    let plaintext_clone = plaintext.clone();
    let sender = tokio::spawn(async move {
        for _ in 0..packet_count {
            let enc = noise_a.encrypt(&plaintext_clone).unwrap();
            transport_a
                .send_to(&enc, TransportAddr::Tcp(addr_b))
                .await
                .unwrap();
        }
    });

    let transport_b = Arc::new(transport_b);
    let receiver = tokio::spawn(async move {
        let mut dec_buf = vec![0u8; 65536];
        for _ in 0..packet_count {
            let (n, _) = transport_b.recv_into(&mut dec_buf).await.unwrap();
            let m = noise_b
                .decrypt_into(&dec_buf[..n], &mut dec_buf.clone())
                .unwrap();
            std::hint::black_box(m);
        }
    });

    tokio::try_join!(sender, receiver).unwrap();
    t0.elapsed()
}

fn bench_tcp_loopback(c: &mut Criterion) {
    let rt = rt();
    let mut group = c.benchmark_group("tcp_loopback");
    const PACKET_COUNT: usize = 200;

    for &size in &[64usize, 512, 1400] {
        let total_bytes = (size + 20) * PACKET_COUNT;
        group.throughput(Throughput::Bytes(total_bytes as u64));
        group.bench_function(BenchmarkId::new("a_to_b", size), |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    total += rt.block_on(tcp_loopback_run(size, PACKET_COUNT));
                }
                total
            });
        });
    }
    group.finish();
}

// ── Group 5: WS loopback ──────────────────────────────────────────────────────

async fn ws_loopback_run(payload_size: usize, packet_count: usize) -> Duration {
    use tokio::time::sleep;
    let secret = derive_network_secret(&Seed::from_passphrase("bench-ws"));
    let keys_a = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xAA; 32]));
    let keys_b = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xBB; 32]));

    let transport_b = WsTransport::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let addr_b = transport_b.local_addr().socket_addr();
    let transport_a = WsTransport::bind("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    // Brief yield so the accept loop task can run before we connect.
    sleep(std::time::Duration::from_millis(1)).await;

    // Establish WS connection A→B (triggers accept) before Noise session.
    transport_a
        .send_to(b"ping", TransportAddr::Ws(addr_b))
        .await
        .unwrap();
    transport_b.recv_from().await.unwrap(); // consume the ping

    // Use in-process Noise handshake — avoids bidirectional WS connection complexity.
    let (mut noise_a, mut noise_b) =
        complete_handshake_pair(&secret, &keys_a, &secret, &keys_b).unwrap();

    let pkt = fake_ip_packet(payload_size);
    let plaintext = serialize_message(&Message::Data(Cow::Owned(pkt)));

    let t0 = Instant::now();

    let transport_a = Arc::new(transport_a);
    let plaintext_clone = plaintext.clone();
    let sender = tokio::spawn(async move {
        for _ in 0..packet_count {
            let enc = noise_a.encrypt(&plaintext_clone).unwrap();
            transport_a
                .send_to(&enc, TransportAddr::Ws(addr_b))
                .await
                .unwrap();
        }
    });

    let transport_b = Arc::new(transport_b);
    let receiver = tokio::spawn(async move {
        let mut dec_buf = vec![0u8; 65536];
        for _ in 0..packet_count {
            let (n, _) = transport_b.recv_into(&mut dec_buf).await.unwrap();
            let m = noise_b
                .decrypt_into(&dec_buf[..n], &mut dec_buf.clone())
                .unwrap();
            std::hint::black_box(m);
        }
    });

    tokio::try_join!(sender, receiver).unwrap();
    t0.elapsed()
}

fn bench_ws_loopback(c: &mut Criterion) {
    let rt = rt();
    let mut group = c.benchmark_group("ws_loopback");
    const PACKET_COUNT: usize = 200;

    for &size in &[64usize, 512, 1400] {
        let total_bytes = (size + 20) * PACKET_COUNT;
        group.throughput(Throughput::Bytes(total_bytes as u64));
        group.bench_function(BenchmarkId::new("a_to_b", size), |b| {
            b.iter_custom(|iters| {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    total += rt.block_on(ws_loopback_run(size, PACKET_COUNT));
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
    targets = bench_serialize, bench_crypto, bench_udp_loopback, bench_tcp_loopback, bench_ws_loopback
);
criterion_main!(benches);
