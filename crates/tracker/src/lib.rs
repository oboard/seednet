//! BitTorrent tracker client for SeedNet.
//!
//! Supports:
//! - HTTP trackers (BEP-0003): `http://tracker.example.com/announce`
//! - UDP trackers (BEP-0015): `udp://tracker.example.com:1337`
//!
//! Returns a list of peer addresses for the given info_hash.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use serde::Deserialize;
use tracing::{debug, warn};

/// Announce to a tracker and return discovered peer addresses.
///
/// `info_hash` — 20-byte SHA-1 info hash
/// `peer_id`   — 20-byte peer ID
/// `port`      — the port this peer is listening on
pub async fn announce(
    tracker_url: &str,
    info_hash: &[u8; 20],
    peer_id: &[u8; 20],
    port: u16,
) -> Vec<SocketAddr> {
    if tracker_url.starts_with("http://") || tracker_url.starts_with("https://") {
        match http_announce(tracker_url, info_hash, peer_id, port).await {
            Ok(peers) => peers,
            Err(e) => {
                warn!(target: "seednet::tracker", url = tracker_url, error = %e, "HTTP tracker failed");
                Vec::new()
            }
        }
    } else if tracker_url.starts_with("udp://") {
        match udp_announce(tracker_url, info_hash, peer_id, port).await {
            Ok(peers) => peers,
            Err(e) => {
                warn!(target: "seednet::tracker", url = tracker_url, error = %e, "UDP tracker failed");
                Vec::new()
            }
        }
    } else {
        warn!(target: "seednet::tracker", url = tracker_url, "unsupported tracker scheme");
        Vec::new()
    }
}

// ---------------------------------------------------------------------------
// HTTP tracker (BEP-0003)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct HttpTrackerResponse {
    #[serde(default)]
    peers: PeersField,
    #[serde(rename = "failure reason", default)]
    failure_reason: String,
}

#[derive(Debug, Default)]
enum PeersField {
    #[default]
    Empty,
    Compact(Vec<u8>),
    Full(Vec<HttpPeerDict>),
}

impl<'de> serde::Deserialize<'de> for PeersField {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = PeersField;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "bytes or list")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                Ok(PeersField::Compact(v.to_vec()))
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut peers = Vec::new();
                while let Some(p) = seq.next_element::<HttpPeerDict>()? {
                    peers.push(p);
                }
                Ok(PeersField::Full(peers))
            }
        }
        d.deserialize_any(V)
    }
}

#[derive(Debug, Deserialize)]
struct HttpPeerDict {
    ip: String,
    port: u16,
}

async fn http_announce(
    url: &str,
    info_hash: &[u8; 20],
    peer_id: &[u8; 20],
    port: u16,
) -> Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
    let ih_encoded = percent_encode(info_hash);
    let pid_encoded = percent_encode(peer_id);

    let full_url = format!(
        "{url}?info_hash={ih}&peer_id={pid}&port={port}&uploaded=0&downloaded=0&left=0&compact=1&event=started&numwant=50",
        ih = ih_encoded,
        pid = pid_encoded,
    );

    debug!(target: "seednet::tracker", url = %full_url, "HTTP tracker announce");

    let body = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?
        .get(&full_url)
        .send()
        .await?
        .bytes()
        .await?;

    let resp: HttpTrackerResponse = serde_bencode::from_bytes(&body)?;
    if !resp.failure_reason.is_empty() {
        return Err(resp.failure_reason.into());
    }

    let addrs = match resp.peers {
        PeersField::Compact(data) => compact_to_addrs(&data),
        PeersField::Full(list) => list
            .into_iter()
            .filter_map(|p| {
                let ip: Ipv4Addr = p.ip.parse().ok()?;
                Some(SocketAddr::V4(SocketAddrV4::new(ip, p.port)))
            })
            .collect(),
        PeersField::Empty => Vec::new(),
    };

    debug!(target: "seednet::tracker", count = addrs.len(), "HTTP tracker returned peers");
    Ok(addrs)
}

/// Parse 6-byte compact peer encoding (4 bytes IP + 2 bytes port).
fn compact_to_addrs(data: &[u8]) -> Vec<SocketAddr> {
    data.chunks_exact(6)
        .map(|c| {
            let ip = Ipv4Addr::new(c[0], c[1], c[2], c[3]);
            let port = u16::from_be_bytes([c[4], c[5]]);
            SocketAddr::V4(SocketAddrV4::new(ip, port))
        })
        .collect()
}

/// Percent-encode binary data for use in a URL query string.
fn percent_encode(data: &[u8]) -> String {
    data.iter()
        .map(|&b| {
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
                format!("{}", b as char)
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// UDP tracker (BEP-0015)
// ---------------------------------------------------------------------------

async fn udp_announce(
    url: &str,
    info_hash: &[u8; 20],
    peer_id: &[u8; 20],
    port: u16,
) -> Result<Vec<SocketAddr>, Box<dyn std::error::Error + Send + Sync>> {
    // Parse "udp://host:port[/announce]"
    let host_part = url.trim_start_matches("udp://");
    let host_port = host_part.split('/').next().unwrap_or(host_part);

    use tokio::net::UdpSocket;
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(host_port).await?;

    let transaction_id: u32 = rand::random();

    // Step 1: Connect request (action=0)
    let mut connect_req = [0u8; 16];
    connect_req[0..8].copy_from_slice(&0x41727101980u64.to_be_bytes()); // magic
    connect_req[8..12].copy_from_slice(&0u32.to_be_bytes()); // action=connect
    connect_req[12..16].copy_from_slice(&transaction_id.to_be_bytes());

    sock.send(&connect_req).await?;

    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv(&mut buf)).await??;
    if n < 16 {
        return Err("connect response too short".into());
    }
    let resp_action = u32::from_be_bytes(buf[0..4].try_into().unwrap());
    let resp_tid = u32::from_be_bytes(buf[4..8].try_into().unwrap());
    if resp_action != 0 || resp_tid != transaction_id {
        return Err("invalid connect response".into());
    }
    let connection_id = u64::from_be_bytes(buf[8..16].try_into().unwrap());

    // Step 2: Announce request (action=1)
    let mut ann_req = [0u8; 98];
    ann_req[0..8].copy_from_slice(&connection_id.to_be_bytes());
    ann_req[8..12].copy_from_slice(&1u32.to_be_bytes()); // action=announce
    ann_req[12..16].copy_from_slice(&transaction_id.to_be_bytes());
    ann_req[16..36].copy_from_slice(info_hash);
    ann_req[36..56].copy_from_slice(peer_id);
    // downloaded=0, left=0, uploaded=0 already zero
    ann_req[80..84].copy_from_slice(&2u32.to_be_bytes()); // event=started
    // ip=0 (default), key=random, num_want=-1 (50 default), port
    ann_req[92..96].copy_from_slice(&(-1i32).to_be_bytes()); // num_want
    ann_req[96..98].copy_from_slice(&port.to_be_bytes());

    sock.send(&ann_req).await?;

    let n = tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv(&mut buf)).await??;
    if n < 20 {
        return Err("announce response too short".into());
    }
    let resp_action = u32::from_be_bytes(buf[0..4].try_into().unwrap());
    if resp_action != 1 {
        return Err(format!("unexpected action {resp_action}").into());
    }
    // peers start at offset 20
    let peers = compact_to_addrs(&buf[20..n]);
    debug!(target: "seednet::tracker", count = peers.len(), "UDP tracker returned peers");
    Ok(peers)
}
