//! STUN client — RFC 5389 BINDING request/response.
//!
//! Queries a public STUN server using the *same* UdpSocket as data traffic so
//! the NAT binding we discover applies to SeedNet's actual data port.

use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;

const STUN_MAGIC: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const STUN_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Debug)]
pub enum StunError {
    Io(std::io::Error),
    Timeout,
    BadResponse(&'static str),
    Resolve(String),
}

impl std::fmt::Display for StunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "STUN I/O: {e}"),
            Self::Timeout => write!(f, "STUN timeout"),
            Self::BadResponse(r) => write!(f, "STUN bad response: {r}"),
            Self::Resolve(r) => write!(f, "STUN resolve: {r}"),
        }
    }
}

impl From<std::io::Error> for StunError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

/// Query one STUN server and return the public `SocketAddr` visible to it.
///
/// Reuses `socket` so the discovered address applies to the same port that
/// SeedNet uses for data and handshake traffic.
pub async fn query_public_addr(
    socket: &UdpSocket,
    stun_host: &str,
) -> Result<SocketAddr, StunError> {
    // Resolve the STUN server address.
    let stun_addrs = tokio::net::lookup_host(stun_host)
        .await
        .map_err(|e| StunError::Resolve(e.to_string()))?
        .filter(|a| a.is_ipv4())
        .collect::<Vec<_>>();
    let stun_addr = stun_addrs
        .first()
        .copied()
        .ok_or_else(|| StunError::Resolve(format!("no A record for {stun_host}")))?;

    // Build a 20-byte BINDING request.
    let mut req = [0u8; 20];
    req[0..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    // Message length = 0 (no attributes).
    req[2..4].copy_from_slice(&0u16.to_be_bytes());
    req[4..8].copy_from_slice(&STUN_MAGIC.to_be_bytes());
    // 12-byte transaction ID — use a fixed value; we verify by magic cookie.
    req[8..20].copy_from_slice(b"seednet-stun");

    socket.send_to(&req, stun_addr).await?;

    // Wait for response, ignoring packets that don't look like STUN.
    let mut buf = [0u8; 512];
    let n = tokio::time::timeout(STUN_TIMEOUT, async {
        loop {
            let (n, _from) = socket.recv_from(&mut buf).await?;
            // Must be at least 20 bytes and have the magic cookie.
            if n >= 20 && u32::from_be_bytes(buf[4..8].try_into().unwrap()) == STUN_MAGIC {
                return Ok::<usize, std::io::Error>(n);
            }
        }
    })
    .await
    .map_err(|_| StunError::Timeout)??;

    parse_stun_response(&buf[..n])
}

/// Try each server in `servers` in order; return first success.
pub async fn query_public_addr_with_fallback(
    socket: &UdpSocket,
    servers: &[&str],
) -> Result<SocketAddr, StunError> {
    let mut last_err = StunError::BadResponse("no servers");
    for &host in servers {
        match query_public_addr(socket, host).await {
            Ok(addr) => {
                tracing::info!(target: "seednet", public_addr = %addr, stun_server = %host, "STUN discovery succeeded");
                return Ok(addr);
            }
            Err(e) => {
                tracing::debug!(target: "seednet", stun_server = %host, error = %e, "STUN query failed");
                last_err = e;
            }
        }
    }
    Err(last_err)
}

fn parse_stun_response(buf: &[u8]) -> Result<SocketAddr, StunError> {
    if buf.len() < 20 {
        return Err(StunError::BadResponse("response too short"));
    }

    // Scan TLV attributes starting at byte 20.
    let mut pos = 20usize;
    while pos + 4 <= buf.len() {
        let attr_type = u16::from_be_bytes(buf[pos..pos + 2].try_into().unwrap());
        let attr_len = u16::from_be_bytes(buf[pos + 2..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if pos + attr_len > buf.len() {
            break;
        }
        let value = &buf[pos..pos + attr_len];

        if attr_type == ATTR_XOR_MAPPED_ADDRESS && attr_len >= 8 && value[1] == 0x01 {
            let port_xored = u16::from_be_bytes(value[2..4].try_into().unwrap());
            let port = port_xored ^ (STUN_MAGIC >> 16) as u16;
            let ip_xored = u32::from_be_bytes(value[4..8].try_into().unwrap());
            let ip = ip_xored ^ STUN_MAGIC;
            let addr = SocketAddr::from((std::net::Ipv4Addr::from(ip), port));
            return Ok(addr);
        } else if attr_type == ATTR_MAPPED_ADDRESS && attr_len >= 8 && value[1] == 0x01 {
            let port = u16::from_be_bytes(value[2..4].try_into().unwrap());
            let ip = u32::from_be_bytes(value[4..8].try_into().unwrap());
            let addr = SocketAddr::from((std::net::Ipv4Addr::from(ip), port));
            return Ok(addr);
        }

        // Attributes are padded to 4-byte boundaries.
        pos += (attr_len + 3) & !3;
    }

    Err(StunError::BadResponse("no MAPPED-ADDRESS attribute found"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_xor_mapped_response(mapped: std::net::SocketAddr) -> Vec<u8> {
        // Build a minimal STUN success response with XOR-MAPPED-ADDRESS.
        let ip = match mapped.ip() {
            std::net::IpAddr::V4(v4) => u32::from(v4),
            _ => panic!("IPv4 only"),
        };
        let port = mapped.port();

        let xor_port = (port ^ (STUN_MAGIC >> 16) as u16).to_be_bytes();
        let xor_ip = (ip ^ STUN_MAGIC).to_be_bytes();

        // Attribute: type=0x0020, len=8, family=0x01
        let attr: Vec<u8> = vec![
            0x00,
            0x20, // XOR-MAPPED-ADDRESS
            0x00,
            0x08, // length 8
            0x00,
            0x01, // reserved + IPv4 family
            xor_port[0],
            xor_port[1],
            xor_ip[0],
            xor_ip[1],
            xor_ip[2],
            xor_ip[3],
        ];

        // Header: success response 0x0101, length = 12 (attr), magic cookie, txn id
        let msg_len = (attr.len() as u16).to_be_bytes();
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0x01, 0x01]); // success response
        resp.extend_from_slice(&msg_len);
        resp.extend_from_slice(&STUN_MAGIC.to_be_bytes());
        resp.extend_from_slice(b"seednet-stun");
        resp.extend(attr);
        resp
    }

    #[test]
    fn parse_xor_mapped_address() {
        let expected: SocketAddr = "203.0.113.42:54321".parse().unwrap();
        let buf = build_xor_mapped_response(expected);
        let got = parse_stun_response(&buf).unwrap();
        assert_eq!(got, expected);
    }

    #[tokio::test]
    async fn loopback_stun_mock() {
        // Bind a "mock STUN server" on loopback.
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_addr = client.local_addr().unwrap();

        // Spawn server: receive BINDING request, reply with XOR-MAPPED-ADDRESS = client_addr.
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            let (_, from) = server.recv_from(&mut buf).await.unwrap();
            let resp = build_xor_mapped_response(from);
            server.send_to(&resp, from).await.unwrap();
        });

        // The STUN host resolves to the mock server via explicit IP.
        let stun_host = server_addr.to_string();
        let discovered = query_public_addr(&client, &stun_host).await.unwrap();
        assert_eq!(discovered.port(), client_addr.port());
    }
}
