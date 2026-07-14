//! NAT traversal for SeedNet: STUN discovery, UDP hole punching, relay.

pub mod punch;
pub mod relay;
pub mod stun;

pub use punch::PunchCoordinator;
pub use relay::RelayTable;
pub use stun::{StunError, query_public_addr, query_public_addr_with_fallback};

use std::net::Ipv4Addr;

/// Returns true if the address is publicly routable (not RFC1918 / loopback / link-local).
pub fn is_publicly_routable(addr: std::net::SocketAddr) -> bool {
    match addr {
        std::net::SocketAddr::V4(a) => {
            let ip = a.ip();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_unspecified()
                && *ip != Ipv4Addr::BROADCAST
        }
        std::net::SocketAddr::V6(_) => false, // conservative: only IPv4 relay for now
    }
}
