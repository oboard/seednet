//! TUN packet routing for the SeedNet overlay.
//!
//! Parses IPv4 packet headers from the TUN interface, looks up the
//! destination overlay IP in the routing table, and forwards packets
//! to the appropriate peer (encrypted). Inbound encrypted packets are
//! decrypted and written back to the TUN interface.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use seednet_common::{Error, OverlayAddr, PeerId, OVERLAY_MTU, OVERLAY_SUBNET_BASE, OVERLAY_SUBNET_PREFIX};
use seednet_crypto::SecureTransport;

const IPV4_HEADER_MIN_LEN: usize = 20;
const IPV4_VERSION_MASK: u8 = 0xF0;
const IPV4_VERSION_SHIFT: u8 = 4;
const IPV4_DST_OFFSET: usize = 16;
const IPV4_SRC_OFFSET: usize = 12;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedPacket {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub payload: Vec<u8>,
}

pub fn parse_ipv4_packet(data: &[u8]) -> std::result::Result<ParsedPacket, Error> {
    if data.len() < IPV4_HEADER_MIN_LEN {
        return Err(Error::NoiseTransport(format!(
            "IPv4 packet too short: {} bytes",
            data.len()
        )));
    }

    let version = (data[0] & IPV4_VERSION_MASK) >> IPV4_VERSION_SHIFT;
    if version != 4 {
        return Err(Error::NoiseTransport(format!(
            "not an IPv4 packet: version {version}"
        )));
    }

    let src_ip = Ipv4Addr::new(data[IPV4_SRC_OFFSET], data[IPV4_SRC_OFFSET + 1], data[IPV4_SRC_OFFSET + 2], data[IPV4_SRC_OFFSET + 3]);
    let dst_ip = Ipv4Addr::new(data[IPV4_DST_OFFSET], data[IPV4_DST_OFFSET + 1], data[IPV4_DST_OFFSET + 2], data[IPV4_DST_OFFSET + 3]);

    Ok(ParsedPacket {
        src_ip,
        dst_ip,
        payload: data.to_vec(),
    })
}

#[derive(Clone, Debug, Default)]
pub struct RoutingTable {
    routes: HashMap<Ipv4Addr, PeerId>,
    peer_addrs: HashMap<PeerId, Ipv4Addr>,
}

impl RoutingTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_route(&mut self, overlay: OverlayAddr, peer_id: PeerId) {
        self.routes.insert(overlay.ip(), peer_id);
        self.peer_addrs.insert(peer_id, overlay.ip());
    }

    pub fn remove_route(&mut self, overlay: &OverlayAddr) -> Option<PeerId> {
        let peer_id = self.routes.remove(&overlay.ip())?;
        self.peer_addrs.remove(&peer_id);
        Some(peer_id)
    }

    pub fn remove_peer(&mut self, peer_id: &PeerId) -> Option<OverlayAddr> {
        let ip = self.peer_addrs.remove(peer_id)?;
        self.routes.remove(&ip);
        Some(OverlayAddr::new(ip))
    }

    pub fn lookup(&self, dst_ip: Ipv4Addr) -> Option<&PeerId> {
        self.routes.get(&dst_ip)
    }

    pub fn lookup_peer_ip(&self, peer_id: &PeerId) -> Option<Ipv4Addr> {
        self.peer_addrs.get(peer_id).copied()
    }

    pub fn len(&self) -> usize {
        self.routes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }

    pub fn is_overlay_dst(&self, dst_ip: Ipv4Addr) -> bool {
        let mask = if OVERLAY_SUBNET_PREFIX == 0 {
            0u32
        } else {
            !0u32 << (32 - OVERLAY_SUBNET_PREFIX)
        };
        (u32::from(dst_ip) & mask) == (u32::from(OVERLAY_SUBNET_BASE) & mask)
    }
}

pub struct Router {
    table: RoutingTable,
    transport: SecureTransport,
    our_overlay: OverlayAddr,
}

impl Router {
    pub fn new(table: RoutingTable, transport: SecureTransport, our_overlay: OverlayAddr) -> Self {
        Self { table, transport, our_overlay }
    }

    pub fn table(&self) -> &RoutingTable {
        &self.table
    }

    pub fn table_mut(&mut self) -> &mut RoutingTable {
        &mut self.table
    }

    pub fn route_outbound(&mut self, packet: &[u8]) -> std::result::Result<Option<(PeerId, Vec<u8>)>, Error> {
        let parsed = parse_ipv4_packet(packet)?;
        if !self.table.is_overlay_dst(parsed.dst_ip) {
            return Ok(None);
        }
        if parsed.dst_ip == self.our_overlay.ip() {
            return Ok(None);
        }
        let peer_id = match self.table.lookup(parsed.dst_ip) {
            Some(id) => *id,
            None => return Ok(None),
        };
        let encrypted = self.transport.encrypt(packet)?;
        Ok(Some((peer_id, encrypted)))
    }

    pub fn route_inbound(&mut self, encrypted: &[u8]) -> std::result::Result<Vec<u8>, Error> {
        let decrypted = self.transport.decrypt(encrypted)?;
        let _parsed = parse_ipv4_packet(&decrypted)?;
        Ok(decrypted)
    }

    pub fn our_overlay(&self) -> OverlayAddr {
        self.our_overlay
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seednet_crypto::{complete_handshake_pair, derive_network_secret, DeviceKeys, DeviceSeedBytes};
    use seednet_common::Seed;

    fn test_peer_id(n: u8) -> PeerId {
        PeerId::from_bytes([n; 32])
    }

    fn make_transport_pair() -> (SecureTransport, SecureTransport) {
        let secret = derive_network_secret(&Seed::from_passphrase("routing test"));
        let keys_a = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0x11u8; 32]));
        let keys_b = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0x22u8; 32]));
        complete_handshake_pair(&secret, &keys_a, &secret, &keys_b).unwrap()
    }

    fn make_ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, payload_len: usize) -> Vec<u8> {
        let total_len = IPV4_HEADER_MIN_LEN + payload_len;
        let mut pkt = vec![0u8; total_len];
        pkt[0] = 0x45;
        pkt[2] = ((total_len >> 8) & 0xFF) as u8;
        pkt[3] = (total_len & 0xFF) as u8;
        pkt[4..8].copy_from_slice(&[0, 0, 0, 0]);
        pkt[8] = 64;
        pkt[9] = 6;
        pkt[10..12].copy_from_slice(&[0, 0]);
        pkt[IPV4_SRC_OFFSET..IPV4_SRC_OFFSET + 4].copy_from_slice(&src.octets());
        pkt[IPV4_DST_OFFSET..IPV4_DST_OFFSET + 4].copy_from_slice(&dst.octets());
        pkt
    }

    #[test]
    fn parse_valid_ipv4() {
        let src = Ipv4Addr::new(10, 88, 1, 1);
        let dst = Ipv4Addr::new(10, 88, 1, 2);
        let pkt = make_ipv4_packet(src, dst, 20);
        let parsed = parse_ipv4_packet(&pkt).unwrap();
        assert_eq!(parsed.src_ip, src);
        assert_eq!(parsed.dst_ip, dst);
    }

    #[test]
    fn parse_too_short() {
        assert!(parse_ipv4_packet(&[0x45, 0, 0, 0]).is_err());
    }

    #[test]
    fn parse_wrong_version() {
        let mut pkt = make_ipv4_packet(Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, 0);
        pkt[0] = 0x60;
        assert!(parse_ipv4_packet(&pkt).is_err());
    }

    #[test]
    fn routing_table_lookup() {
        let mut table = RoutingTable::new();
        let id = test_peer_id(1);
        let overlay = OverlayAddr::new(Ipv4Addr::new(10, 88, 1, 1));
        table.add_route(overlay, id);
        assert_eq!(table.lookup(Ipv4Addr::new(10, 88, 1, 1)), Some(&id));
        assert_eq!(table.lookup(Ipv4Addr::new(10, 88, 1, 99)), None);
    }

    #[test]
    fn routing_table_remove() {
        let mut table = RoutingTable::new();
        let id = test_peer_id(1);
        let overlay = OverlayAddr::new(Ipv4Addr::new(10, 88, 1, 1));
        table.add_route(overlay, id);
        let removed = table.remove_route(&overlay).unwrap();
        assert_eq!(removed, id);
        assert!(table.is_empty());
    }

    #[test]
    fn is_overlay_dst() {
        let table = RoutingTable::new();
        assert!(table.is_overlay_dst(Ipv4Addr::new(10, 88, 1, 1)));
        assert!(table.is_overlay_dst(Ipv4Addr::new(10, 88, 0, 0)));
        assert!(!table.is_overlay_dst(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn router_outbound_encrypts_and_routes() {
        let mut table = RoutingTable::new();
        let id = test_peer_id(1);
        let dst = OverlayAddr::new(Ipv4Addr::new(10, 88, 1, 2));
        let our = OverlayAddr::new(Ipv4Addr::new(10, 88, 1, 1));
        table.add_route(dst, id);

        let (t_a, _) = make_transport_pair();
        let mut router = Router::new(table, t_a, our);

        let pkt = make_ipv4_packet(our.ip(), dst.ip(), 20);
        let result = router.route_outbound(&pkt).unwrap();
        assert!(result.is_some());
        let (routed_peer, encrypted) = result.unwrap();
        assert_eq!(routed_peer, id);
        assert_ne!(encrypted, pkt);
    }

    #[test]
    fn router_outbound_non_overlay_returns_none() {
        let table = RoutingTable::new();
        let our = OverlayAddr::new(Ipv4Addr::new(10, 88, 1, 1));
        let (t_a, _) = make_transport_pair();
        let mut router = Router::new(table, t_a, our);

        let pkt = make_ipv4_packet(Ipv4Addr::new(10, 88, 1, 1), Ipv4Addr::new(192, 168, 1, 1), 20);
        assert!(router.route_outbound(&pkt).unwrap().is_none());
    }

    #[test]
    fn router_inbound_decrypts() {
        let mut table = RoutingTable::new();
        let id = test_peer_id(1);
        let dst = OverlayAddr::new(Ipv4Addr::new(10, 88, 1, 2));
        let our = OverlayAddr::new(Ipv4Addr::new(10, 88, 1, 1));
        table.add_route(dst, id);

        let (t_a, mut t_b) = make_transport_pair();
        let mut router = Router::new(table, t_a, our);

        let pkt = make_ipv4_packet(our.ip(), dst.ip(), 20);
        let (_, encrypted) = router.route_outbound(&pkt).unwrap().unwrap();

        let decrypted: Vec<u8> = t_b.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, pkt);
    }

    #[test]
    fn router_outbound_self_dst_returns_none() {
        let mut table = RoutingTable::new();
        let our = OverlayAddr::new(Ipv4Addr::new(10, 88, 1, 1));
        table.add_route(our, test_peer_id(99));
        let (t_a, _) = make_transport_pair();
        let mut router = Router::new(table, t_a, our);

        let pkt = make_ipv4_packet(our.ip(), our.ip(), 20);
        assert!(router.route_outbound(&pkt).unwrap().is_none());
    }
}
