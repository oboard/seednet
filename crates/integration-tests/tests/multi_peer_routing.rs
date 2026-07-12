use std::net::Ipv4Addr;

use seednet_common::{OverlayAddr, PeerId, Seed};
use seednet_crypto::{
    DeviceKeys, DeviceSeedBytes, complete_handshake_pair, derive_network_secret,
    derive_overlay_addr,
};
use seednet_routing::{Router, RoutingTable, parse_ipv4_packet};

fn make_ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    const HDR: usize = 20;
    let total = HDR + payload.len();
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2] = ((total >> 8) & 0xFF) as u8;
    pkt[3] = (total & 0xFF) as u8;
    pkt[8] = 64;
    pkt[9] = 6;
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    pkt[HDR..].copy_from_slice(payload);
    pkt
}

struct TestPeer {
    id: PeerId,
    overlay: OverlayAddr,
    keys: DeviceKeys,
}

fn make_test_peer(seed_byte: u8) -> TestPeer {
    let keys = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([seed_byte; 32]));
    let id = keys.peer_id();
    let overlay = derive_overlay_addr(&id);
    TestPeer { id, overlay, keys }
}

#[test]
fn three_peers_router_a_can_reach_b_and_c() {
    let secret = derive_network_secret(&Seed::from_passphrase("multi-peer routing"));
    let a = make_test_peer(0xAA);
    let b = make_test_peer(0xBB);
    let c = make_test_peer(0xCC);

    let (t_ab, mut t_ba) = complete_handshake_pair(&secret, &a.keys, &secret, &b.keys).unwrap();
    let (t_ac, mut t_ca) = complete_handshake_pair(&secret, &a.keys, &secret, &c.keys).unwrap();

    let mut table = RoutingTable::new();
    table.add_route(b.overlay, b.id);
    table.add_route(c.overlay, c.id);

    let mut router_a = Router::new(table, a.overlay);
    router_a.add_transport(b.id, t_ab);
    router_a.add_transport(c.id, t_ac);

    let pkt_to_b = make_ipv4_packet(a.overlay.ip(), b.overlay.ip(), b"hello B");
    let (peer_b, enc_b) = router_a.route_outbound(&pkt_to_b).unwrap().unwrap();
    assert_eq!(peer_b, b.id);
    let dec_b: Vec<u8> = t_ba.decrypt(&enc_b).unwrap();
    assert_eq!(dec_b, pkt_to_b);

    let pkt_to_c = make_ipv4_packet(a.overlay.ip(), c.overlay.ip(), b"hello C");
    let (peer_c, enc_c) = router_a.route_outbound(&pkt_to_c).unwrap().unwrap();
    assert_eq!(peer_c, c.id);
    let dec_c: Vec<u8> = t_ca.decrypt(&enc_c).unwrap();
    assert_eq!(dec_c, pkt_to_c);
}

#[test]
fn three_peers_inbound_from_multiple_peers() {
    let secret = derive_network_secret(&Seed::from_passphrase("multi-peer inbound"));
    let a = make_test_peer(0xAA);
    let b = make_test_peer(0xBB);
    let c = make_test_peer(0xCC);

    let (mut t_ab, t_ba) = complete_handshake_pair(&secret, &a.keys, &secret, &b.keys).unwrap();
    let (mut t_ac, t_ca) = complete_handshake_pair(&secret, &a.keys, &secret, &c.keys).unwrap();

    let table = RoutingTable::new();
    let mut router_a = Router::new(table, a.overlay);
    router_a.add_transport(b.id, t_ba);
    router_a.add_transport(c.id, t_ca);

    let pkt_b = make_ipv4_packet(b.overlay.ip(), a.overlay.ip(), b"from B");
    let enc_b = t_ab.encrypt(&pkt_b).unwrap();
    let dec_b = router_a.route_inbound(&b.id, &enc_b).unwrap();
    assert_eq!(dec_b, pkt_b);

    let pkt_c = make_ipv4_packet(c.overlay.ip(), a.overlay.ip(), b"from C");
    let enc_c = t_ac.encrypt(&pkt_c).unwrap();
    let dec_c = router_a.route_inbound(&c.id, &enc_c).unwrap();
    assert_eq!(dec_c, pkt_c);
}

#[test]
fn five_peers_mesh_routing() {
    let secret = derive_network_secret(&Seed::from_passphrase("mesh routing"));
    let seeds: [u8; 5] = [0x10, 0x20, 0x30, 0x40, 0x50];
    let peers: Vec<TestPeer> = seeds.iter().map(|&s| make_test_peer(s)).collect();

    let mut table = RoutingTable::new();
    let mut transports: Vec<(usize, usize, seednet_crypto::SecureTransport)> = Vec::new();

    for i in 0..5 {
        for j in 0..5 {
            if i == j {
                continue;
            }
            let (t_ij, _) =
                complete_handshake_pair(&secret, &peers[i].keys, &secret, &peers[j].keys).unwrap();
            transports.push((i, j, t_ij));
        }
        table.add_route(peers[i].overlay, peers[i].id);
    }

    let mut router_0 = Router::new(table, peers[0].overlay);
    for (i, j, t) in transports {
        if i == 0 {
            router_0.add_transport(peers[j].id, t);
        }
    }

    for j in 1..5 {
        let pkt = make_ipv4_packet(peers[0].overlay.ip(), peers[j].overlay.ip(), b"mesh pkt");
        let (routed_peer, encrypted) = router_0.route_outbound(&pkt).unwrap().unwrap();
        assert_eq!(routed_peer, peers[j].id, "peer 0 must route to peer {j}");
        assert!(!encrypted.is_empty());
    }
}

#[test]
fn remove_peer_isolates_from_mesh() {
    let secret = derive_network_secret(&Seed::from_passphrase("isolation test"));
    let a = make_test_peer(0xAA);
    let b = make_test_peer(0xBB);
    let c = make_test_peer(0xCC);

    let (t_ab, _) = complete_handshake_pair(&secret, &a.keys, &secret, &b.keys).unwrap();
    let (t_ac, _) = complete_handshake_pair(&secret, &a.keys, &secret, &c.keys).unwrap();

    let mut table = RoutingTable::new();
    table.add_route(b.overlay, b.id);
    table.add_route(c.overlay, c.id);

    let mut router_a = Router::new(table, a.overlay);
    router_a.add_transport(b.id, t_ab);
    router_a.add_transport(c.id, t_ac);

    let pkt_b = make_ipv4_packet(a.overlay.ip(), b.overlay.ip(), b"to B");
    assert!(router_a.route_outbound(&pkt_b).unwrap().is_some());

    router_a.remove_transport(&b.id);
    let removed = router_a.table_mut().remove_route(&b.overlay).unwrap();
    assert_eq!(removed, b.id);

    assert!(router_a.route_outbound(&pkt_b).unwrap().is_none());

    let pkt_c = make_ipv4_packet(a.overlay.ip(), c.overlay.ip(), b"to C");
    assert!(router_a.route_outbound(&pkt_c).unwrap().is_some());
}

#[test]
fn bidirectional_exchange_between_three_peers() {
    let secret = derive_network_secret(&Seed::from_passphrase("bidir 3-way"));
    let a = make_test_peer(0xAA);
    let b = make_test_peer(0xBB);
    let c = make_test_peer(0xCC);

    let (mut t_ab, mut t_ba) = complete_handshake_pair(&secret, &a.keys, &secret, &b.keys).unwrap();
    let (mut t_ac, mut t_ca) = complete_handshake_pair(&secret, &a.keys, &secret, &c.keys).unwrap();
    let (mut t_bc, mut t_cb) = complete_handshake_pair(&secret, &b.keys, &secret, &c.keys).unwrap();

    let pkt_ab = make_ipv4_packet(a.overlay.ip(), b.overlay.ip(), b"A->B");
    let enc_ab = t_ab.encrypt(&pkt_ab).unwrap();
    let dec_ab: Vec<u8> = t_ba.decrypt(&enc_ab).unwrap();
    assert_eq!(dec_ab, pkt_ab);

    let pkt_bc = make_ipv4_packet(b.overlay.ip(), c.overlay.ip(), b"B->C");
    let enc_bc = t_bc.encrypt(&pkt_bc).unwrap();
    let dec_bc: Vec<u8> = t_cb.decrypt(&enc_bc).unwrap();
    assert_eq!(dec_bc, pkt_bc);

    let pkt_ca = make_ipv4_packet(c.overlay.ip(), a.overlay.ip(), b"C->A");
    let enc_ca = t_ca.encrypt(&pkt_ca).unwrap();
    let dec_ca: Vec<u8> = t_ac.decrypt(&enc_ca).unwrap();
    let parsed = parse_ipv4_packet(&dec_ca).unwrap();
    assert_eq!(parsed.src_ip, c.overlay.ip());
    assert_eq!(parsed.dst_ip, a.overlay.ip());
}

#[test]
fn router_with_many_transports_selects_correct_peer() {
    let secret = derive_network_secret(&Seed::from_passphrase("many transports"));
    let target = make_test_peer(0xFF);

    let table = RoutingTable::new();
    let mut router = Router::new(table, OverlayAddr::new(Ipv4Addr::new(10, 88, 0, 1)));

    for i in 1u8..=20 {
        let peer = make_test_peer(i);
        let (t, _) = complete_handshake_pair(&secret, &peer.keys, &secret, &target.keys).unwrap();
        router.table_mut().add_route(peer.overlay, peer.id);
        router.add_transport(peer.id, t);
    }

    assert_eq!(router.table().len(), 20);

    let peer_7 = make_test_peer(7);
    let pkt = make_ipv4_packet(
        Ipv4Addr::new(10, 88, 0, 1),
        peer_7.overlay.ip(),
        b"find peer 7",
    );
    let (routed, encrypted) = router.route_outbound(&pkt).unwrap().unwrap();
    assert_eq!(routed, peer_7.id);
    assert!(!encrypted.is_empty());
}
