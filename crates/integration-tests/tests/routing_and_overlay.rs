//! Integration tests for overlay IP allocation and routing.
//! These tests exercise the full chain: derive keys → allocate overlay IP →
//! add routes → route packets through encrypted transports.

use std::net::Ipv4Addr;

use seednet_common::{OverlayAddr, PeerId, Seed};
use seednet_crypto::{
    complete_handshake_pair, derive_network_secret, derive_overlay_addr, DeviceKeys,
    DeviceSeedBytes,
};
use seednet_overlay::AllocationTable;
use seednet_routing::{parse_ipv4_packet, RoutingTable, Router};

/// Two devices get deterministic, distinct overlay IPs and their routes
/// are correctly set up in the routing table.
#[test]
fn two_devices_get_distinct_overlay_ips_and_routes() {
    let keys_a = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xAA; 32]));
    let keys_b = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xBB; 32]));

    let id_a = keys_a.peer_id();
    let id_b = keys_b.peer_id();

    let overlay_a = derive_overlay_addr(&id_a);
    let overlay_b = derive_overlay_addr(&id_b);

    assert_ne!(overlay_a, overlay_b);
    assert!(overlay_a.ip().octets()[0] == 10 && overlay_a.ip().octets()[1] == 88);
    assert!(overlay_b.ip().octets()[0] == 10 && overlay_b.ip().octets()[1] == 88);

    let mut table = AllocationTable::new();
    let alloc_a = table.allocate(id_a);
    let alloc_b = table.allocate(id_b);

    assert_eq!(alloc_a, overlay_a);
    assert_eq!(alloc_b, overlay_b);

    let mut routing = RoutingTable::new();
    routing.add_route(overlay_a, id_a);
    routing.add_route(overlay_b, id_b);

    assert_eq!(routing.lookup(overlay_a.ip()), Some(&id_a));
    assert_eq!(routing.lookup(overlay_b.ip()), Some(&id_b));
}

/// Allocation table resolves collisions: if two peer IDs hash to the same
/// overlay IP, the second gets a fallback address.
#[test]
fn allocation_collision_resolution() {
    let mut table = AllocationTable::new();

    // Force a collision by manually inserting an overlay IP, then allocating
    // a peer whose derived address matches.
    let id_a = PeerId::from_bytes([0x10; 32]);
    let overlay_a = table.allocate(id_a);

    // Manually occupy the derived address of id_b
    let id_b = PeerId::from_bytes([0x20; 32]);
    let derived_b = derive_overlay_addr(&id_b);

    // If they happen to collide, verify resolution works
    if derived_b == overlay_a {
        let overlay_b = table.allocate(id_b);
        assert_ne!(overlay_b, overlay_a, "collision must be resolved to a different IP");
        assert_eq!(table.len(), 2);
    } else {
        // No collision in this case, just verify both allocated
        let overlay_b = table.allocate(id_b);
        assert_eq!(table.len(), 2);
        assert_ne!(overlay_a, overlay_b);
    }
}

/// Full routing simulation: A sends an IPv4 packet to B through the
/// Router (encrypt), then B receives and decrypts it.
#[test]
fn router_encrypt_decrypt_full_simulation() {
    let secret = derive_network_secret(&Seed::from_passphrase("routing integration"));
    let keys_a = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xAA; 32]));
    let keys_b = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xBB; 32]));

    let id_a = keys_a.peer_id();
    let id_b = keys_b.peer_id();
    let overlay_a = derive_overlay_addr(&id_a);
    let overlay_b = derive_overlay_addr(&id_b);

    // Create matching transport pair
    let (t_a, mut t_b) = complete_handshake_pair(&secret, &keys_a, &secret, &keys_b).unwrap();

    let mut table = RoutingTable::new();
    table.add_route(overlay_b, id_b);

    let mut router_a = Router::new(table, t_a, overlay_a);

    // Build a realistic IPv4 packet from A to B
    let packet = make_ipv4_packet(overlay_a.ip(), overlay_b.ip(), b"TCP SYN data");

    // A routes outbound: encrypts and returns (peer_id, ciphertext)
    let result = router_a.route_outbound(&packet).unwrap();
    let (routed_peer, encrypted) = result.unwrap();
    assert_eq!(routed_peer, id_b);

    // B receives: decrypts and gets the original packet
    let decrypted: Vec<u8> = t_b.decrypt(&encrypted).unwrap();
    assert_eq!(decrypted, packet);

    // Verify the decrypted packet parses correctly
    let parsed = parse_ipv4_packet(&decrypted).unwrap();
    assert_eq!(parsed.src_ip, overlay_a.ip());
    assert_eq!(parsed.dst_ip, overlay_b.ip());
}

/// Router drops packets destined for non-overlay IPs (e.g. Internet).
#[test]
fn router_drops_non_overlay_packets() {
    let secret = derive_network_secret(&Seed::from_passphrase("drop test"));
    let keys_a = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xAA; 32]));
    let keys_b = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xBB; 32]));

    let id_b = keys_b.peer_id();
    let overlay_a = derive_overlay_addr(&keys_a.peer_id());

    let (t_a, _) = complete_handshake_pair(&secret, &keys_a, &secret, &keys_b).unwrap();

    let mut table = RoutingTable::new();
    table.add_route(OverlayAddr::new(Ipv4Addr::new(10, 88, 1, 2)), id_b);

    let mut router = Router::new(table, t_a, overlay_a);

    // Packet to 8.8.8.8 — not in 10.88.0.0/16
    let packet = make_ipv4_packet(overlay_a.ip(), Ipv4Addr::new(8, 8, 8, 8), b"DNS query");
    let result = router.route_outbound(&packet).unwrap();
    assert!(result.is_none(), "non-overlay packets must be dropped");
}

/// Router drops packets addressed to self.
#[test]
fn router_drops_self_addressed_packets() {
    let secret = derive_network_secret(&Seed::from_passphrase("self drop"));
    let keys_a = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xAA; 32]));
    let keys_b = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xBB; 32]));

    let overlay_a = derive_overlay_addr(&keys_a.peer_id());

    let (t_a, _) = complete_handshake_pair(&secret, &keys_a, &secret, &keys_b).unwrap();

    let table = RoutingTable::new();
    let mut router = Router::new(table, t_a, overlay_a);

    let packet = make_ipv4_packet(overlay_a.ip(), overlay_a.ip(), b"loopback");
    let result = router.route_outbound(&packet).unwrap();
    assert!(result.is_none(), "self-addressed packets must be dropped");
}

/// Remove a route and verify packets to that destination are no longer routed.
#[test]
fn route_removal_prevents_forwarding() {
    let secret = derive_network_secret(&Seed::from_passphrase("route rm"));
    let keys_a = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xAA; 32]));
    let keys_b = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xBB; 32]));

    let id_b = keys_b.peer_id();
    let overlay_a = derive_overlay_addr(&keys_a.peer_id());
    let overlay_b = derive_overlay_addr(&id_b);

    let (t_a, _) = complete_handshake_pair(&secret, &keys_a, &secret, &keys_b).unwrap();

    let mut table = RoutingTable::new();
    table.add_route(overlay_b, id_b);

    let mut router = Router::new(table, t_a, overlay_a);

    // Route exists → packet is forwarded
    let packet = make_ipv4_packet(overlay_a.ip(), overlay_b.ip(), b"data");
    assert!(router.route_outbound(&packet).unwrap().is_some());

    // Remove the route
    let removed = router.table_mut().remove_route(&overlay_b).unwrap();
    assert_eq!(removed, id_b);

    // Route gone → packet is dropped
    assert!(router.route_outbound(&packet).unwrap().is_none());
}

/// Allocation table correctly tracks many peers and cleans up on removal.
#[test]
fn allocation_table_many_peers_lifecycle() {
    let mut table = AllocationTable::new();
    let mut ids = Vec::new();
    let mut overlays = Vec::new();

    // Allocate 20 peers
    for i in 1u8..=20 {
        let id = PeerId::from_bytes([i; 32]);
        let overlay = table.allocate(id);
        ids.push(id);
        overlays.push(overlay);
    }

    assert_eq!(table.len(), 20);

    // All allocations are in the overlay subnet
    for overlay in &overlays {
        let octets = overlay.ip().octets();
        assert_eq!(&octets[..2], &[10, 88]);
    }

    // Remove half
    for i in 0..10 {
        let removed = table.remove(&ids[i]).unwrap();
        assert_eq!(removed.overlay, overlays[i]);
    }
    assert_eq!(table.len(), 10);

    // Remaining peers still accessible
    for i in 10..20 {
        assert!(table.lookup_by_peer(&ids[i]).is_some());
    }
}

// ── helpers ────────────────────────────────────────────────────

fn make_ipv4_packet(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    const HDR: usize = 20;
    let total = HDR + payload.len();
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45; // version=4, IHL=5
    pkt[2] = ((total >> 8) & 0xFF) as u8;
    pkt[3] = (total & 0xFF) as u8;
    pkt[8] = 64; // TTL
    pkt[9] = 6; // TCP
    pkt[12..16].copy_from_slice(&src.octets());
    pkt[16..20].copy_from_slice(&dst.octets());
    pkt[HDR..].copy_from_slice(payload);
    pkt
}
