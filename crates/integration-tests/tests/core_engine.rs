//! Integration tests for the core engine: identity derivation,
//! overlay allocation, routing table setup, and cross-crate wiring.

use std::sync::atomic::{AtomicU64, Ordering};

use seednet_common::Seed;
use seednet_config::StateDir;
use seednet_core::{SeedNetConfig, SeedNetEngine, print_status};
use seednet_crypto::{
    DeviceKeys, DeviceSeedBytes, derive_infohash, derive_network_secret, derive_overlay_addr,
};
use seednet_overlay::AllocationTable;
use seednet_routing::RoutingTable;

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_state_dir() -> StateDir {
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("seednet-integ-{}-{n}", std::process::id(),));
    StateDir::new(&dir).expect("create temp state dir")
}

/// Engine creates a deterministic identity: same seed → same infohash,
/// same peer_id → same overlay IP.
#[test]
fn deterministic_identity_from_seed() {
    let state_dir = temp_state_dir();
    let seed = Seed::from_passphrase("deterministic test");
    let config = SeedNetConfig::new(seed.clone(), 4242, state_dir);
    let engine = SeedNetEngine::new(config).unwrap();

    let secret = derive_network_secret(&seed);
    let infohash = derive_infohash(&secret);
    assert_eq!(*engine.infohash(), infohash);
    assert_eq!(*engine.network_secret(), secret);
    assert_eq!(
        engine.our_overlay(),
        derive_overlay_addr(&engine.our_peer_id())
    );
}

/// Engine's overlay IP is always in the 10.88.0.0/16 subnet.
#[test]
fn overlay_ip_in_subnet() {
    let state_dir = temp_state_dir();
    let config = SeedNetConfig::new(Seed::from_passphrase("subnet check"), 4242, state_dir);
    let engine = SeedNetEngine::new(config).unwrap();

    let octets = engine.our_overlay().ip().octets();
    assert_eq!(octets[0], 10);
    assert_eq!(octets[1], 88);
}

/// Self-allocation in the engine: our own peer ID → our overlay IP in
/// the allocation table, and a route to self in the routing table
/// (for loopback detection).
#[tokio::test]
async fn self_allocation_and_route() {
    let state_dir = temp_state_dir();
    let config = SeedNetConfig::new(Seed::from_passphrase("self alloc"), 4242, state_dir);
    let engine = SeedNetEngine::new(config).unwrap();

    let peer_id = engine.our_peer_id();
    let overlay = engine.our_overlay();

    let mut alloc = engine.allocation_table().write().await;
    let addr = alloc.allocate(peer_id);
    assert_eq!(addr, overlay);
    drop(alloc);

    let mut routing = engine.routing_table().write().await;
    routing.add_route(overlay, peer_id);
    assert_eq!(routing.lookup(overlay.ip()), Some(&peer_id));
}

/// Two engines with different seeds have different infohashes and
/// different overlay IPs.
#[test]
fn two_engines_different_networks() {
    let state_dir_a = temp_state_dir();
    let state_dir_b = temp_state_dir();
    let config_a = SeedNetConfig::new(Seed::from_passphrase("network A"), 4242, state_dir_a);
    let config_b = SeedNetConfig::new(Seed::from_passphrase("network B"), 4243, state_dir_b);

    let engine_a = SeedNetEngine::new(config_a).unwrap();
    let engine_b = SeedNetEngine::new(config_b).unwrap();

    assert_ne!(engine_a.infohash(), engine_b.infohash());
    assert_ne!(engine_a.our_overlay(), engine_b.our_overlay());
    assert_ne!(engine_a.our_peer_id(), engine_b.our_peer_id());
}

/// Two engines with the SAME seed but different device keys still have
/// the same infohash (same network) but different overlay IPs.
#[test]
fn same_network_different_devices() {
    let state_dir_a = temp_state_dir();
    let state_dir_b = temp_state_dir();
    let seed = Seed::from_passphrase("shared network");

    let config_a = SeedNetConfig::new(seed.clone(), 4242, state_dir_a);
    let config_b = SeedNetConfig::new(seed, 4243, state_dir_b);

    let engine_a = SeedNetEngine::new(config_a).unwrap();
    let engine_b = SeedNetEngine::new(config_b).unwrap();

    assert_eq!(engine_a.infohash(), engine_b.infohash());
    assert_eq!(engine_a.network_secret(), engine_b.network_secret());

    assert_ne!(engine_a.our_peer_id(), engine_b.our_peer_id());
    assert_ne!(engine_a.our_overlay(), engine_b.our_overlay());
}

/// Full cross-crate scenario: two devices, allocate overlay IPs, add
/// routes for each other, verify routing table lookups work.
#[tokio::test]
async fn two_devices_routing_table_cross_reference() {
    let keys_a = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xAA; 32]));
    let keys_b = DeviceKeys::from_seed(DeviceSeedBytes::from_bytes([0xBB; 32]));

    let id_a = keys_a.peer_id();
    let id_b = keys_b.peer_id();
    let overlay_a = derive_overlay_addr(&id_a);
    let overlay_b = derive_overlay_addr(&id_b);

    let mut table_a = AllocationTable::new();
    let mut table_b = AllocationTable::new();
    table_a.allocate(id_a);
    table_b.allocate(id_b);

    let mut routing_a = RoutingTable::new();
    routing_a.add_route(overlay_b, id_b);
    routing_a.add_route(overlay_a, id_a);

    let mut routing_b = RoutingTable::new();
    routing_b.add_route(overlay_a, id_a);
    routing_b.add_route(overlay_b, id_b);

    assert_eq!(routing_a.lookup(overlay_b.ip()), Some(&id_b));
    assert_eq!(routing_b.lookup(overlay_a.ip()), Some(&id_a));
    assert_eq!(routing_a.lookup(overlay_a.ip()), Some(&id_a));

    let removed = routing_a.remove_route(&overlay_b).unwrap();
    assert_eq!(removed, id_b);
    assert!(routing_a.lookup(overlay_b.ip()).is_none());
}

/// Device identity persistence: loading the same state dir twice gives
/// the same peer ID.
#[test]
fn identity_persistence() {
    let state_dir = temp_state_dir();
    let seed = Seed::from_passphrase("persist test");

    let config1 = SeedNetConfig::new(seed.clone(), 4242, state_dir.clone());
    let engine1 = SeedNetEngine::new(config1).unwrap();
    let peer_id1 = engine1.our_peer_id();

    let config2 = SeedNetConfig::new(seed, 4243, state_dir);
    let engine2 = SeedNetEngine::new(config2).unwrap();
    let peer_id2 = engine2.our_peer_id();

    assert_eq!(
        peer_id1, peer_id2,
        "same state dir must yield same identity"
    );
}

/// print_status runs without panic.
#[test]
fn print_status_ok() {
    let state_dir = temp_state_dir();
    let config = SeedNetConfig::new(Seed::from_passphrase("status"), 4242, state_dir);
    let engine = SeedNetEngine::new(config).unwrap();
    print_status(&engine);
}
