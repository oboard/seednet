use std::net::SocketAddr;
use std::time::Duration;

use seednet_common::PeerId;
use seednet_peer::{PeerEvent, PeerManager, PeerState, Session};

fn test_peer_id(n: u8) -> PeerId {
    PeerId::from_bytes([n; 32])
}

#[test]
fn session_expires_after_timeout() {
    let s = Session::with_config(Duration::from_millis(10), Duration::from_millis(50));
    assert!(!s.is_expired());

    std::thread::sleep(Duration::from_millis(60));
    assert!(s.is_expired());
}

#[test]
fn session_activity_resets_expiry() {
    let mut s = Session::with_config(Duration::from_millis(10), Duration::from_millis(50));
    std::thread::sleep(Duration::from_millis(30));
    s.record_activity();
    assert!(!s.is_expired());

    std::thread::sleep(Duration::from_millis(30));
    assert!(!s.is_expired());

    std::thread::sleep(Duration::from_millis(30));
    assert!(s.is_expired());
}

#[test]
fn heartbeat_triggers_at_interval() {
    let s = Session::with_config(Duration::from_millis(20), Duration::from_secs(300));
    assert!(!s.should_send_heartbeat());

    std::thread::sleep(Duration::from_millis(25));
    assert!(s.should_send_heartbeat());
}

#[test]
fn activity_resets_heartbeat_timer() {
    let mut s = Session::with_config(Duration::from_millis(20), Duration::from_secs(300));
    std::thread::sleep(Duration::from_millis(25));
    assert!(s.should_send_heartbeat());
    s.record_activity();
    assert!(!s.should_send_heartbeat());
}

#[tokio::test]
async fn connected_peer_goes_dead_on_eviction() {
    let mgr = PeerManager::new();
    let id = test_peer_id(1);
    let addr: SocketAddr = "10.0.0.1:4242".parse().unwrap();
    let mut rx = mgr.subscribe();

    let _peer = mgr.discover(id, addr).await;
    let _ = rx.try_recv();

    mgr.transition_peer(&id, PeerState::Connecting).await.unwrap();
    let _ = rx.try_recv();
    mgr.transition_peer(&id, PeerState::Handshaking).await.unwrap();
    let _ = rx.try_recv();
    mgr.transition_peer(&id, PeerState::Connected).await.unwrap();
    let _ = rx.try_recv();

    mgr.transition_peer(&id, PeerState::Dead).await.unwrap();

    let evt = rx.try_recv().unwrap();
    assert_eq!(evt, PeerEvent::StateChanged {
        id,
        from: PeerState::Connected,
        to: PeerState::Dead,
    });
}

#[tokio::test]
async fn dead_peer_can_reconnect() {
    let mgr = PeerManager::new();
    let id = test_peer_id(2);
    let addr: SocketAddr = "10.0.0.2:4242".parse().unwrap();

    let _peer = mgr.discover(id, addr).await;
    mgr.transition_peer(&id, PeerState::Connecting).await.unwrap();
    mgr.transition_peer(&id, PeerState::Handshaking).await.unwrap();
    mgr.transition_peer(&id, PeerState::Connected).await.unwrap();
    mgr.transition_peer(&id, PeerState::Dead).await.unwrap();

    mgr.transition_peer(&id, PeerState::Disconnected).await.unwrap();
    mgr.transition_peer(&id, PeerState::Discovering).await.unwrap();
}

#[tokio::test]
async fn remove_evicted_peer_from_manager() {
    let mgr = PeerManager::new();
    let id = test_peer_id(3);
    let addr: SocketAddr = "10.0.0.3:4242".parse().unwrap();

    let _peer = mgr.discover(id, addr).await;
    mgr.transition_peer(&id, PeerState::Connecting).await.unwrap();
    mgr.transition_peer(&id, PeerState::Handshaking).await.unwrap();
    mgr.transition_peer(&id, PeerState::Connected).await.unwrap();

    assert!(mgr.contains(&id));
    assert_eq!(mgr.peer_count(), 1);

    mgr.remove(&id);
    assert!(!mgr.contains(&id));
    assert_eq!(mgr.peer_count(), 0);
}

#[tokio::test]
async fn evict_expired_peers_keeps_active_ones() {
    let mgr = PeerManager::new();
    let id_active = test_peer_id(10);
    let id_expired = test_peer_id(20);
    let addr_a: SocketAddr = "10.0.0.10:4242".parse().unwrap();
    let addr_e: SocketAddr = "10.0.0.20:4242".parse().unwrap();

    let _active = mgr.discover(id_active, addr_a).await;
    mgr.transition_peer(&id_active, PeerState::Connecting).await.unwrap();
    mgr.transition_peer(&id_active, PeerState::Handshaking).await.unwrap();
    mgr.transition_peer(&id_active, PeerState::Connected).await.unwrap();

    let _expired = mgr.discover(id_expired, addr_e).await;
    mgr.transition_peer(&id_expired, PeerState::Connecting).await.unwrap();
    mgr.transition_peer(&id_expired, PeerState::Handshaking).await.unwrap();
    mgr.transition_peer(&id_expired, PeerState::Connected).await.unwrap();

    assert_eq!(mgr.peer_count(), 2);

    mgr.transition_peer(&id_expired, PeerState::Dead).await.unwrap();
    mgr.remove(&id_expired);

    assert_eq!(mgr.peer_count(), 1);
    assert!(mgr.contains(&id_active));
    assert!(!mgr.contains(&id_expired));
}

#[tokio::test]
async fn connected_peers_excludes_dead_and_expired() {
    let mgr = PeerManager::new();
    let id_alive = test_peer_id(30);
    let id_dead = test_peer_id(31);
    let addr_a: SocketAddr = "10.0.0.30:4242".parse().unwrap();
    let addr_d: SocketAddr = "10.0.0.31:4242".parse().unwrap();

    let _alive = mgr.discover(id_alive, addr_a).await;
    mgr.transition_peer(&id_alive, PeerState::Connecting).await.unwrap();
    mgr.transition_peer(&id_alive, PeerState::Handshaking).await.unwrap();
    mgr.transition_peer(&id_alive, PeerState::Connected).await.unwrap();

    let _dead = mgr.discover(id_dead, addr_d).await;
    mgr.transition_peer(&id_dead, PeerState::Connecting).await.unwrap();
    mgr.transition_peer(&id_dead, PeerState::Handshaking).await.unwrap();
    mgr.transition_peer(&id_dead, PeerState::Connected).await.unwrap();
    mgr.transition_peer(&id_dead, PeerState::Dead).await.unwrap();

    let connected = mgr.connected_peers().await;
    assert!(connected.contains(&id_alive));
    assert!(!connected.contains(&id_dead));
}
