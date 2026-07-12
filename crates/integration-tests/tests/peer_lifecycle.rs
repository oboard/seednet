//! Integration tests for the peer state machine lifecycle,
//! session management, and peer manager event system.

use std::net::SocketAddr;
use std::time::Duration;

use seednet_common::{OverlayAddr, PeerId};
use seednet_peer::{PeerManager, PeerState, Session};

/// Complete peer lifecycle: Disconnected → Discovering → Connecting →
/// Handshaking → Connected → Disconnected (graceful close).
#[tokio::test]
async fn full_peer_lifecycle_transitions() {
    let mgr = PeerManager::new();
    let id = PeerId::from_bytes([0x01; 32]);
    let addr: SocketAddr = "10.0.0.1:4242".parse().unwrap();

    let peer = mgr.discover(id, addr).await;
    assert_eq!(peer.state().await, PeerState::Discovering);

    mgr.transition_peer(&id, PeerState::Connecting)
        .await
        .unwrap();
    assert_eq!(peer.state().await, PeerState::Connecting);

    mgr.transition_peer(&id, PeerState::Handshaking)
        .await
        .unwrap();
    assert_eq!(peer.state().await, PeerState::Handshaking);

    mgr.transition_peer(&id, PeerState::Connected)
        .await
        .unwrap();
    assert_eq!(peer.state().await, PeerState::Connected);

    mgr.transition_peer(&id, PeerState::Disconnected)
        .await
        .unwrap();
    assert_eq!(peer.state().await, PeerState::Disconnected);
}

/// Peer going through the lifecycle and then dying.
#[tokio::test]
async fn peer_goes_dead_after_connected() {
    let mgr = PeerManager::new();
    let id = PeerId::from_bytes([0x02; 32]);
    let addr: SocketAddr = "10.0.0.2:4242".parse().unwrap();

    let peer = mgr.discover(id, addr).await;
    mgr.transition_peer(&id, PeerState::Connecting)
        .await
        .unwrap();
    mgr.transition_peer(&id, PeerState::Handshaking)
        .await
        .unwrap();
    mgr.transition_peer(&id, PeerState::Connected)
        .await
        .unwrap();

    mgr.transition_peer(&id, PeerState::Dead).await.unwrap();
    assert_eq!(peer.state().await, PeerState::Dead);

    // Dead peer can transition back to Disconnected for reconnection
    mgr.transition_peer(&id, PeerState::Disconnected)
        .await
        .unwrap();
    assert_eq!(peer.state().await, PeerState::Disconnected);
}

/// Verify that PeerEvent::StateChanged events are emitted in the correct
/// order for a full lifecycle.
#[tokio::test]
async fn event_sequence_for_lifecycle() {
    let mgr = PeerManager::new();
    let mut rx = mgr.subscribe();
    let id = PeerId::from_bytes([0x03; 32]);
    let addr: SocketAddr = "10.0.0.3:4242".parse().unwrap();

    // Discover
    mgr.discover(id, addr).await;
    let evt = rx.try_recv().unwrap();
    assert!(
        matches!(evt, seednet_peer::PeerEvent::Discovered { id: _, underlay } if underlay == addr)
    );

    // Transition through states
    let transitions = [
        (
            PeerState::Connecting,
            PeerState::Discovering,
            PeerState::Connecting,
        ),
        (
            PeerState::Handshaking,
            PeerState::Connecting,
            PeerState::Handshaking,
        ),
        (
            PeerState::Connected,
            PeerState::Handshaking,
            PeerState::Connected,
        ),
    ];

    for (next, expected_from, expected_to) in transitions {
        mgr.transition_peer(&id, next).await.unwrap();
        let evt = rx.try_recv().unwrap();
        match evt {
            seednet_peer::PeerEvent::StateChanged { id: eid, from, to } => {
                assert_eq!(eid, id);
                assert_eq!(from, expected_from);
                assert_eq!(to, expected_to);
            }
            other => panic!("expected StateChanged, got {other:?}"),
        }
    }
}

/// Multiple peers managed simultaneously.
#[tokio::test]
async fn multiple_peers_simultaneously() {
    let mgr = PeerManager::new();

    let ids: Vec<PeerId> = (1..=5).map(|i| PeerId::from_bytes([i; 32])).collect();
    let mut peers = Vec::new();

    for (i, id) in ids.iter().enumerate() {
        let addr: SocketAddr = format!("10.0.0.{}:4242", i + 1).parse().unwrap();
        let peer = mgr.discover(*id, addr).await;
        peers.push(peer);
    }

    assert_eq!(mgr.peer_count(), 5);

    // Transition each peer to Connected
    for id in &ids {
        mgr.transition_peer(id, PeerState::Connecting)
            .await
            .unwrap();
        mgr.transition_peer(id, PeerState::Handshaking)
            .await
            .unwrap();
        mgr.transition_peer(id, PeerState::Connected).await.unwrap();
    }

    let connected = mgr.connected_peers().await;
    assert_eq!(connected.len(), 5);

    // Remove one peer
    mgr.remove(&ids[2]);
    assert_eq!(mgr.peer_count(), 4);

    let connected = mgr.connected_peers().await;
    assert_eq!(connected.len(), 4);
}

/// Session expires after the timeout period.
#[test]
fn session_expires_after_timeout() {
    let mut session = Session::with_config(Duration::from_millis(1), Duration::from_millis(50));

    assert!(!session.is_expired());

    // Wait just past the expiry
    std::thread::sleep(Duration::from_millis(60));
    assert!(session.is_expired());

    // Activity resets the timer
    session.record_activity();
    assert!(!session.is_expired());
}

/// Session heartbeat timing.
#[test]
fn session_heartbeat_timing() {
    let mut session = Session::with_config(Duration::from_millis(100), Duration::from_secs(60));

    // Right after creation, no heartbeat needed yet
    // (elapsed is ~0, which is < 100ms)

    // After waiting past the interval, heartbeat is needed
    std::thread::sleep(Duration::from_millis(110));
    assert!(session.should_send_heartbeat());

    // Activity resets the heartbeat timer
    session.record_activity();
    assert!(!session.should_send_heartbeat());
}

/// Overlay address gets assigned to a peer and can be looked up.
#[tokio::test]
async fn overlay_assignment_and_lookup() {
    let mgr = PeerManager::new();
    let id = PeerId::from_bytes([0xAB; 32]);
    let addr: SocketAddr = "10.0.0.5:4242".parse().unwrap();

    let peer = mgr.discover(id, addr).await;
    assert!(peer.overlay_addr().await.is_none());

    let overlay = OverlayAddr::new(std::net::Ipv4Addr::new(10, 88, 1, 100));
    assert!(mgr.assign_overlay(&id, overlay).await);

    assert_eq!(peer.overlay_addr().await, Some(overlay));
}

/// Re-discovering an existing peer updates its underlay address.
#[tokio::test]
async fn rediscover_updates_underlay() {
    let mgr = PeerManager::new();
    let id = PeerId::from_bytes([0xCC; 32]);
    let addr1: SocketAddr = "10.0.0.10:4242".parse().unwrap();
    let addr2: SocketAddr = "10.0.0.20:4243".parse().unwrap();

    mgr.discover(id, addr1).await;
    let peer = mgr.get(&id).unwrap();
    assert_eq!(peer.underlay_addr().await, Some(addr1));

    // Re-discover with new address (e.g. NAT rebinding)
    mgr.discover(id, addr2).await;
    assert_eq!(peer.underlay_addr().await, Some(addr2));
}
