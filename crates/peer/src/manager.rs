//! [`PeerManager`] — concurrent peer table with event emission.
//!
//! Holds all known [`Peer`]s in a [`DashMap`] keyed by [`PeerId`] for lock-free
//! concurrent access. When a peer is inserted, removed, or changes state, a
//! [`PeerEvent`] is sent on the internal broadcast channel so that the
//! orchestration layer can react without polling.

use std::net::SocketAddr;

use dashmap::DashMap;
use seednet_common::{OverlayAddr, PeerId};
use tokio::sync::broadcast;

use crate::peer::Peer;
use crate::state::{PeerState, TransitionError};

pub const EVENT_CHANNEL_CAPACITY: usize = 256;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PeerEvent {
    Discovered { id: PeerId, underlay: SocketAddr },
    StateChanged { id: PeerId, from: PeerState, to: PeerState },
    OverlayAssigned { id: PeerId, overlay: OverlayAddr },
    Removed { id: PeerId },
}

impl std::fmt::Display for PeerEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerEvent::Discovered { id, underlay } => {
                write!(f, "Discovered({} at {})", id.short(), underlay)
            }
            PeerEvent::StateChanged { id, from, to } => {
                write!(f, "StateChanged({}: {} → {})", id.short(), from, to)
            }
            PeerEvent::OverlayAssigned { id, overlay } => {
                write!(f, "OverlayAssigned({} → {})", id.short(), overlay)
            }
            PeerEvent::Removed { id } => {
                write!(f, "Removed({})", id.short())
            }
        }
    }
}

#[derive(Debug)]
pub struct PeerManager {
    peers: DashMap<PeerId, Peer>,
    tx: broadcast::Sender<PeerEvent>,
}

impl PeerManager {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
        Self {
            peers: DashMap::new(),
            tx,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<PeerEvent> {
        self.tx.subscribe()
    }

    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    pub fn contains(&self, id: &PeerId) -> bool {
        self.peers.contains_key(id)
    }

    pub fn get(&self, id: &PeerId) -> Option<Peer> {
        self.peers.get(id).map(|r| r.value().clone())
    }

    pub fn insert(&self, peer: Peer) {
        let id = peer.id();
        self.peers.insert(id, peer);
    }

    pub fn remove(&self, id: &PeerId) -> Option<Peer> {
        let removed = self.peers.remove(id);
        if removed.is_some() {
            let _ = self.tx.send(PeerEvent::Removed { id: *id });
        }
        removed.map(|(_, v)| v)
    }

    pub fn ids(&self) -> Vec<PeerId> {
        self.peers.iter().map(|r| *r.key()).collect()
    }

    pub async fn discover(&self, id: PeerId, underlay: SocketAddr) -> Peer {
        if let Some(existing) = self.get(&id) {
            existing.set_underlay_addr(underlay).await;
            return existing;
        }
        let peer = Peer::new_with_underlay(id, underlay);
        let _ = peer.transition(PeerState::Discovering).await;
        self.insert(peer.clone());
        let _ = self.tx.send(PeerEvent::Discovered { id, underlay });
        peer
    }

    pub async fn transition_peer(
        &self,
        id: &PeerId,
        next: PeerState,
    ) -> std::result::Result<PeerState, TransitionError> {
        let peer = self
            .get(id)
            .ok_or(TransitionError::InvalidTransition {
                from: PeerState::Dead,
                to: next,
            })?;
        let prev = peer.state().await;
        let result = peer.transition(next).await?;
        let _ = self.tx.send(PeerEvent::StateChanged {
            id: *id,
            from: prev,
            to: result,
        });
        Ok(result)
    }

    pub async fn assign_overlay(&self, id: &PeerId, overlay: OverlayAddr) -> bool {
        if let Some(peer) = self.get(id) {
            peer.set_overlay_addr(overlay).await;
            let _ = self.tx.send(PeerEvent::OverlayAssigned { id: *id, overlay });
            true
        } else {
            false
        }
    }

    pub async fn connected_peers(&self) -> Vec<PeerId> {
        let mut result = Vec::new();
        for entry in self.peers.iter() {
            if entry.value().state().await == PeerState::Connected {
                result.push(*entry.key());
            }
        }
        result
    }
}

impl Default for PeerManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seednet_common::PeerId;

    fn test_peer_id(n: u8) -> PeerId {
        PeerId::from_bytes([n; 32])
    }

    #[tokio::test]
    async fn insert_and_get() {
        let mgr = PeerManager::new();
        let id = test_peer_id(1);
        let p = Peer::new(id);
        mgr.insert(p);
        assert!(mgr.contains(&id));
        assert_eq!(mgr.peer_count(), 1);
        let fetched = mgr.get(&id).unwrap();
        assert_eq!(fetched.id(), id);
    }

    #[tokio::test]
    async fn remove_emits_event() {
        let mgr = PeerManager::new();
        let id = test_peer_id(2);
        mgr.insert(Peer::new(id));
        let mut rx = mgr.subscribe();
        mgr.remove(&id);
        let evt = rx.try_recv().unwrap();
        assert_eq!(evt, PeerEvent::Removed { id });
        assert_eq!(mgr.peer_count(), 0);
    }

    #[tokio::test]
    async fn discover_creates_peer_with_event() {
        let mgr = PeerManager::new();
        let id = test_peer_id(3);
        let addr: SocketAddr = "10.0.0.1:4242".parse().unwrap();
        let mut rx = mgr.subscribe();
        let peer = mgr.discover(id, addr).await;
        assert_eq!(peer.state().await, PeerState::Discovering);
        assert_eq!(peer.underlay_addr().await, Some(addr));
        let evt = rx.try_recv().unwrap();
        assert_eq!(evt, PeerEvent::Discovered { id, underlay: addr });
    }

    #[tokio::test]
    async fn discover_existing_peer_updates_addr() {
        let mgr = PeerManager::new();
        let id = test_peer_id(4);
        let addr1: SocketAddr = "10.0.0.1:4242".parse().unwrap();
        let addr2: SocketAddr = "10.0.0.2:4242".parse().unwrap();
        mgr.discover(id, addr1).await;
        mgr.discover(id, addr2).await;
        let peer = mgr.get(&id).unwrap();
        assert_eq!(peer.underlay_addr().await, Some(addr2));
    }

    #[tokio::test]
    async fn transition_peer_emits_event() {
        let mgr = PeerManager::new();
        let id = test_peer_id(5);
        let addr: SocketAddr = "10.0.0.5:4242".parse().unwrap();
        mgr.discover(id, addr).await;
        let mut rx = mgr.subscribe();
        let _ = rx.try_recv();
        mgr.transition_peer(&id, PeerState::Connecting).await.unwrap();
        let evt = rx.try_recv().unwrap();
        assert_eq!(
            evt,
            PeerEvent::StateChanged {
                id,
                from: PeerState::Discovering,
                to: PeerState::Connecting,
            }
        );
    }

    #[tokio::test]
    async fn transition_peer_unknown_fails() {
        let mgr = PeerManager::new();
        let id = test_peer_id(99);
        let result = mgr.transition_peer(&id, PeerState::Connecting).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn assign_overlay_emits_event() {
        let mgr = PeerManager::new();
        let id = test_peer_id(6);
        mgr.insert(Peer::new(id));
        let mut rx = mgr.subscribe();
        let overlay = OverlayAddr::new(std::net::Ipv4Addr::new(10, 88, 1, 6));
        assert!(mgr.assign_overlay(&id, overlay).await);
        let evt = rx.try_recv().unwrap();
        assert_eq!(evt, PeerEvent::OverlayAssigned { id, overlay });
    }

    #[tokio::test]
    async fn connected_peers_filters() {
        let mgr = PeerManager::new();
        let id_a = test_peer_id(10);
        let id_b = test_peer_id(11);
        let addr_a: SocketAddr = "10.0.0.10:4242".parse().unwrap();
        let addr_b: SocketAddr = "10.0.0.11:4242".parse().unwrap();
        let pa = mgr.discover(id_a, addr_a).await;
        let _pb = mgr.discover(id_b, addr_b).await;
        pa.transition(PeerState::Connecting).await.unwrap();
        pa.transition(PeerState::Handshaking).await.unwrap();
        pa.transition(PeerState::Connected).await.unwrap();
        assert!(mgr.connected_peers().await.contains(&id_a));
        assert!(!mgr.connected_peers().await.contains(&id_b));
    }

    #[tokio::test]
    async fn ids_returns_all() {
        let mgr = PeerManager::new();
        let id1 = test_peer_id(20);
        let id2 = test_peer_id(21);
        mgr.insert(Peer::new(id1));
        mgr.insert(Peer::new(id2));
        let mut ids = mgr.ids();
        ids.sort();
        assert_eq!(ids, vec![id1, id2]);
    }
}
