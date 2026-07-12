//! [`Peer`] — a remote SeedNet device with an attached state machine.
//!
//! Each peer is identified by its [`PeerId`] and can carry an optional
//! [`OverlayAddr`] once it has been assigned an overlay IP. All state
//! transitions go through [`StateRecord::transition`] which enforces the
//! legal lifecycle defined in [`crate::state`].

use std::net::SocketAddr;
use std::sync::Arc;

use seednet_common::{OverlayAddr, PeerId};
use tokio::sync::RwLock;

use crate::state::{PeerState, StateRecord, TransitionError};

#[derive(Debug)]
pub struct PeerInner {
    pub id: PeerId,
    pub overlay_addr: Option<OverlayAddr>,
    pub underlay_addr: Option<SocketAddr>,
    pub state: StateRecord,
}

#[derive(Debug)]
pub struct Peer {
    inner: Arc<RwLock<PeerInner>>,
    id: PeerId,
}

impl Peer {
    pub fn new(id: PeerId) -> Self {
        Self {
            id,
            inner: Arc::new(RwLock::new(PeerInner {
                id,
                overlay_addr: None,
                underlay_addr: None,
                state: StateRecord::new(PeerState::Disconnected),
            })),
        }
    }

    pub fn new_with_underlay(id: PeerId, addr: SocketAddr) -> Self {
        Self {
            id,
            inner: Arc::new(RwLock::new(PeerInner {
                id,
                overlay_addr: None,
                underlay_addr: Some(addr),
                state: StateRecord::new(PeerState::Disconnected),
            })),
        }
    }

    pub fn id(&self) -> PeerId {
        self.id
    }

    pub async fn state(&self) -> PeerState {
        self.inner.read().await.state.state
    }

    pub async fn overlay_addr(&self) -> Option<OverlayAddr> {
        self.inner.read().await.overlay_addr
    }

    pub async fn underlay_addr(&self) -> Option<SocketAddr> {
        self.inner.read().await.underlay_addr
    }

    pub async fn set_overlay_addr(&self, addr: OverlayAddr) {
        self.inner.write().await.overlay_addr = Some(addr);
    }

    pub async fn set_underlay_addr(&self, addr: SocketAddr) {
        self.inner.write().await.underlay_addr = Some(addr);
    }

    pub async fn transition(&self, next: PeerState) -> std::result::Result<PeerState, TransitionError> {
        let mut inner = self.inner.write().await;
        let prev = inner.state.state;
        inner.state.transition(next)?;
        tracing::debug!(peer = %self.id, from = %prev, to = %next, "peer state transition");
        Ok(next)
    }

    pub async fn state_elapsed(&self) -> std::time::Duration {
        self.inner.read().await.state.elapsed()
    }

    pub fn inner_arc(&self) -> Arc<RwLock<PeerInner>> {
        Arc::clone(&self.inner)
    }
}

impl Clone for Peer {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            id: self.id,
        }
    }
}

impl std::fmt::Display for Peer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Peer({})", self.id.short())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seednet_common::PeerId;

    fn test_peer_id() -> PeerId {
        PeerId::from_bytes([0x42u8; 32])
    }

    #[tokio::test]
    async fn new_peer_starts_disconnected() {
        let p = Peer::new(test_peer_id());
        assert_eq!(p.state().await, PeerState::Disconnected);
    }

    #[tokio::test]
    async fn full_lifecycle() {
        let p = Peer::new(test_peer_id());
        p.transition(PeerState::Discovering).await.unwrap();
        p.transition(PeerState::Connecting).await.unwrap();
        p.transition(PeerState::Handshaking).await.unwrap();
        p.transition(PeerState::Connected).await.unwrap();
        assert_eq!(p.state().await, PeerState::Connected);
    }

    #[tokio::test]
    async fn invalid_transition_rejected() {
        let p = Peer::new(test_peer_id());
        assert!(p.transition(PeerState::Connected).await.is_err());
    }

    #[tokio::test]
    async fn overlay_addr_roundtrip() {
        let p = Peer::new(test_peer_id());
        assert!(p.overlay_addr().await.is_none());
        p.set_overlay_addr(OverlayAddr::new(std::net::Ipv4Addr::new(10, 88, 1, 1)))
            .await;
        assert_eq!(
            p.overlay_addr().await,
            Some(OverlayAddr::new(std::net::Ipv4Addr::new(10, 88, 1, 1)))
        );
    }

    #[tokio::test]
    async fn underlay_addr_roundtrip() {
        let addr: SocketAddr = "1.2.3.4:4242".parse().unwrap();
        let p =         Peer::new_with_underlay(test_peer_id(), addr);
        assert_eq!(p.underlay_addr().await, Some(addr));
    }

    #[tokio::test]
    async fn clone_shares_state() {
        let p = Peer::new(test_peer_id());
        let p2 = p.clone();
        p.transition(PeerState::Discovering).await.unwrap();
        assert_eq!(p2.state().await, PeerState::Discovering);
    }
}
