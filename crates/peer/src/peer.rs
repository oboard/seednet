//! [`Peer`] — a remote SeedNet device with an attached state machine.

use std::net::{Ipv6Addr, SocketAddr};
use std::sync::Arc;

use seednet_common::{OverlayAddr, PeerId};
use tokio::sync::RwLock;

use crate::state::{PeerState, StateRecord, TransitionError};

#[derive(Debug)]
pub struct PeerInner {
    pub id: PeerId,
    pub overlay_addr: Option<OverlayAddr>,
    pub overlay_ipv6: Option<Ipv6Addr>,
    pub underlay_addr: Option<SocketAddr>,
    pub hostname: String,
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
                overlay_ipv6: None,
                underlay_addr: None,
                hostname: String::new(),
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
                overlay_ipv6: None,
                underlay_addr: Some(addr),
                hostname: String::new(),
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

    pub async fn overlay_ipv6(&self) -> Option<Ipv6Addr> {
        self.inner.read().await.overlay_ipv6
    }

    pub async fn underlay_addr(&self) -> Option<SocketAddr> {
        self.inner.read().await.underlay_addr
    }

    pub async fn hostname(&self) -> String {
        self.inner.read().await.hostname.clone()
    }

    pub async fn set_overlay_addr(&self, addr: OverlayAddr) {
        self.inner.write().await.overlay_addr = Some(addr);
    }

    pub async fn set_overlay_ipv6(&self, addr: Ipv6Addr) {
        self.inner.write().await.overlay_ipv6 = Some(addr);
    }

    pub async fn set_underlay_addr(&self, addr: SocketAddr) {
        self.inner.write().await.underlay_addr = Some(addr);
    }

    pub async fn set_hostname(&self, name: String) {
        self.inner.write().await.hostname = name;
    }

    pub async fn transition(
        &self,
        next: PeerState,
    ) -> std::result::Result<PeerState, TransitionError> {
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
