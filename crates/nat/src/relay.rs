//! Relay candidate table.
//!
//! Tracks which peers have announced themselves as relay-capable,
//! and which relay paths exist for peers we cannot reach directly.

use std::collections::HashMap;
use std::net::SocketAddr;

use seednet_common::PeerId;

/// Known relay-capable peers and the relay paths for unreachable peers.
pub struct RelayTable {
    /// relay_peer_id → public underlay addr
    candidates: HashMap<PeerId, SocketAddr>,
    /// dst_peer_id → relay_peer_id to use
    paths: HashMap<PeerId, PeerId>,
}

impl RelayTable {
    pub fn new() -> Self {
        Self {
            candidates: HashMap::new(),
            paths: HashMap::new(),
        }
    }

    /// Register a relay-capable peer.
    pub fn add_candidate(&mut self, relay_id: PeerId, addr: SocketAddr) {
        self.candidates.insert(relay_id, addr);
    }

    /// Record that `dst` can be reached via `relay`.
    pub fn add_path(&mut self, dst: PeerId, relay: PeerId) {
        self.paths.insert(dst, relay);
    }

    /// Remove all paths and candidates for a peer (e.g. when it disconnects).
    pub fn remove_peer(&mut self, peer_id: &PeerId) {
        self.candidates.remove(peer_id);
        self.paths.remove(peer_id);
        self.paths.retain(|_, r| r != peer_id);
    }

    /// Return the relay peer_id to use for `dst`, if any.
    pub fn relay_for(&self, dst: &PeerId) -> Option<PeerId> {
        self.paths.get(dst).copied()
    }

    /// Pick any available relay candidate.
    pub fn any_candidate(&self) -> Option<(PeerId, SocketAddr)> {
        self.candidates.iter().next().map(|(id, addr)| (*id, *addr))
    }

    /// All known relay candidates.
    pub fn candidates(&self) -> impl Iterator<Item = (&PeerId, &SocketAddr)> {
        self.candidates.iter()
    }

    pub fn has_candidates(&self) -> bool {
        !self.candidates.is_empty()
    }
}

impl Default for RelayTable {
    fn default() -> Self {
        Self::new()
    }
}
