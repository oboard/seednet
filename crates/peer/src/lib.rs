//! Peer abstraction, state machine, and manager for SeedNet.
//!
//! Every remote SeedNet device is represented as a [`Peer`] that transitions
//! through a well-defined lifecycle:
//!
//! ```text
//! Disconnected → Discovering → Connecting → Handshaking → Connected
//!      ↑              │              │              │             │
//!      │              └──────────────┴──────────────┘             │
//!      │                        (failure)                         │
//!      └──────────────────────────────────────────────────────────┘
//!                         Dead ← (timeout / error)
//! ```
//!
//! The [`PeerManager`] holds all known peers in a [`DashMap`] for lock-free
//! concurrent access and emits [`PeerEvent`]s on a channel so the orchestration
//! layer can react to state changes without polling.

pub mod manager;
pub mod peer;
pub mod state;

pub use manager::{PeerEvent, PeerManager};
pub use peer::Peer;
pub use state::{PeerState, TransitionError};

// Re-export common types.
pub use seednet_common::{OverlayAddr, PeerId};
