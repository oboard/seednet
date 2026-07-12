//! Peer abstraction, state machine, and message layer for SeedNet.
//!
//! Every remote SeedNet device is represented as a [`Peer`] that transitions
//! through a well-defined lifecycle:
//!
//! ```text
//! Disconnected → Discovering → Connecting → Handshaking → Connected
//!      ↑              │              │              │             │
//!      │              └──────────────┴──────────────┘             │
//!      │                        (failure)                         │
//!      └────────────────────────────────────────────────────────┘
//!                         Dead ← (timeout / error)
//! ```
//!
//! The [`PeerManager`] holds all known peers in a [`DashMap`] for lock-free
//! concurrent access and emits [`PeerEvent`]s on a channel so the orchestration
//! layer can react to state changes without polling.
//!
//! The [`MessageChannel`] provides encrypted, framed messaging over UDP with
//! automatic Noise XX handshake, heartbeat keepalives, and session expiration.

pub mod channel;
pub mod frame;
pub mod manager;
pub mod message;
pub mod peer;
pub mod session;
pub mod state;

pub use channel::MessageChannel;
pub use manager::{PeerEvent, PeerManager};
pub use message::{Message, InboundMessage, OutboundMessage};
pub use peer::Peer;
pub use session::Session;
pub use state::{PeerState, TransitionError};

pub use seednet_common::{OverlayAddr, PeerId};
