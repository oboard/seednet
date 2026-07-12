//! Peer state machine: [`PeerState`] and [`TransitionError`].
//!
//! The lifecycle follows this diagram:
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
//! Every transition is validated; invalid attempts return [`TransitionError`].

use std::fmt;
use std::time::Instant;

use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PeerState {
    Disconnected,
    Discovering,
    Connecting,
    Handshaking,
    Connected,
    Dead,
}

impl PeerState {
    pub fn can_transition_to(self, next: PeerState) -> bool {
        matches!(
            (self, next),
            (PeerState::Disconnected, PeerState::Discovering)
                | (PeerState::Discovering, PeerState::Connecting)
                | (PeerState::Discovering, PeerState::Disconnected)
                | (PeerState::Connecting, PeerState::Handshaking)
                | (PeerState::Connecting, PeerState::Disconnected)
                | (PeerState::Handshaking, PeerState::Connected)
                | (PeerState::Handshaking, PeerState::Disconnected)
                | (PeerState::Connected, PeerState::Disconnected)
                | (PeerState::Connected, PeerState::Dead)
                | (PeerState::Dead, PeerState::Disconnected)
        )
    }

    pub fn transition(self, next: PeerState) -> std::result::Result<PeerState, TransitionError> {
        if self.can_transition_to(next) {
            Ok(next)
        } else {
            Err(TransitionError::InvalidTransition {
                from: self,
                to: next,
            })
        }
    }
}

impl fmt::Display for PeerState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            PeerState::Disconnected => "disconnected",
            PeerState::Discovering => "discovering",
            PeerState::Connecting => "connecting",
            PeerState::Handshaking => "handshaking",
            PeerState::Connected => "connected",
            PeerState::Dead => "dead",
        };
        f.write_str(s)
    }
}

#[derive(Debug, Error)]
pub enum TransitionError {
    #[error("invalid state transition from {from} to {to}")]
    InvalidTransition { from: PeerState, to: PeerState },
}

#[derive(Clone, Debug)]
pub struct StateRecord {
    pub state: PeerState,
    pub entered_at: Instant,
}

impl StateRecord {
    pub fn new(state: PeerState) -> Self {
        Self {
            state,
            entered_at: Instant::now(),
        }
    }

    pub fn transition(&mut self, next: PeerState) -> std::result::Result<(), TransitionError> {
        self.state = self.state.transition(next)?;
        self.entered_at = Instant::now();
        Ok(())
    }

    pub fn elapsed(&self) -> std::time::Duration {
        self.entered_at.elapsed()
    }
}

impl From<PeerState> for StateRecord {
    fn from(state: PeerState) -> Self {
        Self::new(state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_lifecycle() {
        let states = [
            PeerState::Disconnected,
            PeerState::Discovering,
            PeerState::Connecting,
            PeerState::Handshaking,
            PeerState::Connected,
        ];
        for pair in states.windows(2) {
            assert!(pair[0].can_transition_to(pair[1]));
            assert!(pair[0].transition(pair[1]).is_ok());
        }
    }

    #[test]
    fn failure_returns_to_disconnected() {
        let failing = [
            PeerState::Discovering,
            PeerState::Connecting,
            PeerState::Handshaking,
        ];
        for s in failing {
            assert!(s.can_transition_to(PeerState::Disconnected));
        }
    }

    #[test]
    fn connected_can_go_dead() {
        assert!(PeerState::Connected.can_transition_to(PeerState::Dead));
    }

    #[test]
    fn dead_can_reconnect() {
        assert!(PeerState::Dead.can_transition_to(PeerState::Disconnected));
    }

    #[test]
    fn disconnected_cannot_go_connected() {
        assert!(!PeerState::Disconnected.can_transition_to(PeerState::Connected));
        assert!(matches!(
            PeerState::Disconnected.transition(PeerState::Connected),
            Err(TransitionError::InvalidTransition {
                from: PeerState::Disconnected,
                to: PeerState::Connected
            })
        ));
    }

    #[test]
    fn no_self_transition() {
        for s in [
            PeerState::Disconnected,
            PeerState::Discovering,
            PeerState::Connecting,
            PeerState::Handshaking,
            PeerState::Connected,
            PeerState::Dead,
        ] {
            assert!(
                !s.can_transition_to(s),
                "{s:?} should not transition to itself"
            );
        }
    }

    #[test]
    fn state_record_transition_updates_time() {
        let mut rec = StateRecord::new(PeerState::Disconnected);
        let before = rec.entered_at;
        rec.transition(PeerState::Discovering).unwrap();
        assert_eq!(rec.state, PeerState::Discovering);
        assert!(rec.entered_at >= before);
    }

    #[test]
    fn state_record_rejects_invalid() {
        let mut rec = StateRecord::new(PeerState::Disconnected);
        assert!(rec.transition(PeerState::Connected).is_err());
    }

    #[test]
    fn display_roundtrip() {
        assert_eq!(PeerState::Connected.to_string(), "connected");
        assert_eq!(PeerState::Dead.to_string(), "dead");
    }
}
