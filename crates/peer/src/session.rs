//! Session tracking: heartbeat and expiration.
//!
//! A session is considered alive as long as traffic (any message including
//! heartbeat) arrives within [`SESSION_EXPIRY_SECS`]. A background task
//! should call [`Session::check_expiry`] periodically.

use std::time::{Duration, Instant};

use seednet_common::{HEARTBEAT_INTERVAL_SECS, SESSION_EXPIRY_SECS};

#[derive(Clone, Debug)]
pub struct Session {
    last_seen: Instant,
    heartbeat_interval: Duration,
    expiry: Duration,
}

impl Session {
    pub fn new() -> Self {
        Self {
            last_seen: Instant::now(),
            heartbeat_interval: Duration::from_secs(HEARTBEAT_INTERVAL_SECS),
            expiry: Duration::from_secs(SESSION_EXPIRY_SECS),
        }
    }

    pub fn with_config(heartbeat_interval: Duration, expiry: Duration) -> Self {
        Self {
            last_seen: Instant::now(),
            heartbeat_interval,
            expiry,
        }
    }

    pub fn record_activity(&mut self) {
        self.last_seen = Instant::now();
    }

    pub fn is_expired(&self) -> bool {
        self.last_seen.elapsed() > self.expiry
    }

    pub fn time_since_last_activity(&self) -> Duration {
        self.last_seen.elapsed()
    }

    pub fn heartbeat_interval(&self) -> Duration {
        self.heartbeat_interval
    }

    pub fn should_send_heartbeat(&self) -> bool {
        self.last_seen.elapsed() >= self.heartbeat_interval
    }
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_session_not_expired() {
        let s = Session::new();
        assert!(!s.is_expired());
    }

    #[test]
    fn session_with_tiny_expiry_expires_immediately() {
        let s = Session::with_config(Duration::from_millis(1), Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(5));
        assert!(s.is_expired());
    }

    #[test]
    fn record_activity_resets_expiry() {
        let mut s = Session::with_config(Duration::from_secs(15), Duration::from_millis(10));
        std::thread::sleep(Duration::from_millis(20));
        assert!(s.is_expired());
        s.record_activity();
        assert!(!s.is_expired());
    }

    #[test]
    fn heartbeat_interval_default() {
        let s = Session::new();
        assert_eq!(
            s.heartbeat_interval(),
            Duration::from_secs(HEARTBEAT_INTERVAL_SECS)
        );
    }
}
