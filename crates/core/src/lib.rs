//! SeedNet orchestration engine.
//!
//! [`SeedNet`] ties together the DHT discovery, peer state machine,
//! Noise handshake, message layer, overlay IP allocation, and routing
//! into a single `run()` entry point that brings the entire overlay up
//! and keeps it running until signalled to stop.

use std::sync::Arc;
use std::time::Duration;

use seednet_common::{Error, InfoHash, NetworkSecret, OverlayAddr, PeerId, Seed, DEFAULT_PORT};
use seednet_config::StateDir;
use seednet_crypto::{
    derive_infohash, derive_network_secret, derive_overlay_addr, DeviceKeys,
};
use seednet_dht::DhtDiscovery;
use seednet_overlay::AllocationTable;
use seednet_peer::PeerManager;
use seednet_routing::RoutingTable;

use tokio::sync::RwLock;

const DHT_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(300);
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(30);

pub struct SeedNetConfig {
    pub seed: Seed,
    pub port: u16,
    pub state_dir: StateDir,
}

impl SeedNetConfig {
    pub fn new(seed: Seed, port: u16, state_dir: StateDir) -> Self {
        Self { seed, port, state_dir }
    }
}

pub struct SeedNetEngine {
    config: SeedNetConfig,
    network_secret: NetworkSecret,
    infohash: InfoHash,
    device_keys: DeviceKeys,
    our_peer_id: PeerId,
    our_overlay: OverlayAddr,
    peer_manager: Arc<PeerManager>,
    allocation_table: Arc<RwLock<AllocationTable>>,
    routing_table: Arc<RwLock<RoutingTable>>,
}

impl SeedNetEngine {
    pub fn new(config: SeedNetConfig) -> std::result::Result<Self, Error> {
        let network_secret = derive_network_secret(&config.seed);
        let infohash = derive_infohash(&network_secret);
        let device_keys = config.state_dir.load_or_create_identity()?;
        let our_peer_id = device_keys.peer_id();
        let our_overlay = derive_overlay_addr(&our_peer_id);

        Ok(Self {
            config,
            network_secret,
            infohash,
            device_keys,
            our_peer_id,
            our_overlay,
            peer_manager: Arc::new(PeerManager::new()),
            allocation_table: Arc::new(RwLock::new(AllocationTable::new())),
            routing_table: Arc::new(RwLock::new(RoutingTable::new())),
        })
    }

    pub fn network_secret(&self) -> &NetworkSecret {
        &self.network_secret
    }

    pub fn infohash(&self) -> &InfoHash {
        &self.infohash
    }

    pub fn our_peer_id(&self) -> PeerId {
        self.our_peer_id
    }

    pub fn our_overlay(&self) -> OverlayAddr {
        self.our_overlay
    }

    pub fn device_keys(&self) -> &DeviceKeys {
        &self.device_keys
    }

    pub fn peer_manager(&self) -> &Arc<PeerManager> {
        &self.peer_manager
    }

    pub fn allocation_table(&self) -> &Arc<RwLock<AllocationTable>> {
        &self.allocation_table
    }

    pub fn routing_table(&self) -> &Arc<RwLock<RoutingTable>> {
        &self.routing_table
    }

    pub fn port(&self) -> u16 {
        self.config.port
    }

    pub fn state_dir(&self) -> &StateDir {
        &self.config.state_dir
    }

    pub async fn run(&self) -> std::result::Result<(), Error> {
        let port = self.config.port;

        tracing::info!(
            target: "seednet",
            infohash = %self.infohash,
            overlay = %self.our_overlay,
            peer_id = %self.our_peer_id.short(),
            port,
            "SeedNet engine starting"
        );

        let mut alloc_table = self.allocation_table.write().await;
        alloc_table.allocate(self.our_peer_id);
        drop(alloc_table);

        let mut routing = self.routing_table.write().await;
        routing.add_route(self.our_overlay, self.our_peer_id);
        drop(routing);

        let dht = DhtDiscovery::start(port)
            .map_err(|e| Error::Dht(format!("DHT start failed: {e}")))?;

        tracing::info!(target: "seednet", "Waiting for DHT bootstrap …");
        let bootstrapped = dht.bootstrapped().await;
        if bootstrapped {
            tracing::info!(target: "seednet", "DHT bootstrapped");
        } else {
            tracing::warn!(target: "seednet", "DHT bootstrap returned false");
        }

        dht.announce(&self.infohash, port).await
            .map_err(|e| Error::Dht(format!("announce failed: {e}")))?;
        tracing::info!(target: "seednet", "Announced on DHT");

        let peer_mgr = self.peer_manager.clone();
        let infohash = self.infohash;
        let _our_peer_id = self.our_peer_id;

        let dht_clone = dht.clone();
        let discovery_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(DISCOVERY_INTERVAL);
            loop {
                interval.tick().await;
                match dht_clone.lookup(&infohash).await {
                    Ok(peers) => {
                        for addr in peers {
                            let _peer = peer_mgr.discover(
                                PeerId::from_bytes([0; 32]),
                                addr,
                            ).await;
                            tracing::debug!(target: "seednet", addr = %addr, "discovered peer via DHT");
                        }
                    }
                    Err(e) => {
                        tracing::debug!(target: "seednet", error = %e, "DHT lookup error");
                    }
                }
                let _ = dht_clone.announce(&infohash, DEFAULT_PORT).await;
            }
        });

        let announce_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(DHT_ANNOUNCE_INTERVAL);
            loop {
                interval.tick().await;
                let _ = dht.announce(&infohash, DEFAULT_PORT).await;
            }
        });

        let ctrl_c = tokio::signal::ctrl_c();
        ctrl_c.await.map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;

        tracing::info!(target: "seednet", "Shutting down …");
        discovery_handle.abort();
        announce_handle.abort();

        Ok(())
    }
}

pub fn print_status(engine: &SeedNetEngine) {
    println!("SeedNet status");
    println!("────────────────────────────────────────────────────────");
    println!("  Infohash    : {}", engine.infohash());
    println!("  PeerId      : {}", engine.our_peer_id());
    println!("  Overlay IP  : {}", engine.our_overlay());
    println!("  Port        : {}", engine.port());
    println!("  State dir   : {}", engine.state_dir().path().display());
    println!("────────────────────────────────────────────────────────");
}

#[cfg(test)]
mod tests {
    use super::*;
    use seednet_common::Seed;

    fn temp_state_dir() -> StateDir {
        let dir = std::env::temp_dir().join(format!(
            "seednet-core-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        StateDir::new(&dir).expect("create temp state dir")
    }

    #[test]
    fn engine_new_derives_identity() {
        let state_dir = temp_state_dir();
        let config = SeedNetConfig::new(
            Seed::from_passphrase("test engine"),
            4242,
            state_dir,
        );
        let engine = SeedNetEngine::new(config).unwrap();
        assert_eq!(engine.our_overlay().ip().octets()[0], 10);
        assert_eq!(engine.our_overlay().ip().octets()[1], 88);
        assert_ne!(engine.infohash().as_bytes(), [0; 20]);
    }

    #[tokio::test]
    async fn allocation_works() {
        let state_dir = temp_state_dir();
        let config = SeedNetConfig::new(
            Seed::from_passphrase("alloc test"),
            4242,
            state_dir,
        );
        let engine = SeedNetEngine::new(config).unwrap();
        let mut table = engine.allocation_table().write().await;
        let addr = table.allocate(engine.our_peer_id());
        assert_eq!(addr, engine.our_overlay());
        let alloc = table.lookup_by_peer(&engine.our_peer_id());
        assert!(alloc.is_some());
    }

    #[test]
    fn print_status_does_not_panic() {
        let state_dir = temp_state_dir();
        let config = SeedNetConfig::new(
            Seed::from_passphrase("status test"),
            4242,
            state_dir,
        );
        let engine = SeedNetEngine::new(config).unwrap();
        print_status(&engine);
    }
}
