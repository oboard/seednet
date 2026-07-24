use std::sync::Arc;

use dashmap::DashMap;
use seednet_common::{Error, InfoHash, NetworkSecret, OverlayAddr, PeerId};
use seednet_config::StateDir;
use seednet_crypto::{
    DeviceKeys, SecureTransport, derive_infohash, derive_network_secret, derive_overlay_addr,
    derive_overlay_ipv6,
};
use seednet_overlay::AllocationTable;
use seednet_peer::PeerManager;
use seednet_routing::RoutingTable;
use seednet_transport::TransportAddr;
use tokio::sync::RwLock;

use crate::config::SeedNetConfig;

/// Combined per-peer session state: Noise transport + underlay address.
pub(crate) struct PeerSession {
    pub(crate) transport: SecureTransport,
    pub(crate) underlay: TransportAddr,
}

pub struct SeedNetEngine {
    pub(crate) config: SeedNetConfig,
    pub(crate) network_secret: NetworkSecret,
    pub(crate) infohash: InfoHash,
    pub(crate) device_keys: DeviceKeys,
    pub(crate) our_peer_id: PeerId,
    pub(crate) our_overlay: OverlayAddr,
    pub(crate) our_overlay_ipv6: std::net::Ipv6Addr,
    pub(crate) peer_manager: Arc<PeerManager>,
    pub(crate) allocation_table: Arc<RwLock<AllocationTable>>,
    pub(crate) routing_table: Arc<RwLock<RoutingTable>>,
}

impl SeedNetEngine {
    pub fn new(config: SeedNetConfig) -> std::result::Result<Self, Error> {
        let network_secret = derive_network_secret(&config.seed);
        let infohash = derive_infohash(&network_secret);
        let device_keys = config.state_dir.load_or_create_identity()?;
        let our_peer_id = device_keys.peer_id();
        let our_overlay = derive_overlay_addr(&our_peer_id);
        let our_overlay_ipv6 = derive_overlay_ipv6(&our_peer_id);

        Ok(Self {
            config,
            network_secret,
            infohash,
            device_keys,
            our_peer_id,
            our_overlay,
            our_overlay_ipv6,
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

    pub fn our_overlay_ipv6(&self) -> std::net::Ipv6Addr {
        self.our_overlay_ipv6
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
}

// Type aliases used across multiple modules.
pub(crate) type Sessions = Arc<DashMap<PeerId, PeerSession>>;
pub(crate) type AddrIndex = Arc<DashMap<TransportAddr, PeerId>>;
pub(crate) type RelayCandidates = Arc<DashMap<PeerId, std::net::SocketAddr>>;
/// Maps dst_peer_id → (next_hop_relay_peer_id, hop_count).
/// hop_count = 1 means single relay, 2 = two hops, etc.
pub(crate) type RelayPaths = Arc<DashMap<PeerId, (PeerId, u8)>>;
