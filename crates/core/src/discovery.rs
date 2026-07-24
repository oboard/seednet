use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use seednet_common::{InfoHash, OverlayAddr, PeerId};
use seednet_dht::DhtDiscovery;
use seednet_peer::PeerManager;
use seednet_routing::RoutingTable;
use seednet_transport::{MultiTransport, TransportAddr};
use tokio::sync::RwLock;

use crate::engine::{AddrIndex, RelayCandidates, RelayPaths, Sessions};
use crate::handshake::{InitiatorArgs, do_initiator_handshake};
use seednet_crypto::{DeviceKeys, NetworkSecret};

/// How often to re-scan DHT for new peers and retry pending connections.
pub(crate) const DISCOVERY_INTERVAL: Duration = Duration::from_secs(10);

pub(crate) struct DiscoveryArgs {
    pub dht: DhtDiscovery,
    pub infohash: InfoHash,
    /// Direct peer addresses + those discovered from trackers (appended async).
    pub tracker_addrs: Arc<tokio::sync::Mutex<Vec<SocketAddr>>>,
    pub transport: Arc<MultiTransport>,
    pub sessions: Sessions,
    pub addr_index: AddrIndex,
    pub stun_addr: Arc<RwLock<Option<SocketAddr>>>,
    pub pending: Arc<RwLock<HashMap<SocketAddr, tokio::sync::oneshot::Sender<Vec<u8>>>>>,
    pub peer_mgr: Arc<PeerManager>,
    pub routing_table: Arc<RwLock<RoutingTable>>,
    pub relay_cands: RelayCandidates,
    pub relay_paths: RelayPaths,
    pub network_secret: NetworkSecret,
    pub device_keys: DeviceKeys,
    pub si_overlay: OverlayAddr,
    pub si_overlay_ipv6: std::net::Ipv6Addr,
    pub si_hostname: String,
    pub our_id: PeerId,
    pub can_relay_flag: Arc<std::sync::atomic::AtomicBool>,
}

pub(crate) async fn run_discovery_loop(args: DiscoveryArgs) {
    let mut interval = tokio::time::interval(DISCOVERY_INTERVAL);
    let mut first_tick = true;
    loop {
        if first_tick {
            first_tick = false;
        } else {
            interval.tick().await;
        }

        let tracker_snapshot = args.tracker_addrs.lock().await.clone();
        let dht_peers = args.dht.lookup(&args.infohash).await.unwrap_or_default();
        tracing::info!(target: "seednet", dht = dht_peers.len(), trackers = tracker_snapshot.len(), "discovery cycle");

        let mut peers: Vec<SocketAddr> = tracker_snapshot;
        for p in dht_peers {
            if !peers.contains(&p) {
                peers.push(p);
            }
        }
        let peers_len = peers.len();
        if peers_len > 0 {
            tracing::info!(target: "seednet", count = peers_len, "peers to try this cycle");
        }

        for addr in peers {
            if let Some(our_pub) = *args.stun_addr.read().await
                && addr == our_pub
            {
                continue;
            }
            let already_connected = args
                .addr_index
                .get(&TransportAddr::Udp(addr))
                .map(|peer_id| args.sessions.contains_key(&*peer_id))
                .unwrap_or(false);
            if already_connected {
                continue;
            }
            if args.pending.read().await.contains_key(&addr) {
                continue;
            }
            if let Some(peer_id) = args.addr_index.get(&TransportAddr::Udp(addr)).map(|r| *r)
                && !args.sessions.contains_key(&peer_id)
            {
                args.addr_index.remove(&TransportAddr::Udp(addr));
            }

            let ia = InitiatorArgs {
                addr,
                network_secret: args.network_secret,
                device_keys: args.device_keys.clone(),
                udp: args.transport.clone(),
                sessions: args.sessions.clone(),
                addr_index: args.addr_index.clone(),
                pending: args.pending.clone(),
                stun_addr: args.stun_addr.clone(),
                peer_mgr: args.peer_mgr.clone(),
                routing_table: args.routing_table.clone(),
                relay_cands: args.relay_cands.clone(),
                relay_paths: args.relay_paths.clone(),
                si_overlay: args.si_overlay,
                si_overlay_ipv6: args.si_overlay_ipv6,
                si_hostname: args.si_hostname.clone(),
                our_id: args.our_id,
                can_relay_flag: args.can_relay_flag.clone(),
            };
            tokio::spawn(do_initiator_handshake(ia));
        }
    }
}
