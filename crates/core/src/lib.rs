use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use seednet_common::{Error, InfoHash, NetworkSecret, OverlayAddr, PeerId, Seed, DEFAULT_PORT, OVERLAY_MTU};
use seednet_config::StateDir;
use seednet_crypto::{
    derive_infohash, derive_network_secret, derive_overlay_addr, DeviceKeys,
    InitiatorHandshake, ResponderHandshake,
};
use seednet_dht::DhtDiscovery;
use seednet_overlay::AllocationTable;
use seednet_peer::{PeerManager, PeerState};
use seednet_routing::RoutingTable;
use seednet_tun::{AsyncTunDevice, TunConfig, platform};
use seednet_tun::subnet_mask;

use tokio::net::UdpSocket;
use tokio::sync::RwLock;

const DHT_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(300);
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(30);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const MAX_DATAGRAM: usize = OVERLAY_MTU + 256;

#[cfg(target_os = "macos")]
const TUN_HEADER_LEN: usize = 4;
#[cfg(not(target_os = "macos"))]
const TUN_HEADER_LEN: usize = 0;

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

        let tun_config = TunConfig::new(self.our_overlay);
        let tun_device = AsyncTunDevice::create(&tun_config)?;
        let tun_name = tun_device.name().to_string();

        if let Err(e) = platform::configure_interface(
            &tun_name,
            self.our_overlay.ip(),
            subnet_mask(seednet_common::OVERLAY_SUBNET_PREFIX),
        ).await {
            tracing::warn!(target: "seednet", error = %e, "platform IP config failed (may need manual ifconfig/ip)");
        }

        let udp_socket = UdpSocket::bind(format!("0.0.0.0:{port}")).await
            .map_err(Error::Io)?;
        tracing::info!(target: "seednet", port, "UDP socket bound");

        let _router = Arc::new(RwLock::new(RoutingTable::new()));
        let transports: Arc<RwLock<HashMap<PeerId, seednet_crypto::SecureTransport>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let peer_underlays: Arc<RwLock<HashMap<PeerId, SocketAddr>>> =
            Arc::new(RwLock::new(HashMap::new()));
        let addr_to_peer: Arc<RwLock<HashMap<SocketAddr, PeerId>>> =
            Arc::new(RwLock::new(HashMap::new()));

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

        let tun_dev = Arc::new(tokio::sync::Mutex::new(tun_device));
        let udp = Arc::new(udp_socket);
        let our_peer_id_out = self.our_peer_id;

        let tun_out = tun_dev.clone();
        let router_out = self.routing_table.clone();
        let transports_out = transports.clone();
        let peer_underlays_out = peer_underlays.clone();
        let udp_out = udp.clone();

        let outbound_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; OVERLAY_MTU + TUN_HEADER_LEN + 100];
            loop {
                let tun = tun_out.lock().await;
                match tun.recv(&mut buf).await {
                    Ok(n) => {
                        let start = if TUN_HEADER_LEN > 0 && n > TUN_HEADER_LEN {
                            TUN_HEADER_LEN
                        } else {
                            0
                        };
                        let packet = &buf[start..n];
                        if packet.is_empty() {
                            continue;
                        }

                        let dst_ip = seednet_routing::parse_ipv4_packet(packet)
                            .map(|p| p.dst_ip)
                            .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);

                        let rt = router_out.read().await;
                        if let Some(peer_id) = rt.lookup(dst_ip) {
                            let peer_id = *peer_id;
                            if peer_id == our_peer_id_out {
                                continue;
                            }
                            drop(rt);
                            let mut ts = transports_out.write().await;
                            if let Some(transport) = ts.get_mut(&peer_id)
                                && let Ok(encrypted) = transport.encrypt(packet)
                            {
                                drop(ts);
                                let underlays = peer_underlays_out.read().await;
                                if let Some(addr) = underlays.get(&peer_id) {
                                    let _ = udp_out.send_to(&encrypted, addr).await;
                                } else {
                                    tracing::debug!(target: "seednet", peer = %peer_id.short(), "no underlay addr for peer");
                                }
                            }
                        } else {
                            tracing::trace!(target: "seednet", dst = %dst_ip, "no route for TUN packet");
                        }
                    }
                    Err(e) => {
                        tracing::debug!(target: "seednet", error = %e, "TUN recv error");
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                }
            }
        });

        let tun_in = tun_dev.clone();
        let udp_in = udp.clone();
        let transports_in = transports.clone();
        let addr_to_peer_in = addr_to_peer.clone();
        let peer_underlays_in = peer_underlays.clone();
        let network_secret_resp = self.network_secret;
        let device_keys_resp = self.device_keys.clone();
        let routing_table_in = self.routing_table.clone();
        let peer_mgr_in = self.peer_manager.clone();

        let inbound_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            loop {
                match udp_in.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        let data = &buf[..n];

                        let a2p = addr_to_peer_in.read().await;
                        if let Some(peer_id) = a2p.get(&from) {
                            let peer_id = *peer_id;
                            drop(a2p);

                            let mut ts = transports_in.write().await;
                            if let Some(transport) = ts.get_mut(&peer_id)
                                && let Ok(decrypted) = transport.decrypt(data)
                            {
                                drop(ts);
                                let tun = tun_in.lock().await;
                                if TUN_HEADER_LEN > 0 {
                                    let mut frame = vec![0u8; TUN_HEADER_LEN + decrypted.len()];
                                    frame[0] = 0x00;
                                    frame[1] = 0x00;
                                    frame[2] = 0x00;
                                    frame[3] = 0x02;
                                    frame[TUN_HEADER_LEN..].copy_from_slice(&decrypted);
                                    let _ = tun.send(&frame).await;
                                } else {
                                    let _ = tun.send(&decrypted).await;
                                }
                            }
                            continue;
                        }
                        drop(a2p);

                        if let Ok(mut responder) = ResponderHandshake::new(&network_secret_resp, &device_keys_resp)
                            && responder.read_message_a(data).is_ok()
                            && let Ok(msg_b) = responder.write_message_b(&[])
                        {
                            let _ = udp_in.send_to(&msg_b, from).await;

                            let mut cbuf = vec![0u8; MAX_DATAGRAM];
                            match udp_in.recv_from(&mut cbuf).await {
                                Ok((cn, cfrom)) if cfrom == from => {
                                    if let Ok(resp_result) = responder.finish(&cbuf[..cn]) {
                                        let remote_static = *resp_result.transport.remote_static_key();
                                        let peer_id = PeerId::from_bytes(remote_static);

                                        tracing::info!(
                                            target: "seednet",
                                            peer = %peer_id.short(),
                                            addr = %from,
                                            "handshake completed (responder)"
                                        );

                                        let mut ts = transports_in.write().await;
                                        ts.insert(peer_id, resp_result.transport);
                                        drop(ts);

                                        let mut a2p = addr_to_peer_in.write().await;
                                        a2p.insert(from, peer_id);
                                        drop(a2p);

                                        let mut pu_w = peer_underlays_in.write().await;
                                        pu_w.insert(peer_id, from);
                                        drop(pu_w);

                                        let overlay = derive_overlay_addr(&peer_id);
                                        let mut rt = routing_table_in.write().await;
                                        rt.add_route(overlay, peer_id);
                                        drop(rt);

                                        let _peer = peer_mgr_in.discover(peer_id, from).await;
                                        let _ = peer_mgr_in.transition_peer(&peer_id, PeerState::Connecting).await;
                                        let _ = peer_mgr_in.transition_peer(&peer_id, PeerState::Handshaking).await;
                                        let _ = peer_mgr_in.transition_peer(&peer_id, PeerState::Connected).await;

                                        tracing::info!(
                                            target: "seednet",
                                            peer = %peer_id.short(),
                                            overlay = %overlay,
                                            "peer route registered"
                                        );
                                    }
                                }
                                _ => {
                                    tracing::debug!(target: "seednet", "handshake msg C not received");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!(target: "seednet", error = %e, "UDP recv error");
                    }
                }
            }
        });

        let peer_mgr_dht = self.peer_manager.clone();
        let network_secret_dht = self.network_secret;
        let device_keys_dht = self.device_keys.clone();
        let udp_dht = udp.clone();
        let transports_dht = transports.clone();
        let addr_to_peer_dht = addr_to_peer.clone();
        let peer_underlays_dht = peer_underlays.clone();
        let routing_table_dht = self.routing_table.clone();
        let our_peer_id_dht = self.our_peer_id;
        let infohash = self.infohash;

        let dht_clone = dht.clone();
        let discovery_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(DISCOVERY_INTERVAL);
            loop {
                interval.tick().await;
                match dht_clone.lookup(&infohash).await {
                    Ok(peers) => {
                        for addr in peers {
                            let a2p = addr_to_peer_dht.read().await;
                            let already_known = a2p.contains_key(&addr);
                            drop(a2p);

                            if already_known {
                                continue;
                            }

                            tracing::info!(target: "seednet", addr = %addr, "initiating handshake to discovered peer");

                            let mut initiator = match InitiatorHandshake::new(&network_secret_dht, &device_keys_dht) {
                                Ok(i) => i,
                                Err(_) => continue,
                            };

                            let msg_a = match initiator.write_message_a(&[]) {
                                Ok(m) => m,
                                Err(_) => continue,
                            };

                            if udp_dht.send_to(&msg_a, addr).await.is_err() {
                                continue;
                            }

                            let mut buf = vec![0u8; MAX_DATAGRAM];
                            let (n, from) = match tokio::time::timeout(
                                Duration::from_secs(5),
                                udp_dht.recv_from(&mut buf),
                            ).await {
                                Ok(Ok(r)) => r,
                                _ => continue,
                            };

                            if from != addr {
                                continue;
                            }

                            if initiator.read_message_b(&buf[..n]).is_err() {
                                continue;
                            }

                            let init_result = match initiator.finish(&[]) {
                                Ok(r) => r,
                                Err(_) => continue,
                            };

                            if udp_dht.send_to(&init_result.msg_bytes, addr).await.is_err() {
                                continue;
                            }

                            let remote_static = *init_result.transport.remote_static_key();
                            let peer_id = PeerId::from_bytes(remote_static);

                            if peer_id == our_peer_id_dht {
                                continue;
                            }

                            tracing::info!(
                                target: "seednet",
                                peer = %peer_id.short(),
                                addr = %addr,
                                "handshake completed (initiator)"
                            );

                            let mut ts = transports_dht.write().await;
                            ts.insert(peer_id, init_result.transport);
                            drop(ts);

                            let mut a2p = addr_to_peer_dht.write().await;
                            a2p.insert(addr, peer_id);
                            drop(a2p);

                            let mut pu = peer_underlays_dht.write().await;
                            pu.insert(peer_id, addr);
                            drop(pu);

                            let overlay = derive_overlay_addr(&peer_id);
                            let mut rt = routing_table_dht.write().await;
                            rt.add_route(overlay, peer_id);
                            drop(rt);

                            let _peer = peer_mgr_dht.discover(peer_id, addr).await;
                            let _ = peer_mgr_dht.transition_peer(&peer_id, PeerState::Connecting).await;
                            let _ = peer_mgr_dht.transition_peer(&peer_id, PeerState::Handshaking).await;
                            let _ = peer_mgr_dht.transition_peer(&peer_id, PeerState::Connected).await;
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

        let udp_hb = udp.clone();
        let transports_hb = transports.clone();
        let peer_underlays_hb = peer_underlays.clone();

        let heartbeat_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
            loop {
                interval.tick().await;
                let ts = transports_hb.read().await;
                let pu = peer_underlays_hb.read().await;
                for (peer_id, _transport) in ts.iter() {
                    if let Some(addr) = pu.get(peer_id) {
                        let _ = udp_hb.send_to(b"seednet-heartbeat", addr).await;
                    }
                }
            }
        });

        let ctrl_c = tokio::signal::ctrl_c();
        ctrl_c.await.map_err(|e| Error::Io(std::io::Error::other(e)))?;

        tracing::info!(target: "seednet", "Shutting down …");
        outbound_handle.abort();
        inbound_handle.abort();
        discovery_handle.abort();
        announce_handle.abort();
        heartbeat_handle.abort();

        Ok(())
    }
}

pub fn print_status(engine: &SeedNetEngine) {
    println!("SeedNet status");
    println!("──────────────────────────────────────────────────────");
    println!("  Infohash    : {}", engine.infohash());
    println!("  PeerId      : {}", engine.our_peer_id());
    println!("  Overlay IP  : {}", engine.our_overlay());
    println!("  Port        : {}", engine.port());
    println!("  State dir   : {}", engine.state_dir().path().display());
    println!("──────────────────────────────────────────────────────");
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
