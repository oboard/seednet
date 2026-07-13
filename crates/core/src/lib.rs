use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use seednet_common::{Error, InfoHash, NetworkSecret, OVERLAY_MTU, OverlayAddr, PeerId, Seed};
use seednet_config::StateDir;
use seednet_crypto::{
    DeviceKeys, InitiatorHandshake, ResponderHandshake, SecureTransport, derive_infohash,
    derive_network_secret, derive_overlay_addr,
};
use seednet_dht::DhtDiscovery;
use seednet_overlay::AllocationTable;
use seednet_peer::{Message, PeerEvent, PeerManager, PeerState};
use seednet_routing::RoutingTable;
use seednet_tun::subnet_mask;
use seednet_tun::{AsyncTunDevice, TunConfig, platform};

use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};

const DHT_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(300);
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(30);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_DATAGRAM: usize = OVERLAY_MTU + 256;

const NOISE_HANDSHAKE_INITIATOR_PREFIX: &[u8] = b"seednet-hs-a";
const NOISE_HANDSHAKE_RESPONDER_PREFIX: &[u8] = b"seednet-hs-b";

/// Combined per-peer session state: Noise transport + underlay address.
///
/// Replaces three separate `RwLock<HashMap<...>>` (`transports`, `peer_underlays`,
/// `addr_to_peer`) with a single `DashMap<PeerId, PeerSession>` plus a thin
/// reverse-index `DashMap<SocketAddr, PeerId>`. All fields that belong to one
/// peer are now co-located, eliminating multi-lock acquisition sequences.
struct PeerSession {
    transport: SecureTransport,
    underlay: SocketAddr,
}

pub struct SeedNetConfig {
    pub seed: Seed,
    pub port: u16,
    pub state_dir: StateDir,
}

impl SeedNetConfig {
    pub fn new(seed: Seed, port: u16, state_dir: StateDir) -> Self {
        Self {
            seed,
            port,
            state_dir,
        }
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
        let (tun_reader, tun_writer, _) = tun_device.into_split();
        let tun_writer = Arc::new(Mutex::new(tun_writer));

        if let Err(e) = platform::configure_interface(
            &tun_name,
            self.our_overlay.ip(),
            subnet_mask(seednet_common::OVERLAY_SUBNET_PREFIX),
        )
        .await
        {
            tracing::warn!(target: "seednet", error = %e, "platform IP config failed (may need manual ifconfig/ip)");
        }

        let udp_socket = UdpSocket::bind(format!("0.0.0.0:{port}"))
            .await
            .map_err(Error::Io)?;
        tracing::info!(target: "seednet", port, "UDP data socket bound");

        // Single DashMap keyed by PeerId; eliminates three separate RwLock<HashMap>
        // and the multi-lock acquisition patterns they required.
        let sessions: Arc<DashMap<PeerId, PeerSession>> = Arc::new(DashMap::new());
        // Reverse index: SocketAddr → PeerId, for O(1) inbound dispatch.
        let addr_index: Arc<DashMap<SocketAddr, PeerId>> = Arc::new(DashMap::new());
        let pending_handshakes: Arc<
            RwLock<HashMap<SocketAddr, tokio::sync::oneshot::Sender<Vec<u8>>>>,
        > = Arc::new(RwLock::new(HashMap::new()));

        let dht = DhtDiscovery::start_with(0, std::net::Ipv4Addr::UNSPECIFIED, &[])
            .map_err(|e| Error::Dht(format!("DHT start failed: {e}")))?;

        tracing::info!(target: "seednet", "Waiting for DHT bootstrap …");
        let bootstrapped = tokio::time::timeout(Duration::from_secs(15), dht.bootstrapped()).await;
        match bootstrapped {
            Ok(true) => tracing::info!(target: "seednet", "DHT bootstrapped"),
            Ok(false) => tracing::warn!(target: "seednet", "DHT bootstrap returned false"),
            Err(_) => {
                tracing::warn!(target: "seednet", "DHT bootstrap timed out after 15s, continuing anyway")
            }
        }

        if let Err(e) = dht.announce(&self.infohash, port).await {
            tracing::warn!(target: "seednet", error = %e, "DHT announce failed, continuing anyway");
        } else {
            tracing::info!(target: "seednet", port, "Announced on DHT");
        }

        let udp = Arc::new(udp_socket);

        let router_out = self.routing_table.clone();
        let sessions_out = sessions.clone();
        let udp_out = udp.clone();
        let our_overlay_out = self.our_overlay;
        let tun_writer_out = tun_writer.clone();

        let mut tun_reader = tun_reader;

        let outbound_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; OVERLAY_MTU + 100];
            loop {
                match tun_reader.recv(&mut buf).await {
                    Ok(n) => {
                        let packet = &buf[..n];
                        if packet.is_empty() {
                            continue;
                        }

                        let dst_ip = seednet_routing::parse_ipv4_packet(packet)
                            .map(|p| p.dst_ip)
                            .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);

                        if dst_ip == our_overlay_out.ip() {
                            let mut writer = tun_writer_out.lock().await;
                            let _ = writer.send(packet).await;
                            continue;
                        }
                        let rt = router_out.read().await;
                        if let Some(peer_id) = rt.lookup(dst_ip) {
                            let peer_id = *peer_id;
                            drop(rt);
                            if let Some(mut session) = sessions_out.get_mut(&peer_id) {
                                match session.transport.encrypt(packet) {
                                    Ok(encrypted) => {
                                        let addr = session.underlay;
                                        drop(session);
                                        let _ = udp_out.send_to(&encrypted, addr).await;
                                    }
                                    Err(e) => {
                                        tracing::debug!(target: "seednet", peer = %peer_id.short(), error = %e, "encrypt failed");
                                    }
                                }
                            } else {
                                tracing::debug!(target: "seednet", peer = %peer_id.short(), "no session for peer");
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

        let tun_writer_in = tun_writer.clone();
        let udp_in = udp.clone();
        let sessions_in = sessions.clone();
        let addr_index_in = addr_index.clone();
        let pending_in = pending_handshakes.clone();
        let network_secret_resp = self.network_secret;
        let device_keys_resp = self.device_keys.clone();
        let routing_table_in = self.routing_table.clone();
        let peer_mgr_in = self.peer_manager.clone();

        let inbound_handle = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DATAGRAM];
            // State machine for concurrent responder-side handshakes.
            // Keyed by peer SocketAddr; value is the half-completed ResponderHandshake
            // (after msg A read + msg B sent) waiting for msg C. Entries older than
            // HANDSHAKE_TIMEOUT are evicted on the next incoming packet.
            let mut pending_responders: HashMap<
                SocketAddr,
                (ResponderHandshake, std::time::Instant),
            > = HashMap::new();

            loop {
                match udp_in.recv_from(&mut buf).await {
                    Ok((n, from)) => {
                        let data = buf[..n].to_vec();

                        // Evict stale half-open responder handshakes.
                        pending_responders.retain(|_, (_, t)| t.elapsed() < HANDSHAKE_TIMEOUT);

                        // --- msg B dispatch: initiator side waiting on a oneshot ---
                        if data.starts_with(NOISE_HANDSHAKE_RESPONDER_PREFIX) {
                            let mut pending = pending_in.write().await;
                            if let Some(sender) = pending.remove(&from) {
                                drop(pending);
                                tracing::debug!(target: "seednet", from = %from, "dispatching msg B to pending initiator");
                                let _ = sender.send(data);
                                continue;
                            }
                            drop(pending);
                            // Not for us — fall through to other handlers.
                        }

                        // --- msg C: complete a pending responder handshake ---
                        if let Some((responder, _)) = pending_responders.remove(&from) {
                            // Ignore anything that looks like a new handshake msg A/B here;
                            // treat it as msg C (will fail to decrypt and be discarded).
                            match responder.finish(&data) {
                                Ok(resp_result) => {
                                    let remote_static = *resp_result.transport.remote_static_key();
                                    let peer_id = PeerId::from_bytes(remote_static);

                                    tracing::info!(
                                        target: "seednet",
                                        peer = %peer_id.short(),
                                        addr = %from,
                                        "handshake completed (responder)"
                                    );

                                    sessions_in.insert(
                                        peer_id,
                                        PeerSession {
                                            transport: resp_result.transport,
                                            underlay: from,
                                        },
                                    );
                                    addr_index_in.insert(from, peer_id);

                                    let overlay = derive_overlay_addr(&peer_id);
                                    let mut rt = routing_table_in.write().await;
                                    rt.add_route(overlay, peer_id);
                                    drop(rt);

                                    let _peer = peer_mgr_in.discover(peer_id, from).await;
                                    let _ = peer_mgr_in
                                        .transition_peer(&peer_id, PeerState::Connecting)
                                        .await;
                                    let _ = peer_mgr_in
                                        .transition_peer(&peer_id, PeerState::Handshaking)
                                        .await;
                                    let _ = peer_mgr_in
                                        .transition_peer(&peer_id, PeerState::Connected)
                                        .await;

                                    tracing::info!(
                                        target: "seednet",
                                        peer = %peer_id.short(),
                                        overlay = %overlay,
                                        addr = %from,
                                        "peer route registered (responder)"
                                    );
                                }
                                Err(e) => {
                                    tracing::debug!(target: "seednet", from = %from, error = %e, "responder finish (msg C) failed");
                                }
                            }
                            continue;
                        }

                        // --- data from an established peer ---
                        if let Some(peer_id) = addr_index_in.get(&from).map(|r| *r) {
                            if let Some(mut session) = sessions_in.get_mut(&peer_id) {
                                match session.transport.decrypt(&data) {
                                    Ok(decrypted) => {
                                        drop(session);
                                        match seednet_peer::message::deserialize_message(&decrypted)
                                        {
                                            Ok(Message::Heartbeat) => {
                                                tracing::trace!(target: "seednet", from = %from, "heartbeat received");
                                            }
                                            Ok(Message::Data(payload)) => {
                                                let mut writer = tun_writer_in.lock().await;
                                                let _ = writer.send(&payload).await;
                                            }
                                            Ok(msg) => {
                                                tracing::debug!(target: "seednet", from = %from, ?msg, "unhandled message type");
                                            }
                                            Err(_) => {
                                                // Legacy: raw IPv4 packet not wrapped in Message.
                                                let mut writer = tun_writer_in.lock().await;
                                                let _ = writer.send(&decrypted).await;
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        tracing::debug!(target: "seednet", from = %from, "decrypt failed for established peer");
                                    }
                                }
                            }
                            continue;
                        }

                        // --- msg A: start responder handshake, send msg B, park state ---
                        if data.starts_with(NOISE_HANDSHAKE_INITIATOR_PREFIX) {
                            let noise_payload = &data[NOISE_HANDSHAKE_INITIATOR_PREFIX.len()..];

                            match ResponderHandshake::new(&network_secret_resp, &device_keys_resp) {
                                Ok(mut responder) => {
                                    if responder.read_message_a(noise_payload).is_ok() {
                                        match responder.write_message_b(&[]) {
                                            Ok(msg_b) => {
                                                let mut tagged =
                                                    NOISE_HANDSHAKE_RESPONDER_PREFIX.to_vec();
                                                tagged.extend_from_slice(&msg_b);

                                                tracing::info!(target: "seednet", from = %from, "received handshake msg A, sending msg B");
                                                let _ = udp_in.send_to(&tagged, from).await;

                                                // Park the half-completed handshake; msg C will
                                                // arrive in a future iteration of this loop.
                                                pending_responders.insert(
                                                    from,
                                                    (responder, std::time::Instant::now()),
                                                );
                                            }
                                            Err(e) => {
                                                tracing::debug!(target: "seednet", from = %from, error = %e, "write_message_b failed");
                                            }
                                        }
                                    } else {
                                        tracing::debug!(target: "seednet", from = %from, "read_message_a failed (wrong network?)");
                                    }
                                }
                                Err(e) => {
                                    tracing::warn!(target: "seednet", error = %e, "responder create failed");
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
        let sessions_dht = sessions.clone();
        let addr_index_dht = addr_index.clone();
        let pending_dht = pending_handshakes.clone();
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
                        tracing::info!(target: "seednet", count = peers.len(), "DHT lookup completed");

                        for addr in peers {
                            let already_known = addr_index_dht.contains_key(&addr);

                            if already_known {
                                tracing::debug!(target: "seednet", addr = %addr, "peer already connected, skipping");
                                continue;
                            }

                            tracing::info!(target: "seednet", addr = %addr, "initiating handshake to discovered peer");

                            let mut initiator = match InitiatorHandshake::new(
                                &network_secret_dht,
                                &device_keys_dht,
                            ) {
                                Ok(i) => i,
                                Err(e) => {
                                    tracing::warn!(target: "seednet", error = %e, "initiator create failed");
                                    continue;
                                }
                            };

                            let msg_a = match initiator.write_message_a(&[]) {
                                Ok(m) => m,
                                Err(e) => {
                                    tracing::warn!(target: "seednet", error = %e, "write_message_a failed");
                                    continue;
                                }
                            };

                            let mut tagged_a = NOISE_HANDSHAKE_INITIATOR_PREFIX.to_vec();
                            tagged_a.extend_from_slice(&msg_a);

                            // Insert the oneshot sender BEFORE send_to so the inbound
                            // task can never receive msg B and look up a missing entry.
                            // On send failure the entry is removed before continuing.
                            // Also skip if a handshake is already in-flight for this addr.
                            let (tx, rx) = tokio::sync::oneshot::channel();
                            {
                                let mut pending = pending_dht.write().await;
                                if pending.contains_key(&addr) {
                                    tracing::debug!(target: "seednet", addr = %addr, "handshake already in flight, skipping");
                                    continue;
                                }
                                pending.insert(addr, tx);
                            }

                            if let Err(e) = udp_dht.send_to(&tagged_a, addr).await {
                                let mut pending = pending_dht.write().await;
                                pending.remove(&addr);
                                tracing::warn!(target: "seednet", error = %e, "send msg A failed");
                                continue;
                            }

                            tracing::debug!(target: "seednet", addr = %addr, "msg A sent, waiting for msg B");

                            match tokio::time::timeout(HANDSHAKE_TIMEOUT, rx).await {
                                Ok(Ok(msg_b_tagged)) => {
                                    if !msg_b_tagged.starts_with(NOISE_HANDSHAKE_RESPONDER_PREFIX) {
                                        tracing::warn!(target: "seednet", "msg B has wrong prefix");
                                        continue;
                                    }
                                    let msg_b =
                                        &msg_b_tagged[NOISE_HANDSHAKE_RESPONDER_PREFIX.len()..];

                                    if let Err(e) = initiator.read_message_b(msg_b) {
                                        tracing::warn!(target: "seednet", error = %e, "read_message_b failed");
                                        continue;
                                    }

                                    let init_result = match initiator.finish(&[]) {
                                        Ok(r) => r,
                                        Err(e) => {
                                            tracing::warn!(target: "seednet", error = %e, "initiator finish failed");
                                            continue;
                                        }
                                    };

                                    if let Err(e) =
                                        udp_dht.send_to(&init_result.msg_bytes, addr).await
                                    {
                                        tracing::warn!(target: "seednet", error = %e, "send msg C failed");
                                        continue;
                                    }

                                    let remote_static = *init_result.transport.remote_static_key();
                                    let peer_id = PeerId::from_bytes(remote_static);

                                    if peer_id == our_peer_id_dht {
                                        tracing::debug!(target: "seednet", "discovered ourselves, ignoring");
                                        continue;
                                    }

                                    tracing::info!(
                                        target: "seednet",
                                        peer = %peer_id.short(),
                                        addr = %addr,
                                        "handshake completed (initiator)"
                                    );

                                    sessions_dht.insert(
                                        peer_id,
                                        PeerSession {
                                            transport: init_result.transport,
                                            underlay: addr,
                                        },
                                    );
                                    addr_index_dht.insert(addr, peer_id);

                                    let overlay = derive_overlay_addr(&peer_id);
                                    let mut rt = routing_table_dht.write().await;
                                    rt.add_route(overlay, peer_id);
                                    drop(rt);

                                    let _peer = peer_mgr_dht.discover(peer_id, addr).await;
                                    let _ = peer_mgr_dht
                                        .transition_peer(&peer_id, PeerState::Connecting)
                                        .await;
                                    let _ = peer_mgr_dht
                                        .transition_peer(&peer_id, PeerState::Handshaking)
                                        .await;
                                    let _ = peer_mgr_dht
                                        .transition_peer(&peer_id, PeerState::Connected)
                                        .await;

                                    tracing::info!(
                                        target: "seednet",
                                        peer = %peer_id.short(),
                                        overlay = %overlay,
                                        addr = %addr,
                                        "peer route registered (initiator)"
                                    );
                                }
                                Ok(Err(_)) => {
                                    tracing::warn!(target: "seednet", addr = %addr, "msg B channel dropped");
                                }
                                Err(_) => {
                                    let mut pending = pending_dht.write().await;
                                    pending.remove(&addr);
                                    tracing::warn!(
                                        target: "seednet",
                                        addr = %addr,
                                        "initiator handshake timed out waiting for msg B"
                                    );
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::warn!(target: "seednet", error = %e, "DHT lookup error");
                    }
                }
            }
        });

        let announce_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(DHT_ANNOUNCE_INTERVAL);
            loop {
                interval.tick().await;
                if let Err(e) = dht.announce(&infohash, port).await {
                    tracing::debug!(target: "seednet", error = %e, "periodic DHT announce failed");
                }
            }
        });

        let udp_hb = udp.clone();
        let sessions_hb = sessions.clone();

        let heartbeat_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
            let heartbeat_payload = seednet_peer::message::serialize_message(&Message::Heartbeat);
            loop {
                interval.tick().await;
                for mut entry in sessions_hb.iter_mut() {
                    let addr = entry.underlay;
                    match entry.transport.encrypt(&heartbeat_payload) {
                        Ok(encrypted) => {
                            let _ = udp_hb.send_to(&encrypted, addr).await;
                        }
                        Err(e) => {
                            tracing::debug!(target: "seednet", peer = %entry.key().short(), error = %e, "heartbeat encrypt failed");
                        }
                    }
                }
            }
        });

        // Subscribe to peer events and write a peers.json snapshot on every
        // connect/disconnect so that `seednet list` always sees current data.
        let mut peer_events = self.peer_manager.subscribe();
        let routing_table_evt = self.routing_table.clone();
        let peer_mgr_evt = self.peer_manager.clone();
        let state_dir_evt = self.config.state_dir.clone();

        let peers_file_handle = tokio::spawn(async move {
            // Write an initial empty snapshot so list shows "no peers" rather
            // than stale data from a previous run.
            let _ = state_dir_evt.write_peers_json(r#"{"peers":[]}"#);

            loop {
                match peer_events.recv().await {
                    Ok(PeerEvent::StateChanged {
                        to: PeerState::Connected,
                        ..
                    })
                    | Ok(PeerEvent::Removed { .. }) => {
                        // Rebuild snapshot on every significant state change.
                        let connected = peer_mgr_evt.connected_peers().await;
                        let rt = routing_table_evt.read().await;

                        let mut entries = Vec::with_capacity(connected.len());
                        for id in &connected {
                            let overlay = rt
                                .lookup_peer_ip(id)
                                .map(|ip| ip.to_string())
                                .unwrap_or_default();
                            let underlay = if let Some(peer) = peer_mgr_evt.get(id) {
                                peer.underlay_addr()
                                    .await
                                    .map(|a| a.to_string())
                                    .unwrap_or_default()
                            } else {
                                String::new()
                            };
                            entries.push(format!(
                                concat!(
                                    r#"{{"id":"{id}","id_short":"{short}","#,
                                    r#""overlay":"{overlay}","underlay":"{underlay}"}}"#,
                                ),
                                id = id,
                                short = id.short(),
                                overlay = overlay,
                                underlay = underlay,
                            ));
                        }
                        drop(rt);

                        let json = format!(r#"{{"peers":[{}]}}"#, entries.join(","));
                        let _ = state_dir_evt.write_peers_json(&json);
                    }
                    Ok(_) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!(target: "seednet", skipped = n, "peer event channel lagged");
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
        });

        let ctrl_c = tokio::signal::ctrl_c();
        ctrl_c
            .await
            .map_err(|e| Error::Io(std::io::Error::other(e)))?;

        tracing::info!(target: "seednet", "Shutting down …");
        outbound_handle.abort();
        inbound_handle.abort();
        discovery_handle.abort();
        announce_handle.abort();
        heartbeat_handle.abort();
        peers_file_handle.abort();
        // Clear the peers snapshot so stale data is not visible after restart.
        let _ = self.config.state_dir.clear_peers_json();

        Ok(())
    }
}

pub fn print_status(engine: &SeedNetEngine) {
    println!("SeedNet status");
    println!("──────────────────────────────────────────────────");
    println!("  Infohash    : {}", engine.infohash());
    println!("  PeerId      : {}", engine.our_peer_id());
    println!("  Overlay IP  : {}", engine.our_overlay());
    println!("  Port        : {}", engine.port());
    println!("  State dir   : {}", engine.state_dir().path().display());
    println!("──────────────────────────────────────────────────");
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
        let config = SeedNetConfig::new(Seed::from_passphrase("test engine"), 4242, state_dir);
        let engine = SeedNetEngine::new(config).unwrap();
        assert_eq!(engine.our_overlay().ip().octets()[0], 10);
        assert_eq!(engine.our_overlay().ip().octets()[1], 88);
        assert_ne!(engine.infohash().as_bytes(), [0; 20]);
    }

    #[tokio::test]
    async fn allocation_works() {
        let state_dir = temp_state_dir();
        let config = SeedNetConfig::new(Seed::from_passphrase("alloc test"), 4242, state_dir);
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
        let config = SeedNetConfig::new(Seed::from_passphrase("status test"), 4242, state_dir);
        let engine = SeedNetEngine::new(config).unwrap();
        print_status(&engine);
    }
}
