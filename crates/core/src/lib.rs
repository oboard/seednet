use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use seednet_common::{
    Error, InfoHash, NetworkSecret, OVERLAY_MTU, OverlayAddr, PeerId, STUN_SERVERS, Seed,
};
use seednet_config::StateDir;
use seednet_crypto::{
    DeviceKeys, InitiatorHandshake, ResponderHandshake, SecureTransport, derive_infohash,
    derive_network_secret, derive_overlay_addr, derive_overlay_ipv6,
};
use seednet_dht::DhtDiscovery;
use seednet_nat::is_publicly_routable;
use seednet_overlay::AllocationTable;
use seednet_peer::{Message, PeerEvent, PeerManager, PeerState};
use seednet_routing::RoutingTable;
use seednet_tun::subnet_mask;
use seednet_tun::{AsyncTunDevice, TunConfig, platform};

use seednet_transport::{MultiTransport, Transport, TransportAddr, UdpTransport};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};

const DHT_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(300);
/// How often to re-scan DHT for new peers and retry pending connections.
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(10);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
/// How long to wait for a direct handshake before falling back to relay.
/// Kept short so relay is available quickly; direct connection is retried
/// in the background and upgrades the path when it succeeds.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
const NOISE_HANDSHAKE_INITIATOR_PREFIX: &[u8] = b"seednet-hs-a";
const NOISE_HANDSHAKE_RESPONDER_PREFIX: &[u8] = b"seednet-hs-b";

/// Default BitTorrent tracker list (ngosang/trackerslist, trackers_all).
/// Used for fast peer discovery without waiting for DHT bootstrap.
const DEFAULT_TRACKERS: &[&str] = &[
    "udp://tracker.publictracker.xyz:6969/announce",
    "udp://tracker.opentrackr.org:1337/announce",
    "http://tracker.opentrackr.org:1337/announce",
    "udp://open.demonii.com:1337/announce",
    "udp://open.tracker.cl:1337/announce",
    "http://open.tracker.cl:1337/announce",
    "udp://open.stealth.si:80/announce",
    "udp://tracker2.dler.org:80/announce",
    "udp://tracker.wildkat.net:6969/announce",
    "udp://tracker.tryhackx.org:6969/announce",
    "udp://tracker.torrent.eu.org:451/announce",
    "udp://tracker.qu.ax:6969/announce",
    "udp://tracker.opentorrent.top:6969/announce",
    "udp://tracker.bittor.pw:1337/announce",
    "udp://tracker.auctor.tv:6969/announce",
    "udp://tracker-udp.gbitt.info:80/announce",
    "udp://tr4ck3r.duckdns.org:6969/announce",
    "udp://torrentclub.online:54123/announce",
    "udp://t.overflow.biz:6969/announce",
    "udp://seedpeer.net:6969/announce",
    "udp://retracker01-msk-virt.corbina.net:80/announce",
    "udp://ns575949.ip-51-222-82.net:6969/announce",
    "udp://leet-tracker.moe:1337/announce",
    "udp://ipv4announce.sktorrent.eu:6969/announce",
    "udp://exodus.desync.com:6969/announce",
    "udp://evan.im:6969/announce",
    "udp://bittorrent-tracker.e-n-c-r-y-p-t.net:1337/announce",
    "udp://admin.52ywp.com:6969/announce",
    "https://tracker.zhuqiy.com:443/announce",
    "https://tracker.yemekyedim.com:443/announce",
    "https://tracker.pmman.tech:443/announce",
    "https://tracker.nekomi.cn:443/announce",
    "https://tracker.leechshield.link:443/announce",
    "https://tracker.gcrenwp.top:443/announce",
    "https://tracker.bt4g.com:443/announce",
    "https://tracker.7471.top:443/announce",
    "https://tr.zukizuki.org:443/announce",
    "https://tr.nyacat.pw:443/announce",
    "https://open.ftorrent.com:443/announce",
    "http://www.torrentsnipe.info:2701/announce",
    "http://tracker810.xyz:11450/announce",
    "http://tracker.zhuqiy.com:80/announce",
    "http://tracker.waaa.moe:6969/announce",
    "http://tracker.vanitycore.co:6969/announce",
    "http://tracker.renfei.net:8080/announce",
    "http://tracker.qu.ax:6969/announce",
    "http://tracker.privateseedbox.xyz:2710/announce",
    "http://tracker.mywaifu.best:6969/announce",
    "http://tracker.lintk.me:2710/announce",
    "http://tracker.ipv6tracker.org:80/announce",
    "http://tracker.dhitechnical.com:6969/announce",
    "http://tracker.bt4g.com:2095/announce",
    "http://tr.nyacat.pw:80/announce",
    "http://tr.kxmp.cf:80/announce",
    "http://torrent.hificode.in:6969/announce",
    "http://t.overflow.biz:6969/announce",
    "http://shubt.net:2710/announce",
    "http://seeders-paradise.org:80/announce",
    "http://open.trackerlist.xyz:80/announce",
    "http://jvavav.com:80/announce",
    "http://home.yxgz.club:6969/announce",
    "http://bt1.xxxxbt.cc:6969/announce",
    "http://bittorrent-tracker.e-n-c-r-y-p-t.net:1337/announce",
    "http://1337.abcvg.info:80/announce",
    "http://004430.xyz:80/announce",
    "udp://tracker.therarbg.to:6969/announce",
    "udp://tracker.skynetcloud.site:6969/announce",
    "udp://tracker.playground.ru:6969/announce",
    "udp://tracker.peerfect.org:6969/announce",
    "udp://tracker.nyaa.vc:6969/announce",
    "udp://tracker.gmi.gd:6969/announce",
    "udp://tracker.filemail.com:6969/announce",
    "udp://tracker.dler.org:6969/announce",
    "udp://tracker.ddunlimited.net:6969/announce",
    "udp://tracker.corpscorp.online:80/announce",
    "udp://open.ftorrent.com:443/announce",
    "udp://open.demonoid.ch:6969/announce",
    "udp://martin-gebhardt.eu:25/announce",
    "udp://explodie.org:6969/announce",
    "https://t.213891.xyz:443/announce",
    "https://pybittrack.retiolus.net:443/announce",
    "http://tracker2.dler.org:80/announce",
    "http://tracker.dler.org:6969/announce",
    "http://tracker.dler.com:6969/announce",
];

/// Combined per-peer session state: Noise transport + underlay address.
///
/// Replaces three separate `RwLock<HashMap<...>>` (`transports`, `peer_underlays`,
/// `addr_to_peer`) with a single `DashMap<PeerId, PeerSession>` plus a thin
/// reverse-index `DashMap<SocketAddr, PeerId>`. All fields that belong to one
/// peer are now co-located, eliminating multi-lock acquisition sequences.
struct PeerSession {
    transport: SecureTransport,
    underlay: TransportAddr,
}

pub struct SeedNetConfig {
    pub seed: Seed,
    pub port: u16,
    pub state_dir: StateDir,
    /// Which transport protocols to enable. Defaults to all.
    pub transports: Vec<seednet_transport::TransportKind>,
    /// BitTorrent tracker URLs (HTTP or UDP) to announce to and discover
    /// peers from. Faster than DHT for initial connection.
    /// Example: "udp://tracker.opentrackr.org:1337"
    pub tracker_urls: Vec<String>,
    /// Known direct peer addresses to connect to immediately on startup
    /// (bypasses DHT and tracker latency entirely).
    pub direct_peers: Vec<std::net::SocketAddr>,
}

impl SeedNetConfig {
    pub fn new(seed: Seed, port: u16, state_dir: StateDir) -> Self {
        Self {
            seed,
            port,
            state_dir,
            transports: vec![
                seednet_transport::TransportKind::Udp,
                seednet_transport::TransportKind::Tcp,
                seednet_transport::TransportKind::Ws,
            ],
            tracker_urls: DEFAULT_TRACKERS.iter().map(|s| s.to_string()).collect(),
            direct_peers: Vec::new(),
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
    our_overlay_ipv6: std::net::Ipv6Addr,
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

        // Prepare our SessionInit payload — sent once to each peer after handshake.
        let our_hostname = local_hostname();
        // Session init payload is rebuilt after STUN so it carries the public addr.
        // We store the components and build it lazily in each handshake path.
        let our_peer_id_si = self.our_peer_id;
        let our_overlay_si = self.our_overlay;
        let our_overlay_ipv6_si = self.our_overlay_ipv6;
        let our_hostname_si = our_hostname;

        let mut alloc_table = self.allocation_table.write().await;
        alloc_table.allocate(self.our_peer_id);
        drop(alloc_table);

        let tun_config = TunConfig::new(self.our_overlay).with_ipv6(self.our_overlay_ipv6);
        let tun_device = AsyncTunDevice::create(&tun_config)?;
        let tun_name = tun_device.name().to_string();
        let (tun_reader, tun_writer, _) = tun_device.into_split();
        let tun_writer = Arc::new(Mutex::new(tun_writer));

        if let Err(e) = platform::configure_interface_full(
            &tun_name,
            self.our_overlay.ip(),
            subnet_mask(seednet_common::OVERLAY_SUBNET_PREFIX),
            Some(&tun_config),
        )
        .await
        {
            tracing::warn!(target: "seednet", error = %e, "platform IP config failed (may need manual ifconfig/ip)");
        }

        // Try to bind the preferred port; fall back to the next available port
        // if it is already in use.  Try up to 10 consecutive ports before giving up.
        let udp_socket = {
            let mut last_err = None;
            let mut bound = None;
            for offset in 0u16..10 {
                let try_port = port.saturating_add(offset);
                match UdpSocket::bind(format!("0.0.0.0:{try_port}")).await {
                    Ok(sock) => {
                        if offset > 0 {
                            tracing::info!(
                                target: "seednet",
                                preferred = port,
                                actual = try_port,
                                "preferred port in use, bound to next available port",
                            );
                        }
                        bound = Some(sock);
                        break;
                    }
                    Err(e) => last_err = Some(e),
                }
            }
            bound.ok_or_else(|| Error::Io(last_err.unwrap()))?
        };
        let udp_transport = UdpTransport::new(Arc::new(udp_socket));
        let bound_port = udp_transport.local_addr().socket_addr().port();
        tracing::info!(target: "seednet", port = bound_port, "UDP data socket bound");

        // Build MultiTransport with all enabled protocols.
        // Each stream transport (TCP, WS) tries bound_port first, then
        // increments until it finds a free port (up to +10).
        let mut builder = MultiTransport::builder().udp(udp_transport);
        let mut next_stream_port = bound_port;
        for kind in &self.config.transports {
            match kind {
                seednet_transport::TransportKind::Tcp => {
                    let mut bound = false;
                    for offset in 0u16..10 {
                        let try_port = next_stream_port.saturating_add(offset);
                        match seednet_transport::TcpTransport::bind(std::net::SocketAddr::from((
                            [0, 0, 0, 0],
                            try_port,
                        )))
                        .await
                        {
                            Ok(t) => {
                                tracing::info!(target: "seednet", port = try_port, "TCP listener bound");
                                builder = builder.tcp(t);
                                next_stream_port = try_port + 1;
                                bound = true;
                                break;
                            }
                            Err(_) if offset < 9 => continue,
                            Err(e) => {
                                tracing::warn!(target: "seednet", error = %e, "TCP bind failed after retries, skipping");
                            }
                        }
                    }
                    if !bound {
                        next_stream_port += 1;
                    }
                }
                seednet_transport::TransportKind::Ws => {
                    let mut bound = false;
                    for offset in 0u16..10 {
                        let try_port = next_stream_port.saturating_add(offset);
                        match seednet_transport::WsTransport::bind(std::net::SocketAddr::from((
                            [0, 0, 0, 0],
                            try_port,
                        )))
                        .await
                        {
                            Ok(t) => {
                                tracing::info!(target: "seednet", port = try_port, "WS listener bound");
                                builder = builder.ws(t);
                                next_stream_port = try_port + 1;
                                bound = true;
                                break;
                            }
                            Err(_) if offset < 9 => continue,
                            Err(e) => {
                                tracing::warn!(target: "seednet", error = %e, "WS bind failed after retries, skipping");
                            }
                        }
                    }
                    if !bound {
                        next_stream_port += 1;
                    }
                }
                _ => {}
            }
        }
        let transport = Arc::new(builder.build());

        // STUN: discover our public address.  Non-fatal — we continue without it.
        let mut public_addr_init = seednet_nat::stun::query_public_addr_with_fallback(
            transport.udp().unwrap().inner(),
            STUN_SERVERS,
        )
        .await
        .ok();

        // If STUN failed (e.g. cloud servers with 1:1 EIP NAT where the public IP
        // is not on the interface but STUN packets are filtered), fall back to
        // reading local network interfaces for a publicly-routable IP.
        if public_addr_init.is_none()
            && let Some(local_pub) = local_public_ip(bound_port)
        {
            tracing::info!(
                target: "seednet",
                public_addr = %local_pub,
                "STUN failed; using local interface public IP"
            );
            public_addr_init = Some(local_pub);
        }

        let can_relay = public_addr_init.map(is_publicly_routable).unwrap_or(false);
        if let Some(addr) = public_addr_init {
            tracing::info!(target: "seednet", public_addr = %addr, can_relay, "public address discovered");
        } else {
            tracing::warn!(target: "seednet", "STUN discovery failed; hole-punching and relay will be limited");
        }
        let stun_public_addr: Arc<RwLock<Option<SocketAddr>>> =
            Arc::new(RwLock::new(public_addr_init));

        // Start DHT, tracker queries, and DHT announce all concurrently.
        // Direct peers are available immediately; tracker + DHT peers arrive
        // as background tasks complete and feed into the discovery loop.
        let dht = DhtDiscovery::start_with(0, std::net::Ipv4Addr::UNSPECIFIED, &[])
            .map_err(|e| Error::Dht(format!("DHT start failed: {e}")))?;

        // Build tracker peer list.
        let mut tracker_addrs: Vec<std::net::SocketAddr> = self.config.direct_peers.clone();
        let infohash_bytes: [u8; 20] = {
            let b = self.infohash.as_bytes();
            let mut arr = [0u8; 20];
            arr.copy_from_slice(b);
            arr
        };
        let peer_id_bytes: [u8; 20] = {
            let pk = self.our_peer_id.as_bytes();
            let mut id = [0u8; 20];
            id.copy_from_slice(&pk[..20]);
            id
        };
        let announce_port = public_addr_init.map(|a| a.port()).unwrap_or(port);

        // Launch all three concurrently and wait for all to finish.
        let ((), tracker_results) = tokio::join!(
            // 1. DHT bootstrap + announce
            async {
                tracing::info!(target: "seednet", "Waiting for DHT bootstrap …");
                let bootstrapped =
                    tokio::time::timeout(Duration::from_secs(15), dht.bootstrapped()).await;
                match bootstrapped {
                    Ok(true) => tracing::info!(target: "seednet", "DHT bootstrapped"),
                    Ok(false) => {
                        tracing::warn!(target: "seednet", "DHT bootstrap returned false")
                    }
                    Err(_) => tracing::warn!(
                        target: "seednet",
                        "DHT bootstrap timed out after 15s, continuing anyway"
                    ),
                }
                if let Err(e) = dht.announce(&self.infohash, announce_port).await {
                    tracing::warn!(target: "seednet", error = %e, "DHT announce failed");
                } else {
                    tracing::info!(target: "seednet", port = announce_port, "Announced on DHT");
                }
            },
            // 2. Tracker queries (all concurrent internally)
            async {
                if self.config.tracker_urls.is_empty() {
                    return Vec::new();
                }
                let mut futs = Vec::new();
                for url in &self.config.tracker_urls {
                    let url = url.clone();
                    let ih = infohash_bytes;
                    let pid = peer_id_bytes;
                    futs.push(tokio::spawn(async move {
                        seednet_tracker::announce(&url, &ih, &pid, port).await
                    }));
                }
                let mut all = Vec::new();
                for fut in futs {
                    if let Ok(peers) = fut.await {
                        all.extend(peers);
                    }
                }
                tracing::info!(
                    target: "seednet",
                    count = all.len(),
                    "tracker peers collected"
                );
                all
            }
        );
        for p in tracker_results {
            if !tracker_addrs.contains(&p) {
                tracker_addrs.push(p);
            }
        }
        if !tracker_addrs.is_empty() {
            tracing::info!(
                target: "seednet",
                total = tracker_addrs.len(),
                "tracker+direct peers ready"
            );
        }

        // relay_candidates: relay_peer_id → underlay SocketAddr
        let relay_candidates: Arc<DashMap<PeerId, SocketAddr>> = Arc::new(DashMap::new());
        // relay_paths: dst_peer_id → relay_peer_id
        let relay_paths: Arc<DashMap<PeerId, PeerId>> = Arc::new(DashMap::new());

        // Single DashMap keyed by PeerId.
        let sessions: Arc<DashMap<PeerId, PeerSession>> = Arc::new(DashMap::new());
        // Reverse index: TransportAddr → PeerId, for O(1) inbound dispatch.
        let addr_index: Arc<DashMap<TransportAddr, PeerId>> = Arc::new(DashMap::new());
        let pending_handshakes: Arc<
            RwLock<HashMap<SocketAddr, tokio::sync::oneshot::Sender<Vec<u8>>>>,
        > = Arc::new(RwLock::new(HashMap::new()));

        let router_out = self.routing_table.clone();
        let sessions_out = sessions.clone();
        let udp_out = transport.clone();
        let our_overlay_out = self.our_overlay;
        let tun_writer_out = tun_writer.clone();
        let relay_candidates_out = relay_candidates.clone();
        let relay_paths_out = relay_paths.clone();

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
                                let wrapped = seednet_peer::message::serialize_message(
                                    &Message::Data(packet.to_vec()),
                                );
                                match session.transport.encrypt(&wrapped) {
                                    Ok(encrypted) => {
                                        let addr = session.underlay.clone();
                                        drop(session);
                                        let _ = udp_out.send_to(&encrypted, addr).await;
                                    }
                                    Err(e) => {
                                        tracing::debug!(target: "seednet", peer = %peer_id.short(), error = %e, "encrypt failed");
                                    }
                                }
                            } else if let Some(relay_id) = relay_paths_out.get(&peer_id).map(|r| *r)
                            {
                                // No direct session; try relay.
                                if let Some(mut relay_session) = sessions_out.get_mut(&relay_id) {
                                    let wrapped = seednet_peer::message::serialize_message(
                                        &Message::Data(packet.to_vec()),
                                    );
                                    if let Ok(inner_enc) = relay_session.transport.encrypt(&wrapped)
                                    {
                                        // Wrap in RelayData for the relay node.
                                        let relay_pkt = seednet_peer::message::serialize_message(
                                            &Message::RelayData {
                                                dst_peer_id: peer_id,
                                                payload: inner_enc,
                                            },
                                        );
                                        if let Ok(outer_enc) =
                                            relay_session.transport.encrypt(&relay_pkt)
                                        {
                                            let addr = relay_session.underlay.clone();
                                            drop(relay_session);
                                            let _ = udp_out.send_to(&outer_enc, addr).await;
                                        }
                                    }
                                }
                            } else {
                                tracing::debug!(target: "seednet", peer = %peer_id.short(), "no session or relay for peer");
                                // Remove stale route so routing table stays consistent.
                                {
                                    let mut rt = router_out.write().await;
                                    if let Some(overlay) = rt.lookup_peer_ip(&peer_id) {
                                        rt.remove_route(&seednet_common::OverlayAddr::new(overlay));
                                        tracing::debug!(target: "seednet", peer = %peer_id.short(), "removed stale route");
                                    }
                                }
                                // Request relay setup if we have a candidate.
                                if let Some(relay_entry) = relay_candidates_out.iter().next() {
                                    let relay_id = *relay_entry.key();
                                    if let Some(mut relay_session) = sessions_out.get_mut(&relay_id)
                                    {
                                        let req = seednet_peer::message::serialize_message(
                                            &Message::RelayRequest {
                                                dst_peer_id: peer_id,
                                            },
                                        );
                                        if let Ok(enc) = relay_session.transport.encrypt(&req) {
                                            let addr = relay_session.underlay.clone();
                                            drop(relay_session);
                                            let _ = udp_out.send_to(&enc, addr).await;
                                            tracing::info!(target: "seednet", peer = %peer_id.short(), relay = %relay_id.short(), "requested relay");
                                        }
                                    }
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

        let tun_writer_in = tun_writer.clone();
        let udp_in = transport.clone();
        let sessions_in = sessions.clone();
        let addr_index_in = addr_index.clone();
        let pending_in = pending_handshakes.clone();
        let network_secret_resp = self.network_secret;
        let device_keys_resp = self.device_keys.clone();
        let routing_table_in = self.routing_table.clone();
        let peer_mgr_in = self.peer_manager.clone();
        let stun_addr_resp = stun_public_addr.clone();
        let si_peer_id_resp = our_peer_id_si;
        let si_overlay_resp = our_overlay_si;
        let si_overlay_ipv6_resp = our_overlay_ipv6_si;
        let si_hostname_resp = our_hostname_si.clone();
        let relay_candidates_in = relay_candidates.clone();
        let relay_paths_in = relay_paths.clone();
        let our_peer_id_relay = self.our_peer_id;
        let can_relay_in = can_relay;

        let inbound_handle = tokio::spawn(async move {
            // State machine for concurrent responder-side handshakes.
            // Keyed by peer SocketAddr; value is the half-completed ResponderHandshake
            // (after msg A read + msg B sent) waiting for msg C. Entries older than
            // HANDSHAKE_TIMEOUT are evicted on the next incoming packet.
            let mut pending_responders: HashMap<
                SocketAddr,
                (ResponderHandshake, std::time::Instant),
            > = HashMap::new();

            loop {
                match udp_in.recv_from().await {
                    Ok((data, from)) => {
                        let from_sa = from.socket_addr();

                        // Evict stale half-open responder handshakes.
                        pending_responders.retain(|_, (_, t)| t.elapsed() < HANDSHAKE_TIMEOUT);

                        // --- hole-punch probes (unencrypted, must check before Noise) ---
                        if data.starts_with(seednet_common::HOLE_PUNCH_PROBE_PREFIX) {
                            let payload = &data[seednet_common::HOLE_PUNCH_PROBE_PREFIX.len()..];
                            match seednet_peer::message::deserialize_message(payload) {
                                Ok(Message::HolePunchProbe { token }) => {
                                    tracing::debug!(target: "seednet", from = %from, token, "hole-punch probe received, sending ack+probe");
                                    let ack = [
                                        seednet_common::HOLE_PUNCH_PROBE_PREFIX,
                                        &seednet_peer::message::serialize_message(
                                            &Message::HolePunchAck { token },
                                        ),
                                    ]
                                    .concat();
                                    let probe = [
                                        seednet_common::HOLE_PUNCH_PROBE_PREFIX,
                                        &seednet_peer::message::serialize_message(
                                            &Message::HolePunchProbe { token },
                                        ),
                                    ]
                                    .concat();
                                    let _ = udp_in.send_to(&ack, from.clone()).await;
                                    let _ = udp_in.send_to(&probe, from.clone()).await;
                                }
                                Ok(Message::HolePunchAck { token }) => {
                                    tracing::debug!(target: "seednet", from = %from, token, "hole-punch ack received");
                                }
                                _ => {}
                            }
                            continue;
                        }

                        // --- msg B dispatch: initiator side waiting on a oneshot ---
                        if data.starts_with(NOISE_HANDSHAKE_RESPONDER_PREFIX) {
                            let mut pending = pending_in.write().await;
                            if let Some(sender) = pending.remove(&from_sa) {
                                drop(pending);
                                tracing::debug!(target: "seednet", from = %from, "dispatching msg B to pending initiator");
                                let _ = sender.send(data.to_vec());
                                continue;
                            }
                            drop(pending);
                            // Not for us — fall through to other handlers.
                        }

                        // --- msg C: complete a pending responder handshake ---
                        if let Some((responder, _)) = pending_responders.remove(&from_sa) {
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

                                    // Direct connection succeeded — remove any relay path.
                                    if relay_paths_in.remove(&peer_id).is_some() {
                                        tracing::info!(
                                            target: "seednet",
                                            peer = %peer_id.short(),
                                            "upgraded from relay to direct connection (responder)"
                                        );
                                    }

                                    sessions_in.insert(
                                        peer_id,
                                        PeerSession {
                                            transport: resp_result.transport,
                                            underlay: from.clone(),
                                        },
                                    );
                                    addr_index_in.insert(from.clone(), peer_id);

                                    let overlay = derive_overlay_addr(&peer_id);
                                    let mut rt = routing_table_in.write().await;
                                    rt.add_route(overlay, peer_id);
                                    drop(rt);

                                    // Send our SessionInit so the peer learns our hostname + IPv6 + public addr.
                                    let our_public = *stun_addr_resp.read().await;
                                    let si_bytes = seednet_peer::message::serialize_message(
                                        &Message::SessionInit {
                                            peer_id: si_peer_id_resp,
                                            overlay: si_overlay_resp,
                                            overlay_ipv6: Some(si_overlay_ipv6_resp.octets()),
                                            hostname: si_hostname_resp.clone(),
                                            public_addr: our_public,
                                        },
                                    );
                                    if let Some(mut session) = sessions_in.get_mut(&peer_id)
                                        && let Ok(enc) = session.transport.encrypt(&si_bytes)
                                    {
                                        let _ = udp_in.send_to(&enc, from.clone()).await;
                                    }

                                    // If we can relay, advertise ourselves and send peer directory.
                                    if can_relay_in
                                        && let Some(our_pub) = *stun_addr_resp.read().await
                                    {
                                        let announce = seednet_peer::message::serialize_message(
                                            &Message::RelayAnnounce {
                                                relay_peer_id: our_peer_id_relay,
                                                public_addr: our_pub,
                                            },
                                        );
                                        if let Some(mut session) = sessions_in.get_mut(&peer_id)
                                            && let Ok(enc) = session.transport.encrypt(&announce)
                                        {
                                            let _ = udp_in.send_to(&enc, from.clone()).await;
                                        }

                                        // Send peer directory so the new peer can request relay
                                        // for peers it hasn't connected to yet.
                                        let entries: Vec<(PeerId, SocketAddr)> = sessions_in
                                            .iter()
                                            .filter(|e| *e.key() != peer_id)
                                            .filter_map(|e| {
                                                if let TransportAddr::Udp(a) = e.underlay {
                                                    Some((*e.key(), a))
                                                } else {
                                                    None
                                                }
                                            })
                                            .collect();
                                        if !entries.is_empty() {
                                            let dir = seednet_peer::message::serialize_message(
                                                &Message::PeerDirectory { entries },
                                            );
                                            if let Some(mut session) = sessions_in.get_mut(&peer_id)
                                                && let Ok(enc) = session.transport.encrypt(&dir)
                                            {
                                                let _ = udp_in.send_to(&enc, from.clone()).await;
                                            }
                                        }
                                    }

                                    let _peer = peer_mgr_in.discover(peer_id, from_sa).await;
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
                                            Ok(Message::Ping { sent_ms }) => {
                                                // Echo back a Pong immediately.
                                                let pong = seednet_peer::message::serialize_message(
                                                    &Message::Pong { sent_ms },
                                                );
                                                let peer_id = addr_index_in.get(&from).map(|r| *r);
                                                if let Some(pid) = peer_id
                                                    && let Some(mut session) =
                                                        sessions_in.get_mut(&pid)
                                                    && let Ok(enc) =
                                                        session.transport.encrypt(&pong)
                                                {
                                                    drop(session);
                                                    let _ =
                                                        udp_in.send_to(&enc, from.clone()).await;
                                                }
                                            }
                                            Ok(Message::Pong { sent_ms }) => {
                                                // Compute RTT and update peer latency.
                                                let now_ms = std::time::SystemTime::now()
                                                    .duration_since(std::time::UNIX_EPOCH)
                                                    .unwrap_or_default()
                                                    .as_millis()
                                                    as u64;
                                                let rtt = now_ms.saturating_sub(sent_ms) as u32;
                                                let peer_id = addr_index_in.get(&from).map(|r| *r);
                                                if let Some(pid) = peer_id
                                                    && let Some(peer) = peer_mgr_in.get(&pid)
                                                {
                                                    peer.set_latency_ms(rtt).await;
                                                    tracing::debug!(
                                                        target: "seednet",
                                                        peer = %pid.short(),
                                                        rtt_ms = rtt,
                                                        "pong received"
                                                    );
                                                }
                                            }
                                            Ok(Message::Data(payload)) => {
                                                let mut writer = tun_writer_in.lock().await;
                                                let _ = writer.send(&payload).await;
                                            }
                                            Ok(Message::SessionInit {
                                                peer_id,
                                                overlay,
                                                overlay_ipv6,
                                                hostname,
                                                public_addr,
                                            }) => {
                                                // The handshake keyed the session on the remote's
                                                // X25519 Noise static key. SessionInit brings the
                                                // canonical Ed25519 PeerId and the correct overlay.
                                                // Re-key session + routing table so everything
                                                // is consistent under the Ed25519 PeerId.
                                                let x25519_peer_id =
                                                    addr_index_in.get(&from).map(|r| *r);
                                                if let Some(old_id) = x25519_peer_id
                                                    && old_id != peer_id
                                                {
                                                    // Move session to canonical peer_id.
                                                    if let Some((_, session)) =
                                                        sessions_in.remove(&old_id)
                                                    {
                                                        sessions_in.insert(peer_id, session);
                                                    }
                                                    addr_index_in.insert(from.clone(), peer_id);

                                                    // Fix routing table BEFORE triggering Connected
                                                    // event so peers.json snapshot sees correct overlay.
                                                    let stale = derive_overlay_addr(&old_id);
                                                    let correct_overlay = OverlayAddr::new(
                                                        std::net::Ipv4Addr::from(overlay),
                                                    );
                                                    {
                                                        let mut rt = routing_table_in.write().await;
                                                        rt.remove_route(&stale);
                                                        rt.add_route(correct_overlay, peer_id);
                                                    }

                                                    // Re-key peer_manager: move from X25519 id to Ed25519 id.
                                                    if let Some(old_peer) =
                                                        peer_mgr_in.remove(&old_id)
                                                    {
                                                        let addr = old_peer
                                                            .underlay_addr()
                                                            .await
                                                            .unwrap_or(from_sa);
                                                        let new_peer = peer_mgr_in
                                                            .discover(peer_id, addr)
                                                            .await;
                                                        let _ = peer_mgr_in
                                                            .transition_peer(
                                                                &peer_id,
                                                                PeerState::Connecting,
                                                            )
                                                            .await;
                                                        let _ = peer_mgr_in
                                                            .transition_peer(
                                                                &peer_id,
                                                                PeerState::Handshaking,
                                                            )
                                                            .await;
                                                        // Connected event fires here — routing
                                                        // table is already correct at this point.
                                                        let _ = peer_mgr_in
                                                            .transition_peer(
                                                                &peer_id,
                                                                PeerState::Connected,
                                                            )
                                                            .await;
                                                        let _ = new_peer;
                                                    }
                                                } else {
                                                    // peer_id unchanged — just update the route.
                                                    let correct_overlay = OverlayAddr::new(
                                                        std::net::Ipv4Addr::from(overlay),
                                                    );
                                                    let mut rt = routing_table_in.write().await;
                                                    rt.add_route(correct_overlay, peer_id);
                                                    drop(rt);
                                                }
                                                tracing::info!(target: "seednet",
                                                    peer = %peer_id.short(),
                                                    overlay = %std::net::Ipv4Addr::from(overlay),
                                                    "peer overlay updated from SessionInit");
                                                if let Some(peer) = peer_mgr_in.get(&peer_id) {
                                                    if let Some(bytes) = overlay_ipv6 {
                                                        peer.set_overlay_ipv6(
                                                            std::net::Ipv6Addr::from(bytes),
                                                        )
                                                        .await;
                                                    }
                                                    if !hostname.is_empty() {
                                                        peer.set_hostname(hostname).await;
                                                    }
                                                    if let Some(addr) = public_addr {
                                                        peer.set_public_addr(addr).await;
                                                    }
                                                }
                                                tracing::debug!(target: "seednet", from = %from, "SessionInit received");
                                            }
                                            Ok(Message::RelayAnnounce {
                                                relay_peer_id,
                                                public_addr,
                                            }) => {
                                                relay_candidates_in
                                                    .insert(relay_peer_id, public_addr);
                                                tracing::info!(target: "seednet", relay = %relay_peer_id.short(), addr = %public_addr, "relay candidate registered");
                                            }
                                            Ok(Message::PeerDirectory { entries }) => {
                                                // The relay sent us a list of peers it knows.
                                                // For each peer we're not yet connected to,
                                                // immediately request a relay path.
                                                let relay_id = addr_index_in.get(&from).map(|r| *r);
                                                if let Some(rid) = relay_id {
                                                    for (pid, pub_addr) in &entries {
                                                        if *pid == our_peer_id_relay {
                                                            continue; // skip ourselves
                                                        }
                                                        // Record the peer's public addr for future hole-punch.
                                                        let p = peer_mgr_in
                                                            .discover(*pid, *pub_addr)
                                                            .await;
                                                        p.set_public_addr(*pub_addr).await;

                                                        if !sessions_in.contains_key(pid) {
                                                            // Not yet connected — request relay immediately.
                                                            if let Some(mut rsession) =
                                                                sessions_in.get_mut(&rid)
                                                            {
                                                                let req = seednet_peer::message::serialize_message(
                                                                    &Message::RelayRequest { dst_peer_id: *pid },
                                                                );
                                                                if let Ok(enc) =
                                                                    rsession.transport.encrypt(&req)
                                                                {
                                                                    let raddr =
                                                                        rsession.underlay.clone();
                                                                    drop(rsession);
                                                                    let _ = udp_in
                                                                        .send_to(&enc, raddr)
                                                                        .await;
                                                                    tracing::info!(
                                                                        target: "seednet",
                                                                        peer = %pid.short(),
                                                                        relay = %rid.short(),
                                                                        pub_addr = %pub_addr,
                                                                        "requested relay via peer directory"
                                                                    );
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                            Ok(Message::RelayRequest { dst_peer_id }) => {
                                                // We are the relay: forward request to dst, notify requester.
                                                if can_relay_in {
                                                    let requesting_id =
                                                        addr_index_in.get(&from).map(|r| *r);
                                                    if let Some(req_id) = requesting_id {
                                                        // Tell dst about the relay request.
                                                        if let Some(mut dst_session) =
                                                            sessions_in.get_mut(&dst_peer_id)
                                                        {
                                                            let fwd = seednet_peer::message::serialize_message(
                                                                &Message::RelayRequest { dst_peer_id: req_id },
                                                            );
                                                            if let Ok(enc) =
                                                                dst_session.transport.encrypt(&fwd)
                                                            {
                                                                let addr =
                                                                    dst_session.underlay.clone();
                                                                drop(dst_session);
                                                                let _ = udp_in
                                                                    .send_to(&enc, addr)
                                                                    .await;
                                                            }
                                                        }
                                                        // Tell requester we're ready.
                                                        if let Some(mut req_session) =
                                                            sessions_in.get_mut(&req_id)
                                                        {
                                                            let ready = seednet_peer::message::serialize_message(
                                                                &Message::RelayReady { relay_peer_id: our_peer_id_relay, dst_peer_id },
                                                            );
                                                            if let Ok(enc) = req_session
                                                                .transport
                                                                .encrypt(&ready)
                                                            {
                                                                let addr =
                                                                    req_session.underlay.clone();
                                                                drop(req_session);
                                                                let _ = udp_in
                                                                    .send_to(&enc, addr)
                                                                    .await;
                                                            }
                                                        }
                                                    }
                                                } else {
                                                    // We are the destination: the relay forwarded a
                                                    // RelayRequest from dst_peer_id (confusingly named —
                                                    // when forwarded, dst_peer_id = the requesting peer).
                                                    // Record the relay path so we can send back.
                                                    let relay_id =
                                                        addr_index_in.get(&from).map(|r| *r);
                                                    if let Some(rid) = relay_id {
                                                        relay_paths_in.insert(dst_peer_id, rid);
                                                        tracing::info!(
                                                            target: "seednet",
                                                            peer = %dst_peer_id.short(),
                                                            relay = %rid.short(),
                                                            "relay path recorded (as destination)"
                                                        );
                                                    }
                                                }
                                            }
                                            Ok(Message::RelayReady {
                                                relay_peer_id,
                                                dst_peer_id,
                                            }) => {
                                                relay_paths_in.insert(dst_peer_id, relay_peer_id);
                                                tracing::info!(target: "seednet", dst = %dst_peer_id.short(), relay = %relay_peer_id.short(), "relay path established");
                                            }
                                            Ok(Message::RelayData {
                                                dst_peer_id,
                                                payload,
                                            }) => {
                                                if dst_peer_id == our_peer_id_relay {
                                                    // Data relayed to us: the payload is a raw IP
                                                    // packet wrapped by the relay in a relay session.
                                                    // Since the relay just forwarded what the sender
                                                    // sent (already decrypted from outer relay session
                                                    // by the relay node), the payload here is the
                                                    // sender's Noise-encrypted Data message.
                                                    // Try to decrypt with the sender's session.
                                                    let sender_id =
                                                        addr_index_in.get(&from).map(|r| *r);
                                                    if let Some(sid) = sender_id
                                                        && let Some(mut session) =
                                                            sessions_in.get_mut(&sid)
                                                        && let Ok(plain) =
                                                            session.transport.decrypt(&payload)
                                                    {
                                                        drop(session);
                                                        if let Ok(
                                                                    Message::Data(ip_pkt),
                                                                ) = seednet_peer::message::deserialize_message(
                                                                    &plain,
                                                                ) {
                                                                    let mut w =
                                                                        tun_writer_in.lock().await;
                                                                    let _ = w.send(&ip_pkt).await;
                                                                    tracing::debug!(target: "seednet", bytes = ip_pkt.len(), "relayed packet written to TUN");
                                                                }
                                                    }
                                                } else if can_relay_in {
                                                    // We are the relay: decrypt from sender's session,
                                                    // re-encrypt with destination's session, forward.
                                                    let sender_id =
                                                        addr_index_in.get(&from).map(|r| *r);
                                                    let inner = if let Some(sid) = sender_id {
                                                        sessions_in.get_mut(&sid).and_then(
                                                            |mut s| {
                                                                s.transport.decrypt(&payload).ok()
                                                            },
                                                        )
                                                    } else {
                                                        None
                                                    };
                                                    if let Some(decrypted) = inner
                                                        && let Some(mut dst_session) =
                                                            sessions_in.get_mut(&dst_peer_id)
                                                        && let Ok(re_enc) = dst_session
                                                            .transport
                                                            .encrypt(&decrypted)
                                                    {
                                                        let fwd = seednet_peer::message::serialize_message(
                                                                    &Message::RelayData {
                                                                        dst_peer_id,
                                                                        payload: re_enc,
                                                                    },
                                                                );
                                                        if let Ok(outer) =
                                                            dst_session.transport.encrypt(&fwd)
                                                        {
                                                            let addr = dst_session.underlay.clone();
                                                            drop(dst_session);
                                                            let _ =
                                                                udp_in.send_to(&outer, addr).await;
                                                            tracing::debug!(target: "seednet", dst = %dst_peer_id.short(), "relayed packet forwarded (re-encrypted)");
                                                        }
                                                    }
                                                }
                                            }
                                            Ok(msg) => {
                                                tracing::debug!(target: "seednet", from = %from, ?msg, "unhandled message type");
                                            }
                                            Err(e) => {
                                                tracing::debug!(target: "seednet", from = %from, error = %e, "malformed message, dropping");
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
                                                let _ = udp_in.send_to(&tagged, from.clone()).await;

                                                // Park the half-completed handshake; msg C will
                                                // arrive in a future iteration of this loop.
                                                pending_responders.insert(
                                                    from_sa,
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
        let udp_dht = transport.clone();
        let sessions_dht = sessions.clone();
        let addr_index_dht = addr_index.clone();
        let stun_addr_dht = stun_public_addr.clone();
        let si_peer_id_dht = our_peer_id_si;
        let si_overlay_dht = our_overlay_si;
        let si_overlay_ipv6_dht = our_overlay_ipv6_si;
        let si_hostname_dht = our_hostname_si.clone();
        let relay_candidates_dht = relay_candidates.clone();
        let relay_paths_dht = relay_paths.clone();
        let can_relay_dht = can_relay;
        let our_peer_id_relay_dht = self.our_peer_id;
        let pending_dht = pending_handshakes.clone();
        let routing_table_dht = self.routing_table.clone();
        let our_peer_id_dht = self.our_peer_id;
        let infohash = self.infohash;

        let dht_clone = dht.clone();
        let discovery_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(DISCOVERY_INTERVAL);
            // On first tick fire immediately to connect trackers without delay.
            let mut first_tick = true;
            loop {
                if first_tick {
                    first_tick = false;
                } else {
                    interval.tick().await;
                }

                // Merge tracker addrs into the peer list — they take priority.
                let dht_peers = dht_clone.lookup(&infohash).await.unwrap_or_default();
                tracing::info!(target: "seednet", dht = dht_peers.len(), trackers = tracker_addrs.len(), "discovery cycle");
                // Trackers first so they're attempted before DHT peers.
                let mut peers: Vec<std::net::SocketAddr> = tracker_addrs.clone();
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
                    // Skip our own public address.
                    if let Some(our_pub) = *stun_addr_dht.read().await
                        && addr == our_pub
                    {
                        continue;
                    }
                    // Skip already-connected peers.
                    let already_connected = addr_index_dht
                        .get(&TransportAddr::Udp(addr))
                        .map(|peer_id| sessions_dht.contains_key(&*peer_id))
                        .unwrap_or(false);
                    if already_connected {
                        continue;
                    }
                    // Skip if handshake already in flight.
                    if pending_dht.read().await.contains_key(&addr) {
                        continue;
                    }
                    // Clean up stale addr_index entry if session is gone.
                    if let Some(peer_id) = addr_index_dht.get(&TransportAddr::Udp(addr)).map(|r| *r)
                        && !sessions_dht.contains_key(&peer_id)
                    {
                        addr_index_dht.remove(&TransportAddr::Udp(addr));
                    }

                    // Spawn each handshake independently so all peers are tried
                    // concurrently and the discovery loop isn't blocked by timeouts.
                    let network_secret = network_secret_dht;
                    let device_keys = device_keys_dht.clone();
                    let udp = udp_dht.clone();
                    let sessions = sessions_dht.clone();
                    let addr_index = addr_index_dht.clone();
                    let pending = pending_dht.clone();
                    let stun_addr = stun_addr_dht.clone();
                    let peer_mgr = peer_mgr_dht.clone();
                    let rt_dht = routing_table_dht.clone();
                    let relay_cands = relay_candidates_dht.clone();
                    let relay_paths2 = relay_paths_dht.clone();
                    let si_peer_id = si_peer_id_dht;
                    let si_overlay = si_overlay_dht;
                    let si_overlay_ipv6 = si_overlay_ipv6_dht;
                    let si_hostname = si_hostname_dht.clone();
                    let our_id = our_peer_id_dht;
                    let our_relay_id = our_peer_id_relay_dht;
                    let can_relay = can_relay_dht;

                    tokio::spawn(async move {
                        tracing::info!(target: "seednet", addr = %addr, "initiating handshake to discovered peer");

                        let mut initiator = match InitiatorHandshake::new(
                            &network_secret,
                            &device_keys,
                        ) {
                            Ok(i) => i,
                            Err(e) => {
                                tracing::warn!(target: "seednet", error = %e, "initiator create failed");
                                return;
                            }
                        };
                        let msg_a = match initiator.write_message_a(&[]) {
                            Ok(m) => m,
                            Err(e) => {
                                tracing::warn!(target: "seednet", error = %e, "write_message_a failed");
                                return;
                            }
                        };
                        let mut tagged_a = NOISE_HANDSHAKE_INITIATOR_PREFIX.to_vec();
                        tagged_a.extend_from_slice(&msg_a);

                        let (tx, rx) = tokio::sync::oneshot::channel();
                        {
                            let mut p = pending.write().await;
                            if p.contains_key(&addr) {
                                return;
                            }
                            p.insert(addr, tx);
                        }
                        if let Err(e) = udp.send_to(&tagged_a, TransportAddr::Udp(addr)).await {
                            pending.write().await.remove(&addr);
                            tracing::warn!(target: "seednet", error = %e, "send msg A failed");
                            return;
                        }

                        match tokio::time::timeout(HANDSHAKE_TIMEOUT, rx).await {
                            Ok(Ok(msg_b_tagged)) => {
                                if !msg_b_tagged.starts_with(NOISE_HANDSHAKE_RESPONDER_PREFIX) {
                                    tracing::warn!(target: "seednet", "msg B has wrong prefix");
                                    return;
                                }
                                let msg_b = &msg_b_tagged[NOISE_HANDSHAKE_RESPONDER_PREFIX.len()..];
                                if let Err(e) = initiator.read_message_b(msg_b) {
                                    tracing::warn!(target: "seednet", error = %e, "read_message_b failed");
                                    return;
                                }
                                let init_result = match initiator.finish(&[]) {
                                    Ok(r) => r,
                                    Err(e) => {
                                        tracing::warn!(target: "seednet", error = %e, "initiator finish failed");
                                        return;
                                    }
                                };
                                if let Err(e) = udp
                                    .send_to(&init_result.msg_bytes, TransportAddr::Udp(addr))
                                    .await
                                {
                                    tracing::warn!(target: "seednet", error = %e, "send msg C failed");
                                    return;
                                }
                                let remote_static = *init_result.transport.remote_static_key();
                                let peer_id = PeerId::from_bytes(remote_static);
                                if peer_id == our_id {
                                    return;
                                }
                                tracing::info!(target: "seednet", peer = %peer_id.short(), addr = %addr, "handshake completed (initiator)");
                                // Direct → remove any relay path.
                                if relay_paths2.remove(&peer_id).is_some() {
                                    tracing::info!(target: "seednet", peer = %peer_id.short(), "upgraded from relay to direct connection");
                                }
                                sessions.insert(
                                    peer_id,
                                    PeerSession {
                                        transport: init_result.transport,
                                        underlay: TransportAddr::Udp(addr),
                                    },
                                );
                                addr_index.insert(TransportAddr::Udp(addr), peer_id);
                                let overlay = derive_overlay_addr(&peer_id);
                                {
                                    let mut rt = rt_dht.write().await;
                                    rt.add_route(overlay, peer_id);
                                }
                                // Send SessionInit.
                                let our_public = *stun_addr.read().await;
                                let si_bytes = seednet_peer::message::serialize_message(
                                    &Message::SessionInit {
                                        peer_id: si_peer_id,
                                        overlay: si_overlay,
                                        overlay_ipv6: Some(si_overlay_ipv6.octets()),
                                        hostname: si_hostname.clone(),
                                        public_addr: our_public,
                                    },
                                );
                                if let Some(mut session) = sessions.get_mut(&peer_id)
                                    && let Ok(enc) = session.transport.encrypt(&si_bytes)
                                {
                                    let _ = udp.send_to(&enc, TransportAddr::Udp(addr)).await;
                                }
                                // Advertise relay + send peer directory.
                                if can_relay && let Some(our_pub) = *stun_addr.read().await {
                                    let announce = seednet_peer::message::serialize_message(
                                        &Message::RelayAnnounce {
                                            relay_peer_id: our_relay_id,
                                            public_addr: our_pub,
                                        },
                                    );
                                    if let Some(mut session) = sessions.get_mut(&peer_id)
                                        && let Ok(enc) = session.transport.encrypt(&announce)
                                    {
                                        let _ = udp.send_to(&enc, TransportAddr::Udp(addr)).await;
                                    }
                                    let entries: Vec<(PeerId, SocketAddr)> = sessions
                                        .iter()
                                        .filter(|e| *e.key() != peer_id)
                                        .filter_map(|e| {
                                            if let TransportAddr::Udp(a) = e.underlay {
                                                Some((*e.key(), a))
                                            } else {
                                                None
                                            }
                                        })
                                        .collect();
                                    if !entries.is_empty() {
                                        let dir = seednet_peer::message::serialize_message(
                                            &Message::PeerDirectory { entries },
                                        );
                                        if let Some(mut session) = sessions.get_mut(&peer_id)
                                            && let Ok(enc) = session.transport.encrypt(&dir)
                                        {
                                            let _ =
                                                udp.send_to(&enc, TransportAddr::Udp(addr)).await;
                                        }
                                    }
                                }
                                let _peer = peer_mgr.discover(peer_id, addr).await;
                                let _ = peer_mgr
                                    .transition_peer(&peer_id, PeerState::Connecting)
                                    .await;
                                let _ = peer_mgr
                                    .transition_peer(&peer_id, PeerState::Handshaking)
                                    .await;
                                let _ = peer_mgr
                                    .transition_peer(&peer_id, PeerState::Connected)
                                    .await;
                                tracing::info!(target: "seednet", peer = %peer_id.short(), overlay = %overlay, addr = %addr, "peer route registered (initiator)");
                            }
                            Ok(Err(_)) => {
                                tracing::warn!(target: "seednet", addr = %addr, "msg B channel dropped");
                            }
                            Err(_) => {
                                let mut p = pending.write().await;
                                p.remove(&addr);
                                tracing::warn!(target: "seednet", addr = %addr, "initiator handshake timed out waiting for msg B");
                                drop(p);
                                // Request relay on timeout.
                                let maybe_peer_id =
                                    addr_index.get(&TransportAddr::Udp(addr)).map(|r| *r);
                                if let Some(target_id) = maybe_peer_id {
                                    for relay_entry in relay_cands.iter() {
                                        let relay_id = *relay_entry.key();
                                        if relay_id == target_id {
                                            continue;
                                        }
                                        if let Some(mut relay_session) = sessions.get_mut(&relay_id)
                                        {
                                            let req = seednet_peer::message::serialize_message(
                                                &Message::RelayRequest {
                                                    dst_peer_id: target_id,
                                                },
                                            );
                                            if let Ok(enc) = relay_session.transport.encrypt(&req) {
                                                let raddr = relay_session.underlay.clone();
                                                drop(relay_session);
                                                let _ = udp.send_to(&enc, raddr).await;
                                                tracing::info!(target: "seednet", peer = %target_id.short(), relay = %relay_id.short(), "requested relay after direct timeout");
                                            }
                                        }
                                    }
                                }
                                // Hole-punch attempt.
                                let peer_id_candidate =
                                    addr_index.get(&TransportAddr::Udp(addr)).map(|r| *r);
                                if let Some(pid) = peer_id_candidate
                                    && let Some(peer) = peer_mgr.get(&pid)
                                    && let Some(pub_addr) = peer.public_addr().await
                                    && pub_addr != addr
                                {
                                    tracing::info!(target: "seednet", addr = %pub_addr, peer = %pid.short(), "attempting hole-punch");
                                    let token = rand::random::<u64>();
                                    let probe = [
                                        seednet_common::HOLE_PUNCH_PROBE_PREFIX,
                                        &seednet_peer::message::serialize_message(
                                            &Message::HolePunchProbe { token },
                                        ),
                                    ]
                                    .concat();
                                    let _ = udp.send_to(&probe, TransportAddr::Udp(pub_addr)).await;
                                }
                            }
                        }
                    }); // end tokio::spawn per peer
                } // end for addr in peers
            } // end loop
        }); // end discovery_handle

        let stun_addr_announce = stun_public_addr.clone();
        let announce_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(DHT_ANNOUNCE_INTERVAL);
            loop {
                interval.tick().await;
                let announce_port = stun_addr_announce
                    .read()
                    .await
                    .map(|a| a.port())
                    .unwrap_or(port);
                if let Err(e) = dht.announce(&infohash, announce_port).await {
                    tracing::debug!(target: "seednet", error = %e, "periodic DHT announce failed");
                }
            }
        });

        let udp_hb = transport.clone();
        let sessions_hb = sessions.clone();

        let heartbeat_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
            let heartbeat_payload = seednet_peer::message::serialize_message(&Message::Heartbeat);
            loop {
                interval.tick().await;
                for mut entry in sessions_hb.iter_mut() {
                    let addr = entry.underlay.clone();
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

        // Health check: send Ping to every connected peer every 5s to measure RTT,
        // then update path_kind (Direct vs Relay) based on what we have.
        const HEALTHCHECK_INTERVAL: Duration = Duration::from_secs(5);
        let udp_hc = transport.clone();
        let sessions_hc = sessions.clone();
        let peer_mgr_hc = self.peer_manager.clone();
        let relay_paths_hc = relay_paths.clone();

        let healthcheck_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(HEALTHCHECK_INTERVAL);
            loop {
                interval.tick().await;
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;
                let ping =
                    seednet_peer::message::serialize_message(&Message::Ping { sent_ms: now_ms });
                for mut entry in sessions_hc.iter_mut() {
                    let peer_id = *entry.key();
                    let addr = entry.underlay.clone();
                    if let Ok(enc) = entry.transport.encrypt(&ping) {
                        drop(entry);
                        let _ = udp_hc.send_to(&enc, addr).await;
                    }
                    // Update path_kind for this peer.
                    if let Some(peer) = peer_mgr_hc.get(&peer_id) {
                        let new_path = if relay_paths_hc.contains_key(&peer_id) {
                            let relay_id = relay_paths_hc.get(&peer_id).map(|r| *r).unwrap();
                            seednet_peer::PathKind::Relay(relay_id)
                        } else {
                            seednet_peer::PathKind::Direct
                        };
                        peer.set_path_kind(new_path).await;
                    }
                }
            }
        });

        // STUN refresh: re-query every DHT_ANNOUNCE_INTERVAL to detect NAT changes.
        let stun_addr_refresh = stun_public_addr.clone();
        let udp_stun = transport.clone();
        let stun_refresh_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(DHT_ANNOUNCE_INTERVAL);
            interval.tick().await; // skip first tick (already queried at startup)
            loop {
                interval.tick().await;
                if let Ok(addr) = seednet_nat::stun::query_public_addr_with_fallback(
                    udp_stun.udp().unwrap().inner(),
                    STUN_SERVERS,
                )
                .await
                {
                    *stun_addr_refresh.write().await = Some(addr);
                }
            }
        });

        // Subscribe to peer events and write a peers.json snapshot on every
        // connect/disconnect so that `seednet list` always sees current data.
        let mut peer_events = self.peer_manager.subscribe();
        let routing_table_evt = self.routing_table.clone();
        let peer_mgr_evt = self.peer_manager.clone();
        let state_dir_evt = self.config.state_dir.clone();
        let relay_paths_evt = relay_paths.clone();
        let sessions_evt = sessions.clone();
        let addr_index_evt = addr_index.clone();
        let local_id = self.our_peer_id;
        let local_overlay = self.our_overlay;
        let local_ipv6 = self.our_overlay_ipv6;
        let local_hostname = local_hostname();
        let local_public_addr = public_addr_init;

        let local_json = format!(
            concat!(
                r#"{{"id":"{id}","id_short":"{short}","#,
                r#""overlay":"{overlay}","overlay_ipv6":"{ipv6}","#,
                r#""hostname":"{hostname}","public_addr":"{pub_addr}","#,
                r#""connection":"direct","underlay":""}}"#,
            ),
            id = local_id,
            short = local_id.short(),
            overlay = local_overlay,
            ipv6 = local_ipv6,
            hostname = local_hostname,
            pub_addr = local_public_addr.map(|a| a.to_string()).unwrap_or_default(),
        );

        let peers_file_handle = tokio::spawn(async move {
            let _ =
                state_dir_evt.write_peers_json(&format!(r#"{{"local":{local_json},"peers":[]}}"#));

            loop {
                match peer_events.recv().await {
                    Ok(PeerEvent::Removed { id }) => {
                        // Clean up session and addr_index so DHT can re-handshake.
                        if let Some((_, session)) = sessions_evt.remove(&id) {
                            addr_index_evt.remove(&session.underlay);
                            tracing::debug!(target: "seednet", peer = %id.short(), "session removed, addr_index cleaned");
                        }
                        // Rebuild peers.json snapshot.
                        let connected = peer_mgr_evt.connected_peers().await;
                        let rt = routing_table_evt.read().await;

                        let mut entries = Vec::with_capacity(connected.len());
                        for id in &connected {
                            let overlay = rt
                                .lookup_peer_ip(id)
                                .map(|ip| ip.to_string())
                                .unwrap_or_default();
                            let (underlay, overlay_ipv6, hostname, public_addr_str) =
                                if let Some(peer) = peer_mgr_evt.get(id) {
                                    let u = peer
                                        .underlay_addr()
                                        .await
                                        .map(|a| a.to_string())
                                        .unwrap_or_default();
                                    let v6 = peer
                                        .overlay_ipv6()
                                        .await
                                        .map(|a| a.to_string())
                                        .unwrap_or_default();
                                    let h = peer.hostname().await;
                                    let pa = peer
                                        .public_addr()
                                        .await
                                        .map(|a| a.to_string())
                                        .unwrap_or_default();
                                    (u, v6, h, pa)
                                } else {
                                    (String::new(), String::new(), String::new(), String::new())
                                };
                            let (connection, relay_via) =
                                if let Some(relay_id) = relay_paths_evt.get(id) {
                                    ("relay", relay_id.short().to_string())
                                } else {
                                    ("direct", String::new())
                                };
                            let latency = if let Some(peer) = peer_mgr_evt.get(id) {
                                peer.latency_ms()
                                    .await
                                    .map(|ms| ms.to_string())
                                    .unwrap_or_default()
                            } else {
                                String::new()
                            };
                            entries.push(format!(
                                concat!(
                                    r#"{{"id":"{id}","id_short":"{short}","#,
                                    r#""overlay":"{overlay}","overlay_ipv6":"{ipv6}","#,
                                    r#""hostname":"{hostname}","public_addr":"{pub_addr}","#,
                                    r#""connection":"{connection}","relay_via":"{relay_via}","#,
                                    r#""latency_ms":"{latency}","#,
                                    r#""underlay":"{underlay}"}}"#,
                                ),
                                id = id,
                                short = id.short(),
                                overlay = overlay,
                                ipv6 = overlay_ipv6,
                                hostname = hostname,
                                pub_addr = public_addr_str,
                                connection = connection,
                                relay_via = relay_via,
                                latency = latency,
                                underlay = underlay,
                            ));
                        }
                        drop(rt);

                        let json = format!(
                            r#"{{"local":{local_json},"peers":[{}]}}"#,
                            entries.join(",")
                        );
                        let _ = state_dir_evt.write_peers_json(&json);
                    }
                    Ok(PeerEvent::StateChanged {
                        to: PeerState::Connected,
                        ..
                    }) => {
                        // Rebuild snapshot when a new peer connects.
                        let connected = peer_mgr_evt.connected_peers().await;
                        let rt = routing_table_evt.read().await;
                        let mut entries = Vec::with_capacity(connected.len());
                        for id in &connected {
                            let overlay = rt
                                .lookup_peer_ip(id)
                                .map(|ip| ip.to_string())
                                .unwrap_or_default();
                            let (underlay, overlay_ipv6, hostname, public_addr_str) =
                                if let Some(peer) = peer_mgr_evt.get(id) {
                                    let u = peer
                                        .underlay_addr()
                                        .await
                                        .map(|a| a.to_string())
                                        .unwrap_or_default();
                                    let v6 = peer
                                        .overlay_ipv6()
                                        .await
                                        .map(|a| a.to_string())
                                        .unwrap_or_default();
                                    let h = peer.hostname().await;
                                    let pa = peer
                                        .public_addr()
                                        .await
                                        .map(|a| a.to_string())
                                        .unwrap_or_default();
                                    (u, v6, h, pa)
                                } else {
                                    (String::new(), String::new(), String::new(), String::new())
                                };
                            let (connection, relay_via) =
                                if let Some(relay_id) = relay_paths_evt.get(id) {
                                    ("relay", relay_id.short().to_string())
                                } else {
                                    ("direct", String::new())
                                };
                            let latency = if let Some(peer) = peer_mgr_evt.get(id) {
                                peer.latency_ms()
                                    .await
                                    .map(|ms| ms.to_string())
                                    .unwrap_or_default()
                            } else {
                                String::new()
                            };
                            entries.push(format!(
                                concat!(
                                    r#"{{"id":"{id}","id_short":"{short}","#,
                                    r#""overlay":"{overlay}","overlay_ipv6":"{ipv6}","#,
                                    r#""hostname":"{hostname}","public_addr":"{pub_addr}","#,
                                    r#""connection":"{connection}","relay_via":"{relay_via}","#,
                                    r#""latency_ms":"{latency}","#,
                                    r#""underlay":"{underlay}"}}"#,
                                ),
                                id = id,
                                short = id.short(),
                                overlay = overlay,
                                ipv6 = overlay_ipv6,
                                hostname = hostname,
                                pub_addr = public_addr_str,
                                connection = connection,
                                relay_via = relay_via,
                                latency = latency,
                                underlay = underlay,
                            ));
                        }
                        drop(rt);
                        let json = format!(
                            r#"{{"local":{local_json},"peers":[{}]}}"#,
                            entries.join(",")
                        );
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
        healthcheck_handle.abort();
        stun_refresh_handle.abort();
        peers_file_handle.abort();
        // Clear the peers snapshot so stale data is not visible after restart.
        let _ = self.config.state_dir.clear_peers_json();

        Ok(())
    }
}

fn local_hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Scan local network interfaces for a publicly-routable IPv4 address.
/// Used as STUN fallback on servers where STUN packets are filtered.
fn local_public_ip(port: u16) -> Option<SocketAddr> {
    // Try cloud metadata services first (AWS, Alibaba Cloud, etc.)
    // Use reqwest blocking to avoid needing curl/wget in the container.
    let metadata_urls = [
        "http://169.254.169.254/latest/meta-data/public-ipv4", // AWS
        "http://100.100.100.200/latest/meta-data/eipv4",       // Alibaba Cloud
    ];
    for url in metadata_urls {
        let result = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(3))
            .build()
            .ok()
            .and_then(|c| c.get(url).send().ok())
            .and_then(|r| r.text().ok());
        if let Some(s) = result
            && let Ok(ip) = s.trim().parse::<std::net::Ipv4Addr>()
            && is_publicly_routable(SocketAddr::from((ip, port)))
        {
            return Some(SocketAddr::from((ip, port)));
        }
    }

    // Fall back to routing table: find the outbound interface IP.
    #[cfg(target_os = "linux")]
    {
        let out = std::process::Command::new("ip")
            .args(["route", "get", "1.1.1.1"])
            .output()
            .ok()?;
        let s = String::from_utf8(out.stdout).ok()?;
        for part in s.split_whitespace().collect::<Vec<_>>().windows(2) {
            if part[0] == "src"
                && let Ok(ip) = part[1].parse::<std::net::Ipv4Addr>()
                && is_publicly_routable(SocketAddr::from((ip, port)))
            {
                return Some(SocketAddr::from((ip, port)));
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("route")
            .args(["-n", "get", "1.1.1.1"])
            .output()
            .ok()?;
        let s = String::from_utf8(out.stdout).ok()?;
        for line in s.lines() {
            if let Some(rest) = line.trim().strip_prefix("interface:") {
                let iface = rest.trim();
                if let Ok(out2) = std::process::Command::new("ipconfig")
                    .args(["getifaddr", iface])
                    .output()
                    && let Ok(ip_str) = String::from_utf8(out2.stdout)
                    && let Ok(ip) = ip_str.trim().parse::<std::net::Ipv4Addr>()
                    && is_publicly_routable(SocketAddr::from((ip, port)))
                {
                    return Some(SocketAddr::from((ip, port)));
                }
            }
        }
    }
    None
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
