use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use seednet_common::{Error, STUN_SERVERS};

use seednet_dht::DhtDiscovery;
use seednet_nat::is_publicly_routable;
use seednet_peer::Message;
use seednet_transport::{MultiTransport, Transport, UdpTransport};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};

mod config;
mod discovery;
mod engine;
mod handshake;
mod inbound;
mod net;
mod outbound;
mod peers_snapshot;
mod trackers;

pub use config::SeedNetConfig;
pub use engine::SeedNetEngine;

use engine::{AddrIndex, RelayCandidates, RelayPaths, Sessions};
use net::{local_hostname, local_public_ip};

const DHT_ANNOUNCE_INTERVAL: Duration = Duration::from_secs(300);
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(15);
const PEER_DIRECTORY_BROADCAST_INTERVAL: Duration = Duration::from_secs(30);

impl SeedNetEngine {
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

        let our_hostname = local_hostname();
        let our_peer_id_si = self.our_peer_id;
        let our_overlay_si = self.our_overlay;
        let our_overlay_ipv6_si = self.our_overlay_ipv6;
        let our_hostname_si = our_hostname;

        let mut alloc_table = self.allocation_table.write().await;
        alloc_table.allocate(self.our_peer_id);
        drop(alloc_table);

        let tun_config =
            seednet_tun::TunConfig::new(self.our_overlay).with_ipv6(self.our_overlay_ipv6);
        let tun_device = seednet_tun::AsyncTunDevice::create(&tun_config)?;
        let tun_name = tun_device.name().to_string();
        let (tun_reader, tun_writer, _) = tun_device.into_split();
        let tun_writer = Arc::new(Mutex::new(tun_writer));

        if let Err(e) = seednet_tun::platform::configure_interface_full(
            &tun_name,
            self.our_overlay.ip(),
            seednet_tun::subnet_mask(seednet_common::OVERLAY_SUBNET_PREFIX),
            Some(&tun_config),
        )
        .await
        {
            tracing::warn!(target: "seednet", error = %e, "platform IP config failed (may need manual ifconfig/ip)");
        }

        // Bind UDP socket with port fallback.
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

        // Build MultiTransport.
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

        // STUN discovery.
        let mut public_addr_init = seednet_nat::stun::query_public_addr_with_fallback(
            transport.udp().unwrap().inner(),
            STUN_SERVERS,
        )
        .await
        .ok();

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

        // DHT bootstrap + tracker queries.
        let dht = DhtDiscovery::start_with(0, std::net::Ipv4Addr::UNSPECIFIED, &[])
            .map_err(|e| Error::Dht(format!("DHT start failed: {e}")))?;

        let mut tracker_addrs: Vec<SocketAddr> = self.config.direct_peers.clone();
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

        let ((), tracker_results) = tokio::join!(
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
                tracing::info!(target: "seednet", count = all.len(), "tracker peers collected");
                all
            }
        );
        for p in tracker_results {
            if !tracker_addrs.contains(&p) {
                tracker_addrs.push(p);
            }
        }
        if !tracker_addrs.is_empty() {
            tracing::info!(target: "seednet", total = tracker_addrs.len(), "tracker+direct peers ready");
        }

        let relay_candidates: RelayCandidates = Arc::new(DashMap::new());
        let relay_paths: RelayPaths = Arc::new(DashMap::new());
        let sessions: Sessions = Arc::new(DashMap::new());
        let addr_index: AddrIndex = Arc::new(DashMap::new());
        let pending_handshakes: Arc<
            RwLock<HashMap<SocketAddr, tokio::sync::oneshot::Sender<Vec<u8>>>>,
        > = Arc::new(RwLock::new(HashMap::new()));

        // Outbound TUN → network task.
        let outbound_handle = {
            let oa = outbound::OutboundArgs {
                routing_table: self.routing_table.clone(),
                sessions: sessions.clone(),
                transport: transport.clone(),
                our_overlay: self.our_overlay,
                our_peer_id: self.our_peer_id,
                tun_writer: tun_writer.clone(),
                relay_candidates: relay_candidates.clone(),
                relay_paths: relay_paths.clone(),
            };
            tokio::spawn(outbound::run_outbound_loop(oa, tun_reader))
        };

        // Inbound network → TUN / handshake task.
        let inbound_handle = {
            let ia = inbound::InboundArgs {
                tun_writer: tun_writer.clone(),
                transport: transport.clone(),
                sessions: sessions.clone(),
                addr_index: addr_index.clone(),
                pending: pending_handshakes.clone(),
                network_secret: self.network_secret,
                device_keys: self.device_keys.clone(),
                routing_table: self.routing_table.clone(),
                peer_mgr: self.peer_manager.clone(),
                stun_addr: stun_public_addr.clone(),
                si_peer_id: our_peer_id_si,
                si_overlay: our_overlay_si,
                si_overlay_ipv6: our_overlay_ipv6_si,
                si_hostname: our_hostname_si.clone(),
                relay_candidates: relay_candidates.clone(),
                relay_paths: relay_paths.clone(),
                our_peer_id: self.our_peer_id,
                can_relay,
            };
            tokio::spawn(inbound::run_inbound_loop(ia))
        };

        // Discovery + per-peer handshake task.
        let infohash = self.infohash;
        let discovery_handle = {
            let da = discovery::DiscoveryArgs {
                dht: dht.clone(),
                infohash,
                tracker_addrs,
                transport: transport.clone(),
                sessions: sessions.clone(),
                addr_index: addr_index.clone(),
                stun_addr: stun_public_addr.clone(),
                pending: pending_handshakes.clone(),
                peer_mgr: self.peer_manager.clone(),
                routing_table: self.routing_table.clone(),
                relay_cands: relay_candidates.clone(),
                relay_paths: relay_paths.clone(),
                network_secret: self.network_secret,
                device_keys: self.device_keys.clone(),
                si_peer_id: our_peer_id_si,
                si_overlay: our_overlay_si,
                si_overlay_ipv6: our_overlay_ipv6_si,
                si_hostname: our_hostname_si.clone(),
                our_id: self.our_peer_id,
                our_relay_id: self.our_peer_id,
                can_relay,
            };
            tokio::spawn(discovery::run_discovery_loop(da))
        };

        // Periodic DHT re-announce task.
        let stun_addr_announce = stun_public_addr.clone();
        let announce_handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(DHT_ANNOUNCE_INTERVAL);
            loop {
                interval.tick().await;
                let ap = stun_addr_announce
                    .read()
                    .await
                    .map(|a| a.port())
                    .unwrap_or(port);
                if let Err(e) = dht.announce(&infohash, ap).await {
                    tracing::debug!(target: "seednet", error = %e, "periodic DHT announce failed");
                }
            }
        });

        // Heartbeat task.
        let heartbeat_handle = {
            let sessions_hb = sessions.clone();
            let udp_hb = transport.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
                let heartbeat_payload =
                    seednet_peer::message::serialize_message(&Message::Heartbeat);
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
            })
        };

        // Periodic peer-directory broadcast (relay nodes only).
        // Ensures every connected peer learns about all others regardless of join order.
        let peer_dir_broadcast_handle = if can_relay {
            let sessions_pdb = sessions.clone();
            let stun_pdb = stun_public_addr.clone();
            let udp_pdb = transport.clone();
            let our_peer_id_pdb = self.our_peer_id;
            Some(tokio::spawn(async move {
                let mut interval = tokio::time::interval(PEER_DIRECTORY_BROADCAST_INTERVAL);
                interval.tick().await; // skip first tick
                loop {
                    interval.tick().await;
                    if stun_pdb.read().await.is_none() {
                        continue;
                    }
                    let all_peers: Vec<(seednet_common::PeerId, SocketAddr)> = sessions_pdb
                        .iter()
                        .filter_map(|e| {
                            if let seednet_transport::TransportAddr::Udp(a) = e.underlay {
                                Some((*e.key(), a))
                            } else {
                                None
                            }
                        })
                        .collect();
                    if all_peers.len() < 2 {
                        continue;
                    }
                    for entry in sessions_pdb.iter() {
                        let recipient_id = *entry.key();
                        let entries: Vec<(seednet_common::PeerId, SocketAddr)> = all_peers
                            .iter()
                            .filter(|(id, _)| *id != recipient_id)
                            .copied()
                            .collect();
                        if entries.is_empty() {
                            continue;
                        }
                        let dir =
                            seednet_peer::message::serialize_message(&Message::PeerDirectory {
                                entries,
                            });
                        if let Some(mut s) = sessions_pdb.get_mut(&recipient_id)
                            && let Ok(enc) = s.transport.encrypt(&dir)
                        {
                            let addr = s.underlay.clone();
                            drop(s);
                            let _ = udp_pdb.send_to(&enc, addr).await;
                        }
                    }
                    tracing::debug!(
                        target: "seednet",
                        peers = all_peers.len(),
                        relay = %our_peer_id_pdb.short(),
                        "broadcast peer directory to all connected peers"
                    );
                }
            }))
        } else {
            None
        };

        // Health-check (ping/RTT + path_kind update) task.
        const HEALTHCHECK_INTERVAL: Duration = Duration::from_secs(5);
        let healthcheck_handle = {
            let sessions_hc = sessions.clone();
            let udp_hc = transport.clone();
            let peer_mgr_hc = self.peer_manager.clone();
            let relay_paths_hc = relay_paths.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(HEALTHCHECK_INTERVAL);
                loop {
                    interval.tick().await;
                    let now_ms = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64;
                    let ping = seednet_peer::message::serialize_message(&Message::Ping {
                        sent_ms: now_ms,
                    });
                    for mut entry in sessions_hc.iter_mut() {
                        let peer_id = *entry.key();
                        let addr = entry.underlay.clone();
                        if let Ok(enc) = entry.transport.encrypt(&ping) {
                            drop(entry);
                            let _ = udp_hc.send_to(&enc, addr).await;
                        }
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
            })
        };

        // STUN refresh task.
        let stun_refresh_handle = {
            let stun_addr_refresh = stun_public_addr.clone();
            let udp_stun = transport.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(DHT_ANNOUNCE_INTERVAL);
                interval.tick().await;
                loop {
                    interval.tick().await;
                    if let Ok(addr) = seednet_nat::stun::query_public_addr_with_fallback(
                        udp_stun.udp().unwrap().inner(),
                        STUN_SERVERS,
                    )
                    .await
                    {
                        let mut w = stun_addr_refresh.write().await;
                        if *w != Some(addr) {
                            tracing::info!(target: "seednet", %addr, "public address changed");
                            *w = Some(addr);
                        }
                    }
                }
            })
        };

        // Peers snapshot task.
        let local_id = self.our_peer_id;
        let local_overlay = self.our_overlay;
        let local_ipv6 = self.our_overlay_ipv6;
        let local_hostname_str = local_hostname();
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
            hostname = local_hostname_str,
            pub_addr = local_public_addr.map(|a| a.to_string()).unwrap_or_default(),
        );
        let peer_events = self.peer_manager.subscribe();
        let peers_file_handle = {
            let psa = peers_snapshot::PeersSnapshotArgs {
                peer_mgr: self.peer_manager.clone(),
                routing_table: self.routing_table.clone(),
                state_dir: self.config.state_dir.clone(),
                relay_paths: relay_paths.clone(),
                sessions: sessions.clone(),
                addr_index: addr_index.clone(),
                local_json,
            };
            tokio::spawn(peers_snapshot::run_peers_file_loop(psa, peer_events))
        };

        tokio::signal::ctrl_c()
            .await
            .map_err(|e| Error::Io(std::io::Error::other(e)))?;

        tracing::info!(target: "seednet", "Shutting down …");
        outbound_handle.abort();
        inbound_handle.abort();
        discovery_handle.abort();
        announce_handle.abort();
        heartbeat_handle.abort();
        if let Some(h) = peer_dir_broadcast_handle {
            h.abort();
        }
        healthcheck_handle.abort();
        stun_refresh_handle.abort();
        peers_file_handle.abort();
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
    use seednet_config::StateDir;

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
